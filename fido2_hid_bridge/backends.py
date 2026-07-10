"""Pluggable authenticator backends for fido2-hid-bridge.

A backend provides access to a FIDO2 authenticator. The bridge talks to
the backend, and the backend talks to the actual authenticator (PC/SC
reader, remote phone over TCP, etc.).
"""

import asyncio
import logging
import struct
import time
from abc import ABC, abstractmethod
from typing import Optional

# PC/SC imports — kept lazy/optional so the TCP backend doesn't require pyscard
try:
    import fido2
    from fido2.pcsc import CtapPcscDevice, CtapError, CTAPHID
    from smartcard.pcsc.PCSCContext import PCSCContext
    from smartcard.scard import SCardReleaseContext
    _PCSC_AVAILABLE = True
except ImportError:
    _PCSC_AVAILABLE = False
    PCSCContext = None

SECONDS_TO_WAIT_FOR_AUTHENTICATOR = 10


class AuthenticatorBackend(ABC):
    """Interface for talking to a FIDO2 authenticator."""

    @abstractmethod
    async def wait_for_device(self) -> bool:
        """Wait until the authenticator is available.

        Returns True if the device became available, False on timeout.
        """
        ...

    @abstractmethod
    async def send_ctap(self, cbor_payload: bytes) -> Optional[bytes]:
        """Send a CTAP2 CBOR payload to the authenticator and return the response.

        Returns None on failure (device not available, communication error).
        """
        ...

    @abstractmethod
    def close(self) -> None:
        """Clean up any resources."""
        ...

    @abstractmethod
    def capabilities(self) -> int:
        """Return the CTAP capabilities byte for INIT responses.

        Bit flags: 0x01=WINK, 0x04=CBOR, 0x08=NMSG (legacy U2F not supported).
        """
        ...


class PcscBackend(AuthenticatorBackend):
    """Local PC/SC authenticator backend (existing behavior)."""

    def __init__(self):
        if not _PCSC_AVAILABLE:
            raise RuntimeError(
                "PC/SC backend requires pyscard and fido2[pcsc] — "
                "install with: poetry install"
            )
        self._device = None

    async def wait_for_device(self) -> bool:
        if self._device is not None:
            return True
        start_time = time.time()
        while time.time() < start_time + SECONDS_TO_WAIT_FOR_AUTHENTICATOR:
            logging.info("WAITING FOR NEW DEVICE")
            devices = list(CtapPcscDevice.list_devices())
            if len(devices) == 0:
                await asyncio.sleep(0.1)
                continue
            self._device = devices[0]

            # Silence fido2 pcsc logger noise (existing behavior)
            fido2.pcsc.logger.setLevel(0)
            fido2.pcsc.logger.disabled = False
            fido2.pcsc.logger.isEnabledFor = lambda x: True
            fido2.pcsc.logger.manager.disable = 0
            fido2.pcsc.logger._cache = {}

            return True
        return False

    async def send_ctap(self, cbor_payload: bytes) -> Optional[bytes]:
        if self._device is None:
            if not await self.wait_for_device():
                return None
        try:
            res = self._device.call(cmd=0x10, data=cbor_payload)  # 0x10 = CBOR
            return res
        except CtapError as e:
            logging.info(f"Got CTAP error response from device: {e}")
            return bytes([e.code])

    def close(self):
        if self._device is not None:
            try:
                if hasattr(self._device, 'close'):
                    logging.info("CLOSED DEVICE CONNECTION")
                    self._device.close()

                if PCSCContext is not None and PCSCContext.instance is not None:
                    ctx = PCSCContext.instance
                    if hasattr(ctx, 'hcontext') and ctx.hcontext is not None:
                        SCardReleaseContext(ctx.hcontext)
                        ctx.hcontext = None
                    PCSCContext.instance = None
                    logging.info("CLOSED PCSC CONNECTION")
            except Exception as e:
                logging.warning(f"Failed to close PC/SC connection: {e}")
            finally:
                self._device = None

    def capabilities(self) -> int:
        if self._device is not None and hasattr(self._device, 'capabilities'):
            return self._device.capabilities
        return 0x04 | 0x08  # CBOR + NMSG


# --- TCP transport protocol constants ---

# Wire format: [4-byte big-endian length] [1-byte message type] [payload]
# The length field covers the type byte + payload.

MSG_HELLO = 0x01         # Phone → Daemon: handshake
MSG_HELLO_ACK = 0x02     # Daemon → Phone: acknowledge
MSG_CTAP_REQUEST = 0x10  # Daemon → Phone: CBOR to send to dongle
MSG_CTAP_RESPONSE = 0x11  # Phone → Daemon: CBOR from dongle
MSG_NFC_STATUS = 0x20     # Phone → Daemon: dongle present/absent
MSG_ERROR = 0xFF          # Either direction: transport error


class TcpRemoteBackend(AuthenticatorBackend):
    """Remote authenticator backend over TCP.

    Listens for a phone connection, then bridges CTAP2 CBOR payloads
    between the bridge and the phone (which relays them to an NFC dongle).
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 28437):
        self._host = host
        self._port = port
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._connected = False
        self._pending_future: Optional[asyncio.Future] = None

    async def start_server(self):
        """Start listening for phone connections."""
        server = await asyncio.start_server(
            self._on_connect, self._host, self._port
        )
        addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
        logging.info(f"Listening for phone on {addrs}")
        return server

    async def _on_connect(self, reader, writer):
        if self._connected:
            logging.warning("Phone already connected, rejecting new connection")
            writer.close()
            return
        peer = writer.get_extra_info('peername')
        logging.info(f"Phone connected from {peer}")
        self._reader = reader
        self._writer = writer
        self._connected = True
        asyncio.ensure_future(self._read_loop())

    async def _read_loop(self):
        """Continuously read messages from the phone."""
        try:
            while self._connected:
                header = await self._reader.readexactly(4)
                total_len = struct.unpack('>I', header)[0]
                body = await self._reader.readexactly(total_len)
                msg_type = body[0]
                payload = body[1:]

                if msg_type == MSG_HELLO:
                    version = payload[0] if payload else 0
                    logging.info(f"Phone hello v{version}")
                    await self._send_message(MSG_HELLO_ACK, bytes([1]))

                elif msg_type == MSG_CTAP_RESPONSE:
                    if self._pending_future and not self._pending_future.done():
                        self._pending_future.set_result(payload)
                    else:
                        logging.warning("Got CTAP_RESPONSE with no pending request")

                elif msg_type == MSG_NFC_STATUS:
                    present = payload[0] if payload else 0
                    logging.info(f"NFC status: present={bool(present)}")

                elif msg_type == MSG_ERROR:
                    logging.error(f"Phone error: {payload}")
                    if self._pending_future and not self._pending_future.done():
                        self._pending_future.set_exception(
                            RuntimeError(f"Phone error: {payload}")
                        )

                else:
                    logging.warning(f"Unknown message type from phone: {msg_type:#x}")

        except asyncio.IncompleteReadError:
            logging.info("Phone disconnected")
        except Exception as e:
            logging.error(f"Read loop error: {e}")
        finally:
            self._connected = False
            self._reader = None
            self._writer = None
            if self._pending_future and not self._pending_future.done():
                self._pending_future.set_exception(
                    RuntimeError("Phone disconnected")
                )

    async def wait_for_device(self) -> bool:
        # For TCP, "device available" means "phone connected"
        if self._connected:
            return True
        # Wait up to the timeout for a phone to connect
        start = time.time()
        while time.time() < start + SECONDS_TO_WAIT_FOR_AUTHENTICATOR:
            if self._connected:
                return True
            await asyncio.sleep(0.1)
        return False

    async def send_ctap(self, cbor_payload: bytes) -> Optional[bytes]:
        if not self._connected or self._writer is None:
            return None

        loop = asyncio.get_event_loop()
        self._pending_future = loop.create_future()

        await self._send_message(MSG_CTAP_REQUEST, cbor_payload)

        try:
            return await asyncio.wait_for(self._pending_future, timeout=30.0)
        except asyncio.TimeoutError:
            logging.error("Timeout waiting for phone response")
            return None

    async def _send_message(self, msg_type: int, payload: bytes):
        if self._writer is None:
            return
        msg = struct.pack('>I', 1 + len(payload)) + bytes([msg_type]) + payload
        self._writer.write(msg)
        await self._writer.drain()

    def close(self):
        if self._writer is not None:
            self._writer.close()
        self._connected = False
        self._reader = None
        self._writer = None

    def capabilities(self) -> int:
        return 0x04 | 0x08  # CBOR + NMSG (no legacy U2F)
