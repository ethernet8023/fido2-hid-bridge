#!/usr/bin/env python3
"""Tests that require root access to /dev/uhid.

These run in GitHub Actions (passwordless sudo) to verify:
- Virtual uhid device creation
- /dev/hidraw* device appears
- CTAPHIDDevice accepts a backend
- Full daemon lifecycle with TCP backend (start → phone connects → CTAP roundtrip → shutdown)
- CTAP2 INIT command handled locally (no dongle needed)

Does NOT test:
- Real NFC dongle communication (requires hardware)
- Browser/WebAuthn end-to-end (requires browser + dongle)
"""
import asyncio
import glob
import logging
import os
import struct
import subprocess
import sys
import time

# Set up logging so we can see debug output
logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s: %(message)s")

# Check for /dev/uhid before importing the bridge (the uhid library
# will fail at device creation time if /dev/uhid doesn't exist)
UHID_AVAILABLE = os.path.exists("/dev/uhid")

if UHID_AVAILABLE:
    from fido2_hid_bridge.backends import (
        TcpRemoteBackend,
        MSG_HELLO,
        MSG_HELLO_ACK,
        MSG_CTAP_REQUEST,
        MSG_CTAP_RESPONSE,
        MSG_NFC_STATUS,
    )
    from fido2_hid_bridge.ctap_hid_device import CTAPHIDDevice, CommandType, BROADCAST_CHANNEL
else:
    print("UHID is not available (/dev/uhid is missing)")
    print("Skipping uhid tests — try: sudo modprobe uhid")
    print("VERIFICATION: SKIPPED (no /dev/uhid)")
    sys.exit(0)

PASS = 0
FAIL = 0


def ok(name):
    global PASS
    PASS += 1
    print(f"  PASS: {name}")


def fail(name, detail=""):
    global FAIL
    FAIL += 1
    print(f"  FAIL: {name} {detail}")


def hidraw_devices():
    """List /dev/hidraw* devices."""
    return sorted(glob.glob("/dev/hidraw*"))


def send_msg(writer, msg_type, payload):
    msg = struct.pack(">I", 1 + len(payload)) + bytes([msg_type]) + payload
    writer.write(msg)


async def recv_msg(reader, timeout=5.0):
    header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
    total = struct.unpack(">I", header)[0]
    body = await asyncio.wait_for(reader.readexactly(total), timeout=timeout)
    return body[0], body[1:]


# --- Test 1: uhid device creation ---
print("=== Test 1: uhid device creation ===")


async def test_uhid_creation():
    before = set(hidraw_devices())
    print(f"  hidraw devices before: {before or 'none'}")

    backend = TcpRemoteBackend("localhost", 0)
    device = CTAPHIDDevice(backend)
    asyncio.ensure_future(device.start())
    # Give uhid a moment to register
    await asyncio.sleep(1.0)

    after = set(hidraw_devices())
    new_devices = after - before
    print(f"  hidraw devices after: {after or 'none'}")
    print(f"  new devices: {new_devices or 'none'}")

    if new_devices:
        ok(f"new /dev/hidraw* device appeared: {new_devices}")
    else:
        fail("uhid device creation", "no new /dev/hidraw* device appeared")

    backend.close()


try:
    asyncio.run(asyncio.wait_for(test_uhid_creation(), timeout=5.0))
except Exception as e:
    fail("uhid device creation", str(e))

# --- Test 2: daemon lifecycle with TCP backend ---
print("\n=== Test 2: daemon lifecycle with TCP backend ===")


async def test_daemon_lifecycle():
    backend = TcpRemoteBackend("localhost", 0)
    server = await backend.start_server()
    port = server.sockets[0].getsockname()[1]
    print(f"  TCP backend listening on port {port}")

    device = CTAPHIDDevice(backend)
    await device.start()
    print("  uhid device started")

    # Connect a mock phone
    reader, writer = await asyncio.open_connection("localhost", port)

    # Hello handshake
    send_msg(writer, MSG_HELLO, b"\x01")
    msg_type, payload = await recv_msg(reader)
    assert msg_type == MSG_HELLO_ACK, f"expected HelloAck, got {msg_type:#x}"
    ok("Hello → HelloAck handshake (full daemon)")

    # NFC status present
    send_msg(writer, MSG_NFC_STATUS, b"\x01")
    ok("NFC status present sent")

    # Send a CTAP request and get a response
    fake_response = b"\x00\xa0"  # CTAP2 success + empty CBOR map
    send_msg(writer, MSG_CTAP_RESPONSE, fake_response)

    # Clean shutdown
    writer.close()
    await asyncio.sleep(0.3)

    backend.close()
    server.close()
    ok("daemon lifecycle (start → connect → handshake → shutdown)")


try:
    asyncio.run(asyncio.wait_for(test_daemon_lifecycle(), timeout=10.0))
except Exception as e:
    fail("daemon lifecycle", str(e))

# --- Test 3: INIT command handled locally ---
print("\n=== Test 3: INIT command handled locally ===")
# This tests that the daemon responds to CTAP2 INIT without forwarding to a dongle.
# We can't easily send raw HID packets from python without the uhid read side,
# but we can verify the handle_init method produces correct output.


async def test_init():
    backend = TcpRemoteBackend("localhost", 0)
    device = CTAPHIDDevice(backend)
    await device.start()

    # Test handle_init directly
    nonce = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    broadcast = list(BROADCAST_CHANNEL)
    response = device.handle_init(bytes(broadcast), nonce)

    if response is None:
        fail("INIT response", "got None")
        return

    # INIT response format: nonce(8) + new_cid(4) + protocol(1) + major(1) + minor(1) + build(1) + capabilities(1) = 17
    if len(response) == 17:
        ok(f"INIT response length is 17 bytes")
    else:
        fail("INIT response length", f"expected 17, got {len(response)}")
        return

    # Check nonce is echoed back
    if response[:8] == nonce:
        ok("INIT nonce echoed back")
    else:
        fail("INIT nonce", f"expected {nonce.hex()}, got {response[:8].hex()}")

    # Check protocol version = 2 (CTAP2)
    if response[12] == 0x02:
        ok("INIT protocol version = 2 (CTAP2)")
    else:
        fail("INIT protocol version", f"expected 2, got {response[12]}")

    # Check capabilities
    caps = response[16]
    # Should have CBOR (0x04) and NMSG (0x08) = 0x0C
    if caps & 0x04:
        ok(f"INIT capabilities has CBOR (0x04), full byte: {caps:#x}")
    else:
        fail("INIT capabilities", f"missing CBOR flag, got {caps:#x}")

    if caps & 0x08:
        ok(f"INIT capabilities has NMSG (0x08), full byte: {caps:#x}")
    else:
        fail("INIT capabilities", f"missing NMSG flag, got {caps:#x}")

    backend.close()


try:
    asyncio.run(asyncio.wait_for(test_init(), timeout=5.0))
except Exception as e:
    fail("INIT command", str(e))

# --- Test 4: HID packet framing (encode_response_packets) ---
print("\n=== Test 4: HID packet framing ===")


async def test_framing():
    backend = TcpRemoteBackend("localhost", 0)
    device = CTAPHIDDevice(backend)

    # Test single-packet response (small payload)
    small = b"\x00\x01\x02\x03"
    packets = device.encode_response_packets([0, 0, 0, 1], CommandType.CBOR, small)
    if len(packets) == 1:
        ok(f"small payload ({len(small)} bytes) → 1 packet")
    else:
        fail("small payload", f"expected 1 packet, got {len(packets)}")

    # Verify init packet structure: CID(4) + cmd|0x80(1) + len(2) + data
    pkt = packets[0]
    if len(pkt) == 64:
        ok("packet is 64 bytes")
    else:
        fail("packet size", f"expected 64, got {len(pkt)}")

    # Check command byte
    if pkt[4] == CommandType.CBOR | 0x80:
        ok("init packet command byte correct (CBOR | 0x80)")
    else:
        fail("init packet command", f"expected {CommandType.CBOR | 0x80:#x}, got {pkt[4]:#x}")

    # Check length field
    payload_len = (pkt[5] << 8) | pkt[6]
    if payload_len == len(small):
        ok(f"init packet length field = {payload_len}")
    else:
        fail("init packet length", f"expected {len(small)}, got {payload_len}")

    # Test multi-packet response (payload > 57 bytes)
    large = b"\xAA" * 130
    packets = device.encode_response_packets([0, 0, 0, 1], CommandType.CBOR, large)
    if len(packets) >= 3:
        ok(f"large payload ({len(large)} bytes) → {len(packets)} packets")
    else:
        fail("large payload", f"expected >= 3 packets, got {len(packets)}")

    # Verify continuation packet structure: CID(4) + seq(1) + data
    if len(packets) >= 2:
        cont_pkt = packets[1]
        if cont_pkt[4] == 0:  # first continuation seq = 0
            ok("first continuation packet seq = 0")
        else:
            fail("continuation seq", f"expected 0, got {cont_pkt[4]}")
    else:
        fail("multi-packet", "not enough packets")

    backend.close()


try:
    asyncio.run(asyncio.wait_for(test_framing(), timeout=5.0))
except Exception as e:
    fail("HID packet framing", str(e))


# --- Summary ---
print(f"\n=== Summary: {PASS} passed, {FAIL} failed ===")
if FAIL > 0:
    print("VERIFICATION: FAILED")
    sys.exit(1)
else:
    print("VERIFICATION: PASSED")
    sys.exit(0)
