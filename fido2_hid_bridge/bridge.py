#!/usr/bin/env python3

import asyncio
import logging
import argparse

from fido2_hid_bridge.ctap_hid_device import CTAPHIDDevice
from fido2_hid_bridge.backends import PcscBackend, TcpRemoteBackend


async def run_device(backend_name: str, host: str, port: int) -> None:
    """Asynchronously run the event loop."""
    if backend_name == "pcsc":
        backend = PcscBackend()
    elif backend_name == "tcp":
        backend = TcpRemoteBackend(host, port)
        await backend.start_server()
    else:
        raise ValueError(f"Unknown backend: {backend_name}")

    device = CTAPHIDDevice(backend)
    await device.start()


def main():
    parser = argparse.ArgumentParser(
        description='Relay USB-HID packets to an authenticator',
        allow_abbrev=False,
    )
    parser.add_argument(
        '--backend',
        choices=['pcsc', 'tcp'],
        default='pcsc',
        help='Authenticator backend (default: pcsc)',
    )
    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='TCP listen host (tcp backend only, default: 0.0.0.0)',
    )
    parser.add_argument(
        '--port',
        type=int,
        default=28437,
        help='TCP listen port (tcp backend only, default: 28437)',
    )
    parser.add_argument(
        '--debug',
        action='store_const',
        const=logging.DEBUG,
        default=logging.INFO,
        help='Enable debug messages',
    )
    args = parser.parse_args()
    logging.basicConfig(level=args.debug)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(run_device(args.backend, args.host, args.port))
    loop.run_forever()


if __name__ == '__main__':
    main()
