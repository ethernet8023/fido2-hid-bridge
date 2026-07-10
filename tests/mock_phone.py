#!/usr/bin/env python3
"""Mock phone for fido-fetch integration testing.

Connects to the fido2-hid-bridge daemon (TCP backend), pretends to be
an Android phone with an NFC FIDO2 dongle, and responds to CTAP2 requests
with fake responses.

Usage:
    python3 mock_phone.py [host] [port]
"""
import socket
import struct
import sys
import threading


def send_msg(sock: socket.socket, msg_type: int, payload: bytes) -> None:
    total = 1 + len(payload)
    sock.sendall(struct.pack(">I", total) + bytes([msg_type]) + payload)


def recv_msg(sock: socket.socket) -> tuple[int, bytes]:
    data = b""
    while len(data) < 4:
        chunk = sock.recv(4 - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    total = struct.unpack(">I", data)[0]
    data = b""
    while len(data) < total:
        chunk = sock.recv(total - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    msg_type = data[0]
    payload = data[1:]
    return msg_type, payload


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 28437

    print(f"Connecting to daemon at {host}:{port}...")
    s = socket.create_connection((host, port))

    # Send Hello
    send_msg(s, 0x01, b"\x01")  # Hello, version 1
    print("Sent Hello")

    # Receive HelloAck
    msg_type, payload = recv_msg(s)
    if msg_type != 0x02:
        print(f"ERROR: expected HelloAck (0x02), got {msg_type:#x}")
        return
    print(f"Got HelloAck (version {payload[0] if payload else '?'})")

    # Send NFC status: present
    send_msg(s, 0x20, b"\x01")
    print("Sent NFC status: present")

    print("Waiting for CTAP requests...")
    while True:
        try:
            msg_type, payload = recv_msg(s)
        except ConnectionError:
            print("Daemon disconnected")
            break

        if msg_type == 0x10:  # CtapRequest
            print(f"\nGot CtapRequest ({len(payload)} bytes): {payload.hex()}")

            # Check if this is a GET_INFO request (CBOR command 0x04)
            if len(payload) > 0 and payload[0] == 0x04:
                # Fake GET_INFO response: CTAP2 status 0x00 (success) + minimal CBOR
                # CBOR map: {1: "fido-fetch-mock", 2: "1.0.0", 3: ["internal"], ...}
                # For now, just return status 0x00 + empty CBOR map (0xA0)
                response = b"\x00\xa0"
                print(f"Sending fake GET_INFO response: {response.hex()}")
                send_msg(s, 0x11, response)
            else:
                # For any other request, send CTAP2 ERR_OTHER (0x01)
                response = b"\x01"
                print(f"Sending error response: {response.hex()}")
                send_msg(s, 0x11, response)
        elif msg_type == 0x20:
            present = payload[0] if payload else 0
            print(f"NFC status ack: present={bool(present)}")
        else:
            print(f"Unknown message type: {msg_type:#x}, payload: {payload.hex()}")

    s.close()


if __name__ == "__main__":
    main()
