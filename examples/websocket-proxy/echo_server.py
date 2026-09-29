#!/usr/bin/env python3
"""Minimal RFC 6455 echo origin for the Tardigrade websocket-proxy example.

Standard library only. Echoes text and binary messages, answers pings, and
completes the close handshake. Plain HTTP requests get a short text reply.
Not for production.
"""

import asyncio
import base64
import hashlib
import struct

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


async def read_frame(reader):
    b1, b2 = await reader.readexactly(2)
    length = b2 & 0x7F
    if length == 126:
        (length,) = struct.unpack("!H", await reader.readexactly(2))
    elif length == 127:
        (length,) = struct.unpack("!Q", await reader.readexactly(8))
    mask = await reader.readexactly(4) if b2 & 0x80 else b"\0\0\0\0"
    payload = bytearray(await reader.readexactly(length))
    for i in range(length):
        payload[i] ^= mask[i % 4]
    return b1 & 0x80, b1 & 0x0F, bytes(payload)


def frame(opcode, payload, fin=True):
    head = bytes([(0x80 if fin else 0) | opcode])
    n = len(payload)
    if n < 126:
        head += bytes([n])
    elif n <= 0xFFFF:
        head += bytes([126]) + struct.pack("!H", n)
    else:
        head += bytes([127]) + struct.pack("!Q", n)
    return head + payload


async def handle(reader, writer):
    head = await reader.readuntil(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    headers = {k.strip().lower(): v.strip() for k, v in (l.split(":", 1) for l in lines[1:] if ":" in l)}
    if headers.get("upgrade", "").lower() != "websocket":
        body = b"plain HTTP reached the origin (no upgrade)\n"
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
        await writer.drain()
        writer.close()
        return
    accept = base64.b64encode(hashlib.sha1(headers["sec-websocket-key"].encode() + GUID).digest())
    print(f"handshake {lines[0]} X-Via={headers.get('x-via')} X-Forwarded-For={headers.get('x-forwarded-for')}")
    writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n")
    await writer.drain()
    try:
        while True:
            fin, opcode, payload = await read_frame(reader)
            if opcode == 0x9:
                writer.write(frame(0xA, payload))
            elif opcode == 0x8:
                writer.write(frame(0x8, payload))
                await writer.drain()
                break
            elif opcode in (0x0, 0x1, 0x2):
                writer.write(frame(opcode, payload, bool(fin)))
            await writer.drain()
    except asyncio.IncompleteReadError:
        pass
    writer.close()


async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", 9000)
    print("echo origin on ws://127.0.0.1:9000")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
