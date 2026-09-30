#!/usr/bin/env python3
"""Tiny WebSocket client for the Tardigrade websocket-proxy example.

Usage: client.py ws://127.0.0.1:8080/ws/echo [Origin]
Sends a text message and a ping through Tardigrade, prints the replies, then
closes cleanly. Standard library only; plain ws:// only.
"""

import base64
import os
import socket
import struct
import sys
from urllib.parse import urlparse


def send(sock, opcode, payload):
    mask = os.urandom(4)
    n = len(payload)
    head = bytes([0x80 | opcode])
    head += bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack("!H", n)
    sock.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


def recv_frame(sock):
    b1, b2 = recv_exact(sock, 2)
    n = b2 & 0x7F
    if n == 126:
        (n,) = struct.unpack("!H", recv_exact(sock, 2))
    elif n == 127:
        (n,) = struct.unpack("!Q", recv_exact(sock, 8))
    return b1 & 0x0F, recv_exact(sock, n)


url = urlparse(sys.argv[1] if len(sys.argv) > 1 else "ws://127.0.0.1:8080/ws/echo")
sock = socket.create_connection((url.hostname, url.port or 80))
key = base64.b64encode(os.urandom(16)).decode()
origin = f"Origin: {sys.argv[2]}\r\n" if len(sys.argv) > 2 else ""
sock.sendall(
    f"GET {url.path or '/'} HTTP/1.1\r\nHost: {url.netloc}\r\nUpgrade: websocket\r\n"
    f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n{origin}\r\n".encode()
)
head = b""
while b"\r\n\r\n" not in head:
    head += recv_exact(sock, 1)
print(head.decode().split("\r\n")[0])
if b" 101 " not in head.split(b"\r\n")[0]:
    sys.exit(1)
send(sock, 0x1, b"hello through tardigrade")
print("echo:", recv_frame(sock)[1].decode())
send(sock, 0x9, b"ping")
print("pong:", recv_frame(sock))
send(sock, 0x8, b"\x03\xe8")
print("close:", recv_frame(sock))
