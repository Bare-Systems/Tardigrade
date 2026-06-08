#!/usr/bin/env python3

from __future__ import annotations

import argparse
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    PAYLOAD_64K = b"x" * (64 * 1024)
    PAYLOAD_256K = b"y" * (256 * 1024)
    PAYLOAD_1M = b"m" * (1024 * 1024)
    PAYLOAD_16M = b"z" * (16 * 1024 * 1024)

    def setup(self) -> None:
        super().setup()
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def do_HEAD(self) -> None:
        self._handle(send_body=False)

    def do_GET(self) -> None:
        self._handle(send_body=True)

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path != "/upload-large":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", "0") or "0")
        remaining = content_length
        while remaining > 0:
            chunk = self.rfile.read(min(64 * 1024, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
        body = b"uploaded"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def _handle(self, *, send_body: bool) -> None:
        parsed = urlsplit(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/health":
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if send_body:
                self.wfile.write(body)
                self.wfile.flush()
            return

        if path == "/payload-64k.bin":
            payload = self.PAYLOAD_64K
            if query.get("size", [""])[0] == "256k":
                payload = self.PAYLOAD_256K
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if send_body:
                self.wfile.write(payload)
                self.wfile.flush()
            return

        if path == "/payload-256k.bin":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(self.PAYLOAD_256K)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if send_body:
                self.wfile.write(self.PAYLOAD_256K)
                self.wfile.flush()
            return

        if path == "/payload-1m.bin":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(self.PAYLOAD_1M)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if send_body:
                self.wfile.write(self.PAYLOAD_1M)
                self.wfile.flush()
            return

        if path == "/payload-16m.bin":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(self.PAYLOAD_16M)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if send_body:
                self.wfile.write(self.PAYLOAD_16M)
                self.wfile.flush()
            return

        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18080)
    args = parser.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
