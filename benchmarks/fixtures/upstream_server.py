#!/usr/bin/env python3

from __future__ import annotations

import argparse
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    PAYLOAD_64K = b"x" * (64 * 1024)

    def setup(self) -> None:
        super().setup()
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def do_HEAD(self) -> None:
        self._handle(send_body=False)

    def do_GET(self) -> None:
        self._handle(send_body=True)

    def _handle(self, *, send_body: bool) -> None:
        if self.path == "/health":
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

        if self.path == "/payload-64k.bin":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(self.PAYLOAD_64K)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if send_body:
                self.wfile.write(self.PAYLOAD_64K)
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
