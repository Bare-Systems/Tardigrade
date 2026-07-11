#!/usr/bin/env python3
"""Minimal aioquic HTTP/3 client used as an external interop peer (#247).

Sends one GET to the native Tardigrade server and prints the status and body.
Certificate verification is disabled: interop asserts the QUIC/TLS/H3 wire
behavior; trust decisions are covered by the native test suite. The UDP
endpoint is built by hand on an IPv4 socket because
`aioquic.asyncio.connect` hardcodes an IPv6 dual-stack socket, which
IPv4-only CI sandboxes cannot create.

usage: aioquic_client.py HOST PORT PATH
"""

import asyncio
import socket
import ssl
import sys

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import QuicEvent


class ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.status = None
        self.body = b""
        self.done = asyncio.Event()

    def quic_event_received(self, event: QuicEvent) -> None:
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                for name, value in http_event.headers:
                    if name == b":status":
                        self.status = int(value)
            if isinstance(http_event, DataReceived):
                self.body += http_event.data
                if http_event.stream_ended:
                    self.done.set()


async def main(host: str, port: int, path: str) -> int:
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    configuration.verify_mode = ssl.CERT_NONE
    configuration.server_name = host
    connection = QuicConnection(configuration=configuration)

    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: ClientProtocol(connection), sock=sock
    )
    try:
        protocol.connect((host, port))
        await asyncio.wait_for(protocol.wait_connected(), timeout=10)

        stream_id = protocol._quic.get_next_available_stream_id()
        protocol.http.send_headers(
            stream_id,
            [
                (b":method", b"GET"),
                (b":scheme", b"https"),
                (b":authority", host.encode()),
                (b":path", path.encode()),
            ],
            end_stream=True,
        )
        protocol.transmit()
        await asyncio.wait_for(protocol.done.wait(), timeout=10)
        print(f"status: {protocol.status}")
        sys.stdout.write(protocol.body.decode(errors="replace"))
        protocol.close()
        await protocol.wait_closed()
        return 0 if protocol.status is not None else 1
    finally:
        transport.close()


if __name__ == "__main__":
    host, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    sys.exit(asyncio.run(main(host, port, path)))
