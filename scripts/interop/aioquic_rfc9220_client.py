#!/usr/bin/env python3
"""External aioquic RFC 9220 WebSocket client for the gateway interop gate.

Usage: aioquic_rfc9220_client.py HOST PORT PATH PAYLOAD [AUTHORITY]

This deliberately uses aioquic's QUIC + HTTP/3 stack rather than the native
test client.  It performs the RFC 9220 non-FIN CONNECT/`:protocol` exchange,
then sends one masked RFC 6455 text frame through the H3 tunnel and requires
the echoed frame before exiting successfully.
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
from aioquic.quic.events import ConnectionTerminated, QuicEvent


def masked_text_frame(payload: bytes) -> bytes:
    if len(payload) > 125:
        raise ValueError("interop payload must fit the short WebSocket frame form")
    mask = b"\x17\x42\x93\x5a"
    masked = bytes(byte ^ mask[index % len(mask)] for index, byte in enumerate(payload))
    return b"\x81" + bytes([0x80 | len(payload)]) + mask + masked


class RFC9220Client(QuicConnectionProtocol):
    def __init__(self, payload: bytes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.payload = payload
        self.stream_id = None
        self.status = None
        self.received = b""
        self.done = asyncio.Event()
        self.failure = None

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ConnectionTerminated):
            self.failure = f"connection terminated: {event.error_code} {event.reason_phrase!r}"
            self.done.set()
            return
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, HeadersReceived) and http_event.stream_id == self.stream_id:
                self.status = next((int(value) for name, value in http_event.headers if name == b":status"), None)
                if self.status != 200:
                    self.failure = f"expected status 200, got {self.status}"
                    self.done.set()
                    continue
                self.http.send_data(self.stream_id, masked_text_frame(self.payload), end_stream=False)
                self.transmit()
            elif isinstance(http_event, DataReceived) and http_event.stream_id == self.stream_id:
                self.received += http_event.data
                if self.payload in self.received:
                    self.done.set()
                elif http_event.stream_ended:
                    self.failure = "tunnel ended before echo"
                    self.done.set()


async def main(host: str, port: int, path: str, payload: str, authority: str) -> int:
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    configuration.verify_mode = ssl.CERT_NONE
    configuration.server_name = authority
    connection = QuicConnection(configuration=configuration)
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: RFC9220Client(payload.encode(), connection), sock=sock
    )
    try:
        protocol.connect((host, port))
        await asyncio.wait_for(protocol.wait_connected(), timeout=10)
        protocol.stream_id = protocol._quic.get_next_available_stream_id()
        protocol.http.send_headers(
            protocol.stream_id,
            [
                (b":method", b"CONNECT"),
                (b":protocol", b"websocket"),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", path.encode()),
            ],
            end_stream=False,
        )
        protocol.transmit()
        await asyncio.wait_for(protocol.done.wait(), timeout=10)
        if protocol.failure:
            print(protocol.failure)
            return 1
        print(f"status: {protocol.status}")
        print(protocol.received.decode(errors="replace"))
        protocol.close()
        await protocol.wait_closed()
        return 0
    finally:
        transport.close()


if __name__ == "__main__":
    host, port, path, payload = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    authority = sys.argv[5] if len(sys.argv) > 5 else host
    sys.exit(asyncio.run(main(host, port, path, payload, authority)))
