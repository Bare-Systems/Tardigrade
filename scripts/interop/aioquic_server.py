#!/usr/bin/env python3
"""Minimal aioquic HTTP/3 server used as an external interop peer (#247).

Serves a fixed body for any request.

usage: aioquic_server.py PORT CERT_PEM KEY_PEM
"""

import asyncio
import sys

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, QuicEvent

BODY = b"hello from aioquic\n"


class ServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = None

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ProtocolNegotiated) and event.alpn_protocol in H3_ALPN:
            self.http = H3Connection(self._quic)
        if self.http is None:
            return
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, HeadersReceived) and http_event.stream_ended:
                self.http.send_headers(
                    http_event.stream_id,
                    [(b":status", b"200"), (b"server", b"aioquic")],
                )
                self.http.send_data(http_event.stream_id, BODY, end_stream=True)
                self.transmit()


async def main(port: int, cert: str, key: str) -> None:
    configuration = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    configuration.load_cert_chain(cert, key)
    await serve(
        "127.0.0.1",
        port,
        configuration=configuration,
        create_protocol=ServerProtocol,
    )
    print(f"aioquic server on udp {port}", file=sys.stderr)
    await asyncio.sleep(3600)


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1]), sys.argv[2], sys.argv[3]))
