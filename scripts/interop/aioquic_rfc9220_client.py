#!/usr/bin/env python3
"""External aioquic RFC 9220 WebSocket client for the gateway interop gate.

Usage: aioquic_rfc9220_client.py HOST PORT PATH PAYLOAD [AUTHORITY]
       [--header NAME:VALUE] [--expect-status STATUS] [--reset-after-200]
       [--isolation-path PATH]
       [--expect-response-header NAME:VALUE]
       [--capacity-probe]

This deliberately uses aioquic's QUIC + HTTP/3 stack rather than the native
test client.  It performs the RFC 9220 non-FIN CONNECT/`:protocol` exchange,
then sends one masked RFC 6455 text frame through the H3 tunnel and requires
the echoed frame before exiting successfully.
"""

import argparse
import asyncio
import socket
import ssl
import sys

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection, Setting
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
    def __init__(
        self,
        payload: bytes,
        expected_status: int,
        reset_after_200: bool,
        reset_recovery_path: str | None,
        authority: str,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.payload = payload
        self.expected_status = expected_status
        self.reset_after_200 = reset_after_200
        self.reset_recovery_path = reset_recovery_path
        self.authority = authority
        self.stream_id = None
        self.status = None
        self.response_headers = []
        self.received = b""
        self.done = asyncio.Event()
        self.failure = None
        self.peer_settings_ready = asyncio.Event()
        self.connect_stream_ids = set()
        self.isolation_stream_id = None
        self.isolation_status = None
        self.reset_recovery_stream_id = None
        self.reset_recovery_status = None
        self.capacity_stream_ids = set()
        self.capacity_statuses = {}

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ConnectionTerminated):
            self.failure = f"connection terminated: {event.error_code} {event.reason_phrase!r}"
            self.peer_settings_ready.set()
            self.done.set()
            return
        http_events = self.http.handle_event(event)
        if self.http.received_settings is not None:
            self.peer_settings_ready.set()
        for http_event in http_events:
            if isinstance(http_event, HeadersReceived) and http_event.stream_id in self.capacity_stream_ids:
                status = next((int(value) for name, value in http_event.headers if name == b":status"), None)
                self.capacity_statuses[http_event.stream_id] = status
                if len(self.capacity_statuses) == len(self.capacity_stream_ids):
                    self.done.set()
                continue
            if isinstance(http_event, HeadersReceived) and http_event.stream_id == self.reset_recovery_stream_id:
                self.reset_recovery_status = next(
                    (int(value) for name, value in http_event.headers if name == b":status"),
                    None,
                )
                if self.reset_recovery_status != 200:
                    self.failure = f"expected reset recovery GET status 200, got {self.reset_recovery_status}"
                    self.done.set()
                continue
            if isinstance(http_event, DataReceived) and http_event.stream_id == self.reset_recovery_stream_id:
                if http_event.stream_ended:
                    self.done.set()
                continue
            if isinstance(http_event, HeadersReceived) and http_event.stream_id == self.isolation_stream_id:
                self.isolation_status = next(
                    (int(value) for name, value in http_event.headers if name == b":status"),
                    None,
                )
                if self.isolation_status != 200:
                    self.failure = f"expected isolated GET status 200, got {self.isolation_status}"
                    self.done.set()
                continue
            if isinstance(http_event, DataReceived) and http_event.stream_id == self.isolation_stream_id:
                if http_event.stream_ended:
                    self.done.set()
                continue
            if isinstance(http_event, HeadersReceived) and http_event.stream_id == self.stream_id:
                self.response_headers = http_event.headers
                self.status = next((int(value) for name, value in http_event.headers if name == b":status"), None)
                if self.status != self.expected_status:
                    self.failure = f"expected status {self.expected_status}, got {self.status}"
                    self.done.set()
                    continue
                if self.status != 200:
                    # A denial response does not establish a WebSocket byte
                    # stream. Seeing its final status is enough for this
                    # client; the integration harness independently checks
                    # that no origin handshake occurred.
                    self.done.set()
                    continue
                if self.reset_after_200:
                    # Exercise real QUIC receive/send cancellation after the
                    # non-FIN 200 HEADERS, when the gateway owns an admitted
                    # tunnel. Both directions are deliberately aborted.
                    self._quic.stop_stream(self.stream_id, 0x10C)
                    self._quic.reset_stream(self.stream_id, 0x10C)
                    self.reset_recovery_stream_id = self._quic.get_next_available_stream_id()
                    self.http.send_headers(
                        self.reset_recovery_stream_id,
                        [
                            (b":method", b"GET"),
                            (b":scheme", b"https"),
                            (b":authority", self.authority.encode()),
                            (b":path", self.reset_recovery_path.encode()),
                        ],
                        end_stream=True,
                    )
                    self.transmit()
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


async def main(
    host: str,
    port: int,
    path: str,
    payload: str,
    authority: str,
    headers: list[tuple[bytes, bytes]],
    expected_status: int,
    reset_after_200: bool,
    reset_recovery_path: str,
    isolation_path: str | None,
    expect_connect_protocol: bool,
    settings_only: bool,
    expected_response_headers: list[tuple[bytes, bytes]],
    capacity_probe: bool,
) -> int:
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    configuration.verify_mode = ssl.CERT_NONE
    configuration.server_name = authority
    connection = QuicConnection(configuration=configuration)
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: RFC9220Client(payload.encode(), expected_status, reset_after_200, reset_recovery_path, authority, connection), sock=sock
    )
    try:
        protocol.connect((host, port))
        await asyncio.wait_for(protocol.wait_connected(), timeout=10)
        await asyncio.wait_for(protocol.peer_settings_ready.wait(), timeout=10)
        if protocol.failure:
            print(protocol.failure)
            return 1
        settings = protocol.http.received_settings
        if settings is None:
            print("peer SETTINGS were not received")
            return 1
        connect_protocol = settings.get(Setting.ENABLE_CONNECT_PROTOCOL, 0) == 1
        print(f"SETTINGS_ENABLE_CONNECT_PROTOCOL: {int(connect_protocol)}")
        if connect_protocol != expect_connect_protocol:
            print(f"expected SETTINGS_ENABLE_CONNECT_PROTOCOL={int(expect_connect_protocol)}")
            return 1
        if settings_only:
            protocol.close()
            await protocol.wait_closed()
            return 0
        if not connect_protocol:
            print("refusing to send Extended CONNECT without negotiated SETTINGS_ENABLE_CONNECT_PROTOCOL")
            return 1
        if capacity_probe:
            for _ in range(2):
                stream_id = protocol._quic.get_next_available_stream_id()
                protocol.capacity_stream_ids.add(stream_id)
                protocol.http.send_headers(
                    stream_id,
                    [
                        (b":method", b"CONNECT"),
                        (b":protocol", b"websocket"),
                        (b":scheme", b"https"),
                        (b":authority", authority.encode()),
                        (b":path", path.encode()),
                    ] + headers,
                    end_stream=False,
                )
            protocol.transmit()
            await asyncio.wait_for(protocol.done.wait(), timeout=10)
            statuses = sorted(protocol.capacity_statuses.values())
            print(f"capacity probe statuses: {statuses}")
            protocol.close()
            await protocol.wait_closed()
            return 0 if statuses == [200, 503] else 1
        if isolation_path:
            # Saturate the dedicated CONNECT-admission executor with two
            # upgrades whose origins deliberately never answer. A healthy
            # gateway must still dispatch this ordinary H3 request on its
            # separate REST executor without waiting for either upgrade.
            for _ in range(2):
                stream_id = protocol._quic.get_next_available_stream_id()
                protocol.connect_stream_ids.add(stream_id)
                protocol.http.send_headers(
                    stream_id,
                    [
                        (b":method", b"CONNECT"),
                        (b":protocol", b"websocket"),
                        (b":scheme", b"https"),
                        (b":authority", authority.encode()),
                        (b":path", path.encode()),
                    ] + headers,
                    end_stream=False,
                )
            protocol.transmit()
            # Give both blocking Upgrade reads a chance to enter the two
            # dedicated admission workers before the ordinary request is
            # issued. The integration harness also observes two origin
            # handshakes, so this is not merely a queued-work assertion.
            await asyncio.sleep(0.25)
            protocol.isolation_stream_id = protocol._quic.get_next_available_stream_id()
            protocol.http.send_headers(
                protocol.isolation_stream_id,
                [
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", authority.encode()),
                    (b":path", isolation_path.encode()),
                ],
                end_stream=True,
            )
            protocol.transmit()
            await asyncio.wait_for(protocol.done.wait(), timeout=5)
            if protocol.failure:
                print(protocol.failure)
                return 1
            print(f"isolated GET status: {protocol.isolation_status}")
            protocol.close()
            await protocol.wait_closed()
            return 0 if protocol.isolation_status == 200 else 1

        protocol.stream_id = protocol._quic.get_next_available_stream_id()
        protocol.http.send_headers(
            protocol.stream_id,
            [
                (b":method", b"CONNECT"),
                (b":protocol", b"websocket"),
                (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", path.encode()),
            ] + headers,
            end_stream=False,
        )
        protocol.transmit()
        await asyncio.wait_for(protocol.done.wait(), timeout=10)
        if protocol.failure:
            print(protocol.failure)
            return 1
        for expected_name, expected_value in expected_response_headers:
            if (expected_name, expected_value) not in protocol.response_headers:
                print(
                    "missing expected response header: "
                    f"{expected_name.decode(errors='replace')}: {expected_value.decode(errors='replace')}"
                )
                return 1
        print(f"status: {protocol.status}")
        for name, value in protocol.response_headers:
            if not name.startswith(b":"):
                print(f"header: {name.decode(errors='replace')}: {value.decode(errors='replace')}")
        if reset_after_200:
            print(f"reset recovery GET status: {protocol.reset_recovery_status}")
        print(protocol.received.decode(errors="replace"))
        protocol.close()
        await protocol.wait_closed()
        return 0
    finally:
        transport.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("path")
    parser.add_argument("payload")
    parser.add_argument("authority", nargs="?")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--expect-status", type=int, default=200)
    parser.add_argument("--reset-after-200", action="store_true")
    parser.add_argument("--reset-recovery-path", default="/healthz")
    parser.add_argument("--isolation-path")
    parser.add_argument("--expect-connect-protocol", type=int, choices=(0, 1), default=1)
    parser.add_argument("--settings-only", action="store_true")
    parser.add_argument("--expect-response-header", action="append", default=[])
    parser.add_argument("--capacity-probe", action="store_true")
    args = parser.parse_args()
    headers = []
    for item in args.header:
        name, sep, value = item.partition(":")
        if not sep or not name:
            parser.error("--header must be NAME:VALUE")
        headers.append((name.encode(), value.encode()))
    expected_response_headers = []
    for item in args.expect_response_header:
        name, sep, value = item.partition(":")
        if not sep or not name:
            parser.error("--expect-response-header must be NAME:VALUE")
        expected_response_headers.append((name.lower().encode(), value.encode()))
    authority = args.authority or args.host
    sys.exit(asyncio.run(main(
        args.host,
        args.port,
        args.path,
        args.payload,
        authority,
        headers,
        args.expect_status,
        args.reset_after_200,
        args.reset_recovery_path,
        args.isolation_path,
        bool(args.expect_connect_protocol),
        args.settings_only,
        expected_response_headers,
        args.capacity_probe,
    )))
