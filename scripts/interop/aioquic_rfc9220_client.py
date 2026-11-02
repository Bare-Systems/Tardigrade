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
import os
import signal
import socket
import ssl
import sys

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection, Setting
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, QuicEvent, StreamReset


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
        drop_transport_after_200: bool,
        slow_receive_delay: float | None,
        reload_signal_pid: int | None,
        lifecycle_signal: int,
        post_reload_payload: bytes | None,
        post_reload_delay: float,
        expect_terminal_after_signal: bool,
        expected_greeting_bytes: int,
        path: str,
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
        self.drop_transport_after_200 = drop_transport_after_200
        self.slow_receive_delay = slow_receive_delay
        self.reload_signal_pid = reload_signal_pid
        self.lifecycle_signal = lifecycle_signal
        self.post_reload_payload = post_reload_payload
        self.post_reload_delay = post_reload_delay
        self.expect_terminal_after_signal = expect_terminal_after_signal
        self.expected_greeting = b"b" * expected_greeting_bytes
        self.path = path
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
        self.reset_recovery_connect_stream_id = None
        self.reset_recovery_connect_status = None
        self.reset_recovery_connect_received = b""
        self.reset_recovery_connect_attempts = 0
        self.capacity_stream_ids = set()
        self.capacity_statuses = {}
        self.transport_dropped = False
        self.stall_server_datagrams = False
        self.slow_receive_pause_completed = False
        self.reload_signaled = False
        self.post_reload_sent = False
        self.post_reload_echo_completed = False
        self.terminal_after_signal = False

    def datagram_received(self, data: bytes, addr) -> None:
        # Deliberately leave server datagrams unacknowledged for a bounded
        # interval after CONNECT succeeds.  Together with the small advertised
        # receive window this makes the gateway hit real QUIC backpressure;
        # releasing the datagrams then proves it resumes the same tunnel.
        if self.stall_server_datagrams:
            return
        super().datagram_received(data, addr)

    def release_slow_receive(self) -> None:
        self.stall_server_datagrams = False
        self.slow_receive_pause_completed = True

    def send_post_reload_frame(self) -> None:
        self.post_reload_sent = True
        self.http.send_data(self.stream_id, masked_text_frame(self.post_reload_payload), end_stream=False)
        self.transmit()

    def signal_gateway(self) -> None:
        os.kill(self.reload_signal_pid, self.lifecycle_signal)

    def received_expected_greeting(self) -> bool:
        # The origin greeting is an unmasked server WebSocket frame.  Looking
        # for this complete contiguous payload proves that H3 DATA preserved
        # every byte and order across the intentionally tiny receive window;
        # the separately asserted echo proves later traffic still progresses.
        return not self.expected_greeting or self.expected_greeting in self.received

    def initial_exchange_complete(self) -> bool:
        return self.payload in self.received and self.received_expected_greeting()

    def start_reset_recovery_connect(self) -> None:
        # Do this only after the unrelated GET completes.  Keeping this QUIC
        # connection open and requiring a second accepted CONNECT with a
        # one-tunnel gateway proves RESET_STREAM/STOP_SENDING released the
        # first stream's admission slot, rather than connection teardown
        # happening to release it later.
        self.reset_recovery_connect_attempts += 1
        if self.reset_recovery_connect_attempts > 100:
            self.failure = "reset recovery CONNECT did not regain capacity while QUIC stayed live"
            self.done.set()
            return
        self.reset_recovery_connect_stream_id = self._quic.get_next_available_stream_id()
        self.http.send_headers(
            self.reset_recovery_connect_stream_id,
            [
                (b":method", b"CONNECT"),
                (b":protocol", b"websocket"),
                (b":scheme", b"https"),
                (b":authority", self.authority.encode()),
                (b":path", self.path.encode()),
            ],
            end_stream=False,
        )
        self.transmit()

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, ConnectionTerminated):
            if self.expect_terminal_after_signal and self.reload_signaled:
                self.terminal_after_signal = True
                self.done.set()
                return
            self.failure = f"connection terminated: {event.error_code} {event.reason_phrase!r}"
            self.peer_settings_ready.set()
            self.done.set()
            return
        if isinstance(event, StreamReset) and event.stream_id == self.stream_id:
            # This is the peer's acknowledgement of the deliberate reset of
            # the first CONNECT stream. It may arrive after the recovery GET
            # has been sent, so it is not a failure of the live connection.
            if self.reset_after_200 and self.reset_recovery_stream_id is not None:
                return
            if self.expect_terminal_after_signal and self.reload_signaled:
                self.terminal_after_signal = True
                self.done.set()
            else:
                self.failure = f"tunnel stream reset: {event.error_code}"
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
                    self.start_reset_recovery_connect()
                continue
            if isinstance(http_event, HeadersReceived) and http_event.stream_id == self.reset_recovery_connect_stream_id:
                self.reset_recovery_connect_status = next(
                    (int(value) for name, value in http_event.headers if name == b":status"),
                    None,
                )
                if self.reset_recovery_connect_status == 503:
                    # Session relay teardown is asynchronous to the QUIC
                    # reactor. Keep this QUIC connection alive and retry a
                    # fresh CONNECT stream until its one-slot lease is
                    # observable as available; a connection-close cleanup
                    # cannot make this pass.
                    self._loop.call_later(0.05, self.start_reset_recovery_connect)
                    continue
                if self.reset_recovery_connect_status != 200:
                    self.failure = (
                        "expected reset recovery CONNECT status 200, got "
                        f"{self.reset_recovery_connect_status}"
                    )
                    self.done.set()
                    continue
                self.http.send_data(
                    self.reset_recovery_connect_stream_id,
                    masked_text_frame(b"recovered-after-stream-reset"),
                    end_stream=False,
                )
                self.transmit()
                continue
            if isinstance(http_event, DataReceived) and http_event.stream_id == self.reset_recovery_connect_stream_id:
                self.reset_recovery_connect_received += http_event.data
                if b"recovered-after-stream-reset" in self.reset_recovery_connect_received:
                    self.done.set()
                elif http_event.stream_ended:
                    self.failure = "reset recovery tunnel ended before echo"
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
                if self.drop_transport_after_200:
                    # Intentionally abandon UDP without emitting QUIC
                    # CONNECTION_CLOSE.  The gateway must settle this tunnel
                    # on the negotiated idle timeout, not only on graceful
                    # peer teardown.
                    self.transport_dropped = True
                    self._transport.close()
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
                if self.slow_receive_delay is not None:
                    self.stall_server_datagrams = True
                    self._loop.call_later(self.slow_receive_delay, self.release_slow_receive)
                self.http.send_data(self.stream_id, masked_text_frame(self.payload), end_stream=False)
                self.transmit()
            elif isinstance(http_event, DataReceived) and http_event.stream_id == self.stream_id:
                self.received += http_event.data
                if self.post_reload_sent and self.post_reload_payload in self.received:
                    self.post_reload_echo_completed = True
                    self.done.set()
                elif self.initial_exchange_complete():
                    if self.reload_signal_pid is not None and not self.reload_signaled:
                        self.signal_gateway()
                        self.reload_signaled = True
                        if self.expect_terminal_after_signal:
                            continue
                        self._loop.call_later(self.post_reload_delay, self.send_post_reload_frame)
                    else:
                        self.done.set()
                elif http_event.stream_ended:
                    if self.expect_terminal_after_signal and self.reload_signaled:
                        self.terminal_after_signal = True
                    else:
                        self.failure = "tunnel ended before complete greeting and echo"
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
    drop_transport_after_200: bool,
    idle_timeout: float | None,
    slow_receive_delay: float | None,
    max_stream_data: int | None,
    reload_signal_pid: int | None,
    lifecycle_signal: int,
    post_reload_payload: str | None,
    post_reload_delay: float,
    expect_terminal_after_signal: bool,
    expected_greeting_bytes: int,
    isolation_path: str | None,
    expect_connect_protocol: bool,
    settings_only: bool,
    expected_response_headers: list[tuple[bytes, bytes]],
    capacity_probe: bool,
) -> int:
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    configuration.verify_mode = ssl.CERT_NONE
    configuration.server_name = authority
    if idle_timeout is not None:
        configuration.idle_timeout = idle_timeout
    if max_stream_data is not None:
        configuration.max_stream_data = max_stream_data
    connection = QuicConnection(configuration=configuration)
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: RFC9220Client(
            payload.encode(),
            expected_status,
            reset_after_200,
            reset_recovery_path,
            drop_transport_after_200,
            slow_receive_delay,
            reload_signal_pid,
            lifecycle_signal,
            post_reload_payload.encode() if post_reload_payload is not None else None,
            post_reload_delay,
            expect_terminal_after_signal,
            expected_greeting_bytes,
            path,
            authority,
            connection,
        ),
        sock=sock,
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
        if protocol.transport_dropped:
            print(f"status: {protocol.status}")
            print("UDP transport dropped without QUIC CONNECTION_CLOSE")
            return 0
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
            print(f"reset recovery CONNECT status: {protocol.reset_recovery_connect_status}")
            print(f"reset recovery CONNECT attempts: {protocol.reset_recovery_connect_attempts}")
            print(protocol.reset_recovery_connect_received.decode(errors="replace"))
        if protocol.slow_receive_pause_completed:
            print("slow receive pause elapsed; echo completed")
        if protocol.expected_greeting:
            if not protocol.received_expected_greeting():
                print(f"missing complete ordered greeting: {len(protocol.expected_greeting)} bytes")
                return 1
            print(f"received complete ordered greeting: {len(protocol.expected_greeting)} bytes")
        if protocol.post_reload_echo_completed:
            print("post-reload tunnel echo completed")
        if protocol.terminal_after_signal:
            print("tunnel ended after lifecycle signal")
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
    parser.add_argument("--drop-transport-after-200", action="store_true")
    parser.add_argument("--idle-timeout", type=float)
    parser.add_argument("--slow-receive-delay", type=float)
    parser.add_argument("--max-stream-data", type=int)
    parser.add_argument("--reload-signal-pid", type=int)
    parser.add_argument("--lifecycle-signal", choices=("HUP", "TERM"), default="HUP")
    parser.add_argument("--post-reload-payload")
    parser.add_argument("--post-reload-delay", type=float, default=0.5)
    parser.add_argument("--expect-terminal-after-signal", action="store_true")
    parser.add_argument("--expect-greeting-bytes", type=int, default=0)
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
        args.drop_transport_after_200,
        args.idle_timeout,
        args.slow_receive_delay,
        args.max_stream_data,
        args.reload_signal_pid,
        getattr(signal, "SIG" + args.lifecycle_signal),
        args.post_reload_payload,
        args.post_reload_delay,
        args.expect_terminal_after_signal,
        args.expect_greeting_bytes,
        args.isolation_path,
        bool(args.expect_connect_protocol),
        args.settings_only,
        expected_response_headers,
        args.capacity_probe,
    )))
