# TLS handshake transport contract

`src/tls/transport.zig` defines the single canonical contract between a TLS
1.3 handshake backend and any transport that carries it. QUIC's adapter
(`src/quic/tls_handshake.zig`) and TCP record mode
(`src/tls/record_epoch_bridge.zig`) both instantiate
`transport.Contract`/`transport.ContractWithOptions` directly with their own
epoch and transport-parameter payload types; neither owns a parallel copy of
the event/sink/driver machinery.

> An earlier record-mode-only contract, `record_transport.zig`, duplicated
> this module's guarantees (secure zeroization, driver teardown) without a
> production consumer — `record_epoch_bridge.zig` used the generic contract
> from the start. It has been removed; this file now documents the one
> contract both transports use (#408 finding 1).

## Events and ownership

The handshake backend emits events tagged with the caller's own `Epoch` type:
handshake bytes to send, traffic-secret installation (read/write, per epoch),
transport-owned peer parameters, negotiated ALPN, peer certificate state,
epoch discard, completion, and a fatal alert.

Event byte slices are copied into the driver-owned `EventSink`. They remain
valid only until the next drive call — `Driver.start`, `Driver.receive`,
`Driver.startOutcome`, or `Driver.receiveOutcome` — all four reset the sink
before invoking the backend. Resetting or deinitializing the sink securely
zeroes the used scratch range, so a copied traffic secret does not survive
past that event lifetime. Event emission is atomic: a rejected emit
(event-count or byte overflow) never leaves a partial payload in scratch or a
phantom event in `items`.

`Driver.deinit()` wipes the sink's final contents. Every owner of a `Driver`
must call it exactly once at teardown, regardless of whether the handshake
completed, failed, or was abandoned mid-flight — QUIC's `Connection.deinitPartial`
does this via `Handshake.deinit()`.

## Terminal error plus events

`Driver.start`/`Driver.receive` return `Transport.Error!*EventSink`: on
backend failure they return only the error, discarding whatever the backend
already emitted into the sink before failing (for example a fatal alert, or
handshake bytes queued ahead of it). That is the right shape for QUIC's
`try`-based happy path, where a failure always tears the connection down
regardless of what else was emitted.

A caller that needs the backend's terminal output — for example TCP record
mode, which must still serialize a fatal alert the backend emitted right
before failing — uses `Driver.startOutcome`/`Driver.receiveOutcome` instead.
Both return `Driver.Outcome`, `{ sink: *EventSink, terminal_error: ?Transport.Error }`,
so the sink and the error are always available together rather than one
discarding the other. This restores the terminal-error-plus-events guarantee
the removed `record_transport.zig` carried (#408 finding 1); once a driver has
failed, repeated `startOutcome`/`receiveOutcome` calls keep returning the same
terminal error and sink contents without re-invoking the backend.

## Fatal alerts

The contract's `Event` union can carry a fatal alert
(`Event.fatal_alert: alerts.AlertDescription`) so a transport can serialize
one before closing. The contract only carries it; deciding *when* to
synthesize an alert from a handshake failure — and the rest of alert /
`close_notify` / truncation policy — is transport-specific and, for TCP record
mode, tracked by #354.

## Record-stream buffer limits

`PureZigRecordStream` keeps its hot path allocation-free: inbound carrier
ciphertext, decrypted application plaintext, outbound ciphertext, and inbound
handshake bytes live in fixed-capacity queues owned by the stream. Runtime
`BufferLimits` add effective low/high/hard watermarks inside those compile-time
capacities; they do not replace the queues with dynamically growing buffers.

Validation rejects zero or nonsensical watermarks (`low < high <= hard` is
required), hard limits above the fixed queue capacity, and policies that cannot
hold a maximum legal TLS fragment or the complete borrowed handshake event batch
that record mode must serialize atomically. Existing constructors use safe
defaults derived from the fixed capacities; callers that need tighter appliance
profiles can use the explicit `init*WithLimits` constructors.

Readiness uses latched hysteresis. Carrier reads pause when inbound ciphertext,
plaintext, or handshake ownership reaches the relevant high watermark, and they
resume only after all inbound queues drain to their low watermarks. Plaintext
writes pause when outbound ciphertext reaches its high watermark and resume
only after the ciphertext queue drains to or below low. `wants_write` remains
true while queued ciphertext can drain.

The backend-neutral `EncryptedStream.bufferSnapshot()` reports allocation-free
state for metrics and HTTP integration: current and peak owned bytes by queue,
peak total owned bytes, configured limits, pause state, pause/resume counters,
hard-limit counters, and stalled-drive count. The pure-Zig record stream reports
only bytes it owns. An OpenSSL adapter must report only measurable adapter/BIO
state and mark opaque internal OpenSSL memory as outside the complete
stream-owned accounting boundary rather than describing unknown memory as zero.

Pure-Zig application writes seal accepted plaintext directly into the outbound
ciphertext queue; there is no hidden pending-plaintext staging queue. HTTP/1.1
and HTTP/2 consumers should use `can_write_plaintext`, `can_read_plaintext`,
`wants_read`, `wants_write`, and the buffer snapshot to register only socket
readiness that can make progress.
