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
valid only until the next `Driver.start` or `Driver.receive` call, both of
which reset the sink. Resetting or deinitializing the sink securely zeroes the
used scratch range, so a copied traffic secret does not survive past that
event lifetime. Event emission is atomic: a rejected emit (event-count or byte
overflow) never leaves a partial payload in scratch or a phantom event in
`items`.

`Driver.deinit()` wipes the sink's final contents. Every owner of a `Driver`
must call it exactly once at teardown, regardless of whether the handshake
completed, failed, or was abandoned mid-flight — QUIC's `Connection.deinitPartial`
does this via `Handshake.deinit()`.

## Fatal alerts

The contract's `Event` union can carry a fatal alert
(`Event.fatal_alert: alerts.AlertDescription`) so a transport can serialize
one before closing. The contract only carries it; deciding *when* to
synthesize an alert from a handshake failure — and the rest of alert /
`close_notify` / truncation policy — is transport-specific and, for TCP record
mode, tracked by #354.
