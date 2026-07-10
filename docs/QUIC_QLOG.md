# QUIC/HTTP-3 Observability: qlog, keylog, metrics

Design for the minimal qlog / keylog / metrics seam the pure-Zig QUIC and
HTTP/3 stack (#240) needs **before** external interop and fuzzing (#247, #255).

This document is the design of record. The scaffolding it describes lives in:

- `src/quic/qlog.zig` — transport-vantage event model + JSON-SEQ serializer.
- `src/http3/qlog.zig` — HTTP/3- and QPACK-vantage event model + serializer.
- `src/quic/keylog.zig` — NSS `SSLKEYLOGFILE` label mapping + line writer.
- `src/quic/config.zig` — `Observability { qlog_enabled, keylog_enabled }`.

The intent is **design + small scaffold**, not a full observability
implementation. Emission call-sites in the connection/packet/stream/path layers
are added as those layers land; this seam fixes the event vocabulary, the
layering, and the safety rules up front so those call-sites are mechanical.

## Goals

- Make handshake, loss/PTO, path validation/migration, stream reset,
  flow-control blocking, and QPACK head-of-line blocking **distinguishable**
  from a captured trace, not just from ad-hoc `std.log` lines.
- Produce artifacts (`*.qlog`, `*.keys`) that the interop/failure harnesses
  (#247) can save and that qvis / Wireshark can consume directly.
- Keep everything **off by default** and cheap when off.
- Keep HTTP/3 out of `src/quic` (the #255 layering constraint).

## Non-goals (per the issue)

- qvis UI integration, high-cardinality per-client metrics, always-on qlog.
- A general logging framework; this is transport observability only.

## Layering: where emission belongs

`src/quic` and `src/http3` are **independent modules** — the build graph keeps
them apart on purpose (see `build.zig`: the smoke harness stitches the two
together "so neither package learns about the other"). The observability seam
respects that boundary rather than punching through it.

```
                 composition root (gateway h3 listener / smoke harness)
                 ┌───────────────────────────────────────────────────┐
                 │  owns the *.qlog file + *.keys file writers        │
                 │  installs one quic.qlog.Sink, one http3.qlog.Sink, │
                 │  one quic.keylog.Sink; interleaves all three       │
                 └───────────────▲───────────────▲───────────────▲────┘
                                 │ Record        │ Record        │ Entry
        transport events ────────┘        H3/QPACK events ┘   TLS secrets ┘
        emitted by src/quic               emitted by src/http3   emitted by
        (connection, packet,              (session, frame,       src/quic
         recovery, path, stream)           qpack)                (tls_adapter)
```

Rules:

1. **Transport-vantage events** (`connectivity`, `security`, `transport`,
   `recovery` qlog categories) are defined in `src/quic/qlog.zig` and emitted
   from the transport layers. `src/quic` imports no HTTP/3 type.
2. **Application-vantage events** (`http`, `qpack` categories) are defined in
   `src/http3/qlog.zig` and emitted from `src/http3`. `src/http3` imports no
   transport type.
3. Both packages emit through an **injected `Sink`** — an opaque context plus a
   function pointer, exactly like the existing `recovery.EventSink`. A default
   `Sink{}` is a no-op, so the seam costs nothing until a root wires it.
4. The **concrete file writers** live at the composition root, which already
   owns both packages. It timestamps and interleaves the streams into one
   JSON-SEQ `.qlog` file, so a single trace still shows transport and H3 events
   side by side without either package depending on the other.

This is why there is no single shared "qlog writer" module: sharing one would
force one package to import the other's event type. Two small symmetric writers
with an identical line format (`0x1E` + JSON + `\n`, RFC 7464 JSON-SEQ) compose
into one valid file at the root instead.

### Relationship to existing hooks and metrics

- `recovery.EventSink` / `recovery.Event` already exist for ACK/loss/PTO. The
  connection layer bridges those into `qlog.Event.packet_lost` etc. rather than
  duplicating loss logic — `recovery` stays qlog-agnostic.
- Per-module counters already exist and remain the source for Prometheus:
  `tls_adapter.Metrics` (protect/deprotect/deprotection-failure),
  `path.Metrics` (challenges, migrations, amplification-blocked),
  `stream.Metrics` (resets, stop-sending). qlog is the *event* view; these
  counters are the *aggregate* view. The two are independent and both feed the
  same operator story.

## qlog event catalogue

Names below are `category:event`. Transport events (`src/quic/qlog.zig`):

| Requirement (#255)        | qlog event                          | Key data |
|---------------------------|-------------------------------------|----------|
| handshake                 | `connectivity:connection_started`   | odcid/scid/dcid lengths |
|                           | `connectivity:handshake`            | `stage` (started → confirmed / failed) |
|                           | `connectivity:connection_closed`    | `reason`, optional `error_code` |
|                           | `security:key_updated`              | `key_phase` |
| packet sent               | `transport:packet_sent`             | type, number, length, ack-eliciting |
| packet received           | `transport:packet_received`         | type, number, length |
| packet lost               | `recovery:packet_lost`              | type, number, bytes-in-flight, cwnd |
| **deprotection failure**  | `transport:packet_dropped`          | `trigger:"payload_decrypt_error"` |
| PATH_CHALLENGE/RESPONSE   | `transport:path_validation`         | `phase` (challenge/response sent/received, validated, failed) |
| migration                 | `connectivity:connection_migrated`  | `kind` (nat_rebinding/active), `outcome` (accepted/blocked) |
| stream reset              | `transport:stream_reset`            | `direction` (reset/stop-sending, sent/received), stream id, error code |
| flow-control blocked      | `transport:data_blocked`            | `scope` (connection/stream), optional stream id, limit |

Application events (`src/http3/qlog.zig`):

| Requirement (#255)        | qlog event                          | Key data |
|---------------------------|-------------------------------------|----------|
| SETTINGS                  | `http:parameters_set`               | max field section size, QPACK table cap, blocked streams |
| control stream / HEADERS / DATA / GOAWAY | `http:frame_created` / `http:frame_parsed` | frame type, stream id, length |
| **QPACK blocked**         | `qpack:stream_state_updated`        | `state` (blocked/unblocked), stream id |

`transport:packet_dropped` with `trigger:"payload_decrypt_error"` is the
canonical qlog encoding of an AEAD deprotection failure, satisfying the #255
requirement that deprotection failures are reported deterministically. It is
distinct from a normal drop (`unknown_connection_id`, `key_unavailable`, …).

### Serialization format

Each record is one JSON-SEQ line:

```
0x1E {"time":<ms>.<us>,"name":"transport:packet_sent","data":{ … }}\n
```

- Time is milliseconds (qlog's default `time_units`) with microsecond
  precision, derived from a monotonic `time_us`.
- Writers are **allocation-free**: they format into a caller-owned buffer
  (`writeJson(record, buf)`), matching the bounded-buffer style already used by
  the TLS handshake wire writer. A 512-byte buffer covers every event.
- A qlog file is a trace header (emitted once by the root) followed by these
  lines. The header (vantage point, `reference_time`, ODCID group id) is the
  root's responsibility since only it spans both packages.

## Keylog

`src/quic/keylog.zig` maps a `(perspective, direction, level)` triple from the
TLS adapter to an NSS `SSLKEYLOGFILE` label and formats the line:

```
<LABEL> <client_random_hex> <secret_hex>\n
```

Labels: `CLIENT_EARLY_TRAFFIC_SECRET`, `{CLIENT,SERVER}_HANDSHAKE_TRAFFIC_SECRET`,
`{CLIENT,SERVER}_TRAFFIC_SECRET_0`. **Initial secrets are never logged** — they
are derivable from the client DCID on the wire, so logging them only widens the
exposure without adding debugging value.

Wiring point: `QuicTlsAdapter.installSecret` is the single choke point where
every traffic secret is installed, so a keylog `Sink` is invoked there (guarded
by `keylog_enabled`) before the secret is later wiped.

### Sensitive / debug-only behaviour  ⚠️

A key log **is** the plaintext. Anyone holding the `.keys` file plus a packet
capture can decrypt the entire connection.

- **Disabled by default.** `config.Observability.keylog_enabled` is `false`.
  qlog is likewise `false` by default.
- **Never in production.** These paths are for local debugging and the interop
  harness only. Treat the key-log destination with the same care as the
  private key: local filesystem, restrictive permissions, deleted after use.
  Do not point it at shared storage, logs, or anything network-reachable.
- **Not for third-party traffic.** Only key-log connections you own and are
  authorized to decrypt.
- The adapter otherwise wipes these secrets (`SecretStore.wipe`); the key log is
  the only path by which they leave the process.
- Artifacts the harness saves (`*.qlog`, `*.keys`) inherit this: store them with
  the capture, scrub them from CI logs, and never attach them to public issues.

## Configuration

`config.Observability`:

```zig
qlog_enabled: bool = false,   // emit qlog events for local/debug runs
keylog_enabled: bool = false, // emit TLS secrets for local decryption
```

Both default off and are intended to be reachable only through explicit
debug/interop configuration, never a production default. The concrete
destinations (qlog directory, keylog path) are supplied by the composition root
that owns the writers, not by the transport config, keeping file I/O out of the
transport core.

## Metrics (Prometheus) — planned surface

qlog answers "what happened on this one connection"; Prometheus answers "what is
happening across all connections". The existing per-module `Metrics` counters
are the source. The gateway `/status/metrics` endpoint (see
`docs/OBSERVABILITY.md`) will export, when the pure-Zig backend is active:

- `tardigrade_quic_connections_active` (gauge)
- `tardigrade_quic_handshake_failures_total{stage}`
- `tardigrade_quic_retry_total`, `tardigrade_quic_amplification_blocked_total`
- `tardigrade_quic_pto_total`, `tardigrade_quic_packets_lost_total`
- `tardigrade_quic_bytes_sent_total`, `tardigrade_quic_bytes_received_total`
- `tardigrade_quic_stream_resets_total`
- `tardigrade_quic_flow_control_blocked_total`
- `tardigrade_quic_deprotection_failures_total`
- `tardigrade_h3_qpack_blocked_streams` (gauge)
- `tardigrade_h3_requests_total` and an h3 latency histogram

Labels are kept low-cardinality (e.g. `stage`, not per-client) per the issue's
non-goals. Wiring these into the gateway registry is follow-up work; the
counters they read from already exist.

## Testing strategy

- **Unit** (in place): event category/name mapping and JSON-SEQ serialization
  for representative transport events, QPACK blocking, and keylog line format,
  in `src/quic/qlog.zig`, `src/http3/qlog.zig`, `src/quic/keylog.zig`.
- **Integration** (follow-up, with the connection layer): drive a handshake and
  assert a produced `.qlog` contains the expected event classes; snapshot
  metrics on common error paths.
- **Manual**: load a saved `.qlog` in qvis and a capture + `.keys` in Wireshark
  once enough transport exists to produce real flows.

## References

- qlog main schema & QUIC/HTTP-3 event definitions (IETF drafts)
- qvis tooling; QUIC Interop Runner artifact conventions
- RFC 7464 (JSON Text Sequences), RFC 9000/9001/9002, RFC 9114/9204
- NSS `SSLKEYLOGFILE` format
- #240 pure-Zig QUIC/HTTP-3 foundation, #247 interop/fuzz/benchmark harness
