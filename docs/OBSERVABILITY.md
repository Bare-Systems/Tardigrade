# Observability

This document defines Tardigrade's operator-facing observability contract for
the stable HTTP/1.1, HTTP/2, and HTTP/3/QUIC gateway paths.

## Structured Logs

Runtime logs and access logs are JSON by default.

- runtime logs: `ts`, `level`, `component`, `msg`, and when available both
  `request_id` and `correlation_id`
- access logs: `type`, `ts`, `request_id`, `correlation_id`, `method`, `path`,
  `status`, `latency_ms`, `client_ip`, `upstream_addr`, `upstream_status`,
  `identity`, `bytes_sent`, `response_bytes`, `error_category`,
  `early_data_source`, `early_data_action`, `early_data_retry_result`, and
  `early_data_replay_exposed`. A WebSocket handshake that became a tunnel
  (#812) is logged once, when the tunnel closes, with status 101 plus
  `tunnel_close_reason` (`client`, `upstream`, `idle`, `lifetime`,
  `shutdown`, `reload`, `error`), `tunnel_duration_ms`,
  `tunnel_client_to_upstream_bytes` and `tunnel_upstream_to_client_bytes`
  (plain format: `tunnel_close=`, `tunnel_ms=`, `tunnel_in=`, `tunnel_out=`).

Early-data access-log fields are bounded enums/booleans only:

- `early_data_source`: `none`, `transport`, `header`, `both`
- `early_data_action`: `ordinary`, `accepted`, `forwarded`, `too_early`,
  `deferred`, `retried`
- `early_data_retry_result`: `none`, `success`, `too_early`, `failure`
- `early_data_replay_exposed`: `true` when transport and/or header provenance
  indicates replay exposure for this request

Access logs are written through `src/http/access_log.zig`. Runtime component
logs are written through `src/http/logger.zig`.

## Metrics

`/status/metrics` exports Prometheus text metrics for:

- total requests and status-class counters
- request latency histogram: `tardigrade_request_latency_ms`
- active connections
- worker-pool active jobs, queued jobs, configured threads, and queue capacity
- event-loop iterations
- queue and connection rejections
- upstream unhealthy backend count
- reverse-proxy streaming and buffered request counters:
  `tardigrade_proxy_streaming_requests_total` and
  `tardigrade_proxy_buffered_requests_total`
- long-lived streamed-response lifecycle metrics (#841):
  `tardigrade_response_streams_active`,
  `tardigrade_response_stream_admissions_total{outcome}` with fixed outcomes
  `admitted` and `capacity`, `tardigrade_response_stream_duration_seconds`,
  and `tardigrade_response_stream_closes_total{reason}` with the fixed reasons
  `client`, `upstream`, `timeout`, `reload`, `shutdown`, and `capacity`.
  Paths, content types, request IDs, and application payload values are never
  used as labels.
- reverse-proxy buffered byte gauges/counters:
  `tardigrade_proxy_buffered_bytes_current` and
  `tardigrade_proxy_buffered_bytes_total`
- shared proxy buffer accounting gauges/counters:
  `tardigrade_buffered_bytes_current{direction,scope}`,
  `tardigrade_buffer_high_watermark_events_total{direction,scope}`,
  `tardigrade_buffer_read_pauses_total{side}`,
  `tardigrade_buffer_read_resumes_total{side}`, and
  `tardigrade_buffer_limit_exceeded_total{direction,scope}`. Labels are fixed
  to protocol-independent directions, scopes, and sides; they never include
  URLs, request IDs, or stream IDs. Current byte gauges cover bounded buffered
  responses, HTTP/1 streaming relay buffers in both directions, HTTP/2 streaming
  response queues, and request-direction upload relay buffers.
  `scope="stream"` reports logical queue occupancy; `scope="global"`
  reports retained allocation, and the two differ while a queue is partially
  drained but still owns its buffer. The `scope="global"` series is a roll-up
  across *all* proxy paths and is **not** the quantity the configured global
  hard limit is checked against — see the next entry.
- the aggregate bytes the global hard limit is enforced against:
  `tardigrade_proxy_buffer_aggregate_bytes_current{direction,scope="global"}`,
  read directly from the account that performs the enforcement. That covers
  HTTP/2 stream queues, HTTP/1 relay buffers in both directions, and
  request-direction upload buffers on both protocols, so this is the series to
  compare with
  `tardigrade_buffer_config_limit_bytes{scope="global",limit="hard"}`; comparing
  the broader `tardigrade_buffered_bytes_current{scope="global"}` roll-up with
  that limit overstates pressure under mixed traffic, because the roll-up also
  includes the bounded buffered compatibility path, which has its own cap.
  `tardigrade_buffer_limit_exceeded_total` carries `scope="origin"` and
  `scope="global"` alongside `scope="stream"`: an aggregate refusal means the
  upstream origin (or the process) had no room for bytes the stream itself could
  have held. `tardigrade_buffer_read_pauses_total{side="upstream"}` and its
  resume counterpart record HTTP/2 streaming response queues crossing their high
  and low watermarks — a pause means stream credit is being withheld from the
  origin, a resume means the coalesced `WINDOW_UPDATE` went out. The
  `side="downstream"` series record the HTTP/1 upload relay finding the origin's
  send buffer full: that path has no queue to cross a watermark, so a blocked
  upstream write *is* its backpressure, and it reads the client again only once
  the write goes through. Both sides count transitions, not writes, so the
  difference between pauses and resumes reads as "how many relays are stalled
  right now".
- per-origin HTTP/2 buffer accounting:
  `tardigrade_upstream_h2_pool_buffered_bytes{upstream,direction}` and
  `tardigrade_upstream_h2_pool_buffer_limit_exceeded_total{upstream,direction}`.
  Response queues and request-direction upload relay buffers are enforced
  against the *same* per-origin account, so both directions are reported: a
  request-only pressure would otherwise read as zero while the limit was
  actively bounding it. Label cardinality stays bounded — two fixed directions
  per distinct configured origin — and `direction` takes the same values as the
  process-wide buffer family.
- per-origin HTTP/1 buffer accounting:
  `tardigrade_upstream_pool_buffered_bytes{upstream,direction}` and
  `tardigrade_upstream_pool_buffer_limit_exceeded_total{upstream,direction}`,
  the HTTP/1 counterparts of the two series above and read from the account
  that enforces the per-origin limit for HTTP/1 origins. The `upstream` label
  is the pool key (`http:host:port`, `https:host:port`, or `unix:/path`), so
  cardinality is again two directions per distinct configured origin. These
  series come from their own map rather than the `tardigrade_upstream_pool_*`
  connection series: an origin gets a buffer account whenever it is proxied to,
  including when connection pooling is disabled, so the two memberships differ
  and summing across families would not line up.
- configured proxy buffer limits:
  `tardigrade_buffer_config_limit_bytes{direction,scope,limit}` for the
  per-stream low/high/hard watermarks plus per-origin/global hard-limit
  settings.
- TLS record-stream backpressure gauges/counters from the allocation-free
  `EncryptedStream.bufferSnapshot()` seam:
  `tardigrade_tls_buffered_bytes_current{backend,queue}`,
  `tardigrade_tls_buffer_pause_events_total{backend,direction}`,
  `tardigrade_tls_buffer_resume_events_total{backend,direction}`,
  `tardigrade_tls_buffer_limit_exceeded_total{backend,queue}`, and
  `tardigrade_tls_buffer_stalled_drives_total{backend}`. Labels are fixed to
  `pure_zig_record`/`openssl`, the four TLS queues, and the two pause
  directions; they never include SNI, URL, IP, request ID, connection ID, or
  stream ID. The `openssl` label value is a pre-#649 holdover in
  `encrypted_stream.BackendKind` — no shipping build constructs an
  OpenSSL-backed stream any more, so no live series ever carries it.
- configured native TLS buffer limits:
  `tardigrade_tls_buffer_config_limit_bytes{queue,limit}` for the pure-Zig
  listener's inbound ciphertext, inbound plaintext, outbound ciphertext, and
  handshake low/high/hard watermarks. These are not described as enforced by
  OpenSSL.
- reverse-proxy abort counters:
  `tardigrade_proxy_client_aborts_total`,
  `tardigrade_proxy_upstream_aborts_total`, and
  `tardigrade_proxy_local_capacity_aborts_total`. The three are mutually
  exclusive causes for one truncated transfer: the client went away, the origin
  went away, or this proxy ran out of buffer capacity after the response head
  was committed. The last is local pressure and is deliberately kept out of the
  upstream series, and out of upstream health and circuit-breaker state, so it
  cannot be mistaken for an origin fault.
- reverse-proxy streaming fallback event counter:
  `tardigrade_proxy_streaming_fallback_total{reason=...}` with fixed reasons
  `policy_disabled`, `retries_configured`, and `early_data_retry_semantics` for
  response-path eligibility plus `missing_content_length`, `body_too_large`,
  `body_dependent_middleware`, and `unsupported_route_type` for request-upload
  eligibility. Upload and response eligibility are evaluated separately, so one
  request can contribute more than one fallback event. See
  [PROXY_STREAMING.md](PROXY_STREAMING.md) for what each reason means and which
  transports stream. Unix-socket and upstream-mTLS targets stream like any other
  upstream and no longer emit a fallback reason.
- reverse-proxy upstream TTFB summary: `tardigrade_proxy_ttfb_ms`
- HTTP/1 response writer counters:
  `tardigrade_response_write_mode_total{mode=...}`,
  `tardigrade_response_writev_iovecs_total`, and
  `tardigrade_response_write_errors_total{mode=...}`. Plaintext socket writers
  use `mode="writev"` when status/headers and body are emitted as gathered
  fragments. Header-only or empty-body responses on gathered-capable writers
  serialize the head once and use `mode="single_write"`. TLS writers stay on the
  TLS library's buffered write path and are reported as `mode="tls_buffered"`
  when callers use the tracked response-write API; generic in-memory or
  compatibility writers use `mode="fallback"`.
- HTTP-level early-data counters (fixed labels only):
  `tardigrade_http_early_data_requests_total{protocol,source}`,
  `tardigrade_http_early_data_decisions_total{protocol,decision}`,
  `tardigrade_http_early_data_upstream_425_total{action}`,
  `tardigrade_http_early_data_retry_total{result}`,
  and `tardigrade_http3_early_data_compat_total{decision}`
- `forward_auth` subrequest outcomes (#761):
  `tardigrade_forward_auth_total{protocol,outcome}` with `protocol` in
  `h1`/`h2`/`h3` and fixed outcomes `allowed`, `denied`, `timeout`,
  `unavailable`, `invalid_response`, and `body_too_large`. Every fail-closed
  outcome also logs a `WARN` line naming the outcome, cause and location.
- WebSocket relaying on `proxy_websocket` locations (#812):
  `tardigrade_websocket_upgrades_total{outcome}` with fixed outcomes
  `relayed`, `upstream_refused` (the origin answered with something other
  than 101), `upstream_error` (connect failure, timeout, or an invalid 101),
  `denied` (auth, `forward_auth`, rate limit, policy, Origin allowlist or
  0-RTT), `invalid` (not a valid RFC 6455 handshake) and `capacity` (tunnel
  cap or proxy-buffer capacity); the `tardigrade_websocket_tunnels_active`
  gauge; `tardigrade_websocket_tunnel_bytes_total{direction}` with
  `client_to_upstream`/`upstream_to_client`; the
  `tardigrade_websocket_tunnel_duration_seconds` summary (`_sum`, `_count`);
  and `tardigrade_websocket_tunnel_closes_total{reason}` with `client`,
  `upstream`, `idle`, `lifetime`, `shutdown`, `reload` (a
  `proxy_websocket_reload drain` window elapsed) and `error`. A relayed handshake
  counts once in `tardigrade_requests_total` and in no status-class total.
  Established tunnels run on reactor threads, not request workers (#818):
  `tardigrade_websocket_reactor_threads` (gauge),
  `tardigrade_websocket_reactor_tunnels` (tunnels the reactor owns),
  `tardigrade_websocket_reactor_thread_tunnels_max` (most on any one thread,
  i.e. load skew), `tardigrade_websocket_reactor_handoffs_total` and
  `tardigrade_websocket_reactor_wakeups_total`. Request-worker load stays in
  the `tardigrade_worker_*` series.
- native TLS/QUIC 0-RTT anti-replay store outcomes (#368):
  `tardigrade_tls_early_data_replay_total{outcome}` with fixed outcomes
  `accepted`, `duplicate`, `capacity_rejected`, `expired`, `unavailable`, and
  `startup_quarantine`. All six series are always present (Prometheus counter
  semantics); with replay mode `disabled` or no eligible native 0-RTT path
  configured, they simply stay at zero, since no store is ever constructed
  to increment them. `duplicate` (the same replay key was presented again —
  this proves a repeat presentation, not necessarily malicious intent; a
  legitimate client retry that happens to resend the same 0-RTT flight would
  also count here) and `capacity_rejected`/`unavailable` (the store cannot
  currently vouch for 0-RTT) are always distinguishable outcomes so operators
  can tell "the same replay key was observed again" apart from "the store is
  saturated or not ready yet." `startup_quarantine` is a separate outcome
  from a genuinely unavailable store so a restart's expected quarantine
  window doesn't read the same as a runtime failure. See "Native TLS 0-RTT
  Anti-Replay Protection" below for the full guarantee this store provides.

Early-data metric label sets are intentionally bounded and never include
high-cardinality request attributes (URL, request id, stream id, host, IP,
ticket fingerprint, PSK, or binder).

Native HTTP/3/QUIC also publishes bounded runtime snapshot counters for
connection and path state. Retry counters are `retry_packets_sent`,
`retry_tokens_accepted`, and `invalid_tokens`; path counters folded from the
QUIC connection layer are `path_challenges_sent`,
`path_validations_succeeded`, `path_validations_failed`,
`path_response_mismatches`, `nat_rebindings`, `migrations`,
`migrations_blocked`, and `migrations_blocked_no_peer_cid`. These snapshots
use fixed counter names only and never include client IPs, connection IDs, or
tokens.

The latency histogram is intentionally global rather than route-labeled to keep
hot-path overhead predictable.

## Native TLS 0-RTT Anti-Replay Protection

This section documents the exact guarantee `TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MODE`
provides for the native (pure-Zig) TLS/QUIC 0-RTT path (#368). It governs only
whether an accepted 0-RTT early-data claim can be replayed — a rejection here
never fails an otherwise-valid PSK/session resumption handshake, which
continues as ordinary 1-RTT resumption.

### Configuration

| Variable | Values | Default |
| --- | --- | --- |
| `TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MODE` | `disabled`, `process_local` | `disabled` |
| `TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MAX_ENTRIES` | integer, `1..1048576` | `65536` |

Both fields are **restart-only**: the replay store/gate are constructed once
at startup and shared for the process lifetime, and rebuilding them on a
config hot reload (`SIGHUP`) would discard replay history and require a
fresh startup-quarantine handoff. A hot reload that changes either field is
therefore rejected outright (`restart required`); the previous configuration
and the already-installed store/gate stay active and coherent, rather than
publishing a config that no longer matches the actually enforced replay
behavior.

`TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MAX_ENTRIES` bounds replay-store
*capacity* only. It is independent of ordinary TLS session-resumption/cache
configuration (`TARDIGRADE_TLS_NATIVE_RESUMPTION_*`, `TARDIGRADE_TLS_SESSION_*`),
and there is deliberately no separate replay TTL/retention setting: the
recording window always comes from the existing TLS early-data age-skew/
freshness policy, so replay protection can never accidentally outlive or
undercut the freshness window that admitted the 0-RTT attempt in the first
place. An unrecognized mode or an out-of-range entry count fails
configuration validation at startup rather than silently falling back.

### Guarantee by mode

| Replay mode | Guarantee | Cluster behavior |
| --- | --- | --- |
| `disabled` (default) | The replay gate stays `.unavailable`; 0-RTT is never accepted. Ordinary 1-RTT resumption is unaffected. | Safe fallback — no anti-replay claim is made at all. |
| `process_local` | **At most one successful 0-RTT claim per replay key, per Tardigrade process, during the recording window.** | A captured 0-RTT flight can potentially be accepted once by **each** independent process a load balancer can route it to. |
| future distributed backend | Defined by the backend's advertised atomic scope (see below). | Must not be advertised as available until an authoritative distributed backend is implemented and configured. |

`process_local` is **not** cluster-safe, globally at-most-once, or
distributed replay protection. For N independent Tardigrade processes each
running their own local store:

```text
load balancer
    |
    +-- process A -> LocalStore A
    +-- process B -> LocalStore B
    +-- process C -> LocalStore C
```

the same captured 0-RTT flight can be accepted once by each process if the
load balancer can route the replay across them. **Operators requiring
cluster-wide at-most-once 0-RTT must leave 0-RTT disabled** (replay mode
`disabled`) until an authoritative distributed replay backend exists and is
configured — `process_local` must never be described or relied on as a
substitute.

This is proven live, not only asserted here: `tests/integration.zig`'s
`soak.replay.process_local_scope` (#520) runs two real Tardigrade
processes sharing one persistent ticket-key snapshot and replays the exact
same ticket identity against both, showing it is legitimately accepted
once by *each* process independently while a same-process replay is still
rejected as a duplicate — the process-local scope this section describes,
not a regression toward a cluster-wide guarantee.

0-RTT also remains replay-exposed at the HTTP application layer regardless of
this store's mode; the `Early-Data`/`425 Too Early` handling documented above
(`early_data_source`/`early_data_action`/`early_data_replay_exposed`) is a
separate, still-required layer of policy.

### Startup/restart quarantine

A `process_local` store is in-memory and loses its replay history on
restart. To avoid forgetting recent replay history and reopening a window an
attacker could exploit, a freshly constructed store rejects **all** 0-RTT
claims (`unavailable`, surfaced as the `startup_quarantine` metric outcome)
for an initial quarantine window before evaluating claims normally. Ordinary
1-RTT resumption is unaffected during quarantine — only 0-RTT is rejected.

### Capacity behavior

The store never evicts a live (unexpired) replay record to make room for a
new one — doing so would turn memory pressure into a replay bypass. Once the
configured `TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MAX_ENTRIES` capacity is
reached and no expired entries can be reclaimed, a new claim is rejected
(`capacity_rejected`): that connection's 0-RTT attempt is refused, but its
otherwise-valid 1-RTT PSK/session resumption still proceeds normally.

### Process/worker sharing

When enabled, exactly one process-scoped store is constructed at the gateway
composition root and shared — via one gate — by every native TCP worker and
the native QUIC/H3 runtime in the process. A worker-local or protocol-local
store is not an acceptable production configuration, since it would let the
same replay be accepted once per worker instead of once per process.

### Future distributed backends

`#368` defines, but does not implement, the contract a future networked
(e.g. Redis/etcd) distributed replay backend must satisfy to safely replace
`process_local`:

- atomic insert-if-absent/compare-and-set semantics across its advertised
  protection scope (an eventually-consistent `GET` then `SET` is explicitly
  **not** valid — two racing processes could both observe absence and both
  accept the same replay);
- an expiry/TTL no shorter than the supplied recording deadline;
- no `accepted` result before the claim is authoritatively committed;
- a duplicate committed key always resolves to `duplicate`;
- timeout, network failure, partial/ambiguous commit, or replication
  uncertainty always resolve to `unavailable` unless the backend can prove
  the claim outcome — never `accepted`;
- no raw ticket, PSK, binder, ClientHello, request body, or other
  application payload as stored key/value material.

Until such a backend exists and is configured, `process_local` (or
`disabled`) are the only supported modes.

## Request Tracing

Tardigrade always maintains a request identifier.

- inbound `X-Request-ID` is accepted when safe
- `X-Correlation-ID` remains supported as a legacy alias
- generated IDs are echoed back in both headers
- proxied upstream requests receive the same request ID headers

For W3C Trace Context, proxied upstream requests also propagate `traceparent`.
When no inbound `traceparent` exists, Tardigrade originates one for the hop.

`src/http/trace_context.zig` covers the wire-format handling; this is trace
propagation, not full span export.

## Resource Limits and Overload Behavior

Tardigrade is a fixed-resource edge gateway: it accepts work onto a bounded
worker pool with blocking I/O and rejects load it cannot serve rather than
allocating without bound. This section catalogs every configured limit, the
overload path it guards, the deterministic outcome when the limit is reached,
and the signal an operator should watch.

Two outcome shapes exist:

- **Deterministic HTTP response** — when an HTTP response is still possible, the
  client receives a fixed, predictable status. Accept-time rejections share the
  exact byte string `gateway_accept.overload_response_503` (a `503` with
  `Connection: close`, `Content-Length: 0`, and `Retry-After: 1`).
- **Safe socket close** — when no meaningful HTTP response can be produced (for
  example a queued fd discarded during a shutdown drain), the socket is closed
  rather than left in a partial or ambiguous state.

### Configured limits

| Scenario | Config (env) | Default | Enforced in | Outcome when reached |
|---|---|---|---|---|
| File descriptors | `TARDIGRADE_FD_SOFT_LIMIT` | OS default | `gateway_accept.applyFdSoftLimit` | Soft `RLIMIT_NOFILE` raised toward the hard cap at startup; `accept()` errors are logged, the loop yields, and the listener keeps running |
| Accept batch cap | `TARDIGRADE_ACCEPT_BATCH_LIMIT` | 64 | `gateway_accept.acceptReadyConnectionsShard` | Each listener readiness turn accepts at most this many connections before yielding back to the event loop |
| Accept fairness yield | `TARDIGRADE_ACCEPT_FAIRNESS_YIELD_EVERY` | 0 (disabled) | `gateway_accept.acceptReadyConnectionsShard` | When non-zero, stops a readiness turn after this many accepts even if the batch cap is higher; increments `tardigrade_accept_fairness_yields_total` |
| Global connection limit | `TARDIGRADE_MAX_ACTIVE_CONNECTIONS` | 0 (unlimited) | `GatewayState.tryAcquireConnectionSlot` → `.over_global_limit` | Deterministic `503`; `connection_rejections` + `error_overload` incremented |
| Per-IP connection limit | `TARDIGRADE_MAX_CONNECTIONS_PER_IP` | 0 (unlimited) | `tryAcquireConnectionSlot` → `.over_ip_limit` | Deterministic `503`; `connection_rejections` + `error_overload`; warn log names the IP |
| Connection memory budget | `TARDIGRADE_MAX_TOTAL_CONNECTION_MEMORY_BYTES` | 0 (off) | `tryAcquireConnectionSlot` → `.over_global_memory_limit` | Projected `(active+1) × per-conn estimate` over budget → deterministic `503`; `connection_rejections` + `error_overload` |
| Worker queue saturation | `TARDIGRADE_WORKER_MAX_QUEUE_DEPTH` (+ per-worker depth) | 0 (uses pool default) | `WorkerPool.submit` → `error.QueueFull` | Slot released, deterministic `503`; `queue_rejections` + `error_overload` |
| Concurrent in-flight requests | `TARDIGRADE_MAX_IN_FLIGHT_REQUESTS` | 0 (unlimited) | `GatewayState.tryAcquireRequestSlot` | Returns `503` before any request work; `error_overload` incremented |
| URI too long | `TARDIGRADE_MAX_URI_LENGTH` | 8 KiB | `request_limits.validateUriLength` | `414`-class rejection before body allocation |
| Too many headers | `TARDIGRADE_MAX_HEADER_COUNT` | 100 | `request_limits.validateHeaderCount` | `431`-class rejection before body allocation |
| Single header too large | `TARDIGRADE_MAX_HEADER_SIZE` | 8 KiB | `request_limits.validateHeaderSize` | `431`-class rejection |
| All headers too large | `TARDIGRADE_MAX_HEADERS_TOTAL_SIZE` | 32 KiB | `request_limits.validateHeadersTotalSize` | `431` before body allocation |
| Request body too large | `TARDIGRADE_MAX_BODY_SIZE` | 1 MiB | `request_limits.validateBodySize` | `413`-class rejection |
| Proxy per-stream buffer low watermark | `TARDIGRADE_PROXY_BUFFER_PER_STREAM_LOW_WATERMARK_BYTES` | 256 KiB | proxy buffer accounting; HTTP/2 stream credit | Must satisfy `low < high <= hard`. An HTTP/2 stream queue that reached the high watermark is credited nothing until it drains below this, then receives one coalesced `WINDOW_UPDATE` |
| Proxy per-stream buffer high watermark | `TARDIGRADE_PROXY_BUFFER_PER_STREAM_HIGH_WATERMARK_BYTES` | 768 KiB | proxy buffer accounting; HTTP/2 `SETTINGS_INITIAL_WINDOW_SIZE` | High-watermark transition is observable through `tardigrade_buffer_high_watermark_events_total`. This value is advertised verbatim as the streaming HTTP/2 receive window, so a well-behaved origin stops sending once a stream holds this many unconsumed bytes. A reload applies to connections opened afterwards (SETTINGS are per connection) |
| Proxy per-stream buffer hard limit | `TARDIGRADE_PROXY_BUFFER_PER_STREAM_HARD_LIMIT_BYTES` | 1 MiB | proxy buffer accounting | Bounds everything one stream owns at once, including an HTTP/2 queue and the relay buffer together. Must be at least `per_stream_high_watermark + max(proxy_stream_buffer_size, 16 KiB)` or startup/reload is rejected — otherwise an origin filling its advertised window would push the stream over its own limit. Hard-limit exceedance is observable through `tardigrade_buffer_limit_exceeded_total`. On the request direction a refusal here is *this* upload outgrowing its allowed in-flight bound → `413 payload_too_large`, distinct from an aggregate refusal's `503` |
| Proxy per-origin buffer hard limit | `TARDIGRADE_PROXY_BUFFER_PER_ORIGIN_HARD_LIMIT_BYTES` | 0 (unlimited) | HTTP/2 stream queues and HTTP/1 relay buffers, in both directions | When non-zero, must be at least the per-stream hard limit. Caps the retained buffer memory every concurrent request to one origin holds together, on both protocols. Refused before commitment → `503 proxy_buffer_saturated`; refused after → that HTTP/2 stream is reset and truncated. Never counted against upstream health. Reload applies immediately, including to origins already holding reservations |
| Proxy global buffer hard limit | `TARDIGRADE_PROXY_BUFFER_GLOBAL_HARD_LIMIT_BYTES` | 0 (unlimited) | HTTP/2 stream queues, HTTP/1 relay buffers, upload relay buffers | When non-zero, must be at least the per-stream hard limit. Process-wide ceiling across every origin and both directions, with the same pre/post-commitment behavior; reload applies immediately |
| Native TLS inbound ciphertext watermarks | `TARDIGRADE_TLS_INBOUND_CIPHERTEXT_LOW_WATERMARK_BYTES`, `TARDIGRADE_TLS_INBOUND_CIPHERTEXT_HIGH_WATERMARK_BYTES`, `TARDIGRADE_TLS_INBOUND_CIPHERTEXT_HARD_LIMIT_BYTES` | TLS core defaults | pure-Zig TLS record stream | Invalid ordering, capacity overflow, or reserve violations reject startup/reload |
| Native TLS inbound plaintext watermarks | `TARDIGRADE_TLS_INBOUND_PLAINTEXT_LOW_WATERMARK_BYTES`, `TARDIGRADE_TLS_INBOUND_PLAINTEXT_HIGH_WATERMARK_BYTES`, `TARDIGRADE_TLS_INBOUND_PLAINTEXT_HARD_LIMIT_BYTES` | TLS core defaults | pure-Zig TLS record stream | High pauses carrier reads; resume occurs only after all inbound queues drain to low |
| Native TLS outbound ciphertext watermarks | `TARDIGRADE_TLS_OUTBOUND_CIPHERTEXT_LOW_WATERMARK_BYTES`, `TARDIGRADE_TLS_OUTBOUND_CIPHERTEXT_HIGH_WATERMARK_BYTES`, `TARDIGRADE_TLS_OUTBOUND_CIPHERTEXT_HARD_LIMIT_BYTES` | TLS core defaults | pure-Zig TLS record stream | High pauses plaintext writes; hard-limit rejection does not advance write state |
| Native TLS handshake watermarks | `TARDIGRADE_TLS_HANDSHAKE_LOW_WATERMARK_BYTES`, `TARDIGRADE_TLS_HANDSHAKE_HIGH_WATERMARK_BYTES`, `TARDIGRADE_TLS_HANDSHAKE_HARD_LIMIT_BYTES` | TLS core defaults | pure-Zig TLS record stream | Handshake buffering is bounded separately from application plaintext |
| Parked keepalive backlog | idle-park timeout / `max_requests_per_connection` | — | `keepalive_park.ParkedRegistry` | Idle parked connections reaped on the timer tick (`timeouts_total`); none hold a worker while idle |

The request-size limits are enforced in two layers: the HTTP parser
(`http/headers.zig`) applies fixed backstops (per-header 8 KiB, all-headers
32 KiB, header count 100) that bound parse-time allocation regardless of
config, and the handler (`gateway_handlers.zig`) then applies the
operator-configured `request_limits` values. Configuring a value *stricter*
than the parser backstop tightens the limit; a value *looser* is still capped
by the parser backstop. All request-limit rejections are deterministic and
emit a `warn` runtime log plus the corresponding access-log status.

Notes on the two pool-style resources called out in the issue:

- **Request/relay buffer pools** (`http/buffer_pool.zig`) are caches, not hard
  caps: `acquire` always returns a buffer (reused when available, freshly
  allocated otherwise) and `release` frees anything beyond `max_cached` instead
  of growing without bound. Backpressure that actually bounds buffer demand
  comes from the connection and in-flight limits above, not from the pool.
- **Upstream connection pool / pending upstream requests** are bounded by the
  per-upstream health and active-request accounting in `GatewayState`
  (`upstream_active_requests`) together with the circuit breaker; an unhealthy
  or saturated upstream fails the affected request rather than the listener. The
  least-connections balancer sheds a saturated backend to the least-loaded
  healthy one and returns no candidate when every backend is unhealthy (the
  request is shed deterministically rather than queued without bound); the
  process-wide circuit breaker fast-fails proxied requests with HTTP `503` and
  JSON `"code":"upstream_circuit_open"` once upstream failures trip its
  configured threshold, then recovers through a half-open probe after
  `TARDIGRADE_CB_TIMEOUT_MS`. The state machine has focused coverage in
  `src/gateway_state.zig` and `src/gateway_proxy_runtime.zig`; live
  open → half-open → closed behavior is covered by
  `proxy.circuit_breaker_opens_fast_fails_and_recovers` in
  `tests/integration.zig`.
- **Log / metrics sink slow or unavailable** — access logging is best-effort and
  never blocks the request that emitted it. In buffered mode the buffer flushes
  at its configured threshold and is cleared regardless of the write outcome, so
  a stalled sink cannot grow retained memory without bound. A write the sink
  refuses is dropped (not retried) and counted, so a stalled sink is observable
  rather than silent. Bounded-buffer + drop-counting behavior is pinned by a
  fault-injecting-sink test in `src/http/access_log.zig`.

### Distinguishing overload causes

Every overload cause maps to a distinct signal so operators can tell them apart
without reading source:

- **Metrics** — `tardigrade_connection_rejections_total` counts connection-slot
  rejections (global / per-IP / memory); `tardigrade_queue_rejections_total`
  counts worker-queue saturation; `tardigrade_error_overload_total` aggregates
  both accept-time families. `active_connections`, `worker_queued_jobs`, and
  `worker_queue_capacity` show how close the gateway is to its caps.
- **Accept batching** — `tardigrade_accept_batch_size` records how many
  connections each listener readiness turn drained; `tardigrade_accept_batches_total`
  counts non-empty accept turns; `tardigrade_accept_fairness_yields_total` shows
  when `TARDIGRADE_ACCEPT_FAIRNESS_YIELD_EVERY` forced the loop to give active
  connections, parked keepalives, timers, or sibling listener shards another turn.
- **Logs** — each accept-time rejection emits a distinct `warn` runtime log:
  per-IP limit names the offending IP, the global and memory limits each have
  their own message, and queue-submit failures log the submit error. Request
  validation rejections surface through the access log `error_category`.

The metrics that drive these counters are unit-tested in
`src/http/metrics.zig`; the deterministic accept-time response is pinned by a
regression test in `src/gateway_accept.zig`.

### Operator troubleshooting

| Symptom | Likely cause | First checks |
|---|---|---|
| Clients see `503` + `Retry-After`, `connection_rejections` climbing | Global or per-IP connection cap, or memory budget, reached | Compare `active_connections` to `TARDIGRADE_MAX_ACTIVE_CONNECTIONS`; grep runtime logs for `connection limit reached` / `memory estimate limit`; check for a single hot IP |
| `503`s with `queue_rejections` climbing while CPU is not saturated | Worker queue full faster than workers drain | Watch `worker_queued_jobs` vs `worker_queue_capacity` and `worker_active_jobs`; raise worker count or `TARDIGRADE_WORKER_MAX_QUEUE_DEPTH`, or investigate slow upstreams holding workers |
| `503`s with no rejection counters moving | In-flight request cap hit | Review `TARDIGRADE_MAX_IN_FLIGHT_REQUESTS` against expected concurrency |
| `accept error` logs, new connections refused | File-descriptor exhaustion | Verify `TARDIGRADE_FD_SOFT_LIMIT` and the OS hard `RLIMIT_NOFILE`; look for fd leaks via `active_connections` not returning to baseline |
| `413` / `431` / `414` in access logs | Oversized body, headers, or URI | Confirm the configured request limits match legitimate client traffic before raising them |
| Tail latency spikes under many idle keepalive clients | Parked-connection backlog or too-long idle timeout | Watch parked `timeouts_total`; tune the idle-park timeout and `max_requests_per_connection` |
| Gaps in access logs, throughput otherwise normal | Log sink (stderr pipe / syslog) slow or unavailable | Logging is best-effort: dropped lines are counted internally and the request path is never blocked; check the downstream log collector / pipe rather than the gateway |
| Proxied requests fail fast with `503` / `upstream_circuit_open` and no upstream contact | Circuit breaker open | Expected protection after repeated upstream failures; confirm the upstream is healthy — the breaker recovers via a half-open probe once `TARDIGRADE_CB_TIMEOUT_MS` elapses |

Tuning principle: raise a limit only after confirming the gateway has headroom
(CPU, memory, fds) to honor it. The limits exist so that exhaustion produces a
predictable `503` or a clean socket close instead of unbounded allocation or
worker starvation.

## Reload and Shutdown

Tardigrade supports zero-downtime configuration reload and graceful shutdown.
Both are driven by POSIX signals delivered to the running process (the
`tardi reload` / `tardi stop` CLI commands send these for you).

| Signal | Effect |
|---|---|
| `SIGHUP` | Hot-reload configuration from the environment / config file. |
| `SIGUSR1` | Reopen the error log (log rotation). |
| `SIGUSR2` | Begin graceful shutdown (alias of the upgrade path). |
| `SIGTERM` / `SIGINT` | Begin graceful shutdown. |

### Hot reload (SIGHUP)

On `SIGHUP` the gateway re-reads its configuration and applies it without
dropping connections:

1. **Load** the new configuration from the environment / config file.
2. **Validate** it. Invalid configuration is rejected here.
3. **Install** the new config version through a lease-counted store
   (`ReloadableConfigStore`): in-flight requests keep their request-scoped config
   lease, and the old version is retired only after its last lease is released.
   New requests pick up the new version once installation completes.

Guarantees:

- **A failed reload before config publication keeps the previous published
  config active** for request routing and config leases; the failure is recorded
  and logged. Reload-owned runtime resources are not fully transactional.
- **In-flight requests are not dropped** by a reload; they keep their
  request-scoped config lease but can observe reloaded process-shared policy.
- Reload status is queryable at `GET /tardigrade/reload/status`, which returns
  `{"ok": <bool|null>, "at_ms": <ts>, "error": <string|null>}`.

### Graceful shutdown and drain

On a shutdown signal the accept loop stops taking new TCP connections and the
TCP worker pool drains:

- **Active (already-dispatched) TCP handlers are allowed to finish** naturally.
  Requests whose handler starts after shutdown has been requested cap their
  request deadline to the drain window when no stricter deadline exists.
- **Queued, queue-owned, not-yet-started TCP accepted sockets** that remain when
  the drain deadline elapses are **force-closed**. A drain timeout of `0`
  abandons queued jobs immediately and closes queue-owned accepted sockets.
- Native HTTP/3 uses the same timeout as a hard H3 drain deadline; H3 deadline
  expiry is not folded into the TCP worker-pool drain timeout metric.
- After the drain completes the worker threads are joined and the process exits.

### Reload / shutdown observability

Logs (runtime, via `src/http/logger.zig`):

- `configuration hot-reload starting` / `configuration hot-reload applied`
- `config reload failed during load` / `config reload rejected by validation` /
  `config reload allocation failed` / `config reload bookkeeping failed`
- `Shutdown requested; draining active connection work (timeout=… active_connections=…)`
- `drain timeout elapsed; force-closed N queued connection(s)` (TCP worker-pool timeout)
- `Graceful shutdown complete (forced_closes=… drain_timed_out=…)` (TCP worker-pool outcome)

Metrics (`/status/metrics`):

| Metric | Meaning |
|---|---|
| `tardigrade_reload_attempts_total` | Reloads started (SIGHUP received and processed). |
| `tardigrade_reload_success_total` | Reloads that loaded, validated, and installed. |
| `tardigrade_reload_failure_total` | Reloads rejected; previous config kept. |
| `tardigrade_drain_total` | Graceful-shutdown drains started. |
| `tardigrade_drain_timeouts_total` | TCP worker-pool drains that reached a positive drain deadline before worker jobs finished; does not report native H3 deadline expiry. |
| `tardigrade_drain_forced_closes_total` | Queue-owned unstarted TCP accepted sockets closed on worker drain expiry or an immediate zero-timeout shutdown. |

A healthy reload increments `reload_attempts_total` and `reload_success_total`
together; a rejected reload increments `reload_attempts_total` and
`reload_failure_total` while the reload-status endpoint reports `ok: false` with
the rejection reason.

## QUIC / HTTP-3 (pure-Zig backend)

The pure-Zig QUIC/H3 stack (#240) has its own transport-level observability
surface: qlog event tracing, TLS key logging for local decryption, runtime
snapshot counters, and Prometheus counters designed in
[`QUIC_QLOG.md`](QUIC_QLOG.md). qlog and keylog outputs are **disabled by
default** and **sensitive/debug-only**: a key log decrypts the connection. They
are for local debugging and interop diagnosis, never a production default.
