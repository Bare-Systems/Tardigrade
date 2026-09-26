# Reverse-proxy streaming

Tardigrade can relay reverse-proxy traffic incrementally instead of
materializing whole bodies in memory. This document is the contract for that
behavior: which combinations stream, which fall back to the bounded buffered
path, how a fallback is observed, and what streaming costs in retry and
middleware semantics.

Related: [OBSERVABILITY.md](OBSERVABILITY.md) for the exported metric names,
[TIMEOUTS.md](TIMEOUTS.md) for the per-phase deadlines that bound a stalled
stream, and [UPSTREAM_POOLING.md](UPSTREAM_POOLING.md) for connection reuse.

## Policy

Streaming is off by default. It is selected globally and can be overridden per
route.

**Global** — `TARDIGRADE_PROXY_STREAMING_MODE`, or the `proxy_streaming_mode`
directive in a config file:

| Value | Aliases | Effect |
| --- | --- | --- |
| `off` | `buffered` | Bounded buffered path for every request. |
| `response` | `responses` | Upstream responses stream; request bodies are buffered. |
| `full` | `request_response`, `request-response` | Eligible request bodies stream as well. |

**Per route** — the `proxy_streaming` (or `proxy_streaming_mode`) directive
inside a `location` block, or the `stream:<value>` location option:

| Value | Effect |
| --- | --- |
| `inherit` | Default. Use the global mode. |
| `off` / `buffered` | Force the buffered path for this route. |
| `response` / `responses` | Stream responses for this route even when the global mode is `off`. |
| `full` / `request_response` / `request-response` | Stream responses and eligible uploads for this route. |

A route override replaces the global mode for that route in both directions; it
never partially merges with it.

```nginx
proxy_streaming_mode off;          # global default: buffered

location /bulk/ {
    proxy_pass http://origin;
    proxy_streaming full;          # stream uploads and downloads on this route
}
```

## Supported matrix

Response streaming and request-upload streaming are decided independently, so a
route may stream a large response while buffering a small upload.

### Upstream responses

| Upstream framing | Behavior |
| --- | --- |
| `Content-Length` | Streamed; re-chunked downstream. |
| `Transfer-Encoding: chunked` | Decoded incrementally and re-chunked downstream; chunk extensions and trailers are not forwarded. |
| Close-delimited (HTTP/1.0-style) | Streamed; the upstream connection is not reusable afterwards. |
| Bodiless (HEAD, 1xx, 204, 304) | Head relayed, no body read. |
| HTTP/2 upstream | Streamed over the shared per-origin connection; the stream receive window is replenished only as the downstream relay drains, so a slow client backpressures the origin. |

An HTTP/1.1 upstream connection is returned to the keep-alive pool only when the
framing ended exactly on a message boundary. Extra bytes, a truncated body, or a
close-delimited response mark the connection unusable rather than risking a
desynchronized pipeline.

### Client uploads (`full` mode only)

| Client framing | HTTP/1.1 upstream | HTTP/2 upstream |
| --- | --- | --- |
| `Content-Length` | Streamed with the same `Content-Length`. | Streamed as flow-controlled DATA frames. |
| `Transfer-Encoding: chunked` | Decoded incrementally and re-framed as `Transfer-Encoding: chunked`. | Decoded incrementally and sent as DATA frames terminated by `END_STREAM`; no `Content-Length` is synthesized. |

Chunked uploads are re-framed rather than forwarded byte-for-byte, so chunk
extensions and trailers sent by the client are consumed and dropped, not passed
to the origin. The decoded payload is counted against the configured
request-body maximum while it is relayed: an upload that outgrows the maximum is
rejected with `413` mid-relay, and malformed chunk framing is rejected with
`400`. Neither is attributed to the origin's health.

Because either failure is only detectable once the offending bytes arrive, the
origin has by then received a partial request. How that is cleaned up depends on
the upstream protocol: an HTTP/1.1 connection carries only this request, so it is
closed rather than returned to the pool; an HTTP/2 connection is shared, so only
the affected stream is reset with `CANCEL` and the connection stays reusable for
unrelated multiplexed requests unless it is independently unhealthy.

A streamed upload disables downstream keep-alive for that connection.

### Transports

Unix-socket and mTLS upstreams stream. The streaming relay owns AF_UNIX
connect and pooling directly, and it uses the same `UpstreamTlsOptions` —
including the client certificate and key — as the buffered path. A Unix-socket
upstream always uses HTTP/1.1: there is no origin for the HTTP/2 pool to key or
ALPN-negotiate.

## Fallback reasons

When a request cannot stream, it takes the bounded buffered path and the reason
is recorded on `tardigrade_proxy_streaming_fallback_total{reason=...}` and
logged at debug level with the request's correlation ID.

| Reason | Applies to | Meaning |
| --- | --- | --- |
| `policy_disabled` | response, upload | The effective policy for the route does not enable this direction. |
| `retries_configured` | response, upload | The retry budget resolves to more than one attempt, and a streamed exchange cannot be replayed. |
| `early_data_retry_semantics` | response | The request arrived as replay-exposed TLS early data and needs 425 orchestration, which requires a retryable exchange. |
| `missing_content_length` | upload | A body-bearing method sent neither `Content-Length` nor `Transfer-Encoding`. |
| `body_too_large` | upload | The declared `Content-Length` exceeds the request-body maximum. |
| `body_dependent_middleware` | upload | Rewrite, return, conditional, internal-redirect, mirror, or `auth_request` rules are configured, and they may read or duplicate the body. |
| `unsupported_route_type` | upload | The request did not match a route, or matched a route whose action is not a direct `proxy_pass`. |

Upload and response eligibility are evaluated separately, so a single request can
contribute more than one fallback event.

Streaming eligibility for an upload is decided from the request head, before any
body byte is read. If routing later resolves to something the streaming path
cannot serve, the request fails with `502` rather than silently buffering — the
client bytes have already been committed and cannot be replayed.

## Retry and middleware contract

Streaming trades replayability for bounded memory. The boundaries are:

- **A streamed response cannot be retried once downstream bytes are committed.**
  The response head reaches the client before the body is known to be complete,
  so a mid-body upstream failure surfaces as a truncated body and an
  `tardigrade_proxy_upstream_aborts_total` event, not as a retry. Requests are
  only eligible for streaming when the retry budget is exactly one attempt.
- **A streamed upload is not replayable once client bytes are consumed.** The
  stale-pooled-connection retry that the buffered path performs is disabled for
  streamed uploads even before any response byte exists, because the request
  body has already been forwarded and cannot be re-sent. For replayable bodies
  the retry follows the zero-byte replay policy in
  [UPSTREAM_POOLING.md](UPSTREAM_POOLING.md#stale-connection-replay-policy-785).
- **Body-dependent middleware requires buffering.** Rewrite, return,
  conditional, internal-redirect, mirror, and `auth_request` all need the whole
  body, or need to duplicate it. Routes configured with any of them fall back
  with `body_dependent_middleware`. Making them work with streaming needs an
  explicit tee, not an incidental buffer.
- **Streaming mode is a route behavior decision, not a guarantee.** Enabling
  `full` asks for streaming where it is supported; it does not promise that
  every target and middleware combination can stream. The fallback reasons above
  are the supported way to find out what actually happened.

## Memory

The HTTP/1 relay copies through one fixed buffer per direction and writes to the
far side before reading more, so user-space relay memory does not grow with body
size. The response buffer is `proxy_stream_buffer_size` (floored at 16 KiB); the
upload buffer is a fixed 16 KiB. The HTTP/2 relay is bounded by the per-stream
receive window, replenished only as the downstream relay drains.

### HTTP/2 response bounds

The streaming receive window an HTTP/2 upstream connection advertises is
`TARDIGRADE_PROXY_BUFFER_PER_STREAM_HIGH_WATERMARK_BYTES` — the same value the
accounting model treats as "this stream's queue is full" — so a well-behaved
origin stops sending exactly there. An origin that overruns the window is
committing a flow-control violation: that stream is failed, reset upstream with
`RST_STREAM(FLOW_CONTROL_ERROR)` so the origin actually stops sending on it, and
left discard-only. Other streams on the connection are unaffected.

Credit is then returned with hysteresis rather than chunk by chunk. While a
stream's queue sits at or above the high watermark, downstream-consumed bytes
are accumulated but **not** credited back to the origin; the accumulated total
is sent as a single `WINDOW_UPDATE` once the queue drains below
`TARDIGRADE_PROXY_BUFFER_PER_STREAM_LOW_WATERMARK_BYTES`. Crediting each chunk
as it drained would let the origin refill the queue immediately and the
watermark band would never actually pause anything. Each transition is visible
as `tardigrade_buffer_read_pauses_total{side="upstream"}` and
`tardigrade_buffer_read_resumes_total{side="upstream"}`.

Per-stream bounds alone do not bound the process: N concurrent slow streams
retain up to N windows. Two aggregate hard limits close that gap:

| Limit | Scope |
| --- | --- |
| `TARDIGRADE_PROXY_BUFFER_PER_ORIGIN_HARD_LIMIT_BYTES` | every concurrent request to one upstream origin, on either protocol |
| `TARDIGRADE_PROXY_BUFFER_GLOBAL_HARD_LIMIT_BYTES` | the whole process, across all origins |

The relay buffer the response is copied into is reserved as well, for as long
as it is relaying. That matters because it is a *second* copy: bytes are read
out of the stream queue into the buffer, and the queue's own reservation is not
released until the downstream write has completed. While a slow client blocks
in that write, both copies are owned at once, so charging only the queue let N
concurrent slow responses hold roughly `N × buffer` beyond every configured
ceiling with nothing in the accounting to show it. The reservation is taken
before the response head is committed downstream — a refusal is therefore a
clean `503` — and released on every exit. A bodiless response never touches the
buffer and is not charged for it.

The two are bounded **together** by the per-stream hard limit, not separately.
With a limit each, a single stream could own `per_stream_hard_limit` of queue
*and* a relay buffer on top while neither reported an exceedance — so the
per-stream hard limit would not actually limit what one stream owns. That is
enforced by holding the relay's size back from the queue's own hard limit when
the stream is opened, so the two sum to the configured limit at most.

Deliberately reserved headroom rather than a budget object the two share: such
an object would have to outlive both a worker's relay reservation and a stream
the connection's reader thread can still be inside, and streams are destroyed
outside that connection's state lock. Headroom needs no shared lifetime, and
bounds the sum just as well. The queue keeps its own accounting of its
*logical* length, because that — not total ownership — is what the high/low
watermarks and the `WINDOW_UPDATE` hysteresis run on.

Nothing is allocated before it is reserved, either. The relay buffer is
allocated only once a reservation has admitted it, so requests waiting on a
slow origin hold no relay memory at all: allocating first and refusing
afterwards would let concurrent requests reach the memory peak the limit exists
to prevent, and be turned away only once it had already happened.

For that budget to be satisfiable, the hard limit has to have room for both at
once, so configuration requires:

```
per_stream_hard_limit >= per_stream_high_watermark + max(proxy_stream_buffer_size, 16 KiB)
```

Without it, an origin doing exactly what the advertised window invites — filling
it to the high watermark — would push the stream past its own hard limit and
have its response truncated. Startup and reload reject such a policy instead.
The shipped defaults satisfy it with room to spare (768 KiB + 16 KiB ≤ 1 MiB).

Both limits default to `0`, which means unlimited. Reservations are taken
*before* any memory is committed, and they track each queue's **retained
allocation** rather
than its logical length — a drained queue that still owned its peak buffer
would otherwise be invisible to these limits. A queue's storage (and its
reservation) is released as soon as it drains empty.

This is also why the current-byte gauges move on different schedules:
`tardigrade_buffered_bytes_current{scope="stream"}` reports logical queue
occupancy, while `scope="global"` reports retained allocation. A partially
drained queue shows a lower stream value than global value; that is the buffer
it still owns.

**Do not compare `tardigrade_buffered_bytes_current{scope="global"}` with
`TARDIGRADE_PROXY_BUFFER_GLOBAL_HARD_LIMIT_BYTES`.** That gauge is a roll-up of
every proxy-owned buffer, including paths the limit does not govern — most
notably the bounded buffered compatibility path, which has its own hard cap in
`TARDIGRADE_MAX_BUFFERED_UPSTREAM_RESPONSE_BYTES`. Under mixed traffic the
roll-up is larger than the quantity being checked, so reading it as "how close
am I to the limit" overstates pressure.

The series to put next to the limit is
`tardigrade_proxy_buffer_aggregate_bytes_current{direction,scope="global"}`,
which is read directly from the account that performs the enforcement. It
covers HTTP/2 stream queues, HTTP/1 relay buffers in both directions, and
request-direction upload buffers on both protocols.

The per-origin equivalents are
`tardigrade_upstream_h2_pool_buffered_bytes{upstream,direction}` for HTTP/2
origins and `tardigrade_upstream_pool_buffered_bytes{upstream,direction}` for
HTTP/1 ones, with `…_buffer_limit_exceeded_total` counterparts. Both are read
from the accounts that enforce
`TARDIGRADE_PROXY_BUFFER_PER_ORIGIN_HARD_LIMIT_BYTES`, so either is directly
comparable with it.

#### What a refusal does

The behavior depends on whether the downstream response has been committed.
That question is decided, not raced: the worker claims the commitment boundary
under the connection's state lock immediately before writing the head, so a
refusal that physically happened first is always treated as pre-commitment.

- **Before the response head is written** the request fails with `503` and the
  code `proxy_buffer_saturated`. This covers the reader rejecting DATA between
  decoding the origin's headers and the worker relaying them, and it also
  covers a streaming upload: an origin can answer while the request body is
  still being written, so a capacity refusal can surface through the *next
  upload write* rather than through the response path. All of these are *local*
  saturation, so none is recorded against upstream health or the circuit
  breaker, and none is retried — a retry would meet the same wall.
- **After commitment** the status can no longer change. The stream is reset
  upstream immediately (`RST_STREAM(CANCEL)`), the downstream response is
  truncated, every scope's reservation is released, and the truncation is
  logged. It is counted in `tardigrade_buffer_limit_exceeded_total` at the
  refusing scope but, again, is **not** counted as an upstream failure — local
  memory pressure must not trip a healthy origin's failure policy.

In both cases the stream becomes discard-only: DATA still in flight for it is
dropped without reserving again, so a single refusal cannot be re-counted or
re-queue bytes behind an error the consumer has not seen yet. Unrelated
streams — including others on the same connection — are untouched, and a
refusal rolls back cleanly across scopes, so a stream the origin scope rejects
never leaves bytes reserved at the global scope.

#### Reload semantics

Aggregate hard limits apply immediately, including to origins that already hold
reservations. "Immediately" is exact rather than approximate: a reservation and
a reload are linearizable against each other, so a reservation either commits
before the new limit is published — and is then the "already reserved above the
new limit" case, which stays reserved — or commits after it and is refused.
A reservation cannot read the old limit, be overtaken by the reload, and still
commit under the policy it read.

The per-stream policy — and the receive window derived from it —
applies to connections opened after the reload: `SETTINGS_INITIAL_WINDOW_SIZE`
is negotiated once per connection, and a peer already holding credit is still
judged by what it was granted. Each connection therefore pins the complete
low/high/hard policy it advertised, and every stream on it is measured against
that, never against a newer snapshot.

That is *every* per-stream decision, not just the queue: the headroom held back
for the relay buffer, and the relay buffer itself, are sized from the
connection's pinned policy too. Taking any of them from the current config would put one stream
under two generations of policy at once — its queue judged by what the
connection advertised and the rest by whatever the config says now — which on a
raise lets a stream own more than the hard limit it is documented to be
measured against, and on a shrink refuses a stream still operating inside the
window that connection granted it. Either way the outcome would depend on
whether a request happened to land on a pre-reload pooled connection.

The relay buffer is a case of this worth naming. `proxy_stream_buffer_size` can
be raised by a reload, which would ask a request on an older connection for a
buffer that connection's pinned policy was never validated to cover. The HTTP/2
relay therefore **allocates** it only once the connection is acquired, at the
size that policy can account for — at least 16 KiB, since that is the smallest
relay any validated policy was checked against.

Allocating the larger size and using only part of it would not do. These limits
bound *retained allocation*, not bytes currently populated, so an untouched
remainder is still real per-request memory that no scope is charged for: N
concurrent streams on such a connection would hold N times the difference
beyond every configured ceiling. What is allocated and what is accounted are
deliberately the same number. (The HTTP/1 path keeps allocating and charging at
the current config's size — an HTTP/1 connection pins no policy of its own, so
there is no older generation for its buffer to have to fit inside.)

### HTTP/1 aggregate bounds

An HTTP/1 relay has no queue, so the per-stream watermarks have nothing to
pause; what it has is a fixed buffer per direction, and that buffer is what the
aggregate scopes account. The response relay reserves
`proxy_stream_buffer_size` (floored at 16 KiB) once, immediately after the
origin's response head is parsed and before that head is written downstream;
the upload relay reserves its fixed 16 KiB before the request head goes out.

Both clear the per-origin scope as well as the global one. That scope is the
one that matters here: a fixed buffer bounds one request, but nothing bounds
how many requests an origin has in flight, so without it a single slow origin
could hold `concurrency × buffer` with every individual request looking
perfectly well behaved. Origins are keyed the way the connection pool keys them
(`http:host:port`, `https:host:port`, `unix:/path`), and an origin reached over
TLS whose ALPN negotiated HTTP/1.1 is accounted under its HTTP/1 key rather
than the HTTP/2 pool key it was acquired through — otherwise one origin's
memory would be split across two limits.

The account exists whenever an origin is proxied to, including when connection
pooling is disabled: it bounds memory, which pooling has no bearing on.

**An HTTP/1 response can never meet a capacity refusal after commitment.** Its
whole reservation is taken up front, before the head is written, so a refusal
is always a clean pre-commitment `503 proxy_buffer_saturated` — the
post-commitment reset-and-truncate path described above is HTTP/2-only, because
only HTTP/2 reserves again as more DATA arrives.

### Request-direction bounds

Uploads are accounted the same way, under
`direction="downstream_to_upstream"`. Both relays copy through one fixed buffer
for the life of the upload, so what is reserved is that buffer — reserved once,
not once per chunk — plus whatever the relay still holds from the request head.

That second amount differs by framing, because the two retain different parts of
the same slice. A `Content-Length` upload keeps only the body bytes it will
forward, and gives them back as soon as they are written. A chunked upload hands
the whole raw remainder to the decoder, framing octets included, so the raw
length is what is reserved; the relay releases it incrementally as the decoder
consumes it, rather than holding the request head's peak for the whole upload.

**The reservation is taken before anything is sent upstream** — before the
HTTP/1 request head is written, and before HTTP/2 `HEADERS` go out. This is not
just bookkeeping: reserving inside the relay would mean a local `413`/`503`
could only be raised once the origin had already received a real, possibly
side-effecting request whose body then never arrives. Reserving first makes a
refusal something the origin never sees.

An upload therefore reserves a bounded amount that does not grow with the body,
and the reservation is released on every exit: completion, client abort,
cancellation, timeout, malformed chunk framing, and upstream failure alike.

**The claim ends when the upload does, not when the exchange does.** On HTTP/2
the same relay buffer goes on to serve the response, so the request-direction
reservation is released explicitly at the upload/response boundary; carrying it
through the response would occupy upload capacity for as long as the response
took, which is long enough for one slow response to make an unrelated upload
fail with a `503` it should never have seen. (HTTP/1 has no equivalent window —
the request-sending function returns, releasing its reservation, before the
response is read.) The buffer is then re-reserved in the response direction for
the response relay; see below.

Every upload reservation clears both
`TARDIGRADE_PROXY_BUFFER_PER_ORIGIN_HARD_LIMIT_BYTES` and
`TARDIGRADE_PROXY_BUFFER_GLOBAL_HARD_LIMIT_BYTES`, on either protocol.

Refusals split by what ran out, because the two mean different things to the
client:

| Refused at | Status | Meaning |
| --- | --- | --- |
| per-stream hard limit | `413` `payload_too_large` | *this* upload's in-flight bytes exceed the bound it is allowed |
| per-origin or global hard limit | `503` `proxy_buffer_saturated` | the proxy is out of room for anybody |

Both are raised before the response head is committed, and neither is recorded
against upstream health — a healthy origin must not be blamed for this proxy's
memory pressure.

### Seeing a slow origin on HTTP/1

The HTTP/1 relay has no queue whose depth could cross a watermark: it reads the
client only after the upstream write completes, so a full upstream send buffer
*is* a pause of downstream reads. Before each chunk the relay asks (with a
zero-timeout `poll`, so a healthy origin pays nothing and moves no counters)
whether the origin can take more bytes. When it cannot, the transition is
recorded as `tardigrade_buffer_read_pauses_total{side="downstream"}`, and the
matching resume once the write goes through.

Only a genuinely full send buffer counts. `poll` also reports a descriptor
ready for `POLLERR`/`POLLHUP`/`POLLNVAL`, so readiness alone does not mean
writable and its absence does not mean full; the three outcomes are separated
deliberately, because a broken origin recorded as a stall would show up as
backpressure on a connection that is simply dead.

Only transitions are counted: a relay stalled across many chunks reports one
pause and one resume, not one per write, and a relay torn down mid-stall still
reports its resume — so the difference between the two counters reads as "how
many uploads are stalled right now" rather than drifting by one per abort. A
write that begins to block only *after* the check passes is deliberately not
counted; an origin that has genuinely stopped consuming keeps the buffer full
across iterations and is caught, while a momentary block is not a backpressure
event.

## Tuning the buffer limits

The five limits answer three different questions, and it helps to set them in
that order rather than as one block of numbers.

### 1. Per-stream: how much should one slow consumer be allowed to hold?

`TARDIGRADE_PROXY_BUFFER_PER_STREAM_HIGH_WATERMARK_BYTES` is the important one:
on HTTP/2 it is advertised verbatim as the receive window, so it decides how
far ahead of a slow client an origin may run. It is a throughput/memory trade,
not a safety setting. Too low and a fast origin stalls waiting for credit on
every long response; too high and each concurrent slow stream is expensive. The
768 KiB default suits typical WAN round trips; raise it for high
bandwidth-delay-product origins (a large intra-datacenter transfer), lower it
when concurrency matters more than per-stream speed.

`…_LOW_WATERMARK_BYTES` sets the hysteresis band. The gap between low and high
is how much a stream drains before the origin is credited again, so a narrow
band means frequent small `WINDOW_UPDATE`s and a wide one means the origin
pauses for longer. Something like a third of high is a reasonable start; the
default pair (256 KiB / 768 KiB) is that ratio.

`…_PER_STREAM_HARD_LIMIT_BYTES` is a safety net, not a tuning knob. It bounds
everything one stream owns at once, so it must cover a full window *plus* the
relay buffer the response is copied into:

```
per_stream_hard_limit >= per_stream_high_watermark + max(proxy_stream_buffer_size, 16 KiB)
```

Startup and reload reject anything less, because an origin filling the window
it was advertised would otherwise push the stream past its own limit and have
its response truncated. Beyond that floor, leave headroom for DATA already in
flight when the window closes — roughly 1.3× the high watermark is enough; the
defaults use 1 MiB against 768 KiB.

On the request direction this limit does double duty: an upload whose in-flight
bytes exceed it is a `413`, so it is also the answer to "how many bytes of one
upload may this proxy hold at once".

### 2. Per-origin: how much should one bad origin be allowed to cost?

`TARDIGRADE_PROXY_BUFFER_PER_ORIGIN_HARD_LIMIT_BYTES` bounds what every
concurrent request to a single origin holds together, on both protocols. Size
it from the concurrency you want to sustain to that origin — but what one
request costs is protocol-dependent, so the multiplier is too:

| Protocol | What one request holds | Sizing |
| --- | --- | --- |
| HTTP/1 | A fixed relay buffer: `max(proxy_stream_buffer_size, 16 KiB)` for a response, 16 KiB for an upload. It does not grow with the body. | `per_origin ≈ concurrent requests × relay buffer` |
| HTTP/2 | The stream's queue, which fills toward the per-stream high watermark under a slow consumer, plus the response relay buffer while it is relaying. | `per_origin ≈ concurrent slow streams × (per_stream_high_watermark + relay buffer)` |

Because HTTP/1's cost per request is fixed and small, an origin served over
HTTP/1 sustains far more concurrency per byte of budget than an HTTP/2 origin
whose streams each fill a window. Size against whichever protocol the origin
actually negotiates.

The floor is the per-stream hard limit: it guarantees that one
maximum-size stream fits, **not** that only one request fits. With the shipped
defaults a 1 MiB floor admits roughly 64 concurrent 16 KiB HTTP/1 relay
reservations in one direction, and it admits several HTTP/2 streams whenever
each retains less than the full per-stream hard limit. To admit exactly one
HTTP/1 request at a time, set the limit to that relay buffer size — which
requires lowering the per-stream hard limit to match, since the floor still
applies.

Default `0` means unlimited, which is only appropriate when the global limit is
doing all the work and no single origin can be trusted less than the others.

The value to watch next to it is
`tardigrade_upstream_pool_buffered_bytes{upstream,direction}` (HTTP/1) or
`tardigrade_upstream_h2_pool_buffered_bytes{upstream,direction}` (HTTP/2). Both
come from the enforcing account, so they are directly comparable with the
limit. A non-zero
`…_buffer_limit_exceeded_total{upstream,direction}` on one origin while others
stay quiet is the signal this limit is designed to produce: that origin is
absorbing memory and is being contained rather than allowed to spread.

### 3. Global: what is this process's ceiling?

`TARDIGRADE_PROXY_BUFFER_GLOBAL_HARD_LIMIT_BYTES` is the process-wide backstop
across all origins and both directions. Derive it from the memory you are
willing to spend on proxy body buffers — not from the sum of the per-origin
limits, which is deliberately allowed to oversubscribe it. Oversubscribing is
the point: per-origin containment stops one origin monopolising memory, and the
global limit stops all of them together exceeding the box.

Compare it with
`tardigrade_proxy_buffer_aggregate_bytes_current{direction,scope="global"}`,
**not** with `tardigrade_buffered_bytes_current{scope="global"}`. The latter
also rolls up the bounded buffered compatibility path, which is capped
separately by `TARDIGRADE_MAX_BUFFERED_UPSTREAM_RESPONSE_BYTES`, so under mixed
traffic it reads higher than the quantity actually being checked.

### Reading the metrics together

| Symptom | Series | What it means |
| --- | --- | --- |
| Steady `tardigrade_buffer_high_watermark_events_total{scope="stream"}` with pauses and resumes tracking each other | per-stream | Working as designed: consumers are slower than origins and flow control is doing its job. Not a problem unless throughput matters more than memory, in which case raise the high watermark |
| `tardigrade_buffer_read_pauses_total` running well ahead of `…_resumes_total` | either side | Relays are stalled *right now*, and the count is how many. A persistent gap is a slow peer, not a leak — the counters are balanced on teardown |
| `tardigrade_buffer_limit_exceeded_total{scope="stream"}` climbing | per-stream hard limit | Uploads are outgrowing their allowed in-flight bound (`413`s). Either clients legitimately send more than the limit allows, or the limit is set below what one request needs |
| `tardigrade_buffer_limit_exceeded_total{scope="origin"}` climbing | per-origin hard limit | Concurrency to one origin exceeds its budget: `503 proxy_buffer_saturated`. Raise the limit, cap concurrency to that origin, or fix the origin |
| `tardigrade_buffer_limit_exceeded_total{scope="global"}` climbing | global hard limit | The process is out of room. Check whether one origin dominates the per-origin gauges before raising the global ceiling |
| `tardigrade_proxy_local_capacity_aborts_total` climbing | post-commitment refusals | HTTP/2 responses truncated after their head was committed. Only reachable on HTTP/2, and always local pressure — deliberately excluded from upstream health and the circuit breaker |
| A current-byte gauge not returning to zero when traffic stops | any scope | This would be a reservation leak. Every scope returns to zero after success, client abort, cancellation, timeout, upstream failure, and teardown, and that is asserted directly by the tests |

Configured values are exported as
`tardigrade_buffer_config_limit_bytes{direction,scope,limit}`, so a dashboard
can plot each gauge against the limit in force without the limits being
hard-coded into it.

### Benchmarks and regression thresholds

This document covers what the limits do and how to read them. Representative
memory/latency benchmark scenarios for these paths are owned by #149, and CI
performance-regression thresholds and artifacts by #150; neither is configured
here.
