# HTTP Proxy Security Hardening

This document describes Tardigrade's intended security behavior at each HTTP
proxy trust boundary. It is the authoritative reference for what the codebase
guarantees and what operators must configure for safe deployments.

## Threat Model Summary

Tardigrade sits between untrusted external clients and trusted internal
upstreams. The attack surface at this boundary includes:

- Request smuggling via ambiguous body framing (TE/CL conflicts, duplicate
  headers, malformed chunked encoding).
- Header injection and log poisoning via unvalidated header names/values.
- Trust boundary bypass by forwarding client-controlled proxy identity headers.
- Information disclosure via upstream technology headers.
- Directory traversal via path-encoded sequences in static file serving.
- Cross-site tracing (XST) via TRACE method reflection.
- Correlation-ID spoofing to poison audit logs.

## 1. Hop-by-Hop Header Stripping

**RFC 7230 §6.1.** Hop-by-hop headers must not be forwarded beyond the next
hop. Tardigrade strips the following headers in both directions.

### Request direction (client → upstream)

Removed unconditionally before the upstream request is sent:

| Header | Reason |
|---|---|
| `Connection` | Hop-by-hop, not end-to-end |
| `Keep-Alive` | Connection management, not forwarded |
| `Proxy-Authenticate` | Proxy auth, not upstream auth |
| `Proxy-Authorization` | Proxy auth, not upstream auth |
| `Proxy-Connection` | Non-standard keep-alive signal |
| `TE` | Transfer-encoding negotiation |
| `Trailer` | Chunked trailer announcement |
| `Transfer-Encoding` | Body framing, re-framed by Tardigrade |
| `Upgrade` | Protocol upgrade negotiation |
| `Accept-Encoding` | Tardigrade controls upstream compression |
| `Content-Length` | Re-calculated by Tardigrade |
| `Host` | Replaced with the upstream host |

Additionally, any header named by the inbound `Connection` header value is
treated as hop-by-hop and removed. Example: if the client sends
`Connection: X-My-Custom-Header`, Tardigrade strips `X-My-Custom-Header`
before forwarding (RFC 7230 §6.1). See `connectionHeaderReferencesHeader()`
in `src/gateway_proxy_headers.zig`.

### Response direction (upstream → client)

Removed before the client response is written:

| Header | Reason |
|---|---|
| `Connection` | Hop-by-hop |
| `Keep-Alive` | Connection management |
| `Proxy-Connection` | Non-standard |
| `TE` | Transfer-encoding negotiation |
| `Trailer` | Chunked trailer announcement |
| `Transfer-Encoding` | Body framing; re-framed by Tardigrade |
| `Upgrade` | Protocol upgrade |
| `Content-Encoding` | Tardigrade decodes before re-encoding |
| `Content-Length` | Recalculated from materialized body |
| `Server` | Replaced by Tardigrade's own Server header |
| `X-Powered-By` | Technology disclosure (WSTG-INFO-02, ASVS-14.3.3) |
| `X-Request-ID` | Prevents upstream from spoofing correlation IDs |
| `X-Correlation-ID` | Same; Tardigrade emits authoritative IDs |

Additionally, any header named by the upstream response's own `Connection`
header value is treated as hop-by-hop and removed before the response
reaches the client (#673), mirroring the request-direction handling in §2.

Implementation: `shouldSkipUpstreamRequestHeader()` and
`shouldSkipUpstreamResponseHeader()` in `src/gateway_proxy_headers.zig`.

## 2. Connection Header Token Handling

When a `Connection` header lists additional header names (RFC 7230 §6.1),
Tardigrade splits the value on commas, trims whitespace around each token,
and strips the named headers before forwarding. Token comparison is
case-insensitive. This applies in **both directions**: an inbound client
`Connection` header nominates headers to drop before the upstream request is
sent, and an upstream response's own `Connection` header nominates headers to
drop before the response reaches the client (#673) -- a malicious or
misbehaving upstream cannot use this mechanism to smuggle an arbitrary header
past the static hop-by-hop list.

Example (request direction):

```
Connection: X-Foo, X-Bar
X-Foo: client-value
X-Bar: client-value
```

Both `X-Foo` and `X-Bar` are removed before the upstream request is sent,
in addition to `Connection` itself. The same holds symmetrically for an
upstream response that sends `Connection: X-Foo` alongside `X-Foo: ...`.

If `Connection` is itself repeated as multiple header fields, every field's
tokens are honored (#673): a nomination hiding in a second or later
`Connection` field is treated exactly like one in the first, in both
directions. RFC 7230 §3.2.2 treats duplicate fields with the same name as
semantically equivalent to one comma-joined field, and the filtering logic
must not silently fall back to only the first occurrence. Each occurrence's
own value is scanned directly rather than pre-joined into a fixed-size
buffer -- an earlier version of this fix joined every occurrence into a
`[4096]u8` buffer and silently truncated on overflow, which was itself
bypassable by padding earlier fields past the buffer boundary.

Implementation: `anyConnectionHeaderReferencesHeader()` /
`anyRawConnectionHeaderReferencesHeader()` in `src/gateway_proxy_headers.zig`.

## 3. Transfer-Encoding vs Content-Length Conflict

**RFC 7230 §3.3.3** states that a message with both `Transfer-Encoding` and
`Content-Length` is a potential HTTP request smuggling vector and MUST be
rejected. Tardigrade returns `400 Bad Request` for any such request.

Similarly, duplicate `Content-Length` headers (with or without matching
values) are rejected: the parser returns `error.ConflictingHeaders` which the
gateway maps to `400 Bad Request`.

Upstream responses with conflicting framing headers are also treated as
`error.UpstreamProtocolError`, causing a synthetic `502 Bad Gateway`. This
now applies symmetrically to the response direction (#673): a response
carrying both `Transfer-Encoding: chunked` and `Content-Length` is rejected
outright rather than letting `Transfer-Encoding` silently take precedence,
a duplicated `Transfer-Encoding` field is rejected the same way a
duplicated `Content-Length` field is, and the `Transfer-Encoding` value
itself must equal `chunked` exactly — a coding list such as
`chunked, gzip` is rejected rather than treated as plain chunked framing
with the unrecognized coding silently dropped.

The request direction has the same exact-match requirement (#673 review
round 7): `Request.parse()`/`Request.parseHead()` reject a `Transfer-Encoding`
value that is anything other than `chunked` exactly, rather than accepting
any comma-separated list containing a `chunked` token.

Implementation: `src/http/request.zig`, function `Request.parse()`, lines
that set `error.ConflictingHeaders`; the response-direction equivalent in
`detectResponseFraming()` in `src/gateway_proxy.zig`.

## 4. Duplicate Content-Length

Duplicate `Content-Length` headers are rejected with `error.ConflictingHeaders`
regardless of whether the values match. A single unambiguous value is required.

The same policy applies to an **upstream response's** `Content-Length`
(#673): `detectResponseFraming()` in `src/gateway_proxy.zig` rejects a
duplicate field with `error.UpstreamProtocolError` regardless of field
order or whether the values match, rather than resolving to whichever
field happened to appear last.

See the regression corpus case `tests/corpus/http/request/duplicate_content_length.http`.

## 4a. Duplicate Authorization (#673)

HTTP defines no combination semantics for `Authorization`, so a request
carrying more than one `Authorization` field is ambiguous in the same way a
request with duplicate `Content-Length` fields is. Duplicate `Authorization`
headers are rejected with `error.DuplicateAuthorizationHeader` (mapped to
`400 Bad Request`) before routing or auth resolution ever runs -- regardless
of field order, and even when one of the two duplicated values would
otherwise have been a valid credential. A client cannot smuggle a second,
attacker-controlled `Authorization` value past whichever single value a
given code path happens to read.

Implementation: `src/http/request.zig`, `Request.parse()` and
`Request.parseHead()`.

## 4b. Routing Authority Ambiguity

HTTP/1 requests carrying more than one `Host` field are rejected with
`error.DuplicateHostHeader` (mapped to `400 Bad Request`) before routing,
authentication, or proxying. This applies even when the values are identical:
accepting either the first or last value would let different intermediaries
disagree about the request's routing authority.

Host values are syntax-checked, and an absolute-form request target retains
its authority until it can be compared with Host (including default-port
normalization). A mismatch is rejected before virtual-host selection.

HTTP/2 applies the equivalent rule to its entire request-header envelope.
Initial header blocks reject duplicated or unknown pseudo-headers,
pseudo-headers appearing after regular fields, and uppercase header names.
Ordinary requests require exactly one `:method`, `:scheme`, and `:path`;
CONNECT uses the RFC-specific `:method`/`:authority` form. Trailer blocks may
contain only lowercase regular fields. Violations terminate the connection
with `PROTOCOL_ERROR` before a route or upstream is selected.

HTTP/3 applies the same uniqueness, ordering, lowercase-name,
connection-specific-field, authority, and pseudo-value rules before a request
is dispatched. Both multiplexed protocols also enforce the configured
per-request body ceiling and an aggregate request-assembly ceiling across all
concurrent streams on one connection.

Implementation: `src/http/request.zig`, `Request.parse()` and
`Request.parseHead()`; `src/edge_gateway.zig`,
`h2RequestHeaderBlockIsValid()` and `h2ProcessHeaderBlock()`.

## 4c. HTTP/2 Stream Lifecycle as the Authority

Inbound HEADERS and DATA are gated on the RFC 7540 §5.1 stream state, not on
whether request-assembly state happens to exist. A dispatched request is removed
from the pending-assembly map while its stream entry stays alive (a response can
be parked on send-credit exhaustion), so "absent from pending" must never be
read as "this is a new request": that would let a peer open a second request on
one stream and duplicate route, auth, and handler execution while the first
response is still outstanding. Frames arriving on a stream the remote has closed
for sending are answered with `RST_STREAM(STREAM_CLOSED)`.

CONNECT is accepted by the header validator as syntactically valid HTTP/2 (RFC
9113 §8.5 authority-form) but is deliberately **not implemented**: tunneling has
no representation in the shared HTTP/1 adapter, and synthesizing an origin-form
`:path` would route a tunnel request at an unrelated path. Such a stream is
refused with `RST_STREAM(REFUSED_STREAM)`, leaving the connection and its other
streams intact.

Implementation: `src/edge_gateway.zig`, `h2StreamAcceptsInboundFrame()` and
`h2HeaderBlockRequestsConnect()`.

## 4d. Inbound Asserted-Identity Headers

`X-Tardigrade-*` request headers are reserved for Tardigrade's own assertions
about an authenticated principal. On the HTTP path they are stripped from
inbound requests (`shouldSkipUpstreamRequestHeader`). The SMTP proxy applies the
same boundary inside the message-header section carried by `DATA`: the `DATA`
command is matched case-insensitively, only the header section (through the
first blank line) is inspected, and any reserved field there is rejected
regardless of whether the request carries an authenticated identity. This closes
both forgery (supplying an identity) and suppression (pre-supplying the header
so the authoritative value is not injected). Body text resembling the header is
not treated as a header.

Implementation: `src/gateway_protocols.zig`, `injectSmtpAuthIdentity()`.

## 4e. Trusted-Peer Matching

Decisions that depend on "did this come from a trusted proxy tier" — inbound
forwarded-client metadata and geo country headers — compare parsed IP addresses
rather than textual spellings. A bare IPv6 literal has no `:port` suffix to
strip (RFC 3986 §3.2.2 requires brackets for that), so truncating its last group
would make different addresses compare equal; HTTP/3 supplies peers in exactly
that unbracketed form. Hostnames still compare case-insensitively, and an IP
literal never matches a hostname.

Implementation: `src/gateway_proxy_headers.zig`, `stripPort()`,
`trustHostsEqual()`, and `isTrustedUpstream()`.

## 4f. Access-Control Policy Generations

The parsed IP access-control list is owned by the configuration version a
request leased, not by shared gateway state. Authorization state must not
outlive or under-live the configuration it belongs to: a single mutable global
both races reload (freeing rules while a worker is inside `check()`) and lets a
request holding an older lease observe a newer or absent policy, skipping a
denial its own configuration still requires. A reload attaches its ACL to the
new generation before publishing it, and an old generation's ACL is freed only
when its last lease is released.

Implementation: `src/gateway_state.zig`, `ManagedConfigVersion.access_control`;
`src/edge_config.zig`, `EdgeConfig.parsed_access_control`.

## 5. Header Casing and Normalization

All header names stored by Tardigrade's `Headers` collection are lowercased on
ingress. Lookups are always case-insensitive. Header values are trimmed of
leading and trailing whitespace (HTAB and SP).

Header names must consist only of RFC 7230 §3.2.6 `tchar` characters:
`` !#$%&'*+-.^_`|~ ``, digits, and letters — visible ASCII excluding
control characters, DEL (0x7F), SP/HTAB, and every separator character
(`` ()<>@,;:\"/[]?={} ``). Any inbound header that violates this rule is
rejected with `400 Bad Request`. (`isValidHeaderName()` in
`src/http/headers.zig` previously only excluded control characters, space,
DEL, and colon — a header name like `Bad(Name` or `Bad,Name` still passed
despite this document already describing the stricter rule; #673 review
round 9 made the implementation match it.)

Header values must not contain CR (0x0D), LF (0x0A), NUL (0x00), or any other
control character (0x00–0x1F, 0x7F). HTAB (0x09) and SP (0x20) are allowed
within a value. This prevents CRLF injection and log poisoning.

Obs-fold (line continuation with LF + SP/HTAB) is rejected; folded headers
produce `400 Bad Request`.

The same name/value validation is applied to **upstream response** headers
before they are forwarded to the client (#673): a header line is only split
on an exact `\r\n` boundary, so without this check a bare CR or embedded NUL
inside what should be a single value would survive parsing and be forwarded
verbatim, letting a hostile or compromised upstream inject control
characters into a response header the client receives. A response with an
invalid header name or value is rejected as `error.UpstreamProtocolError`
(`502 Bad Gateway`) rather than partially forwarded.

Implementation: `isValidHeaderName()`, `isValidHeaderValue()`,
`parseHeaders()` in `src/http/headers.zig`; the same two functions applied
to upstream response headers in `parseBufferedUpstreamResponse()` and
`readUpstreamHead()` in `src/gateway_proxy.zig`.

## 6. Absolute-Form vs Origin-Form Request Targets

Clients may send requests in either origin-form (`GET /path HTTP/1.1`) or
absolute-form (`GET http://example.com/path HTTP/1.1`). Tardigrade's request
parser normalizes absolute-form targets by extracting the path component and
retaining the scheme and authority for validation. Host-based routing still
uses the `Host` field, but only after it is proven equivalent to the target
authority; disagreement is rejected with `400 Bad Request`.

Absolute-form URIs with no explicit path component (e.g., `http://example.com`
with no trailing slash) are rejected with `400 Bad Request` (`error.InvalidUri`).

Implementation: `parseUri()` in `src/http/request.zig`.

## 7. Forwarded / X-Forwarded-* Trust Boundary

Tardigrade unconditionally strips all client-supplied `X-Forwarded-For`,
`X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Real-IP` headers before
forwarding the request upstream. Tardigrade then sets authoritative values
derived from the actual connection:

| Header | Value |
|---|---|
| `X-Forwarded-For` | Client IP appended to any existing chain from a trusted proxy tier in front of Tardigrade (see below) |
| `X-Real-IP` | Direct connection IP |
| `X-Forwarded-Proto` | `https` or `http` based on TLS state |
| `X-Forwarded-Host` | The inbound `Host` header value |

### Trusted upstream identity

When `trust_require_upstream_identity: true` is set in the config, Tardigrade
only treats a forwarding chain as authoritative if the connection originates
from a host in `trusted_upstream_identities`. If an untrusted host sends
`X-Forwarded-For`, that header is stripped and replaced by just the connection
IP.

**Default**: trust is open (any connecting host). Operators running Tardigrade
behind a load balancer MUST set `trusted_upstream_identities` to the load
balancer's address(es) and enable `trust_require_upstream_identity: true` to
prevent clients from spoofing their source IP via `X-Forwarded-For`.

The same trust decision also governs the `client_ip` Tardigrade uses
internally: the identity rate limiting keys unauthenticated traffic on
(`ip:{client_ip}` buckets) and the `client_ip` field written to access logs.
Before #673, this internal resolution (`extractClientIp()`) had no trust
gate at all -- any client could rewrite both just by sending
`X-Forwarded-For`/`X-Real-IP`, live even behind a correctly configured
`trusted_upstream_identities`, because that code path never consulted it.

Implementation: `isTrustedUpstream()`, `buildForwardedFor()`,
`appendProxyRequestHeaders()` in `src/gateway_proxy_headers.zig`;
`extractClientIp()` in `src/http/request_context.zig`; the untrusted-path
header strip in `edge_gateway.zig` (`handleConnection`, right before
`extractClientIp()` is called).

## 8. Host Header Handling

**RFC 7230 §5.4** requires HTTP/1.1 clients to include a `Host` header.
Tardigrade rejects any HTTP/1.1 request that lacks a `Host` header with
`400 Bad Request` before routing or proxying. HTTP/1.0 clients are exempt.

The `Host` header value (stripped of port) is used for virtual-host routing
when multiple server blocks share a port. A non-matching Host produces a
`404 Not Found`.

## 9. Request Body Size Enforcement

The maximum accepted request body is configured via `max_body_size` (default:
1 MB). Bodies exceeding this limit are rejected with `413 Payload Too Large`
after parsing, before any upstream connection is opened. For chunked bodies,
each decoded chunk is accumulated and the running total is checked against the
limit; the first chunk that would push the total over the limit causes
`error.BodyTooLarge`.

A chunked request body must actually be complete before it is treated as
one (#673 review round 7): reaching the end of the buffered bytes right
after a nonzero chunk, with no terminating zero-size chunk ever seen, is a
truncated body and is rejected (`error.InvalidChunkedBody`) rather than
accepted as if it ended there. The trailer section following the
terminating chunk must reach its own blank-line terminator, and each
non-blank trailer line must actually be valid `field-name ":" OWS
field-value OWS` syntax (RFC 9112 §7.1.2), not merely "contains a colon
somewhere" (#673 review round 8): the name is validated with the same
`isValidHeaderName()` an ordinary request header uses, on the bytes exactly
as they appear before the colon — a space immediately before it is part of
the name for this check and is not trimmed away first, since RFC 7230/9112
treat that as invalid framing rather than benign padding — and the value
with `isValidHeaderValue()`. `Request.parse()` reports exactly how many
bytes of the input a chunked body's encoding consumed, so a pipelined next
request sitting immediately after the real terminator is left for the next
parse rather than being silently swallowed into (or corrupting) the
current request's consumed-bytes count.

This trailer-line validation is one shared function, `isValidTrailerLine()`
in `src/http/headers.zig`, used by all four chunked-trailer-consuming
implementations in the codebase: the buffered request decoder just
described, the buffered upstream-response decoder (§11 below), the
streaming request-upload reader (`http.chunked_upload.Reader`), and the
streaming upstream-response relay's trailer consumer (§11 below) — the
first two originally shipped with only a colon-presence check, and the
latter two originally had no validation at all, until round 8 closed all
four onto the one invariant.

This same completeness requirement is enforced *before* `Request.parse()`
is even called: on the buffered H1 path, `firstRequestCompleteLen()`
(`src/gateway_connection.zig`) decides how many already-read bytes make up
"one complete request" so the connection knows when to stop waiting for
more data. For a `Transfer-Encoding: chunked` request with no
`Content-Length`, this used to default the assumed body length to zero and
declare the request complete the instant its headers finished — before a
single body byte had arrived. `Request.parse()` would then decode an empty
body, and the connection would be treated as ready for the next request
while the real chunked body was still in flight on the wire — a
request-smuggling-class desync. `firstRequestCompleteLen()` now scans for
the actual chunked-body boundary (mirroring the completeness rules above,
without decoding) whenever `Transfer-Encoding: chunked` is present, so the
buffered path waits for the real terminator the same way it already waits
for a declared `Content-Length` to be fully delivered.

Implementation: `decodeChunkedBody()` in `src/http/request.zig`;
`firstRequestCompleteLen()`/`chunkedBodyCompleteLen()`/
`hasChunkedTransferEncoding()` in `src/gateway_connection.zig`.

## 10. Header Size and Header Count Limits

Three independent limits are enforced during request parsing:

| Limit | Default | Error |
|---|---|---|
| Single header line size | 8 KB | `error.HeaderTooLarge` → 431 |
| Aggregate headers size | 32 KB | `error.HeadersTooLarge` → 431 |
| Maximum header count | 100 | `error.TooManyHeaders` → 431 |

All three limits are applied by the parser before any gateway logic runs,
preventing hash-flood and slow-header attacks.

Implementation: constants `MAX_HEADER_SIZE`, `MAX_HEADERS_TOTAL_SIZE`,
`MAX_HEADERS` in `src/http/headers.zig`.

## 11. Proxying Malformed Upstream Responses

If an upstream closes the connection before sending a complete HTTP response
head (`\r\n\r\n`), or sends a partial status line, Tardigrade returns
`502 Bad Gateway` (`error.UpstreamProtocolError`). The parser does not attempt
to recover or guess at partial responses.

Upstream hop-by-hop and technology-disclosure headers are stripped from all
responses regardless of status code, including 5xx error responses.

An upstream `1xx`, `204`, or `304` response is bodiless by definition (RFC
7230 §3.3, RFC 7231 §6.3.5/§6.5.5), regardless of any `Content-Length` the
upstream sends. Tardigrade discards any trailing bytes on those responses
rather than forwarding them as a body: a downstream client honors the
bodiless rule and would otherwise treat the illegal bytes as the start of
the next response on the connection, making a naive pass-through a
response-splitting vector (#673).

A bodiless response's upstream connection is **never** returned to the
keep-alive pool for reuse, even when nothing trailed the header block at
parse time (#673). A malicious or misbehaving upstream can send just the
header block, flush, and only send an illegal body or a full extra response
after Tardigrade has already decided to pool the connection; those delayed
bytes would otherwise become part of whatever unrelated request checks the
connection out next. This holds on both the buffered and the streaming
HTTP/1 proxy paths, which have separate implementations of the rule.

An upstream `1xx` interim response (`100 Continue`, `103 Early Hints`, etc.)
does not end the exchange, on either the buffered or the streaming HTTP/1
proxy path. Tardigrade discards each interim response and keeps reading
until the actual final, non-1xx response arrives; only that final response
is returned to the client. Interim responses are not currently relayed to
the downstream client separately.

On the streaming path, the number of interim responses discarded this way
is capped (`max_interim_upstream_responses`, 64) rather than unbounded
(#673 review round 7): a hostile origin that drip-feeds interim responses
indefinitely is rejected once the cap is exceeded, the loop checks
cancellation on every iteration, and each discarded interim head's
header/reason-phrase allocations are freed (`arena.reset(.free_all)`)
before the next one is read, instead of accumulating in one arena for the
life of the request. Without this, an origin could tie up a request past
its nominal deadline and grow memory without bound simply by never
sending a final response. The buffered path's equivalent loop is already
bounded by the existing total-bytes cap on the response buffer regardless
of how many interim responses arrive, so it did not need the same fix.

An upstream `101 Switching Protocols` response is rejected outright
(`error.UpstreamProtocolError`, `502 Bad Gateway`) rather than either
being treated as a skippable 1xx interim response or forwarded as an
ordinary bodiless final response (#673). `101` is terminal — it hands the
connection off to a different protocol entirely — and this generic
reverse-proxy path has no actual protocol-tunnel support to hand it off
to; forwarding it verbatim would leave the client believing the
connection had switched protocols while Tardigrade still parses it as
HTTP/1.1 request/response framing, a client-visible desync.

A duplicate upstream `Content-Length` — conflicting values, matching
values, or either field order — is rejected the same way a duplicate
request `Content-Length` is (§4), rather than resolving to whichever field
happened to appear last.

The upstream response status line itself is validated for embedded control
characters and a parseable status code, and rejected outright if either
check fails, on both proxy paths. Without this, a bare LF (not part of a
`\r\n` pair) immediately after the status line could let a real header
line — including one nominated via `Connection` — merge with the status
line text and either evade the `Connection`-nomination scanner (buffered
path) or be written verbatim into the reason phrase sent to the downstream
client, which may treat the embedded LF as its own line terminator (streaming
path). All three status-line-parsing call sites (`detectResponseFraming()`,
`parseBufferedUpstreamResponse()`, `readUpstreamHead()`) share one
implementation, `parseStrictStatusLine()`, so this validation cannot drift
out of sync between them (#673).

A "parseable" status code must also fall inside RFC 9110 §15's valid
`100..599` range, not merely be three decimal digits (#673): a value like
`099` or `600` is rejected rather than accepted and, on the buffered path,
reformatted straight back out to the client as an invalid status line
(e.g. `HTTP/1.1 99 ...`).

A chunked upstream response body's connection is only marked reusable when
the decoder consumed *exactly* the bytes read — through and including the
terminating `0\r\n\r\n` chunk's trailer section — mirroring the
Content-Length case above. Extra or ghost bytes already sitting past the
terminator in the same read leave the connection un-pooled rather than
reusable, on both proxy paths (#673). Each chunk's data must also be
followed by a literal CRLF, not merely two arbitrary bytes the decoder
skips past, and chunk-size arithmetic uses checked addition so a
maliciously oversized hex chunk-size is rejected as a protocol error
instead of overflowing. Each non-blank trailer line must be valid
`field-name ":" OWS field-value OWS` syntax, the same `isValidTrailerLine()`
invariant described in §9 above — on **both** the buffered decoder and the
streaming path's separate trailer consumer (`consumeChunkTrailers()`),
which originally had no trailer validation at all (#673 review round 8).

All of the framing-correctness rules above only prove a connection was in
sync *at the instant it was released* back to the keep-alive pool. A
`Content-Length` or chunked response that lands exactly on its declared
boundary is legitimately marked reusable — but a hostile or misbehaving
origin can still send a "ghost" response *asynchronously*, any time after
release, with no relationship to any request Tardigrade ever sent on that
connection; nothing at release time can observe bytes that have not
arrived yet. `UpstreamPool.checkout()` now checks each idle connection for
exactly this immediately before handing it to the next, unrelated caller
(#673 review round 7): anything already pending — an unsolicited byte, or
the peer having closed the connection — discards that connection instead
of reusing it, the same way an aged-out idle connection is discarded. This
closes the gap for `Content-Length`/chunked responses the same way the
bodiless-never-reusable rule above closes it for bodiless ones.

The check differs by transport. A **plain** connection uses a zero-timeout
`poll()` on the raw fd (`POLLIN`/`POLLHUP`/`POLLERR`): every byte on a
plain connection's raw fd is necessarily application-layer, so any of
these unambiguously means "do not reuse", and a poll failure fails closed
(treated as stale) rather than risking a false "clean" result. A **TLS**
connection cannot use the same raw-fd poll: real TLS 1.3 servers routinely
send a `NewSessionTicket` (or other post-handshake, record-layer-only
message) asynchronously right after the handshake, with no relationship to
application data — that ciphertext shows up as immediately readable on the
raw fd regardless, which would flag essentially every freshly-pooled TLS
connection as stale and defeat TLS connection pooling outright.

TLS connections check `UpstreamTlsConn.drainQueuedRecordsAndCheckReady()`:
it nonblockingly drives the record layer through everything already
queued on the raw fd (the fd is already nonblocking for this client, so
`drive()` never waits on the network) and reports "do not reuse" only if
genuine application plaintext or a clean shutdown actually emerges from
that — correctly letting protocol-only traffic like a `NewSessionTicket`
through, unlike the raw-fd poll a plain connection uses. It also fails
closed if the record layer still owns any not-yet-resolved ciphertext when
the drive stalls (a partial record is not proof that nothing is pending —
a hostile origin could otherwise trickle a ghost response's first bytes
before release and complete it only after reuse). A simpler alternative,
`UpstreamTlsConn.readReady()` (already-decrypted plaintext or a completed
clean shutdown only, never driving new ciphertext), remains defined as a
documented fallback but is not currently called from the pool; see
`docs/SECURITY_TEST_PLAN.md` defect 27 for the full history of this
check, including a Linux-ARM-only CI failure this drive-based approach
previously caused and a code/documentation mismatch that briefly
shipped an unapplied revert.

Implementation: `exchangeBoundedBufferedHttpRequest()`,
`parseBufferedUpstreamResponse()`, `detectResponseFraming()`,
`decodeChunkedBody()`, `parseStrictStatusLine()`, and
`readUpstreamHead()`/`streamProxyOverTransport()`/`relayUpstreamBody()`
(the streaming path's equivalents) in `src/gateway_proxy.zig`;
`UpstreamPool.checkout()`/`hasUnexpectedReadableBytes()` in
`src/http/upstream_pool.zig`;
`UpstreamTlsConn.drainQueuedRecordsAndCheckReady()` (currently used) and
`readReady()`/`pending()` (documented fallback, not currently called) in
`src/http/upstream_tls.zig`.

## 12. Directory Traversal — Static File Serving

Tardigrade resolves the canonical (`realpath`) absolute path of both the
configured document root and the requested file. The resolved file path must
have the document root as a prefix; any path that escapes the root is served
as `403 Forbidden`.

The following traversal sequences are all blocked:

| Sequence | Example |
|---|---|
| `..` segments | `/../secret.txt` |
| Percent-encoded `..` | `/%2e%2e/secret.txt` |
| Double percent-encoded | `/%252e%252e/secret.txt` |
| Backslash traversal | `/..\\secret.txt` |
| Symlink outside root | Symlink pointing to a file above the document root |

The protection is implemented by comparing real paths (resolved by the OS via
`realpath()`), which handles all encoding variants by operating on the
normalized filesystem namespace.

Implementation: `resolvePath()` in `src/http/static_file.zig`.
Tests: see the `serve rejects traversal …` test cases in the same file.

## 12a. `root` / `index` / `try_files` Interaction (#437)

A `location` block that sets `root` (or `alias`) is served through
`resolvePath()` in the following order for a directory-style request (the
request path is empty after stripping the location prefix, or ends in `/`):

1. **`try_files`**, if configured — each candidate is tried in order; `$uri`
   resolves to the request path. A candidate that resolves to a directory
   falls through to step 2 (the directory-relative index) before step 3.
2. **`index`**, resolved *relative to the requested directory* — not just the
   location root. `GET /docs/` checks `docs/index.html`, not the root's
   `index.html`; a nonexistent directory still 404s. If `index` is not
   explicitly configured, it **defaults to `index.html`** (nginx-compatible),
   so `location / { root ...; }` alone serves `index.html` instead of
   404ing. This applies identically after stripping an `alias` prefix.
3. **`autoindex`**, if `on` — a directory listing is generated only after
   steps 1–2 fail to resolve a file, so an existing `index.html` always takes
   priority over a directory listing.

To opt out of the default index fallback entirely (e.g. to rely solely on
`autoindex` or a custom `error_page`), set an explicit empty index:
`index "";`.

Implementation: `buildLocationBlockEntry()` in `src/http/config_file.zig`
(default applied at config-parse time) and `resolveDirectoryIndex()` /
`resolvePath()` in `src/http/static_file.zig` (directory-relative resolution
and fallback order).
Tests: `location block with root and no index or try_files defaults index to
index.html` in `src/http/config_file.zig`; `static file integration serves
default index.html when root is set without index or try_files (#437)`,
`static file integration resolves nested directory index relative to the
requested directory (#437)`, `static file integration does not fall back to
the root index for a nonexistent directory (#437)`, and `static file
integration prefers an existing index over autoindex when both are enabled
(#437)` in `tests/integration.zig`.

## 13. TRACE Method Rejection

**RFC 7231 §4.3.8 / ASVS-14.5.1.** The `TRACE` method is rejected globally
with `405 Method Not Allowed` before any location block is consulted. This
prevents Cross-Site Tracing (XST) attacks, which can expose `HttpOnly` cookies
and `Authorization` headers via JavaScript even when those headers are
otherwise inaccessible.

Implementation: `edge_gateway.zig`, immediately after Host header validation.

## 14. Correlation ID Validation (Log Poisoning Defense)

Client-supplied `X-Request-ID` and `X-Correlation-ID` headers are accepted only
if they match the Tardigrade ID format: `tg-<decimal-ms>-<lowercase-hex>`. Any
other value is discarded and a fresh ID is generated. This prevents log
poisoning (WSTG-INPV-11, ASVS-7.1.1) and trace-ID spoofing.

The ID is reflected in the response `X-Request-ID` / `X-Correlation-ID`
headers and in the access log.

Implementation: `isValid()` and `fromHeadersOrGenerate()` in
`src/http/correlation_id.zig`.

## 15. Asserted Identity Headers (X-Tardigrade-*)

The `X-Tardigrade-Auth-Identity`, `X-Tardigrade-User-ID`,
`X-Tardigrade-Device-ID`, and `X-Tardigrade-Scopes` headers are set by
Tardigrade after authentication resolves. Any client-supplied header with the
`X-Tardigrade-` prefix is stripped before the upstream request is forwarded,
preventing clients from impersonating authenticated identities.

Implementation: `shouldSkipUpstreamRequestHeader()` in `src/gateway_proxy_headers.zig`.

## Safe Deployment Checklist

1. **Load balancer in front of Tardigrade**: Set `trusted_upstream_identities`
   to the load balancer's IP(s) and enable `trust_require_upstream_identity:
   true`.  Without this, clients can forge `X-Forwarded-For` to spoof their
   apparent source IP.

2. **TLS termination**: Enable `tls_cert_path` / `tls_key_path` to terminate
   TLS at Tardigrade. Use `hsts_enabled: true` on public HTTPS services.

3. **Auth on sensitive routes**: Set `auth: required` on any `location` block
   that should not be publicly accessible.

4. **Body size limit**: Tune `max_body_size` to match the largest expected
   upload for each upstream. The default 1 MB is conservative.

5. **Upstream TLS verification**: Enable `upstream_tls_verify: true` (the
   default) unless the upstream uses a self-signed certificate in a controlled
   environment. Never disable verification in production.

6. **Metrics and logs**: Configure an access log destination. Rejected
   malformed requests are logged at `warn` level with the rejection category
   (e.g., "Too many headers: 105", "URI too long: 9123 bytes") without echoing
   the raw header values that caused the rejection.

## See Also

- `docs/SECURITY_TEST_PLAN.md` — test coverage map and release gate
- `docs/PENTEST_PLAYBOOK.md` — internal pentest procedures
- `docs/CODE_REVIEW_CHECKLIST.md` — per-PR security checklist
- `src/gateway_proxy_headers.zig` — hop-by-hop filtering implementation
- `src/http/request.zig` — request parser with smuggling defenses
- `src/http/headers.zig` — header validation and limits
- `src/http/correlation_id.zig` — correlation ID validation
- `src/http/static_file.zig` — directory traversal protections
