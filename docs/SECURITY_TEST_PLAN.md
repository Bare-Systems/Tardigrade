# Security Test Plan

Tardigrade is a public-edge service that terminates TLS, parses untrusted HTTP
input, enforces auth, and proxies to internal upstreams. Security validation is
a release gate, not a best-effort activity.

## Threat Model To Coverage Map

### Path and filesystem safety

- Unit coverage lives in `src/http/static_file.zig`.
- Focus areas: traversal, percent-encoded traversal, double-encoded traversal,
  backslash traversal, symlink escape, alias/root interaction, autoindex safety.
- Integration coverage lives in `tests/integration.zig` for live static serving
  and top-level `try_files`.

### Request parser abuse

- Unit coverage lives in `src/http/request.zig` and `src/http/headers.zig`.
- Focus areas: duplicate `Host`/`Content-Length`, `Transfer-Encoding` conflicts,
  malformed chunked bodies, premature EOF, oversized request lines, header line
  limits, aggregate header limits, header-count limits, obs-fold rejection, and
  HTTP/2/HTTP/3 pseudo-header ordering, uniqueness, value syntax, casing,
  padding, dynamic compression-state limits, and multiplexed aggregate-memory
  limits.
- Live edge coverage lives in `tests/integration.zig` to verify malformed input
  is rejected before routing or proxying.

### Header injection and response splitting

- Unit coverage lives in `src/http/headers.zig`.
- Focus areas: control characters in names/values, CRLF injection, obs-fold,
  log-poisoning-safe header validation.
- Integration coverage verifies hop-by-hop stripping and upstream header
  sanitization.

### Auth, sessions, rate limiting, and approval policy

- Unit coverage lives in `src/http/auth.zig`, `src/http/session.zig`, and
  `src/edge_gateway.zig`.
- Integration coverage lives in `tests/integration.zig`.
- Focus areas: protected-route bypass, malformed bearer input, invalid JWT
  signature, malformed session token input, asserted-identity rate limiting,
  approval-management route bypass from recursive approval checks.

### Corpus Replay And Coverage-Guided Fuzzing

- Corpus files live under `tests/corpus/http/request/`.
- The replay and deterministic mutation harness lives in
  `tests/security/request_parser_corpus.zig`.
- `zig build test-security-corpus` replays known hostile HTTP/1.1 request
  bytes and applies deterministic byte mutations. It is intentionally bounded,
  exact-byte, and PR-safe; it is not the repository's coverage-guided fuzz
  campaign.
- True Zig coverage-guided fuzz targets already exist today. They live as
  `test "fuzz: ..."` owners next to the parser/state-machine code or in
  focused test files, use target-local seed corpora, and become
  coverage-guided runs under `zig build <step> -Doptimize=ReleaseFast
  --fuzz=<runs>`.
- Current fuzz owners include `test-tls-protocol-fuzz`,
  `test-tls-record-fuzz`, `test-tls-resumption-fuzz`, `test-pki-fuzz`,
  `test-crypto-provider-fuzz`, and `test-quic`. See
  [CRYPTO_FUZZ_CONTRACT.md](CRYPTO_FUZZ_CONTRACT.md) and
  [QUIC_H3_FUZZ_MATRIX.md](QUIC_H3_FUZZ_MATRIX.md).
- The sustained canonical 10M/50M fuzz campaign and the final
  scheduled-versus-manual cadence decision remain owned by #675 until that
  campaign is executed or explicitly dispositioned.

## Commands

Use Zig `0.16.0` (see `CONTRIBUTING.md`). If it is not already on `PATH`,
bootstrap it first:

```bash
sh ./scripts/install-zig.sh 0.16.0
```

```bash
# Unit + parser/path/auth hardening coverage
zig build test

# Seed corpus replay + deterministic mutation pass
zig build test-security-corpus

# Live-process integration coverage
zig build test-integration
```

## Release Gate

Do not ship a wider public distribution unless all of the following are true:

- `zig build test` passes with the pinned Zig `0.16.0` toolchain.
- `zig build test-security-corpus` passes with the pinned Zig `0.16.0`
  toolchain.
- `zig build test-integration` passes, or any environment-specific skip is
  explicitly documented in the release notes.
- The first internal pentest playbook has been executed against a local or
  isolated non-public target and the sanitized result has been recorded in
  `docs/PENTEST_PLAYBOOK.md`.
- Scanner and pentest evidence is recorded separately from exact-byte
  protocol harness authority. Scanners help find exposed behavior; exact
  protocol conformance, smuggling, malformed-framing, TLS, QUIC, and H3
  claims need the repository harnesses or documented external-peer matrices
  that preserve the relevant bytes/state.
- Public-edge behavior changes update tests and operator-facing docs.

## Current Gaps And Follow-Up

- HTTP/2, HTTP/3, WebSocket, SSE, FastCGI, SCGI, and uWSGI malicious-input
  coverage is still narrower than HTTP/1.1 parser coverage. The #677 release
  sweep added installed-artifact H2/H3 correctness, malformed-route, real
  client, cancellation, drain, and resource-settle evidence; it does not prove
  H1-style malicious-input parity for every H2/H3 framing edge.
- `test-security-corpus` is a deterministic hostile HTTP/1.1 replay/mutation
  gate. The true TLS/PKI/crypto/QUIC/H3 coverage-guided fuzz targets exist
  today, but sustained run-count evidence and the recurring cadence decision
  remain open under #675.
- Keep ordinary CI bounded: deterministic seed/corpus replay is PR-safe, while
  10M/50M/100M+ fuzz campaigns remain manual/on-demand until #675 records
  measured cost and usefulness for any scheduled subset.

### Resolved Gaps (issue #174)

**F-01 — HTTP method enforcement (WSTG-CONF-06, ASVS-13.2.1)** ✅ RESOLVED
`TRACE` is rejected globally with 405 in `edge_gateway.zig` before any
location block is consulted. The `return_response` action additionally rejects
non-GET/HEAD methods on non-redirect static-return directives with 405
(ASVS-14.5.1). Corpus case `trace_method.http` documents the expected
behavior.

**F-02 — Upstream Server header passthrough (WSTG-INFO-02, ASVS-14.3.3)** ✅ RESOLVED
`shouldSkipUpstreamResponseHeader()` in `gateway_proxy_headers.zig` strips
upstream `Server` and `X-Powered-By` headers. Tardigrade emits its own
`Server: tardigrade` header. Covered by unit tests in `gateway_proxy_headers.zig`.

**F-03 — Missing Host header not rejected (WSTG-CONF-07, ASVS-14.5.1)** ✅ RESOLVED
HTTP/1.1 requests missing `Host` are rejected with `400 Bad Request` in
`edge_gateway.zig` before routing or proxying. HTTP/1.0 is exempt per RFC
1945. Corpus case `no_host_http11.http` documents parser acceptance; gateway
enforcement is tested via unit conditions in `edge_gateway.zig`.

**F-04 — Client-controlled X-Request-ID / X-Correlation-ID (WSTG-INPV-11, ASVS-7.1.1)** ✅ RESOLVED
`fromHeadersOrGenerate()` in `src/http/correlation_id.zig` validates incoming
IDs against the `tg-<decimal>-<lowercase-hex>` format. Arbitrary client values
are discarded and a fresh ID is generated. Covered by unit tests in
`correlation_id.zig`.

**F-05 — Live native TLS surface pass** ✅ RESOLVED
Issue #672 completed a live black-box pass against an isolated native
`tardi` listener using synthetic credentials, OpenSSL probes, `nghttp`, and
scanner tooling. The committed sanitized evidence, command matrix, public
certificate metadata, and scanner-tool limitations are recorded in
[`docs/F05_LIVE_TLS_SURFACE_672.md`](F05_LIVE_TLS_SURFACE_672.md).

**F-07 — Static file serving via catch-all `location /` non-functional** ✅ RESOLVED
A `location` block with `root` but no `index` or `try_files` directive used
to 404 on directory requests because static serving had no default index
value. Maintainer decision (#437): default `index` to `index.html` when not
explicitly configured (nginx-compatible). See `docs/PROXY_SECURITY.md` §12a
for the full `root`/`index`/`try_files` resolution order. Covered by a unit
test in `src/http/config_file.zig` and an integration test in
`tests/integration.zig`.

**F-06 — Auth enforcement and hostile HTTP/1.1 framing pass (WSTG-ATHZ-01/02, WSTG-INPV-15, ASVS-4.1/4.3, RFC 7230 §6.1) (#673)** ✅ RESOLVED
A live black-box campaign runs raw, byte-exact HTTP/1.1 requests against a
real local `tardi` process fronting a disposable marker-recording upstream,
with one bearer/JWT-protected route, one deliberately hostile upstream
route, and (per the Safe Deployment Checklist) `trust_require_upstream_identity`
enabled with the test client itself left untrusted. Assertions are made from
the upstream's own hit log, not just the client-visible status code, so
"denied" means the protected upstream was never invoked, not merely that the
client got a 4xx -- and every smuggling-shaped framing probe additionally
appends a unique pipelined marker request to prove it is never dispatched,
not just that the malformed probe itself was rejected.

Coverage (164 live cases):
- missing/malformed credentials (no header, bare `Bearer`, wrong scheme,
  oversized token, malformed/invalid-signature JWT, comma-joined
  `Authorization`, NUL/CR injection attempts), including a strict deny for
  duplicate `Authorization` fields in **both** orderings regardless of
  whether one of the two duplicated values is itself valid;
- `X-Tardigrade-*` / `X-Forwarded-*` / `Connection`-nominated identity
  spoofing cannot become trusted identity, and rotating forged
  `X-Forwarded-For`/`X-Real-IP` values from an untrusted connection cannot
  rewrite the client identity used for rate limiting and access logging;
- method-change bypass across GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS/TRACE/CONNECT;
- path/Host canonicalization variants (trailing slash, duplicate/encoded
  slashes, dot segments, single/double percent-encoding, absolute-form
  target, a genuine duplicate `Host` field carrying otherwise-valid
  authorization) cannot move a request off the protected boundary;
- positive control plus sequential and concurrent bearer/JWT reuse;
- the issue's own TE+CL and duplicate-conflicting-`Content-Length` smuggling
  probes, plus the wider CL/TE/duplicate-TE/chunked matrix -- every
  non-truncated case proven with a unique pipelined marker request that
  never reaches the upstream; truncated-body cases (where no coherent
  trailing request could exist) proven by zero upstream hits instead;
- request header syntax limits (obs-fold, NUL/CTL, bare LF, bare CR without
  LF, oversized line/header, header-count and aggregate-size limits,
  malformed version/method);
- the static traversal boundary, including a real symlink escaping the doc
  root and a separate `alias`-rooted location retested for the same
  boundary;
- a hostile upstream response matrix (equal and conflicting duplicate CL,
  TE+CL, malformed status line, control-character/bare-CR injection in a
  header value, `Connection`-nominated header, `Proxy-Connection`/`TE`/
  `Trailer`/`Upgrade`/`Server`/`X-Powered-By`, truncated body, extra bytes
  after the framed response, unusual 1xx chain, invalid 204/304 framing),
  each checked both on a fresh connection and on the *same* downstream
  connection used for the hostile probe (with the first response's own
  framing validated, not just what follows it), plus a dedicated check that
  a "ghost" second response smuggled by the hostile upstream never leaks
  into a later, unrelated proxied response over a reused upstream
  connection -- including when the hostile upstream deliberately delays
  sending the ghost bytes until after Tardigrade would have returned the
  connection to the idle pool;
- the client-visible result of an upstream `103 → 103 → 200` interim-response
  chain is exactly the real final response, not a bare 103 with the 200
  silently dropped, and a Connection-nominated header hidden behind a bare
  LF in the status line is still stripped;
- every scenario in the hostile upstream response matrix that specifically
  targets the buffered proxy path's bodiless-response/1xx/Content-Length
  handling is replayed against a forced-streaming twin route
  (`/hostile-streaming`, `proxy_streaming response;`), since the streaming
  proxy path (`streamProxyOverTransport()`/`readUpstreamHead()`) has its
  own, separately-fixed copies of that logic and is off by default;
- a `Transfer-Encoding` value that names anything other than exactly
  `chunked` (e.g. a coding list like `chunked, gzip`) and a duplicated
  `Transfer-Encoding` field are both rejected rather than tolerated; a
  chunked body's terminating chunk followed by extra/ghost bytes never
  leaves the connection reusable, on a fresh connection, the same
  downstream connection as the hostile probe, and (for a representative
  pair of cases) the forced-streaming twin route.
- a status 101 upstream response is rejected outright rather than either
  being treated as a skippable 1xx interim response or relayed to the
  client as an ordinary bodiless final response, on both the buffered and
  streaming paths;
- an upstream status code outside RFC 9110 §15's valid `100..599` range
  (e.g. `099`, `600`) is rejected outright rather than reformatted back out
  to the client as an invalid status line, on both the buffered and
  streaming paths;
- every request-direction smuggling-shaped framing probe (duplicate/
  conflicting Content-Length, TE+CL together in either header order or
  case, duplicate/unsupported/misordered Transfer-Encoding, invalid/
  oversized chunk-size hex, missing chunk-data CRLF, a malformed
  no-colon chunk trailer) is sent with **valid** auth so a parser bug that
  wrongly accepts the framing would actually reach the upstream instead of
  being masked by the `/protected` auth gate, and a separate positive-
  control case proves a single, ordinary, valid `Content-Length` request's
  body boundary is computed exactly -- neither over- nor under-reading by
  even one byte;
- a hostile origin drip-feeding interim `1xx` responses well past what any
  real origin would ever send is rejected outright on the streaming path
  rather than tying up the request indefinitely, without breaking the edge
  for unrelated requests;
- a "ghost" response delayed until after release, on a `Content-Length` or
  chunked response that legitimately lands on its declared boundary (not
  just the already-covered bodiless case), never poisons a later, unrelated
  request over the same pooled upstream connection, on both the buffered
  and streaming paths;
- a chunked-body trailer line with a colon but a malformed name (e.g. a
  space in it, or a valid-looking name containing a non-colon RFC 7230
  separator such as `(`) is rejected on both the request direction (with
  valid auth, so the parser rejection is what is actually proven) and the
  response direction (both the buffered and forced-streaming hostile
  routes).

The campaign found and fixed twenty-eight real defects, all now covered by
deterministic regression tests:

1. `shouldSkipUpstreamResponseHeader()` did not honor the upstream
   response's own `Connection` header nomination (RFC 7230 §6.1) the way
   the request-direction `shouldSkipUpstreamRequestHeader()` already did. A
   malicious or misconfigured upstream sending `Connection: X-Hostile-Secret`
   alongside `X-Hostile-Secret: ...` could ride an arbitrary header past the
   static response hop-by-hop list straight through to the client. Fixed at
   all five call sites (buffered and streamed proxy response paths, HTTP/2
   upstream header forwarding in `edge_gateway.zig`).
2. That same nomination check only consulted the *first* `Connection` field
   when a header was duplicated, in both directions (`Headers.get()`
   returns only the first match). A first attempt at fixing this by joining
   every occurrence into a fixed `[4096]u8` buffer was itself bypassable:
   padding earlier `Connection` field(s) with enough benign tokens pushes a
   real nomination past byte 4096, where it silently drops out of the
   truncated joined value. Fixed by scanning each occurrence's own
   (unbounded) value directly instead -- `anyConnectionHeaderReferencesHeader()`
   / `anyRawConnectionHeaderReferencesHeader()` in `gateway_proxy_headers.zig` --
   which has no size limit to bypass.
3. Duplicate `Authorization` header fields were accepted whenever the
   *first* field (whichever the reading code path happened to consult) was
   a valid credential, silently ignoring a second, malformed field. Fixed
   by rejecting any request with more than one `Authorization` field
   outright (`error.DuplicateAuthorizationHeader` in `src/http/request.zig`,
   mapped to `400 Bad Request` before routing or auth ever runs) --
   analogous to the existing duplicate-`Content-Length` rejection.
4. `extractClientIp()` (`src/http/request_context.zig`) honored client-supplied
   `X-Forwarded-For`/`X-Real-IP` unconditionally, with no trust gate at all,
   even though `docs/PROXY_SECURITY.md` §7 documents `trust_require_upstream_identity`
   / `trusted_upstream_identities` as the boundary that should govern this.
   Any client could rewrite the identity used to key rate-limit buckets and
   the `client_ip` recorded in access logs, live even behind a correctly
   configured trust boundary. Fixed by gating on the same trust check used
   elsewhere (`gph.isTrustedUpstream()`) and stripping the headers from the
   request outright when untrusted, before any other code (including the
   outbound `X-Forwarded-For` chain sent to Tardigrade's own upstream) can
   read them.
5. Upstream response headers were copied into the client-facing response
   with no validation at all -- unlike client *request* headers, which
   `Headers.append()` validates against `isValidHeaderName()` /
   `isValidHeaderValue()`. Because a header line is only split on an exact
   `\r\n` boundary, a bare CR or embedded NUL inside what should be a
   single header value survived parsing and was forwarded to the client
   verbatim, letting a hostile or compromised upstream inject control
   characters into a response header. Fixed by validating every upstream
   response header name/value the same way request headers already are,
   rejecting the response as `error.UpstreamProtocolError` (502) if either
   fails, at both the buffered (`parseBufferedUpstreamResponse()`) and
   streamed (`readUpstreamHead()`) parse sites in `gateway_proxy.zig`.
6. The buffered proxy path forwarded a body for upstream `204`/`304`/`1xx`
   responses whenever the upstream included one, even though those statuses
   are bodiless by definition regardless of `Content-Length` -- a real
   response-splitting vector, since a downstream client would treat the
   illegal bytes as the start of the next response on the connection.
7. Both the buffered and streamed proxy paths could still return a bodiless
   (`204`/`304`/`1xx`/`HEAD`) upstream connection to the idle pool for reuse
   whenever nothing had trailed the header block *at the instant it was
   parsed*. That cannot prove a malicious/misbehaving upstream won't send
   an illegal body or a full ghost response moments later, after the
   connection is already pooled -- those delayed bytes would then become
   part of whatever unrelated request next checks the connection out,
   poisoning it. Fixed by never marking a bodiless response's upstream
   connection reusable, in `exchangeBoundedBufferedHttpRequest()` and
   `relayUpstreamBody()` in `gateway_proxy.zig`.
8. `detectResponseFraming()` maps every `1xx` status to bodiless framing,
   which the buffered exchange loop treated as "the response is complete" --
   so the *first* interim `1xx` response (e.g. `103 Early Hints`) was
   wrongly returned to the caller as if it were the final response, and
   whatever actually followed (including the real final response) was
   silently discarded. Fixed by having the buffered exchange loop discard
   1xx interim responses (other than `101`, which completes a protocol
   switch rather than signaling more to come) and keep reading until the
   real final response arrives, in `exchangeBoundedBufferedHttpRequest()`
   in `gateway_proxy.zig`.
9. Defects 7 and 8's fixes only ran on the **buffered** HTTP/1 proxy path.
   The **streaming** path (`streamProxyOverTransport()`) calls
   `relayUpstreamBody()` -- where defect 7's fix lives -- only inside
   `if (body_allowed)`, and `responseBodyAllowed()` is false for exactly
   `HEAD`/`1xx`/`204`/`304`, so that branch (and the fix in it) never ran
   for precisely the response family it was meant to protect; a delayed
   illegal body/ghost could still poison a streamed HTTP/1 upstream socket.
   Fixed by making bodiless streamed final responses fail closed for reuse
   in `streamProxyOverTransport()` itself, not only in the relay helper.
10. `streamProxyOverTransport()` still called `readUpstreamHead()` once and
    immediately serialized that head downstream, so a streaming route
    receiving a `103 → 103 → 200` chain still treated the first `103` as
    the completed exchange and abandoned the final response -- the
    streaming analog of defect 8, in a separate code path. Fixed by
    looping `readUpstreamHead()` past 1xx interim responses (101 excepted)
    before committing anything downstream, mirroring the buffered fix.
11. `detectResponseFraming()` overwrote `content_length` on every
    `Content-Length` occurrence instead of rejecting duplicates, so a
    conflicting pair resolved to whichever field came last regardless of
    order -- reversing the order from "small value first" to "large value
    first" flips which boundary wins, and picking the smaller one leaves
    "extra" bytes (e.g. a smuggled follow-up request or a ghost response)
    past what the parser thinks is the end of the response. Fixed by
    rejecting any duplicate `Content-Length` outright (`error.UpstreamProtocolError`),
    matching the request-direction policy, regardless of field order or
    whether the values happen to match.
12. Upstream response status-line parsing was not strict, and a bare LF (not
    part of a `\r\n` pair) right after the status line could bypass the
    `Connection`-nomination filter from defect 2's fix: in the buffered
    path, the nomination scanner walked the raw header block from byte 0
    using exact `\r\n` splitting, so the still-unterminated status line text
    merged with the first real header line into one bogus segment that no
    longer matched `connection` by name; in the streaming path, the whole
    run up to the first genuine `\r\n` -- including an injected header --
    was swallowed into the reason phrase and later written verbatim into
    the status line sent to the downstream client, which may treat the
    embedded LF as a line terminator of its own and interpret the smuggled
    text as a genuine extra header. This composes two explicit #673
    malicious-upstream cases: malformed status line and
    Connection-nominated hop-by-hop header. Fixed by validating the parsed
    status line for embedded control characters (rejecting the response
    outright if present, in both paths) and, in the buffered path, scanning
    the same header-lines view the main per-header loop already uses
    (starting after the status line) rather than the whole raw block from
    byte 0. Also rejects a status line whose status code doesn't parse,
    rather than silently defaulting to `200`/`0`.
13. Even after defect 12 made all three status-line/header-boundary sites
    (`detectResponseFraming()`, `parseBufferedUpstreamResponse()`,
    `readUpstreamHead()`) individually strict, each still computed the
    boundary with its own independent logic -- three implementations that
    happened to agree rather than one that could not disagree. Consolidated
    into a single shared `parseStrictStatusLine()` in `gateway_proxy.zig`
    that all three now call, removing the risk of the same class of drift
    defect 12 fixed from silently reopening in only one of the three sites
    during a future change.
14. `detectResponseFraming()` matched `Transfer-Encoding` by splitting the
    value on commas and accepting the response as chunked if *any* token in
    the list equaled `chunked` (e.g. `Transfer-Encoding: chunked, gzip`
    would be treated as plain chunked framing, silently discarding the
    `gzip` coding Tardigrade has no way to apply). It also never rejected a
    duplicated `Transfer-Encoding` field the way duplicate `Content-Length`
    already was. Fixed by requiring the field to equal `chunked` exactly
    and rejecting a second occurrence outright, matching the
    duplicate-`Content-Length` policy.
15. `detectResponseFraming()` deliberately let a response carry both a valid
    `Transfer-Encoding: chunked` and a `Content-Length` together, giving
    `Transfer-Encoding` precedence per a comment citing RFC 7230 §3.3.3 --
    but §3.3.3 actually directs a recipient to treat this combination as an
    error indicating possible request smuggling, not to pick a winner. The
    existing live `te_and_cl` probe only proved the edge did not hang when
    sent this combination, not that the framing choice was safe. Fixed by
    rejecting the response outright (`error.UpstreamProtocolError`) when
    both are present, regardless of order.
16. A status `101` upstream response was excluded from the loop that
    discards `1xx` interim responses, but had no dedicated handling either
    -- so it fell through and was re-serialized to the client as an
    ordinary bodiless *final* response by a generic reverse-proxy relay
    with no actual protocol-tunnel support, leaving the client believing
    the connection had switched to a new protocol while Tardigrade still
    treated it as HTTP/1.1 request/response framing. Fixed by rejecting
    status `101` outright at the shared framing-detection layer
    (`detectResponseFraming()`), before either the buffered or streaming
    path can act on it.
17. The buffered path's chunked-body decoder (`decodeChunkedBody()`)
    returned only the decoded payload, not how many bytes of the read
    buffer it had actually consumed, so the exchange loop marked the
    upstream connection reusable unconditionally the instant decoding
    succeeded -- even when extra/ghost bytes already sat past the
    terminating chunk's trailer section in the same read, the chunked-body
    counterpart of defect 7. It also advanced past the two bytes following
    each chunk's data without checking they were a literal CRLF, and
    computed chunk boundaries with unchecked `usize` arithmetic that a
    maliciously oversized hex chunk-size could overflow, crashing the
    process via a safety-checked panic instead of failing the request.
    Fixed by having `decodeChunkedBody()` report a consumed-byte offset
    that the caller compares against the full amount read before marking
    the connection reusable, validating the trailing CRLF literally, and
    using checked arithmetic that surfaces overflow as
    `error.UpstreamProtocolError` instead of a panic.
18. `parseStrictStatusLine()` required exactly three decimal digits but
    never checked they fell inside RFC 9110 §15's valid `100..599` status
    code range, so a value like `099` or `600` parsed successfully. On the
    buffered path the numeric status is later reformatted straight back
    out to the client with `{d}`, so an unrejected `099` upstream status
    became an invalid `HTTP/1.1 99 ...` downstream response line rather
    than the safe `error.UpstreamProtocolError`/502 path; an out-of-range
    high value is likewise not a status any caller downstream of the
    parser is prepared to handle. Fixed by rejecting any status code
    outside `100..599` in the shared `parseStrictStatusLine()`, covering
    both the buffered and streaming paths from the single call site.
19. The campaign's request-framing smuggling oracle (`framing_marker_case()`)
    sent every malformed/ambiguous probe to `/protected` with no
    `Authorization` header at all. Its pass condition -- zero upstream hits
    -- was equally satisfied by "the framing parser correctly rejected this"
    or "the parser wrongly accepted it, but auth rejected the request
    anyway", so 15 live cases proved nothing about parser behavior. Fixed by
    giving every probe valid auth, so a parser bug that wrongly accepts the
    framing now actually reaches (and is visible at) the upstream instead of
    being masked by the auth gate.
20. Once probes had valid auth, `Request.parse()`/`parseHead()` (request
    direction) turned out to have the same `Transfer-Encoding` list-matching
    defect already fixed on the response direction (defect 14): a coding
    list like `Transfer-Encoding: chunked, gzip` or `gzip, chunked` was
    accepted as plain chunked framing because the check only asked "does any
    comma-separated token equal chunked". Fixed the same way: the value must
    equal `chunked` exactly.
21. The request-side chunked-body decoder (`decodeChunkedBody()` in
    `src/http/request.zig`) had the same defects as the response-side one
    before defects 13/17 fixed it: its outer loop condition
    (`while (pos < data.len)`) silently accepted reaching the end of the
    buffer right after a nonzero chunk -- with no terminating zero-size
    chunk ever seen -- as a complete body; it never required the trailer
    section to reach its own blank-line terminator; and it always reported
    `total_bytes = data.len`, so a pipelined next request sitting right
    after a chunked body's real terminator was silently swallowed into "this
    request's consumed bytes" instead of being left for the next parse.
    Fixed the same way as the response side: require the terminator, require
    the trailer section's blank line, and return an exact consumed offset.
22. Neither chunked-body decoder (request or response direction) validated
    that a non-blank trailer line was actually `header-field` syntax (RFC
    7230 §4.1.2 -- `name ":" value`); a line with no colon at all was
    silently accepted as "a trailer". Unstructured bytes there could really
    be the start of a pipelined next request. Fixed by requiring a colon in
    each non-blank trailer line, in both decoders.
23. `firstRequestCompleteLen()` in `src/gateway_connection.zig` -- which
    decides how many buffered bytes make up "one complete request" on the
    buffered H1 path -- had no `Transfer-Encoding` awareness at all. With no
    `Content-Length` header, `parseContentLength()` returns `null`, which
    defaulted the assumed body length to zero: a chunked request was
    declared "complete" the instant its headers finished, before a single
    body byte arrived. `Request.parse()` would then be handed an empty body
    slice (decoding to an empty body, thanks to defect 21's bug), and the
    connection would be treated as ready for the next request while the
    real chunked body was still in flight -- a request-smuggling-class
    desync where the actual body (or an attacker-crafted "next request"
    embedded in it) gets misread as a separate pipelined request. Fixed by
    adding a chunked-body boundary scanner that `firstRequestCompleteLen()`
    consults whenever `Transfer-Encoding: chunked` is present, so the
    buffered path waits for the real terminator the same way the
    `Content-Length` path waits for the declared body length.
24. The streaming path's interim-`1xx`-discarding loop
    (`streamProxyOverTransport()`) had three unbounded-processing gaps: no
    cap on the number of interim responses a hostile origin could drip-feed
    before Tardigrade gave up, no cancellation check inside the loop, and a
    single arena shared across every iteration that never freed a discarded
    interim head's header/reason-phrase allocations until the whole request
    ended -- letting a hostile origin grow memory and tie up the request
    past its nominal read deadline by sending 1xx responses indefinitely.
    Fixed by capping the number of interim responses
    (`max_interim_upstream_responses = 64`), checking `cancel_token` each
    iteration, and resetting the arena (`.free_all`) before reading each new
    interim head so only the eventual final head's allocations survive.
25. `UpstreamPool.checkout()` handed back an idle pooled connection without
    checking whether its peer had sent anything (or closed) since release.
    The bodiless-response fix (defect 7) prevents a bodiless response's
    connection from ever being pooled at all, but a `Content-Length` or
    chunked response that lands exactly on its declared boundary is
    legitimately marked reusable -- and a hostile or misbehaving origin can
    still send a "ghost" response *asynchronously*, any time after release,
    with no relationship to any request Tardigrade ever sent on that
    connection. Nothing at release time can observe that; only a check at
    the next checkout can. Fixed by checking each idle connection before
    handing it out, discarding it instead of reusing it if anything is
    already pending -- for a plain connection, a zero-timeout `poll()` on
    the raw fd (`POLLIN`/`POLLHUP`/`POLLERR`), failing closed on a poll
    error too. **Self-caught regression before landing**: the first version
    of this fix used the same raw-fd `poll()` for TLS-wrapped connections
    too, which broke TLS connection pooling outright -- real TLS 1.3
    servers routinely send a `NewSessionTicket` asynchronously right after
    the handshake, and that ciphertext is immediately readable on the raw
    fd regardless of whether any application data was ever sent, flagging
    essentially every freshly-pooled TLS connection as stale (caught by
    `zig build test-integration-native-tls`'s pooled-TLS-reuse assertion
    failing in CI). Fixed (first pass) by using `UpstreamTlsConn.readReady()`
    for TLS connections instead -- already-decrypted buffered plaintext or a
    clean TLS shutdown, which distinguishes genuine leftover application
    data from ordinary post-handshake protocol chatter. **Still incomplete**,
    per defect 27 below: `readReady()` only reflects what a *prior* `read()`
    call already decrypted, not ciphertext that has arrived on the wire but
    not yet been driven through the record layer.
26. Both newly-added chunked-body trailer checks (defect 22, request and
    response direction) validated only "does this non-blank line contain a
    colon", not that it is actually valid `field-name ":" OWS field-value
    OWS` syntax (RFC 9112 §7.1.2) -- so `Bad Name: x` (space in the name),
    `X-Bad\x00Name: x` (NUL in the name), or `X-Good: bad\x00value` (NUL in
    the value) all satisfied the check despite being malformed HTTP fields.
    On top of that, two more production trailer-consuming implementations
    had **no** validation at all, not even a colon check: the streaming
    request-upload decoder (`http.chunked_upload.Reader.consumeTrailers()`)
    and the streaming response-relay's trailer consumer
    (`consumeChunkTrailers()` in `gateway_proxy.zig`) -- so defect 22 was not
    actually closed on the production paths the campaign now exercises via
    the forced-streaming route and the streaming upload path. Fixed by
    adding one shared validator, `isValidTrailerLine()` in
    `src/http/headers.zig` (splits on the first colon, validates the name
    bytes exactly as they appear before it with `isValidHeaderName()` --
    critically, without trimming a space immediately before the colon into
    validity first, since RFC 7230/9112 treat that as invalid framing, not
    padding -- and the value with `isValidHeaderValue()`), and switching all
    four trailer-consuming implementations to call it, so this cannot drift
    out of sync between them the way the status-line boundary once did.
27. `UpstreamTlsConn.readReady()` (defect 25's fix) only reports
    already-decrypted plaintext (`pending() > 0`) or an already-observed
    clean shutdown -- it does not drive the record layer to process
    ciphertext that has newly arrived on the raw fd but has not yet been
    fed through it. A hostile TLS origin can send a second application-data
    TLS record immediately after a legitimate first response and before the
    connection is next checked out; that record can already be queued on
    the fd while `inbound_plaintext` is still empty, so `readReady()`
    reports "nothing pending" for it exactly as it would for a harmless
    session ticket -- the poisoned connection gets reused, and the next
    `read()`/`writeAll()` drive decrypts the ghost as if it were the
    unrelated next request's response.

    Fixed with `UpstreamTlsConn.drainQueuedRecordsAndCheckReady()`, which
    nonblockingly drives the record layer through everything currently
    queued on the raw fd (the fd is already nonblocking for this client, so
    `drive()` never waits on the network -- the same primitive `read()`
    itself uses before ever calling `waitForFd()`) and reports "do not
    reuse" only if genuine application plaintext or a clean shutdown
    actually emerges from that, correctly letting protocol-only traffic
    like a `NewSessionTicket` through without discarding a still-healthy
    connection. This is the function actually wired into
    `UpstreamPool.checkout()` (`hasUnexpectedReadableBytes()` in
    `src/http/upstream_pool.zig`) as of this writing; the simpler
    `readReady()` (already-decrypted plaintext or a completed clean
    shutdown only) remains defined on `UpstreamTlsConn` as a documented
    fallback, not currently called from the pool.

    **This fix has a two-round history worth recording in full, because
    both rounds surfaced real problems:**

    Round 8's first version of the drive-based fix passed locally (macOS)
    and in that platform's own CI, but broke `"native upstream https: two
    proxied requests reuse the pooled TLS connection"` on **Linux ARM CI**
    specifically (`reused_total` stayed at 0). Round 9 could not safely
    root-cause a cross-platform behavior difference without access to that
    environment, and reverted the intended call site to `readReady()` --
    but the revert was only made in the doc comment, PR description,
    `CHANGELOG.md`, and this file; the actual `return` statement in
    `hasUnexpectedReadableBytes()` still called
    `tls.drainQueuedRecordsAndCheckReady()`. Round 10's re-review caught
    this code/documentation mismatch directly: the shipped commit was
    running the drive-based behavior the surrounding text claimed had been
    removed. This is itself the kind of gap this whole campaign exists to
    catch -- an unreviewed discrepancy between what the evidence describes
    and what the binary actually does -- so it is recorded here rather than
    quietly corrected without a trace.

    Separately, round 10 also found a genuine logic gap in the drive-based
    check itself: a stalled drive (`made_progress == false`, meaning no
    more progress is possible without waiting for more bytes) is not by
    itself proof that nothing is pending. `drive()` can consume a prefix of
    a record into the parser without ever producing plaintext, if the
    record is only partially present on the wire -- so a hostile origin
    could trickle a ghost response's first few ciphertext bytes before
    release and complete it only after the connection is checked out again,
    and the original check would call that stall "clean" the moment it
    happened. Fixed by also checking, whenever the drive stalls, whether
    the record layer still owns any not-yet-resolved ciphertext -- the sum
    of `inbound_carrier.len + initial_parser.len + ciphertext_parser.len`,
    the same three buffers `PureZigRecordStream`'s own (private)
    `inboundCiphertextOwned()` sums internally -- and failing closed
    (treating the connection as unsafe to reuse) if that sum is nonzero.

    Issue #692 showed that the corrected drive-based check could still
    false-stale a healthy native-TLS pooled connection on hosted ARM
    runners when a protected record was only partially available at
    checkout. The pool now reports a typed TLS checkout outcome instead of
    a boolean stale decision. Definite application plaintext, peer close,
    drive errors, and drain-budget exhaustion still fail closed and close
    the connection. Incomplete ciphertext is moved to a bounded quarantine
    list so the current checkout opens a fresh connection without waiting,
    while a later maintenance pass can finish the nonblocking record drain
    and either return the connection to idle or close it once the record is
    classifiable. Retained capacity counts both idle and quarantined
    connections, and maintenance detaches a small quarantine batch before
    calling the TLS record drain so record work does not monopolize the
    shared pool mutex.

    The remaining deterministic coverage gap was closed by #697's
    socketpair-backed native-TLS pool harness. That harness completes a real
    TLS 1.3 handshake with `UpstreamTlsConn`, serves a clean persistent
    HTTP/1.1 exchange as the reuse control, injects complete unsolicited
    application data before checkout, splits one protected application record
    at a caller-selected byte boundary so checkout sees incomplete
    ciphertext, finishes that record during quarantine maintenance, and
    emits a controlled idle `close_notify`. The assertions pin the typed
    application-plaintext, incomplete-ciphertext quarantine, and peer-close
    outcomes, and prove that the poisoned connection is never reused for the
    later request path.

    Issue #725 investigated the old nested-Tardigrade-origin version of the
    native upstream HTTPS reuse test. Its preserved macOS ARM64 failure had
    `checkout_stale_tls_drive_error_total=1`, not plaintext, peer-close, or
    incomplete-ciphertext counters. That class maps to
    `UpstreamTlsConn.drainQueuedRecordsAndCheckReady()` catching a native
    record-layer `drive()` failure. The supported lifecycle diagnosis is that
    the old nested-origin fixture could leave the pooled TLS connection broken
    during readiness-probe teardown between release and the next checkout. An
    abrupt EOF without a peer `close_notify` maps to `TruncatedStream`, but the
    preserved soak telemetry did not retain the exact `drive()` error. That is
    a fixture lifecycle condition, not a production relaxation target: checkout
    must continue to reject every drive error because it cannot prove the
    connection is still synchronized.
    The focused #698/#724 soak therefore uses a persistent raw OpenSSL peer,
    which keeps one HTTP/1.1 TLS connection alive across both expected
    requests and isolates the upstream client/pool reuse invariant from a
    second Tardigrade process's readiness/teardown behavior.
28. `isValidHeaderName()` -- the function `isValidTrailerLine()` (defect 26)
    delegates field-name validation to -- claimed to implement RFC 7230
    §3.2.6's `token`/`tchar` grammar but actually only rejected control
    characters, space, DEL, and colon. Every *other* ASCII separator
    (`()<>@,;"/[]?={}` minus colon) still passed, so a trailer like
    `Bad(Name: x` or `Bad,Name: x` satisfied `isValidTrailerLine()` despite
    not being a valid header field -- meaning defect 26's stated invariant
    ("real `field-name: value` syntax across all four paths") was not
    actually true. Since every header-name validation in the codebase
    (ordinary request/response headers, not just trailers) goes through
    this same function, the gap was universal, not trailer-specific. Fixed
    by making `isValidHeaderName()` an actual `tchar` validator (RFC 7230
    §3.2.6: `"!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
    "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA`), which also hardens every
    other header-name validation site consistently, not only trailers.

Tooling: `scripts/run-f06-auth-framing-campaign.sh` builds `tardi`, starts
the fixtures in `tests/security/fixtures/` (`f06_upstream.py`,
`f06_tardigrade.conf` -- with both a buffered `/hostile` route and a
forced-streaming `/hostile-streaming` twin -- plus a symlink and an
`alias`-rooted directory), and runs the probe engine in
`tests/security/f06_live_campaign.py`, writing evidence (metadata, raw
results, process logs) to `.zig-cache/f06-campaign-673/`. All credentials
are synthetic and local-only; no production secrets or traffic were used.
164/164 probes pass after the fixes (Zig 0.16.0, macOS arm64; rerun the
script for current evidence -- results are not committed).

## Proxy Security Behavior Reference

See `docs/PROXY_SECURITY.md` for the authoritative description of Tardigrade's
intended behavior at each HTTP proxy trust boundary, including:

- Hop-by-hop header stripping (request and response directions)
- Connection header token handling (RFC 7230 §6.1)
- TE/CL conflict and duplicate Content-Length rejection
- Header casing normalization and validation rules
- Absolute-form vs origin-form URI handling
- X-Forwarded-* trust boundary and safe deployment requirements
- Host header enforcement (HTTP/1.1)
- Body size and header size/count limits
- Malformed upstream response handling
- Directory traversal protection for static serving
- TRACE method rejection (XST defense)
- Correlation ID validation (log poisoning defense)
- X-Tardigrade-* asserted identity header stripping
