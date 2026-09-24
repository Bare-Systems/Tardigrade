//! Shared proxy primitives and bounded buffered HTTP/1 upstream transports.
//!
//! Functions whose names include `BoundedBuffered` materialize an upstream
//! response in memory only after enforcing an explicit size cap. They are kept
//! separate from the reverse-proxy data-plane orchestration in
//! `gateway_proxy_runtime.zig` so streaming/backpressure work can replace the
//! data-plane executor without depending on control-plane helper behavior.

const compat = @import("zig_compat");
const std = @import("std");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");
const gs = @import("gateway_state.zig");
const gph = @import("gateway_proxy_headers.zig");
const gpres = @import("gateway_proxy_response.zig");
const gpt = @import("gateway_proxy_target.zig");
const gconn = @import("gateway_connection.zig");
const proxy_buffer_account = http.proxy_buffer_account;

fn upstreamAlpnPolicy(protocol: edge_config.UpstreamProtocol) http.upstream_tls.UpstreamAlpnPolicy {
    return switch (protocol) {
        .http1 => .require_http1,
        .h2, .h2c => .require_h2,
        .auto => .prefer_h2_allow_http1,
    };
}

// Compatibility re-exports of the split-out proxy helper APIs (headers /
// response / target modules) so existing callers that import this module keep
// compiling. New code should import from the owning module directly
// (`gph` / `gpres` / `gpt`); this shim shrinks as callers migrate (#156, #152).
// Grouped by owning module so code search points at the true owner.
//
// -- gateway_proxy_headers.zig (gph)
pub const buildForwardedFor = gph.buildForwardedFor;
pub const isTrustedUpstream = gph.isTrustedUpstream;
pub const appendTrustedUpstreamHeaders = gph.appendTrustedUpstreamHeaders;
pub const appendRequestIdHeaders = gph.appendRequestIdHeaders;
pub const writeRequestIdHeaders = gph.writeRequestIdHeaders;
pub const setRequestIdHeaders = gph.setRequestIdHeaders;
// -- gateway_proxy_response.zig (gpres)
pub const applyResponseHeaders = gpres.applyResponseHeaders;
pub const writeStreamedUpstreamResponse = gpres.writeStreamedUpstreamResponse;
pub const writeStreamedUpstreamResponseHeadFromHeaders = gpres.writeStreamedUpstreamResponseHeadFromHeaders;
pub const writeBufferedUpstreamResponse = gpres.writeBufferedUpstreamResponse;
pub const writeBufferedUpstreamResponseWithMetrics = gpres.writeBufferedUpstreamResponseWithMetrics;
pub const computeHstsValue = gpres.computeHstsValue;
pub const writeSecurityHeaders = gpres.writeSecurityHeaders;
pub const writeChunk = gpres.writeChunk;
pub const buildApiErrorJson = gpres.buildApiErrorJson;
pub const sendApiError = gpres.sendApiError;
pub const upstreamReasonPhrase = gpres.upstreamReasonPhrase;
// -- gateway_proxy_target.zig (gpt)
pub const ResolvedProxyTarget = gpt.ResolvedProxyTarget;
pub const resolveProxyTarget = gpt.resolveProxyTarget;
pub const appendProxyQueryString = gpt.appendProxyQueryString;
pub const unixSocketPathFromEndpoint = gpt.unixSocketPathFromEndpoint;
const maxBufferedUpstreamResponseBytes = gs.maxBufferedUpstreamResponseBytes;
const CancellationToken = http.cancellation.CancellationToken;

fn setSocketRecvTimeoutMs(fd: std.posix.fd_t, timeout_ms: u32) !void {
    const tv = std.posix.timeval{
        .sec = @intCast(timeout_ms / 1000),
        .usec = @intCast((timeout_ms % 1000) * 1000),
    };
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv));
}

fn setSocketTimeoutMs(fd: std.posix.fd_t, recv_timeout_ms: u32, send_timeout_ms: u32) !void {
    const recv_tv = std.posix.timeval{
        .sec = @intCast(recv_timeout_ms / 1000),
        .usec = @intCast((recv_timeout_ms % 1000) * 1000),
    };
    const send_tv = std.posix.timeval{
        .sec = @intCast(send_timeout_ms / 1000),
        .usec = @intCast((send_timeout_ms % 1000) * 1000),
    };
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&recv_tv));
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&send_tv));
}

fn isHttpMethodIdempotent(method: []const u8) bool {
    return std.ascii.eqlIgnoreCase(method, "GET") or
        std.ascii.eqlIgnoreCase(method, "HEAD") or
        std.ascii.eqlIgnoreCase(method, "PUT") or
        std.ascii.eqlIgnoreCase(method, "DELETE") or
        std.ascii.eqlIgnoreCase(method, "OPTIONS") or
        std.ascii.eqlIgnoreCase(method, "TRACE");
}

pub const UpstreamHeader = struct {
    name: []const u8,
    value: []const u8,
};

/// Fully materialized upstream response returned by bounded buffered helpers.
pub const BufferedUpstreamResponse = struct {
    metadata_arena: std.heap.ArenaAllocator,
    status_code: u16,
    reason: []const u8,
    headers: []UpstreamHeader,
    body: []u8,
    representation_content_length: ?[]const u8 = null,

    pub fn deinit(self: *BufferedUpstreamResponse, allocator: std.mem.Allocator) void {
        self.metadata_arena.deinit();
        allocator.free(self.body);
        self.* = undefined;
    }

    pub fn headerValue(self: *const BufferedUpstreamResponse, name: []const u8) ?[]const u8 {
        for (self.headers) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
        }
        return null;
    }
};

/// A client upload that is relayed to the upstream incrementally instead of
/// being materialized first (#139).
pub const StreamingRequestBody = struct {
    /// Downstream body framing.
    framing: Framing,
    /// Body bytes that arrived in the same read as the request head. They are
    /// relayed before the downstream connection is read again.
    initial_bytes: []const u8 = &.{},
    /// Decoded-payload budget enforced while relaying `.chunked` uploads. A
    /// `.length` upload is bounded by its own Content-Length, which routing
    /// already checked against the same maximum.
    max_body_bytes: usize = 0,

    pub const Framing = union(enum) {
        /// Client sent a `Content-Length`; the exact byte count is known up front.
        length: usize,
        /// Client sent `Transfer-Encoding: chunked`; the total size is unknown
        /// until the terminal chunk arrives.
        chunked,
    };
};

const ProxyBufferReservation = struct {
    account: proxy_buffer_account.Account,
    observer: proxy_buffer_account.Observer,
    /// Aggregate scopes this relay's bytes must clear on top of the per-stream
    /// bound. An empty capacity (a path with no origin identity and no process
    /// account, or a test harness) leaves those scopes unlimited.
    capacity: proxy_buffer_account.AggregateCapacity,
    active: bool = false,

    fn init(
        direction: proxy_buffer_account.Direction,
        limits: proxy_buffer_account.Limits,
        observer: proxy_buffer_account.Observer,
        capacity: proxy_buffer_account.AggregateCapacity,
    ) ProxyBufferReservation {
        return .{
            .account = proxy_buffer_account.Account.init(direction, .stream, limits),
            .observer = observer,
            .capacity = capacity,
        };
    }

    fn reserve(self: *ProxyBufferReservation, bytes: usize) !void {
        const before = self.account.snapshot();
        self.account.reserve(bytes) catch |err| {
            const after = self.account.snapshot();
            if (after.limit_exceeded_events > before.limit_exceeded_events) {
                self.observer.recordReservation(self.account.direction, 0, false, true);
            }
            return err;
        };
        // Charge the aggregate scopes only once the per-stream bound has
        // admitted the bytes, and roll the per-stream reservation back if they
        // refuse: no scope may be left holding bytes this relay never took.
        self.capacity.reserve(self.account.direction, bytes) catch |err| {
            self.account.release(bytes) catch unreachable;
            self.observer.recordAggregateLimitExceeded(
                self.account.direction,
                proxy_buffer_account.aggregateFailureScope(err),
            );
            return error.ProxyBufferCapacityUnavailable;
        };
        const after = self.account.snapshot();
        self.observer.recordReservation(
            self.account.direction,
            bytes,
            after.high_watermark_events > before.high_watermark_events,
            after.limit_exceeded_events > before.limit_exceeded_events,
        );
        // The HTTP/1 relay's buffer is allocated for as long as it is reserved,
        // so its logical and retained byte counts move together — unlike an
        // HTTP/2 stream queue, which drains ahead of its backing storage.
        self.observer.recordRetainedBytes(self.account.direction, bytes);
        self.active = true;
    }

    fn release(self: *ProxyBufferReservation, bytes: usize) void {
        if (!self.active) return;
        self.account.release(bytes) catch unreachable;
        self.capacity.release(self.account.direction, bytes);
        self.observer.releaseReservation(self.account.direction, bytes);
        self.observer.releaseRetainedBytes(self.account.direction, bytes);
        self.active = self.account.snapshot().current != 0;
    }

    fn releaseAll(self: *ProxyBufferReservation) void {
        const current = self.account.snapshot().current;
        if (current == 0) return;
        self.release(current);
    }
};

/// Reserve request-direction relay bytes with the failure semantics #140 defines
/// for the pre-commitment side of the boundary. The two refusals mean different
/// things and must not collapse into one status: a per-stream refusal is this
/// client's in-flight upload outgrowing the bound it is allowed (`413`), while
/// an aggregate refusal is the proxy being out of room for anybody (`503`,
/// already the error's own meaning). Both are raised before any response byte
/// is committed, and neither is charged to the origin.
fn reserveUploadBytes(reservation: *ProxyBufferReservation, bytes: usize) !void {
    reservation.reserve(bytes) catch |err| return switch (err) {
        error.BufferLimitExceeded => error.RequestBufferLimitExceeded,
        else => err,
    };
}

/// The HTTP/1 upload relay's fixed copy buffer. Named because the reservation
/// covering it is taken before the request head is written, in a different
/// function from the array it describes.
const http1_upload_relay_bytes: usize = 16 * 1024;

/// Build the `:path` pseudo-header value. Extracted so the HTTP/2 caller can
/// hand the connection reference back on failure instead of returning through
/// a bare `try` while holding it.
fn buildRequestTarget(
    path_buf: *std.Io.Writer.Allocating,
    path_component: []const u8,
    query: ?std.Uri.Component,
) !void {
    try path_buf.writer.writeAll(if (path_component.len > 0) path_component else "/");
    if (query) |q| {
        try path_buf.writer.writeByte('?');
        try path_buf.writer.writeAll(uriComponentBytes(q));
    }
}

/// The smallest relay buffer any path will use. Config validation already
/// floors `proxy_stream_buffer_size` here and checks every policy against it,
/// so this is a backstop for the one place a buffer size is derived rather than
/// configured: the HTTP/2 relay sizing itself to a connection's pinned policy.
const min_proxy_relay_bytes: usize = 16 * 1024;

/// Bytes a relay retains from the request head, on top of its fixed relay
/// buffer. The two framings retain different amounts of the same slice: a
/// `.length` upload forwards only the body bytes it is owed, while a `.chunked`
/// upload hands the whole raw remainder to the decoder, which reads framing
/// octets out of it too — so the retained slice there is its raw length.
fn uploadInitialBytesFootprint(sb: StreamingRequestBody) usize {
    return switch (sb.framing) {
        .length => |content_length| @min(sb.initial_bytes.len, content_length),
        .chunked => sb.initial_bytes.len,
    };
}

/// Claim an upload's whole known buffer footprint *before* anything is sent
/// upstream.
///
/// #140 requires capacity decisions to be deterministic before request
/// forwarding, and that is not just bookkeeping: reserving inside the relay
/// means the request head (HTTP/1) or HEADERS (HTTP/2) has already reached the
/// origin, so a local 413/503 would leave a real, possibly side-effecting
/// request half-delivered. Reserving first makes a refusal something the origin
/// never sees.
///
/// The returned reservation is live and owned by the caller, which must
/// `releaseAll` it on every exit; the relay releases the initial-bytes portion
/// as those bytes drain.
fn preflightUploadReservation(
    limits: proxy_buffer_account.Limits,
    observer: proxy_buffer_account.Observer,
    capacity: proxy_buffer_account.AggregateCapacity,
    relay_bytes: usize,
    initial_bytes: usize,
) !ProxyBufferReservation {
    var reservation = ProxyBufferReservation.init(.downstream_to_upstream, limits, observer, capacity);
    errdefer reservation.releaseAll();

    try reserveUploadBytes(&reservation, relay_bytes);
    if (initial_bytes != 0) try reserveUploadBytes(&reservation, initial_bytes);
    return reservation;
}

/// Note a write that cannot make progress right now as a downstream read pause.
/// The check never waits (zero timeout), so a relay whose origin keeps draining
/// costs one non-blocking `poll` per chunk and never touches the counters.
/// Only a genuinely full send buffer counts: a socket that is erroring or hung
/// up records nothing, so a broken upstream never looks like a slow one.
///
/// This reports a stall that is *already* in effect, so a single write that
/// happens to block briefly after the check passes is not counted. That is the
/// intended reading: an origin that has genuinely stopped consuming leaves the
/// send buffer full across relay iterations and is caught, while a momentary
/// block is not a backpressure event worth a counter.
fn noteUpstreamWriteStall(fd: std.posix.fd_t, stall: *proxy_buffer_account.ReadStall) void {
    if (pollUpstreamWritability(fd) == .blocked) stall.pause();
}

pub const StreamingProxyResult = struct {
    status_code: u16,
    reason: []const u8,
    response_body_bytes: usize,
    upstream_ttfb_ms: u64,
    upstream_aborted: bool = false,
    downstream_aborted_after_status: bool = false,
    /// The relay was truncated because *local* proxy buffer capacity ran out,
    /// not because the origin failed. The response head was already committed
    /// so the status cannot change, but the origin must not be blamed for it —
    /// counting this against upstream health would let local memory pressure
    /// trip a healthy origin's circuit breaker.
    local_capacity_aborted: bool = false,
};

fn streamingResultAfterDownstreamAbort(status_code: u16, reason: []const u8, body_bytes: usize, ttfb_ms: u64) StreamingProxyResult {
    return .{
        .status_code = status_code,
        .reason = reason,
        .response_body_bytes = body_bytes,
        .upstream_ttfb_ms = ttfb_ms,
        .downstream_aborted_after_status = true,
    };
}

pub fn uriComponentBytes(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw => |value| value,
        .percent_encoded => |value| value,
    };
}

/// Parse an HTTP/1 response that has already been read under a caller-owned
/// bound. Do not call this on unbounded network input.
pub fn parseBufferedUpstreamResponse(allocator: std.mem.Allocator, raw: []const u8) !BufferedUpstreamResponse {
    var metadata_arena = std.heap.ArenaAllocator.init(allocator);
    errdefer metadata_arena.deinit();
    const metadata_allocator = metadata_arena.allocator();

    // If the upstream closed before sending a complete response head, treat it
    // as a protocol error (not an unsupported method — the name would be
    // misleading here).  Callers synthesise a 502 Bad Gateway for this case.
    const header_end = std.mem.find(u8, raw, "\r\n\r\n") orelse return error.UpstreamProtocolError;
    const headers_raw = raw[0..header_end];

    // Uses the SAME strict status-line parser `detectResponseFraming` (the
    // exchange loop's framing/reuse decisions) already used to determine
    // how many bytes to read for this response (#673 review). A prior
    // version had this function find the status line's own end via the
    // first BARE LF while `detectResponseFraming` required an exact
    // `\r\n`, so the two could disagree about where headers begin -- e.g.
    // hiding one of two duplicate `Content-Length` fields from whichever
    // parser's view happened to start later, reopening the exact
    // order-dependent framing ambiguity the duplicate-Content-Length
    // rejection was meant to close.
    const status_line = try parseStrictStatusLine(headers_raw);
    const status_code = status_line.status_code;
    const reason = status_line.reason;

    // RFC 7230 §3.3 / RFC 7231 §6.3.5, §6.5.5: 1xx, 204, and 304 responses
    // are defined as bodiless *regardless of any Content-Length the
    // upstream sent*. A downstream client or intermediary honors that rule
    // and will treat any trailing bytes as the start of the next response
    // on the connection -- so blindly forwarding a hostile/misbehaving
    // upstream's illegal body here is itself a response-splitting vector,
    // not just an RFC nicety (#673 review). Discard any trailing bytes
    // rather than treating them as this response's body.
    const resp_body = if (responseStatusIsBodiless(status_code)) "" else raw[header_end + 4 ..];

    var resp_headers = std.array_list.Managed(UpstreamHeader).init(metadata_allocator);
    var representation_content_length: ?[]const u8 = null;
    var hdr_lines = std.mem.splitSequence(u8, headers_raw[status_line.header_lines_start..], "\r\n");
    while (hdr_lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        const hname = std.mem.trim(u8, line[0..colon], " \t");
        const hval = std.mem.trim(u8, line[colon + 1 ..], " \t");
        // Reject the whole response rather than silently forwarding a
        // malformed header: an upstream response header is only ever
        // split on an exact "\r\n" line boundary, so a bare CR/LF or NUL
        // embedded *inside* what should be a single header value survives
        // into `hval` unless validated here. Without this check, a hostile
        // or compromised upstream could ride control characters straight
        // through to the client (#673) -- the request-direction parser
        // already rejects these via Headers.append()/isValidHeaderValue();
        // upstream responses never went through that path at all.
        if (!http.headers.isValidHeaderName(hname) or !http.headers.isValidHeaderValue(hval)) {
            return error.UpstreamProtocolError;
        }
        // Scan the SAME header-lines view this loop itself iterates
        // (starting after the status line), not the whole `headers_raw`
        // from byte 0 (#673 review). Scanning from byte 0 let a status
        // line corrupted by an embedded bare LF merge with the first real
        // header line into one bogus "\r\n"-delimited segment, which no
        // longer matched "connection" by name -- hiding a genuine
        // Connection-nominated header from this scanner even though the
        // main loop above (which already starts past the status line)
        // parsed that same header correctly.
        const connection_nominated = gph.anyRawConnectionHeaderReferencesHeader(headers_raw[status_line.header_lines_start..], hname);
        if (std.ascii.eqlIgnoreCase(hname, "content-length") and representation_content_length == null and !connection_nominated) {
            representation_content_length = try metadata_allocator.dupe(u8, hval);
        }
        if (gph.shouldSkipUpstreamResponseHeader(hname, null)) continue;
        if (connection_nominated) continue;
        try resp_headers.append(.{
            .name = try metadata_allocator.dupe(u8, hname),
            .value = try metadata_allocator.dupe(u8, hval),
        });
    }

    // Allocate everything into the arena BEFORE copying `metadata_arena` into
    // the returned struct. A struct literal evaluates fields in order, so
    // copying the arena first would snapshot its buffer list before these
    // allocations — and when no headers were kept (response carried only
    // hop-by-hop headers), the arena had no buffer node yet, so the `reason`
    // node would be created only in the local arena and leak.
    const reason_owned = try metadata_allocator.dupe(u8, reason);
    const headers_owned = try resp_headers.toOwnedSlice();
    const body_owned = try allocator.dupe(u8, resp_body);

    return .{
        .metadata_arena = metadata_arena,
        .status_code = status_code,
        .reason = reason_owned,
        .headers = headers_owned,
        .body = body_owned,
        .representation_content_length = representation_content_length,
    };
}

/// Execute a bounded buffered HTTP/1 request over a Unix socket. This is
/// appropriate for small control-plane/internal calls and compatibility paths
/// where the caller provides a strict response cap.
///
/// When `pool` is non-null and enabled, connections are kept alive and reused
/// under `unix:<path>` keys (#239 — unix connects are cheap, but keep-alive
/// still spares the origin per-request accept/fd churn, matters for
/// php-fpm-style backends, and brings unix upstreams under the same
/// idle/lifetime/active-cap policy and metrics as TCP). A reused connection
/// the origin closed while idle is retried once on a fresh one.
pub fn executeBoundedBufferedUnixSocketHttpRequest(
    allocator: std.mem.Allocator,
    socket_path: []const u8,
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    body: []const u8,
    content_type_override: ?[]const u8,
    max_buffered_response_bytes: usize,
    timeout_ms: u32,
    /// If > 0, overrides `SO_RCVTIMEO` after sending the request to enforce a
    /// separate deadline for waiting on the first response byte (distinct from
    /// the write-phase timeout above).
    response_timeout_ms: u32,
    /// Optional keep-alive pool (#239). Null (or disabled) keeps the previous
    /// fresh `Connection: close` connection per request.
    pool: ?*http.upstream_pool.UpstreamPool,
) !BufferedUpstreamResponse {
    const active_pool: ?*http.upstream_pool.UpstreamPool = if (pool) |p| (if (p.config.enabled) p else null) else null;

    if (active_pool == null) {
        const fd = try compat.connectBlockingUnix(socket_path);
        defer _ = std.c.close(fd);
        return exchangeBoundedBufferedHttpRequest(
            allocator,
            compat.netStreamFromFd(fd),
            fd,
            uri,
            method,
            extra_headers,
            body,
            content_type_override,
            max_buffered_response_bytes,
            timeout_ms,
            response_timeout_ms,
            false,
            null,
        );
    }

    const p = active_pool.?;
    var key_buf: [512]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "unix:{s}", .{socket_path}) catch socket_path;

    var attempt: usize = 0;
    while (attempt < 2) : (attempt += 1) {
        const now_ms = http.event_loop.monotonicMs();
        var reused = false;
        var conn: http.upstream_pool.PooledConn = undefined;
        if (attempt == 0) {
            if (try p.checkout(key, now_ms)) |pooled| {
                conn = pooled;
                reused = true;
            }
        } else {
            try p.reserveSlot(key); // stale retry: deliberately fresh, still capped
        }
        if (!reused) {
            const connect_start_ms = http.event_loop.monotonicMs();
            const new_fd = compat.connectBlockingUnix(socket_path) catch |err| {
                p.releaseSlot(key);
                return err;
            };
            p.recordConnectLatency(http.event_loop.monotonicMs() - connect_start_ms);
            p.noteNewConnection(key);
            conn = .{ .stream = compat.netStreamFromFd(new_fd), .tls = null, .created_ms = now_ms, .last_used_ms = now_ms };
        }
        const fd = conn.stream.handle;

        var reusable = false;
        const result = exchangeBoundedBufferedHttpRequest(allocator, compat.netStreamFromFd(fd), fd, uri, method, extra_headers, body, content_type_override, max_buffered_response_bytes, timeout_ms, response_timeout_ms, true, &reusable);

        if (result) |resp| {
            p.release(key, conn, reusable, http.event_loop.monotonicMs());
            return resp;
        } else |err| {
            p.release(key, conn, false, http.event_loop.monotonicMs());
            if (shouldRetryStalePooledBufferedExchange(reused, attempt, err, method)) {
                p.recordStaleRetry(key);
                continue; // request never delivered — retry once on a fresh conn
            }
            return err;
        }
    }
    unreachable;
}

/// Whether a buffered exchange that failed on attempt 0 should be retried once
/// on a fresh connection. A write failure on a reused pooled connection means
/// the origin closed it while idle and never saw the request, so every method
/// is safe (issue #787). A zero-byte response read is ambiguous about delivery,
/// so it stays limited to idempotent methods.
fn shouldRetryStalePooledBufferedExchange(reused: bool, attempt: usize, err: anyerror, method: []const u8) bool {
    if (!reused or attempt != 0) return false;
    if (err == error.UpstreamRequestWriteFailed) return true;
    return err == error.UpstreamConnectionClosed and isHttpMethodIdempotent(method);
}

/// Execute a bounded buffered HTTP/1 request over a TCP socket, with optional
/// TLS. This is the manual-transport replacement for the `std.http.Client`
/// data-plane and control-plane proxy paths: unlike `std.http.Client` it
/// exposes the underlying socket fd, so per-phase connect and response timeouts
/// (`SO_SNDTIMEO`/`SO_RCVTIMEO`/`poll`) are enforced (issue #196).
///
/// When `pool` is non-null and enabled the connection is kept alive and reused
/// across requests (issue #141), for both plain HTTP and TLS (#141 Phase 1c).
/// The pool key is scheme-prefixed so plain and TLS connections to the same
/// origin are never confused. When pooling is off, a fresh `Connection: close`
/// connection is used per request.
pub fn executeBoundedBufferedTcpHttpRequest(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    /// When non-null, wrap the TCP stream in TLS before exchanging the request.
    tls_options: ?http.upstream_tls.UpstreamTlsOptions,
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    body: []const u8,
    content_type_override: ?[]const u8,
    max_buffered_response_bytes: usize,
    /// Bounds the connect/handshake and request-write phase. The blocking TCP
    /// connect itself is not interruptible by SO_*TIMEO; this bounds the
    /// handshake stall and the write phase that follow.
    connect_timeout_ms: u32,
    /// If > 0, overrides `SO_RCVTIMEO` after the request is sent to bound the
    /// wait for the first response byte separately from the write phase.
    response_timeout_ms: u32,
    /// Optional keep-alive pool for upstream connection reuse.
    pool: ?*http.upstream_pool.UpstreamPool,
    /// Optional per-origin HTTP/2 multiplexing pool (#145). When present and the
    /// caller offered h2, requests multiplex over a shared origin connection.
    h2_pool: ?*http.upstream_h2.H2ConnPool,
    /// Speak prior-knowledge cleartext h2c to this plain-HTTP upstream (#237).
    /// Only set when the operator explicitly configured
    /// `TARDIGRADE_UPSTREAM_PROTOCOL=h2c` — there is no negotiation on
    /// cleartext, so an h1-only origin would break under it. Ignored for TLS.
    h2c_prior_knowledge: bool,
) !BufferedUpstreamResponse {
    // HTTP/2 upstream (#145): when the caller asked to offer h2 (TLS only),
    // multiplex over a shared per-origin connection when an h2 pool is provided,
    // else fall back to a fresh single-stream connection. h1 origins are
    // detected via ALPN and handled on the HTTP/1.1 path.
    if (tls_options) |opts| {
        if (opts.alpn_policy.offersH2()) {
            if (h2_pool) |hp| {
                return executeBufferedViaH2Pool(allocator, hp, host, port, opts, uri, method, extra_headers, body, content_type_override, max_buffered_response_bytes, connect_timeout_ms, response_timeout_ms, pool);
            }
            return executeBufferedH2OrH1Fresh(allocator, host, port, opts, uri, method, extra_headers, body, content_type_override, max_buffered_response_bytes, connect_timeout_ms, response_timeout_ms, pool);
        }
    } else if (h2c_prior_knowledge) {
        // Cleartext h2c (#237): multiplex over the shared per-origin plain h2
        // connection. Requires the pool (always present on the data plane);
        // without one, fall through to HTTP/1.1.
        if (h2_pool) |hp| {
            return executeBufferedViaH2Pool(allocator, hp, host, port, null, uri, method, extra_headers, body, content_type_override, max_buffered_response_bytes, connect_timeout_ms, response_timeout_ms, pool);
        }
    }
    // Every request that reaches the buffered HTTP/1.1 path counts as h1 (an h2
    // request would have returned above). The streaming path counts its own
    // requests in executeStreamingHttpProxyRequest.
    if (pool) |p| p.recordProtocol(false);

    const active_pool: ?*http.upstream_pool.UpstreamPool = if (pool) |p| (if (p.config.enabled) p else null) else null;

    // No pool: a single fresh `Connection: close` connection (plain or TLS),
    // cleaned up on return.
    if (active_pool == null) {
        const start_ms = http.event_loop.monotonicMs();
        const fd = try compat.connectBoundedTcp(host, port, connect_timeout_ms);
        defer _ = std.c.close(fd);
        if (connect_timeout_ms > 0) {
            try setSocketTimeoutMs(fd, connect_timeout_ms, connect_timeout_ms);
        }
        if (tls_options) |opts| {
            var tls_conn = try http.upstream_tls.UpstreamTlsConn.connect(fd, host, opts);
            defer tls_conn.deinit();
            const resp = try exchangeBoundedBufferedHttpRequest(allocator, &tls_conn, fd, uri, method, extra_headers, body, content_type_override, max_buffered_response_bytes, connect_timeout_ms, response_timeout_ms, false, null);
            if (pool) |p| p.recordRequestLatency(false, http.event_loop.monotonicMs() - start_ms);
            return resp;
        }
        const resp = try exchangeBoundedBufferedHttpRequest(allocator, compat.netStreamFromFd(fd), fd, uri, method, extra_headers, body, content_type_override, max_buffered_response_bytes, connect_timeout_ms, response_timeout_ms, false, null);
        if (pool) |p| p.recordRequestLatency(false, http.event_loop.monotonicMs() - start_ms);
        return resp;
    }

    const p = active_pool.?;
    const is_tls = tls_options != null;
    var key_buf: [268]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "{s}:{s}:{d}", .{ if (is_tls) "https" else "http", host, port }) catch host;

    // Attempt 0 uses a pooled connection when available; a reused connection the
    // origin already closed (error.UpstreamConnectionClosed with zero bytes) is
    // retried once on a fresh connection since the request was never delivered.
    // Checkout reserves an active slot before connecting, so the per-origin
    // active cap (#239) cannot be raced past; a failed connect must release the
    // reservation.
    var attempt: usize = 0;
    while (attempt < 2) : (attempt += 1) {
        const now_ms = http.event_loop.monotonicMs();
        var reused = false;
        var conn: http.upstream_pool.PooledConn = undefined;
        if (attempt == 0) {
            if (try p.checkout(key, now_ms)) |pooled| {
                conn = pooled;
                reused = true;
            }
        } else {
            // Stale retry: deliberately fresh, but still capped.
            try p.reserveSlot(key);
        }
        if (!reused) {
            const connect_start_ms = http.event_loop.monotonicMs();
            const new_fd = compat.connectBoundedTcp(host, port, connect_timeout_ms) catch |err| {
                p.releaseSlot(key);
                return err;
            };
            p.recordConnectLatency(http.event_loop.monotonicMs() - connect_start_ms);
            if (is_tls) {
                if (connect_timeout_ms > 0) setSocketTimeoutMs(new_fd, connect_timeout_ms, connect_timeout_ms) catch {};
                const tls_ptr = p.allocator.create(http.upstream_tls.UpstreamTlsConn) catch {
                    _ = std.c.close(new_fd);
                    p.releaseSlot(key);
                    return error.OutOfMemory;
                };
                tls_ptr.* = http.upstream_tls.UpstreamTlsConn.connect(new_fd, host, tls_options.?) catch |err| {
                    p.allocator.destroy(tls_ptr);
                    _ = std.c.close(new_fd);
                    p.releaseSlot(key);
                    return err;
                };
                p.noteNewConnection(key);
                conn = .{ .stream = compat.netStreamFromFd(new_fd), .tls = tls_ptr, .created_ms = now_ms, .last_used_ms = now_ms };
            } else {
                p.noteNewConnection(key);
                conn = .{ .stream = compat.netStreamFromFd(new_fd), .tls = null, .created_ms = now_ms, .last_used_ms = now_ms };
            }
        }
        const fd = conn.stream.handle;

        if (connect_timeout_ms > 0) {
            setSocketTimeoutMs(fd, connect_timeout_ms, connect_timeout_ms) catch {};
        }

        var reusable = false;
        const exchange_start_ms = http.event_loop.monotonicMs();
        const result = if (conn.tls) |tls|
            exchangeBoundedBufferedHttpRequest(allocator, tls, fd, uri, method, extra_headers, body, content_type_override, max_buffered_response_bytes, connect_timeout_ms, response_timeout_ms, true, &reusable)
        else
            exchangeBoundedBufferedHttpRequest(allocator, compat.netStreamFromFd(fd), fd, uri, method, extra_headers, body, content_type_override, max_buffered_response_bytes, connect_timeout_ms, response_timeout_ms, true, &reusable);

        if (result) |resp| {
            p.release(key, conn, reusable, http.event_loop.monotonicMs());
            p.recordRequestLatency(false, http.event_loop.monotonicMs() - exchange_start_ms);
            return resp;
        } else |err| {
            p.release(key, conn, false, http.event_loop.monotonicMs()); // active--, close (deinits TLS)
            if (shouldRetryStalePooledBufferedExchange(reused, attempt, err, method)) {
                p.recordStaleRetry(key);
                continue; // retry once on a fresh connection
            }
            return err;
        }
    }
    unreachable;
}

/// HTTP/2 upstream attempt over a fresh TLS connection (#145, PR 1). Connects,
/// handshakes with ALPN offering h2, and — if the origin negotiated h2 — runs a
/// single-stream h2 exchange; otherwise falls back to the HTTP/1.1 buffered
/// exchange on the same connection. Not pooled in PR 1 (the connection is closed
/// on return); h2 pooling/multiplexing is a later PR.
fn executeBufferedH2OrH1Fresh(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    opts: http.upstream_tls.UpstreamTlsOptions,
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    body: []const u8,
    content_type_override: ?[]const u8,
    max_buffered_response_bytes: usize,
    connect_timeout_ms: u32,
    response_timeout_ms: u32,
    pool: ?*http.upstream_pool.UpstreamPool,
) !BufferedUpstreamResponse {
    const fd = try compat.connectBoundedTcp(host, port, connect_timeout_ms);
    defer _ = std.c.close(fd);
    if (connect_timeout_ms > 0) setSocketTimeoutMs(fd, connect_timeout_ms, connect_timeout_ms) catch {};

    var tls_conn = try http.upstream_tls.UpstreamTlsConn.connect(fd, host, opts);
    defer tls_conn.deinit();

    if (tls_conn.negotiatedProtocol() == .http2) {
        if (pool) |p| p.recordProtocol(true);
        const deadline_ms: u32 = if (response_timeout_ms > 0)
            response_timeout_ms
        else if (connect_timeout_ms > 0) connect_timeout_ms else 30_000;

        var authority_buf: [300]u8 = undefined;
        const authority = if (port == 443)
            host
        else
            std.fmt.bufPrint(&authority_buf, "{s}:{d}", .{ host, port }) catch host;

        var path_buf: std.Io.Writer.Allocating = .init(allocator);
        defer path_buf.deinit();
        const path_component = uriComponentBytes(uri.path);
        try path_buf.writer.writeAll(if (path_component.len > 0) path_component else "/");
        if (uri.query) |q| {
            try path_buf.writer.writeByte('?');
            try path_buf.writer.writeAll(uriComponentBytes(q));
        }

        const start_ms = http.event_loop.monotonicMs();
        var h2resp = try http.upstream_h2.exchange(allocator, &tls_conn, fd, .{
            .method = method,
            .scheme = "https",
            .authority = authority,
            .path = path_buf.written(),
            .headers = extra_headers,
            .body = body,
        }, deadline_ms);
        defer h2resp.deinit();
        if (pool) |p| p.recordRequestLatency(true, http.event_loop.monotonicMs() - start_ms);
        return h2ResponseToBuffered(allocator, &h2resp);
    }

    // Origin chose HTTP/1.1: run the buffered h1 exchange on this connection.
    if (pool) |p| p.recordProtocol(false);
    var reusable = false;
    const start_ms = http.event_loop.monotonicMs();
    const resp = try exchangeBoundedBufferedHttpRequest(allocator, &tls_conn, fd, uri, method, extra_headers, body, content_type_override, max_buffered_response_bytes, connect_timeout_ms, response_timeout_ms, false, &reusable);
    if (pool) |p| p.recordRequestLatency(false, http.event_loop.monotonicMs() - start_ms);
    return resp;
}

/// HTTP/2 buffered request multiplexed over a shared per-origin connection
/// (#145, PR 2). Acquires (or creates) the origin's h2 connection from the pool
/// and issues one stream on it. A connection-level failure evicts the dead
/// connection and retries once on a fresh one. If the origin negotiated HTTP/1.1
/// over ALPN, the request runs on the HTTP/1.1 path over that connection.
///
/// `opts == null` selects prior-knowledge cleartext h2c (#237): plain socket,
/// `http` scheme, `h2c:`-prefixed pool key, and no `.h1` fallback (there is no
/// negotiation to fall back from).
fn executeBufferedViaH2Pool(
    allocator: std.mem.Allocator,
    h2_pool: *http.upstream_h2.H2ConnPool,
    host: []const u8,
    port: u16,
    opts: ?http.upstream_tls.UpstreamTlsOptions,
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    body: []const u8,
    content_type_override: ?[]const u8,
    max_buffered_response_bytes: usize,
    connect_timeout_ms: u32,
    response_timeout_ms: u32,
    h1_pool: ?*http.upstream_pool.UpstreamPool,
) !BufferedUpstreamResponse {
    const deadline_ms: u32 = if (response_timeout_ms > 0)
        response_timeout_ms
    else if (connect_timeout_ms > 0) connect_timeout_ms else 30_000;

    const is_tls = opts != null;
    const scheme: []const u8 = if (is_tls) "https" else "http";
    const default_port: u16 = if (is_tls) 443 else 80;
    var key_buf: [300]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "{s}:{s}:{d}", .{ if (is_tls) "h2" else "h2c", host, port }) catch host;

    var attempt: usize = 0;
    while (attempt < 2) : (attempt += 1) {
        const acq = try h2_pool.acquire(key, host, port, opts, connect_timeout_ms, deadline_ms);
        switch (acq) {
            .h1 => |tls_ptr| {
                // ALPN negotiated HTTP/1.1: run the h1 exchange on this fresh
                // (unpooled) connection, then tear it down. (TLS only — the
                // h2c path has no negotiation and never lands here.)
                defer {
                    tls_ptr.close();
                    h2_pool.allocator.destroy(tls_ptr);
                }
                if (h1_pool) |p| p.recordProtocol(false);
                var reusable = false;
                const start_ms = http.event_loop.monotonicMs();
                const resp = try exchangeBoundedBufferedHttpRequest(allocator, tls_ptr, tls_ptr.fd, uri, method, extra_headers, body, content_type_override, max_buffered_response_bytes, connect_timeout_ms, response_timeout_ms, false, &reusable);
                if (h1_pool) |p| p.recordRequestLatency(false, http.event_loop.monotonicMs() - start_ms);
                return resp;
            },
            .h2 => |conn| {
                if (h1_pool) |p| p.recordProtocol(true);

                var authority_buf: [300]u8 = undefined;
                const authority = if (port == default_port)
                    host
                else
                    std.fmt.bufPrint(&authority_buf, "{s}:{d}", .{ host, port }) catch host;

                var path_buf: std.Io.Writer.Allocating = .init(allocator);
                defer path_buf.deinit();
                const path_component = uriComponentBytes(uri.path);
                try path_buf.writer.writeAll(if (path_component.len > 0) path_component else "/");
                if (uri.query) |q| {
                    try path_buf.writer.writeByte('?');
                    try path_buf.writer.writeAll(uriComponentBytes(q));
                }

                const start_ms = http.event_loop.monotonicMs();
                var h2resp = conn.request(.{
                    .method = method,
                    .scheme = scheme,
                    .authority = authority,
                    .path = path_buf.written(),
                    .headers = extra_headers,
                    .body = body,
                }) catch |err| {
                    // Connection-level failure: evict the dead connection so new
                    // requests do not pick it, drop our ref, and retry once.
                    h2_pool.evict(key, conn);
                    h2_pool.release(conn);
                    if (attempt == 0 and (err == error.Http2GoAway or err == error.Http2ConnectionClosed or err == error.Http2StreamReset)) {
                        continue;
                    }
                    return err;
                };
                defer h2resp.deinit();
                h2_pool.release(conn);
                if (h1_pool) |p| p.recordRequestLatency(true, http.event_loop.monotonicMs() - start_ms);
                return h2ResponseToBuffered(allocator, &h2resp);
            },
        }
    }
    unreachable;
}

/// Streaming reverse-proxy exchange over the per-origin HTTP/2 pool (#145,
/// Phase 4b PR 4). Issues the request as one stream on the shared origin
/// connection and relays DATA frames downstream as they arrive, with bounded
/// per-stream buffering: the actor replenishes the stream-level flow-control
/// window only as this relay drains, so a slow downstream client
/// backpressures its own stream without stalling other streams on the shared
/// connection (whose connection-level window the reader replenishes promptly).
///
/// A failure before any downstream byte evicts the connection and retries once
/// on connection-level errors (matching the buffered h2 path). Once the
/// response head has been written downstream, an upstream failure is reported
/// as an aborted relay (truncated chunked body) rather than an error. When the
/// Relay a streamed client upload to an HTTP/2 upstream as incremental DATA.
/// The caller owns connection teardown on error. `read_buf` is the single relay
/// buffer, so upload memory stays bounded; per-stream flow control supplies the
/// backpressure.
///
/// `reservation` is preflighted by the caller — before HEADERS are sent, so a
/// capacity refusal is something the origin never sees — and already covers
/// `read_buf` plus `uploadInitialBytesFootprint(sb)`. The caller releases the
/// rest; this function gives back only the initial-bytes portion as it drains.
fn relayStreamingUploadToHttp2(
    conn: anytype,
    stream: anytype,
    sb: StreamingRequestBody,
    read_buf: []u8,
    downstream_conn: anytype,
    cancel_token: ?*const CancellationToken,
    reservation: *ProxyBufferReservation,
) !void {
    switch (sb.framing) {
        .length => |content_length| {
            var sent: usize = @min(sb.initial_bytes.len, content_length);
            if (sent > 0) {
                conn.writeStreamingRequestBody(stream, sb.initial_bytes[0..sent], sent == content_length) catch |err| {
                    reservation.release(sent);
                    return err;
                };
                // Forwarded: the request head's body bytes are no longer held.
                reservation.release(sent);
            }
            while (sent < content_length) {
                if (cancelStopped(cancel_token)) return error.RequestCancelled;
                const want = @min(read_buf.len, content_length - sent);
                const n = downstream_conn.read(read_buf[0..want]) catch return error.ClientAborted;
                if (n == 0) return error.ClientAborted;
                try conn.writeStreamingRequestBody(stream, read_buf[0..n], sent + n == content_length);
                sent += n;
            }
            // A zero-length streamed body still needs an END_STREAM DATA frame.
            if (content_length == 0) try conn.writeStreamingRequestBody(stream, "", true);
        },
        .chunked => {
            // HTTP/2 has no chunked transfer coding: the decoded payload goes
            // out as DATA frames and END_STREAM replaces the terminal chunk, so
            // the upstream never sees a Content-Length it cannot know.
            var reader = http.chunked_upload.Reader(@TypeOf(downstream_conn))
                .init(downstream_conn, sb.initial_bytes, sb.max_body_bytes);
            // The decoder borrows the whole raw request-head remainder, framing
            // octets included — see `uploadInitialBytesFootprint`.
            var head_bytes_held = sb.initial_bytes.len;
            while (true) {
                if (cancelStopped(cancel_token)) return error.RequestCancelled;
                const n = try reader.next(read_buf);
                // Before acting on `n`: the terminal call consumes borrowed
                // trailer bytes too.
                releaseDrainedHeadBytes(reservation, &head_bytes_held, reader.pendingBytes());
                if (n == 0) break;
                try conn.writeStreamingRequestBody(stream, read_buf[0..n], false);
            }
            try conn.writeStreamingRequestBody(stream, "", true);
        },
    }
}

/// Streaming reverse-proxy exchange over the per-origin HTTP/2 pool (#145,
/// Phase 4b PR 4). Issues the request as one stream on the shared origin
/// connection and relays DATA frames downstream as they arrive, with bounded
/// per-stream buffering: the actor replenishes the stream-level flow-control
/// window only as this relay drains, so a slow downstream client
/// backpressures its own stream without stalling other streams on the shared
/// connection (whose connection-level window the reader replenishes promptly).
///
/// A failure before any downstream byte evicts the connection and retries once
/// on connection-level errors (matching the buffered h2 path). Once the
/// response head has been written downstream, an upstream failure is reported
/// as an aborted relay (truncated chunked body) rather than an error. When the
/// origin negotiates HTTP/1.1 via ALPN, the request runs on the h1 streaming
/// relay over that fresh (unpooled) connection instead.
///
/// The h2-pool `.h1` arm's exchange, factored out so it can be driven over an
/// arbitrary `transport`/`fd` pair in a unit test — production call sites
/// always pass the pool's `*UpstreamTlsConn`, but a test can pass any fake
/// transport implementing the same small `read`/`writeAll` surface (plus a
/// real fd for the poll-based readiness check `streamProxyOverTransport`'s
/// buffered reader falls back to). Sets `downstream_committed.*` on every
/// error return, from `streamProxyOverTransport`'s own `wrote_downstream`
/// (#643): once the response head is on the wire, the caller must not
/// serialize a second one after a later failure.
fn runNegotiatedH1Exchange(
    allocator: std.mem.Allocator,
    transport: anytype,
    fd: std.posix.fd_t,
    relay_bytes: usize,
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    buffered_body: []const u8,
    streaming_body: ?StreamingRequestBody,
    downstream_conn: anytype,
    downstream_writer: anytype,
    security: *const http.security_headers.SecurityHeaders,
    alt_svc: ?[]const u8,
    sticky_set_cookie: ?[]const u8,
    correlation_id: []const u8,
    downstream_keep_alive: bool,
    connect_timeout_ms: u32,
    read_deadline_ms: u32,
    cancel_token: ?*const CancellationToken,
    proxy_buffer_limits: proxy_buffer_account.Limits,
    proxy_buffer_observer: proxy_buffer_account.Observer,
    proxy_buffer_capacity: proxy_buffer_account.AggregateCapacity,
    downstream_committed: *bool,
) !StreamingProxyResult {
    var wrote_downstream = false;
    const res = streamProxyOverTransport(allocator, transport, fd, relay_bytes, uri, method, extra_headers, buffered_body, streaming_body, downstream_conn, downstream_writer, security, alt_svc, sticky_set_cookie, correlation_id, downstream_keep_alive, connect_timeout_ms, read_deadline_ms, cancel_token, &wrote_downstream, proxy_buffer_limits, proxy_buffer_observer, proxy_buffer_capacity) catch |err| {
        downstream_committed.* = wrote_downstream;
        return err;
    };
    return res.result;
}

/// `opts == null` selects prior-knowledge cleartext h2c (#237): plain socket,
/// `http` scheme, `h2c:`-prefixed pool key, no `.h1` fallback.
fn streamViaH2Pool(
    allocator: std.mem.Allocator,
    h2_pool: *http.upstream_h2.H2ConnPool,
    h1_pool: ?*http.upstream_pool.UpstreamPool,
    host: []const u8,
    port: u16,
    opts: ?http.upstream_tls.UpstreamTlsOptions,
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    buffered_body: []const u8,
    streaming_body: ?StreamingRequestBody,
    /// Relay buffer size the *current* config asks for. Deliberately a size
    /// rather than a buffer: the h2 path allocates its own once the connection
    /// is acquired, because only then is the policy that has to account for it
    /// known. Allocating up front and slicing down would leave the untouched
    /// remainder as real per-request memory that no scope is charged for —
    /// exactly the retained-but-unaccounted allocation these limits exist to
    /// prevent.
    requested_relay_bytes: usize,
    downstream_conn: anytype,
    downstream_writer: anytype,
    security: *const http.security_headers.SecurityHeaders,
    alt_svc: ?[]const u8,
    sticky_set_cookie: ?[]const u8,
    correlation_id: []const u8,
    downstream_keep_alive: bool,
    connect_timeout_ms: u32,
    read_deadline_ms: u32,
    cancel_token: ?*const CancellationToken,
    proxy_buffer_limits: proxy_buffer_account.Limits,
    proxy_buffer_observer: proxy_buffer_account.Observer,
    proxy_buffer_global: ?*proxy_buffer_account.Aggregate,
    /// Mirrors `executeStreamingHttpProxyRequest`'s own parameter of the same
    /// name: set true on an error return once the downstream response head
    /// has already been written, so the caller never serializes a second
    /// response onto an already-committed connection.
    downstream_committed: *bool,
) !StreamingProxyResult {
    const deadline_ms: u32 = if (read_deadline_ms > 0)
        read_deadline_ms
    else if (connect_timeout_ms > 0) connect_timeout_ms else 30_000;

    const is_tls = opts != null;
    const scheme: []const u8 = if (is_tls) "https" else "http";
    const default_port: u16 = if (is_tls) 443 else 80;
    var key_buf: [300]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "{s}:{s}:{d}", .{ if (is_tls) "h2" else "h2c", host, port }) catch host;

    var attempt: usize = 0;
    while (attempt < 2) : (attempt += 1) {
        const acq = try h2_pool.acquire(key, host, port, opts, connect_timeout_ms, deadline_ms);
        switch (acq) {
            .h1 => |tls_ptr| {
                // ALPN negotiated HTTP/1.1: run the h1 streaming relay on this
                // fresh (unpooled) connection, then tear it down.
                defer {
                    tls_ptr.close();
                    h2_pool.allocator.destroy(tls_ptr);
                }
                if (h1_pool) |p| p.recordProtocol(false);
                const start_ms = http.event_loop.monotonicMs();
                // An ALPN-h1 origin never creates an h2 origin entry, so its
                // per-origin account comes from the h1 pool — under the h1 key
                // (`https:host:port`), which is the same origin identity the
                // h1 relay would use had h2 never been offered. Keying it under
                // `h2:…` would split one origin's memory across two limits.
                const h1_origin_account: ?*proxy_buffer_account.Aggregate = if (h1_pool) |p| blk: {
                    var h1_key_buf: [300]u8 = undefined;
                    const h1_key = std.fmt.bufPrint(&h1_key_buf, "{s}:{s}:{d}", .{ scheme, host, port }) catch host;
                    break :blk p.originBufferAccount(h1_key) catch return error.ProxyBufferCapacityUnavailable;
                } else null;
                // A fresh, unpooled connection with no pinned policy of its
                // own, so this is an ordinary HTTP/1 exchange: allocate and
                // charge at the current config's size, exactly as the h1 path
                // below does.
                const result = try runNegotiatedH1Exchange(allocator, tls_ptr, tls_ptr.fd, requested_relay_bytes, uri, method, extra_headers, buffered_body, streaming_body, downstream_conn, downstream_writer, security, alt_svc, sticky_set_cookie, correlation_id, downstream_keep_alive, connect_timeout_ms, read_deadline_ms, cancel_token, proxy_buffer_limits, proxy_buffer_observer, .{ .origin = h1_origin_account, .global = proxy_buffer_global }, downstream_committed);
                if (h1_pool) |p| p.recordRequestLatency(false, http.event_loop.monotonicMs() - start_ms);
                return result;
            },
            .h2 => |conn| {
                if (h1_pool) |p| p.recordProtocol(true);

                // Aggregate capacity for this origin's queued response bytes
                // (#140). Looked up only on the h2 path, so an ALPN-h1 origin
                // never creates an h2 origin entry. The pointer is stable for
                // the pool's life, surviving retries and reconnects.
                //
                // A failure here means the accounting itself is unavailable
                // (allocation failure) — precisely when these limits matter
                // most. Dropping the scope would let the request retain
                // response bytes outside the configured per-origin bound, so
                // this is a deterministic pre-commit rejection instead.
                const origin_buffer_account = h2_pool.originBufferAccount(key) catch {
                    h2_pool.release(conn);
                    return error.ProxyBufferCapacityUnavailable;
                };
                // Every per-stream decision below comes from the connection's
                // pinned policy, never from `proxy_buffer_limits` — which is
                // the *current* config snapshot, and a pooled connection
                // outlives reloads. Mixing them judged one stream by two
                // generations at once: its queue by what the connection
                // advertised, everything sized here by whatever the config said
                // now. On a raise that let a stream own more than the hard
                // limit it is documented to be measured against; on a shrink it
                // refused a stream still operating inside the window this
                // connection had granted it, so the outcome depended on whether
                // the request happened to land on a pre-reload connection.
                const pinned_limits = conn.proxyBufferLimits();

                // The queue and this request's relay buffer are live at the
                // same time, so they must share one per-stream bound (#140).
                // That is done by holding the relay's size back from the
                // queue's own hard limit at `openStreaming` below, rather than
                // by pointing both at a shared budget object: such an object
                // would have to outlive both a worker's relay reservation and a
                // stream the reader thread can still be inside, and
                // `finishStreaming` destroys streams outside the connection's
                // state lock. Reserved headroom needs no shared lifetime at
                // all, and the sum is bounded either way.
                const proxy_buffer_capacity = proxy_buffer_account.AggregateCapacity{
                    .origin = origin_buffer_account,
                    .global = proxy_buffer_global,
                };

                // Allocate the relay buffer only now, at the size the pinned
                // policy can account for. The config may ask for more than this
                // connection's policy was validated against — `hard >= high +
                // relay` held for the relay size in force when it opened, not
                // for one a later reload grew — and allocating the larger size
                // and slicing down would leave the remainder as real
                // per-request memory charged to no scope at all. With N
                // concurrent streams that is exactly the unaccounted retained
                // allocation these limits exist to bound, so what is allocated
                // and what is accounted are deliberately the same number.
                //
                // Never restrictive in practice: the pinned policy was
                // validated against a relay of at least 16 KiB, so the headroom
                // below is always at least that.
                //
                // Floored all the same, because the failure mode if it were
                // ever zero is silent: a zero-length relay buffer makes
                // `readStreamingBody` return 0, which this loop reads as end of
                // body and truncates the response without a word. A policy that
                // leaves no headroom is only reachable by constructing `Limits`
                // directly rather than through config validation, and flooring
                // turns that into an ordinary over-budget refusal — a clean
                // pre-commit 503 — instead.
                const pinned_relay_headroom = pinned_limits.per_stream_hard_limit -| pinned_limits.per_stream_high_watermark;
                const pinned_relay_bytes = @max(
                    @min(requested_relay_bytes, pinned_relay_headroom),
                    min_proxy_relay_bytes,
                );
                // Nothing is allocated here. #140 requires the reservation to
                // come *before* the allocation, not merely to match its size:
                // N concurrent requests to an origin slow to answer would
                // otherwise all allocate a relay buffer while none had charged
                // a scope yet, and the aggregate cap could not stop the process
                // holding N of them. They would be refused only afterwards,
                // past the peak the limit exists to prevent. Each phase below
                // reserves first and allocates second, and a bodiless response
                // allocates nothing at all.

                var authority_buf: [300]u8 = undefined;
                const authority = if (port == default_port)
                    host
                else
                    std.fmt.bufPrint(&authority_buf, "{s}:{d}", .{ host, port }) catch host;

                // The connection is acquired, so every failure from here on has
                // to hand its reference back before returning.
                var path_buf: std.Io.Writer.Allocating = .init(allocator);
                defer path_buf.deinit();
                const path_component = uriComponentBytes(uri.path);
                buildRequestTarget(&path_buf, path_component, uri.query) catch |err| {
                    h2_pool.release(conn);
                    return err;
                };

                // Claim the upload's buffer footprint before `openStreaming`,
                // which sends HEADERS (#140). Reserving after it would let a
                // local 413/503 be raised only once the origin had already
                // received a request it will never see the body of.
                var upload_reservation: ?ProxyBufferReservation = null;
                defer if (upload_reservation) |*reservation| reservation.releaseAll();
                var upload_buf: ?[]u8 = null;
                defer if (upload_buf) |buf| allocator.free(buf);
                if (streaming_body) |sb| {
                    upload_reservation = preflightUploadReservation(
                        pinned_limits,
                        proxy_buffer_observer,
                        proxy_buffer_capacity,
                        pinned_relay_bytes,
                        uploadInitialBytesFootprint(sb),
                    ) catch |err| {
                        h2_pool.release(conn);
                        return err;
                    };
                    // Admitted, so the memory may now exist.
                    upload_buf = allocator.alloc(u8, pinned_relay_bytes) catch |err| {
                        h2_pool.release(conn);
                        return err;
                    };
                }

                const start_ms = http.event_loop.monotonicMs();
                const stream = conn.openStreaming(.{
                    .method = method,
                    .scheme = scheme,
                    .authority = authority,
                    .path = path_buf.written(),
                    .headers = extra_headers,
                    .body = buffered_body,
                    .body_mode = if (streaming_body == null) .complete else .streaming,
                    .proxy_buffer_accounting = true,
                    .proxy_buffer_observer = proxy_buffer_observer,
                    .proxy_buffer_capacity = proxy_buffer_capacity,
                    // Only a response can own a relay buffer alongside the
                    // queue; an upload's buffer is gone before the queue fills.
                    .proxy_relay_reserved_bytes = pinned_relay_bytes,
                }) catch |err| {
                    // Nothing has reached the client yet: evict the dead
                    // connection so new requests do not pick it, and retry
                    // once on connection-level failures.
                    h2_pool.evict(key, conn);
                    h2_pool.release(conn);
                    if (streaming_body == null and attempt == 0 and (err == error.Http2GoAway or err == error.Http2ConnectionClosed or err == error.Http2StreamReset)) {
                        continue;
                    }
                    return err;
                };

                if (streaming_body) |sb| {
                    relayStreamingUploadToHttp2(
                        conn,
                        stream,
                        sb,
                        upload_buf.?,
                        downstream_conn,
                        cancel_token,
                        &upload_reservation.?,
                    ) catch |err| {
                        const capacity_abort = err == error.BufferLimitExceeded or
                            conn.abortCause(stream) == .local_capacity;
                        conn.finishStreaming(stream);
                        if (!conn.healthy()) h2_pool.evict(key, conn);
                        h2_pool.release(conn);
                        // An early response can exhaust local buffer capacity
                        // while the upload is still being written, and the
                        // reader reports that through the *next* body write.
                        // Nothing is committed downstream yet, so it is a 503 —
                        // returning the raw error here made it a 502 charged to
                        // a healthy origin.
                        if (capacity_abort) return error.ProxyBufferCapacityUnavailable;
                        return err;
                    };
                    // The upload is done: `read_buf` holds no client bytes any
                    // more, so the request-direction claim ends here rather
                    // than at the end of the exchange. Carrying it through
                    // `waitStreamingResponseHead` and the response relay would
                    // occupy upload capacity for as long as the response takes
                    // — long enough for one slow response to make unrelated
                    // uploads fail with a 503 they should never have seen, and
                    // long enough for the direction gauges to keep reporting an
                    // upload that finished. (The HTTP/1 path has no equivalent
                    // window: `sendStreamingProxyRequest` returns, releasing
                    // its reservation, before the response is read.)
                    if (upload_reservation) |*reservation| {
                        reservation.releaseAll();
                        upload_reservation = null;
                    }
                    // And the buffer itself: holding an empty upload buffer
                    // through the response would be allocated-but-unaccounted
                    // memory, which is the thing this whole section is about.
                    if (upload_buf) |buf| {
                        allocator.free(buf);
                        upload_buf = null;
                    }
                }

                conn.waitStreamingResponseHead(stream) catch |err| {
                    conn.finishStreaming(stream);
                    if (!conn.healthy()) h2_pool.evict(key, conn);
                    h2_pool.release(conn);
                    // Local capacity, not the origin: nothing has reached the
                    // client, so this becomes a clean 503 and never counts
                    // against the origin. Retrying would hit the same wall.
                    if (err == error.BufferLimitExceeded) return error.ProxyBufferCapacityUnavailable;
                    if (streaming_body == null and attempt == 0 and (err == error.Http2GoAway or err == error.Http2ConnectionClosed or err == error.Http2StreamReset)) {
                        continue;
                    }
                    return err;
                };
                const ttfb_ms = http.event_loop.monotonicMs() - start_ms;
                const status = stream.status.?; // requestStreaming guarantees a status

                const reason = gpres.upstreamReasonPhrase(@enumFromInt(status));
                const body_allowed = gpres.responseBodyAllowed(method, status);

                // The response relay copies queued DATA out of the stream into
                // `read_buf`, and the queue's own reservation is not released
                // until `acknowledgeStreamingBody` — which runs *after* the
                // downstream write. While a slow client blocks in that write
                // the same bytes therefore exist twice in application-owned
                // memory, and charging only the queue let N concurrent slow
                // responses exceed every configured ceiling by roughly
                // N * read_buf_bytes with nothing in the accounting to show it
                // (#140).
                //
                // Taken before the commitment boundary below, so a refusal is
                // still a clean pre-commit 503 rather than a committed status
                // that has to be truncated, and released on every exit from
                // this block — including the retry `continue` paths. A
                // bodiless response never touches the buffer and is not
                // charged for it, which is the line HTTP/1 draws too.
                var response_reservation: ?ProxyBufferReservation = null;
                defer if (response_reservation) |*reservation| reservation.releaseAll();
                var response_buf: ?[]u8 = null;
                defer if (response_buf) |buf| allocator.free(buf);
                if (body_allowed) {
                    var reservation = ProxyBufferReservation.init(
                        .upstream_to_downstream,
                        pinned_limits,
                        proxy_buffer_observer,
                        proxy_buffer_capacity,
                    );
                    // `reserve` rolls itself back completely at either scope,
                    // so a refusal leaves nothing to clean up here.
                    reservation.reserve(pinned_relay_bytes) catch {
                        conn.finishStreaming(stream);
                        if (!conn.healthy()) h2_pool.evict(key, conn);
                        h2_pool.release(conn);
                        return error.ProxyBufferCapacityUnavailable;
                    };
                    response_reservation = reservation;
                    // Admitted, and still before the commitment boundary below.
                    response_buf = allocator.alloc(u8, pinned_relay_bytes) catch |err| {
                        conn.finishStreaming(stream);
                        if (!conn.healthy()) h2_pool.evict(key, conn);
                        h2_pool.release(conn);
                        return err;
                    };
                }

                // Linearize the commitment boundary: the reader can reject DATA
                // in the gap between the head arriving and this write starting.
                // Claiming the transition under the connection's state lock
                // makes that a decided question — a refusal that lands first is
                // still a pre-commit 503 rather than a committed origin status
                // that we then have to truncate.
                conn.beginDownstreamCommit(stream) catch {
                    conn.finishStreaming(stream);
                    if (!conn.healthy()) h2_pool.evict(key, conn);
                    h2_pool.release(conn);
                    return error.ProxyBufferCapacityUnavailable;
                };
                var downstream_write = gpres.StreamingResponseWriteState{};
                defer downstream_write.deinit();
                downstream_write.initHeadFromHeaders(
                    allocator,
                    status,
                    reason,
                    stream.headers.items,
                    body_allowed,
                    downstream_keep_alive,
                    correlation_id,
                    security,
                    alt_svc,
                    sticky_set_cookie,
                ) catch |err| {
                    conn.finishStreaming(stream);
                    if (!conn.healthy()) h2_pool.evict(key, conn);
                    h2_pool.release(conn);
                    return err;
                };
                gpres.drainStreamingWriteBlocking(&downstream_write, downstream_writer) catch {
                    conn.finishStreaming(stream); // resets the unfinished stream
                    h2_pool.release(conn);
                    return streamingResultAfterDownstreamAbort(status, reason, 0, ttfb_ms);
                };
                // The response head is on the wire from here on: the body
                // loop's own `cancelStopped` check below can still throw
                // `error.RequestCancelled` after this point (mid-relay
                // cancellation, not the pre-commit kind), so the caller must
                // know not to serialize a second response for it.
                downstream_committed.* = true;

                var body_bytes: usize = 0;
                var aborted = false;
                var local_capacity_aborted = false;
                if (body_allowed) {
                    while (true) {
                        if (cancelStopped(cancel_token)) {
                            conn.finishStreaming(stream);
                            h2_pool.release(conn);
                            return error.RequestCancelled;
                        }
                        const n = conn.readStreamingBody(stream, response_buf.?) catch |err| {
                            // Failed mid-body after the head went downstream:
                            // report an aborted relay (the client sees the
                            // truncated chunked body); other streams on the
                            // connection are unaffected unless the whole
                            // connection died (handled below).
                            //
                            // The status can no longer change, but the *cause*
                            // still matters: a local buffer-capacity abort is
                            // this proxy running out of room, and blaming the
                            // origin for it would let local memory pressure
                            // trip a healthy origin's failure policy.
                            local_capacity_aborted = err == error.BufferLimitExceeded;
                            aborted = true;
                            break;
                        };
                        if (n == 0) break;
                        downstream_write.beginChunk(response_buf.?[0..n]) catch {
                            conn.finishStreaming(stream);
                            h2_pool.release(conn);
                            return streamingResultAfterDownstreamAbort(status, reason, body_bytes, ttfb_ms);
                        };
                        gpres.drainStreamingWriteBlocking(&downstream_write, downstream_writer) catch {
                            conn.finishStreaming(stream);
                            h2_pool.release(conn);
                            return streamingResultAfterDownstreamAbort(status, reason, body_bytes, ttfb_ms);
                        };
                        conn.acknowledgeStreamingBody(stream, n);
                        body_bytes += n;
                    }
                    if (!aborted) {
                        downstream_write.beginTerminalChunk() catch {
                            conn.finishStreaming(stream);
                            h2_pool.release(conn);
                            return streamingResultAfterDownstreamAbort(status, reason, body_bytes, ttfb_ms);
                        };
                        gpres.drainStreamingWriteBlocking(&downstream_write, downstream_writer) catch {
                            conn.finishStreaming(stream);
                            h2_pool.release(conn);
                            return streamingResultAfterDownstreamAbort(status, reason, body_bytes, ttfb_ms);
                        };
                    }
                } else {
                    downstream_write.finishWithoutBody() catch {
                        conn.finishStreaming(stream);
                        h2_pool.release(conn);
                        return streamingResultAfterDownstreamAbort(status, reason, body_bytes, ttfb_ms);
                    };
                }
                conn.finishStreaming(stream);
                // A connection-level failure mid-relay leaves the connection
                // unhealthy — evict it so new requests reconnect.
                if (aborted and !conn.healthy()) h2_pool.evict(key, conn);
                h2_pool.release(conn);
                if (!aborted) {
                    if (h1_pool) |p| p.recordRequestLatency(true, http.event_loop.monotonicMs() - start_ms);
                }

                return .{
                    .status_code = status,
                    .reason = reason,
                    .response_body_bytes = body_bytes,
                    .upstream_ttfb_ms = ttfb_ms,
                    .upstream_aborted = aborted,
                    .local_capacity_aborted = local_capacity_aborted,
                };
            },
        }
    }
    unreachable;
}

/// Convert an HTTP/2 response into the buffered-response shape the proxy path
/// expects. Headers + reason are owned by the response's metadata arena; the
/// body is duped with `allocator` (freed in `BufferedUpstreamResponse.deinit`).
fn h2ResponseToBuffered(allocator: std.mem.Allocator, h2resp: *http.upstream_h2.Response) !BufferedUpstreamResponse {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const aa = arena.allocator();

    const reason = try aa.dupe(u8, gpres.upstreamReasonPhrase(@enumFromInt(h2resp.status)));
    var headers = try aa.alloc(UpstreamHeader, h2resp.headers.len);
    var representation_content_length: ?[]const u8 = null;
    for (h2resp.headers, 0..) |h, i| {
        headers[i] = .{ .name = try aa.dupe(u8, h.name), .value = try aa.dupe(u8, h.value) };
        if (representation_content_length == null and
            std.ascii.eqlIgnoreCase(h.name, "content-length") and
            !gph.anyConnectionHeaderReferencesHeader(h2resp.headers, h.name))
        {
            representation_content_length = try aa.dupe(u8, h.value);
        }
    }
    const body = try allocator.dupe(u8, h2resp.body);
    return .{
        .metadata_arena = arena,
        .status_code = h2resp.status,
        .reason = reason,
        .headers = headers,
        .body = body,
        .representation_content_length = representation_content_length,
    };
}

/// Send a bounded buffered HTTP/1 request over an already-connected transport
/// and parse the response. `transport` must provide `writeAll([]const u8)` and
/// `read([]u8) !usize` (satisfied by both `compat.NetStream` and
/// `*UpstreamTlsConn`). `fd` is the underlying socket used for per-phase
/// timeout control. The caller owns connecting and closing the transport.
fn headerValue(headers: []const std.http.Header, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

fn exchangeBoundedBufferedHttpRequest(
    allocator: std.mem.Allocator,
    transport: anytype,
    fd: std.posix.fd_t,
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    body: []const u8,
    content_type_override: ?[]const u8,
    max_buffered_response_bytes: usize,
    send_timeout_ms: u32,
    response_timeout_ms: u32,
    /// When true the request omits `Connection: close`, allowing the upstream
    /// socket to be returned to the pool for reuse.
    keep_alive: bool,
    /// Set (when non-null) to whether the connection may be safely reused after
    /// this exchange: HTTP/1.1, no `Connection: close` in the response,
    /// definitively framed body, and the socket left in sync.
    reusable: ?*bool,
) !BufferedUpstreamResponse {
    if (reusable) |r| r.* = false;
    if (send_timeout_ms > 0) {
        try setSocketTimeoutMs(fd, send_timeout_ms, send_timeout_ms);
    }

    var req_aw: std.Io.Writer.Allocating = .init(allocator);
    defer req_aw.deinit();
    const req_writer = &req_aw.writer;
    var host_buf: [256]u8 = undefined;
    const upstream_host = if (uri.host) |value| try value.toRaw(&host_buf) else "localhost";
    const host_override = headerValue(extra_headers, "host");
    const host = host_override orelse upstream_host;

    try req_writer.print("{s} {s}", .{ method, uriComponentBytes(uri.path) });
    if (uri.query) |query| {
        try req_writer.print("?{s}", .{uriComponentBytes(query)});
    }
    try req_writer.writeAll(" HTTP/1.1\r\n");
    // Preserve a non-default upstream port in the Host header.
    const default_port: u16 = if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) 443 else 80;
    if (host_override != null) {
        try req_writer.print("Host: {s}\r\n", .{host});
    } else if (uri.port) |p| {
        if (p != default_port) {
            try req_writer.print("Host: {s}:{d}\r\n", .{ host, p });
        } else {
            try req_writer.print("Host: {s}\r\n", .{host});
        }
    } else {
        try req_writer.print("Host: {s}\r\n", .{host});
    }
    if (!keep_alive) {
        try req_writer.writeAll("Connection: close\r\n");
    }
    if (content_type_override) |content_type| {
        try req_writer.print("Content-Type: {s}\r\n", .{content_type});
    }
    for (extra_headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "host")) continue;
        try req_writer.print("{s}: {s}\r\n", .{ header.name, header.value });
    }
    if (body.len > 0) {
        try req_writer.print("Content-Length: {d}\r\n", .{body.len});
    }
    try req_writer.writeAll("\r\n");
    if (body.len > 0) {
        try req_writer.writeAll(body);
    }

    // A failed write means the request never (fully) reached the origin, so a
    // caller holding a reused pooled connection may retry any method on a fresh
    // one. Timeouts and OOM keep their own meaning.
    transport.writeAll(req_aw.written()) catch |err| {
        // Transports expose different error sets, so match by name.
        const name = @errorName(err);
        if (std.mem.eql(u8, name, "Timeout") or std.mem.eql(u8, name, "OutOfMemory")) return err;
        return error.UpstreamRequestWriteFailed;
    };

    // Bound the wait for the response with poll() rather than SO_RCVTIMEO:
    // SO_RCVTIMEO is reliably honored on AF_UNIX sockets but is silently ignored
    // on the AF_INET upstream sockets used here, so a hung TCP origin would block
    // the worker forever. SO_RCVTIMEO is still set (best effort) so OpenSSL-driven
    // TLS reads remain bounded; poll() is the authoritative deadline. (issue #196)
    if (response_timeout_ms > 0) {
        setSocketRecvTimeoutMs(fd, response_timeout_ms) catch {};
    }
    const read_deadline_ms = if (response_timeout_ms > 0) response_timeout_ms else send_timeout_ms;

    // Read until the response is complete per HTTP/1.1 framing. Reading until
    // EOF would stall against keep-alive upstreams that frame with
    // Content-Length / chunked and hold the socket open, so determine the body
    // boundary from the headers and stop there (issue #196).
    var resp_raw = std.array_list.Managed(u8).init(allocator);
    defer resp_raw.deinit();
    var read_buf: [8192]u8 = undefined;
    var header_end: ?usize = null;
    var framing: ResponseFraming = .close;
    // Start of the response currently being parsed. Advances past each
    // consumed 1xx interim response (#673 review): this bounded buffered
    // path has no mechanism to relay interim responses to the downstream
    // client separately from the final one, so 1xx responses (other than
    // 101, which completes a protocol switch rather than signaling "more
    // to come") are discarded here and the loop keeps reading until the
    // actual final, non-1xx response arrives. Before this fix, the FIRST
    // 1xx was wrongly treated as a complete response: the exchange would
    // return that 1xx to the caller as if it were final and abandon
    // whatever followed, silently dropping the real response.
    var response_start: usize = 0;
    while (true) {
        if (header_end == null) {
            if (std.mem.find(u8, resp_raw.items[response_start..], "\r\n\r\n")) |rel_he| {
                const he = response_start + rel_he;
                header_end = he;
                framing = try detectResponseFraming(resp_raw.items[response_start..he], method);
            }
        }
        if (header_end) |he| {
            const headers_block = resp_raw.items[response_start..he];
            const body_start = he + 4;
            const resp_body = resp_raw.items[body_start..];
            switch (framing) {
                .none => {
                    // `detectResponseFraming` already rejects status 101
                    // outright, so any status reaching here that is still
                    // in the 1xx range is a genuine skippable interim
                    // response (100 Continue, 103 Early Hints, ...).
                    const parsed_status = try parseStrictStatusLine(headers_block);
                    if (parsed_status.status_code >= 100 and parsed_status.status_code < 200) {
                        // Interim informational response: discard it and keep
                        // reading for the actual final response.
                        response_start = body_start;
                        header_end = null;
                        continue;
                    }
                    // Bodiless final response (204/304/HEAD): never
                    // reusable, even if nothing has trailed the headers
                    // *yet*. A malicious/misbehaving upstream can send just
                    // the header block, flush, wait until Tardigrade returns
                    // this socket to the idle pool, and only then send an
                    // illegal body or a full ghost response -- those bytes
                    // would become part of whatever unrelated request next
                    // checks the connection out of the pool (#673 review).
                    // `resp_body.len == 0` only proves nothing had arrived
                    // *by this instant*; it cannot prove nothing ever will.
                    setReusable(reusable, keep_alive, headers_block, false);
                    break;
                },
                .length => |content_length| {
                    if (content_length > max_buffered_response_bytes) return error.StreamTooLong;
                    if (resp_body.len >= content_length) {
                        // Extra bytes past Content-Length leave the socket out of
                        // sync, so it can only be reused when the body landed
                        // exactly on the boundary.
                        setReusable(reusable, keep_alive, headers_block, resp_body.len == content_length);
                        resp_raw.shrinkRetainingCapacity(body_start + content_length);
                        break;
                    }
                },
                .chunked => {
                    if (try decodeChunkedBody(allocator, resp_body, max_buffered_response_bytes)) |decoded| {
                        defer allocator.free(decoded.body);
                        // Reusable only if the socket is back in sync: no
                        // bytes past the terminating chunk's trailer section
                        // (#673 review) -- extra/ghost bytes there would
                        // otherwise poison the pooled connection for
                        // whatever unrelated request checks it out next.
                        setReusable(reusable, keep_alive, headers_block, decoded.consumed == resp_body.len);
                        var rebuilt = std.array_list.Managed(u8).init(allocator);
                        defer rebuilt.deinit();
                        try rebuilt.appendSlice(resp_raw.items[response_start..body_start]);
                        try rebuilt.appendSlice(decoded.body);
                        return parseBufferedUpstreamResponse(allocator, rebuilt.items);
                    }
                },
                .close => {}, // no length advertised — server will close; not reusable
            }
        }

        if (read_deadline_ms > 0 and !transportHasBufferedInput(transport) and !try pollFdReadable(fd, read_deadline_ms)) {
            return error.Timeout;
        }
        const n = try transport.read(&read_buf);
        if (n == 0) {
            // EOF. A close-delimited body ends here, and an empty/partial header
            // block is handled by the checks below. But a Content-Length or
            // chunked body that has not yet reached its declared end means the
            // origin closed mid-response: surface it as a protocol error so the
            // caller returns 502 instead of forwarding a body shorter than the
            // advertised length (#269).
            if (header_end != null) {
                switch (framing) {
                    .length, .chunked => return error.UpstreamProtocolError,
                    .none, .close => {},
                }
            }
            break;
        }
        try resp_raw.appendSlice(read_buf[0..n]);
        if (resp_raw.items.len > max_buffered_response_bytes) return error.StreamTooLong;
    }

    // A reused keep-alive connection the origin closed while idle (or one
    // that closed after only ever sending 1xx interim responses) yields
    // nothing beyond `response_start` here; surface it distinctly so the
    // caller can retry on a fresh connection.
    if (resp_raw.items.len == response_start) return error.UpstreamConnectionClosed;

    return parseBufferedUpstreamResponse(allocator, resp_raw.items[response_start..]);
}

/// Set the caller's reusability flag: a connection may be reused only when we
/// asked to keep it alive, the response is HTTP/1.1 without `Connection: close`,
/// and the socket was left in sync (no bytes past the framed body).
fn setReusable(out: ?*bool, keep_alive: bool, headers_block: []const u8, in_sync: bool) void {
    const r = out orelse return;
    if (!keep_alive or !in_sync) {
        r.* = false;
        return;
    }
    const first_line_end = std.mem.find(u8, headers_block, "\r\n") orelse headers_block.len;
    if (!std.mem.startsWith(u8, headers_block[0..first_line_end], "HTTP/1.1")) {
        r.* = false;
        return;
    }
    var lines = std.mem.splitSequence(u8, headers_block[@min(first_line_end + 2, headers_block.len)..], "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " \t"), "connection")) continue;
        var tokens = std.mem.splitScalar(u8, std.mem.trim(u8, line[colon + 1 ..], " \t"), ',');
        while (tokens.next()) |token| {
            if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, token, " \t"), "close")) {
                r.* = false;
                return;
            }
        }
    }
    r.* = true;
}

/// How the upstream delimits the response body (RFC 7230 §3.3.3).
const ResponseFraming = union(enum) {
    none, // bodiless: HEAD request, or 1xx/204/304 status
    length: usize, // Content-Length bytes follow the header block
    chunked, // Transfer-Encoding: chunked
    close, // no length advertised — body ends when the connection closes
};

fn responseStatusIsBodiless(status: u16) bool {
    return (status >= 100 and status < 200) or status == 204 or status == 304;
}

const ParsedStatusLine = struct {
    status_code: u16,
    reason: []const u8,
    /// Byte offset within the header block immediately after the
    /// terminating "\r\n" -- i.e. where header lines begin.
    header_lines_start: usize,
};

/// Strictly parses an HTTP/1.x response status line: an exact `\r\n`
/// terminator, a supported `HTTP/1.0 ` or `HTTP/1.1 ` version prefix,
/// exactly three status digits, and no control characters anywhere in the
/// line (including the reason phrase). Every upstream-response parsing
/// site uses this ONE parser so they cannot disagree about where the
/// status line ends and headers begin (#673 review) -- a prior version had
/// each site do its own ad hoc boundary search (one via the first bare LF,
/// one via the first exact `\r\n`), and a status line containing an
/// embedded bare LF could make them disagree about which of two duplicate
/// `Content-Length` fields counts as "the first header line", reopening
/// order-dependent framing after the fix that made duplicate
/// `Content-Length` rejected outright.
fn parseStrictStatusLine(header_block: []const u8) !ParsedStatusLine {
    // `header_block` is everything up to (but excluding) the blank-line
    // terminator, so a response with a status line and NO additional
    // headers contains no "\r\n" at all -- fall back to treating the whole
    // block as the status line with nothing following, matching the
    // pre-existing streaming-path behavior for that case. This is still
    // safe against the bare-LF-hides-a-header attack this function exists
    // to close: if a REAL "\r\n" appears anywhere, `find` locates the
    // first one deterministically (single source of truth for every
    // caller); this fallback path only applies when there is no "\r\n"
    // anywhere in the block, in which case `isValidHeaderValue` below
    // scans the ENTIRE block (not just what would have been "the status
    // line") and still rejects an embedded bare LF.
    const line_end = std.mem.find(u8, header_block, "\r\n") orelse header_block.len;
    const line = header_block[0..line_end];
    if (!http.headers.isValidHeaderValue(line)) return error.UpstreamProtocolError;

    const version_len = "HTTP/1.1 ".len; // same length as "HTTP/1.0 "
    if (line.len < version_len + 3) return error.UpstreamProtocolError;
    const version_ok = std.mem.startsWith(u8, line, "HTTP/1.1 ") or std.mem.startsWith(u8, line, "HTTP/1.0 ");
    if (!version_ok) return error.UpstreamProtocolError;

    const rest = line[version_len..];
    const status_digits = rest[0..3];
    for (status_digits) |c| {
        if (!std.ascii.isDigit(c)) return error.UpstreamProtocolError;
    }
    const status_code = std.fmt.parseInt(u16, status_digits, 10) catch return error.UpstreamProtocolError;
    // RFC 9110 §15 defines valid status codes as 100..599; three decimal
    // digits alone admits 000..099 and 600..999, which downstream code
    // assumes never occur (e.g. the buffered path reformats `status_code`
    // straight back out with `{d}`, so an unrejected `099` would become an
    // invalid `HTTP/1.1 99 ...` response line to the client) (#673 review).
    if (status_code < 100 or status_code > 599) return error.UpstreamProtocolError;

    var reason: []const u8 = "";
    if (rest.len > 3) {
        // A reason phrase, when present, must be separated from the status
        // code by exactly one space.
        if (rest[3] != ' ') return error.UpstreamProtocolError;
        reason = rest[4..];
    }

    // When `line_end` hit the no-"\r\n"-anywhere fallback above, there are no
    // header lines to point past -- stay at `header_block.len` rather than
    // overshooting it by 2.
    const header_lines_start = if (line_end >= header_block.len) header_block.len else line_end + 2;
    return .{ .status_code = status_code, .reason = reason, .header_lines_start = header_lines_start };
}

/// Determine response framing from the header block (excluding the trailing
/// CRLFCRLF), the request method, and the status line.
///
/// Returns `error.UpstreamProtocolError` for:
/// - an invalid or duplicated `Content-Length` (#673 review): a prior
///   version silently kept overwriting `content_length` on every
///   occurrence, so a duplicate `Content-Length` -- conflicting *or*
///   merely repeated -- picked whichever field happened to come last, with
///   no guarantee a downstream client would resolve the same ambiguity the
///   same way. This mirrors the request-direction policy, which rejects
///   any duplicate Content-Length outright regardless of whether the
///   values match.
/// - a duplicated `Transfer-Encoding` field, or one whose value isn't
///   EXACTLY (trimmed, case-insensitive) `chunked` (#673 review): Tardigrade
///   only implements chunk *decoding*, nothing else, so accepting "any
///   token list containing chunked somewhere" -- e.g. `chunked, gzip`
///   (chunked not final) or `gzip` alone (falling through to trust an
///   accompanying Content-Length that TE makes non-authoritative) -- risked
///   a boundary Tardigrade computes one way while a stricter downstream
///   client computes another.
/// - both a valid `Transfer-Encoding: chunked` and a `Content-Length`
///   present together: fails closed the same way the request direction
///   already does, rather than silently trusting chunked and ignoring the
///   Content-Length.
/// - status 101: this generic reverse-proxy path re-serializes the
///   response as ordinary HTTP after stripping `Connection`/`Upgrade`, so
///   forwarding an upstream 101 without an actual protocol tunnel is
///   protocol confusion, not a completed exchange (#673 review).
fn detectResponseFraming(header_block: []const u8, method: []const u8) !ResponseFraming {
    const status_line = try parseStrictStatusLine(header_block);
    const status = status_line.status_code;
    if (status == 101) return error.UpstreamProtocolError;

    if (std.ascii.eqlIgnoreCase(method, "HEAD")) return .none;
    if (responseStatusIsBodiless(status)) return .none;

    var content_length: ?usize = null;
    var chunked = false;
    var te_seen = false;
    var lines = std.mem.splitSequence(u8, header_block[@min(status_line.header_lines_start, header_block.len)..], "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            if (te_seen) return error.UpstreamProtocolError;
            te_seen = true;
            if (!std.ascii.eqlIgnoreCase(value, "chunked")) return error.UpstreamProtocolError;
            chunked = true;
        } else if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            const parsed = std.fmt.parseInt(usize, value, 10) catch return error.UpstreamProtocolError;
            if (content_length != null) return error.UpstreamProtocolError;
            content_length = parsed;
        }
    }
    if (chunked and content_length != null) return error.UpstreamProtocolError;

    if (chunked) return .chunked;
    if (content_length) |cl| return .{ .length = cl };
    return .close;
}

/// Decode a chunked message body. Returns the decoded payload when the
/// terminating zero-length chunk (and trailer section) has fully arrived, or
/// null when more bytes are needed. The caller owns the returned slice.
/// Decoded chunked-body payload plus how many leading bytes of `encoded` the
/// decode actually consumed (through and including the terminating chunk's
/// trailer section). The buffered exchange loop must compare `consumed`
/// against the full length of what it read before deciding the connection is
/// safe to reuse: a hostile/misbehaving upstream can append extra bytes (a
/// ghost response, smuggled framing) right after `0\r\n\r\n`, and those bytes
/// would otherwise poison whatever unrelated request checks the pooled
/// connection out next (#673 review). The streaming path's `relayUpstreamBody`
/// already gets this for free via `rb.available().len == 0`; the buffered
/// path decodes into one flat slice and needs the offset made explicit.
const ChunkedDecodeResult = struct { body: []u8, consumed: usize };

fn decodeChunkedBody(allocator: std.mem.Allocator, encoded: []const u8, max_bytes: usize) !?ChunkedDecodeResult {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();
    var pos: usize = 0;
    while (true) {
        const line_len = std.mem.find(u8, encoded[pos..], "\r\n") orelse return null;
        const size_line = encoded[pos .. pos + line_len];
        // Strip optional chunk extensions (";name=value").
        const size_str = if (std.mem.findScalar(u8, size_line, ';')) |s| size_line[0..s] else size_line;
        const size = std.fmt.parseInt(usize, std.mem.trim(u8, size_str, " \t"), 16) catch return error.UpstreamProtocolError;
        const data_start = pos + line_len + 2;
        if (size == 0) {
            // Last chunk: consume the (possibly empty) trailer section, which
            // ends at the first blank line.
            var tpos = data_start;
            while (true) {
                const tlen = std.mem.find(u8, encoded[tpos..], "\r\n") orelse return null;
                if (tlen == 0) return .{ .body = try out.toOwnedSlice(), .consumed = tpos + 2 }; // blank line → done
                // RFC 9112 §7.1.2: the trailer part is `*( field-line CRLF
                // )` -- a non-blank line must actually be valid
                // `field-name ":" OWS field-value OWS` syntax, not merely
                // "contains a colon somewhere" a hostile upstream could use
                // to hide a pipelined ghost response inside what looks like
                // "just a trailer" (#673 review round 8: a colon-only check
                // still let a malformed name/value through).
                const trailer_line = encoded[tpos .. tpos + tlen];
                if (!http.headers.isValidTrailerLine(trailer_line)) return error.UpstreamProtocolError;
                tpos += tlen + 2;
            }
        }
        // A hostile upstream can send an oversized hex chunk-size (up to
        // 16 `f`s fits in a usize) specifically to overflow `data_start +
        // size`; use checked arithmetic so that lands as a rejected
        // response instead of a safety-checked panic (#673 review).
        const data_end = std.math.add(usize, data_start, size) catch return error.UpstreamProtocolError;
        const chunk_end = std.math.add(usize, data_end, 2) catch return error.UpstreamProtocolError;
        if (chunk_end > encoded.len) return null; // chunk data + trailing CRLF not yet here
        // The two bytes after the chunk data must be a literal CRLF, not
        // just "any two bytes we can skip" -- otherwise a malformed chunk
        // terminator silently resyncs onto attacker-chosen bytes instead of
        // being rejected, unlike the streaming path's `consumeExactCrlf`
        // (#673 review).
        if (!std.mem.eql(u8, encoded[data_end..chunk_end], "\r\n")) return error.UpstreamProtocolError;
        try out.appendSlice(encoded[data_start..data_end]);
        if (out.items.len > max_bytes) return error.StreamTooLong;
        pos = chunk_end;
    }
}

/// Whether `transport`'s next `read()` call is already known to return
/// without needing the raw fd to become readable first. Two cases:
///
/// 1. `transport` already has decrypted/decoded bytes buffered above the raw
///    fd (e.g. a TLS record layer that read more of the socket than one call
///    needed, or over-read past the handshake into the first response
///    bytes). Polling the raw fd for *new* readability in that case is wrong
///    — the peer may have nothing further to send until it gets our next
///    request, so the poll would starve out its own deadline waiting for
///    bytes that already arrived. Mirrors `upstream_h2.zig`'s existing `if
///    (transport.pending() > 0) return;` guard.
/// 2. `transport` already knows its next `read()` returns `0` regardless of
///    the fd — e.g. a TLS transport that has already seen the peer's
///    `close_notify`. `close_notify` is a half-close signal (RFC 8446 §6.1):
///    the peer's raw TCP socket often stays open afterward (waiting for this
///    side's own `close_notify`), so the raw fd can legitimately never show
///    readable even though `read()` itself would return immediately —
///    observed as a close-delimited streamed body hanging for the full
///    deadline instead of completing (#634). Transports that know this
///    expose it as `readReady()`, preferred over `pending()` when present.
///
/// `transport` types with neither method (e.g. `compat.NetStream`, the
/// plaintext transport) have no buffering/half-close distinction above the
/// fd, so they always poll normally.
fn transportHasBufferedInput(transport: anytype) bool {
    const T = @TypeOf(transport);
    const info = @typeInfo(T);
    const Target = if (info == .pointer) info.pointer.child else T;
    if (@hasDecl(Target, "readReady")) return transport.readReady();
    if (!@hasDecl(Target, "pending")) return false;
    return transport.pending() > 0;
}

/// Wait up to `timeout_ms` for `fd` to become readable. Returns false on
/// timeout. EINTR is retried within the original deadline.
fn pollFdReadable(fd: std.posix.fd_t, timeout_ms: u32) !bool {
    var pfds = [_]std.posix.pollfd{.{
        .fd = fd,
        .events = std.posix.POLL.IN | std.posix.POLL.HUP | std.posix.POLL.ERR,
        .revents = 0,
    }};
    const ready = std.posix.poll(&pfds, @intCast(@min(timeout_ms, std.math.maxInt(i32)))) catch |err| switch (err) {
        error.Unexpected => return error.Timeout,
        else => return err,
    };
    return ready != 0;
}

/// What a zero-timeout writability check found on the upstream socket.
const UpstreamWritability = enum {
    /// The socket can take bytes right now.
    writable,
    /// The send buffer is full because the peer has stopped draining, so the
    /// next write blocks until it resumes. This — and only this — is
    /// backpressure, and for the synchronous HTTP/1 relay it is the whole of
    /// it, since that relay has no queue whose depth could cross a watermark.
    blocked,
    /// The socket is in error or hung up, or the check itself failed. A broken
    /// connection is not a slow one: the write is about to fail, and calling
    /// that a pause would report an upstream *failure* as a stalled origin.
    failed,
};

/// Ask whether `fd` can take bytes right now. Never waits.
///
/// `poll` reports a descriptor as ready for `POLLERR`, `POLLHUP`, or
/// `POLLNVAL` even when `POLLOUT` is absent, so readiness alone does not mean
/// writable and its absence does not mean full — the three outcomes have to be
/// separated or a dead upstream shows up in the backpressure counters.
fn pollUpstreamWritability(fd: std.posix.fd_t) UpstreamWritability {
    var pfds = [_]std.posix.pollfd{.{
        .fd = fd,
        .events = std.posix.POLL.OUT,
        .revents = 0,
    }};
    const ready = std.posix.poll(&pfds, 0) catch return .failed;
    if (ready == 0) return .blocked;
    const revents = pfds[0].revents;
    // Error bits win even when POLLOUT is also set: the write is not going to
    // succeed, so this is not a stall to wait out.
    if ((revents & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL)) != 0) return .failed;
    if ((revents & std.posix.POLL.OUT) != 0) return .writable;
    return .failed;
}

test "parseBufferedUpstreamResponse keeps metadata in an arena and preserves forwarded headers" {
    var parsed = try parseBufferedUpstreamResponse(
        std.testing.allocator,
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "Cache-Control: no-store\r\n" ++
            "Connection: close\r\n" ++
            "\r\n" ++
            "ok",
    );
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u16, 200), parsed.status_code);
    try std.testing.expectEqualStrings("OK", parsed.reason);
    try std.testing.expectEqualStrings("text/plain", parsed.headerValue("content-type").?);
    try std.testing.expect(bufferedUpstreamResponseHasNoStore(&parsed));
    try std.testing.expectEqualStrings("ok", parsed.body);
}

test "parseBufferedUpstreamResponse returns UpstreamProtocolError on partial upstream response" {
    // Simulates an upstream that closes the TCP connection before sending a
    // complete HTTP response head (the scenario reported in issue #94).
    // Before the fix this returned error.UnsupportedHttpMethod, a misleading
    // name that also prevented callers from distinguishing a real method
    // rejection from a dropped-connection scenario.
    const testing = std.testing;

    // Upstream closed immediately — empty body
    try testing.expectError(error.UpstreamProtocolError, parseBufferedUpstreamResponse(testing.allocator, ""));

    // Upstream sent a partial status line and closed
    try testing.expectError(error.UpstreamProtocolError, parseBufferedUpstreamResponse(testing.allocator, "HTTP/1.1"));

    // Upstream sent headers but no blank line (no \r\n\r\n terminator)
    try testing.expectError(error.UpstreamProtocolError, parseBufferedUpstreamResponse(testing.allocator, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"));
}

test "parseBufferedUpstreamResponse rejects control characters embedded in a header value (#673)" {
    // A header line is only split on an exact "\r\n" boundary, so a bare CR
    // (not part of a \r\n pair) or a NUL byte embedded inside what should
    // be a single value survives into the parsed value unless explicitly
    // validated. Before this fix, a hostile or compromised upstream could
    // ride such bytes straight through to the client -- exactly the kind
    // of response-splitting-adjacent injection the request-direction
    // parser already rejects via Headers.append()/isValidHeaderValue(),
    // which upstream responses never went through.
    const testing = std.testing;

    // Bare CR (0x0D) embedded in a value, not part of a \r\n line ending.
    try testing.expectError(
        error.UpstreamProtocolError,
        parseBufferedUpstreamResponse(testing.allocator, "HTTP/1.1 200 OK\r\nX-Hostile: val\rue\r\nContent-Length: 2\r\n\r\nok"),
    );

    // NUL byte embedded in a value.
    try testing.expectError(
        error.UpstreamProtocolError,
        parseBufferedUpstreamResponse(testing.allocator, "HTTP/1.1 200 OK\r\nX-Hostile: val\x00ue\r\nContent-Length: 2\r\n\r\nok"),
    );

    // Control character embedded in a header name.
    try testing.expectError(
        error.UpstreamProtocolError,
        parseBufferedUpstreamResponse(testing.allocator, "HTTP/1.1 200 OK\r\nX-Bad\x01Name: value\r\nContent-Length: 2\r\n\r\nok"),
    );

    // A clean response with no control characters is unaffected.
    var ok_response = try parseBufferedUpstreamResponse(testing.allocator, "HTTP/1.1 200 OK\r\nX-Safe: value\r\nContent-Length: 2\r\n\r\nok");
    defer ok_response.deinit(testing.allocator);
    try testing.expectEqualStrings("ok", ok_response.body);
}

test "exchange rejects duplicate upstream Content-Length in either order, not just conflicting values (#673 review)" {
    // `detectResponseFraming()` -- which the buffered/streaming EXCHANGE
    // loops call to decide how many bytes to read, not
    // `parseBufferedUpstreamResponse()`, which only parses an
    // already-fully-buffered blob -- kept overwriting `content_length` on
    // every occurrence. A duplicate field, whether the values conflicted
    // or merely repeated, silently resolved to whichever field came last,
    // with no guarantee a downstream client would resolve the same
    // ambiguity the same way. This mirrors the request-direction policy,
    // which rejects ANY duplicate Content-Length outright.
    const testing = std.testing;

    // Small value first, then large: the smaller of the two would produce
    // a "safe-looking" short read if honored, so this ordering alone could
    // previously mask the bug (the larger, later value always won).
    try testing.expectError(
        error.UpstreamProtocolError,
        exchangeAgainstKeepAlivePeer(testing.allocator, "GET", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 99\r\n\r\nok"),
    );

    // Large value first, then small: with the old last-wins logic this
    // ordering picks the SMALLER boundary, leaving "extra" bytes -- e.g. a
    // smuggled follow-up request or a ghost response -- past what the
    // parser thinks is the end of this response.
    try testing.expectError(
        error.UpstreamProtocolError,
        exchangeAgainstKeepAlivePeer(testing.allocator, "GET", "HTTP/1.1 200 OK\r\nContent-Length: 99\r\nContent-Length: 2\r\n\r\nok"),
    );

    // Equal duplicate values are also rejected -- HTTP defines no
    // combination semantics for Content-Length, so a repeated field is
    // ambiguous regardless of whether the values happen to match.
    try testing.expectError(
        error.UpstreamProtocolError,
        exchangeAgainstKeepAlivePeer(testing.allocator, "GET", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok"),
    );

    // A single, unambiguous Content-Length is unaffected.
    var ok_response = try exchangeAgainstKeepAlivePeer(testing.allocator, "GET", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok");
    defer ok_response.deinit(testing.allocator);
    try testing.expectEqualStrings("ok", ok_response.body);
}

test "parseBufferedUpstreamResponse rejects an unparseable status code instead of defaulting to 200 (#673 review)" {
    // Silently defaulting to 200 on a garbled status line could mask a
    // real upstream error response as success.
    const testing = std.testing;
    try testing.expectError(
        error.UpstreamProtocolError,
        parseBufferedUpstreamResponse(testing.allocator, "HTTP/1.1 NOTASTATUS OK\r\nContent-Length: 2\r\n\r\nok"),
    );
}

test "parseBufferedUpstreamResponse rejects a bare LF in the status line instead of letting it hide a header (#673 review)" {
    // The reviewer's exact composed example. This used to be a "still
    // strips the nomination correctly" regression test: the buffered path
    // found the status line's own end via the first BARE LF (matching
    // `compat.trimRight(..., "\r")` immediately after), so it happened to
    // isolate "HTTP/1.1 200 OK" and treat "Connection: X-Hostile-Secret" as
    // an ordinary header line, same as if it had arrived after a normal
    // "\r\n" -- ad hoc bare-LF tolerance that the streaming path never had.
    // Now that both paths share `parseStrictStatusLine` (#673 review round
    // 5), the buffered path is exactly as strict as streaming: a bare LF
    // inside the status line makes `isValidHeaderValue` reject it outright,
    // the same way `readUpstreamHead` already did below.
    const testing = std.testing;
    const hostile =
        "HTTP/1.1 200 OK\nConnection: X-Hostile-Secret\r\n" ++
        "X-Hostile-Secret: must-not-leak\r\n" ++
        "Content-Length: 2\r\n\r\nok";
    try testing.expectError(
        error.UpstreamProtocolError,
        parseBufferedUpstreamResponse(testing.allocator, hostile),
    );
}

test "readUpstreamHead rejects a status line whose embedded bare LF swallows a header into the reason phrase (#673 review)" {
    // The streaming path's status-line boundary is found via the first
    // EXACT "\r\n" (not a bare LF), so for the reviewer's composed hostile
    // example the whole run "HTTP/1.1 200 OK\nConnection: X-Hostile-Secret"
    // -- everything up to the first REAL "\r\n", which lands after
    // "X-Hostile-Secret" rather than right after "OK" -- gets treated as
    // ONE status line, with "OK\nConnection: X-Hostile-Secret" becoming the
    // reason phrase. That text would then be written verbatim into the
    // status line Tardigrade sends the downstream client, which may treat
    // the embedded LF as a line terminator of its own and interpret the
    // smuggled text as a genuine extra header -- a response-splitting
    // vector distinct from (and, for this path, more direct than) the
    // Connection-nomination-scanner bypass the buffered path had.
    const testing = std.testing;
    const allocator = std.testing.allocator;
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);
    const hostile =
        "HTTP/1.1 200 OK\nConnection: X-Hostile-Secret\r\n" ++
        "X-Hostile-Secret: must-not-leak\r\n" ++
        "Content-Length: 2\r\n\r\nok";
    _ = std.c.write(peer_fd, hostile.ptr, hostile.len);

    var read_storage: [4096]u8 = undefined;
    var rb = StreamReadBuf{ .buf = &read_storage };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const transport = compat.netStreamFromFd(client_fd);

    try testing.expectError(
        error.UpstreamProtocolError,
        readUpstreamHead(arena.allocator(), &rb, transport, client_fd, 1_000, "GET"),
    );
}

pub fn bufferedUpstreamResponseHasNoStore(response: *const BufferedUpstreamResponse) bool {
    for (response.headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "cache-control")) continue;
        var tokens = std.mem.splitScalar(u8, header.value, ',');
        while (tokens.next()) |token_raw| {
            const token = std.mem.trim(u8, token_raw, " \t\r\n");
            if (std.ascii.eqlIgnoreCase(token, "no-store")) return true;
        }
    }
    return false;
}

/// Execute the current bounded buffered HTTP/1 reverse-proxy transport.
/// `gateway_proxy_runtime.zig` owns data-plane retry/routing semantics and
/// should be the place future streaming/backpressure work swaps this out.
pub fn executeBoundedBufferedHttpProxyRequest(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    url: []const u8,
    unix_socket_path: ?[]const u8,
    method: []const u8,
    request_headers: *const http.Headers,
    body: []const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    forwarded_proto: []const u8,
    incoming_host: ?[]const u8,
    upstream_host_override: ?[]const u8,
    auth_identity: ?[]const u8,
    auth_user_id: ?[]const u8,
    auth_device_id: ?[]const u8,
    auth_scopes: ?[]const u8,
    forward_early_data: bool,
    attempt_timeout_ms: u32,
    connect_timeout_ms: u32,
    /// If > 0, caps the time from finished request-send to first response byte.
    /// Enforced on all transports (Unix socket, TCP, TLS) via per-phase socket
    /// timeouts now that the path no longer routes through std.http.Client.
    response_timeout_ms: u32,
    cancel_token: ?*const CancellationToken,
    /// Optional keep-alive pool for plain-HTTP upstream connection reuse (#141).
    pool: ?*http.upstream_pool.UpstreamPool,
    /// Optional per-origin HTTP/2 multiplexing pool (#145).
    h2_pool: ?*http.upstream_h2.H2ConnPool,
) !BufferedUpstreamResponse {
    // Bail out before touching the network if the request is already stopped.
    if (cancel_token) |tok| {
        if (tok.isStopped()) return error.RequestCancelled;
    }
    const proxy_extra_header_slack = 11;
    const max_buffered_response_bytes = maxBufferedUpstreamResponseBytes(cfg);
    const uri = try std.Uri.parse(url);

    var extra_headers_stack = std.heap.stackFallback(2048, allocator);
    const extra_headers_allocator = extra_headers_stack.get();
    var forwarded_for = try gph.buildForwardedFor(allocator, request_headers.get("x-forwarded-for"), client_ip);
    defer forwarded_for.deinit(allocator);

    var extra_headers = std.array_list.Managed(std.http.Header).init(extra_headers_allocator);
    defer extra_headers.deinit();
    try extra_headers.ensureUnusedCapacity(request_headers.count() + proxy_extra_header_slack);
    try gph.appendProxyRequestHeaders(&extra_headers, request_headers);
    if (upstream_host_override) |value| {
        const trimmed = std.mem.trim(u8, value, " \t\r\n");
        if (trimmed.len > 0) try extra_headers.append(.{ .name = "Host", .value = trimmed });
    }
    try gph.appendCanonicalEarlyDataHeader(&extra_headers, forward_early_data);
    try gph.appendRequestIdHeaders(&extra_headers, correlation_id);
    try extra_headers.append(.{ .name = "X-Forwarded-For", .value = forwarded_for.value });
    try extra_headers.append(.{ .name = "X-Real-IP", .value = client_ip });
    try extra_headers.append(.{ .name = "X-Forwarded-Proto", .value = forwarded_proto });
    if (incoming_host) |value| {
        const trimmed = std.mem.trim(u8, value, " \t\r\n");
        if (trimmed.len > 0) try extra_headers.append(.{ .name = "X-Forwarded-Host", .value = trimmed });
    }
    try gph.appendAssertedIdentityHeaders(&extra_headers, auth_identity, auth_user_id, auth_device_id, auth_scopes);
    // W3C Trace Context: propagate inbound traceparent or originate a new one.
    // A child span is created from an inbound context so the trace ID is preserved
    // but each hop gets its own span ID.
    var traceparent_buf: [55]u8 = undefined;
    if (request_headers.get("traceparent") == null) {
        const tc = http.trace_context.generate();
        const tp = tc.format(&traceparent_buf);
        if (tp.len > 0) try extra_headers.append(.{ .name = "traceparent", .value = tp });
    }

    if (unix_socket_path) |socket_path| {
        const base_timeout_ms = if (attempt_timeout_ms > 0) attempt_timeout_ms else connect_timeout_ms;
        const effective_timeout_ms = if (cancel_token) |tok|
            tok.effectiveTimeoutMs(base_timeout_ms)
        else
            base_timeout_ms;
        const effective_response_timeout_ms = if (cancel_token) |tok|
            tok.effectiveTimeoutMs(response_timeout_ms)
        else
            response_timeout_ms;
        return executeBoundedBufferedUnixSocketHttpRequest(
            allocator,
            socket_path,
            uri,
            method,
            extra_headers.items,
            body,
            null,
            max_buffered_response_bytes,
            effective_timeout_ms,
            effective_response_timeout_ms,
            pool,
        );
    }

    // Plain HTTP/1 or TLS TCP upstream — manual bounded transport with per-phase
    // timeout enforcement (issue #196) and keep-alive pooling (#141). HTTPS uses
    // the global upstream TLS config and is pooled separately from plain HTTP.
    const is_https = std.ascii.eqlIgnoreCase(uri.scheme, "https");
    const host = if (uri.host) |h| uriComponentBytes(h) else return error.UpstreamProtocolError;
    const port: u16 = uri.port orelse (if (is_https) @as(u16, 443) else 80);
    const tls_options: ?http.upstream_tls.UpstreamTlsOptions = if (is_https) .{
        .skip_verify = !cfg.upstream_tls_verify,
        .ca_bundle_path = cfg.upstream_tls_ca_bundle,
        .sni_override = cfg.upstream_tls_server_name,
        .client_cert_path = cfg.upstream_tls_client_cert,
        .client_key_path = cfg.upstream_tls_client_key,
        .alpn_policy = upstreamAlpnPolicy(cfg.upstream_protocol),
    } else null;
    const base_timeout_ms = if (attempt_timeout_ms > 0) attempt_timeout_ms else connect_timeout_ms;
    const effective_send_timeout_ms = if (cancel_token) |tok|
        tok.effectiveTimeoutMs(base_timeout_ms)
    else
        base_timeout_ms;
    const effective_response_timeout_ms = if (cancel_token) |tok|
        tok.effectiveTimeoutMs(response_timeout_ms)
    else
        response_timeout_ms;
    return executeBoundedBufferedTcpHttpRequest(
        allocator,
        host,
        port,
        tls_options,
        uri,
        method,
        extra_headers.items,
        body,
        null,
        max_buffered_response_bytes,
        effective_send_timeout_ms,
        effective_response_timeout_ms,
        pool,
        h2_pool,
        cfg.upstream_protocol.h2cPriorKnowledge(),
    );
}

// ---------------------------------------------------------------------------
// Manual streaming upstream reader (#141 Phase 3)
//
// Replaces std.http.Client's framing-aware reader on the streaming proxy path
// with a poll-bounded manual reader so streaming inherits the #196 timeout
// enforcement and pooling instead of the opaque client.
// ---------------------------------------------------------------------------

/// A sliding-window read buffer over a manual transport. Holds bytes read from
/// the socket so the response head can be parsed and the body streamed without
/// re-reading. `buf` is caller-owned.
const StreamReadBuf = struct {
    buf: []u8,
    start: usize = 0,
    end: usize = 0,

    fn available(self: *const StreamReadBuf) []u8 {
        return self.buf[self.start..self.end];
    }

    fn consume(self: *StreamReadBuf, n: usize) void {
        self.start += n;
        if (self.start == self.end) {
            self.start = 0;
            self.end = 0;
        }
    }

    /// Read more bytes from the transport (poll-bounded). Returns false on EOF.
    fn fill(self: *StreamReadBuf, transport: anytype, fd: std.posix.fd_t, deadline_ms: u32) !bool {
        if (self.start == self.end) {
            self.start = 0;
            self.end = 0;
        } else if (self.end == self.buf.len) {
            std.mem.copyForwards(u8, self.buf[0 .. self.end - self.start], self.buf[self.start..self.end]);
            self.end -= self.start;
            self.start = 0;
        }
        if (self.end == self.buf.len) return error.StreamTooLong; // window full without a delimiter
        if (deadline_ms > 0 and !transportHasBufferedInput(transport) and !try pollFdReadable(fd, deadline_ms)) return error.Timeout;
        const n = try transport.read(self.buf[self.end..]);
        if (n == 0) return false;
        self.end += n;
        return true;
    }
};

fn cancelStopped(tok: ?*const CancellationToken) bool {
    if (tok) |t| return t.isStopped();
    return false;
}

const ParsedUpstreamHead = struct {
    status_code: u16,
    reason: []const u8, // arena-owned
    headers: []UpstreamHeader, // arena-owned
    framing: ResponseFraming,
    connection_close: bool,
    http_1_1: bool,
};

/// Read and parse the upstream response head from `rb` (poll-bounded), leaving
/// any already-read body bytes in `rb`. reason/headers are allocated in `arena`.
fn readUpstreamHead(
    arena: std.mem.Allocator,
    rb: *StreamReadBuf,
    transport: anytype,
    fd: std.posix.fd_t,
    deadline_ms: u32,
    method: []const u8,
) !ParsedUpstreamHead {
    while (std.mem.find(u8, rb.available(), "\r\n\r\n") == null) {
        if (!try rb.fill(transport, fd, deadline_ms)) {
            return if (rb.available().len == 0) error.UpstreamConnectionClosed else error.UpstreamProtocolError;
        }
    }
    const win = rb.available();
    const head_end = std.mem.find(u8, win, "\r\n\r\n").?;
    const header_block = win[0..head_end];

    // Uses the SAME strict status-line parser `detectResponseFraming`
    // uses (#673 review): a prior version had this function find the
    // status line's own end independently, via the first exact `\r\n`
    // wherever it happened to fall, without validating the line's
    // content -- so a bare LF earlier in the response let real header
    // text (including a real `Connection`-nominated header) get absorbed
    // into what this parser treated as the status line's own
    // reason-phrase text, which was then written verbatim into the status
    // line sent to the downstream client. A single shared parser also
    // means this function and `detectResponseFraming` cannot disagree
    // about where headers begin.
    const status_line = try parseStrictStatusLine(header_block);
    const http_1_1 = std.mem.startsWith(u8, header_block, "HTTP/1.1 ");
    const status_code = status_line.status_code;
    const reason = try arena.dupe(u8, status_line.reason);

    var headers = std.array_list.Managed(UpstreamHeader).init(arena);
    var connection_close = false;
    var lines = std.mem.splitSequence(u8, header_block[@min(status_line.header_lines_start, header_block.len)..], "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "connection")) {
            var toks = std.mem.splitScalar(u8, value, ',');
            while (toks.next()) |t| {
                if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, t, " \t"), "close")) connection_close = true;
            }
        }
        // See parseBufferedUpstreamResponse: a header line is only split on
        // an exact "\r\n" boundary, so a bare CR/LF or NUL embedded inside
        // what should be a single value survives into `value` unless
        // validated here -- reject the response rather than forward a
        // hostile upstream's control characters straight to the client (#673).
        if (!http.headers.isValidHeaderName(name) or !http.headers.isValidHeaderValue(value)) {
            return error.UpstreamProtocolError;
        }
        if (gph.shouldSkipUpstreamResponseHeader(name, null)) continue;
        // See parseBufferedUpstreamResponse: scan the same header-lines
        // view this loop itself iterates (starting after the status
        // line), not the whole `header_block` from byte 0.
        if (gph.anyRawConnectionHeaderReferencesHeader(header_block[@min(status_line.header_lines_start, header_block.len)..], name)) continue;
        try headers.append(.{ .name = try arena.dupe(u8, name), .value = try arena.dupe(u8, value) });
    }
    const framing = try detectResponseFraming(header_block, method);
    rb.consume(head_end + 4);
    return .{
        .status_code = status_code,
        .reason = reason,
        .headers = try headers.toOwnedSlice(),
        .framing = framing,
        .connection_close = connection_close,
        .http_1_1 = http_1_1,
    };
}

const RelayOutcome = struct {
    body_bytes: usize,
    aborted: bool, // upstream closed/failed before the framed body completed
    reusable: bool, // connection may be returned to the pool
};

fn readChunkSize(rb: *StreamReadBuf, transport: anytype, fd: std.posix.fd_t, deadline_ms: u32) !?usize {
    while (std.mem.find(u8, rb.available(), "\r\n") == null) {
        if (!try rb.fill(transport, fd, deadline_ms)) return null;
    }
    const avail = rb.available();
    const eol = std.mem.find(u8, avail, "\r\n").?;
    const size_line = avail[0..eol];
    const size_str = if (std.mem.findScalar(u8, size_line, ';')) |s| size_line[0..s] else size_line;
    const size = std.fmt.parseInt(usize, std.mem.trim(u8, size_str, " \t"), 16) catch return error.UpstreamProtocolError;
    rb.consume(eol + 2);
    return size;
}

fn consumeExactCrlf(rb: *StreamReadBuf, transport: anytype, fd: std.posix.fd_t, deadline_ms: u32) !bool {
    while (rb.available().len < 2) {
        if (!try rb.fill(transport, fd, deadline_ms)) return false;
    }
    if (!std.mem.eql(u8, rb.available()[0..2], "\r\n")) return error.UpstreamProtocolError;
    rb.consume(2);
    return true;
}

fn consumeChunkTrailers(rb: *StreamReadBuf, transport: anytype, fd: std.posix.fd_t, deadline_ms: u32) !bool {
    while (true) {
        while (std.mem.find(u8, rb.available(), "\r\n") == null) {
            if (!try rb.fill(transport, fd, deadline_ms)) return false;
        }
        const avail = rb.available();
        const eol = std.mem.find(u8, avail, "\r\n").?;
        if (eol == 0) {
            rb.consume(2);
            return true; // blank line terminates the trailer section
        }
        // RFC 9112 §7.1.2: a non-blank trailer line must actually be valid
        // `field-name ":" OWS field-value OWS` syntax, not arbitrary text a
        // hostile upstream could use to hide a pipelined ghost response
        // inside what looks like "just a trailer" (#673 review round 8):
        // the streaming response-relay path consumed any CRLF-delimited
        // line here with no validation at all, unlike the buffered
        // decoder's equivalent.
        if (!http.headers.isValidTrailerLine(avail[0..eol])) return error.UpstreamProtocolError;
        rb.consume(eol + 2);
    }
}

/// Relay the upstream response body to `downstream_writer` (re-chunked via
/// `writeChunk`), decoding the upstream framing as it streams. Returns the
/// number of body bytes relayed and whether the connection is reusable.
/// Downstream write failures surface as error.ClientAborted.
fn relayUpstreamBody(
    rb: *StreamReadBuf,
    transport: anytype,
    fd: std.posix.fd_t,
    deadline_ms: u32,
    framing: ResponseFraming,
    downstream_write: *gpres.StreamingResponseWriteState,
    downstream_writer: anytype,
    cancel_token: ?*const CancellationToken,
) !RelayOutcome {
    var total: usize = 0;
    switch (framing) {
        // Bodiless (HEAD/204/304/1xx): never reusable, even if nothing has
        // trailed the head *yet*. A malicious/misbehaving upstream can send
        // just the header block, flush, wait until Tardigrade returns this
        // socket to the idle pool, and only then send an illegal body or a
        // full ghost response -- those bytes would become part of whatever
        // unrelated request next checks the connection out of the pool
        // (#673 review). `rb.available().len == 0` only proves nothing had
        // arrived *by this instant*; it cannot prove nothing ever will.
        .none => return .{ .body_bytes = 0, .aborted = false, .reusable = false },
        .length => |content_length| {
            var remaining = content_length;
            while (remaining > 0) {
                if (cancelStopped(cancel_token)) return error.RequestCancelled;
                if (rb.available().len == 0 and !try rb.fill(transport, fd, deadline_ms)) {
                    return .{ .body_bytes = total, .aborted = true, .reusable = false };
                }
                const take = @min(rb.available().len, remaining);
                downstream_write.beginChunk(rb.available()[0..take]) catch return error.ClientAborted;
                gpres.drainStreamingWriteBlocking(downstream_write, downstream_writer) catch return error.ClientAborted;
                rb.consume(take);
                total += take;
                remaining -= take;
            }
            // Reusable only if the socket is back in sync (no bytes past the body).
            return .{ .body_bytes = total, .aborted = false, .reusable = rb.available().len == 0 };
        },
        .chunked => {
            while (true) {
                if (cancelStopped(cancel_token)) return error.RequestCancelled;
                const size = (try readChunkSize(rb, transport, fd, deadline_ms)) orelse
                    return .{ .body_bytes = total, .aborted = true, .reusable = false };
                if (size == 0) {
                    if (!try consumeChunkTrailers(rb, transport, fd, deadline_ms)) {
                        return .{ .body_bytes = total, .aborted = true, .reusable = false };
                    }
                    // Reusable only if nothing trailed the terminating chunk.
                    return .{ .body_bytes = total, .aborted = false, .reusable = rb.available().len == 0 };
                }
                var chunk_remaining = size;
                while (chunk_remaining > 0) {
                    if (rb.available().len == 0 and !try rb.fill(transport, fd, deadline_ms)) {
                        return .{ .body_bytes = total, .aborted = true, .reusable = false };
                    }
                    const take = @min(rb.available().len, chunk_remaining);
                    downstream_write.beginChunk(rb.available()[0..take]) catch return error.ClientAborted;
                    gpres.drainStreamingWriteBlocking(downstream_write, downstream_writer) catch return error.ClientAborted;
                    rb.consume(take);
                    total += take;
                    chunk_remaining -= take;
                }
                if (!try consumeExactCrlf(rb, transport, fd, deadline_ms)) {
                    return .{ .body_bytes = total, .aborted = true, .reusable = false };
                }
            }
        },
        .close => {
            while (true) {
                if (cancelStopped(cancel_token)) return error.RequestCancelled;
                if (rb.available().len == 0 and !try rb.fill(transport, fd, deadline_ms)) break;
                downstream_write.beginChunk(rb.available()) catch return error.ClientAborted;
                gpres.drainStreamingWriteBlocking(downstream_write, downstream_writer) catch return error.ClientAborted;
                total += rb.available().len;
                rb.consume(rb.available().len);
            }
            // Close-delimited responses cannot be reused (the socket is spent).
            return .{ .body_bytes = total, .aborted = false, .reusable = false };
        },
    }
}

/// Send the proxied request head and body to the upstream over `transport`.
/// `streaming_body` relays the client upload incrementally; `buffered_body` is
/// sent in one shot. Keep-alive (no `Connection: close`) so the connection can
/// be pooled.
fn sendStreamingProxyRequest(
    allocator: std.mem.Allocator,
    transport: anytype,
    fd: std.posix.fd_t,
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    buffered_body: []const u8,
    streaming_body: ?StreamingRequestBody,
    downstream_conn: anytype,
    cancel_token: ?*const CancellationToken,
    proxy_buffer_limits: proxy_buffer_account.Limits,
    proxy_buffer_observer: proxy_buffer_account.Observer,
    proxy_buffer_capacity: proxy_buffer_account.AggregateCapacity,
) !void {
    // Claim the upload's buffer footprint before a single byte of the request
    // reaches the origin (#140). Reserving inside the relay meant a local
    // 413/503 could only be raised after the origin had already received a
    // half-delivered, possibly side-effecting request.
    var upload_reservation: ?ProxyBufferReservation = null;
    defer if (upload_reservation) |*reservation| reservation.releaseAll();
    if (streaming_body) |sb| {
        upload_reservation = try preflightUploadReservation(
            proxy_buffer_limits,
            proxy_buffer_observer,
            proxy_buffer_capacity,
            http1_upload_relay_bytes,
            uploadInitialBytesFootprint(sb),
        );
    }

    var req_aw: std.Io.Writer.Allocating = .init(allocator);
    defer req_aw.deinit();
    const w = &req_aw.writer;
    var host_buf: [256]u8 = undefined;
    const host = if (uri.host) |value| try value.toRaw(&host_buf) else "localhost";

    try w.print("{s} {s}", .{ method, uriComponentBytes(uri.path) });
    if (uri.query) |query| try w.print("?{s}", .{uriComponentBytes(query)});
    try w.writeAll(" HTTP/1.1\r\n");
    // Preserve a non-default upstream port in the Host header.
    const default_port: u16 = if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) 443 else 80;
    if (uri.port) |p| {
        if (p != default_port) {
            try w.print("Host: {s}:{d}\r\n", .{ host, p });
        } else {
            try w.print("Host: {s}\r\n", .{host});
        }
    } else {
        try w.print("Host: {s}\r\n", .{host});
    }
    for (extra_headers) |header| try w.print("{s}: {s}\r\n", .{ header.name, header.value });
    if (streaming_body) |sb| {
        switch (sb.framing) {
            // A chunked client upload is re-framed rather than buffered, so the
            // upstream request stays chunked and no length is declared.
            .length => |content_length| try w.print("Content-Length: {d}\r\n", .{content_length}),
            .chunked => try w.writeAll("Transfer-Encoding: chunked\r\n"),
        }
    } else if (buffered_body.len > 0) {
        try w.print("Content-Length: {d}\r\n", .{buffered_body.len});
    }
    try w.writeAll("\r\n");
    try transport.writeAll(req_aw.written());

    if (streaming_body) |sb| {
        try relayStreamingUploadToHttp1(
            transport,
            fd,
            sb,
            downstream_conn,
            cancel_token,
            &upload_reservation.?,
            proxy_buffer_observer,
        );
    } else if (buffered_body.len > 0) {
        try transport.writeAll(buffered_body);
    }
}

/// Relay a streamed client upload to an HTTP/1.1 upstream. Both framings copy
/// through one fixed relay buffer, so peak user-space upload memory is bounded
/// regardless of the body size.
///
/// `fd` is the upstream socket (the TLS carrier when the transport is TLS). It
/// is used only to notice a write that would block: this relay reads the client
/// again only after the upstream write completes, so a full upstream send buffer
/// *is* a pause of downstream reads, and that transition is the only place a
/// slow origin becomes visible on a path that deliberately has no queue (#140).
///
/// `reservation` is preflighted by the caller and already covers this relay
/// buffer plus `uploadInitialBytesFootprint(sb)`; the caller releases the rest.
/// This function only gives back the initial-bytes portion as those bytes
/// actually drain, so a long upload does not hold the request head's peak for
/// its whole life.
fn relayStreamingUploadToHttp1(
    transport: anytype,
    fd: std.posix.fd_t,
    sb: StreamingRequestBody,
    downstream_conn: anytype,
    cancel_token: ?*const CancellationToken,
    reservation: *ProxyBufferReservation,
    observer: proxy_buffer_account.Observer,
) !void {
    var relay: [http1_upload_relay_bytes]u8 = undefined;

    // Balanced on every exit — success, client abort, cancellation, upstream
    // failure — so the pause/resume difference reads as "relays stalled right
    // now" instead of drifting by one per aborted upload.
    var stall = proxy_buffer_account.ReadStall.init(.downstream, observer);
    defer stall.unpause();

    switch (sb.framing) {
        .length => |content_length| {
            var sent: usize = @min(sb.initial_bytes.len, content_length);
            if (sent > 0) {
                noteUpstreamWriteStall(fd, &stall);
                transport.writeAll(sb.initial_bytes[0..sent]) catch |err| {
                    reservation.release(sent);
                    return err;
                };
                stall.unpause();
                // Forwarded: the request head's body bytes are no longer held.
                reservation.release(sent);
            }
            while (sent < content_length) {
                if (cancelStopped(cancel_token)) return error.RequestCancelled;
                const want = @min(relay.len, content_length - sent);
                const n = downstream_conn.read(relay[0..want]) catch return error.ClientAborted;
                if (n == 0) return error.ClientAborted;
                noteUpstreamWriteStall(fd, &stall);
                try transport.writeAll(relay[0..n]);
                stall.unpause();
                sent += n;
            }
        },
        .chunked => {
            // Decode the client's framing and re-chunk downstream-to-upstream.
            // Re-framing (rather than forwarding the raw octets) keeps the
            // upstream request well formed even when the client uses chunk
            // extensions or trailers, which this hop does not forward.
            var reader = http.chunked_upload.Reader(@TypeOf(downstream_conn))
                .init(downstream_conn, sb.initial_bytes, sb.max_body_bytes);
            // The decoder borrows the whole raw request-head remainder —
            // framing octets included, which is why the reservation covers the
            // raw length rather than the decoded payload.
            var head_bytes_held = sb.initial_bytes.len;
            while (true) {
                if (cancelStopped(cancel_token)) return error.RequestCancelled;
                const n = try reader.next(&relay);
                // Give back what the decoder has finished with, before acting on
                // `n`: the terminal call consumes borrowed trailer bytes too.
                releaseDrainedHeadBytes(reservation, &head_bytes_held, reader.pendingBytes());
                if (n == 0) break;
                var size_buf: [24]u8 = undefined;
                const size_line = std.fmt.bufPrint(&size_buf, "{x}\r\n", .{n}) catch unreachable;
                // One stall check per chunk, not per write: the three writes
                // below are one logical chunk and stall or drain together.
                noteUpstreamWriteStall(fd, &stall);
                try transport.writeAll(size_line);
                try transport.writeAll(relay[0..n]);
                try transport.writeAll("\r\n");
                stall.unpause();
            }
            try transport.writeAll("0\r\n\r\n");
        },
    }
}

/// Release the request-head bytes a chunked decoder has consumed since the last
/// check. `still_held` is what it still borrows; anything below the previous
/// mark has been copied out and is no longer retained.
fn releaseDrainedHeadBytes(
    reservation: *ProxyBufferReservation,
    head_bytes_held: *usize,
    still_held: usize,
) void {
    if (still_held >= head_bytes_held.*) return;
    reservation.release(head_bytes_held.* - still_held);
    head_bytes_held.* = still_held;
}

/// Hard cap on the number of `1xx` interim responses `streamProxyOverTransport`
/// will discard while waiting for an upstream's actual final response.
/// Without this, a hostile or misbehaving origin could drip-feed interim
/// responses (e.g. `103 Early Hints`) indefinitely, tying up the request past
/// any read-level deadline (#673 review). Generous enough for legitimate
/// multi-hint chains; far below anything a real origin would ever need.
const max_interim_upstream_responses: usize = 64;

/// Run one streaming proxy attempt over an already-connected `transport`: send
/// the request, read the response head, relay the head+body downstream, and
/// report whether the connection is reusable. `wrote_downstream` is set true the
/// moment any response bytes are written to the client (after which the caller
/// must not retry on a fresh connection).
fn streamProxyOverTransport(
    allocator: std.mem.Allocator,
    transport: anytype,
    fd: std.posix.fd_t,
    /// Response relay buffer size. A size rather than a buffer because the
    /// reservation has to come first: this buffer is application-owned the
    /// moment it exists, and `readUpstreamHead` reads into it — past the blank
    /// line, so response body bytes can land there — before any scope has been
    /// charged. Allocated per attempt, once admitted.
    relay_bytes: usize,
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    buffered_body: []const u8,
    streaming_body: ?StreamingRequestBody,
    downstream_conn: anytype,
    downstream_writer: anytype,
    security: *const http.security_headers.SecurityHeaders,
    alt_svc: ?[]const u8,
    sticky_set_cookie: ?[]const u8,
    correlation_id: []const u8,
    downstream_keep_alive: bool,
    connect_timeout_ms: u32,
    read_deadline_ms: u32,
    cancel_token: ?*const CancellationToken,
    wrote_downstream: *bool,
    proxy_buffer_limits: proxy_buffer_account.Limits,
    proxy_buffer_observer: proxy_buffer_account.Observer,
    proxy_buffer_capacity: proxy_buffer_account.AggregateCapacity,
) !struct { result: StreamingProxyResult, reusable: bool } {
    if (connect_timeout_ms > 0) setSocketTimeoutMs(fd, connect_timeout_ms, connect_timeout_ms) catch {};
    try sendStreamingProxyRequest(
        allocator,
        transport,
        fd,
        uri,
        method,
        extra_headers,
        buffered_body,
        streaming_body,
        downstream_conn,
        cancel_token,
        proxy_buffer_limits,
        proxy_buffer_observer,
        proxy_buffer_capacity,
    );
    if (read_deadline_ms > 0) setSocketRecvTimeoutMs(fd, read_deadline_ms) catch {};

    // The upload phase has returned its reservation, so the response phase
    // claims its own — *before* the buffer exists and before a byte of the
    // response is read into it.
    //
    // Ordering this the other way round meant the cap could only refuse after
    // the memory it bounds had already been taken: N concurrent requests to an
    // origin slow to finish a response head would each hold a relay buffer
    // while the enforcing aggregate still read zero. And because
    // `readUpstreamHead` reads past the blank line, body bytes could already be
    // sitting in that buffer by then.
    //
    // Unlike HTTP/2 there is no bodiless exemption: this buffer is what
    // *discovers* whether a body exists, so it cannot be treated as unowned
    // while that question is open.
    var response_reservation = ProxyBufferReservation.init(
        .upstream_to_downstream,
        proxy_buffer_limits,
        proxy_buffer_observer,
        proxy_buffer_capacity,
    );
    defer response_reservation.releaseAll();
    // Either refusal is local capacity before anything is committed
    // downstream, so both are the caller's clean 503 rather than a status
    // blamed on the origin.
    response_reservation.reserve(relay_bytes) catch return error.ProxyBufferCapacityUnavailable;
    const read_buf = try allocator.alloc(u8, relay_bytes);
    defer allocator.free(read_buf);

    const ttfb_start_ms = http.event_loop.monotonicMs();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var rb = StreamReadBuf{ .buf = read_buf };
    // Discard 1xx interim responses and keep reading until the actual final
    // response arrives (#673 review): before this fix, the streaming path --
    // like the buffered path before its own fix -- treated the FIRST interim
    // response (e.g. 103 Early Hints) as the complete exchange, committing it
    // downstream and abandoning whatever actually followed, including the
    // real final response. `readUpstreamHead` (via `detectResponseFraming`)
    // already rejects status 101 outright with `error.UpstreamProtocolError`
    // before it can ever reach this loop, so any status still in the 1xx
    // range here is a genuine skippable interim response.
    //
    // Three further hardenings on this loop (#673 review): a hostile origin
    // that drip-feeds interim responses forever must not be able to (1) grow
    // memory without bound -- each `readUpstreamHead` call allocates header
    // and reason-phrase copies from `arena`, and a shared arena across
    // unboundedly many iterations never frees a discarded interim head's
    // allocations until the whole request ends; (2) run past the request's
    // actual cancellation, since nothing inside this loop previously checked
    // `cancel_token`; or (3) run for an unbounded number of iterations at
    // all, since `read_deadline_ms` bounds a single read, not the cumulative
    // time/iterations spent here.
    var head = try readUpstreamHead(arena.allocator(), &rb, transport, fd, read_deadline_ms, method);
    var interim_responses: usize = 0;
    while (head.status_code >= 100 and head.status_code < 200) {
        if (cancelStopped(cancel_token)) return error.RequestCancelled;
        interim_responses += 1;
        if (interim_responses > max_interim_upstream_responses) return error.UpstreamProtocolError;
        // Free the just-discarded interim head's allocations before reading
        // the next one; the eventual non-1xx head's allocations are the only
        // ones left standing when this loop exits.
        _ = arena.reset(.free_all);
        head = try readUpstreamHead(arena.allocator(), &rb, transport, fd, read_deadline_ms, method);
    }
    const ttfb_ms = http.event_loop.monotonicMs() - ttfb_start_ms;

    const reason = gpres.upstreamReasonPhrase(@enumFromInt(head.status_code));
    const body_allowed = gpres.responseBodyAllowed(method, head.status_code);

    var downstream_write = gpres.StreamingResponseWriteState{};
    defer downstream_write.deinit();
    downstream_write.initHeadFromHeaders(
        allocator,
        head.status_code,
        reason,
        head.headers,
        body_allowed,
        downstream_keep_alive,
        correlation_id,
        security,
        alt_svc,
        sticky_set_cookie,
    ) catch return .{
        .result = streamingResultAfterDownstreamAbort(head.status_code, reason, 0, ttfb_ms),
        .reusable = false,
    };
    gpres.drainStreamingWriteBlocking(&downstream_write, downstream_writer) catch return .{
        .result = streamingResultAfterDownstreamAbort(head.status_code, reason, 0, ttfb_ms),
        .reusable = false,
    };
    wrote_downstream.* = true;

    var body_bytes: usize = 0;
    var aborted = false;
    // Bodiless final responses (HEAD/204/304 -- 1xx was already consumed
    // above) never mark the upstream connection reusable, regardless of
    // HTTP version or Connection header (#673 review): `relayUpstreamBody`
    // is the ONLY place that previously enforced this, but it is skipped
    // entirely whenever `!body_allowed`, so its fix never actually ran for
    // exactly the response family it was meant to protect. A malicious or
    // misbehaving upstream can send just the header block, flush, wait
    // until this connection is pooled, and only then send an illegal body
    // or a full ghost response.
    var reusable = body_allowed and head.http_1_1 and !head.connection_close;
    if (body_allowed) {
        const outcome = relayUpstreamBody(&rb, transport, fd, read_deadline_ms, head.framing, &downstream_write, downstream_writer, cancel_token) catch |err| {
            if (err == error.ClientAborted) {
                return .{
                    .result = streamingResultAfterDownstreamAbort(head.status_code, reason, body_bytes, ttfb_ms),
                    .reusable = false,
                };
            }
            return err;
        };
        body_bytes = outcome.body_bytes;
        aborted = outcome.aborted;
        reusable = reusable and outcome.reusable;
        if (!aborted) {
            downstream_write.beginTerminalChunk() catch return .{
                .result = streamingResultAfterDownstreamAbort(head.status_code, reason, body_bytes, ttfb_ms),
                .reusable = false,
            };
            gpres.drainStreamingWriteBlocking(&downstream_write, downstream_writer) catch return .{
                .result = streamingResultAfterDownstreamAbort(head.status_code, reason, body_bytes, ttfb_ms),
                .reusable = false,
            };
        }
    } else {
        downstream_write.finishWithoutBody() catch return .{
            .result = streamingResultAfterDownstreamAbort(head.status_code, reason, body_bytes, ttfb_ms),
            .reusable = false,
        };
    }
    if (aborted) reusable = false;

    return .{
        .result = .{
            .status_code = head.status_code,
            .reason = reason,
            .response_body_bytes = body_bytes,
            .upstream_ttfb_ms = ttfb_ms,
            .upstream_aborted = aborted,
        },
        .reusable = reusable,
    };
}

/// Stream a reverse-proxy request/response over the manual bounded transport
/// (issue #141 Phase 3), replacing `std.http.Client`. The upstream connection
/// is pooled (plain or TLS) and per-phase reads are `poll`-bounded, so the
/// streaming path inherits the #196 timeout enforcement and #141 reuse.
///
/// When `TARDIGRADE_UPSTREAM_PROTOCOL` offers h2 and the target is HTTPS, or
/// when h2c prior knowledge is explicitly configured for plain HTTP, the
/// exchange is multiplexed over the shared per-origin HTTP/2 connection. Full
/// streaming uploads relay request DATA incrementally over the h2 stream; h1 is
/// used only when h2 is not requested or TLS ALPN negotiates HTTP/1.1.
pub fn executeStreamingHttpProxyRequest(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    url: []const u8,
    /// When set, the exchange runs over this AF_UNIX socket instead of a TCP
    /// connection to `url`'s authority; `url` still supplies the request target.
    unix_socket_path: ?[]const u8,
    method: []const u8,
    request_headers: *const http.Headers,
    buffered_body: []const u8,
    streaming_body: ?StreamingRequestBody,
    downstream_conn: anytype,
    downstream_writer: anytype,
    correlation_id: []const u8,
    client_ip: []const u8,
    forwarded_proto: []const u8,
    incoming_host: ?[]const u8,
    auth_identity: ?[]const u8,
    auth_user_id: ?[]const u8,
    auth_device_id: ?[]const u8,
    auth_scopes: ?[]const u8,
    security: *const http.security_headers.SecurityHeaders,
    alt_svc: ?[]const u8,
    sticky_set_cookie: ?[]const u8,
    cancel_token: ?*const CancellationToken,
    downstream_keep_alive: bool,
    proxy_buffer_observer: proxy_buffer_account.Observer,
    /// Process-wide proxy buffer aggregate (#140). Streams reserve against it
    /// before retaining queued body bytes, so aggregate memory stays bounded no
    /// matter how many origins or concurrent streams are slow.
    proxy_buffer_global: ?*proxy_buffer_account.Aggregate,
    pool: ?*http.upstream_pool.UpstreamPool,
    /// Optional per-origin HTTP/2 multiplexing pool (#145).
    h2_pool: ?*http.upstream_h2.H2ConnPool,
    /// Set true on an error return once the downstream response head has
    /// already been written (`streamProxyOverTransport`'s own
    /// `wrote_downstream` reached true before the failure). Callers must not
    /// serialize a second HTTP response onto `downstream_writer` when this is
    /// true -- doing so corrupts an already-started response (e.g. appending
    /// a raw status line after a chunked head, breaking the client's framing
    /// mid-stream) rather than reporting the failure cleanly. Left `false`
    /// (the caller's initial value is never read, only overwritten) for
    /// every failure that occurs before any response byte is committed.
    downstream_committed: *bool,
) !StreamingProxyResult {
    if (cancelStopped(cancel_token)) return error.RequestCancelled;

    const proxy_extra_header_slack = 10;
    const uri = try std.Uri.parse(url);
    // A Unix-socket upstream is always plain HTTP/1.1 over the socket: the
    // resolved URL is a synthetic http://localhost target that only carries the
    // request line and Host header.
    const is_https = unix_socket_path == null and std.ascii.eqlIgnoreCase(uri.scheme, "https");
    const host = if (uri.host) |h| uriComponentBytes(h) else return error.UpstreamProtocolError;
    const port: u16 = uri.port orelse (if (is_https) @as(u16, 443) else 80);
    const tls_options: ?http.upstream_tls.UpstreamTlsOptions = if (is_https) .{
        .skip_verify = !cfg.upstream_tls_verify,
        .ca_bundle_path = cfg.upstream_tls_ca_bundle,
        .sni_override = cfg.upstream_tls_server_name,
        .client_cert_path = cfg.upstream_tls_client_cert,
        .client_key_path = cfg.upstream_tls_client_key,
        // Must match the buffered path: without this the policy defaults to
        // `require_http1`, so a TLS origin is only ever offered `http/1.1` and
        // `streamViaH2Pool` can never negotiate h2 no matter how
        // `TARDIGRADE_UPSTREAM_PROTOCOL` is set.
        .alpn_policy = upstreamAlpnPolicy(cfg.upstream_protocol),
    } else null;

    // Per-phase deadlines (closes the #196 streaming gap): bound the connect/
    // write phase and each response read; the read deadline bounds a hung
    // upstream stalling mid-stream.
    const connect_timeout_ms: u32 = if (cfg.upstream_connect_timeout_ms > 0) cfg.upstream_connect_timeout_ms else cfg.upstream_timeout_ms;
    const base_read_ms: u32 = if (cfg.upstream_response_timeout_ms > 0) cfg.upstream_response_timeout_ms else cfg.upstream_timeout_ms;
    const read_deadline_ms: u32 = if (cancel_token) |tok| tok.effectiveTimeoutMs(base_read_ms) else base_read_ms;

    var forwarded_for = try buildForwardedFor(allocator, request_headers.get("x-forwarded-for"), client_ip);
    defer forwarded_for.deinit(allocator);
    var extra_headers_stack = std.heap.stackFallback(2048, allocator);
    const extra_headers_allocator = extra_headers_stack.get();
    var extra_headers = std.array_list.Managed(std.http.Header).init(extra_headers_allocator);
    defer extra_headers.deinit();
    try extra_headers.ensureUnusedCapacity(request_headers.count() + proxy_extra_header_slack);
    try gph.appendProxyRequestHeaders(&extra_headers, request_headers);
    try gph.appendRequestIdHeaders(&extra_headers, correlation_id);
    try extra_headers.append(.{ .name = "X-Forwarded-For", .value = forwarded_for.value });
    try extra_headers.append(.{ .name = "X-Real-IP", .value = client_ip });
    try extra_headers.append(.{ .name = "X-Forwarded-Proto", .value = forwarded_proto });
    if (incoming_host) |value| {
        const trimmed = std.mem.trim(u8, value, " \t\r\n");
        if (trimmed.len > 0) try extra_headers.append(.{ .name = "X-Forwarded-Host", .value = trimmed });
    }
    try gph.appendAssertedIdentityHeaders(&extra_headers, auth_identity, auth_user_id, auth_device_id, auth_scopes);
    var traceparent_buf: [55]u8 = undefined;
    if (request_headers.get("traceparent") == null) {
        const tc = http.trace_context.generate();
        const tp = tc.format(&traceparent_buf);
        if (tp.len > 0) try extra_headers.append(.{ .name = "traceparent", .value = tp });
    }

    // The relay buffer's size, not the buffer: the h2 path allocates its own
    // once it knows the policy that will have to account for it, so nothing is
    // allocated here for an exchange that never uses it.
    const requested_relay_bytes = @max(cfg.proxy_stream_buffer_size, 16 * 1024);

    // HTTP/2 upstream (#145/#301): multiplex the streaming exchange over the
    // shared per-origin h2 connection when configured — via ALPN for HTTPS (h1
    // origins fall back inside) or prior-knowledge h2c for plain HTTP when
    // explicitly opted in (#237).
    // A Unix-socket upstream has no origin the h2 pool can key or ALPN-negotiate,
    // so it always uses the HTTP/1.1 relay below.
    const h2_requested_for_streaming = if (is_https) cfg.upstream_protocol.offersH2() else cfg.upstream_protocol.h2cPriorKnowledge();
    const stream_h2 = unix_socket_path == null and h2_requested_for_streaming;
    if (stream_h2) {
        if (h2_pool) |hp| {
            const h2_opts: ?http.upstream_tls.UpstreamTlsOptions = if (is_https) tls_options.? else null;
            return streamViaH2Pool(allocator, hp, pool, host, port, h2_opts, uri, method, extra_headers.items, buffered_body, streaming_body, requested_relay_bytes, downstream_conn, downstream_writer, security, alt_svc, sticky_set_cookie, correlation_id, downstream_keep_alive, connect_timeout_ms, read_deadline_ms, cancel_token, cfg.proxy_buffer_limits, proxy_buffer_observer, proxy_buffer_global, downstream_committed);
        }
        if (streaming_body != null) {
            if (pool) |p| p.recordH2StreamingUploadFallback();
        }
    }
    // Everything below runs HTTP/1.1 (counted per request, not per attempt).
    if (pool) |p| p.recordProtocol(false);

    const active_pool: ?*http.upstream_pool.UpstreamPool = if (pool) |p| (if (p.config.enabled) p else null) else null;
    var key_buf: [512]u8 = undefined;
    const key = if (unix_socket_path) |socket_path|
        std.fmt.bufPrint(&key_buf, "unix:{s}", .{socket_path}) catch socket_path
    else
        std.fmt.bufPrint(&key_buf, "{s}:{s}:{d}", .{ if (is_https) "https" else "http", host, port }) catch host;

    // Aggregate capacity for this connection's relay buffers, in both
    // directions (#140). A fixed relay buffer bounds one request, but nothing
    // bounds how many requests an origin has in flight, so the per-origin scope
    // is what stops one slow origin from multiplying its own relay memory.
    //
    // Looked up on `pool` rather than `active_pool`: the account exists to
    // bound memory, which is just as true when connection pooling is disabled.
    // A lookup failure means the accounting itself is unavailable (allocation
    // failure) — precisely when these limits matter most — so it is a
    // deterministic pre-commit refusal rather than a silently unaccounted
    // request.
    const h1_origin_buffer_account: ?*proxy_buffer_account.Aggregate = if (pool) |p|
        p.originBufferAccount(key) catch return error.ProxyBufferCapacityUnavailable
    else
        null;
    const h1_buffer_capacity = proxy_buffer_account.AggregateCapacity{
        .origin = h1_origin_buffer_account,
        .global = proxy_buffer_global,
    };

    // A dead reused connection can only be retried before any response byte
    // reaches the client, and only when the request body is re-sendable (a
    // streamed upload has already consumed the client).
    const retry_allowed = streaming_body == null;
    var attempt: usize = 0;
    while (true) : (attempt += 1) {
        const now_ms = http.event_loop.monotonicMs();

        // Acquire a connection: pooled (attempt 0) or freshly connected. The
        // checkout/reserveSlot reserves an active slot before connecting so the
        // per-origin cap (#239) is a real hard cap; failed connects release it.
        var reused = false;
        var conn: http.upstream_pool.PooledConn = undefined;
        if (active_pool) |p| {
            if (attempt == 0) {
                if (try p.checkout(key, now_ms)) |c| {
                    conn = c;
                    reused = true;
                }
            } else {
                try p.reserveSlot(key); // stale retry: deliberately fresh, still capped
            }
        }
        if (!reused) {
            const connect_start = http.event_loop.monotonicMs();
            const new_fd = (if (unix_socket_path) |socket_path|
                compat.connectBoundedUnix(socket_path, connect_timeout_ms)
            else
                compat.connectBoundedTcp(host, port, connect_timeout_ms)) catch |err| {
                if (active_pool) |p| p.releaseSlot(key);
                return err;
            };
            if (active_pool) |p| p.recordConnectLatency(http.event_loop.monotonicMs() - connect_start);
            if (tls_options) |opts| {
                if (connect_timeout_ms > 0) setSocketTimeoutMs(new_fd, connect_timeout_ms, connect_timeout_ms) catch {};
                const owner = if (active_pool) |p| p.allocator else allocator;
                const tls_ptr = owner.create(http.upstream_tls.UpstreamTlsConn) catch {
                    _ = std.c.close(new_fd);
                    if (active_pool) |p| p.releaseSlot(key);
                    return error.OutOfMemory;
                };
                tls_ptr.* = http.upstream_tls.UpstreamTlsConn.connect(new_fd, host, opts) catch |err| {
                    owner.destroy(tls_ptr);
                    _ = std.c.close(new_fd);
                    if (active_pool) |p| p.releaseSlot(key);
                    return err;
                };
                if (active_pool) |p| p.noteNewConnection(key);
                conn = .{ .stream = compat.netStreamFromFd(new_fd), .tls = tls_ptr, .created_ms = now_ms, .last_used_ms = now_ms };
            } else {
                if (active_pool) |p| p.noteNewConnection(key);
                conn = .{ .stream = compat.netStreamFromFd(new_fd), .tls = null, .created_ms = now_ms, .last_used_ms = now_ms };
            }
        }

        var wrote_downstream = false;
        const exchange_start_ms = http.event_loop.monotonicMs();
        const fd = conn.stream.handle;
        const res = (if (conn.tls) |tls|
            streamProxyOverTransport(allocator, tls, fd, requested_relay_bytes, uri, method, extra_headers.items, buffered_body, streaming_body, downstream_conn, downstream_writer, security, alt_svc, sticky_set_cookie, correlation_id, downstream_keep_alive, connect_timeout_ms, read_deadline_ms, cancel_token, &wrote_downstream, cfg.proxy_buffer_limits, proxy_buffer_observer, h1_buffer_capacity)
        else
            streamProxyOverTransport(allocator, compat.netStreamFromFd(fd), fd, requested_relay_bytes, uri, method, extra_headers.items, buffered_body, streaming_body, downstream_conn, downstream_writer, security, alt_svc, sticky_set_cookie, correlation_id, downstream_keep_alive, connect_timeout_ms, read_deadline_ms, cancel_token, &wrote_downstream, cfg.proxy_buffer_limits, proxy_buffer_observer, h1_buffer_capacity)) catch |err| {
            // Tear down the connection (release handles active-- and close).
            if (active_pool) |p| {
                p.release(key, conn, false, http.event_loop.monotonicMs());
            } else {
                if (conn.tls) |t| {
                    t.deinit();
                    allocator.destroy(t);
                }
                var s = conn.stream;
                s.close();
            }
            if (!wrote_downstream and reused and retry_allowed and attempt == 0 and
                (err == error.UpstreamConnectionClosed or err == error.WriteFailed))
            {
                if (active_pool) |p| p.recordStaleRetry(key);
                continue;
            }
            downstream_committed.* = wrote_downstream;
            return err;
        };

        // Success: pool the connection when reusable, else close it.
        if (active_pool) |p| {
            p.release(key, conn, res.reusable, http.event_loop.monotonicMs());
        } else {
            if (conn.tls) |t| {
                t.deinit();
                allocator.destroy(t);
            }
            var s = conn.stream;
            s.close();
        }
        if (pool) |p| p.recordRequestLatency(false, http.event_loop.monotonicMs() - exchange_start_ms);
        return res.result;
    }
}

pub fn upstreamResponseHasNoStore(response: std.http.Client.Response.Head) bool {
    var it = response.iterateHeaders();
    while (it.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "cache-control")) continue;
        var tokens = std.mem.splitScalar(u8, header.value, ',');
        while (tokens.next()) |token_raw| {
            const token = std.mem.trim(u8, token_raw, " \t\r\n");
            if (std.ascii.eqlIgnoreCase(token, "no-store")) return true;
        }
    }
    return false;
}

pub const UpstreamMappedError = struct {
    status: u16,
    code: []const u8,
    message: []const u8,
};

pub const ProxyExecMappedError = struct {
    status: http.Status,
    code: []const u8,
    message: []const u8,
};

pub fn mapUpstreamError(status: u16) UpstreamMappedError {
    return switch (status) {
        401 => .{ .status = 401, .code = "unauthorized", .message = "Unauthorized" },
        429 => .{ .status = 429, .code = "rate_limited", .message = "Rate limited" },
        502, 503 => .{ .status = 503, .code = "tool_unavailable", .message = "Upstream unavailable" },
        504 => .{ .status = 504, .code = "upstream_timeout", .message = "Upstream timeout" },
        else => .{ .status = 500, .code = "internal_error", .message = "Internal error" },
    };
}

/// Intentionally takes `anyerror`: proxy execution surfaces a heterogeneous set
/// (the specific upstream errors below, plus allocator and compat socket I/O
/// errors that are themselves `anyerror` until the I/O boundary is narrowed in
/// #211). The `else` arm maps everything unrecognized to a safe gateway-timeout.
pub fn mapControlPlaneProxyExecutionError(err: anyerror) ProxyExecMappedError {
    return switch (err) {
        error.UpstreamUntrusted => .{
            .status = .service_unavailable,
            .code = "upstream_untrusted",
            .message = "Untrusted upstream response",
        },
        error.Timeout => .{
            .status = .gateway_timeout,
            .code = "upstream_timeout",
            .message = "Upstream timeout",
        },
        error.UpstreamAtCapacity => .{
            .status = .service_unavailable,
            .code = "upstream_saturated",
            .message = "Upstream connection limit reached",
        },
        error.CircuitOpen => .{
            .status = .service_unavailable,
            .code = "upstream_circuit_open",
            .message = "Upstream circuit breaker open",
        },
        error.ControlPlaneResponseMaterializationFailed => .{
            .status = .bad_gateway,
            .code = "upstream_response_error",
            .message = "Upstream response could not be delivered",
        },
        else => .{
            .status = .gateway_timeout,
            .code = "upstream_timeout",
            .message = "Upstream timeout",
        },
    };
}

test "mapUpstreamError returns stable codes" {
    const mapped = mapUpstreamError(502);
    try std.testing.expectEqual(@as(u16, 503), mapped.status);
    try std.testing.expectEqualStrings("tool_unavailable", mapped.code);
}

test "mapControlPlaneProxyExecutionError maps open circuit distinctly" {
    const mapped = mapControlPlaneProxyExecutionError(error.CircuitOpen);
    try std.testing.expectEqual(http.Status.service_unavailable, mapped.status);
    try std.testing.expectEqualStrings("upstream_circuit_open", mapped.code);
}

// --- Malformed upstream response handling tests ---

test "parseBufferedUpstreamResponse handles response with no body" {
    // The parser requires at least one header line so that headers_raw contains
    // a newline (from which the status-line boundary is found).
    var parsed = try parseBufferedUpstreamResponse(
        std.testing.allocator,
        "HTTP/1.1 204 No Content\r\nX-Accel-Buffering: no\r\n\r\n",
    );
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 204), parsed.status_code);
    try std.testing.expectEqualStrings("No Content", parsed.reason);
    try std.testing.expectEqualStrings("", parsed.body);
    try std.testing.expectEqualStrings("no", parsed.headerValue("X-Accel-Buffering").?);
}

test "parseBufferedUpstreamResponse discards an illegal body on 204/304/1xx regardless of upstream Content-Length (#673 review)" {
    // RFC 7230 §3.3 / RFC 7231 §6.3.5, §6.5.5: 1xx, 204, and 304 responses
    // are bodiless by definition, regardless of any Content-Length the
    // upstream sends. A downstream client honors that rule and treats any
    // trailing bytes as the START OF THE NEXT RESPONSE on the connection --
    // so a hostile/misbehaving upstream sending `204 No Content` with
    // `Content-Length: 5\r\n\r\nnope!` must not have "nope!" forwarded to
    // the client as this response's body; that is a response-splitting
    // vector, not just an RFC nicety.
    const testing = std.testing;

    var parsed_204 = try parseBufferedUpstreamResponse(
        testing.allocator,
        "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\nnope!",
    );
    defer parsed_204.deinit(testing.allocator);
    try testing.expectEqualStrings("", parsed_204.body);

    var parsed_304 = try parseBufferedUpstreamResponse(
        testing.allocator,
        "HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\nnope!",
    );
    defer parsed_304.deinit(testing.allocator);
    try testing.expectEqualStrings("", parsed_304.body);

    var parsed_1xx = try parseBufferedUpstreamResponse(
        testing.allocator,
        "HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\nnope!",
    );
    defer parsed_1xx.deinit(testing.allocator);
    try testing.expectEqualStrings("", parsed_1xx.body);

    // A normal 200 with a body is unaffected.
    var parsed_200 = try parseBufferedUpstreamResponse(
        testing.allocator,
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    );
    defer parsed_200.deinit(testing.allocator);
    try testing.expectEqualStrings("ok", parsed_200.body);
}

test "parseBufferedUpstreamResponse strips hop-by-hop headers from upstream 5xx responses" {
    var parsed = try parseBufferedUpstreamResponse(
        std.testing.allocator,
        "HTTP/1.1 502 Bad Gateway\r\n" ++
            "Connection: close\r\n" ++
            "Transfer-Encoding: chunked\r\n" ++
            "Server: nginx/1.24.0\r\n" ++
            "X-Powered-By: PHP/8.1\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "\r\n" ++
            "error",
    );
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 502), parsed.status_code);
    try std.testing.expect(parsed.headerValue("connection") == null);
    try std.testing.expect(parsed.headerValue("transfer-encoding") == null);
    try std.testing.expect(parsed.headerValue("server") == null);
    try std.testing.expect(parsed.headerValue("x-powered-by") == null);
    try std.testing.expectEqualStrings("text/plain", parsed.headerValue("content-type").?);
}

test "parseBufferedUpstreamResponse strips Content-Length from upstream (Tardigrade recalculates)" {
    var parsed = try parseBufferedUpstreamResponse(
        std.testing.allocator,
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Length: 5\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "\r\n" ++
            "hello",
    );
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expect(parsed.headerValue("content-length") == null);
    try std.testing.expectEqualStrings("text/plain", parsed.headerValue("content-type").?);
    try std.testing.expectEqualStrings("hello", parsed.body);
}

test "parseBufferedUpstreamResponse handles upstream with missing reason phrase" {
    var parsed = try parseBufferedUpstreamResponse(
        std.testing.allocator,
        "HTTP/1.1 200 \r\nContent-Type: text/plain\r\n\r\nbody",
    );
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 200), parsed.status_code);
    try std.testing.expectEqualStrings("body", parsed.body);
}

test "parseBufferedUpstreamResponse errors on empty response" {
    try std.testing.expectError(
        error.UpstreamProtocolError,
        parseBufferedUpstreamResponse(std.testing.allocator, ""),
    );
}

test "parseBufferedUpstreamResponse errors on truncated status line" {
    try std.testing.expectError(
        error.UpstreamProtocolError,
        parseBufferedUpstreamResponse(std.testing.allocator, "HTTP/1.1 200"),
    );
}

test "parseBufferedUpstreamResponse errors when header block is never terminated" {
    try std.testing.expectError(
        error.UpstreamProtocolError,
        parseBufferedUpstreamResponse(
            std.testing.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n",
        ),
    );
}

// ---------------------------------------------------------------------------
// Bounded transport exchange + timeout enforcement (issue #196)
// ---------------------------------------------------------------------------
//
// These tests drive exchangeBoundedBufferedHttpRequest over a blocking
// socketpair: deterministic, no event loop, no threads. They cover the two
// behaviors the std.http.Client path could not provide: a correct buffered
// request/response exchange, and a bounded response read that returns an error
// (rather than blocking forever) when the peer never replies.

fn makeBlockingSocketpair() ![2]std.posix.fd_t {
    var fds: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) {
        return error.SocketPairFailed;
    }
    return fds;
}

test "exchangeBoundedBufferedHttpRequest parses a buffered response from a peer" {
    const allocator = std.testing.allocator;
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    // Pre-load the peer's response, then shut its write side so the client read
    // loop sees EOF once the response is drained.
    const response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nhello";
    _ = std.c.write(peer_fd, response.ptr, response.len);
    _ = std.c.shutdown(peer_fd, std.posix.SHUT.WR);

    const uri = try std.Uri.parse("http://localhost/");
    var resp = try exchangeBoundedBufferedHttpRequest(
        allocator,
        compat.netStreamFromFd(client_fd),
        client_fd,
        uri,
        "GET",
        &.{},
        "",
        null,
        1 << 20,
        1_000,
        1_000,
        false,
        null,
    );
    defer resp.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status_code);
    try std.testing.expectEqualStrings("hello", resp.body);
    try std.testing.expectEqualStrings("text/plain", resp.headerValue("content-type").?);

    // The serialized request is readable from the peer end, Connection: close
    // and a derived Host header included.
    var req_buf: [512]u8 = undefined;
    const n = std.c.read(peer_fd, &req_buf, req_buf.len);
    try std.testing.expect(n > 0);
    const req = req_buf[0..@intCast(n)];
    try std.testing.expect(std.mem.startsWith(u8, req, "GET / HTTP/1.1\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, req, "Connection: close\r\n") != null);
}

/// Run one buffered exchange against a socketpair peer and return the request
/// bytes the client serialized (caller owns the returned slice).
fn captureBufferedRequestBytes(allocator: std.mem.Allocator, url: []const u8) ![]u8 {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    const response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    _ = std.c.write(peer_fd, response.ptr, response.len);
    _ = std.c.shutdown(peer_fd, std.posix.SHUT.WR);

    const uri = try std.Uri.parse(url);
    var resp = try exchangeBoundedBufferedHttpRequest(
        allocator,
        compat.netStreamFromFd(client_fd),
        client_fd,
        uri,
        "GET",
        &.{},
        "",
        null,
        1 << 20,
        1_000,
        1_000,
        false,
        null,
    );
    resp.deinit(allocator);

    var req_buf: [512]u8 = undefined;
    const n = std.c.read(peer_fd, &req_buf, req_buf.len);
    try std.testing.expect(n > 0);
    return allocator.dupe(u8, req_buf[0..@intCast(n)]);
}

test "buffered request Host header includes a non-default upstream port" {
    const allocator = std.testing.allocator;
    const req = try captureBufferedRequestBytes(allocator, "http://127.0.0.1:8123/");
    defer allocator.free(req);
    try std.testing.expect(std.mem.indexOf(u8, req, "Host: 127.0.0.1:8123\r\n") != null);
}

test "buffered request Host header omits a default upstream port" {
    const allocator = std.testing.allocator;
    // Explicit default port (80) must not be echoed into the Host header.
    const req = try captureBufferedRequestBytes(allocator, "http://127.0.0.1:80/");
    defer allocator.free(req);
    try std.testing.expect(std.mem.indexOf(u8, req, "Host: 127.0.0.1\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, req, "127.0.0.1:80") == null);
}

test "exchangeBoundedBufferedHttpRequest enforces the response read timeout when the peer never replies" {
    const allocator = std.testing.allocator;
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    // The peer accepts the request bytes but never writes a response and never
    // closes. Without per-phase timeouts the client read would block forever;
    // the 200ms response timeout must surface an error instead.
    const uri = try std.Uri.parse("http://localhost/");
    const start_ms = http.event_loop.monotonicMs();
    const result = exchangeBoundedBufferedHttpRequest(
        allocator,
        compat.netStreamFromFd(client_fd),
        client_fd,
        uri,
        "GET",
        &.{},
        "",
        null,
        1 << 20,
        1_000, // send timeout: generous
        200, // response timeout: short — this must fire on the silent peer
        false,
        null,
    );
    const elapsed_ms = http.event_loop.monotonicMs() - start_ms;

    if (result) |resp_val| {
        var resp = resp_val;
        resp.deinit(allocator);
        return error.TestUnexpectedResult; // a silent peer must not yield a response
    } else |_| {}

    // Returned via the 200ms poll deadline, with generous slack for scheduler
    // noise on busy CI hosts.
    try std.testing.expect(elapsed_ms >= 150);
    try std.testing.expect(elapsed_ms < 5_000);
}

/// Run an exchange against a peer that has pre-written `response` and then keeps
/// the socket open (never closes) — simulating a keep-alive HTTP/1.1 upstream
/// that frames its body with Content-Length/chunked. With a generous response
/// timeout, a framing-unaware reader would block until the deadline; a correct
/// one returns as soon as the framed body is complete.
fn exchangeAgainstKeepAlivePeer(allocator: std.mem.Allocator, method: []const u8, response: []const u8) !BufferedUpstreamResponse {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    _ = std.c.write(peer_fd, response.ptr, response.len);
    // Deliberately do NOT close peer_fd — the body boundary must come from
    // framing, not EOF.
    const uri = try std.Uri.parse("http://localhost/");
    return exchangeBoundedBufferedHttpRequest(
        allocator,
        compat.netStreamFromFd(client_fd),
        client_fd,
        uri,
        method,
        &.{},
        "",
        null,
        1 << 20,
        1_000,
        1_000,
        false,
        null,
    );
}

test "exchange stops at Content-Length on a keep-alive upstream (issue #196 regression)" {
    const allocator = std.testing.allocator;
    var resp = try exchangeAgainstKeepAlivePeer(
        allocator,
        "GET",
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello",
    );
    defer resp.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), resp.status_code);
    try std.testing.expectEqualStrings("hello", resp.body);
}

test "exchange decodes a chunked body on a keep-alive upstream" {
    const allocator = std.testing.allocator;
    var resp = try exchangeAgainstKeepAlivePeer(
        allocator,
        "GET",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
    );
    defer resp.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), resp.status_code);
    try std.testing.expectEqualStrings("hello world", resp.body);
}

test "exchange treats 204 as bodiless on a keep-alive upstream" {
    const allocator = std.testing.allocator;
    var resp = try exchangeAgainstKeepAlivePeer(
        allocator,
        "GET",
        "HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n",
    );
    defer resp.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), resp.status_code);
    try std.testing.expectEqual(@as(usize, 0), resp.body.len);
}

test "exchange treats a HEAD response as bodiless despite Content-Length" {
    const allocator = std.testing.allocator;
    var resp = try exchangeAgainstKeepAlivePeer(
        allocator,
        "HEAD",
        "HTTP/1.1 200 OK\r\nContent-Length: 99\r\nConnection: keep-alive\r\n\r\n",
    );
    defer resp.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), resp.status_code);
    try std.testing.expectEqual(@as(usize, 0), resp.body.len);
}

test "exchange consumes a 1xx interim chain and returns the actual final response (#673 review)" {
    // Before this fix, the FIRST 1xx response was wrongly treated as a
    // complete exchange: the caller would receive a bare 103 with no body
    // and the real 200 (plus its body) would be silently discarded.
    const allocator = std.testing.allocator;
    var resp = try exchangeAgainstKeepAlivePeer(
        allocator,
        "GET",
        "HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n" ++
            "HTTP/1.1 103 Early Hints\r\nLink: </style2.css>\r\n\r\n" ++
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
    );
    defer resp.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), resp.status_code);
    try std.testing.expectEqualStrings("ok", resp.body);
}

test "exchange never marks a keep-alive connection reusable after a bodiless response, even with nothing trailing yet (#673 review)" {
    // A prior version of this fix marked the connection reusable whenever
    // `resp_body.len == 0` *at the instant the header block was parsed*.
    // That cannot prove a malicious/misbehaving upstream won't send an
    // illegal body or a full ghost response moments later, after
    // Tardigrade has already returned the socket to the idle pool -- those
    // delayed bytes would then poison whatever unrelated request checks
    // the connection out next. Bodiless responses must never be pooled.
    const allocator = std.testing.allocator;
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    const response = "HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n";
    _ = std.c.write(peer_fd, response.ptr, response.len);

    const uri = try std.Uri.parse("http://localhost/");
    var reusable: bool = true;
    var resp = try exchangeBoundedBufferedHttpRequest(
        allocator,
        compat.netStreamFromFd(client_fd),
        client_fd,
        uri,
        "GET",
        &.{},
        "",
        null,
        1 << 20,
        1_000,
        1_000,
        true,
        &reusable,
    );
    defer resp.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), resp.status_code);
    try std.testing.expect(!reusable);
}

test "exchange rejects a Transfer-Encoding value that is not exactly \"chunked\" (#673 review)" {
    // RFC 7230 §3.3.1 permits a *list* of transfer-codings, but Tardigrade
    // only understands "chunked" -- accepting anything else as if it were
    // plain chunked framing would mean decoding a body whose actual wire
    // encoding is unknown, corrupting or misframing it entirely.
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.UpstreamProtocolError, exchangeAgainstKeepAlivePeer(
        allocator,
        "GET",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\nConnection: keep-alive\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    ));
}

test "exchange rejects a duplicate Transfer-Encoding header (#673 review)" {
    // HTTP defines no combination semantics for a singleton framing header
    // like Transfer-Encoding; a second occurrence must be rejected outright
    // rather than the exchange loop picking whichever one it saw first or
    // last (#673 review, same rationale as duplicate Content-Length).
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.UpstreamProtocolError, exchangeAgainstKeepAlivePeer(
        allocator,
        "GET",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    ));
}

test "exchange rejects Transfer-Encoding and Content-Length sent together (#673 review)" {
    // A response carrying both is the classic request/response-smuggling
    // ambiguity (RFC 7230 §3.3.3 p.3): whichever header the two ends of a
    // proxy chain each trust to determine framing can disagree about where
    // the body ends. Reject rather than pick a winner.
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.UpstreamProtocolError, exchangeAgainstKeepAlivePeer(
        allocator,
        "GET",
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    ));
}

test "exchange rejects a 101 Switching Protocols upstream response (#673 review)" {
    // 101 is terminal and hands the connection off to a different protocol
    // entirely (RFC 7230 §6.7) -- it must never be treated as just another
    // skippable 1xx interim response on the way to a "real" final response,
    // nor forwarded as if it were an ordinary bodiless response, since
    // Tardigrade has no support for relaying whatever comes after it.
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.UpstreamProtocolError, exchangeAgainstKeepAlivePeer(
        allocator,
        "GET",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
    ));
}

test "exchange refuses reuse when bytes trail a chunked body's terminator (#673 review)" {
    // Mirrors "streaming relay refuses reuse when bytes trail a chunked
    // body": decodeChunkedBody must report how much of the read buffer it
    // actually consumed so the buffered exchange loop can tell a complete
    // chunked body + trailer apart from one followed by a ghost/smuggled
    // response that happened to arrive in the same read (#673 review) --
    // before this fix the buffered path unconditionally marked the
    // connection reusable the moment decoding succeeded, regardless of
    // what (if anything) came after the terminator.
    const allocator = std.testing.allocator;
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    const response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5\r\nhello\r\n0\r\n\r\nEXTRA";
    _ = std.c.write(peer_fd, response.ptr, response.len);

    const uri = try std.Uri.parse("http://localhost/");
    var reusable: bool = true;
    var resp = try exchangeBoundedBufferedHttpRequest(
        allocator,
        compat.netStreamFromFd(client_fd),
        client_fd,
        uri,
        "GET",
        &.{},
        "",
        null,
        1 << 20,
        1_000,
        1_000,
        true,
        &reusable,
    );
    defer resp.deinit(allocator);
    try std.testing.expectEqualStrings("hello", resp.body);
    try std.testing.expect(!reusable);
}

test "exchange rejects an upstream chunked body whose trailer line has no colon (#673 review)" {
    // Same rationale as the request-side fix: RFC 7230 §4.1.2's trailer
    // part is `*( header-field CRLF )`, not arbitrary text -- a hostile
    // upstream could otherwise hide unstructured bytes (potentially the
    // start of a smuggled ghost response) behind what looks like "just a
    // trailer".
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.UpstreamProtocolError, exchangeAgainstKeepAlivePeer(
        allocator,
        "GET",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5\r\nhello\r\n0\r\nBad Trailer No Colon\r\n\r\n",
    ));
}

test "exchange rejects an upstream chunked trailer that has a colon but is not a valid header field (#673 review round 8)" {
    // A colon-only check (the round-7 version of this validation) would
    // have accepted all of these: a colon is present, but the name or
    // value is malformed.
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.UpstreamProtocolError, exchangeAgainstKeepAlivePeer(
        allocator,
        "GET",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5\r\nhello\r\n0\r\nBad Name: x\r\n\r\n",
    ));
    try std.testing.expectError(error.UpstreamProtocolError, exchangeAgainstKeepAlivePeer(
        allocator,
        "GET",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5\r\nhello\r\n0\r\nX-Good: bad\x00value\r\n\r\n",
    ));
}

test "exchange rejects a chunk whose data is not terminated by CRLF (#673 review)" {
    // Mirrors "streaming relay rejects a chunk not terminated by CRLF":
    // the two bytes immediately after a chunk's data must be a literal
    // CRLF, not just any two bytes the decoder can skip past -- otherwise a
    // malformed chunk terminator silently resyncs onto attacker-chosen
    // bytes instead of being rejected (#673 review).
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.UpstreamProtocolError, exchangeAgainstKeepAlivePeer(
        allocator,
        "GET",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n5\r\nhelloXX0\r\n\r\n",
    ));
}

test "exchange rejects an upstream status code below 100 (#673 review)" {
    // RFC 9110 §15 defines valid status codes as 100..599; three decimal
    // digits alone also admits 000..099. Unchecked, the buffered path
    // reformats `status_code` straight back out to the client with `{d}`,
    // so an unrejected "099" would become an invalid "HTTP/1.1 99 ..."
    // downstream response line.
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.UpstreamProtocolError, exchangeAgainstKeepAlivePeer(
        allocator,
        "GET",
        "HTTP/1.1 099 Weird\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
    ));
}

test "exchange rejects an upstream status code above 599 (#673 review)" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.UpstreamProtocolError, exchangeAgainstKeepAlivePeer(
        allocator,
        "GET",
        "HTTP/1.1 600 Weird\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
    ));
    try std.testing.expectError(error.UpstreamProtocolError, exchangeAgainstKeepAlivePeer(
        allocator,
        "GET",
        "HTTP/1.1 999 Weird\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
    ));
}

test "readUpstreamHead rejects an upstream status code outside 100..599 (#673 review)" {
    // Same rationale as the buffered-path equivalents, on the streaming
    // path's shared call into parseStrictStatusLine().
    const allocator = std.testing.allocator;
    for ([_][]const u8{
        "HTTP/1.1 099 Weird\r\nContent-Length: 2\r\n\r\nok",
        "HTTP/1.1 600 Weird\r\nContent-Length: 2\r\n\r\nok",
    }) |response| {
        const fds = try makeBlockingSocketpair();
        const client_fd = fds[0];
        const peer_fd = fds[1];
        defer _ = std.c.close(client_fd);
        defer _ = std.c.close(peer_fd);
        _ = std.c.write(peer_fd, response.ptr, response.len);

        var read_storage: [4096]u8 = undefined;
        var rb = StreamReadBuf{ .buf = &read_storage };
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const transport = compat.netStreamFromFd(client_fd);

        try std.testing.expectError(
            error.UpstreamProtocolError,
            readUpstreamHead(arena.allocator(), &rb, transport, client_fd, 1_000, "GET"),
        );
    }
}

/// A capturing downstream writer for the streaming-relay tests: satisfies the
/// `print`/`writeAll` interface `writeChunk` needs and records all bytes.
const CaptureWriter = struct {
    list: *std.array_list.Managed(u8),
    pub fn writeAll(self: CaptureWriter, bytes: []const u8) !void {
        try self.list.appendSlice(bytes);
    }
    pub fn print(self: CaptureWriter, comptime fmt: []const u8, args: anytype) !void {
        var buf: [64]u8 = undefined;
        try self.list.appendSlice(try std.fmt.bufPrint(&buf, fmt, args));
    }
};

/// Drive readUpstreamHead + relayUpstreamBody over a socketpair preloaded with
/// `response`. Returns the parsed head and the de-chunked relayed body. The peer
/// stays open (length/chunked) unless `close_after` shuts it for close-framing.
fn runStreamingRelay(
    allocator: std.mem.Allocator,
    method: []const u8,
    response: []const u8,
    close_after: bool,
    out_body: *std.array_list.Managed(u8),
) !struct { status: u16, framing_tag: []const u8, reusable: bool, aborted: bool, body_len: usize } {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);
    _ = std.c.write(peer_fd, response.ptr, response.len);
    if (close_after) _ = std.c.shutdown(peer_fd, std.posix.SHUT.WR);

    var read_storage: [4096]u8 = undefined;
    var rb = StreamReadBuf{ .buf = &read_storage };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const transport = compat.netStreamFromFd(client_fd);

    const head = try readUpstreamHead(arena.allocator(), &rb, transport, client_fd, 1_000, method);

    var captured = std.array_list.Managed(u8).init(allocator);
    defer captured.deinit();
    const writer = CaptureWriter{ .list = &captured };
    var downstream_write = gpres.StreamingResponseWriteState.init("");
    try gpres.drainStreamingWriteBlocking(&downstream_write, writer);
    const outcome = try relayUpstreamBody(&rb, transport, client_fd, 1_000, head.framing, &downstream_write, writer, null);

    // De-chunk the captured downstream stream (relay does not emit the
    // terminating zero chunk; append it so decodeChunkedBody can parse).
    try captured.appendSlice("0\r\n\r\n");
    if (try decodeChunkedBody(allocator, captured.items, 1 << 20)) |decoded| {
        defer allocator.free(decoded.body);
        try out_body.appendSlice(decoded.body);
    }
    const tag = switch (head.framing) {
        .none => "none",
        .length => "length",
        .chunked => "chunked",
        .close => "close",
    };
    return .{ .status = head.status_code, .framing_tag = tag, .reusable = outcome.reusable, .aborted = outcome.aborted, .body_len = outcome.body_bytes };
}

test "streaming relay streams a Content-Length body and keeps the connection reusable" {
    const allocator = std.testing.allocator;
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    const r = try runStreamingRelay(allocator, "GET", "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world", false, &body);
    try std.testing.expectEqual(@as(u16, 200), r.status);
    try std.testing.expectEqualStrings("length", r.framing_tag);
    try std.testing.expectEqualStrings("hello world", body.items);
    try std.testing.expect(r.reusable and !r.aborted);
}

test "streaming relay decodes a chunked body and stays reusable" {
    const allocator = std.testing.allocator;
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    const r = try runStreamingRelay(allocator, "GET", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n", false, &body);
    try std.testing.expectEqualStrings("chunked", r.framing_tag);
    try std.testing.expectEqualStrings("hello world", body.items);
    try std.testing.expect(r.reusable and !r.aborted);
}

test "streaming relay handles a close-delimited body (not reusable)" {
    const allocator = std.testing.allocator;
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    const r = try runStreamingRelay(allocator, "GET", "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nstreamed-to-eof", true, &body);
    try std.testing.expectEqualStrings("close", r.framing_tag);
    try std.testing.expectEqualStrings("streamed-to-eof", body.items);
    try std.testing.expect(!r.reusable and !r.aborted);
}

test "streaming relay treats 204 as bodiless and never reuses the connection (#673 review)" {
    // A bodiless response is never pooled for reuse, even when nothing has
    // trailed the headers at parse time: a malicious/misbehaving upstream
    // could still send an illegal body or a ghost response later, after
    // Tardigrade has already returned the socket to the idle pool, and
    // those bytes would poison whatever unrelated request checks the
    // connection out next.
    const allocator = std.testing.allocator;
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    const r = try runStreamingRelay(allocator, "GET", "HTTP/1.1 204 No Content\r\n\r\n", false, &body);
    try std.testing.expectEqual(@as(u16, 204), r.status);
    try std.testing.expectEqualStrings("none", r.framing_tag);
    try std.testing.expectEqual(@as(usize, 0), body.items.len);
    try std.testing.expect(!r.reusable);
}

test "streaming relay reports abort on a truncated Content-Length body" {
    const allocator = std.testing.allocator;
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    // Promises 20 bytes but only sends 5, then closes.
    const r = try runStreamingRelay(allocator, "GET", "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nhello", true, &body);
    try std.testing.expect(r.aborted and !r.reusable);
    try std.testing.expectEqual(@as(usize, 5), r.body_len);
}

test "streaming relay refuses reuse when bytes trail a Content-Length body" {
    const allocator = std.testing.allocator;
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    // 5-byte body, but "EXTRA" remains buffered past the body boundary.
    const r = try runStreamingRelay(allocator, "GET", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA", false, &body);
    try std.testing.expectEqualStrings("hello", body.items);
    try std.testing.expect(!r.aborted);
    try std.testing.expect(!r.reusable); // socket out of sync — must not be pooled
}

test "readUpstreamHead rejects control characters embedded in a header value (#673)" {
    // Same defect as the buffered path (see the parseBufferedUpstreamResponse
    // test of the same name): a header line is only split on an exact
    // "\r\n" boundary, so a bare CR or NUL embedded inside what should be a
    // single value survives unless explicitly validated, letting a hostile
    // upstream ride control characters through to the client over the
    // streaming relay path too.
    const allocator = std.testing.allocator;
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);
    const response = "HTTP/1.1 200 OK\r\nX-Hostile: val\rue\r\nContent-Length: 2\r\n\r\nok";
    _ = std.c.write(peer_fd, response.ptr, response.len);

    var read_storage: [4096]u8 = undefined;
    var rb = StreamReadBuf{ .buf = &read_storage };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const transport = compat.netStreamFromFd(client_fd);

    try std.testing.expectError(
        error.UpstreamProtocolError,
        readUpstreamHead(arena.allocator(), &rb, transport, client_fd, 1_000, "GET"),
    );
}

test "readUpstreamHead rejects a 101 Switching Protocols upstream response (#673 review)" {
    // Same rationale as the buffered-path equivalent: 101 hands the
    // connection off to a different protocol entirely and must never be
    // treated as a skippable 1xx interim response or relayed as an
    // ordinary bodiless one.
    const allocator = std.testing.allocator;
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);
    const response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    _ = std.c.write(peer_fd, response.ptr, response.len);

    var read_storage: [4096]u8 = undefined;
    var rb = StreamReadBuf{ .buf = &read_storage };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const transport = compat.netStreamFromFd(client_fd);

    try std.testing.expectError(
        error.UpstreamProtocolError,
        readUpstreamHead(arena.allocator(), &rb, transport, client_fd, 1_000, "GET"),
    );
}

test "streaming relay refuses reuse when bytes trail a 204 head" {
    const allocator = std.testing.allocator;
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    const r = try runStreamingRelay(allocator, "GET", "HTTP/1.1 204 No Content\r\n\r\nEXTRA", false, &body);
    try std.testing.expectEqual(@as(u16, 204), r.status);
    try std.testing.expectEqual(@as(usize, 0), body.items.len);
    try std.testing.expect(!r.reusable);
}

test "streaming relay refuses reuse when bytes trail a chunked body" {
    const allocator = std.testing.allocator;
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    // Complete chunked body + trailer, then a stray "EXTRA" past the terminator.
    const r = try runStreamingRelay(allocator, "GET", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\nEXTRA", false, &body);
    try std.testing.expectEqualStrings("hello", body.items);
    try std.testing.expect(!r.aborted);
    try std.testing.expect(!r.reusable);
}

test "streaming relay rejects a chunk not terminated by CRLF" {
    const allocator = std.testing.allocator;
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    // Chunk data "hello" is followed by "XX" instead of CRLF.
    try std.testing.expectError(error.UpstreamProtocolError, runStreamingRelay(
        allocator,
        "GET",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX0\r\n\r\n",
        false,
        &body,
    ));
}

test "streaming relay rejects a chunk trailer that is not a valid header field (#673 review round 8)" {
    // consumeChunkTrailers() (the streaming response-relay's trailer
    // consumer) used to accept any CRLF-delimited line here with no
    // validation at all -- not even a colon check -- unlike the buffered
    // decoder's equivalent.
    const allocator = std.testing.allocator;
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    try std.testing.expectError(error.UpstreamProtocolError, runStreamingRelay(
        allocator,
        "GET",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nBad Trailer No Colon\r\n\r\n",
        false,
        &body,
    ));
    try std.testing.expectError(error.UpstreamProtocolError, runStreamingRelay(
        allocator,
        "GET",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nBad Name: x\r\n\r\n",
        false,
        &body,
    ));
}

// ---------------------------------------------------------------------------
// Request-direction buffer accounting and HTTP/1 stall observability (#140).
// ---------------------------------------------------------------------------

/// Records everything the request-direction relays report, so a test can assert
/// both the transitions and that every gauge returns to zero at teardown.
const UploadBufferObserver = struct {
    reserved: usize = 0,
    peak_reserved: usize = 0,
    retained: usize = 0,
    pauses: u64 = 0,
    resumes: u64 = 0,
    stream_limit_exceeded: u64 = 0,
    aggregate_limit_exceeded: u64 = 0,
    last_aggregate_scope: ?proxy_buffer_account.Scope = null,

    fn observer(self: *UploadBufferObserver) proxy_buffer_account.Observer {
        return .{
            .context = self,
            .recordReservationFn = recordReservation,
            .releaseReservationFn = releaseReservation,
            .recordAggregateLimitExceededFn = recordAggregateLimitExceeded,
            .recordReadPauseFn = recordReadPause,
            .recordReadResumeFn = recordReadResume,
            .recordRetainedBytesFn = recordRetained,
            .releaseRetainedBytesFn = releaseRetained,
        };
    }

    fn recordReservation(
        context: *anyopaque,
        _: proxy_buffer_account.Direction,
        bytes: usize,
        _: bool,
        limit_exceeded: bool,
    ) void {
        const self: *UploadBufferObserver = @ptrCast(@alignCast(context));
        if (limit_exceeded) self.stream_limit_exceeded += 1;
        self.reserved += bytes;
        self.peak_reserved = @max(self.peak_reserved, self.reserved);
    }

    fn releaseReservation(context: *anyopaque, _: proxy_buffer_account.Direction, bytes: usize) void {
        const self: *UploadBufferObserver = @ptrCast(@alignCast(context));
        self.reserved -= bytes;
    }

    fn recordAggregateLimitExceeded(
        context: *anyopaque,
        _: proxy_buffer_account.Direction,
        scope: proxy_buffer_account.Scope,
    ) void {
        const self: *UploadBufferObserver = @ptrCast(@alignCast(context));
        self.aggregate_limit_exceeded += 1;
        self.last_aggregate_scope = scope;
    }

    fn recordReadPause(context: *anyopaque, _: proxy_buffer_account.Side) void {
        const self: *UploadBufferObserver = @ptrCast(@alignCast(context));
        self.pauses += 1;
    }

    fn recordReadResume(context: *anyopaque, _: proxy_buffer_account.Side) void {
        const self: *UploadBufferObserver = @ptrCast(@alignCast(context));
        self.resumes += 1;
    }

    fn recordRetained(context: *anyopaque, _: proxy_buffer_account.Direction, bytes: usize) void {
        const self: *UploadBufferObserver = @ptrCast(@alignCast(context));
        self.retained += bytes;
    }

    fn releaseRetained(context: *anyopaque, _: proxy_buffer_account.Direction, bytes: usize) void {
        const self: *UploadBufferObserver = @ptrCast(@alignCast(context));
        self.retained -= bytes;
    }
};

/// A client upload served from memory. `abort_after` makes the read fail once
/// that many bytes have been handed over, standing in for a client that
/// disappears mid-upload.
const FakeUploadSource = struct {
    data: []const u8,
    pos: usize = 0,
    abort_after: ?usize = null,

    pub fn read(self: *FakeUploadSource, buf: []u8) !usize {
        if (self.abort_after) |limit| {
            if (self.pos >= limit) return error.ConnectionResetByPeer;
        }
        const take = @min(buf.len, self.data.len - self.pos);
        @memcpy(buf[0..take], self.data[self.pos..][0..take]);
        self.pos += take;
        return take;
    }
};

fn uploadTestLimits(hard: usize) proxy_buffer_account.Limits {
    return .{
        .per_stream_low_watermark = hard / 4,
        .per_stream_high_watermark = hard / 2,
        .per_stream_hard_limit = hard,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    };
}

/// Preflight then relay, in the order `sendStreamingProxyRequest` does, so
/// tests exercise the same reservation lifetime production uses.
fn runHttp1Upload(
    transport: anytype,
    fd: std.posix.fd_t,
    sb: StreamingRequestBody,
    downstream_conn: anytype,
    limits: proxy_buffer_account.Limits,
    observer: proxy_buffer_account.Observer,
    capacity: proxy_buffer_account.AggregateCapacity,
) !void {
    var reservation = try preflightUploadReservation(
        limits,
        observer,
        capacity,
        http1_upload_relay_bytes,
        uploadInitialBytesFootprint(sb),
    );
    defer reservation.releaseAll();
    try relayStreamingUploadToHttp1(transport, fd, sb, downstream_conn, null, &reservation, observer);
}

/// The HTTP/2 mirror of `runHttp1Upload`.
fn runHttp2Upload(
    conn: anytype,
    stream: anytype,
    sb: StreamingRequestBody,
    read_buf: []u8,
    downstream_conn: anytype,
    limits: proxy_buffer_account.Limits,
    observer: proxy_buffer_account.Observer,
    capacity: proxy_buffer_account.AggregateCapacity,
) !void {
    var reservation = try preflightUploadReservation(
        limits,
        observer,
        capacity,
        read_buf.len,
        uploadInitialBytesFootprint(sb),
    );
    defer reservation.releaseAll();
    try relayStreamingUploadToHttp2(conn, stream, sb, read_buf, downstream_conn, null, &reservation);
}

/// Drain `total` bytes from `fd` after `delay_ms`. The delay is what lets the
/// relay observe an origin that has stopped consuming.
fn slowUploadDrain(fd: std.posix.fd_t, delay_ms: u64, total: usize) void {
    // A bare `poll` with no descriptors, not `std.Io.sleep`: this runs on a raw
    // spawned thread with no Io context, and a sleep that silently no-ops would
    // let the drain keep pace with the relay so the stall under test would
    // never happen.
    var no_fds: [0]std.posix.pollfd = .{};
    _ = std.posix.poll(&no_fds, @intCast(delay_ms)) catch {};
    var buf: [4096]u8 = undefined;
    var drained: usize = 0;
    while (drained < total) {
        const n = std.c.read(fd, &buf, buf.len);
        if (n <= 0) return;
        drained += @intCast(n);
    }
}

/// Write into `fd` until it will not take another byte, and report how much
/// went in. Non-blocking for the duration, so a partially free send buffer
/// cannot park the caller with nobody draining. This is what makes a stall a
/// fact of the socket's state at the moment the relay looks at it, rather than
/// a race against a background reader.
fn fillSocketSendBuffer(fd: std.posix.fd_t) !usize {
    const flags = std.c.fcntl(fd, std.posix.F.GETFL, @as(c_int, 0));
    if (flags < 0) return error.SocketFillFailed;
    const nonblock: c_int = @bitCast(@as(u32, @bitCast(std.posix.O{ .NONBLOCK = true })));
    if (std.c.fcntl(fd, std.posix.F.SETFL, flags | nonblock) < 0) return error.SocketFillFailed;
    defer _ = std.c.fcntl(fd, std.posix.F.SETFL, flags);

    const chunk = [_]u8{'p'} ** 1024;
    var written: usize = 0;
    // Bounded: a platform that never reports a full buffer must fail the test,
    // not spin here forever.
    while (written < 8 * 1024 * 1024) {
        const n = std.c.write(fd, &chunk, chunk.len);
        if (n <= 0) return written;
        written += @intCast(n);
    }
    return error.SocketFillFailed;
}

test "http1 upload relay reports a slow origin as a downstream read pause" {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    // Shrink both ends so the origin's window fills well before the upload is
    // done, whatever the platform default happens to be.
    const small: c_int = 4096;
    std.posix.setsockopt(client_fd, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&small)) catch {};
    std.posix.setsockopt(peer_fd, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&small)) catch {};

    const payload = try std.testing.allocator.alloc(u8, 64 * 1024);
    defer std.testing.allocator.free(payload);
    @memset(payload, 'u');

    // Leave the origin's window already full, so the relay's first look at the
    // socket is guaranteed to find a stall rather than racing the drainer for
    // one. The probe must agree, or the check below is not testing anything.
    const prefilled = try fillSocketSendBuffer(client_fd);
    try std.testing.expect(prefilled > 0);
    try std.testing.expectEqual(UpstreamWritability.blocked, pollUpstreamWritability(client_fd));

    const drainer = try std.Thread.spawn(.{}, slowUploadDrain, .{ peer_fd, @as(u64, 20), prefilled + payload.len });
    defer drainer.join();

    var counters = UploadBufferObserver{};
    var source = FakeUploadSource{ .data = payload };
    try runHttp1Upload(
        compat.netStreamFromFd(client_fd),
        client_fd,
        .{ .framing = .{ .length = payload.len } },
        &source,
        uploadTestLimits(1024 * 1024),
        counters.observer(),
        .{},
    );

    // The origin stopped draining, so downstream reads really were held back.
    try std.testing.expect(counters.pauses >= 1);
    // And every pause was resolved, not left dangling.
    try std.testing.expectEqual(counters.pauses, counters.resumes);
    // Peak relay memory is the fixed buffer, not the body.
    try std.testing.expectEqual(@as(usize, 16 * 1024), counters.peak_reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
}

test "http1 upload relay leaves nothing reserved when the client aborts mid-upload" {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    var counters = UploadBufferObserver{};
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    // Promises 8 KiB, delivers 4 KiB, then the client goes away.
    var source = FakeUploadSource{ .data = &[_]u8{'x'} ** 4096, .abort_after = 4096 };
    try std.testing.expectError(error.ClientAborted, runHttp1Upload(
        compat.netStreamFromFd(client_fd),
        client_fd,
        .{ .framing = .{ .length = 8192 } },
        &source,
        uploadTestLimits(1024 * 1024),
        counters.observer(),
        .{ .global = &global },
    ));

    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));
    // Never stalled, so the pause counters stay untouched.
    try std.testing.expectEqual(@as(u64, 0), counters.pauses);
    try std.testing.expectEqual(@as(u64, 0), counters.resumes);
}

test "http1 upload relay rejects an over-limit in-flight upload as a client fault" {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    var counters = UploadBufferObserver{};
    var source = FakeUploadSource{ .data = "" };
    // The relay buffer alone consumes the whole per-stream budget, so the bytes
    // that arrived with the request head have nowhere to go.
    try std.testing.expectError(error.RequestBufferLimitExceeded, runHttp1Upload(
        compat.netStreamFromFd(client_fd),
        client_fd,
        .{ .framing = .{ .length = 32 }, .initial_bytes = "inline-body-bytes" },
        &source,
        uploadTestLimits(16 * 1024),
        counters.observer(),
        .{},
    ));

    // Charged to the stream scope (a 413), not to an aggregate one (a 503).
    try std.testing.expectEqual(@as(u64, 1), counters.stream_limit_exceeded);
    try std.testing.expectEqual(@as(u64, 0), counters.aggregate_limit_exceeded);
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
}

test "http1 upload relay refuses when a concurrent relay has taken the aggregate" {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    const limits = uploadTestLimits(16 * 1024);
    var counters = UploadBufferObserver{};
    // Room for one relay buffer and a little more — the second upload is what
    // proves concurrency cannot multiply the per-stream bound.
    var global = proxy_buffer_account.Aggregate.init(.global, 24 * 1024);
    const capacity = proxy_buffer_account.AggregateCapacity{ .global = &global };

    var in_flight = ProxyBufferReservation.init(.downstream_to_upstream, limits, counters.observer(), capacity);
    try in_flight.reserve(16 * 1024);

    var source = FakeUploadSource{ .data = "" };
    try std.testing.expectError(error.ProxyBufferCapacityUnavailable, runHttp1Upload(
        compat.netStreamFromFd(client_fd),
        client_fd,
        .{ .framing = .{ .length = 0 } },
        &source,
        limits,
        counters.observer(),
        capacity,
    ));

    try std.testing.expectEqual(@as(u64, 1), counters.aggregate_limit_exceeded);
    try std.testing.expectEqual(proxy_buffer_account.Scope.global, counters.last_aggregate_scope.?);
    // The refused relay retained nothing; the reservation that did fit is intact.
    try std.testing.expectEqual(@as(usize, 16 * 1024), global.currentBytes(.downstream_to_upstream));

    in_flight.releaseAll();
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
}

/// Has anything arrived on `fd` yet? Zero timeout — used to assert an origin
/// was left untouched, so it must not wait for something that will never come.
fn peerHasBytes(fd: std.posix.fd_t) !bool {
    var pfds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    const ready = try std.posix.poll(&pfds, 0);
    return ready != 0 and (pfds[0].revents & std.posix.POLL.IN) != 0;
}

test "http1 chunked upload accounts the raw request-head remainder and releases it as it drains" {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    var counters = UploadBufferObserver{};
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    const limits = uploadTestLimits(1024 * 1024);
    const capacity = proxy_buffer_account.AggregateCapacity{ .global = &global };

    // The whole chunked body arrived with the request head. The decoder borrows
    // that raw slice — framing octets included — so all 14 bytes are retained
    // alongside the relay buffer even though only 5 are payload.
    const head_remainder = "5\r\nhello\r\n0\r\n\r\n";
    const sb = StreamingRequestBody{
        .framing = .chunked,
        .initial_bytes = head_remainder,
        .max_body_bytes = 1024,
    };
    try std.testing.expectEqual(@as(usize, head_remainder.len), uploadInitialBytesFootprint(sb));

    var source = FakeUploadSource{ .data = "" };
    var reservation = try preflightUploadReservation(
        limits,
        counters.observer(),
        capacity,
        http1_upload_relay_bytes,
        uploadInitialBytesFootprint(sb),
    );
    defer reservation.releaseAll();
    try std.testing.expectEqual(
        http1_upload_relay_bytes + head_remainder.len,
        counters.peak_reserved,
    );

    try relayStreamingUploadToHttp1(
        compat.netStreamFromFd(client_fd),
        client_fd,
        sb,
        &source,
        null,
        &reservation,
        counters.observer(),
    );

    // The relay gave the head remainder back as the decoder drained it, rather
    // than holding the peak until teardown — only the relay buffer is left.
    try std.testing.expectEqual(http1_upload_relay_bytes, reservation.account.snapshot().current);
    try std.testing.expectEqual(http1_upload_relay_bytes, global.currentBytes(.downstream_to_upstream));

    reservation.releaseAll();
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));

    // The re-chunked body did reach the origin.
    var seen: [64]u8 = undefined;
    const got = std.c.read(peer_fd, &seen, seen.len);
    try std.testing.expect(got > 0);
    try std.testing.expectEqualStrings("5\r\nhello\r\n0\r\n\r\n", seen[0..@intCast(got)]);
}

test "chunked request-head remainder counts against the aggregate scope" {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    const limits = uploadTestLimits(64 * 1024);
    var counters = UploadBufferObserver{};
    var global = proxy_buffer_account.Aggregate.init(.global, 64 * 1024);
    const capacity = proxy_buffer_account.AggregateCapacity{ .global = &global };

    // Concurrent work already holds 40 KiB. The relay buffer still fits; the
    // request-head remainder is what tips the scope over — which it could only
    // do if that remainder is accounted at all.
    var in_flight = ProxyBufferReservation.init(.downstream_to_upstream, limits, counters.observer(), capacity);
    try in_flight.reserve(40 * 1024);

    const head_remainder = [_]u8{'z'} ** (12 * 1024);
    var source = FakeUploadSource{ .data = "" };
    try std.testing.expectError(error.ProxyBufferCapacityUnavailable, runHttp1Upload(
        compat.netStreamFromFd(client_fd),
        client_fd,
        .{ .framing = .chunked, .initial_bytes = &head_remainder, .max_body_bytes = 1 << 20 },
        &source,
        limits,
        counters.observer(),
        capacity,
    ));

    try std.testing.expectEqual(@as(u64, 1), counters.aggregate_limit_exceeded);
    try std.testing.expectEqual(proxy_buffer_account.Scope.global, counters.last_aggregate_scope.?);
    // The refused upload rolled back completely; the concurrent holder is intact.
    try std.testing.expectEqual(@as(usize, 40 * 1024), global.currentBytes(.downstream_to_upstream));

    in_flight.releaseAll();
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
}

test "malformed chunked framing cannot leak the request-head reservation" {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    var counters = UploadBufferObserver{};
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    var source = FakeUploadSource{ .data = "" };
    try std.testing.expectError(error.InvalidChunkedUpload, runHttp1Upload(
        compat.netStreamFromFd(client_fd),
        client_fd,
        // Not a chunk-size line.
        .{ .framing = .chunked, .initial_bytes = "not-hex\r\n", .max_body_bytes = 1024 },
        &source,
        uploadTestLimits(1024 * 1024),
        counters.observer(),
        .{ .global = &global },
    ));

    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));
}

test "a client that vanishes mid-chunk releases the request-head reservation" {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    var counters = UploadBufferObserver{};
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    // Announces a 16-byte chunk, supplies none of it, then goes away.
    var source = FakeUploadSource{ .data = "", .abort_after = 0 };
    try std.testing.expectError(error.ClientAborted, runHttp1Upload(
        compat.netStreamFromFd(client_fd),
        client_fd,
        .{ .framing = .chunked, .initial_bytes = "10\r\n", .max_body_bytes = 1024 },
        &source,
        uploadTestLimits(1024 * 1024),
        counters.observer(),
        .{ .global = &global },
    ));

    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));
}

test "a broken upstream socket is not counted as backpressure" {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);

    // The origin is gone, not slow. `poll` still reports the descriptor ready
    // — for POLLERR/POLLHUP — so a naive readiness test would call this a full
    // send buffer and record a pause the write is about to invalidate.
    _ = std.c.close(peer_fd);

    var counters = UploadBufferObserver{};
    var stall = proxy_buffer_account.ReadStall.init(.downstream, counters.observer());
    try std.testing.expect(pollUpstreamWritability(client_fd) != .blocked);
    noteUpstreamWriteStall(client_fd, &stall);

    try std.testing.expectEqual(@as(u64, 0), counters.pauses);
    try std.testing.expectEqual(@as(u64, 0), counters.resumes);
    try std.testing.expect(!stall.paused);
}

test "http1 upload capacity is refused before the request head reaches the origin" {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    const limits = uploadTestLimits(16 * 1024);
    var counters = UploadBufferObserver{};
    var global = proxy_buffer_account.Aggregate.init(.global, 16 * 1024);
    const capacity = proxy_buffer_account.AggregateCapacity{ .global = &global };

    // The process account is already spoken for, so this upload cannot be
    // admitted at all.
    var in_flight = ProxyBufferReservation.init(.downstream_to_upstream, limits, counters.observer(), capacity);
    try in_flight.reserve(16 * 1024);
    defer in_flight.releaseAll();

    var source = FakeUploadSource{ .data = "" };
    const uri = try std.Uri.parse("http://origin.test/upload");
    try std.testing.expectError(error.ProxyBufferCapacityUnavailable, sendStreamingProxyRequest(
        std.testing.allocator,
        compat.netStreamFromFd(client_fd),
        client_fd,
        uri,
        "POST",
        &.{},
        "",
        .{ .framing = .{ .length = 4096 } },
        &source,
        null,
        limits,
        counters.observer(),
        capacity,
    ));

    // The whole point: the origin never saw a request it would have had to
    // decide what to do with. A refusal after the head went out would leave a
    // real, possibly side-effecting request half-delivered.
    try std.testing.expect(!try peerHasBytes(peer_fd));
}

/// A prior-knowledge h2c origin that completes just enough handshake for the
/// pool to hand back a connection, then records everything else the client
/// sends. Used to prove a request the proxy refused locally never reached it.
const H2CapacityProbe = struct {
    listen_fd: std.posix.fd_t,
    recorded: [4096]u8 = undefined,
    len: usize = 0,
};

fn h2PrefaceOnlyOrigin(probe: *H2CapacityProbe) void {
    const conn = std.c.accept(probe.listen_fd, null, null);
    if (conn < 0) return;
    defer _ = std.c.close(conn);

    var preface: [24]u8 = undefined;
    var got: usize = 0;
    while (got < preface.len) {
        const n = std.c.read(conn, preface[got..].ptr, preface.len - got);
        if (n <= 0) return;
        got += @intCast(n);
    }
    // An empty SETTINGS frame is all `acquire` needs to consider the
    // connection usable.
    const settings = [_]u8{ 0, 0, 0, 0x04, 0, 0, 0, 0, 0 };
    _ = std.c.write(conn, &settings, settings.len);

    while (probe.len < probe.recorded.len) {
        var pfd = [_]std.posix.pollfd{.{ .fd = conn, .events = std.posix.POLL.IN, .revents = 0 }};
        const ready = std.posix.poll(&pfd, 500) catch return;
        if (ready == 0) return;
        const n = std.c.read(conn, probe.recorded[probe.len..].ptr, probe.recorded.len - probe.len);
        if (n <= 0) return;
        probe.len += @intCast(n);
    }
}

fn readExactlyFromFd(fd: std.posix.fd_t, out: []u8) bool {
    var got: usize = 0;
    while (got < out.len) {
        const n = std.c.read(fd, out[got..].ptr, out.len - got);
        if (n <= 0) return false;
        got += @intCast(n);
    }
    return true;
}

fn sleepMs(ms: u32) void {
    var no_fds: [0]std.posix.pollfd = .{};
    _ = std.posix.poll(&no_fds, @intCast(ms)) catch {};
}

/// Bind a loopback listener on an ephemeral port and report it.
fn listenLoopbackEphemeral() !struct { fd: std.posix.fd_t, port: u16 } {
    const listen_fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    if (listen_fd < 0) return error.SocketFailed;
    errdefer _ = std.c.close(listen_fd);
    _ = std.c.setsockopt(listen_fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&@as(c_int, 1)), @sizeOf(c_int));
    const sin: std.c.sockaddr.in = .{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 0),
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
        .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    if (std.c.bind(listen_fd, @ptrCast(&sin), @sizeOf(std.c.sockaddr.in)) != 0) return error.BindFailed;
    if (std.c.listen(listen_fd, 4) != 0) return error.ListenFailed;
    var bound: std.c.sockaddr.in = undefined;
    var bound_len: std.posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    if (std.c.getsockname(listen_fd, @ptrCast(&bound), &bound_len) != 0) return error.SockNameFailed;
    return .{ .fd = listen_fd, .port = std.mem.bigToNative(u16, bound.port) };
}

/// An h2c origin that consumes a whole upload, answers with response headers,
/// and then holds the body back until told to release it. That gap is the
/// window where the upload has finished but the exchange has not, which is
/// exactly where a request-direction reservation must no longer be held.
const H2SlowResponseOrigin = struct {
    listen_fd: std.posix.fd_t,
    head_sent: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    release_body: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

fn h2SlowResponseServe(origin: *H2SlowResponseOrigin) void {
    const conn = std.c.accept(origin.listen_fd, null, null);
    if (conn < 0) return;
    defer _ = std.c.close(conn);

    var preface: [24]u8 = undefined;
    if (!readExactlyFromFd(conn, &preface)) return;
    const settings = [_]u8{ 0, 0, 0, 0x04, 0, 0, 0, 0, 0 };
    _ = std.c.write(conn, &settings, settings.len);

    // Drain frames until the request stream ends, remembering its id.
    var stream_id: u32 = 0;
    while (true) {
        var hdr: [9]u8 = undefined;
        if (!readExactlyFromFd(conn, &hdr)) return;
        const payload_len = (@as(usize, hdr[0]) << 16) | (@as(usize, hdr[1]) << 8) | @as(usize, hdr[2]);
        const typ = hdr[3];
        const flags = hdr[4];
        const sid = std.mem.readInt(u32, hdr[5..9], .big) & 0x7fff_ffff;
        var scratch: [4096]u8 = undefined;
        var remaining = payload_len;
        while (remaining > 0) {
            const take = @min(remaining, scratch.len);
            if (!readExactlyFromFd(conn, scratch[0..take])) return;
            remaining -= take;
        }
        if (typ == 0x01) stream_id = sid; // HEADERS
        if (typ == 0x00 and (flags & 0x01) != 0) break; // DATA with END_STREAM
    }
    if (stream_id == 0) return;

    // HEADERS, END_HEADERS, one byte of HPACK: `:status: 200` is static-table
    // index 8, so an indexed header field encodes the whole block.
    var head_frame = [_]u8{ 0, 0, 1, 0x01, 0x04, 0, 0, 0, 0, 0x88 };
    std.mem.writeInt(u32, head_frame[5..9], stream_id, .big);
    _ = std.c.write(conn, &head_frame, head_frame.len);
    origin.head_sent.store(true, .release);

    while (!origin.release_body.load(.acquire)) sleepMs(5);

    var body_frame = [_]u8{ 0, 0, 2, 0x00, 0x01, 0, 0, 0, 0, 'o', 'k' };
    std.mem.writeInt(u32, body_frame[5..9], stream_id, .big);
    _ = std.c.write(conn, &body_frame, body_frame.len);

    var drain: [256]u8 = undefined;
    while (true) {
        const got = std.c.read(conn, &drain, drain.len);
        if (got <= 0) break;
    }
}

/// Runs one `streamViaH2Pool` exchange on its own thread so the test can
/// observe accounting while the exchange is mid-flight.
const H2ExchangeCtx = struct {
    pool: *http.upstream_h2.H2ConnPool,
    port: u16,
    uri: std.Uri,
    read_buf: []u8,
    source: *FakeUploadSource,
    captured: *std.array_list.Managed(u8),
    security: *const http.security_headers.SecurityHeaders,
    limits: proxy_buffer_account.Limits,
    observer: proxy_buffer_account.Observer,
    global: *proxy_buffer_account.Aggregate,
    finished: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    failed: bool = false,
    status: u16 = 0,
    err: ?anyerror = null,
    downstream_committed: bool = false,
};

fn runH2ExchangeThread(ctx: *H2ExchangeCtx) void {
    defer ctx.finished.store(true, .release);
    var downstream_committed = false;
    const result = streamViaH2Pool(
        std.testing.allocator,
        ctx.pool,
        null,
        "127.0.0.1",
        ctx.port,
        null, // prior-knowledge h2c
        ctx.uri,
        "POST",
        &.{},
        "",
        .{ .framing = .{ .length = 8 } },
        ctx.read_buf.len,
        ctx.source,
        CaptureWriter{ .list = ctx.captured },
        ctx.security,
        null,
        null,
        "lifetime-test",
        true,
        2000,
        5000,
        null,
        ctx.limits,
        ctx.observer,
        ctx.global,
        &downstream_committed,
    ) catch {
        ctx.failed = true;
        return;
    };
    ctx.status = result.status_code;
}

/// A downstream writer that cancels `token` the moment it has captured a
/// complete response head (`\r\n\r\n`), as a side effect of the very write
/// call that commits the response -- guaranteeing the cancellation is
/// already visible by the h2-pool body loop's *first* `cancelStopped()`
/// check, rather than racing to land it inside a narrow window between
/// loop iterations.
const CancelingHeadCaptureWriter = struct {
    captured: *std.array_list.Managed(u8),
    token: *CancellationToken,

    fn maybeCancel(self: CancelingHeadCaptureWriter) void {
        if (!self.token.isCancelled() and std.mem.find(u8, self.captured.items, "\r\n\r\n") != null) {
            self.token.cancel(.client_disconnect);
        }
    }

    pub fn writeAll(self: CancelingHeadCaptureWriter, bytes: []const u8) !void {
        try self.captured.appendSlice(bytes);
        self.maybeCancel();
    }
    pub fn print(self: CancelingHeadCaptureWriter, comptime fmt: []const u8, args: anytype) !void {
        var buf: [64]u8 = undefined;
        try self.captured.appendSlice(try std.fmt.bufPrint(&buf, fmt, args));
        self.maybeCancel();
    }
};

/// Same exchange as `runH2ExchangeThread`, but a GET with no upload body,
/// over `CancelingHeadCaptureWriter`, and reporting the error plus
/// `downstream_committed` state back on `ctx` (#643).
fn runH2CancelExchangeThread(ctx: *H2ExchangeCtx, token: *CancellationToken) void {
    defer ctx.finished.store(true, .release);
    var downstream_committed = false;
    const result = streamViaH2Pool(
        std.testing.allocator,
        ctx.pool,
        null,
        "127.0.0.1",
        ctx.port,
        null, // prior-knowledge h2c
        ctx.uri,
        "POST",
        &.{},
        // A buffered (non-streamed) body, not empty: `H2SlowResponseOrigin`
        // only proceeds past the request phase once it has read a DATA
        // frame carrying END_STREAM, which a genuinely bodiless request
        // never sends (END_STREAM lands directly on HEADERS instead) --
        // confirmed empirically as the exchange timing out server-side
        // never receiving a response at all.
        "x",
        null, // buffered, not streamed
        ctx.read_buf.len,
        ctx.source,
        CancelingHeadCaptureWriter{ .captured = ctx.captured, .token = token },
        ctx.security,
        null,
        null,
        "h2-cancel-test",
        true,
        2000,
        5000,
        token,
        ctx.limits,
        ctx.observer,
        ctx.global,
        &downstream_committed,
    ) catch |err| {
        ctx.failed = true;
        ctx.err = err;
        ctx.downstream_committed = downstream_committed;
        return;
    };
    ctx.status = result.status_code;
    ctx.downstream_committed = downstream_committed;
}

test "an http2 upload releases request-direction capacity before its response completes" {
    const listener = try listenLoopbackEphemeral();
    defer _ = std.c.close(listener.fd);

    var origin = H2SlowResponseOrigin{ .listen_fd = listener.fd };
    const origin_thread = try std.Thread.spawn(.{}, h2SlowResponseServe, .{&origin});

    var read_buf: [16 * 1024]u8 = undefined;
    const limits = uploadTestLimits(1024 * 1024);
    // Exactly one relay buffer fits per direction. The upload's claim is
    // therefore the only thing that can keep a second upload out.
    var global = proxy_buffer_account.Aggregate.init(.global, read_buf.len);

    var counters = UploadBufferObserver{};
    var source = FakeUploadSource{ .data = "upload!!" };
    var captured = std.array_list.Managed(u8).init(std.testing.allocator);
    defer captured.deinit();
    var security = http.security_headers.SecurityHeaders{};
    var url_buf: [64]u8 = undefined;
    const uri = try std.Uri.parse(try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/upload", .{listener.port}));

    var pool = http.upstream_h2.H2ConnPool.init(std.testing.allocator, .{});
    var ctx = H2ExchangeCtx{
        .pool = &pool,
        .port = listener.port,
        .uri = uri,
        .read_buf = &read_buf,
        .source = &source,
        .captured = &captured,
        .security = &security,
        .limits = limits,
        .observer = counters.observer(),
        .global = &global,
    };
    const exchange = try std.Thread.spawn(.{}, runH2ExchangeThread, .{&ctx});

    // The origin has taken the whole upload and answered with headers; the
    // response body is still being withheld, so the exchange is mid-flight.
    var waited: u32 = 0;
    while (!origin.head_sent.load(.acquire) and waited < 5000) : (waited += 5) sleepMs(5);
    try std.testing.expect(origin.head_sent.load(.acquire));

    // The upload finished, so its capacity must be back — even though the
    // exchange has not. Bounded wait, because the release happens on the
    // exchange thread just after the relay returns; the budget is well inside
    // the exchange's own read deadline so a regression fails here on the
    // reservation rather than later on a timeout.
    waited = 0;
    while (global.currentBytes(.downstream_to_upstream) != 0 and waited < 1000) : (waited += 5) sleepMs(5);
    // Checked first: it is what makes the next assertion meaningful — the
    // capacity came back while the exchange was still running, not because it
    // ended.
    try std.testing.expect(!ctx.finished.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));

    // And the capacity is genuinely usable: a second upload can take it. With
    // the claim held for the whole exchange this reservation was refused, which
    // is the false `503 proxy_buffer_saturated` an unrelated client would see.
    var other = UploadBufferObserver{};
    var second_upload = ProxyBufferReservation.init(
        .downstream_to_upstream,
        limits,
        other.observer(),
        .{ .global = &global },
    );
    try second_upload.reserve(read_buf.len);
    second_upload.releaseAll();

    origin.release_body.store(true, .release);
    exchange.join();
    try std.testing.expect(!ctx.failed);
    try std.testing.expectEqual(@as(u16, 200), ctx.status);

    pool.deinit();
    origin_thread.join();

    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.upstream_to_downstream));
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
}

// Reviewer-requested regression (#643): `streamViaH2Pool`'s real `.h2` arm
// must set `downstream_committed` when its own mid-relay `cancelStopped()`
// check throws `error.RequestCancelled` *after* the response head already
// went downstream -- the second of the two commitment gaps the first
// implementation of this fix left uncovered (the first is the sibling
// `.h1`-arm test above). Reuses `H2SlowResponseOrigin`: it sends HEADERS
// then withholds the body, which would otherwise make "wait for
// cancellation to matter" a race against the body loop's next iteration --
// sidestepped entirely by canceling the token as a side effect of
// `CancelingHeadCaptureWriter` observing the head write complete, which
// happens synchronously before the body loop's first (not second)
// `cancelStopped()` check.
test "an http2 mid-relay cancellation reports downstream_committed" {
    const listener = try listenLoopbackEphemeral();
    defer _ = std.c.close(listener.fd);

    var origin = H2SlowResponseOrigin{ .listen_fd = listener.fd };
    const origin_thread = try std.Thread.spawn(.{}, h2SlowResponseServe, .{&origin});

    var read_buf: [16 * 1024]u8 = undefined;
    const limits = uploadTestLimits(1024 * 1024);
    var global = proxy_buffer_account.Aggregate.init(.global, read_buf.len);
    var counters = UploadBufferObserver{};
    var source = FakeUploadSource{ .data = "" };
    var captured = std.array_list.Managed(u8).init(std.testing.allocator);
    defer captured.deinit();
    var security = http.security_headers.SecurityHeaders{};
    var url_buf: [64]u8 = undefined;
    const uri = try std.Uri.parse(try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/slow", .{listener.port}));

    var pool = http.upstream_h2.H2ConnPool.init(std.testing.allocator, .{});
    var ctx = H2ExchangeCtx{
        .pool = &pool,
        .port = listener.port,
        .uri = uri,
        .read_buf = &read_buf,
        .source = &source,
        .captured = &captured,
        .security = &security,
        .limits = limits,
        .observer = counters.observer(),
        .global = &global,
    };
    var token = CancellationToken.init(0); // no deadline; canceled explicitly
    const exchange = try std.Thread.spawn(.{}, runH2CancelExchangeThread, .{ &ctx, &token });
    exchange.join();

    // Unstick the origin thread (still waiting on `release_body`, which
    // this exchange -- canceled before ever reading the body -- never
    // reaches) so it can exit cleanly.
    origin.release_body.store(true, .release);
    pool.deinit();
    origin_thread.join();

    try std.testing.expect(ctx.failed);
    try std.testing.expectEqual(@as(?anyerror, error.RequestCancelled), ctx.err);
    try std.testing.expect(ctx.downstream_committed);
}

/// Walk an HTTP/2 frame stream looking for one frame type. Frames are
/// length-prefixed, so this needs no protocol state.
fn h2StreamContainsFrameType(bytes: []const u8, wanted: u8) bool {
    var i: usize = 0;
    while (i + 9 <= bytes.len) {
        const payload_len = (@as(usize, bytes[i]) << 16) | (@as(usize, bytes[i + 1]) << 8) | @as(usize, bytes[i + 2]);
        if (bytes[i + 3] == wanted) return true;
        i += 9 + payload_len;
    }
    return false;
}

test "http2 upload capacity is refused before HEADERS reach the origin" {
    const listen_fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    try std.testing.expect(listen_fd >= 0);
    defer _ = std.c.close(listen_fd);
    _ = std.c.setsockopt(listen_fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&@as(c_int, 1)), @sizeOf(c_int));
    const sin: std.c.sockaddr.in = .{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 0),
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
        .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    try std.testing.expect(std.c.bind(listen_fd, @ptrCast(&sin), @sizeOf(std.c.sockaddr.in)) == 0);
    try std.testing.expect(std.c.listen(listen_fd, 4) == 0);
    var bound: std.c.sockaddr.in = undefined;
    var bound_len: std.posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    try std.testing.expect(std.c.getsockname(listen_fd, @ptrCast(&bound), &bound_len) == 0);
    const port = std.mem.bigToNative(u16, bound.port);

    var probe = H2CapacityProbe{ .listen_fd = listen_fd };
    const origin = try std.Thread.spawn(.{}, h2PrefaceOnlyOrigin, .{&probe});

    const limits = uploadTestLimits(1024 * 1024);
    var counters = UploadBufferObserver{};
    // The process account is full before the request starts.
    var global = proxy_buffer_account.Aggregate.init(.global, 16 * 1024);
    var in_flight = ProxyBufferReservation.init(
        .downstream_to_upstream,
        limits,
        counters.observer(),
        .{ .global = &global },
    );
    try in_flight.reserve(16 * 1024);
    defer in_flight.releaseAll();

    const relay_bytes: usize = 16 * 1024;
    var source = FakeUploadSource{ .data = "" };
    var captured = std.array_list.Managed(u8).init(std.testing.allocator);
    defer captured.deinit();
    var security = http.security_headers.SecurityHeaders{};
    var url_buf: [64]u8 = undefined;
    const uri = try std.Uri.parse(try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/upload", .{port}));

    {
        var pool = http.upstream_h2.H2ConnPool.init(std.testing.allocator, .{});
        defer pool.deinit();
        var downstream_committed = false;

        try std.testing.expectError(error.ProxyBufferCapacityUnavailable, streamViaH2Pool(
            std.testing.allocator,
            &pool,
            null,
            "127.0.0.1",
            port,
            null, // prior-knowledge h2c
            uri,
            "POST",
            &.{},
            "",
            .{ .framing = .{ .length = 4096 } },
            relay_bytes,
            &source,
            CaptureWriter{ .list = &captured },
            &security,
            null,
            null,
            "test-correlation-id",
            false,
            2000,
            2000,
            null,
            limits,
            counters.observer(),
            &global,
            &downstream_committed,
        ));
    }
    origin.join();

    // The origin completed a connection but was never asked to do any work:
    // refusing after HEADERS would have left it holding a request whose body
    // never arrives, and any side effects that came with it.
    try std.testing.expect(!h2StreamContainsFrameType(probe.recorded[0..probe.len], 0x01));
    // Nothing beyond the deliberately-held reservation is outstanding: the
    // refused request rolled back everything it touched.
    try std.testing.expectEqual(@as(usize, 16 * 1024), counters.retained);
    try std.testing.expectEqual(@as(usize, 16 * 1024), global.currentBytes(.downstream_to_upstream));
}

const FakeH2UploadStream = struct { id: u32 = 1 };

const FakeH2UploadConn = struct {
    written: usize = 0,
    end_stream: bool = false,

    fn writeStreamingRequestBody(
        self: *FakeH2UploadConn,
        _: *FakeH2UploadStream,
        bytes: []const u8,
        end_stream: bool,
    ) !void {
        self.written += bytes.len;
        if (end_stream) self.end_stream = true;
    }
};

test "http2 upload relay reserves the relay buffer once, not once per DATA frame" {
    var conn = FakeH2UploadConn{};
    var stream = FakeH2UploadStream{};
    var counters = UploadBufferObserver{};
    var global = proxy_buffer_account.Aggregate.init(.global, 0);

    const payload = try std.testing.allocator.alloc(u8, 256 * 1024);
    defer std.testing.allocator.free(payload);
    @memset(payload, 'd');
    var read_buf: [16 * 1024]u8 = undefined;
    var source = FakeUploadSource{ .data = payload };

    try runHttp2Upload(
        &conn,
        &stream,
        .{ .framing = .{ .length = payload.len } },
        &read_buf,
        &source,
        uploadTestLimits(1024 * 1024),
        counters.observer(),
        .{ .global = &global },
    );

    try std.testing.expectEqual(payload.len, conn.written);
    try std.testing.expect(conn.end_stream);
    // 16 DATA frames went out, but only one buffer was ever owned.
    try std.testing.expectEqual(@as(usize, read_buf.len), counters.peak_reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));
}

test "http2 chunked upload accounts and releases the raw request-head remainder" {
    var conn = FakeH2UploadConn{};
    var stream = FakeH2UploadStream{};
    var counters = UploadBufferObserver{};
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    const limits = uploadTestLimits(1024 * 1024);
    const capacity = proxy_buffer_account.AggregateCapacity{ .global = &global };
    var read_buf: [16 * 1024]u8 = undefined;

    const head_remainder = "5\r\nhello\r\n0\r\n\r\n";
    const sb = StreamingRequestBody{
        .framing = .chunked,
        .initial_bytes = head_remainder,
        .max_body_bytes = 1024,
    };
    var source = FakeUploadSource{ .data = "" };

    var reservation = try preflightUploadReservation(
        limits,
        counters.observer(),
        capacity,
        read_buf.len,
        uploadInitialBytesFootprint(sb),
    );
    defer reservation.releaseAll();
    try std.testing.expectEqual(read_buf.len + head_remainder.len, counters.peak_reserved);

    try relayStreamingUploadToHttp2(&conn, &stream, sb, &read_buf, &source, null, &reservation);

    // Decoded payload went out as DATA; the raw framing octets were accounted
    // and then handed back as the decoder consumed them.
    try std.testing.expectEqual(@as(usize, 5), conn.written);
    try std.testing.expect(conn.end_stream);
    try std.testing.expectEqual(read_buf.len, reservation.account.snapshot().current);

    reservation.releaseAll();
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));
}

test "http2 upload relay releases the aggregate when the client aborts" {
    var conn = FakeH2UploadConn{};
    var stream = FakeH2UploadStream{};
    var counters = UploadBufferObserver{};
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    var read_buf: [16 * 1024]u8 = undefined;
    var source = FakeUploadSource{ .data = &[_]u8{'y'} ** 1024, .abort_after = 1024 };

    try std.testing.expectError(error.ClientAborted, runHttp2Upload(
        &conn,
        &stream,
        .{ .framing = .{ .length = 64 * 1024 } },
        &read_buf,
        &source,
        uploadTestLimits(1024 * 1024),
        counters.observer(),
        .{ .global = &global },
    ));

    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));
}

/// Raw blocking responder: accepts one connection, drains the request, writes a
/// fixed 200 response, and closes. Uses std.c directly so the test never touches
/// the std.Io event loop.
fn rawHttpResponder(listen_fd: std.posix.fd_t) void {
    const conn = std.c.accept(listen_fd, null, null);
    if (conn < 0) return;
    defer _ = std.c.close(conn);
    var buf: [4096]u8 = undefined;
    _ = std.c.read(conn, &buf, buf.len);
    const response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nhello";
    _ = std.c.write(conn, response.ptr, response.len);
}

test "connectBlockingTcp + exchange round-trips a real TCP origin" {
    const allocator = std.testing.allocator;

    // Raw blocking listener (no event loop).
    const listen_fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    try std.testing.expect(listen_fd >= 0);
    defer _ = std.c.close(listen_fd);
    _ = std.c.setsockopt(listen_fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&@as(c_int, 1)), @sizeOf(c_int));

    const sin: std.c.sockaddr.in = .{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 0),
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
        .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    try std.testing.expect(std.c.bind(listen_fd, @ptrCast(&sin), @sizeOf(std.c.sockaddr.in)) == 0);
    try std.testing.expect(std.c.listen(listen_fd, 8) == 0);

    var bound: std.c.sockaddr.in = undefined;
    var bound_len: std.posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    try std.testing.expect(std.c.getsockname(listen_fd, @ptrCast(&bound), &bound_len) == 0);
    const port = std.mem.bigToNative(u16, bound.port);
    try std.testing.expect(port != 0);

    const responder = try std.Thread.spawn(.{}, rawHttpResponder, .{listen_fd});
    defer responder.join();

    const uri = try std.Uri.parse("http://127.0.0.1/");
    var resp = try executeBoundedBufferedTcpHttpRequest(
        allocator,
        "127.0.0.1",
        port,
        null,
        uri,
        "GET",
        &.{},
        "",
        null,
        1 << 20,
        2_000,
        2_000,
        null,
        null,
        false,
    );
    defer resp.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status_code);
    try std.testing.expectEqualStrings("hello", resp.body);
    try std.testing.expectEqualStrings("text/plain", resp.headerValue("content-type").?);
}

/// Raw blocking keep-alive responder: accepts one connection and serves `n`
/// framed responses on it (Content-Length, no `Connection: close`), so a
/// pooled client can reuse the connection across requests.
fn rawKeepAliveHttpResponder(listen_fd: std.posix.fd_t, n: usize) void {
    const conn = std.c.accept(listen_fd, null, null);
    if (conn < 0) return;
    defer _ = std.c.close(conn);
    var buf: [4096]u8 = undefined;
    var served: usize = 0;
    while (served < n) : (served += 1) {
        const got = std.posix.read(conn, buf[0..]) catch return;
        if (got == 0) return;
        const response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
        _ = std.c.write(conn, response.ptr, response.len);
    }
    // Drain until the client closes so our close never RSTs unread bytes.
    while (true) {
        const got = std.posix.read(conn, buf[0..]) catch return;
        if (got == 0) return;
    }
}

test "unix-socket upstream connections pool and reuse across requests (#239)" {
    const allocator = std.testing.allocator;

    var full_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var rnd: [8]u8 = undefined;
    compat.randomBytes(&rnd);
    const full_path = try std.fmt.bufPrint(&full_path_buf, "/tmp/tardigrade-pool-{x}.sock", .{std.mem.readInt(u64, &rnd, .little)});
    var path_z: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(path_z[0..full_path.len], full_path);
    path_z[full_path.len] = 0;
    _ = std.c.unlink(@ptrCast(&path_z));
    defer _ = std.c.unlink(@ptrCast(&path_z));

    const listen_fd = std.c.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
    try std.testing.expect(listen_fd >= 0);
    defer _ = std.c.close(listen_fd);
    var un = std.mem.zeroes(std.c.sockaddr.un);
    un.family = std.posix.AF.UNIX;
    try std.testing.expect(full_path.len < un.path.len);
    @memcpy(un.path[0..full_path.len], full_path);
    const un_len: std.posix.socklen_t = @intCast(@offsetOf(std.c.sockaddr.un, "path") + full_path.len + 1);
    try std.testing.expect(std.c.bind(listen_fd, @ptrCast(&un), un_len) == 0);
    try std.testing.expect(std.c.listen(listen_fd, 8) == 0);

    const responder = try std.Thread.spawn(.{}, rawKeepAliveHttpResponder, .{ listen_fd, @as(usize, 2) });
    defer responder.join();

    var pool = http.upstream_pool.UpstreamPool.init(allocator, .{});
    defer pool.deinit();

    const uri = try std.Uri.parse("http://localhost/");
    var i: usize = 0;
    while (i < 2) : (i += 1) {
        var resp = try executeBoundedBufferedUnixSocketHttpRequest(
            allocator,
            full_path,
            uri,
            "GET",
            &.{},
            "",
            null,
            1 << 20,
            2_000,
            2_000,
            &pool,
        );
        defer resp.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), resp.status_code);
        try std.testing.expectEqualStrings("hello", resp.body);
    }

    // One connection served both requests: 1 new, 1 reused, keyed unix:<path>.
    const agg = pool.aggregateStats();
    try std.testing.expectEqual(@as(u64, 1), agg.new_total);
    try std.testing.expectEqual(@as(u64, 1), agg.reused_total);
    const snaps = try pool.snapshotHosts(allocator);
    defer http.upstream_pool.freeHostSnapshots(allocator, snaps);
    try std.testing.expectEqual(@as(usize, 1), snaps.len);
    try std.testing.expect(std.mem.startsWith(u8, snaps[0].host, "unix:/tmp/tardigrade-pool-"));
}

test "connectBlockingUnix + exchange round-trips a Unix-socket origin" {
    const allocator = std.testing.allocator;

    var full_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var rnd: [8]u8 = undefined;
    compat.randomBytes(&rnd);
    const full_path = try std.fmt.bufPrint(&full_path_buf, "/tmp/tardigrade-test-{x}.sock", .{std.mem.readInt(u64, &rnd, .little)});
    var path_z: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(path_z[0..full_path.len], full_path);
    path_z[full_path.len] = 0;
    _ = std.c.unlink(@ptrCast(&path_z)); // best-effort: clear any stale socket
    defer _ = std.c.unlink(@ptrCast(&path_z));

    const listen_fd = std.c.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
    try std.testing.expect(listen_fd >= 0);
    defer _ = std.c.close(listen_fd);

    var un = std.mem.zeroes(std.c.sockaddr.un);
    un.family = std.posix.AF.UNIX;
    try std.testing.expect(full_path.len < un.path.len);
    @memcpy(un.path[0..full_path.len], full_path);
    const un_len: std.posix.socklen_t = @intCast(@offsetOf(std.c.sockaddr.un, "path") + full_path.len + 1);
    try std.testing.expect(std.c.bind(listen_fd, @ptrCast(&un), un_len) == 0);
    try std.testing.expect(std.c.listen(listen_fd, 8) == 0);

    const responder = try std.Thread.spawn(.{}, rawHttpResponder, .{listen_fd});
    defer responder.join();

    const uri = try std.Uri.parse("http://localhost/");
    var resp = try executeBoundedBufferedUnixSocketHttpRequest(
        allocator,
        full_path,
        uri,
        "GET",
        &.{},
        "",
        null,
        1 << 20,
        2_000,
        2_000,
        null,
    );
    defer resp.deinit(allocator);

    try std.testing.expectEqual(@as(u16, 200), resp.status_code);
    try std.testing.expectEqualStrings("hello", resp.body);
}

// ---------------------------------------------------------------------------
// Response-direction per-origin buffer accounting for HTTP/1 origins (#140).
// ---------------------------------------------------------------------------

/// A downstream client whose socket is already gone. The response reservation
/// is taken before the head is written, so this fails with the reservation
/// live — the case that would leak it.
const FailingDownstreamWriter = struct {
    pub fn writeAll(_: FailingDownstreamWriter, _: []const u8) !void {
        return error.BrokenPipe;
    }
    pub fn print(_: FailingDownstreamWriter, comptime _: []const u8, _: anytype) !void {
        return error.BrokenPipe;
    }
};

/// One HTTP/1 response relay driven over a socketpair standing in for the
/// origin. `preload` is written to the origin end before the relay starts; the
/// test writes the rest (or closes) to control when the relay finishes.
const Http1ResponseRelay = struct {
    client_fd: std.posix.fd_t,
    origin_fd: std.posix.fd_t,
    /// The relay buffer's size; the production path allocates it, so a test can
    /// observe both the allocation and the reservation.
    relay_bytes: usize,
    allocator: std.mem.Allocator = std.testing.allocator,
    captured: std.array_list.Managed(u8),
    counters: UploadBufferObserver = .{},
    limits: proxy_buffer_account.Limits,
    capacity: proxy_buffer_account.AggregateCapacity,
    read_deadline_ms: u32 = 5000,
    cancel_token: ?*const CancellationToken = null,
    finished: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    err: ?anyerror = null,
    status: u16 = 0,
    upstream_aborted: bool = false,
    downstream_aborted_after_status: bool = false,
    /// Set from `runNegotiatedH1Exchange`'s own out-parameter on an error
    /// return (#643): whether the downstream response head had already been
    /// written before the failure, i.e. whether a caller may safely
    /// serialize a replacement response.
    downstream_committed: bool = false,

    fn init(
        relay_bytes: usize,
        limits: proxy_buffer_account.Limits,
        capacity: proxy_buffer_account.AggregateCapacity,
    ) !Http1ResponseRelay {
        const fds = try makeBlockingSocketpair();
        return .{
            .client_fd = fds[0],
            .origin_fd = fds[1],
            .relay_bytes = relay_bytes,
            .captured = std.array_list.Managed(u8).init(std.testing.allocator),
            .limits = limits,
            .capacity = capacity,
        };
    }

    fn deinit(self: *Http1ResponseRelay) void {
        self.captured.deinit();
        _ = std.c.close(self.client_fd);
        _ = std.c.close(self.origin_fd);
    }

    fn originSend(self: *Http1ResponseRelay, bytes: []const u8) void {
        _ = std.c.write(self.origin_fd, bytes.ptr, bytes.len);
    }

    fn originClose(self: *Http1ResponseRelay) void {
        _ = std.c.shutdown(self.origin_fd, std.posix.SHUT.WR);
    }

    fn run(self: *Http1ResponseRelay, downstream_writer: anytype) void {
        defer self.finished.store(true, .release);
        var security = http.security_headers.SecurityHeaders{};
        var source = FakeUploadSource{ .data = "" };
        const uri = std.Uri.parse("http://origin.test/resource") catch unreachable;
        const result = runNegotiatedH1Exchange(
            self.allocator,
            compat.netStreamFromFd(self.client_fd),
            self.client_fd,
            self.relay_bytes,
            uri,
            "GET",
            &.{},
            "",
            null, // no streaming upload: this exercises the response direction
            &source,
            downstream_writer,
            &security,
            null,
            null,
            "origin-buffer-test",
            true,
            0,
            self.read_deadline_ms,
            self.cancel_token,
            self.limits,
            self.counters.observer(),
            self.capacity,
            &self.downstream_committed,
        ) catch |err| {
            self.err = err;
            return;
        };
        self.status = result.status_code;
        self.upstream_aborted = result.upstream_aborted;
        self.downstream_aborted_after_status = result.downstream_aborted_after_status;
    }

    fn runCapturing(self: *Http1ResponseRelay) void {
        self.run(CaptureWriter{ .list = &self.captured });
    }

    /// Every scope this relay touched is back to zero, and so is the local
    /// accounting the metrics are derived from.
    fn expectNothingHeld(self: *const Http1ResponseRelay) !void {
        try std.testing.expectEqual(@as(usize, 0), self.counters.reserved);
        try std.testing.expectEqual(@as(usize, 0), self.counters.retained);
        if (self.capacity.origin) |origin| {
            try std.testing.expectEqual(@as(usize, 0), origin.currentBytes(.upstream_to_downstream));
        }
        if (self.capacity.global) |global| {
            try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.upstream_to_downstream));
        }
    }
};

const h1_response_head = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n";

test "http1 response relay releases its origin reservation on success" {
    var origin = proxy_buffer_account.Aggregate.init(.origin, 64 * 1024);
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    const relay_bytes: usize = 16 * 1024;

    var relay = try Http1ResponseRelay.init(
        relay_bytes,
        uploadTestLimits(1024 * 1024),
        .{ .origin = &origin, .global = &global },
    );
    defer relay.deinit();

    relay.originSend(h1_response_head ++ "body");
    relay.runCapturing();

    try std.testing.expect(relay.err == null);
    try std.testing.expectEqual(@as(u16, 200), relay.status);
    // The relay buffer was charged to the origin while it ran, and only that.
    try std.testing.expectEqual(relay_bytes, relay.counters.peak_reserved);
    try relay.expectNothingHeld();
}

test "http1 response relay releases its origin reservation when the upstream aborts mid-body" {
    var origin = proxy_buffer_account.Aggregate.init(.origin, 64 * 1024);
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    const relay_bytes: usize = 16 * 1024;

    var relay = try Http1ResponseRelay.init(
        relay_bytes,
        uploadTestLimits(1024 * 1024),
        .{ .origin = &origin, .global = &global },
    );
    defer relay.deinit();

    // Promises four body bytes, sends one, then goes away.
    relay.originSend(h1_response_head ++ "b");
    relay.originClose();
    relay.runCapturing();

    try std.testing.expect(relay.err == null);
    try std.testing.expect(relay.upstream_aborted);
    try relay.expectNothingHeld();
}

// Reviewer-requested regression (#643): the h2-pool's ALPN->h1 fallback arm
// (`streamViaH2Pool`'s `.h1` case) must set `downstream_committed` on error
// exactly like the direct-H1 pooled path does, so a caller never serializes
// a second HTTP response onto an already-committed connection. Exercises
// `runNegotiatedH1Exchange` directly -- the small helper `streamViaH2Pool`'s
// `.h1` arm calls -- since forcing a deterministic post-commit failure
// through a real ALPN-negotiated TLS connection would need far more
// machinery than the actual commitment contract being tested here.
//
// Reuses the sibling read-timeout test's exact mechanism below (head sent,
// no body follows, a short deadline) rather than attempting a TCP-style RST:
// this harness's socketpair is AF_UNIX (`makeBlockingSocketpair`), which has
// no RST/FIN distinction at the protocol level -- an abrupt
// `SO_LINGER{onoff=1,linger=0}` close on it still surfaces to the peer as a
// plain, graceful `read() == 0` (confirmed empirically: it produced
// `relayUpstreamBody`'s existing `.aborted = true` outcome, not a thrown
// error). A read timeout is a genuinely thrown error reached only after the
// head already committed, which is exactly the post-commit failure shape
// this test needs to prove.
test "negotiated-h1 exchange reports downstream_committed on a post-commit read timeout" {
    var origin = proxy_buffer_account.Aggregate.init(.origin, 64 * 1024);
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    const relay_bytes: usize = 16 * 1024;

    var relay = try Http1ResponseRelay.init(
        relay_bytes,
        uploadTestLimits(1024 * 1024),
        .{ .origin = &origin, .global = &global },
    );
    defer relay.deinit();
    relay.read_deadline_ms = 100;

    // The head commits the response; the promised body never arrives.
    relay.originSend(h1_response_head);
    relay.runCapturing();

    try std.testing.expect(relay.err != null);
    try std.testing.expect(relay.downstream_committed);
}

test "http1 response relay releases its origin reservation on a read timeout" {
    var origin = proxy_buffer_account.Aggregate.init(.origin, 64 * 1024);
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    const relay_bytes: usize = 16 * 1024;

    var relay = try Http1ResponseRelay.init(
        relay_bytes,
        uploadTestLimits(1024 * 1024),
        .{ .origin = &origin, .global = &global },
    );
    defer relay.deinit();
    relay.read_deadline_ms = 100;

    // The head arrives, the body never does: the relay is holding its
    // reservation when the read deadline fires.
    relay.originSend(h1_response_head);
    relay.runCapturing();

    try std.testing.expect(relay.err != null);
    try relay.expectNothingHeld();
}

test "http1 response relay releases its origin reservation when the request is cancelled" {
    var origin = proxy_buffer_account.Aggregate.init(.origin, 64 * 1024);
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    const relay_bytes: usize = 16 * 1024;

    var relay = try Http1ResponseRelay.init(
        relay_bytes,
        uploadTestLimits(1024 * 1024),
        .{ .origin = &origin, .global = &global },
    );
    defer relay.deinit();

    var token = CancellationToken.init(0);
    token.cancel(.client_disconnect);
    relay.cancel_token = &token;

    relay.originSend(h1_response_head);
    relay.runCapturing();

    try std.testing.expectEqual(@as(?anyerror, error.RequestCancelled), relay.err);
    try relay.expectNothingHeld();
}

test "http1 response relay releases its origin reservation when the client aborts" {
    var origin = proxy_buffer_account.Aggregate.init(.origin, 64 * 1024);
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    const relay_bytes: usize = 16 * 1024;

    var relay = try Http1ResponseRelay.init(
        relay_bytes,
        uploadTestLimits(1024 * 1024),
        .{ .origin = &origin, .global = &global },
    );
    defer relay.deinit();

    relay.originSend(h1_response_head ++ "body");
    // The reservation is taken before the head is written downstream, so the
    // write failing means it is live at the moment the client vanishes.
    relay.run(FailingDownstreamWriter{});

    try std.testing.expect(relay.err == null);
    try std.testing.expectEqual(@as(u16, 200), relay.status);
    try std.testing.expect(relay.downstream_aborted_after_status);
    try relay.expectNothingHeld();
}

test "http1 response relay returns known 500 when downstream aborts after status" {
    var origin = proxy_buffer_account.Aggregate.init(.origin, 64 * 1024);
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    const relay_bytes: usize = 16 * 1024;

    var relay = try Http1ResponseRelay.init(
        relay_bytes,
        uploadTestLimits(1024 * 1024),
        .{ .origin = &origin, .global = &global },
    );
    defer relay.deinit();

    relay.originSend("HTTP/1.1 500 Oops\r\nContent-Length: 4\r\n\r\nfail");
    relay.run(FailingDownstreamWriter{});

    try std.testing.expect(relay.err == null);
    try std.testing.expectEqual(@as(u16, 500), relay.status);
    try std.testing.expect(relay.downstream_aborted_after_status);
    try relay.expectNothingHeld();
}

test "http1 response memory is not allocated until a reservation admits it" {
    // The HTTP/1 analogue of the HTTP/2 ordering rule. The response buffer is
    // application-owned the moment it exists, and `readUpstreamHead` reads into
    // it — past the blank line, so body bytes can land there — so allocating
    // before the reservation let the cap refuse only after the memory it
    // bounds had already been taken.
    const relay_bytes: usize = 16 * 1024;
    // Room for exactly one response relay across the whole origin.
    var origin = proxy_buffer_account.Aggregate.init(.origin, relay_bytes);
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    const limits = uploadTestLimits(1024 * 1024);
    const capacity = proxy_buffer_account.AggregateCapacity{ .origin = &origin, .global = &global };

    // One tracker across all three, so this measures relay memory held by the
    // process at once rather than per exchange. Safe to share: every field
    // update is under its lock.
    var tracker = LargestAllocationTracker{ .child = std.testing.allocator };

    var relays: [3]Http1ResponseRelay = undefined;
    for (&relays) |*relay| {
        relay.* = try Http1ResponseRelay.init(relay_bytes, limits, capacity);
        relay.allocator = tracker.allocator();
    }
    defer for (&relays) |*relay| relay.deinit();

    // None of them gets a complete response head, so an admitted relay parks
    // inside `readUpstreamHead` holding its reservation — the exact state the
    // cap has to bound.
    var threads: [3]std.Thread = undefined;
    for (&relays, 0..) |*relay, i| {
        relay.originSend("HTTP/1.1 200 OK\r\n");
        threads[i] = try std.Thread.spawn(.{}, Http1ResponseRelay.runCapturing, .{relay});
    }
    // Teardown must survive an early failure: finish the heads so parked
    // relays can complete, then join.
    defer for (&threads) |thread| thread.join();
    defer for (&relays) |*relay| {
        relay.originSend("Content-Length: 4\r\n\r\nbody");
        relay.originClose();
    };

    // Wait for the two refusals to land, then for the survivor to be holding
    // its buffer.
    var refused: usize = 0;
    var waited: u32 = 0;
    while (refused < 2 and waited < 30_000) : (waited += 5) {
        refused = 0;
        for (&relays) |*relay| {
            if (relay.finished.load(.acquire) and relay.err != null) refused += 1;
        }
        if (refused < 2) sleepMs(5);
    }
    try std.testing.expectEqual(@as(usize, 2), refused);

    // Exactly one relay buffer exists in the whole process. Before the
    // reordering all three allocated one and only then discovered the cap, so
    // this read 3 x 16 KiB.
    try std.testing.expectEqual(relay_bytes, tracker.peakLargeLive());
    try std.testing.expectEqual(relay_bytes, origin.currentBytes(.upstream_to_downstream));

    // The refusals are local capacity, raised before any response byte was
    // read into a buffer, let alone committed downstream.
    for (&relays) |*relay| {
        if (relay.err) |err| {
            try std.testing.expectEqual(@as(anyerror, error.ProxyBufferCapacityUnavailable), err);
            try std.testing.expectEqual(@as(usize, 0), relay.captured.items.len);
        }
    }

    // Let the survivor finish, and prove every scope drains.
    for (&relays) |*relay| {
        relay.originSend("Content-Length: 4\r\n\r\nbody");
    }
    for (&relays) |*relay| {
        var settle: u32 = 0;
        while (!relay.finished.load(.acquire) and settle < 30_000) : (settle += 5) sleepMs(5);
    }
    try std.testing.expectEqual(@as(usize, 0), origin.currentBytes(.upstream_to_downstream));
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.upstream_to_downstream));
    try std.testing.expectEqual(@as(usize, 0), tracker.large_live);
}

test "a cancelled http1 upload releases its origin reservation" {
    const fds = try makeBlockingSocketpair();
    const client_fd = fds[0];
    const peer_fd = fds[1];
    defer _ = std.c.close(client_fd);
    defer _ = std.c.close(peer_fd);

    var counters = UploadBufferObserver{};
    var origin = proxy_buffer_account.Aggregate.init(.origin, 64 * 1024);
    var global = proxy_buffer_account.Aggregate.init(.global, 0);

    var token = CancellationToken.init(0);
    token.cancel(.timeout);

    var source = FakeUploadSource{ .data = &[_]u8{'u'} ** 4096 };
    var reservation = try preflightUploadReservation(
        uploadTestLimits(1024 * 1024),
        counters.observer(),
        .{ .origin = &origin, .global = &global },
        http1_upload_relay_bytes,
        0,
    );
    defer reservation.releaseAll();
    try std.testing.expectEqual(@as(usize, http1_upload_relay_bytes), origin.currentBytes(.downstream_to_upstream));

    try std.testing.expectError(error.RequestCancelled, relayStreamingUploadToHttp1(
        compat.netStreamFromFd(client_fd),
        client_fd,
        .{ .framing = .{ .length = 4096 } },
        &source,
        &token,
        &reservation,
        counters.observer(),
    ));

    reservation.releaseAll();
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
    try std.testing.expectEqual(@as(usize, 0), origin.currentBytes(.downstream_to_upstream));
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));
}

// ---------------------------------------------------------------------------
// HTTP/2 response relay buffer accounting (#140).
// ---------------------------------------------------------------------------

/// An h2c origin that answers with a head plus one DATA frame and then holds
/// `END_STREAM` back. That leaves a stream whose queue is non-empty while the
/// relay is working, which is the state where the queue and the relay buffer
/// are two application-owned copies of the same bytes.
const H2GatedBodyOrigin = struct {
    listen_fd: std.posix.fd_t,
    release_end: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

fn h2GatedBodyServe(origin: *H2GatedBodyOrigin) void {
    const conn = std.c.accept(origin.listen_fd, null, null);
    if (conn < 0) return;
    defer _ = std.c.close(conn);

    var preface: [24]u8 = undefined;
    if (!readExactlyFromFd(conn, &preface)) return;
    const settings = [_]u8{ 0, 0, 0, 0x04, 0, 0, 0, 0, 0 };
    _ = std.c.write(conn, &settings, settings.len);

    var stream_id: u32 = 0;
    while (stream_id == 0) {
        var hdr: [9]u8 = undefined;
        if (!readExactlyFromFd(conn, &hdr)) return;
        const payload_len = (@as(usize, hdr[0]) << 16) | (@as(usize, hdr[1]) << 8) | @as(usize, hdr[2]);
        const typ = hdr[3];
        const sid = std.mem.readInt(u32, hdr[5..9], .big) & 0x7fff_ffff;
        var scratch: [4096]u8 = undefined;
        var remaining = payload_len;
        while (remaining > 0) {
            const take = @min(remaining, scratch.len);
            if (!readExactlyFromFd(conn, scratch[0..take])) return;
            remaining -= take;
        }
        if (typ == 0x01) stream_id = sid; // HEADERS
    }

    var head_frame = [_]u8{ 0, 0, 1, 0x01, 0x04, 0, 0, 0, 0, 0x88 };
    std.mem.writeInt(u32, head_frame[5..9], stream_id, .big);
    _ = std.c.write(conn, &head_frame, head_frame.len);

    // DATA without END_STREAM: the relay has bytes to move but the message is
    // not over, so the stream stays alive while the downstream write blocks.
    var body_frame = [_]u8{ 0, 0, 2, 0x00, 0x00, 0, 0, 0, 0, 'h', 'i' };
    std.mem.writeInt(u32, body_frame[5..9], stream_id, .big);
    _ = std.c.write(conn, &body_frame, body_frame.len);

    while (!origin.release_end.load(.acquire)) sleepMs(5);

    var end_frame = [_]u8{ 0, 0, 0, 0x00, 0x01, 0, 0, 0, 0 };
    std.mem.writeInt(u32, end_frame[5..9], stream_id, .big);
    _ = std.c.write(conn, &end_frame, end_frame.len);

    var drain: [256]u8 = undefined;
    while (true) {
        const got = std.c.read(conn, &drain, drain.len);
        if (got <= 0) break;
    }
}

/// A downstream client that stops reading once the response head has arrived,
/// standing in for a slow consumer. It parks the relay inside the body write —
/// after the bytes have been copied into the relay buffer and before
/// `acknowledgeStreamingBody` releases the queue's reservation, which is
/// exactly the window where both copies are owned at once.
const GatedChunkWriter = struct {
    captured: *std.array_list.Managed(u8),
    head_done: *std.atomic.Value(bool),
    blocked: *std.atomic.Value(bool),
    release: *std.atomic.Value(bool),

    fn gate(self: GatedChunkWriter) void {
        if (!self.head_done.load(.acquire)) return;
        self.blocked.store(true, .release);
        while (!self.release.load(.acquire)) sleepMs(2);
    }

    fn noteHeadEnd(self: GatedChunkWriter) void {
        if (std.mem.endsWith(u8, self.captured.items, "\r\n\r\n")) self.head_done.store(true, .release);
    }

    pub fn writeAll(self: GatedChunkWriter, bytes: []const u8) !void {
        self.gate();
        try self.captured.appendSlice(bytes);
        self.noteHeadEnd();
    }

    pub fn print(self: GatedChunkWriter, comptime fmt: []const u8, args: anytype) !void {
        self.gate();
        var buf: [64]u8 = undefined;
        try self.captured.appendSlice(try std.fmt.bufPrint(&buf, fmt, args));
        self.noteHeadEnd();
    }
};

const H2GatedExchangeCtx = struct {
    pool: *http.upstream_h2.H2ConnPool,
    port: u16,
    uri: std.Uri,
    /// The size the exchange's config asks for; `streamViaH2Pool` allocates.
    read_buf_bytes: usize,
    captured: *std.array_list.Managed(u8),
    security: *const http.security_headers.SecurityHeaders,
    limits: proxy_buffer_account.Limits,
    observer: proxy_buffer_account.Observer,
    global: *proxy_buffer_account.Aggregate,
    head_done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    blocked: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    release: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    finished: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    failed: bool = false,
    status: u16 = 0,
};

fn runH2GatedExchangeThread(ctx: *H2GatedExchangeCtx) void {
    defer ctx.finished.store(true, .release);
    var source = FakeUploadSource{ .data = "" };
    var downstream_committed = false;
    const result = streamViaH2Pool(
        std.testing.allocator,
        ctx.pool,
        null,
        "127.0.0.1",
        ctx.port,
        null, // prior-knowledge h2c
        ctx.uri,
        "GET",
        &.{},
        "",
        null, // no upload: this is about the response relay buffer
        ctx.read_buf_bytes,
        &source,
        GatedChunkWriter{
            .captured = ctx.captured,
            .head_done = &ctx.head_done,
            .blocked = &ctx.blocked,
            .release = &ctx.release,
        },
        ctx.security,
        null,
        null,
        "h2-response-buffer-test",
        true,
        2000,
        10_000,
        null,
        ctx.limits,
        ctx.observer,
        ctx.global,
        &downstream_committed,
    ) catch {
        ctx.failed = true;
        return;
    };
    ctx.status = result.status_code;
}

/// Wait (bounded) for a gated exchange thread to finish. Used where the test
/// wants the exchange's result before its own deferred join runs.
fn waitForExchange(ctx: *H2GatedExchangeCtx) void {
    var waited: u32 = 0;
    while (!ctx.finished.load(.acquire) and waited < 30_000) : (waited += 5) sleepMs(5);
}

test "an http2 response relay buffer is charged to the aggregate scopes while it relays" {
    const listener = try listenLoopbackEphemeral();
    defer _ = std.c.close(listener.fd);

    var origin_server = H2GatedBodyOrigin{ .listen_fd = listener.fd };
    const origin_thread = try std.Thread.spawn(.{}, h2GatedBodyServe, .{&origin_server});

    // Large enough that the stream queue's own retained allocation for two
    // body bytes cannot be mistaken for it.
    const read_buf_bytes: usize = 64 * 1024;
    const limits = uploadTestLimits(1024 * 1024);
    // Room for two relay buffers. One is what the exchange takes; the second
    // is what a concurrent response would need, and must no longer be
    // available while this one is relaying.
    var global = proxy_buffer_account.Aggregate.init(.global, 2 * read_buf_bytes);

    var counters = UploadBufferObserver{};
    var captured = std.array_list.Managed(u8).init(std.testing.allocator);
    defer captured.deinit();
    var security = http.security_headers.SecurityHeaders{};
    var url_buf: [64]u8 = undefined;
    const uri = try std.Uri.parse(try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/download", .{listener.port}));

    var pool = http.upstream_h2.H2ConnPool.init(std.testing.allocator, .{
        .proxy_buffer_limits = blk: {
            var origin_limits = limits;
            origin_limits.per_origin_hard_limit = 2 * read_buf_bytes;
            break :blk origin_limits;
        },
    });
    defer origin_thread.join();
    defer pool.deinit();
    // The same account the exchange will reserve against: the pool hands out a
    // pointer that is stable for its lifetime, so reading it here observes the
    // origin scope the relay is actually charged to rather than a stand-in.
    var origin_key_buf: [64]u8 = undefined;
    const origin_key = try std.fmt.bufPrint(&origin_key_buf, "h2c:127.0.0.1:{d}", .{listener.port});
    const origin = try pool.originBufferAccount(origin_key);

    var ctx = H2GatedExchangeCtx{
        .pool = &pool,
        .port = listener.port,
        .uri = uri,
        .read_buf_bytes = read_buf_bytes,
        .captured = &captured,
        .security = &security,
        .limits = limits,
        .observer = counters.observer(),
        .global = &global,
    };
    const exchange = try std.Thread.spawn(.{}, runH2GatedExchangeThread, .{&ctx});
    // Teardown has to survive an early assertion failure below, or the pool is
    // destroyed while the exchange is still using it. Declared so they run as:
    // open the gates, join the exchange, destroy the pool, join the origin
    // (which only exits once the pool closes the connection).
    defer exchange.join();
    defer {
        ctx.release.store(true, .release);
        origin_server.release_end.store(true, .release);
    }

    // The client has the head and has stopped reading; the relay is parked
    // inside the body write, holding the relay buffer, with the queue's
    // reservation not yet acknowledged.
    var waited: u32 = 0;
    while (!ctx.blocked.load(.acquire) and waited < 30_000) : (waited += 5) sleepMs(5);
    try std.testing.expect(ctx.blocked.load(.acquire));

    // The relay buffer is represented in the process aggregate. Before it was
    // charged, this read only the stream queue's retained bytes for a two-byte
    // body, which is nowhere near a relay buffer.
    try std.testing.expect(global.currentBytes(.upstream_to_downstream) >= read_buf_bytes);
    // The origin scope carries it too, so one slow origin's relay buffers are
    // contained by its own limit and not only by the process ceiling.
    try std.testing.expect(origin.currentBytes(.upstream_to_downstream) >= read_buf_bytes);

    // And the ceiling actually accounts for it: a concurrent response needing
    // its own relay buffer no longer fits, which is the whole point — N slow
    // responses used to be able to hold N relay buffers beyond the configured
    // limit with nothing in the accounting to show for it.
    var other = UploadBufferObserver{};
    var concurrent = ProxyBufferReservation.init(
        .upstream_to_downstream,
        limits,
        other.observer(),
        .{ .global = &global },
    );
    try std.testing.expectError(
        error.ProxyBufferCapacityUnavailable,
        concurrent.reserve(read_buf_bytes),
    );
    try std.testing.expectEqual(@as(u64, 1), other.aggregate_limit_exceeded);

    // Let the client drain and the origin finish the message.
    ctx.release.store(true, .release);
    origin_server.release_end.store(true, .release);
    waitForExchange(&ctx);
    try std.testing.expect(!ctx.failed);
    try std.testing.expectEqual(@as(u16, 200), ctx.status);

    // Every scope returns to zero once the exchange ends. The origin accounts
    // live in the pool, so they are read before the deferred `pool.deinit()`.
    try std.testing.expectEqual(@as(usize, 0), origin.currentBytes(.upstream_to_downstream));
    try std.testing.expectEqual(@as(usize, 0), origin.currentBytes(.downstream_to_upstream));

    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.upstream_to_downstream));
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.downstream_to_upstream));
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
    // The body really did reach the client, so this measured a working relay.
    try std.testing.expect(std.mem.find(u8, captured.items, "hi") != null);
}

test "an http2 stream cannot own more than its per-stream hard limit across queue and relay" {
    // The queue and the relay buffer are live at the same time, so each having
    // its own per-stream budget let one stream own two hard limits' worth with
    // neither budget reporting an exceedance. They now share one.
    const listener = try listenLoopbackEphemeral();
    defer _ = std.c.close(listener.fd);

    var origin_server = H2GatedBodyOrigin{ .listen_fd = listener.fd };
    const origin_thread = try std.Thread.spawn(.{}, h2GatedBodyServe, .{&origin_server});

    const read_buf_bytes: usize = 16 * 1024;
    // A policy sized exactly the way config validation now requires: the hard
    // limit covers one full window plus one relay buffer, and no more. That
    // makes the shared budget's ceiling observable — anything above
    // `high + relay` would have to come from double-budgeting.
    const high = 16 * 1024;
    const limits = proxy_buffer_account.Limits{
        .per_stream_low_watermark = high / 2,
        .per_stream_high_watermark = high,
        .per_stream_hard_limit = high + read_buf_bytes,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    };
    // Generous aggregates: this test is about the per-stream budget, so
    // nothing else may be what refuses.
    var global = proxy_buffer_account.Aggregate.init(.global, 0);

    var counters = UploadBufferObserver{};
    var captured = std.array_list.Managed(u8).init(std.testing.allocator);
    defer captured.deinit();
    var security = http.security_headers.SecurityHeaders{};
    var url_buf: [64]u8 = undefined;
    const uri = try std.Uri.parse(try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/download", .{listener.port}));

    var pool = http.upstream_h2.H2ConnPool.init(std.testing.allocator, .{ .proxy_buffer_limits = limits });
    defer origin_thread.join();
    defer pool.deinit();
    var ctx = H2GatedExchangeCtx{
        .pool = &pool,
        .port = listener.port,
        .uri = uri,
        .read_buf_bytes = read_buf_bytes,
        .captured = &captured,
        .security = &security,
        .limits = limits,
        .observer = counters.observer(),
        .global = &global,
    };
    const exchange = try std.Thread.spawn(.{}, runH2GatedExchangeThread, .{&ctx});
    defer exchange.join();
    defer {
        ctx.release.store(true, .release);
        origin_server.release_end.store(true, .release);
    }

    var waited: u32 = 0;
    while (!ctx.blocked.load(.acquire) and waited < 30_000) : (waited += 5) sleepMs(5);
    try std.testing.expect(ctx.blocked.load(.acquire));

    // Parked mid-relay with both copies owned. The process gauge sees the
    // relay buffer and the queue's retained storage together, and that total
    // must be inside the one per-stream hard limit rather than inside two.
    const owned = global.currentBytes(.upstream_to_downstream);
    try std.testing.expect(owned >= read_buf_bytes); // the relay buffer is in there
    try std.testing.expect(owned <= limits.per_stream_hard_limit);

    ctx.release.store(true, .release);
    origin_server.release_end.store(true, .release);
    waitForExchange(&ctx);
    try std.testing.expect(!ctx.failed);
    try std.testing.expectEqual(@as(u16, 200), ctx.status);

    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.upstream_to_downstream));
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
}

test "a stream queue's hard limit is reduced by the relay buffer it coexists with" {
    // The queue and the response relay buffer are live at the same time, so
    // the per-stream hard limit has to cover both. That is enforced by holding
    // the relay's size back from the queue's own limit rather than by sharing
    // a budget object between a worker and the connection's reader thread.
    const relay_bytes: usize = 16 * 1024;
    const limits = proxy_buffer_account.Limits{
        .per_stream_low_watermark = 8 * 1024,
        .per_stream_high_watermark = 16 * 1024,
        .per_stream_hard_limit = 16 * 1024 + relay_bytes,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    };

    var queue_limits = limits;
    queue_limits.per_stream_hard_limit -|= relay_bytes;
    var queue = proxy_buffer_account.Account.init(.upstream_to_downstream, .stream, queue_limits);

    // The queue still has room for a full receive window, which is what config
    // validation's `hard >= high + relay` rule guarantees.
    try queue.reserve(limits.per_stream_high_watermark);
    // But not for the relay buffer's share on top: together they would exceed
    // the configured per-stream hard limit.
    try std.testing.expectError(error.BufferLimitExceeded, queue.reserve(relay_bytes));
    try std.testing.expectEqual(@as(u64, 1), queue.snapshot().limit_exceeded_events);

    // Queue + relay is exactly the configured limit, never more.
    try std.testing.expectEqual(
        limits.per_stream_hard_limit,
        queue_limits.per_stream_hard_limit + relay_bytes,
    );
    queue.releaseAll();
}

/// The multi-stream form of `h2GatedBodyServe`: serves `stream_count` requests
/// on **one** connection, so a test can reuse a pooled connection across a
/// reload. Each response is a head plus one DATA frame, with `END_STREAM` held
/// back until released.
const H2GatedMultiOrigin = struct {
    listen_fd: std.posix.fd_t,
    stream_count: usize,
    release_end: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

fn h2GatedMultiServe(origin: *H2GatedMultiOrigin) void {
    const conn = std.c.accept(origin.listen_fd, null, null);
    if (conn < 0) return;
    defer _ = std.c.close(conn);

    var preface: [24]u8 = undefined;
    if (!readExactlyFromFd(conn, &preface)) return;
    const settings = [_]u8{ 0, 0, 0, 0x04, 0, 0, 0, 0, 0 };
    _ = std.c.write(conn, &settings, settings.len);

    var served: usize = 0;
    while (served < origin.stream_count) : (served += 1) {
        var stream_id: u32 = 0;
        while (stream_id == 0) {
            var hdr: [9]u8 = undefined;
            if (!readExactlyFromFd(conn, &hdr)) return;
            const payload_len = (@as(usize, hdr[0]) << 16) | (@as(usize, hdr[1]) << 8) | @as(usize, hdr[2]);
            const typ = hdr[3];
            const sid = std.mem.readInt(u32, hdr[5..9], .big) & 0x7fff_ffff;
            var scratch: [4096]u8 = undefined;
            var remaining = payload_len;
            while (remaining > 0) {
                const take = @min(remaining, scratch.len);
                if (!readExactlyFromFd(conn, scratch[0..take])) return;
                remaining -= take;
            }
            if (typ == 0x01) stream_id = sid;
        }

        var head_frame = [_]u8{ 0, 0, 1, 0x01, 0x04, 0, 0, 0, 0, 0x88 };
        std.mem.writeInt(u32, head_frame[5..9], stream_id, .big);
        _ = std.c.write(conn, &head_frame, head_frame.len);

        var body_frame = [_]u8{ 0, 0, 2, 0x00, 0x00, 0, 0, 0, 0, 'h', 'i' };
        std.mem.writeInt(u32, body_frame[5..9], stream_id, .big);
        _ = std.c.write(conn, &body_frame, body_frame.len);

        // The last stream is the one the test parks on; earlier ones complete
        // straight away so the connection lands back in the pool.
        if (served + 1 == origin.stream_count) {
            while (!origin.release_end.load(.acquire)) sleepMs(5);
        }
        var end_frame = [_]u8{ 0, 0, 0, 0x00, 0x01, 0, 0, 0, 0 };
        std.mem.writeInt(u32, end_frame[5..9], stream_id, .big);
        _ = std.c.write(conn, &end_frame, end_frame.len);
    }

    var drain: [256]u8 = undefined;
    while (true) {
        const got = std.c.read(conn, &drain, drain.len);
        if (got <= 0) break;
    }
}

test "a stream on a pooled http2 connection is judged by the policy that connection pinned" {
    // A pooled connection outlives a reload, and the queue is deliberately
    // judged by the policy the connection advertised. Anything the caller
    // sizes from its own config snapshot would put the same stream under two
    // generations of policy at once — larger or smaller than the connection's,
    // depending on which way the reload went — so the outcome would depend on
    // whether the request happened to reuse a pre-reload connection.
    const listener = try listenLoopbackEphemeral();
    defer _ = std.c.close(listener.fd);

    var origin_server = H2GatedMultiOrigin{ .listen_fd = listener.fd, .stream_count = 2 };
    const origin_thread = try std.Thread.spawn(.{}, h2GatedMultiServe, .{&origin_server});

    // Policy A pins the connection. Its hard limit leaves exactly one 16 KiB
    // relay buffer above the window, which is the tightest validation allows.
    const relay_bytes = 16 * 1024;
    const policy_a = proxy_buffer_account.Limits{
        .per_stream_low_watermark = 8 * 1024,
        .per_stream_high_watermark = relay_bytes,
        .per_stream_hard_limit = relay_bytes * 2,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    };
    // Policy B is four times larger in every dimension. If any per-stream
    // decision came from the caller's snapshot it would be visibly bigger than
    // what A allows.
    const policy_b = proxy_buffer_account.Limits{
        .per_stream_low_watermark = 32 * 1024,
        .per_stream_high_watermark = 64 * 1024,
        .per_stream_hard_limit = 128 * 1024,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    };

    // Sized from B's larger `proxy_stream_buffer_size`, as a post-reload
    // request would ask for.
    const read_buf_bytes: usize = 64 * 1024;
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    var counters = UploadBufferObserver{};
    var captured = std.array_list.Managed(u8).init(std.testing.allocator);
    defer captured.deinit();
    var security = http.security_headers.SecurityHeaders{};
    var url_buf: [64]u8 = undefined;
    const uri = try std.Uri.parse(try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/download", .{listener.port}));

    var pool = http.upstream_h2.H2ConnPool.init(std.testing.allocator, .{ .proxy_buffer_limits = policy_a });
    defer origin_thread.join();
    defer pool.deinit();

    // Exchange one opens the connection under A and completes, returning it to
    // the pool.
    var first_captured = std.array_list.Managed(u8).init(std.testing.allocator);
    defer first_captured.deinit();
    var first = H2GatedExchangeCtx{
        .pool = &pool,
        .port = listener.port,
        .uri = uri,
        .read_buf_bytes = read_buf_bytes,
        .captured = &first_captured,
        .security = &security,
        .limits = policy_a,
        .observer = counters.observer(),
        .global = &global,
    };
    first.release.store(true, .release); // never park this one
    origin_server.release_end.store(false, .release);
    runH2GatedExchangeThread(&first);
    try std.testing.expect(!first.failed);
    try std.testing.expectEqual(@as(u16, 200), first.status);

    // Reload to B. The pool's *new* connections would get B; this one keeps A.
    pool.setProxyBufferLimits(policy_b);
    try std.testing.expectEqual(policy_b, pool.currentProxyBufferLimits());

    // Exchange two runs with B as its config snapshot but reuses the
    // A-pinned connection, and parks mid-relay so the accounting is readable.
    var second = H2GatedExchangeCtx{
        .pool = &pool,
        .port = listener.port,
        .uri = uri,
        .read_buf_bytes = read_buf_bytes,
        .captured = &captured,
        .security = &security,
        .limits = policy_b,
        .observer = counters.observer(),
        .global = &global,
    };
    const exchange = try std.Thread.spawn(.{}, runH2GatedExchangeThread, .{&second});
    // Teardown must survive an early assertion failure, or the pool is
    // destroyed while the exchange is still using it.
    defer exchange.join();
    defer {
        second.release.store(true, .release);
        origin_server.release_end.store(true, .release);
    }

    var waited: u32 = 0;
    while (!second.blocked.load(.acquire) and waited < 30_000) : (waited += 5) sleepMs(5);
    try std.testing.expect(second.blocked.load(.acquire));

    // Everything this stream owns is inside A's hard limit, not B's. Sourcing
    // the budget or the relay size from the caller's snapshot would show up
    // here as a relay buffer of B's 64 KiB rather than the 16 KiB A can cover.
    const owned = global.currentBytes(.upstream_to_downstream);
    try std.testing.expect(owned >= relay_bytes);
    try std.testing.expect(owned <= policy_a.per_stream_hard_limit);
    try std.testing.expect(owned < policy_b.per_stream_hard_limit);

    second.release.store(true, .release);
    origin_server.release_end.store(true, .release);
    waitForExchange(&second);
    try std.testing.expect(!second.failed);
    try std.testing.expectEqual(@as(u16, 200), second.status);

    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.upstream_to_downstream));
    try std.testing.expectEqual(@as(usize, 0), counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), counters.retained);
}

/// Remembers the largest single allocation made through it. The relay buffer is
/// by far the biggest thing a streaming exchange allocates, so this observes
/// the size actually taken from the heap rather than the size the caller meant
/// to use — the distinction between a buffer that is *sized* to the accounted
/// amount and one that is merely *sliced* down to it.
const LargestAllocationTracker = struct {
    child: std.mem.Allocator,
    largest: usize = 0,
    /// Relay-sized allocations currently live, and the high-water mark of that.
    /// Tracked separately from `largest` because the question "did N concurrent
    /// requests each allocate a relay buffer" is about *concurrent* ownership,
    /// which a largest-single-allocation figure cannot answer. Small
    /// allocations are ignored so header and arena churn cannot drown the
    /// signal.
    large_live: usize = 0,
    peak_large_live: usize = 0,
    /// Fail any allocation at or above the relay threshold once this is set,
    /// so a test can drive the out-of-memory path at exactly the relay buffer.
    fail_large: bool = false,
    large_threshold: usize = min_proxy_relay_bytes,
    mutex: compat.Mutex = .{},

    fn allocator(self: *LargestAllocationTracker) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    /// Every field update goes through here under the lock. `largest` is not
    /// read concurrently by today's tests, but unsynchronized writes from
    /// several exchange threads are a race regardless of who reads them.
    fn noteAlloc(self: *LargestAllocationTracker, len: usize) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.largest = @max(self.largest, len);
        if (len < self.large_threshold) return;
        self.large_live += len;
        self.peak_large_live = @max(self.peak_large_live, self.large_live);
    }

    fn noteFree(self: *LargestAllocationTracker, len: usize) void {
        if (len < self.large_threshold) return;
        self.mutex.lock();
        defer self.mutex.unlock();
        self.large_live -= @min(self.large_live, len);
    }

    fn largestAllocation(self: *LargestAllocationTracker) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.largest;
    }

    fn peakLargeLive(self: *LargestAllocationTracker) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.peak_large_live;
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *LargestAllocationTracker = @ptrCast(@alignCast(ctx));
        if (self.fail_large and len >= self.large_threshold) return null;
        const ptr = self.child.rawAlloc(len, alignment, ret_addr) orelse return null;
        self.noteAlloc(len);
        return ptr;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *LargestAllocationTracker = @ptrCast(@alignCast(ctx));
        if (!self.child.rawResize(memory, alignment, new_len, ret_addr)) return false;
        self.noteFree(memory.len);
        self.noteAlloc(new_len);
        return true;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *LargestAllocationTracker = @ptrCast(@alignCast(ctx));
        const ptr = self.child.rawRemap(memory, alignment, new_len, ret_addr) orelse return null;
        self.noteFree(memory.len);
        self.noteAlloc(new_len);
        return ptr;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *LargestAllocationTracker = @ptrCast(@alignCast(ctx));
        self.noteFree(memory.len);
        self.child.rawFree(memory, alignment, ret_addr);
    }

    const vtable = std.mem.Allocator.VTable{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };
};

const H2TrackedExchangeCtx = struct {
    allocator: std.mem.Allocator,
    pool: *http.upstream_h2.H2ConnPool,
    port: u16,
    uri: std.Uri,
    read_buf_bytes: usize,
    captured: *std.array_list.Managed(u8),
    security: *const http.security_headers.SecurityHeaders,
    limits: proxy_buffer_account.Limits,
    /// Owned per exchange rather than shared: `UploadBufferObserver` keeps
    /// plain counters, and several of these run concurrently, where a shared
    /// one would race its own subtraction into a wrap.
    counters: UploadBufferObserver = .{},
    global: *proxy_buffer_account.Aggregate,
    finished: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    failed: bool = false,
    err: ?anyerror = null,
    status: u16 = 0,
};

fn runH2TrackedExchange(ctx: *H2TrackedExchangeCtx) void {
    defer ctx.finished.store(true, .release);
    var source = FakeUploadSource{ .data = "" };
    var downstream_committed = false;
    const result = streamViaH2Pool(
        ctx.allocator,
        ctx.pool,
        null,
        "127.0.0.1",
        ctx.port,
        null, // prior-knowledge h2c
        ctx.uri,
        "GET",
        &.{},
        "",
        null,
        ctx.read_buf_bytes,
        &source,
        CaptureWriter{ .list = ctx.captured },
        ctx.security,
        null,
        null,
        "h2-allocation-test",
        true,
        2000,
        10_000,
        null,
        ctx.limits,
        ctx.counters.observer(),
        ctx.global,
        &downstream_committed,
    ) catch |err| {
        ctx.failed = true;
        ctx.err = err;
        return;
    };
    ctx.status = result.status_code;
}

test "an http2 relay buffer allocates exactly what it accounts across a buffer-size reload" {
    // Capping the *slice* is not enough: the allocation is what costs memory.
    // A reload that grows `proxy_stream_buffer_size` must not let a request on
    // an older connection allocate the larger buffer and charge only the part
    // its pinned policy covers — with N concurrent streams that is precisely
    // the retained-but-unaccounted allocation these limits exist to bound.
    const listener = try listenLoopbackEphemeral();
    defer _ = std.c.close(listener.fd);

    var origin_server = H2GatedMultiOrigin{ .listen_fd = listener.fd, .stream_count = 2 };
    origin_server.release_end.store(true, .release); // neither stream parks
    const origin_thread = try std.Thread.spawn(.{}, h2GatedMultiServe, .{&origin_server});

    const pinned_relay_bytes: usize = 16 * 1024;
    const policy_a = proxy_buffer_account.Limits{
        .per_stream_low_watermark = 8 * 1024,
        .per_stream_high_watermark = pinned_relay_bytes,
        .per_stream_hard_limit = pinned_relay_bytes * 2,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    };
    const policy_b = proxy_buffer_account.Limits{
        .per_stream_low_watermark = 256 * 1024,
        .per_stream_high_watermark = 512 * 1024,
        .per_stream_hard_limit = 2 * 1024 * 1024,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    };

    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    var captured = std.array_list.Managed(u8).init(std.testing.allocator);
    defer captured.deinit();
    var security = http.security_headers.SecurityHeaders{};
    var url_buf: [64]u8 = undefined;
    const uri = try std.Uri.parse(try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/download", .{listener.port}));

    // Ordered so the pool tears connections down before the origin thread is
    // joined, and so an assertion failure below still cleans up rather than
    // reporting the connection as a leak.
    var pool = http.upstream_h2.H2ConnPool.init(std.testing.allocator, .{ .proxy_buffer_limits = policy_a });
    defer origin_thread.join();
    defer pool.deinit();

    // First exchange pins the connection to A, under A's own buffer size.
    var warm_captured = std.array_list.Managed(u8).init(std.testing.allocator);
    defer warm_captured.deinit();
    var warm = H2TrackedExchangeCtx{
        .allocator = std.testing.allocator,
        .pool = &pool,
        .port = listener.port,
        .uri = uri,
        .read_buf_bytes = pinned_relay_bytes,
        .captured = &warm_captured,
        .security = &security,
        .limits = policy_a,
        .global = &global,
    };
    runH2TrackedExchange(&warm);
    try std.testing.expect(!warm.failed);
    try std.testing.expectEqual(@as(u16, 200), warm.status);

    // Reload to a policy whose buffer size is 64x larger, then reuse the
    // A-pinned connection.
    pool.setProxyBufferLimits(policy_b);
    const reloaded_relay_bytes: usize = 1024 * 1024;

    var tracker = LargestAllocationTracker{ .child = std.testing.allocator };
    var tracked = H2TrackedExchangeCtx{
        .allocator = tracker.allocator(),
        .pool = &pool,
        .port = listener.port,
        .uri = uri,
        .read_buf_bytes = reloaded_relay_bytes,
        .captured = &captured,
        .security = &security,
        .limits = policy_b,
        .global = &global,
    };
    runH2TrackedExchange(&tracked);
    try std.testing.expect(!tracked.failed);
    try std.testing.expectEqual(@as(u16, 200), tracked.status);

    // What was taken from the heap is what the pinned policy accounts for —
    // not the 1 MiB the reloaded config asked for. Slicing a 1 MiB allocation
    // down to 16 KiB would leave this reading 1 MiB.
    try std.testing.expectEqual(pinned_relay_bytes, tracker.largestAllocation());
    try std.testing.expect(tracker.largestAllocation() < reloaded_relay_bytes);
    // And that allocation is what was charged. (The peak also carries the
    // stream queue's couple of body bytes, so this is a band rather than an
    // equality — the point is that it tracks the pinned size, not the 1 MiB
    // the reloaded config asked for.)
    try std.testing.expect(tracked.counters.peak_reserved >= pinned_relay_bytes);
    try std.testing.expect(tracked.counters.peak_reserved < reloaded_relay_bytes);

    try std.testing.expectEqual(@as(usize, 0), tracked.counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), tracked.counters.retained);
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.upstream_to_downstream));
}

test "a pinned policy with no relay headroom refuses rather than truncating silently" {
    // Config validation makes this policy unreachable, but `Limits` can be
    // built directly. The sizing arithmetic must not be able to produce a
    // zero-length relay buffer: `readStreamingBody` would return 0, the relay
    // would read that as end of body, and the response would be truncated with
    // nothing logged and no metric moved. Flooring turns it into an ordinary
    // over-budget refusal instead.
    const airless = proxy_buffer_account.Limits{
        .per_stream_low_watermark = 8 * 1024,
        .per_stream_high_watermark = 16 * 1024,
        .per_stream_hard_limit = 16 * 1024, // high == hard: no headroom at all
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    };
    const headroom = airless.per_stream_hard_limit -| airless.per_stream_high_watermark;
    try std.testing.expectEqual(@as(usize, 0), headroom);
    const sized = @max(@min(@as(usize, 64 * 1024), headroom), min_proxy_relay_bytes);
    try std.testing.expectEqual(min_proxy_relay_bytes, sized);

    // And with no headroom, the queue's own limit is reduced to nothing by the
    // relay it has to coexist with, so the very first queued byte is refused
    // rather than the response being silently cut short.
    var queue_limits = airless;
    queue_limits.per_stream_hard_limit -|= sized;
    try std.testing.expectEqual(@as(usize, 0), queue_limits.per_stream_hard_limit);
    var queue = proxy_buffer_account.Account.init(.upstream_to_downstream, .stream, queue_limits);
    try std.testing.expectError(error.BufferLimitExceeded, queue.reserve(1));
    try std.testing.expectEqual(@as(u64, 1), queue.snapshot().limit_exceeded_events);
}

/// An h2c origin that accepts `stream_count` requests and answers none of them
/// until released. That parks every exchange in the window between acquiring a
/// connection and knowing the response head — the window where a relay buffer
/// must not yet exist.
const H2SilentHeadOrigin = struct {
    listen_fd: std.posix.fd_t,
    /// Streams answered immediately, to establish the pooled connection before
    /// the concurrent phase. Without this the concurrent exchanges race to
    /// create the connection and the losers sit in the listen backlog of a
    /// fixture that only ever accepts one.
    warm_count: usize,
    stream_count: usize,
    seen: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    release: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

/// Read one frame header + payload, reporting its type and stream id.
fn h2ReadFrame(conn: std.posix.fd_t) ?struct { typ: u8, stream_id: u32 } {
    var hdr: [9]u8 = undefined;
    if (!readExactlyFromFd(conn, &hdr)) return null;
    const payload_len = (@as(usize, hdr[0]) << 16) | (@as(usize, hdr[1]) << 8) | @as(usize, hdr[2]);
    const typ = hdr[3];
    const sid = std.mem.readInt(u32, hdr[5..9], .big) & 0x7fff_ffff;
    var scratch: [4096]u8 = undefined;
    var remaining = payload_len;
    while (remaining > 0) {
        const take = @min(remaining, scratch.len);
        if (!readExactlyFromFd(conn, scratch[0..take])) return null;
        remaining -= take;
    }
    return .{ .typ = typ, .stream_id = sid };
}

fn h2AnswerBodiless(conn: std.posix.fd_t, stream_id: u32) void {
    var head_frame = [_]u8{ 0, 0, 1, 0x01, 0x04, 0, 0, 0, 0, 0x88 };
    std.mem.writeInt(u32, head_frame[5..9], stream_id, .big);
    _ = std.c.write(conn, &head_frame, head_frame.len);
    var end_frame = [_]u8{ 0, 0, 0, 0x00, 0x01, 0, 0, 0, 0 };
    std.mem.writeInt(u32, end_frame[5..9], stream_id, .big);
    _ = std.c.write(conn, &end_frame, end_frame.len);
}

fn h2SilentHeadServe(origin: *H2SilentHeadOrigin) void {
    const conn = std.c.accept(origin.listen_fd, null, null);
    if (conn < 0) return;
    defer _ = std.c.close(conn);

    var preface: [24]u8 = undefined;
    if (!readExactlyFromFd(conn, &preface)) return;
    const settings = [_]u8{ 0, 0, 0, 0x04, 0, 0, 0, 0, 0 };
    _ = std.c.write(conn, &settings, settings.len);

    // Warm-up: answer immediately so the connection lands back in the pool and
    // the concurrent phase below is guaranteed to reuse it.
    var warmed: usize = 0;
    while (warmed < origin.warm_count) {
        const frame = h2ReadFrame(conn) orelse return;
        if (frame.typ != 0x01) continue;
        h2AnswerBodiless(conn, frame.stream_id);
        warmed += 1;
    }

    // Concurrent phase: collect every request and answer none of them until
    // released, parking each exchange between acquiring the connection and
    // learning its response head.
    var ids: [8]u32 = undefined;
    var count: usize = 0;
    while (count < origin.stream_count and count < ids.len) {
        const frame = h2ReadFrame(conn) orelse return;
        if (frame.typ != 0x01) continue;
        ids[count] = frame.stream_id;
        count += 1;
        origin.seen.store(count, .release);
    }

    while (!origin.release.load(.acquire)) sleepMs(5);
    for (ids[0..count]) |sid| h2AnswerBodiless(conn, sid);

    var drain: [256]u8 = undefined;
    while (true) {
        const got = std.c.read(conn, &drain, drain.len);
        if (got <= 0) break;
    }
}

test "http2 relay memory is not allocated until a reservation admits it" {
    // The peak this bound exists to prevent happens *before* the refusal if
    // allocation runs first: every concurrent request to a slow-to-answer
    // origin would take a relay buffer while none had charged a scope yet, and
    // the aggregate cap could not stop the process holding all of them.
    const listener = try listenLoopbackEphemeral();
    defer _ = std.c.close(listener.fd);

    const concurrency = 3;
    var origin_server = H2SilentHeadOrigin{
        .listen_fd = listener.fd,
        .warm_count = 1,
        .stream_count = concurrency,
    };
    const origin_thread = try std.Thread.spawn(.{}, h2SilentHeadServe, .{&origin_server});

    const relay_bytes: usize = 32 * 1024;
    const limits = proxy_buffer_account.Limits{
        .per_stream_low_watermark = 8 * 1024,
        .per_stream_high_watermark = 16 * 1024,
        .per_stream_hard_limit = 16 * 1024 + relay_bytes,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    };
    // Room for exactly one relay buffer across the whole process.
    var global = proxy_buffer_account.Aggregate.init(.global, relay_bytes);
    var security = http.security_headers.SecurityHeaders{};
    var url_buf: [64]u8 = undefined;
    const uri = try std.Uri.parse(try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/download", .{listener.port}));

    var tracker = LargestAllocationTracker{ .child = std.testing.allocator };
    var pool = http.upstream_h2.H2ConnPool.init(std.testing.allocator, .{ .proxy_buffer_limits = limits });
    defer origin_thread.join();
    defer pool.deinit();

    var captures: [concurrency]std.array_list.Managed(u8) = undefined;
    for (&captures) |*c| c.* = std.array_list.Managed(u8).init(std.testing.allocator);
    defer for (&captures) |*c| c.deinit();

    // Establish the pooled connection first, on the plain allocator so the
    // tracker below measures only the concurrent phase.
    var warm_captured = std.array_list.Managed(u8).init(std.testing.allocator);
    defer warm_captured.deinit();
    var warm = H2TrackedExchangeCtx{
        .allocator = std.testing.allocator,
        .pool = &pool,
        .port = listener.port,
        .uri = uri,
        .read_buf_bytes = relay_bytes,
        .captured = &warm_captured,
        .security = &security,
        .limits = limits,
        .global = &global,
    };
    runH2TrackedExchange(&warm);
    try std.testing.expect(!warm.failed);
    try std.testing.expectEqual(@as(u16, 200), warm.status);
    try std.testing.expectEqual(@as(usize, 0), tracker.peakLargeLive());

    var ctxs: [concurrency]H2TrackedExchangeCtx = undefined;
    var threads: [concurrency]std.Thread = undefined;
    for (&ctxs, 0..) |*ctx, i| {
        ctx.* = .{
            .allocator = tracker.allocator(),
            .pool = &pool,
            .port = listener.port,
            .uri = uri,
            .read_buf_bytes = relay_bytes,
            .captured = &captures[i],
            .security = &security,
            .limits = limits,
            .global = &global,
        };
        threads[i] = try std.Thread.spawn(.{}, runH2TrackedExchange, .{ctx});
    }
    // Same teardown ordering as the gated tests: an assertion failing below
    // must not leave three live exchanges using a pool that is about to be
    // destroyed. Runs as: open the gate, join the exchanges, destroy the pool,
    // join the origin.
    defer for (threads) |thread| thread.join();
    defer origin_server.release.store(true, .release);

    // All three have reached the origin and are waiting on a response head.
    var waited: u32 = 0;
    while (origin_server.seen.load(.acquire) < concurrency and waited < 30_000) : (waited += 5) sleepMs(5);
    try std.testing.expectEqual(@as(usize, concurrency), origin_server.seen.load(.acquire));
    // Give any eager allocation a chance to have happened before measuring.
    sleepMs(50);

    // Nothing has been admitted yet, so no relay memory may exist. With
    // allocation ahead of reservation this reads 3 x 32 KiB.
    try std.testing.expectEqual(@as(usize, 0), tracker.peakLargeLive());
    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.upstream_to_downstream));

    origin_server.release.store(true, .release);
    for (&ctxs) |*ctx| {
        var waited_done: u32 = 0;
        while (!ctx.finished.load(.acquire) and waited_done < 30_000) : (waited_done += 5) sleepMs(5);
    }

    // Once heads arrive each response is admitted in turn and allocates its
    // buffer then. The cap is what bounds the process: it can never hold more
    // relay memory than one admitted reservation's worth, however the three
    // interleave.
    try std.testing.expect(tracker.peakLargeLive() <= relay_bytes);

    // Whatever the interleaving, every exchange either completed or was turned
    // away for capacity — never for some other reason, and never by allocating
    // first and discovering the limit afterwards.
    var completed: usize = 0;
    for (&ctxs) |*ctx| {
        if (ctx.failed) {
            try std.testing.expectEqual(
                @as(?anyerror, error.ProxyBufferCapacityUnavailable),
                ctx.err,
            );
        } else {
            try std.testing.expectEqual(@as(u16, 200), ctx.status);
            completed += 1;
        }
    }
    try std.testing.expect(completed >= 1);

    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.upstream_to_downstream));
    for (&ctxs) |*ctx| try std.testing.expectEqual(@as(usize, 0), ctx.counters.reserved);
}

test "a failed relay allocation hands the http2 connection back" {
    // The relay buffer is allocated after the connection is acquired, so its
    // failure path has to release that reference. Leaking it would strand a
    // pool connection on every out-of-memory response.
    const listener = try listenLoopbackEphemeral();
    defer _ = std.c.close(listener.fd);

    var origin_server = H2GatedMultiOrigin{ .listen_fd = listener.fd, .stream_count = 2 };
    origin_server.release_end.store(true, .release);
    const origin_thread = try std.Thread.spawn(.{}, h2GatedMultiServe, .{&origin_server});

    const relay_bytes: usize = 32 * 1024;
    const limits = proxy_buffer_account.Limits{
        .per_stream_low_watermark = 8 * 1024,
        .per_stream_high_watermark = 16 * 1024,
        .per_stream_hard_limit = 16 * 1024 + relay_bytes,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    };
    var global = proxy_buffer_account.Aggregate.init(.global, 0);
    var security = http.security_headers.SecurityHeaders{};
    var url_buf: [64]u8 = undefined;
    const uri = try std.Uri.parse(try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/download", .{listener.port}));

    var pool = http.upstream_h2.H2ConnPool.init(std.testing.allocator, .{ .proxy_buffer_limits = limits });
    defer origin_thread.join();
    defer pool.deinit();

    var failing = LargestAllocationTracker{ .child = std.testing.allocator, .fail_large = true };
    var failed_captured = std.array_list.Managed(u8).init(std.testing.allocator);
    defer failed_captured.deinit();
    var failed_ctx = H2TrackedExchangeCtx{
        .allocator = failing.allocator(),
        .pool = &pool,
        .port = listener.port,
        .uri = uri,
        .read_buf_bytes = relay_bytes,
        .captured = &failed_captured,
        .security = &security,
        .limits = limits,
        .global = &global,
    };
    runH2TrackedExchange(&failed_ctx);
    try std.testing.expect(failed_ctx.failed);

    // The pool is still usable, which it would not be if the reference were
    // stranded — and the testing allocator's leak check covers the connection
    // object itself at `pool.deinit()`.
    var ok_captured = std.array_list.Managed(u8).init(std.testing.allocator);
    defer ok_captured.deinit();
    var ok_ctx = H2TrackedExchangeCtx{
        .allocator = std.testing.allocator,
        .pool = &pool,
        .port = listener.port,
        .uri = uri,
        .read_buf_bytes = relay_bytes,
        .captured = &ok_captured,
        .security = &security,
        .limits = limits,
        .global = &global,
    };
    runH2TrackedExchange(&ok_ctx);
    try std.testing.expect(!ok_ctx.failed);
    try std.testing.expectEqual(@as(u16, 200), ok_ctx.status);

    try std.testing.expectEqual(@as(usize, 0), global.currentBytes(.upstream_to_downstream));
    try std.testing.expectEqual(@as(usize, 0), failed_ctx.counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), ok_ctx.counters.reserved);
    try std.testing.expectEqual(@as(usize, 0), ok_ctx.counters.retained);
}

test "shouldRetryStalePooledBufferedExchange retries write failures for any method" {
    try std.testing.expect(shouldRetryStalePooledBufferedExchange(true, 0, error.UpstreamRequestWriteFailed, "POST"));
    try std.testing.expect(shouldRetryStalePooledBufferedExchange(true, 0, error.UpstreamRequestWriteFailed, "GET"));
    try std.testing.expect(!shouldRetryStalePooledBufferedExchange(false, 0, error.UpstreamRequestWriteFailed, "POST"));
    try std.testing.expect(!shouldRetryStalePooledBufferedExchange(true, 1, error.UpstreamRequestWriteFailed, "POST"));
}

test "shouldRetryStalePooledBufferedExchange keeps zero-byte reads idempotent-only" {
    try std.testing.expect(shouldRetryStalePooledBufferedExchange(true, 0, error.UpstreamConnectionClosed, "GET"));
    try std.testing.expect(!shouldRetryStalePooledBufferedExchange(true, 0, error.UpstreamConnectionClosed, "POST"));
    try std.testing.expect(!shouldRetryStalePooledBufferedExchange(true, 0, error.Timeout, "GET"));
}
