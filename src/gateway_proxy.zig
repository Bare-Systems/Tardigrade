//! Shared proxy primitives and bounded buffered HTTP/1 upstream transports.
//!
//! Functions whose names include `BoundedBuffered` materialize an upstream
//! response in memory only after enforcing an explicit size cap. They are kept
//! separate from the reverse-proxy data-plane orchestration in
//! `gateway_proxy_runtime.zig` so streaming/backpressure work can replace the
//! data-plane executor without depending on control-plane helper behavior.

const compat = @import("zig_compat.zig");
const std = @import("std");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");
const gs = @import("gateway_state.zig");
const gph = @import("gateway_proxy_headers.zig");
const gpres = @import("gateway_proxy_response.zig");
const gpt = @import("gateway_proxy_target.zig");
const gconn = @import("gateway_connection.zig");

// Re-export the header-boundary API so existing callers that import from this
// module continue to work without change.
pub const MaybeOwnedBytes = gph.MaybeOwnedBytes;
pub const buildForwardedFor = gph.buildForwardedFor;
pub const isTrustedUpstream = gph.isTrustedUpstream;
pub const appendTrustedUpstreamHeaders = gph.appendTrustedUpstreamHeaders;
pub const appendRequestIdHeaders = gph.appendRequestIdHeaders;
pub const writeRequestIdHeaders = gph.writeRequestIdHeaders;
pub const setRequestIdHeaders = gph.setRequestIdHeaders;
pub const applyResponseHeaders = gpres.applyResponseHeaders;
pub const writeStreamedUpstreamResponse = gpres.writeStreamedUpstreamResponse;
pub const writeStreamedUpstreamResponseHead = gpres.writeStreamedUpstreamResponseHead;
pub const writeStreamedUpstreamResponseHeadFromHeaders = gpres.writeStreamedUpstreamResponseHeadFromHeaders;
pub const writeBufferedUpstreamResponse = gpres.writeBufferedUpstreamResponse;
pub const writeBufferedUpstreamResponseHead = gpres.writeBufferedUpstreamResponseHead;
pub const computeHstsValue = gpres.computeHstsValue;
pub const writeSecurityHeaders = gpres.writeSecurityHeaders;
pub const writeSecurityHeadersFiltered = gpres.writeSecurityHeadersFiltered;
pub const writeChunk = gpres.writeChunk;
pub const buildApiErrorJson = gpres.buildApiErrorJson;
pub const sendApiError = gpres.sendApiError;
pub const upstreamReasonPhrase = gpres.upstreamReasonPhrase;
pub const ResolvedProxyTarget = gpt.ResolvedProxyTarget;
pub const isRedirectStatusCode = gpt.isRedirectStatusCode;
pub const resolveProxyTarget = gpt.resolveProxyTarget;
pub const appendProxyQueryString = gpt.appendProxyQueryString;
pub const resolveRedirectTargetUrl = gpt.resolveRedirectTargetUrl;
pub const unixSocketPathFromEndpoint = gpt.unixSocketPathFromEndpoint;
pub const combineProxyTarget = gpt.combineProxyTarget;
pub const parseUpstreamHost = gpt.parseUpstreamHost;
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

pub const StreamingRequestBody = struct {
    content_length: usize,
    initial_bytes: []const u8 = &.{},
};

pub const StreamingProxyResult = struct {
    status_code: u16,
    reason: []const u8,
    response_body_bytes: usize,
    upstream_ttfb_ms: u64,
    upstream_aborted: bool = false,
};

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
    const resp_body = raw[header_end + 4 ..];

    const first_line_end = std.mem.findScalar(u8, headers_raw, '\n') orelse return error.UpstreamProtocolError;
    const first_line = compat.trimRight(u8, headers_raw[0..first_line_end], "\r");
    var line_parts = std.mem.splitScalar(u8, first_line, ' ');
    _ = line_parts.next();
    const status_str = line_parts.next() orelse "200";
    const status_code = std.fmt.parseInt(u16, status_str, 10) catch 200;
    const reason = line_parts.rest();

    var resp_headers = std.array_list.Managed(UpstreamHeader).init(metadata_allocator);
    var hdr_lines = std.mem.splitSequence(u8, headers_raw[first_line_end + 1 ..], "\r\n");
    while (hdr_lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        const hname = std.mem.trim(u8, line[0..colon], " \t");
        const hval = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (gph.shouldSkipUpstreamResponseHeader(hname)) continue;
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
            if (reused and err == error.UpstreamConnectionClosed and attempt == 0) {
                p.recordStaleRetry(key);
                continue; // request never delivered — retry once on a fresh conn
            }
            return err;
        }
    }
    unreachable;
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
    tls_options: ?http.tls_termination.UpstreamTlsOptions,
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
        if (opts.offer_h2) {
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
            var tls_conn = try http.tls_termination.UpstreamTlsConn.connect(fd, host, opts);
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
                const tls_ptr = p.allocator.create(http.tls_termination.UpstreamTlsConn) catch {
                    _ = std.c.close(new_fd);
                    p.releaseSlot(key);
                    return error.OutOfMemory;
                };
                tls_ptr.* = http.tls_termination.UpstreamTlsConn.connect(new_fd, host, tls_options.?) catch |err| {
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
            if (reused and err == error.UpstreamConnectionClosed and attempt == 0) {
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
    opts: http.tls_termination.UpstreamTlsOptions,
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

    var tls_conn = try http.tls_termination.UpstreamTlsConn.connect(fd, host, opts);
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
    opts: ?http.tls_termination.UpstreamTlsOptions,
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
/// origin negotiates HTTP/1.1 via ALPN, the request runs on the h1 streaming
/// relay over that fresh (unpooled) connection instead.
///
/// `opts == null` selects prior-knowledge cleartext h2c (#237): plain socket,
/// `http` scheme, `h2c:`-prefixed pool key, no `.h1` fallback.
fn streamViaH2Pool(
    allocator: std.mem.Allocator,
    h2_pool: *http.upstream_h2.H2ConnPool,
    h1_pool: ?*http.upstream_pool.UpstreamPool,
    host: []const u8,
    port: u16,
    opts: ?http.tls_termination.UpstreamTlsOptions,
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    buffered_body: []const u8,
    read_buf: []u8,
    downstream_conn: anytype,
    downstream_writer: anytype,
    security: *const http.security_headers.SecurityHeaders,
    sticky_set_cookie: ?[]const u8,
    correlation_id: []const u8,
    connect_timeout_ms: u32,
    read_deadline_ms: u32,
    cancel_token: ?*const CancellationToken,
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
                var wrote_downstream = false;
                const res = try streamProxyOverTransport(allocator, tls_ptr, tls_ptr.fd, read_buf, uri, method, extra_headers, buffered_body, null, downstream_conn, downstream_writer, security, sticky_set_cookie, correlation_id, connect_timeout_ms, read_deadline_ms, cancel_token, &wrote_downstream);
                if (h1_pool) |p| p.recordRequestLatency(false, http.event_loop.monotonicMs() - start_ms);
                return res.result;
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
                const stream = conn.requestStreaming(.{
                    .method = method,
                    .scheme = scheme,
                    .authority = authority,
                    .path = path_buf.written(),
                    .headers = extra_headers,
                    .body = buffered_body,
                }) catch |err| {
                    // Nothing has reached the client yet: evict the dead
                    // connection so new requests do not pick it, and retry
                    // once on connection-level failures.
                    h2_pool.evict(key, conn);
                    h2_pool.release(conn);
                    if (attempt == 0 and (err == error.Http2GoAway or err == error.Http2ConnectionClosed or err == error.Http2StreamReset)) {
                        continue;
                    }
                    return err;
                };
                const ttfb_ms = http.event_loop.monotonicMs() - start_ms;
                const status = stream.status.?; // requestStreaming guarantees a status

                const reason = gpres.upstreamReasonPhrase(@enumFromInt(status));
                const body_allowed = gpres.responseBodyAllowed(method, status);
                gpres.writeStreamedUpstreamResponseHeadFromHeaders(
                    downstream_writer,
                    status,
                    reason,
                    stream.headers.items,
                    body_allowed,
                    correlation_id,
                    security,
                    sticky_set_cookie,
                ) catch {
                    conn.finishStreaming(stream); // resets the unfinished stream
                    h2_pool.release(conn);
                    return error.ClientAborted;
                };

                var body_bytes: usize = 0;
                var aborted = false;
                if (body_allowed) {
                    while (true) {
                        if (cancelStopped(cancel_token)) {
                            conn.finishStreaming(stream);
                            h2_pool.release(conn);
                            return error.RequestCancelled;
                        }
                        const n = conn.readStreamingBody(stream, read_buf) catch {
                            // Upstream failed mid-body after the head went
                            // downstream: report an aborted relay (the client
                            // sees the truncated chunked body); other streams
                            // on the connection are unaffected unless the
                            // whole connection died (handled below).
                            aborted = true;
                            break;
                        };
                        if (n == 0) break;
                        gpres.writeChunk(downstream_writer, read_buf[0..n]) catch {
                            conn.finishStreaming(stream);
                            h2_pool.release(conn);
                            return error.ClientAborted;
                        };
                        body_bytes += n;
                    }
                    if (!aborted) {
                        gpres.writeChunk(downstream_writer, "") catch {
                            conn.finishStreaming(stream);
                            h2_pool.release(conn);
                            return error.ClientAborted;
                        };
                    }
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
    for (h2resp.headers, 0..) |h, i| {
        headers[i] = .{ .name = try aa.dupe(u8, h.name), .value = try aa.dupe(u8, h.value) };
    }
    const body = try allocator.dupe(u8, h2resp.body);
    return .{
        .metadata_arena = arena,
        .status_code = h2resp.status,
        .reason = reason,
        .headers = headers,
        .body = body,
    };
}

/// Send a bounded buffered HTTP/1 request over an already-connected transport
/// and parse the response. `transport` must provide `writeAll([]const u8)` and
/// `read([]u8) !usize` (satisfied by both `compat.NetStream` and
/// `*UpstreamTlsConn`). `fd` is the underlying socket used for per-phase
/// timeout control. The caller owns connecting and closing the transport.
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
    const host = if (uri.host) |value| try value.toRaw(&host_buf) else "localhost";

    try req_writer.print("{s} {s}", .{ method, uriComponentBytes(uri.path) });
    if (uri.query) |query| {
        try req_writer.print("?{s}", .{uriComponentBytes(query)});
    }
    try req_writer.writeAll(" HTTP/1.1\r\n");
    // Preserve a non-default upstream port in the Host header.
    const default_port: u16 = if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) 443 else 80;
    if (uri.port) |p| {
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
        try req_writer.print("{s}: {s}\r\n", .{ header.name, header.value });
    }
    if (body.len > 0) {
        try req_writer.print("Content-Length: {d}\r\n", .{body.len});
    }
    try req_writer.writeAll("\r\n");
    if (body.len > 0) {
        try req_writer.writeAll(body);
    }

    try transport.writeAll(req_aw.written());

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
    while (true) {
        if (header_end == null) {
            if (std.mem.find(u8, resp_raw.items, "\r\n\r\n")) |he| {
                header_end = he;
                framing = detectResponseFraming(resp_raw.items[0..he], method);
            }
        }
        if (header_end) |he| {
            const headers_block = resp_raw.items[0..he];
            const body_start = he + 4;
            const resp_body = resp_raw.items[body_start..];
            switch (framing) {
                .none => {
                    // Bodiless: reusable only if nothing trailed the headers.
                    setReusable(reusable, keep_alive, headers_block, resp_body.len == 0);
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
                        defer allocator.free(decoded);
                        setReusable(reusable, keep_alive, headers_block, true);
                        var rebuilt = std.array_list.Managed(u8).init(allocator);
                        defer rebuilt.deinit();
                        try rebuilt.appendSlice(resp_raw.items[0..body_start]);
                        try rebuilt.appendSlice(decoded);
                        return parseBufferedUpstreamResponse(allocator, rebuilt.items);
                    }
                },
                .close => {}, // no length advertised — server will close; not reusable
            }
        }

        if (read_deadline_ms > 0 and !try pollFdReadable(fd, read_deadline_ms)) {
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

    // A reused keep-alive connection the origin closed while idle yields zero
    // bytes here; surface it distinctly so the caller can retry on a fresh
    // connection (the request was never delivered).
    if (resp_raw.items.len == 0) return error.UpstreamConnectionClosed;

    return parseBufferedUpstreamResponse(allocator, resp_raw.items);
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

/// Determine response framing from the header block (excluding the trailing
/// CRLFCRLF), the request method, and the status line.
fn detectResponseFraming(header_block: []const u8, method: []const u8) ResponseFraming {
    const first_line_end = std.mem.find(u8, header_block, "\r\n") orelse header_block.len;
    var status_parts = std.mem.splitScalar(u8, header_block[0..first_line_end], ' ');
    _ = status_parts.next();
    const status = std.fmt.parseInt(u16, status_parts.next() orelse "0", 10) catch 0;

    if (std.ascii.eqlIgnoreCase(method, "HEAD")) return .none;
    if (responseStatusIsBodiless(status)) return .none;

    var content_length: ?usize = null;
    var chunked = false;
    var lines = std.mem.splitSequence(u8, header_block[@min(first_line_end + 2, header_block.len)..], "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            var tokens = std.mem.splitScalar(u8, value, ',');
            while (tokens.next()) |token| {
                if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, token, " \t"), "chunked")) chunked = true;
            }
        } else if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            content_length = std.fmt.parseInt(usize, value, 10) catch null;
        }
    }

    // Transfer-Encoding takes precedence over Content-Length (RFC 7230 §3.3.3).
    if (chunked) return .chunked;
    if (content_length) |cl| return .{ .length = cl };
    return .close;
}

/// Decode a chunked message body. Returns the decoded payload when the
/// terminating zero-length chunk (and trailer section) has fully arrived, or
/// null when more bytes are needed. The caller owns the returned slice.
fn decodeChunkedBody(allocator: std.mem.Allocator, encoded: []const u8, max_bytes: usize) !?[]u8 {
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
                if (tlen == 0) return try out.toOwnedSlice(); // blank line → done
                tpos += tlen + 2;
            }
        }
        const data_end = data_start + size;
        if (data_end + 2 > encoded.len) return null; // chunk data + trailing CRLF not yet here
        try out.appendSlice(encoded[data_start..data_end]);
        if (out.items.len > max_bytes) return error.StreamTooLong;
        pos = data_end + 2; // skip the CRLF after the chunk data
    }
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
    auth_identity: ?[]const u8,
    auth_user_id: ?[]const u8,
    auth_device_id: ?[]const u8,
    auth_scopes: ?[]const u8,
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
    const proxy_extra_header_slack = 10;
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
    const tls_options: ?http.tls_termination.UpstreamTlsOptions = if (is_https) .{
        .skip_verify = !cfg.upstream_tls_verify,
        .ca_bundle_path = cfg.upstream_tls_ca_bundle,
        .sni_override = cfg.upstream_tls_server_name,
        .client_cert_path = cfg.upstream_tls_client_cert,
        .client_key_path = cfg.upstream_tls_client_key,
        // Offer HTTP/2 via ALPN when configured (#145). The streaming path
        // offers h2 too (executeStreamingHttpProxyRequest sets it on its own
        // TLS options when routing through the h2 pool).
        .offer_h2 = cfg.upstream_protocol.offersH2(),
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
        if (deadline_ms > 0 and !try pollFdReadable(fd, deadline_ms)) return error.Timeout;
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

    const first_line_end = std.mem.find(u8, header_block, "\r\n") orelse head_end;
    const status_line = header_block[0..first_line_end];
    const http_1_1 = std.mem.startsWith(u8, status_line, "HTTP/1.1");
    var sp = std.mem.splitScalar(u8, status_line, ' ');
    _ = sp.next();
    const status_code = std.fmt.parseInt(u16, sp.next() orelse "0", 10) catch 0;
    const reason = try arena.dupe(u8, sp.rest());

    var headers = std.array_list.Managed(UpstreamHeader).init(arena);
    var connection_close = false;
    var lines = std.mem.splitSequence(u8, header_block[@min(first_line_end + 2, header_block.len)..], "\r\n");
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
        if (gph.shouldSkipUpstreamResponseHeader(name)) continue;
        try headers.append(.{ .name = try arena.dupe(u8, name), .value = try arena.dupe(u8, value) });
    }
    const framing = detectResponseFraming(header_block, method);
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
        rb.consume(eol + 2);
        if (eol == 0) return true; // blank line terminates the trailer section
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
    downstream_writer: anytype,
    cancel_token: ?*const CancellationToken,
) !RelayOutcome {
    var total: usize = 0;
    switch (framing) {
        // Bodiless (HEAD/204/304/1xx): reusable only if nothing trailed the head.
        .none => return .{ .body_bytes = 0, .aborted = false, .reusable = rb.available().len == 0 },
        .length => |content_length| {
            var remaining = content_length;
            while (remaining > 0) {
                if (cancelStopped(cancel_token)) return error.RequestCancelled;
                if (rb.available().len == 0 and !try rb.fill(transport, fd, deadline_ms)) {
                    return .{ .body_bytes = total, .aborted = true, .reusable = false };
                }
                const take = @min(rb.available().len, remaining);
                gpres.writeChunk(downstream_writer, rb.available()[0..take]) catch return error.ClientAborted;
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
                    gpres.writeChunk(downstream_writer, rb.available()[0..take]) catch return error.ClientAborted;
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
                gpres.writeChunk(downstream_writer, rb.available()) catch return error.ClientAborted;
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
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    buffered_body: []const u8,
    streaming_body: ?StreamingRequestBody,
    downstream_conn: anytype,
    cancel_token: ?*const CancellationToken,
) !void {
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
        try w.print("Content-Length: {d}\r\n", .{sb.content_length});
    } else if (buffered_body.len > 0) {
        try w.print("Content-Length: {d}\r\n", .{buffered_body.len});
    }
    try w.writeAll("\r\n");
    try transport.writeAll(req_aw.written());

    if (streaming_body) |sb| {
        var relay: [16 * 1024]u8 = undefined;
        var sent: usize = @min(sb.initial_bytes.len, sb.content_length);
        if (sent > 0) try transport.writeAll(sb.initial_bytes[0..sent]);
        while (sent < sb.content_length) {
            if (cancelStopped(cancel_token)) return error.RequestCancelled;
            const want = @min(relay.len, sb.content_length - sent);
            const n = downstream_conn.read(relay[0..want]) catch return error.ClientAborted;
            if (n == 0) return error.ClientAborted;
            try transport.writeAll(relay[0..n]);
            sent += n;
        }
    } else if (buffered_body.len > 0) {
        try transport.writeAll(buffered_body);
    }
}

/// Run one streaming proxy attempt over an already-connected `transport`: send
/// the request, read the response head, relay the head+body downstream, and
/// report whether the connection is reusable. `wrote_downstream` is set true the
/// moment any response bytes are written to the client (after which the caller
/// must not retry on a fresh connection).
fn streamProxyOverTransport(
    allocator: std.mem.Allocator,
    transport: anytype,
    fd: std.posix.fd_t,
    read_buf: []u8,
    uri: std.Uri,
    method: []const u8,
    extra_headers: []const std.http.Header,
    buffered_body: []const u8,
    streaming_body: ?StreamingRequestBody,
    downstream_conn: anytype,
    downstream_writer: anytype,
    security: *const http.security_headers.SecurityHeaders,
    sticky_set_cookie: ?[]const u8,
    correlation_id: []const u8,
    connect_timeout_ms: u32,
    read_deadline_ms: u32,
    cancel_token: ?*const CancellationToken,
    wrote_downstream: *bool,
) !struct { result: StreamingProxyResult, reusable: bool } {
    if (connect_timeout_ms > 0) setSocketTimeoutMs(fd, connect_timeout_ms, connect_timeout_ms) catch {};
    try sendStreamingProxyRequest(allocator, transport, uri, method, extra_headers, buffered_body, streaming_body, downstream_conn, cancel_token);
    if (read_deadline_ms > 0) setSocketRecvTimeoutMs(fd, read_deadline_ms) catch {};

    const ttfb_start_ms = http.event_loop.monotonicMs();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var rb = StreamReadBuf{ .buf = read_buf };
    const head = try readUpstreamHead(arena.allocator(), &rb, transport, fd, read_deadline_ms, method);
    const ttfb_ms = http.event_loop.monotonicMs() - ttfb_start_ms;

    const reason = gpres.upstreamReasonPhrase(@enumFromInt(head.status_code));
    const body_allowed = gpres.responseBodyAllowed(method, head.status_code);

    gpres.writeStreamedUpstreamResponseHeadFromHeaders(
        downstream_writer,
        head.status_code,
        reason,
        head.headers,
        body_allowed,
        correlation_id,
        security,
        sticky_set_cookie,
    ) catch return error.ClientAborted;
    wrote_downstream.* = true;

    var body_bytes: usize = 0;
    var aborted = false;
    var reusable = head.http_1_1 and !head.connection_close;
    if (body_allowed) {
        const outcome = try relayUpstreamBody(&rb, transport, fd, read_deadline_ms, head.framing, downstream_writer, cancel_token);
        body_bytes = outcome.body_bytes;
        aborted = outcome.aborted;
        reusable = reusable and outcome.reusable;
        if (!aborted) gpres.writeChunk(downstream_writer, "") catch return error.ClientAborted;
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
/// When `TARDIGRADE_UPSTREAM_PROTOCOL` offers h2 and the target is HTTPS, the
/// response is multiplexed over the shared per-origin HTTP/2 connection
/// (#145, Phase 4b PR 4) with bounded per-stream buffering — see
/// `streamViaH2Pool`. Streaming request bodies (`full` mode uploads) stay on
/// the HTTP/1.1 path: relaying a slow client upload over the shared h2
/// connection is deferred.
pub fn executeStreamingHttpProxyRequest(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    url: []const u8,
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
    sticky_set_cookie: ?[]const u8,
    cancel_token: ?*const CancellationToken,
    pool: ?*http.upstream_pool.UpstreamPool,
    /// Optional per-origin HTTP/2 multiplexing pool (#145).
    h2_pool: ?*http.upstream_h2.H2ConnPool,
) !StreamingProxyResult {
    if (cancelStopped(cancel_token)) return error.RequestCancelled;

    const proxy_extra_header_slack = 10;
    const uri = try std.Uri.parse(url);
    const is_https = std.ascii.eqlIgnoreCase(uri.scheme, "https");
    const host = if (uri.host) |h| uriComponentBytes(h) else return error.UpstreamProtocolError;
    const port: u16 = uri.port orelse (if (is_https) @as(u16, 443) else 80);
    const tls_options: ?http.tls_termination.UpstreamTlsOptions = if (is_https) .{
        .skip_verify = !cfg.upstream_tls_verify,
        .ca_bundle_path = cfg.upstream_tls_ca_bundle,
        .sni_override = cfg.upstream_tls_server_name,
        .client_cert_path = cfg.upstream_tls_client_cert,
        .client_key_path = cfg.upstream_tls_client_key,
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

    const read_buf = try allocator.alloc(u8, @max(cfg.proxy_stream_buffer_size, 16 * 1024));
    defer allocator.free(read_buf);

    // HTTP/2 upstream (#145 PR 4): multiplex the streaming response over the
    // shared per-origin h2 connection when configured — via ALPN for HTTPS
    // (h1 origins fall back inside) or prior-knowledge h2c for plain HTTP
    // when explicitly opted in (#237). Streaming uploads stay on the h1 path
    // below (`offer_h2` remains false there, so ALPN cannot negotiate a
    // protocol we then would not speak).
    const stream_h2 = streaming_body == null and
        (if (is_https) cfg.upstream_protocol.offersH2() else cfg.upstream_protocol.h2cPriorKnowledge());
    if (stream_h2) {
        if (h2_pool) |hp| {
            const h2_opts: ?http.tls_termination.UpstreamTlsOptions = if (is_https) blk: {
                var o = tls_options.?;
                o.offer_h2 = true;
                break :blk o;
            } else null;
            return streamViaH2Pool(allocator, hp, pool, host, port, h2_opts, uri, method, extra_headers.items, buffered_body, read_buf, downstream_conn, downstream_writer, security, sticky_set_cookie, correlation_id, connect_timeout_ms, read_deadline_ms, cancel_token);
        }
    }
    // Everything below runs HTTP/1.1 (counted per request, not per attempt).
    if (pool) |p| p.recordProtocol(false);

    const active_pool: ?*http.upstream_pool.UpstreamPool = if (pool) |p| (if (p.config.enabled) p else null) else null;
    var key_buf: [268]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "{s}:{s}:{d}", .{ if (is_https) "https" else "http", host, port }) catch host;

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
            const new_fd = compat.connectBoundedTcp(host, port, connect_timeout_ms) catch |err| {
                if (active_pool) |p| p.releaseSlot(key);
                return err;
            };
            if (active_pool) |p| p.recordConnectLatency(http.event_loop.monotonicMs() - connect_start);
            if (tls_options) |opts| {
                if (connect_timeout_ms > 0) setSocketTimeoutMs(new_fd, connect_timeout_ms, connect_timeout_ms) catch {};
                const owner = if (active_pool) |p| p.allocator else allocator;
                const tls_ptr = owner.create(http.tls_termination.UpstreamTlsConn) catch {
                    _ = std.c.close(new_fd);
                    if (active_pool) |p| p.releaseSlot(key);
                    return error.OutOfMemory;
                };
                tls_ptr.* = http.tls_termination.UpstreamTlsConn.connect(new_fd, host, opts) catch |err| {
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
            streamProxyOverTransport(allocator, tls, fd, read_buf, uri, method, extra_headers.items, buffered_body, streaming_body, downstream_conn, downstream_writer, security, sticky_set_cookie, correlation_id, connect_timeout_ms, read_deadline_ms, cancel_token, &wrote_downstream)
        else
            streamProxyOverTransport(allocator, compat.netStreamFromFd(fd), fd, read_buf, uri, method, extra_headers.items, buffered_body, streaming_body, downstream_conn, downstream_writer, security, sticky_set_cookie, correlation_id, connect_timeout_ms, read_deadline_ms, cancel_token, &wrote_downstream)) catch |err| {
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
    const outcome = try relayUpstreamBody(&rb, transport, client_fd, 1_000, head.framing, writer, null);

    // De-chunk the captured downstream stream (relay does not emit the
    // terminating zero chunk; append it so decodeChunkedBody can parse).
    try captured.appendSlice("0\r\n\r\n");
    if (try decodeChunkedBody(allocator, captured.items, 1 << 20)) |decoded| {
        defer allocator.free(decoded);
        try out_body.appendSlice(decoded);
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

test "streaming relay treats 204 as bodiless" {
    const allocator = std.testing.allocator;
    var body = std.array_list.Managed(u8).init(allocator);
    defer body.deinit();
    const r = try runStreamingRelay(allocator, "GET", "HTTP/1.1 204 No Content\r\n\r\n", false, &body);
    try std.testing.expectEqual(@as(u16, 204), r.status);
    try std.testing.expectEqualStrings("none", r.framing_tag);
    try std.testing.expectEqual(@as(usize, 0), body.items.len);
    try std.testing.expect(r.reusable);
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
