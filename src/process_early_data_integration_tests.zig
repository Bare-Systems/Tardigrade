//! #369 Slice 2: process-level 0-RTT replay / 425 assurance — the real
//! upstream-retry half. `src/tls/tls13_backend_tests.zig` proves the TLS/
//! replay-store layer with real production TLS and replay-store code, and
//! `edge_gateway.zig` proves the real H1 orchestration/dispatch-gating and
//! composition-decision scenarios (both need production code these files
//! cannot see — orchestration internals and the replay-store composition
//! helpers are private to `edge_gateway.zig`). This file's scenario needs
//! neither: it drives the real `gateway_proxy_runtime.runBufferedProxyAttempts`
//! retry/425 state machine and the real production TCP HTTP client
//! (`gateway_proxy_runtime.executeBufferedDataPlaneProxyRequest`) against an
//! actual loopback upstream test server with an atomic execution counter —
//! not a scripted attempt executor — so a real `425 Too Early` response and
//! a real retry are what get proven, not a stand-in.
//!
//! `ProductionBufferedProxyAttemptExecutor` in `gateway_proxy_runtime.zig`
//! is the real production executor, but it is wired to a full
//! `GatewayState` (upstream health/circuit-breaker/logger/security headers/
//! transcript store/...). Reconstructing all of that machinery merely to
//! reach the two fields (`state.upstream_pool`, `state.h2_pool`) the
//! executor actually threads through to the real HTTP client would be a
//! large, brittle test-only reimplementation of `GatewayState` itself.
//! `LoopbackAttemptExecutor` below is the smaller seam: it implements the
//! same `attempt_executor` contract `runBufferedProxyAttempts` requires,
//! but calls the *same* public, production
//! `executeBufferedDataPlaneProxyRequest` function directly against a real
//! `http.upstream_pool.UpstreamPool` and a real `http.metrics.Metrics`
//! instance, so the retry/425 policy under test
//! (`runBufferedProxyAttempts`/`shouldRetryEarlyUpstream425`) and the
//! upstream transport are both genuine production code; only the
//! observability plumbing that would otherwise live on `GatewayState` is
//! test-local.

const std = @import("std");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");
const gproxy_runtime = @import("gateway_proxy_runtime.zig");

const testing = std.testing;

// ---------------------------------------------------------------------
// A real loopback upstream test server with an atomic execution counter.
// Mirrors the raw blocking-listener fixture already used by
// `gateway_proxy.zig`'s "connectBlockingTcp + exchange round-trips a real
// TCP origin" test (bind on an ephemeral port, accept on a thread), but
// bounded throughout with `poll` so a regression that this test is meant
// to catch (e.g. the retry never happening) makes the *test* fail with a
// useful assertion instead of hanging `zig build test`/CI forever.
// ---------------------------------------------------------------------

const EphemeralListener = struct {
    fd: std.posix.fd_t,
    port: u16,
};

fn bindEphemeralLoopbackListener() !EphemeralListener {
    const listen_fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    try testing.expect(listen_fd >= 0);
    errdefer _ = std.c.close(listen_fd);
    _ = std.c.setsockopt(listen_fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&@as(c_int, 1)), @sizeOf(c_int));

    const sin: std.c.sockaddr.in = .{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 0),
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
        .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    try testing.expect(std.c.bind(listen_fd, @ptrCast(&sin), @sizeOf(std.c.sockaddr.in)) == 0);
    try testing.expect(std.c.listen(listen_fd, 8) == 0);

    var bound: std.c.sockaddr.in = undefined;
    var bound_len: std.posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    try testing.expect(std.c.getsockname(listen_fd, @ptrCast(&bound), &bound_len) == 0);
    const port = std.mem.bigToNative(u16, bound.port);
    try testing.expect(port != 0);
    return .{ .fd = listen_fd, .port = port };
}

/// Polls `fd` for readability with a bounded timeout. Never blocks forever:
/// returns `false` on timeout or a poll error, both of which the caller
/// must treat as "give up", not "keep waiting".
fn pollReadable(fd: std.posix.fd_t, timeout_ms: i32) bool {
    var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    const n = std.posix.poll(&fds, timeout_ms) catch return false;
    return n > 0 and (fds[0].revents & std.posix.POLL.IN) != 0;
}

/// Bounded, non-secret record of what the real origin observed per
/// connection — case ID, execution count, and whether each request carried
/// the real `Early-Data: 1` header — never request bodies or ticket/PSK
/// material (there is none here to leak). Only `stop` is written from the
/// main test thread; everything else is written by the responder thread
/// and must only be read by the main thread *after* `Thread.join` has
/// returned, which is the real happens-before relationship this file
/// relies on (see the test below) rather than relying on these fields
/// being atomic.
const OriginState = struct {
    executed: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    connections_seen: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    early_header_seen: [4]bool = .{ false, false, false, false },
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

fn requestHasEarlyDataHeader(raw: []const u8) bool {
    var lower_buf: [4096]u8 = undefined;
    const n = @min(raw.len, lower_buf.len);
    for (raw[0..n], 0..) |c, i| lower_buf[i] = std.ascii.toLower(c);
    return std.mem.indexOf(u8, lower_buf[0..n], "early-data: 1") != null;
}

/// Bounded wait for one inbound connection: polls in small slices, checking
/// `state.stop` between them, up to `max_wait_ms` total. Returns `null`
/// (never blocks indefinitely) if `stop` is requested or the deadline
/// passes without a peer connecting — the caller must treat that as "no
/// more connections are coming," not retry forever.
fn acceptBounded(listen_fd: std.posix.fd_t, state: *OriginState, max_wait_ms: i64) ?std.posix.fd_t {
    const poll_slice_ms = 25;
    var waited_ms: i64 = 0;
    while (waited_ms < max_wait_ms) : (waited_ms += poll_slice_ms) {
        if (state.stop.load(.acquire)) return null;
        if (pollReadable(listen_fd, poll_slice_ms)) {
            const conn = std.c.accept(listen_fd, null, null);
            if (conn < 0) return null;
            return conn;
        }
    }
    return null;
}

/// Reads one HTTP request head from `conn`, bounded both in time (via
/// `pollReadable`) and in size (`buf.len`). Returns the bytes read so far
/// on any of: seeing the `\r\n\r\n` head terminator, a read timeout, EOF,
/// or a full buffer — never blocks indefinitely on a peer that stops
/// sending mid-request.
fn readRequestHeadBounded(conn: std.posix.fd_t, buf: []u8) []const u8 {
    var total: usize = 0;
    while (total < buf.len) {
        if (!pollReadable(conn, 2_000)) break;
        const got = std.c.read(conn, buf[total..].ptr, buf.len - total);
        if (got <= 0) break;
        total += @intCast(got);
        if (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n") != null) break;
    }
    return buf[0..total];
}

/// Real blocking-but-bounded origin: accepts up to `max_connections`
/// sequential connections (the buffered HTTP client always sends
/// `Connection: close` bound responses here, so each attempt is a fresh
/// TCP connection). Any request that actually carries `Early-Data: 1` is
/// answered with a real `425 Too Early` and does **not** increment
/// `executed` — modeling an origin that itself enforces RFC 8470 and
/// refuses to treat early data as a safe side-effecting request. Any other
/// request executes normally. Every wait in this function is bounded (see
/// `acceptBounded`/`readRequestHeadBounded`), so a regression this test is
/// meant to catch (e.g. the client never retrying) makes this function
/// return promptly instead of blocking the test process forever.
fn earlyRejectingOriginResponder(listen_fd: std.posix.fd_t, state: *OriginState, max_connections: usize) void {
    var handled: usize = 0;
    while (handled < max_connections) : (handled += 1) {
        const conn = acceptBounded(listen_fd, state, 5_000) orelse return;
        defer _ = std.c.close(conn);

        var buf: [4096]u8 = undefined;
        const request_head = readRequestHeadBounded(conn, &buf);
        if (request_head.len == 0) return;

        const has_early = requestHasEarlyDataHeader(request_head);
        const idx = state.connections_seen.fetchAdd(1, .monotonic);
        if (idx < state.early_header_seen.len) state.early_header_seen[idx] = has_early;

        if (has_early) {
            const response = "HTTP/1.1 425 Too Early\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\ntoo early";
            _ = std.c.write(conn, response.ptr, response.len);
        } else {
            _ = state.executed.fetchAdd(1, .monotonic);
            const response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            _ = std.c.write(conn, response.ptr, response.len);
        }
    }
}

/// Real `runBufferedProxyAttempts` attempt executor driving the genuine
/// production upstream TCP client. See the module doc for why this exists
/// instead of reusing `ProductionBufferedProxyAttemptExecutor` directly.
const LoopbackAttemptExecutor = struct {
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    request: *const http.Request,
    upstream_url: []const u8,
    correlation_id: []const u8,
    pool: *http.upstream_pool.UpstreamPool,
    metrics: *http.metrics.Metrics,

    pub fn execute(
        self: *LoopbackAttemptExecutor,
        attempt: usize,
        forward_early_data: bool,
    ) !gproxy_runtime.DataPlaneProxyResponse {
        _ = attempt;
        return gproxy_runtime.executeBufferedDataPlaneProxyRequest(
            self.allocator,
            self.cfg,
            self.upstream_url,
            null,
            self.request.method.toString(),
            &self.request.headers,
            self.request.body orelse "",
            self.correlation_id,
            "127.0.0.1",
            "http",
            self.request.headers.get("host"),
            null,
            &.{},
            null,
            null,
            null,
            null,
            forward_early_data,
            2_000,
            2_000,
            2_000,
            null,
            self.pool,
            null,
        );
    }

    pub fn onBufferedResponse(self: *LoopbackAttemptExecutor, result: *gproxy_runtime.DataPlaneProxyResponse) !void {
        _ = self;
        _ = result;
    }

    pub fn onStaleConnectionRetry(self: *LoopbackAttemptExecutor, stale_conn_retries: usize, max_stale_conn_retries: usize) !void {
        _ = self;
        _ = stale_conn_retries;
        _ = max_stale_conn_retries;
    }

    pub fn onTerminalAttemptError(self: *LoopbackAttemptExecutor, _: anyerror) !void {
        _ = self;
    }

    pub fn onConfiguredErrorRetry(self: *LoopbackAttemptExecutor, configured_attempt_index: usize, max_attempts: usize, _: anyerror) !void {
        _ = self;
        _ = configured_attempt_index;
        _ = max_attempts;
    }

    pub fn onEarly425Retry(self: *LoopbackAttemptExecutor, result: *gproxy_runtime.DataPlaneProxyResponse) !void {
        result.deinit(self.allocator);
    }

    pub fn onEarly425HandshakeFailure(self: *LoopbackAttemptExecutor, _: anyerror) !void {
        _ = self;
    }

    pub fn onConfigured5xxRetry(self: *LoopbackAttemptExecutor, configured_attempt_index: usize, max_attempts: usize, result: *gproxy_runtime.DataPlaneProxyResponse) !void {
        _ = configured_attempt_index;
        _ = max_attempts;
        result.deinit(self.allocator);
    }

    pub fn recordEarlyUpstream425Action(self: *LoopbackAttemptExecutor, action: http.metrics.EarlyDataUpstream425Action) void {
        self.metrics.recordHttpEarlyDataUpstream425(action);
    }

    pub fn recordEarlyRetryResult(self: *LoopbackAttemptExecutor, result: http.metrics.EarlyDataRetryResult) void {
        self.metrics.recordHttpEarlyDataRetry(result);
    }
};

/// Deterministic downstream-handshake barrier, matching the
/// `TestEarly425Barrier` pattern already used by
/// `gateway_proxy_runtime.zig`'s own "early upstream 425 retry..." test:
/// starts incomplete (modeling a connection still mid-handshake when the
/// early request arrived — the actual condition current-hop early data
/// requires) and completes when `runBufferedProxyAttempts` drives it while
/// waiting to retry after a 425. A `null` barrier instead means "already
/// complete", which would make this current-hop-early scenario
/// indistinguishable from an ordinary post-handshake request.
const TestDownstreamHandshakeBarrier = struct {
    complete: bool = false,
    waits: usize = 0,

    fn isComplete(ptr: *anyopaque) bool {
        const self: *TestDownstreamHandshakeBarrier = @ptrCast(@alignCast(ptr));
        return self.complete;
    }

    fn waitOrDrive(ptr: *anyopaque) anyerror!void {
        const self: *TestDownstreamHandshakeBarrier = @ptrCast(@alignCast(ptr));
        self.waits += 1;
        self.complete = true;
    }

    fn barrier(self: *TestDownstreamHandshakeBarrier) http.request_context.DownstreamHandshakeBarrier {
        return .{
            .ctx = self,
            .is_complete_fn = isComplete,
            .wait_or_drive_fn = waitOrDrive,
        };
    }
};

test "#369 Slice 2 rt0.retry.425_exactly_once: a real early-data 425 from a real upstream retries exactly once, and the upstream executes exactly once" {
    const allocator = testing.allocator;

    var cfg = try edge_config.loadFromEnv(allocator);
    defer cfg.deinit(allocator);

    const listener = try bindEphemeralLoopbackListener();
    defer _ = std.c.close(listener.fd);

    var origin = OriginState{};
    const responder = try std.Thread.spawn(.{}, earlyRejectingOriginResponder, .{ listener.fd, &origin, @as(usize, 2) });
    // Belt-and-suspenders for every early-return path between here and the
    // explicit join below (e.g. an allocation failure building the request/
    // URL): request a bounded shutdown and join at most once. `joined`
    // guards against the double-join UB that would result from both this
    // defer and the explicit join below running.
    var joined = false;
    defer if (!joined) {
        origin.stop.store(true, .release);
        responder.join();
    };

    var url_buf: [64]u8 = undefined;
    const upstream_url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/work", .{listener.port});

    const block = edge_config.EdgeConfig.LocationBlock{
        .match_type = .prefix,
        .pattern = "/",
        .priority = 0,
        .action = .{ .proxy_pass = upstream_url },
        .early_data = .replay_safe,
        .proxy_early_data = .rfc8470,
    };

    var parsed = try http.Request.parseHead(allocator, "GET /work HTTP/1.1\r\nHost: example.test\r\n\r\n", 1 << 20);
    defer parsed.request.deinit();

    var pool = http.upstream_pool.UpstreamPool.init(allocator, .{});
    defer pool.deinit();
    var metrics = http.metrics.Metrics.init();

    var executor = LoopbackAttemptExecutor{
        .allocator = allocator,
        .cfg = &cfg,
        .request = &parsed.request,
        .upstream_url = upstream_url,
        .correlation_id = "req-425",
        .pool = &pool,
        .metrics = &metrics,
    };

    // Current-hop 0-RTT early data, no prior-hop `Early-Data` marker, and a
    // downstream handshake that has not yet completed (the actual
    // condition current-hop early data implies) — this is the shape #367's
    // contract allows exactly one transparent retry for, on a replay-safe
    // GET to an RFC-8470-aware origin.
    var handshake_barrier = TestDownstreamHandshakeBarrier{};
    var early_ctx = http.request_context.EarlyDataContext{
        .transport_early = true,
        .downstream_handshake = handshake_barrier.barrier(),
    };
    const first_attempt_forward_early_data = early_ctx.inbound_marker or
        (early_ctx.transport_early and !early_ctx.downstreamHandshakeComplete());
    try testing.expect(first_attempt_forward_early_data);

    const before_retried = metrics.http_early_data_upstream_425_total[@intFromEnum(http.metrics.EarlyDataUpstream425Action.retried)];
    const before_success = metrics.http_early_data_retry_total[@intFromEnum(http.metrics.EarlyDataRetryResult.success)];

    const outcome_result = gproxy_runtime.runBufferedProxyAttempts(
        &early_ctx,
        first_attempt_forward_early_data,
        "GET",
        &block,
        1,
        0,
        cfg.upstream_retry_idempotent_only,
        &executor,
    );

    // Establish a real happens-before relationship with the responder
    // thread *before* reading any of its (non-atomic) observations below —
    // `Thread.join` synchronizes-with the thread's completion. This must
    // run whether `outcome_result` is a value or an error, and before the
    // `try` that would otherwise skip straight to the deferred cleanup.
    origin.stop.store(true, .release);
    responder.join();
    joined = true;

    var response = switch (try outcome_result) {
        .response => |r| r,
        else => return error.TestUnexpectedResult,
    };
    defer response.deinit(allocator);

    // The response returned to the caller is the successful retry response.
    try testing.expectEqual(@as(u16, 200), response.statusCode());

    // Real origin, real bytes: first connection carried Early-Data: 1 and
    // was rejected; the retried connection did not carry it.
    try testing.expectEqual(@as(usize, 2), origin.connections_seen.load(.monotonic));
    try testing.expect(origin.early_header_seen[0]);
    try testing.expect(!origin.early_header_seen[1]);

    // Exactly one real upstream execution across both attempts.
    try testing.expectEqual(@as(usize, 1), origin.executed.load(.monotonic));

    // Retry occurred at most once (exactly once here), per the #367
    // contract; metrics distinguish the initial 425 from the successful
    // retry.
    try testing.expectEqual(before_retried + 1, metrics.http_early_data_upstream_425_total[@intFromEnum(http.metrics.EarlyDataUpstream425Action.retried)]);
    try testing.expectEqual(before_success + 1, metrics.http_early_data_retry_total[@intFromEnum(http.metrics.EarlyDataRetryResult.success)]);
    // The retry genuinely waited on the downstream handshake barrier
    // exactly once before retrying as ordinary.
    try testing.expectEqual(@as(usize, 1), handshake_barrier.waits);
}
