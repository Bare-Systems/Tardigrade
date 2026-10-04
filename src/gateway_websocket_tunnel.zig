//! An established WebSocket tunnel handed from a worker to the tunnel
//! reactor (#818).
//!
//! A worker runs the handshake and every admission gate, verifies the
//! origin's 101 and relays it, then packs everything the tunnel holds into a
//! `TunnelJob`: the origin connection and its direction buffers, the tunnel
//! slot, the upstream in-flight count, the configuration lease its reload
//! policy was fixed from, and what its access-log line needs. The connection
//! loop then detaches the client connection from its own bookkeeping,
//! `attach`es it, and `submit`s the job; the worker goes back to serving
//! requests. The reactor relays bytes, and `finish` releases everything, in
//! the same order the inline relay did, on whichever thread ends the tunnel.

const std = @import("std");
const compat = @import("zig_compat");
const http = @import("http.zig");
const gp = @import("gateway_proxy.zig");
const gs = @import("gateway_state.zig");
const ghandlers = @import("gateway_handlers.zig");

const GatewayState = gs.GatewayState;
const Relay = http.tunnel.Relay(http.tunnel.AnyEndpoint, http.tunnel.AnyEndpoint);

pub const TunnelJob = struct {
    job: http.tunnel_reactor.Job = .{ .vtable = &vtable },
    allocator: std.mem.Allocator,
    state: *GatewayState,
    upgraded: *gp.UpgradedUpstream,
    /// Owned copy of the upstream base URL counted in flight for
    /// least-connections balancing.
    upstream_base_url: []u8,
    /// Owned copy of client bytes read past the handshake.
    initial_to_upstream: []u8,
    opts: http.tunnel.Options,
    /// Lease on the configuration generation the handshake ran under; its
    /// supersession stamp is what `opts.reload_drain` points at.
    config_lease: ?gs.ConfigLease = null,
    downstream: Downstream = .none,
    /// The native TLS connection's non-blocking view (its address is what
    /// `http.tunnel.EncryptedEndpoint` holds).
    encrypted: http.encrypted_stream_connection.EncryptedStreamHttpConnection = undefined,
    relay: Relay = undefined,
    access: AccessSnapshot = .{},
    access_arena: std.heap.ArenaAllocator,

    pub const Downstream = union(enum) {
        none,
        /// A plaintext client socket; its connection slot is still held.
        plaintext: std.posix.fd_t,
        /// A native TLS client connection with its full lifecycle (slot,
        /// connection config lease, TLS state).
        native: http.downstream_connection.ManagedConnection,
    };

    /// What the handshake's access-log line needs once the tunnel closes.
    const AccessSnapshot = struct {
        captured: bool = false,
        method: []const u8 = "",
        path: []const u8 = "",
        user_agent: []const u8 = "",
        client_ip: []const u8 = "",
        correlation_id: []const u8 = "",
        upstream_addr: []const u8 = "",
        identity: []const u8 = "-",
        upstream_status: ?u16 = null,
        response_bytes: usize = 0,
        started_ms: i64 = 0,
        status: u16 = 101,
        early_data_source: []const u8 = "none",
        early_data_action: []const u8 = "ordinary",
        early_data_retry_result: []const u8 = "none",
        early_data_replay_exposed: bool = false,
    };

    const vtable = http.tunnel_reactor.Job.VTable{ .fds = fds, .observe = observe, .advance = advance, .finish = finishJob, .abort = abortJob };

    /// Prepare a possible handoff. This allocates only job-private metadata;
    /// the caller keeps ownership of `upgraded`, the tunnel slot and the
    /// upstream in-flight count until the downstream 101 has been committed.
    pub fn create(
        allocator: std.mem.Allocator,
        state: *GatewayState,
        upgraded: *gp.UpgradedUpstream,
        upstream_base_url: []const u8,
        initial_to_upstream: []const u8,
        opts: http.tunnel.Options,
    ) !*TunnelJob {
        const self = try allocator.create(TunnelJob);
        errdefer allocator.destroy(self);
        const base_url = try allocator.dupe(u8, upstream_base_url);
        errdefer allocator.free(base_url);
        const initial = try allocator.dupe(u8, initial_to_upstream);
        self.* = .{
            .allocator = allocator,
            .state = state,
            .upgraded = upgraded,
            .upstream_base_url = base_url,
            .initial_to_upstream = initial,
            .opts = opts,
            .access_arena = std.heap.ArenaAllocator.init(allocator),
        };
        return self;
    }

    /// Free a prepared handoff before shared ownership transfers. This never
    /// touches the origin connection, tunnel slot, or upstream in-flight
    /// count; those still belong to the request path.
    pub fn discardPrepared(self: *TunnelJob) void {
        std.debug.assert(self.downstream == .none);
        std.debug.assert(self.config_lease == null);
        const allocator = self.allocator;
        allocator.free(self.upstream_base_url);
        allocator.free(self.initial_to_upstream);
        self.access_arena.deinit();
        allocator.destroy(self);
    }

    /// Record the handshake's access-log fields; the line itself is written
    /// when the tunnel closes, with its close reason and byte counts.
    pub fn captureAccessLog(self: *TunnelJob, ctx: *const http.request_context.RequestContext, request: *const http.Request, status: u16) !void {
        const a = self.access_arena.allocator();
        self.access = .{
            .captured = true,
            .method = try a.dupe(u8, request.method.toString()),
            .path = try a.dupe(u8, request.uri.path),
            .user_agent = try a.dupe(u8, request.headers.get("user-agent") orelse ""),
            .client_ip = try a.dupe(u8, ctx.client_ip),
            .correlation_id = try a.dupe(u8, ctx.request_id),
            .upstream_addr = try a.dupe(u8, ctx.upstream_addr orelse ""),
            .identity = try a.dupe(u8, ctx.identity orelse "-"),
            .upstream_status = ctx.upstream_status,
            .response_bytes = ctx.response_bytes,
            .started_ms = ctx.started_ms,
            .status = status,
            .early_data_source = @tagName(ctx.early_data.source()),
            .early_data_action = @tagName(ctx.early_data_action),
            .early_data_retry_result = @tagName(ctx.early_data_retry_result),
            .early_data_replay_exposed = ctx.early_data.replayExposed(),
        };
    }

    /// Keep the configuration generation the handshake ran under alive for
    /// the tunnel's life.
    pub fn adoptConfigLease(self: *TunnelJob, lease: gs.ConfigLease) void {
        std.debug.assert(self.config_lease == null);
        self.config_lease = lease;
    }

    /// Give the tunnel its client connection and start the relay.
    pub fn attach(self: *TunnelJob, downstream: Downstream) void {
        std.debug.assert(self.downstream == .none);
        self.downstream = downstream;
        const client: http.tunnel.AnyEndpoint = switch (self.downstream) {
            .none => unreachable,
            .plaintext => |fd| .{ .socket = .{ .handle = fd } },
            .native => |*managed| blk: {
                self.encrypted = managed.transport.native.httpConnection();
                break :blk .{ .encrypted = .{ .conn = &self.encrypted } };
            },
        };
        const upstream: http.tunnel.AnyEndpoint = if (self.upgraded.tls) |tls|
            .{ .upstream_tls = .{ .tls = tls } }
        else
            .{ .socket = .{ .handle = self.upgraded.fd } };
        self.relay = Relay.init(client, upstream, self.upgraded.to_upstream_buf, self.upgraded.to_client_buf, self.initial_to_upstream, self.upgraded.early_upstream_bytes, self.opts);
    }

    /// Hand the attached tunnel to the reactor, or, when there is none or it
    /// has stopped, run it to completion on the calling thread. Either way
    /// ownership is gone when this returns.
    pub fn submit(self: *TunnelJob) void {
        std.debug.assert(self.downstream != .none);
        if (self.state.tunnel_reactor) |reactor| {
            reactor.submit(&self.job) catch {
                self.runInline();
            };
            return;
        }
        self.runInline();
    }

    fn runInline(self: *TunnelJob) void {
        while (true) {
            const wait = switch (self.relay.advance()) {
                .closed => break,
                .wait => |wait| wait,
            };
            if (wait.ready_now) continue;
            var pfds = [2]std.posix.pollfd{
                http.tunnel.pollEntry(self.relay.client.fd(), wait.client),
                http.tunnel.pollEntry(self.relay.upstream.fd(), wait.upstream),
            };
            const now = http.event_loop.monotonicMs();
            // Bounded, so a shutdown request is noticed.
            const until = if (wait.deadline_ms) |at| @min(at -| now, 250) else 250;
            _ = std.posix.poll(&pfds, @intCast(until)) catch {};
            self.relay.observe(pfds[0].revents, pfds[1].revents);
        }
        self.finish();
    }

    /// Release a job that was never attached (the handshake's client write
    /// failed after the job was built, or the connection loop could not
    /// detach its connection). Returns the tunnel slot and closes the origin.
    pub fn abandon(self: *TunnelJob) void {
        std.debug.assert(self.downstream == .none);
        self.state.metricsRecordWebSocketTunnelClosed(.{ .close_reason = .client_error });
        self.releaseShared();
    }

    fn from(job: *http.tunnel_reactor.Job) *TunnelJob {
        return @fieldParentPtr("job", job);
    }

    fn fds(job: *http.tunnel_reactor.Job) [2]std.posix.fd_t {
        const self = from(job);
        return .{ self.relay.client.fd(), self.relay.upstream.fd() };
    }

    fn observe(job: *http.tunnel_reactor.Job, client_revents: i16, upstream_revents: i16) void {
        from(job).relay.observe(client_revents, upstream_revents);
    }

    fn advance(job: *http.tunnel_reactor.Job) http.tunnel.Progress {
        return from(job).relay.advance();
    }

    fn finishJob(job: *http.tunnel_reactor.Job) void {
        from(job).finish();
    }

    fn abortJob(job: *http.tunnel_reactor.Job, reason: http.tunnel.CloseReason) void {
        from(job).finishWithStats(.{ .close_reason = reason });
    }

    fn finish(self: *TunnelJob) void {
        self.finishWithStats(self.relay.stats());
    }

    fn finishWithStats(self: *TunnelJob, stats: http.tunnel.Stats) void {
        const state = self.state;
        state.metricsRecordWebSocketTunnelClosed(stats);
        state.logger.debug(if (self.access.captured) self.access.correlation_id else null, "websocket tunnel closed: reason={s} duration_ms={d} client_to_upstream={d} upstream_to_client={d}", .{
            stats.close_reason.label(),
            stats.duration_ms,
            stats.client_to_upstream_bytes,
            stats.upstream_to_client_bytes,
        });
        if (self.access.captured) self.logAccess(stats);
        switch (self.downstream) {
            .none => {},
            .plaintext => |fd| {
                // The slot table is keyed by fd: release it while this
                // tunnel still owns the number.
                state.releaseConnectionSlot(fd);
                _ = std.c.close(fd);
            },
            .native => |*managed| managed.deinit(),
        }
        self.downstream = .none;
        self.releaseShared();
    }

    fn releaseShared(self: *TunnelJob) void {
        const allocator = self.allocator;
        const state = self.state;
        self.upgraded.deinit();
        state.recordUpstreamAttemptEnd(self.upstream_base_url);
        state.releaseWebSocketTunnel();
        if (self.config_lease) |*lease| lease.release();
        allocator.free(self.upstream_base_url);
        allocator.free(self.initial_to_upstream);
        self.access_arena.deinit();
        allocator.destroy(self);
    }

    fn logAccess(self: *const TunnelJob, stats: http.tunnel.Stats) void {
        const a = &self.access;
        const latency_ms = compat.milliTimestamp() - a.started_ms;
        self.state.metricsRecordLatencyMs(latency_ms);
        const entry = http.access_log.AccessLogEntry{
            .method = a.method,
            .path = a.path,
            .status = a.status,
            .latency_ms = latency_ms,
            .client_ip = a.client_ip,
            .correlation_id = a.correlation_id,
            .upstream_addr = a.upstream_addr,
            .upstream_status = a.upstream_status,
            .identity = a.identity,
            .user_agent = a.user_agent,
            .bytes_sent = a.response_bytes,
            .response_bytes = a.response_bytes,
            .error_category = ghandlers.classifyErrorCategory(a.status),
            .early_data_source = a.early_data_source,
            .early_data_action = a.early_data_action,
            .early_data_retry_result = a.early_data_retry_result,
            .early_data_replay_exposed = a.early_data_replay_exposed,
            .tunnel = .{
                .close_reason = stats.close_reason.label(),
                .duration_ms = stats.duration_ms,
                .client_to_upstream_bytes = stats.client_to_upstream_bytes,
                .upstream_to_client_bytes = stats.upstream_to_client_bytes,
            },
        };
        entry.log();
    }
};


fn neverShutdownForPreparationTest() bool {
    return false;
}

test "TunnelJob preparation is allocation-failure clean before handoff commit (#827)" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var state: GatewayState = undefined;
            var upgraded: gp.UpgradedUpstream = undefined;
            const job = try TunnelJob.create(
                allocator,
                &state,
                &upgraded,
                "http://origin.example",
                "queued-client-bytes",
                .{ .idle_timeout_ms = 30_000, .shutdown_requested = neverShutdownForPreparationTest },
            );
            job.discardPrepared();
        }
    }.run, .{});
}
