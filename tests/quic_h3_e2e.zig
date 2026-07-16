//! Deterministic native QUIC/H3 end-to-end harness (#247).
//!
//! Drives the native connection driver (`quic.connection.Connection`) and the
//! HTTP/3 glue (`http3.conn`) through a simulated network with a fully
//! deterministic clock and controlled datagram delivery: loss, reordering,
//! duplication, and delay are all expressed as explicit per-datagram rules,
//! so every failure reproduces exactly.
//!
//! Covered smoke cases (task #247 phase 3):
//!   - no loss: handshake, SETTINGS, request/response, clean close
//!   - one lost client Initial (PTO recovery at the Initial level)
//!   - one lost server handshake-flight datagram
//!   - one lost 1-RTT request datagram
//!   - reordered 1-RTT datagrams
//!   - duplicated datagrams
//!   - stream reset propagation
//!   - connection close propagation and drain
//!   - flow-control blocking and resumed progress under tiny windows
//!   - repeated request/response loop on one connection

const std = @import("std");
const quic = @import("quic");
const http3 = @import("http3");

const connection = quic.connection;
const tls_backend = quic.tls_backend;
const Connection = connection.Connection;

const testing = std.testing;

const H3 = http3.conn.Conn(Connection);

const HarnessFailure = error{
    NoProgress,
    IterationLimit,
    SimulatedTimeLimit,
    QueueDatagramLimit,
    QueueByteLimit,
    PacketProductionLimit,
    TimerEventLimit,
    UnexpectedConnectionClosure,
    DatagramTooLarge,
};

const Direction = enum { to_server, to_client };

/// Hard resource and progress limits for every deterministic scenario. These
/// are deliberately part of the harness configuration rather than implicit
/// test-runner timeouts, so adversarial cases fail at a reproducible boundary.
const Limits = struct {
    max_iterations: usize = 16_384,
    max_simulated_time_us: u64 = 90_000_000,
    max_queued_datagrams: usize = 128,
    max_queued_bytes: usize = 256 * 1024,
    max_packets_per_iteration: usize = 64,
    max_timer_events: usize = 2_048,
};

/// Per-direction delivery rules, indexed by datagram sequence number in that
/// direction (0-based, counted at the sender).
const Rules = struct {
    /// Datagram indices to drop entirely.
    drop: []const usize = &.{},
    /// Datagram indices to deliver twice.
    duplicate: []const usize = &.{},
    /// Pairs of consecutive indices to swap on delivery: entry n swaps
    /// datagrams n and n+1.
    swap: []const usize = &.{},
    /// Fixed one-way latency applied to every datagram.
    latency_us: u64 = 1_000,

    fn shouldDrop(self: Rules, index: usize) bool {
        return std.mem.indexOfScalar(usize, self.drop, index) != null;
    }

    fn shouldDuplicate(self: Rules, index: usize) bool {
        return std.mem.indexOfScalar(usize, self.duplicate, index) != null;
    }

    fn swapsWithNext(self: Rules, index: usize) bool {
        return std.mem.indexOfScalar(usize, self.swap, index) != null;
    }
};

const InFlight = struct {
    deliver_at_us: u64,
    len: usize,
    bytes: [max_test_datagram_size]u8,
};

const max_test_datagram_size = 2048;

const Pipe = struct {
    rules: Rules,
    sent: usize = 0,
    queue: std.ArrayList(InFlight) = .empty,

    fn deinit(self: *Pipe, allocator: std.mem.Allocator) void {
        self.queue.deinit(allocator);
    }

    fn append(self: *Pipe, allocator: std.mem.Allocator, bytes: []const u8, deliver_at_us: u64) !void {
        if (bytes.len > max_test_datagram_size) return error.DatagramTooLarge;
        var entry = InFlight{ .deliver_at_us = deliver_at_us, .len = bytes.len, .bytes = undefined };
        @memcpy(entry.bytes[0..bytes.len], bytes);
        try self.queue.append(allocator, entry);
    }

    fn queuedBytes(self: *const Pipe) usize {
        var total: usize = 0;
        for (self.queue.items) |entry| total += entry.len;
        return total;
    }

    fn schedule(self: *Pipe, allocator: std.mem.Allocator, bytes: []const u8, now_us: u64) !void {
        const index = self.sent;
        self.sent += 1;
        if (self.rules.shouldDrop(index)) return;
        var deliver_at = now_us + self.rules.latency_us;
        if (self.rules.swapsWithNext(index)) {
            // Delivered after its successor: push it further out.
            deliver_at += 2 * self.rules.latency_us;
        }
        try self.append(allocator, bytes, deliver_at);
        if (self.rules.shouldDuplicate(index)) {
            try self.append(allocator, bytes, deliver_at + 1);
        }
    }

    fn nextDeliveryUs(self: *const Pipe) ?u64 {
        var best: ?u64 = null;
        for (self.queue.items) |entry| {
            if (best == null or entry.deliver_at_us < best.?) best = entry.deliver_at_us;
        }
        return best;
    }

    /// Deliver every datagram due at or before `now_us` into `conn`.
    fn deliverDue(self: *Pipe, conn: *Connection, now_us: u64) !usize {
        var delivered: usize = 0;
        while (true) {
            var due_index: ?usize = null;
            var due_time: u64 = std.math.maxInt(u64);
            for (self.queue.items, 0..) |entry, i| {
                if (entry.deliver_at_us <= now_us and entry.deliver_at_us < due_time) {
                    due_time = entry.deliver_at_us;
                    due_index = i;
                }
            }
            const index = due_index orelse break;
            const entry = self.queue.orderedRemove(index);
            try conn.ingest(entry.bytes[0..entry.len], now_us);
            delivered += 1;
        }
        return delivered;
    }
};

/// Deterministic in-memory datagram network with aggregate queue bounds in
/// both directions. `Pipe` owns ordering rules; this layer owns resource
/// accounting so duplication and delay cannot grow memory without a cap.
const TestNetwork = struct {
    to_server: Pipe,
    to_client: Pipe,
    limits: Limits,
    max_observed_datagrams: usize = 0,
    max_observed_bytes: usize = 0,

    fn deinit(self: *TestNetwork, allocator: std.mem.Allocator) void {
        self.to_server.deinit(allocator);
        self.to_client.deinit(allocator);
    }

    fn queuedDatagrams(self: *const TestNetwork) usize {
        return self.to_server.queue.items.len + self.to_client.queue.items.len;
    }

    fn queuedBytes(self: *const TestNetwork) usize {
        return self.to_server.queuedBytes() + self.to_client.queuedBytes();
    }

    fn enqueue(
        self: *TestNetwork,
        allocator: std.mem.Allocator,
        comptime direction: Direction,
        bytes: []const u8,
        now_us: u64,
    ) !void {
        const pipe = switch (direction) {
            .to_server => &self.to_server,
            .to_client => &self.to_client,
        };
        const index = pipe.sent;
        const copies: usize = if (pipe.rules.shouldDrop(index)) 0 else if (pipe.rules.shouldDuplicate(index)) 2 else 1;
        if (bytes.len > max_test_datagram_size) return error.DatagramTooLarge;
        if (self.queuedDatagrams() + copies > self.limits.max_queued_datagrams) return error.QueueDatagramLimit;
        if (self.queuedBytes() + bytes.len * copies > self.limits.max_queued_bytes) return error.QueueByteLimit;

        try pipe.schedule(allocator, bytes, now_us);
        self.max_observed_datagrams = @max(self.max_observed_datagrams, self.queuedDatagrams());
        self.max_observed_bytes = @max(self.max_observed_bytes, self.queuedBytes());
    }

    fn nextDeliveryUs(self: *const TestNetwork) ?u64 {
        var next = self.to_server.nextDeliveryUs();
        if (self.to_client.nextDeliveryUs()) |candidate| {
            next = if (next) |current| @min(current, candidate) else candidate;
        }
        return next;
    }
};

const Sim = struct {
    allocator: std.mem.Allocator,
    now_us: u64 = 1_000_000,
    started_at_us: u64 = 1_000_000,
    /// When set, `step` never advances the clock past this point; reaching it
    /// reports quiescence instead (keeps idle timers out of short scenarios).
    clock_cap: ?u64 = null,
    scenario: []const u8,
    seed: u64,
    limits: Limits,
    log_failures: bool,
    iterations: usize = 0,
    timer_events: usize = 0,
    last_failure: ?FailureSnapshot = null,
    client_backend: tls_backend.Tls13Backend,
    server_backend: tls_backend.Tls13Backend,
    client: *Connection,
    server: *Connection,
    network: TestNetwork,

    const client_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    const Config = struct {
        scenario: []const u8 = "unnamed",
        seed: u64 = 0x247_5eed,
        to_server: Rules = .{},
        to_client: Rules = .{},
        quic: quic.config.Config = .{},
        limits: Limits = .{},
        log_failures: bool = true,
    };

    const FailureSnapshot = struct {
        reason: anyerror,
        scenario: []const u8,
        seed: u64,
        now_us: u64,
        iterations: usize,
        timer_events: usize,
        queued_datagrams: usize,
        queued_bytes: usize,
        client_state: connection.State,
        server_state: connection.State,
    };

    fn deterministicBytes(seed: u64, domain: u8) [32]u8 {
        var input: [9]u8 = undefined;
        std.mem.writeInt(u64, input[0..8], seed, .little);
        input[8] = domain;
        var output: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&input, &output, .{});
        return output;
    }

    fn init(allocator: std.mem.Allocator, sim_config: Config) !*Sim {
        const sim = try allocator.create(Sim);
        errdefer allocator.destroy(sim);
        sim.* = .{
            .allocator = allocator,
            .scenario = sim_config.scenario,
            .seed = sim_config.seed,
            .limits = sim_config.limits,
            .log_failures = sim_config.log_failures,
            .client_backend = tls_backend.Tls13Backend.initClient(
                .{
                    .hello_random = deterministicBytes(sim_config.seed, 0x01),
                    .key_share_seed = deterministicBytes(sim_config.seed, 0x02),
                },
                .{ .pinned_certificate = tls_backend.testdata.certificate_der },
            ),
            .server_backend = tls_backend.Tls13Backend.initServer(
                .{
                    .hello_random = deterministicBytes(sim_config.seed, 0x03),
                    .key_share_seed = deterministicBytes(sim_config.seed, 0x04),
                },
                try tls_backend.Identity.initPkcs8(
                    tls_backend.testdata.certificate_der,
                    tls_backend.testdata.private_key_pkcs8_der,
                ),
            ),
            .client = undefined,
            .server = undefined,
            .network = .{
                .to_server = .{ .rules = sim_config.to_server },
                .to_client = .{ .rules = sim_config.to_client },
                .limits = sim_config.limits,
            },
        };
        sim.client = try Connection.init(allocator, .{
            .role = .client,
            .config = sim_config.quic,
            .local_cid = &client_cid,
            .original_dcid = &odcid,
            .tls = sim.client_backend.backend(),
            .now_us = sim.now_us,
        });
        errdefer sim.client.deinit();
        sim.server = try Connection.init(allocator, .{
            .role = .server,
            .config = sim_config.quic,
            .local_cid = &odcid,
            .original_dcid = &odcid,
            .peer_cid = &client_cid,
            .tls = sim.server_backend.backend(),
            .now_us = sim.now_us,
        });
        return sim;
    }

    fn deinit(self: *Sim) void {
        self.client.deinit();
        self.server.deinit();
        self.network.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    fn recordFailure(self: *Sim, reason: anyerror) void {
        if (self.last_failure != null) return;
        self.last_failure = .{
            .reason = reason,
            .scenario = self.scenario,
            .seed = self.seed,
            .now_us = self.now_us,
            .iterations = self.iterations,
            .timer_events = self.timer_events,
            .queued_datagrams = self.network.queuedDatagrams(),
            .queued_bytes = self.network.queuedBytes(),
            .client_state = self.client.state(),
            .server_state = self.server.state(),
        };
        if (self.log_failures) self.logFailure();
    }

    fn logFailure(self: *const Sim) void {
        const failure = self.last_failure.?;
        std.log.err(
            "QUIC/H3 scenario '{s}' seed=0x{x} failed: {s}; now_us={d} iterations={d} timer_events={d} queued={d}/{d}B client={s} server={s}",
            .{
                failure.scenario,
                failure.seed,
                @errorName(failure.reason),
                failure.now_us,
                failure.iterations,
                failure.timer_events,
                failure.queued_datagrams,
                failure.queued_bytes,
                @tagName(failure.client_state),
                @tagName(failure.server_state),
            },
        );
    }

    fn fail(self: *Sim, reason: anyerror) anyerror {
        self.recordFailure(reason);
        return reason;
    }

    fn enqueue(self: *Sim, comptime direction: Direction, datagram: []const u8) !void {
        self.network.enqueue(self.allocator, direction, datagram, self.now_us) catch |err| switch (err) {
            error.DatagramTooLarge => return self.fail(error.DatagramTooLarge),
            error.QueueDatagramLimit => return self.fail(error.QueueDatagramLimit),
            error.QueueByteLimit => return self.fail(error.QueueByteLimit),
            else => return err,
        };
    }

    fn fireTimers(self: *Sim) !void {
        if (self.timer_events >= self.limits.max_timer_events) return self.fail(error.TimerEventLimit);
        self.client.onTimeout(self.now_us);
        self.server.onTimeout(self.now_us);
        self.timer_events += 1;
    }

    fn advanceAndFireTimers(self: *Sim, delta_us: u64) !void {
        const target = std.math.add(u64, self.now_us, delta_us) catch
            return self.fail(error.SimulatedTimeLimit);
        if (target - self.started_at_us > self.limits.max_simulated_time_us) {
            return self.fail(error.SimulatedTimeLimit);
        }
        self.now_us = target;
        try self.fireTimers();
    }

    /// One simulation step: flush transmit queues, deliver due datagrams,
    /// then — if nothing moved — advance the clock to the next deadline.
    /// Returns false when no progress is possible (both sides quiescent).
    fn step(self: *Sim) !bool {
        if (self.iterations >= self.limits.max_iterations) return self.fail(error.IterationLimit);
        self.iterations += 1;
        var progressed = false;
        var packets_produced: usize = 0;
        var buf: [max_test_datagram_size]u8 = undefined;
        while (self.client.pollTransmit(&buf, self.now_us)) |datagram| {
            packets_produced += 1;
            if (packets_produced > self.limits.max_packets_per_iteration) return self.fail(error.PacketProductionLimit);
            try self.enqueue(.to_server, datagram);
            progressed = true;
        }
        while (self.server.pollTransmit(&buf, self.now_us)) |datagram| {
            packets_produced += 1;
            if (packets_produced > self.limits.max_packets_per_iteration) return self.fail(error.PacketProductionLimit);
            try self.enqueue(.to_client, datagram);
            progressed = true;
        }
        if (try self.network.to_server.deliverDue(self.server, self.now_us) > 0) progressed = true;
        if (try self.network.to_client.deliverDue(self.client, self.now_us) > 0) progressed = true;
        if (progressed) return true;

        // Nothing due now: jump to the earliest of in-flight delivery times
        // and both connections' timer deadlines.
        var next: ?u64 = null;
        if (self.network.nextDeliveryUs()) |t| next = minOpt(next, t);
        if (self.client.nextTimeoutUs()) |t| next = minOpt(next, t);
        if (self.server.nextTimeoutUs()) |t| next = minOpt(next, t);
        var target = next orelse return false;
        if (self.clock_cap) |cap| {
            if (self.now_us >= cap) return false;
            target = @min(target, cap);
        }
        if (target <= self.now_us) {
            // A deadline already expired; fire timers without moving time.
            try self.fireTimers();
            return true;
        }
        try self.advanceAndFireTimers(target - self.now_us);
        return true;
    }

    fn minOpt(current: ?u64, candidate: u64) ?u64 {
        if (current) |value| return @min(value, candidate);
        return candidate;
    }

    /// Run until `predicate` holds or the simulated clock passes `budget_us`.
    fn runUntil(self: *Sim, comptime predicate: fn (*Sim) bool, budget_us: u64) !void {
        const deadline = self.now_us + @min(budget_us, self.limits.max_simulated_time_us);
        while (self.now_us < deadline) {
            if (predicate(self)) return;
            if (self.client.state() == .closed or self.server.state() == .closed) {
                return self.fail(error.UnexpectedConnectionClosure);
            }
            if (!try self.step()) {
                if (predicate(self)) return;
                return self.fail(error.NoProgress);
            }
        }
        return self.fail(error.SimulatedTimeLimit);
    }

    fn bothEstablished(self: *Sim) bool {
        return self.client.isEstablished() and self.server.isEstablished();
    }
};

/// Full HTTP/3 exchange over the simulated network. Asserts handshake, ALPN,
/// SETTINGS, request/response HEADERS+DATA, and stream cleanup.
fn runH3Exchange(sim: *Sim) !void {
    try sim.runUntil(Sim.bothEstablished, 30_000_000);
    try testing.expect(sim.client.negotiatedH3());
    try testing.expect(sim.server.negotiatedH3());

    var client_h3 = H3.init(sim.allocator, .client);
    defer client_h3.deinit();
    var server_h3 = H3.init(sim.allocator, .server);
    defer server_h3.deinit();
    try client_h3.start(sim.client);
    try server_h3.start(sim.server);

    const request_id = try client_h3.sendRequest(sim.client, .{
        .authority = "tardigrade.test",
        .path = "/e2e",
        .headers = &.{.{ .name = "user-agent", .value = "tardigrade-e2e/1" }},
        .body = "ping-e2e-body",
    });

    // Serve exactly one request, then read the response.
    var responded = false;
    var response_done = false;
    const budget_end = sim.now_us + 60_000_000;
    while (sim.now_us < budget_end and
        !(response_done and server_h3.metrics.settings_received and client_h3.metrics.settings_received))
    {
        _ = try sim.step();
        try server_h3.pump(sim.server);
        if (!responded) {
            if (try server_h3.pollRequest()) |incoming| {
                try testing.expectEqualStrings("GET", incoming.exchange.request.method);
                try testing.expectEqualStrings("/e2e", incoming.exchange.request.path);
                try testing.expectEqualStrings("tardigrade.test", incoming.exchange.request.authority);
                try testing.expectEqualStrings("ping-e2e-body", incoming.exchange.body.buffered);
                try server_h3.sendResponse(sim.server, incoming.stream_id, 200, &.{
                    .{ .name = "server", .value = "tardigrade" },
                }, "pong-e2e-body");
                responded = true;
            }
        }
        try client_h3.pump(sim.client);
        if (try client_h3.pollResponse(request_id)) |response| {
            try testing.expectEqual(@as(u16, 200), response.status);
            try testing.expectEqualStrings("pong-e2e-body", response.body);
            try testing.expectEqualStrings("server", response.headers[0].name);
            response_done = true;
        }
    }
    try testing.expect(response_done);
    try testing.expect(server_h3.metrics.settings_received);
    try testing.expect(client_h3.metrics.settings_received);
    client_h3.releaseResponse(request_id);

    // Request stream is fully closed on both sides.
    try testing.expectEqual(quic.stream.StreamState.closed, sim.client.streamState(request_id).?);
    try testing.expectEqual(quic.stream.StreamState.closed, sim.server.streamState(request_id).?);
    try testing.expect(sim.network.max_observed_datagrams <= sim.limits.max_queued_datagrams);
    try testing.expect(sim.network.max_observed_bytes <= sim.limits.max_queued_bytes);
}

test "e2e: lossless handshake, SETTINGS, request/response, clean close" {
    var sim = try Sim.init(testing.allocator, .{ .scenario = "lossless" });
    defer sim.deinit();
    errdefer |err| sim.recordFailure(err);
    try runH3Exchange(sim);

    // Clean close: client closes, server drains, both reach closed.
    sim.client.close(0, "done", sim.now_us);
    var budget: usize = 0;
    while (budget < 64 and (sim.client.state() != .closed or sim.server.state() != .closed)) : (budget += 1) {
        if (!try sim.step()) break;
    }
    // Force the 3×PTO close/drain timers if the pipes went quiet first.
    try sim.advanceAndFireTimers(10_000_000);
    try testing.expectEqual(connection.State.closed, sim.client.state());
    try testing.expectEqual(connection.State.closed, sim.server.state());
    const info = sim.server.closeInfo().?;
    try testing.expect(info.is_application);
    try testing.expect(!info.local);
}

test "e2e: lost client Initial recovers via PTO" {
    // Datagram 0 client->server is the first Initial (ClientHello).
    var sim = try Sim.init(testing.allocator, .{
        .scenario = "lost-client-initial",
        .to_server = .{ .drop = &.{0} },
    });
    defer sim.deinit();
    errdefer |err| sim.recordFailure(err);
    try runH3Exchange(sim);
    try testing.expect(sim.client.metrics.pto_count_total > 0);
}

test "e2e: lost server handshake flight recovers" {
    // Datagram 1 server->client carries part of the handshake flight.
    var sim = try Sim.init(testing.allocator, .{
        .scenario = "lost-server-handshake-flight",
        .to_client = .{ .drop = &.{1} },
    });
    defer sim.deinit();
    errdefer |err| sim.recordFailure(err);
    try runH3Exchange(sim);
}

test "e2e: lost 1-RTT request datagram recovers" {
    // After the 4-datagram handshake exchange, subsequent client datagrams
    // carry the H3 control stream and the request; drop two of them.
    var sim = try Sim.init(testing.allocator, .{
        .scenario = "lost-1rtt-request",
        .to_server = .{ .drop = &.{ 3, 4 } },
    });
    defer sim.deinit();
    errdefer |err| sim.recordFailure(err);
    try runH3Exchange(sim);
}

test "e2e: reordered datagrams still complete the exchange" {
    var sim = try Sim.init(testing.allocator, .{
        .scenario = "reordered-datagrams",
        .to_server = .{ .swap = &.{ 2, 4 } },
        .to_client = .{ .swap = &.{3} },
    });
    defer sim.deinit();
    errdefer |err| sim.recordFailure(err);
    try runH3Exchange(sim);
}

test "e2e: duplicated datagrams are idempotent" {
    var sim = try Sim.init(testing.allocator, .{
        .scenario = "duplicated-datagrams",
        .to_server = .{ .duplicate = &.{ 0, 2, 3 } },
        .to_client = .{ .duplicate = &.{ 1, 2 } },
    });
    defer sim.deinit();
    errdefer |err| sim.recordFailure(err);
    try runH3Exchange(sim);
}

test "e2e: loss in both directions during the handshake" {
    var sim = try Sim.init(testing.allocator, .{
        .scenario = "bidirectional-handshake-loss",
        .to_server = .{ .drop = &.{1} },
        .to_client = .{ .drop = &.{0} },
    });
    defer sim.deinit();
    errdefer |err| sim.recordFailure(err);
    try runH3Exchange(sim);
}

test "e2e: stream reset propagates across the simulated network" {
    var sim = try Sim.init(testing.allocator, .{ .scenario = "stream-reset" });
    defer sim.deinit();
    errdefer |err| sim.recordFailure(err);
    try sim.runUntil(Sim.bothEstablished, 30_000_000);

    const id = try sim.client.openStream(.bidi);
    _ = try sim.client.writeStream(id, "partial-body", false);
    sim.clock_cap = sim.now_us + 2_000_000;
    while (try sim.step()) {}
    try sim.client.resetStream(id, 0x0107);
    sim.clock_cap = sim.now_us + 2_000_000;
    while (try sim.step()) {}

    var buf: [32]u8 = undefined;
    try testing.expectError(error.StreamReset, sim.server.readStream(id, &buf));
}

test "e2e: flow-control blocking then resumed progress under tiny windows" {
    // Windows far below the body size force MAX_DATA / MAX_STREAM_DATA
    // credit round-trips mid-transfer.
    var sim = try Sim.init(testing.allocator, .{
        .scenario = "flow-control-resume",
        .quic = .{
            .initial_max_data = 2048,
            .initial_max_stream_data_bidi_local = 1200,
            .initial_max_stream_data_bidi_remote = 1200,
            .initial_max_stream_data_uni = 1200,
        },
    });
    defer sim.deinit();
    errdefer |err| sim.recordFailure(err);
    try sim.runUntil(Sim.bothEstablished, 30_000_000);

    const id = try sim.client.openStream(.bidi);
    const body = [_]u8{0xab} ** 6000;
    var written: usize = 0;
    var received: usize = 0;
    var fin_seen = false;
    var buf: [512]u8 = undefined;
    var stalls: usize = 0;
    while (!fin_seen and stalls < 200) {
        if (written < body.len) {
            written += try sim.client.writeStream(id, body[written..], written + (body.len - written) == body.len);
        }
        const moved = try sim.step();
        while (true) {
            const result = sim.server.readStream(id, &buf) catch break;
            received += result.len;
            if (result.fin) fin_seen = true;
            if (result.len == 0) break;
        }
        if (!moved) stalls += 1 else stalls = 0;
    }
    try testing.expect(fin_seen);
    try testing.expectEqual(body.len, received);
    // The transfer had to be granted more credit than the initial window.
    try testing.expect(sim.server.streams.?.bytes_received == body.len);
    try testing.expect(body.len > 2048);
}

test "e2e: repeated request/response loop on one connection" {
    var sim = try Sim.init(testing.allocator, .{ .scenario = "repeated-requests" });
    defer sim.deinit();
    errdefer |err| sim.recordFailure(err);
    try sim.runUntil(Sim.bothEstablished, 30_000_000);

    var client_h3 = H3.init(sim.allocator, .client);
    defer client_h3.deinit();
    var server_h3 = H3.init(sim.allocator, .server);
    defer server_h3.deinit();
    try client_h3.start(sim.client);
    try server_h3.start(sim.server);

    var round: usize = 0;
    while (round < 12) : (round += 1) {
        var path_buf: [32]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "/loop/{d}", .{round});
        const id = try client_h3.sendRequest(sim.client, .{
            .authority = "tardigrade.test",
            .path = path,
            .body = "loop-body",
        });
        var done = false;
        var responded = false;
        var steps: usize = 0;
        while (!done and steps < 256) : (steps += 1) {
            _ = try sim.step();
            try server_h3.pump(sim.server);
            if (!responded) {
                if (try server_h3.pollRequest()) |incoming| {
                    try testing.expectEqualStrings(path, incoming.exchange.request.path);
                    try server_h3.sendResponse(sim.server, incoming.stream_id, 200, &.{}, "loop-response");
                    responded = true;
                }
            }
            try client_h3.pump(sim.client);
            if (try client_h3.pollResponse(id)) |response| {
                try testing.expectEqual(@as(u16, 200), response.status);
                try testing.expectEqualStrings("loop-response", response.body);
                done = true;
            }
        }
        try testing.expect(done);
        client_h3.releaseResponse(id);
    }
    try testing.expectEqual(@as(u64, 12), server_h3.metrics.requests_decoded);
    try testing.expectEqual(@as(u64, 12), client_h3.metrics.responses_decoded);
}

fn expectFailureSnapshot(sim: *Sim, expected: anyerror, scenario: []const u8, seed: u64) !void {
    const failure = sim.last_failure orelse return error.MissingFailureSnapshot;
    try testing.expectEqual(expected, failure.reason);
    try testing.expectEqualStrings(scenario, failure.scenario);
    try testing.expectEqual(seed, failure.seed);
    try testing.expectEqual(sim.iterations, failure.iterations);
    try testing.expectEqual(sim.timer_events, failure.timer_events);
}

test "e2e harness: scenario seed reproduces the protected wire image" {
    const seed = 0x247_d37e;
    var first = try Sim.init(testing.allocator, .{ .scenario = "seed-first", .seed = seed });
    defer first.deinit();
    errdefer |err| first.recordFailure(err);
    var second = try Sim.init(testing.allocator, .{ .scenario = "seed-second", .seed = seed });
    defer second.deinit();
    errdefer |err| second.recordFailure(err);
    var different = try Sim.init(testing.allocator, .{ .scenario = "seed-different", .seed = seed + 1 });
    defer different.deinit();
    errdefer |err| different.recordFailure(err);

    try testing.expect(try first.step());
    try testing.expect(try second.step());
    try testing.expect(try different.step());
    try testing.expectEqual(@as(usize, 1), first.network.to_server.queue.items.len);
    try testing.expectEqual(@as(usize, 1), second.network.to_server.queue.items.len);
    const first_initial = first.network.to_server.queue.items[0];
    const second_initial = second.network.to_server.queue.items[0];
    try testing.expectEqual(first_initial.len, second_initial.len);
    try testing.expectEqualSlices(
        u8,
        first_initial.bytes[0..first_initial.len],
        second_initial.bytes[0..second_initial.len],
    );

    const different_initial = different.network.to_server.queue.items[0];
    try testing.expect(
        first_initial.len != different_initial.len or
            !std.mem.eql(
                u8,
                first_initial.bytes[0..first_initial.len],
                different_initial.bytes[0..different_initial.len],
            ),
    );
}

test "e2e harness: ordinary scenario errors retain deterministic context" {
    const scenario = "ordinary-protocol-error";
    const seed = 0x247_fa11;
    var sim = try Sim.init(testing.allocator, .{
        .scenario = scenario,
        .seed = seed,
        .log_failures = false,
    });
    defer sim.deinit();
    errdefer |err| sim.recordFailure(err);

    const client_state = sim.client.state();
    const server_state = sim.server.state();
    sim.recordFailure(error.QpackRegression);
    sim.recordFailure(error.LaterFailureMustNotOverwrite);

    try expectFailureSnapshot(sim, error.QpackRegression, scenario, seed);
    try testing.expectEqual(client_state, sim.last_failure.?.client_state);
    try testing.expectEqual(server_state, sim.last_failure.?.server_state);
}

test "e2e network: datagram limit is aggregate across directions" {
    var network = TestNetwork{
        .to_server = .{ .rules = .{} },
        .to_client = .{ .rules = .{} },
        .limits = .{ .max_queued_datagrams = 1 },
    };
    defer network.deinit(testing.allocator);

    const byte = [_]u8{0xaa};
    try network.enqueue(testing.allocator, .to_server, &byte, 0);
    try testing.expectError(
        error.QueueDatagramLimit,
        network.enqueue(testing.allocator, .to_client, &byte, 0),
    );
    try testing.expectEqual(@as(usize, 1), network.queuedDatagrams());
}

test "e2e network: byte limit is aggregate across directions" {
    var network = TestNetwork{
        .to_server = .{ .rules = .{} },
        .to_client = .{ .rules = .{} },
        .limits = .{ .max_queued_bytes = 1 },
    };
    defer network.deinit(testing.allocator);

    const byte = [_]u8{0xbb};
    try network.enqueue(testing.allocator, .to_server, &byte, 0);
    try testing.expectError(
        error.QueueByteLimit,
        network.enqueue(testing.allocator, .to_client, &byte, 0),
    );
    try testing.expectEqual(@as(usize, 1), network.queuedBytes());
}

test "e2e harness: queued datagram limit bounds duplication" {
    const scenario = "queue-datagram-limit";
    const seed = 0x247_0001;
    var sim = try Sim.init(testing.allocator, .{
        .scenario = scenario,
        .seed = seed,
        .to_server = .{ .duplicate = &.{0} },
        .limits = .{ .max_queued_datagrams = 1 },
        .log_failures = false,
    });
    defer sim.deinit();
    errdefer |err| sim.recordFailure(err);

    try testing.expectError(error.QueueDatagramLimit, sim.step());
    try expectFailureSnapshot(sim, error.QueueDatagramLimit, scenario, seed);
    try testing.expectEqual(@as(usize, 0), sim.network.queuedDatagrams());
    try testing.expectEqual(@as(usize, 0), sim.network.queuedBytes());
}

test "e2e harness: queued byte limit rejects oversized aggregate" {
    const scenario = "queue-byte-limit";
    const seed = 0x247_0002;
    var sim = try Sim.init(testing.allocator, .{
        .scenario = scenario,
        .seed = seed,
        .limits = .{ .max_queued_bytes = 1 },
        .log_failures = false,
    });
    defer sim.deinit();
    errdefer |err| sim.recordFailure(err);

    try testing.expectError(error.QueueByteLimit, sim.step());
    try expectFailureSnapshot(sim, error.QueueByteLimit, scenario, seed);
}

test "e2e harness: packet production per iteration is bounded" {
    const scenario = "packet-production-limit";
    const seed = 0x247_0003;
    var sim = try Sim.init(testing.allocator, .{
        .scenario = scenario,
        .seed = seed,
        .limits = .{ .max_packets_per_iteration = 0 },
        .log_failures = false,
    });
    defer sim.deinit();
    errdefer |err| sim.recordFailure(err);

    try testing.expectError(error.PacketProductionLimit, sim.step());
    try expectFailureSnapshot(sim, error.PacketProductionLimit, scenario, seed);
}

test "e2e harness: iteration limit fails at an exact boundary" {
    const scenario = "iteration-limit";
    const seed = 0x247_0004;
    var sim = try Sim.init(testing.allocator, .{
        .scenario = scenario,
        .seed = seed,
        .limits = .{ .max_iterations = 0 },
        .log_failures = false,
    });
    defer sim.deinit();
    errdefer |err| sim.recordFailure(err);

    try testing.expectError(error.IterationLimit, sim.step());
    try expectFailureSnapshot(sim, error.IterationLimit, scenario, seed);
    try testing.expectEqual(@as(usize, 0), sim.iterations);
}

test "e2e harness: timer event limit bounds repeated PTO work" {
    const scenario = "timer-event-limit";
    const seed = 0x247_0005;
    var sim = try Sim.init(testing.allocator, .{
        .scenario = scenario,
        .seed = seed,
        .to_server = .{ .drop = &.{0} },
        .limits = .{ .max_timer_events = 0 },
        .log_failures = false,
    });
    defer sim.deinit();
    errdefer |err| sim.recordFailure(err);

    try testing.expect(try sim.step()); // Produce and deterministically drop Initial.
    try testing.expectError(error.TimerEventLimit, sim.step());
    try expectFailureSnapshot(sim, error.TimerEventLimit, scenario, seed);
    try testing.expectEqual(@as(usize, 0), sim.timer_events);
}

test "e2e harness: simulated elapsed time is bounded without sleeping" {
    const scenario = "simulated-time-limit";
    const seed = 0x247_0006;
    var sim = try Sim.init(testing.allocator, .{
        .scenario = scenario,
        .seed = seed,
        .to_server = .{ .latency_us = 1_000 },
        .limits = .{ .max_simulated_time_us = 500 },
        .log_failures = false,
    });
    defer sim.deinit();
    errdefer |err| sim.recordFailure(err);

    try testing.expect(try sim.step()); // Queue the Initial for delayed delivery.
    try testing.expectError(error.SimulatedTimeLimit, sim.step());
    try expectFailureSnapshot(sim, error.SimulatedTimeLimit, scenario, seed);
}

test "e2e harness: unexpected closure records endpoint states" {
    const scenario = "unexpected-close";
    const seed = 0x247_0007;
    var sim = try Sim.init(testing.allocator, .{
        .scenario = scenario,
        .seed = seed,
        .log_failures = false,
    });
    defer sim.deinit();
    errdefer |err| sim.recordFailure(err);

    sim.client.close(0x247, "closed before establishment", sim.now_us);
    try sim.advanceAndFireTimers(10_000_000);
    try testing.expectEqual(connection.State.closed, sim.client.state());
    try testing.expectError(error.UnexpectedConnectionClosure, sim.runUntil(Sim.bothEstablished, 1_000_000));
    try expectFailureSnapshot(sim, error.UnexpectedConnectionClosure, scenario, seed);
    try testing.expectEqual(connection.State.closed, sim.last_failure.?.client_state);
}
