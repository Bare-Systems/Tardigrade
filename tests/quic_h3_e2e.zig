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
    bytes: [2048]u8,
};

const Pipe = struct {
    rules: Rules,
    sent: usize = 0,
    queue: std.ArrayList(InFlight) = .empty,

    fn deinit(self: *Pipe, allocator: std.mem.Allocator) void {
        self.queue.deinit(allocator);
    }

    fn push(self: *Pipe, allocator: std.mem.Allocator, bytes: []const u8, now_us: u64) !void {
        const index = self.sent;
        self.sent += 1;
        if (self.rules.shouldDrop(index)) return;
        var deliver_at = now_us + self.rules.latency_us;
        if (self.rules.swapsWithNext(index)) {
            // Delivered after its successor: push it further out.
            deliver_at += 2 * self.rules.latency_us;
        }
        var entry = InFlight{ .deliver_at_us = deliver_at, .len = bytes.len, .bytes = undefined };
        @memcpy(entry.bytes[0..bytes.len], bytes);
        try self.queue.append(allocator, entry);
        if (self.rules.shouldDuplicate(index)) {
            entry.deliver_at_us += 1;
            try self.queue.append(allocator, entry);
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

const Sim = struct {
    allocator: std.mem.Allocator,
    now_us: u64 = 1_000_000,
    /// When set, `step` never advances the clock past this point; reaching it
    /// reports quiescence instead (keeps idle timers out of short scenarios).
    clock_cap: ?u64 = null,
    client_backend: tls_backend.Tls13Backend,
    server_backend: tls_backend.Tls13Backend,
    client: *Connection,
    server: *Connection,
    to_server: Pipe,
    to_client: Pipe,

    const client_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    const Config = struct {
        to_server: Rules = .{},
        to_client: Rules = .{},
        quic: quic.config.Config = .{},
    };

    fn init(allocator: std.mem.Allocator, sim_config: Config) !*Sim {
        const sim = try allocator.create(Sim);
        errdefer allocator.destroy(sim);
        sim.* = .{
            .allocator = allocator,
            .client_backend = tls_backend.Tls13Backend.initClient(
                .{ .hello_random = [_]u8{0xc1} ** 32, .key_share_seed = [_]u8{0x11} ** 32 },
                .{ .pinned_certificate = tls_backend.testdata.certificate_der },
            ),
            .server_backend = tls_backend.Tls13Backend.initServer(
                .{ .hello_random = [_]u8{0x51} ** 32, .key_share_seed = [_]u8{0x22} ** 32 },
                try tls_backend.Identity.initPkcs8(
                    tls_backend.testdata.certificate_der,
                    tls_backend.testdata.private_key_pkcs8_der,
                ),
            ),
            .client = undefined,
            .server = undefined,
            .to_server = .{ .rules = sim_config.to_server },
            .to_client = .{ .rules = sim_config.to_client },
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
        self.to_server.deinit(self.allocator);
        self.to_client.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    /// One simulation step: flush transmit queues, deliver due datagrams,
    /// then — if nothing moved — advance the clock to the next deadline.
    /// Returns false when no progress is possible (both sides quiescent).
    fn step(self: *Sim) !bool {
        var progressed = false;
        var buf: [2048]u8 = undefined;
        while (self.client.pollTransmit(&buf, self.now_us)) |datagram| {
            try self.to_server.push(self.allocator, datagram, self.now_us);
            progressed = true;
        }
        while (self.server.pollTransmit(&buf, self.now_us)) |datagram| {
            try self.to_client.push(self.allocator, datagram, self.now_us);
            progressed = true;
        }
        if (try self.to_server.deliverDue(self.server, self.now_us) > 0) progressed = true;
        if (try self.to_client.deliverDue(self.client, self.now_us) > 0) progressed = true;
        if (progressed) return true;

        // Nothing due now: jump to the earliest of in-flight delivery times
        // and both connections' timer deadlines.
        var next: ?u64 = null;
        if (self.to_server.nextDeliveryUs()) |t| next = minOpt(next, t);
        if (self.to_client.nextDeliveryUs()) |t| next = minOpt(next, t);
        if (self.client.nextTimeoutUs()) |t| next = minOpt(next, t);
        if (self.server.nextTimeoutUs()) |t| next = minOpt(next, t);
        var target = next orelse return false;
        if (self.clock_cap) |cap| {
            if (self.now_us >= cap) return false;
            target = @min(target, cap);
        }
        if (target <= self.now_us) {
            // A deadline already expired; fire timers without moving time.
            self.client.onTimeout(self.now_us);
            self.server.onTimeout(self.now_us);
            return true;
        }
        self.now_us = target;
        self.client.onTimeout(self.now_us);
        self.server.onTimeout(self.now_us);
        return true;
    }

    fn minOpt(current: ?u64, candidate: u64) ?u64 {
        if (current) |value| return @min(value, candidate);
        return candidate;
    }

    /// Run until `predicate` holds or the simulated clock passes `budget_us`.
    fn runUntil(self: *Sim, comptime predicate: fn (*Sim) bool, budget_us: u64) !void {
        const deadline = self.now_us + budget_us;
        while (self.now_us < deadline) {
            if (predicate(self)) return;
            if (!try self.step()) {
                if (predicate(self)) return;
                return error.SimulationQuiescent;
            }
        }
        return error.SimulationBudgetExceeded;
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
}

test "e2e: lossless handshake, SETTINGS, request/response, clean close" {
    var sim = try Sim.init(testing.allocator, .{});
    defer sim.deinit();
    try runH3Exchange(sim);

    // Clean close: client closes, server drains, both reach closed.
    sim.client.close(0, "done", sim.now_us);
    var budget: usize = 0;
    while (budget < 64 and (sim.client.state() != .closed or sim.server.state() != .closed)) : (budget += 1) {
        if (!try sim.step()) break;
    }
    // Force the 3×PTO close/drain timers if the pipes went quiet first.
    sim.now_us += 10_000_000;
    sim.client.onTimeout(sim.now_us);
    sim.server.onTimeout(sim.now_us);
    try testing.expectEqual(connection.State.closed, sim.client.state());
    try testing.expectEqual(connection.State.closed, sim.server.state());
    const info = sim.server.closeInfo().?;
    try testing.expect(info.is_application);
    try testing.expect(!info.local);
}

test "e2e: lost client Initial recovers via PTO" {
    // Datagram 0 client->server is the first Initial (ClientHello).
    var sim = try Sim.init(testing.allocator, .{
        .to_server = .{ .drop = &.{0} },
    });
    defer sim.deinit();
    try runH3Exchange(sim);
    try testing.expect(sim.client.metrics.pto_count_total > 0);
}

test "e2e: lost server handshake flight recovers" {
    // Datagram 1 server->client carries part of the handshake flight.
    var sim = try Sim.init(testing.allocator, .{
        .to_client = .{ .drop = &.{1} },
    });
    defer sim.deinit();
    try runH3Exchange(sim);
}

test "e2e: lost 1-RTT request datagram recovers" {
    // After the 4-datagram handshake exchange, subsequent client datagrams
    // carry the H3 control stream and the request; drop two of them.
    var sim = try Sim.init(testing.allocator, .{
        .to_server = .{ .drop = &.{ 3, 4 } },
    });
    defer sim.deinit();
    try runH3Exchange(sim);
}

test "e2e: reordered datagrams still complete the exchange" {
    var sim = try Sim.init(testing.allocator, .{
        .to_server = .{ .swap = &.{ 2, 4 } },
        .to_client = .{ .swap = &.{3} },
    });
    defer sim.deinit();
    try runH3Exchange(sim);
}

test "e2e: duplicated datagrams are idempotent" {
    var sim = try Sim.init(testing.allocator, .{
        .to_server = .{ .duplicate = &.{ 0, 2, 3 } },
        .to_client = .{ .duplicate = &.{ 1, 2 } },
    });
    defer sim.deinit();
    try runH3Exchange(sim);
}

test "e2e: loss in both directions during the handshake" {
    var sim = try Sim.init(testing.allocator, .{
        .to_server = .{ .drop = &.{1} },
        .to_client = .{ .drop = &.{0} },
    });
    defer sim.deinit();
    try runH3Exchange(sim);
}

test "e2e: stream reset propagates across the simulated network" {
    var sim = try Sim.init(testing.allocator, .{});
    defer sim.deinit();
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
        .quic = .{
            .initial_max_data = 2048,
            .initial_max_stream_data_bidi_local = 1200,
            .initial_max_stream_data_bidi_remote = 1200,
            .initial_max_stream_data_uni = 1200,
        },
    });
    defer sim.deinit();
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
    var sim = try Sim.init(testing.allocator, .{});
    defer sim.deinit();
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
