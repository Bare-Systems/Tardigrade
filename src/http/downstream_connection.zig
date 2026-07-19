const std = @import("std");
const tls_core = @import("tls_core");
const compat = @import("../zig_compat.zig");
const event_loop = @import("event_loop.zig");
const native_tls_connection = @import("native_tls_connection.zig");
const request_mod = @import("request.zig");
const response_mod = @import("response.zig");
const tls_termination = @import("tls_backend.zig");
const hpack = @import("hpack.zig");

const encrypted_stream = tls_core.encrypted_stream;

pub const RuntimeOutcome = union(enum) {
    continue_now,
    wait: event_loop.Interest,
    idle_keepalive,
    close,
};

pub const OpenSslTransport = struct {
    conn: *tls_termination.TlsConnection,
    allocator: ?std.mem.Allocator = null,
};

pub const DownstreamTransport = union(enum) {
    plaintext: std.posix.fd_t,
    openssl: OpenSslTransport,
    native: *native_tls_connection.NativeTlsConnection,

    pub fn rawFd(self: *const DownstreamTransport) std.posix.fd_t {
        return switch (self.*) {
            .plaintext => |fd| fd,
            .openssl => |transport| transport.conn.rawFd(),
            .native => |conn| conn.rawFd(),
        };
    }

    pub fn encryptedStream(self: *DownstreamTransport) ?encrypted_stream.EncryptedStream {
        return switch (self.*) {
            .plaintext => null,
            .openssl => |transport| transport.conn.stream(),
            .native => |conn| conn.stream(),
        };
    }

    pub fn pendingPlaintext(self: *const DownstreamTransport) usize {
        return switch (self.*) {
            .plaintext => 0,
            .openssl => |transport| transport.conn.pending(),
            .native => |conn| conn.record.bufferSnapshot().current.inbound_plaintext,
        };
    }

    pub fn readiness(self: *DownstreamTransport) encrypted_stream.Readiness {
        return switch (self.*) {
            .plaintext => .{ .wants_read = true, .can_write_plaintext = true },
            .openssl => |transport| transport.conn.stream().readiness(),
            .native => |conn| conn.readiness(),
        };
    }

    pub fn interest(self: *DownstreamTransport) event_loop.Interest {
        return switch (self.*) {
            .plaintext => .{ .read = true },
            else => native_tls_connection.interestForReadiness(self.readiness()),
        };
    }

    pub fn deinit(self: *DownstreamTransport) void {
        switch (self.*) {
            .plaintext => |fd| closeFd(fd),
            .openssl => |transport| {
                const fd = transport.conn.rawFd();
                transport.conn.deinit();
                if (fd >= 0) closeFd(fd);
                if (transport.allocator) |allocator| allocator.destroy(transport.conn);
            },
            .native => |conn| conn.destroy(),
        }
        self.* = undefined;
    }
};

pub const NativeHandshakeState = struct {
    attempts: u32 = 0,
    deadline_ms: u64 = 0,
};

pub const Http1ConnectionState = struct {
    allocator: std.mem.Allocator,
    input: []u8,
    consumed: usize = 0,
    filled: usize = 0,
    parser: RequestParserState = .{},
    request_arena: *std.heap.ArenaAllocator,
    request: ?request_mod.Request = null,
    response: ?response_mod.Response = null,
    write_state: ?response_mod.ResponseWriteState = null,
    include_response_body: bool = true,
    keep_alive: bool = false,
    close_after_response: bool = false,
    served: u32 = 0,
    phase_deadline_ms: u64 = 0,
    outbound: std.ArrayList(u8) = .empty,
    outbound_offset: usize = 0,

    pub const RequestParserState = struct {
        request_line_end: ?usize = null,
        headers_end: ?usize = null,
        body_expected: usize = 0,
        body_received: usize = 0,
    };

    pub fn init(allocator: std.mem.Allocator, input_capacity: usize) !Http1ConnectionState {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        errdefer allocator.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        const input = try allocator.alloc(u8, input_capacity);
        errdefer allocator.free(input);

        return .{
            .allocator = allocator,
            .input = input,
            .request_arena = arena,
        };
    }

    /// Move `response` into this connection state and initialize the output
    /// cursor against the retained object. The caller must not deinit
    /// `response` after a successful call.
    pub fn beginResponse(self: *Http1ConnectionState, response: response_mod.Response, include_body: bool) !void {
        var next_response = response;
        var next_write = try response_mod.ResponseWriteState.init(
            self.allocator,
            &next_response,
            include_body,
        );
        errdefer next_write.deinit();

        if (self.write_state) |*write| {
            write.deinit();
            self.write_state = null;
        }
        if (self.response) |*existing| {
            existing.deinit();
            self.response = null;
        }

        self.response = next_response;
        self.include_response_body = include_body;
        self.write_state = next_write;
    }

    pub fn deinit(self: *Http1ConnectionState) void {
        if (self.write_state) |*write| write.deinit();
        if (self.response) |*response| response.deinit();
        if (self.request) |*request| request.deinit();
        self.outbound.deinit(self.allocator);
        self.request_arena.deinit();
        self.allocator.destroy(self.request_arena);
        self.allocator.free(self.input);
        self.* = undefined;
    }
};

pub const Http2ConnectionState = struct {
    allocator: std.mem.Allocator,
    phase: Phase = .preface,
    preface_offset: usize = 0,
    frame_header: [9]u8 = undefined,
    frame_header_offset: usize = 0,
    frame_payload_len: usize = 0,
    frame_type: u8 = 0,
    frame_flags: u8 = 0,
    frame_stream_id: u31 = 0,
    frame_payload: std.ArrayList(u8) = .empty,
    frame_payload_offset: usize = 0,
    outbound: std.ArrayList(u8) = .empty,
    outbound_offset: usize = 0,
    decoder: hpack.Decoder = hpack.Decoder.init(),
    header_block: std.ArrayList(u8) = .empty,
    conn_recv_window: i64 = 65_535,
    conn_send_window: i64 = 65_535,
    last_stream_id: u31 = 0,
    next_server_stream_id: u31 = 2,
    closing: bool = false,
    idle_or_io_deadline_ms: u64 = 0,

    pub const Phase = enum {
        preface,
        server_settings,
        frame_header,
        frame_payload,
        dispatch,
        closing,
    };

    pub fn init(allocator: std.mem.Allocator) Http2ConnectionState {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Http2ConnectionState) void {
        self.frame_payload.deinit(self.allocator);
        self.outbound.deinit(self.allocator);
        self.header_block.deinit(self.allocator);
        self.decoder.deinit(self.allocator);
        self.* = undefined;
    }
};

pub const ConnectionPhase = union(enum) {
    native_handshake: NativeHandshakeState,
    http1: Http1ConnectionState,
    http2: Http2ConnectionState,
    idle_http1,
};

pub const ManagedConnection = struct {
    pub const Lifecycle = struct {
        session: ?*anyopaque = null,
        release_session_ctx: ?*anyopaque = null,
        release_session_fn: ?*const fn (*anyopaque, *anyopaque) void = null,
        config: ?*const anyopaque = null,
        release_config_ctx: ?*anyopaque = null,
        release_config_version: ?*anyopaque = null,
        release_config_fn: ?*const fn (*anyopaque, *anyopaque) void = null,
        close_ctx: ?*anyopaque = null,
        close_fn: ?*const fn (*anyopaque, std.posix.fd_t) void = null,
        owned_ip: ?[]u8 = null,
        allocator: ?std.mem.Allocator = null,
        config_generation: u64 = 0,
        handshake_timeout_ms: u32 = 0,
        header_timeout_ms: u32 = 0,
        body_timeout_ms: u32 = 0,
        write_timeout_ms: u32 = 0,
        idle_timeout_ms: u32 = 0,

        pub fn connectionIp(self: *const Lifecycle) []const u8 {
            return self.owned_ip orelse "unknown";
        }

        fn deinit(self: *Lifecycle, fd: std.posix.fd_t) void {
            if (self.release_session_fn) |release| {
                if (self.release_session_ctx) |ctx| {
                    if (self.session) |session| release(ctx, session);
                }
            }
            if (self.release_config_fn) |release| {
                if (self.release_config_ctx) |ctx| {
                    if (self.release_config_version) |version| release(ctx, version);
                }
            }
            if (self.owned_ip) |ip| {
                if (self.allocator) |allocator| allocator.free(ip);
            }
            if (self.close_fn) |close_hook| {
                if (self.close_ctx) |ctx| close_hook(ctx, fd);
            }
            self.* = .{};
        }
    };

    fd: std.posix.fd_t,
    transport: DownstreamTransport,
    phase: ConnectionPhase,
    interest: event_loop.Interest,
    lifecycle: Lifecycle = .{},

    pub fn init(transport: DownstreamTransport, phase: ConnectionPhase) ManagedConnection {
        var mutable = transport;
        const interest = mutable.interest();
        return .{
            .fd = mutable.rawFd(),
            .transport = mutable,
            .phase = phase,
            .interest = interest,
        };
    }

    pub fn updateInterest(self: *ManagedConnection) event_loop.Interest {
        return self.updateInterestFor(.{ .read = true });
    }

    pub fn updateInterestFor(self: *ManagedConnection, requested: event_loop.Interest) event_loop.Interest {
        self.interest = switch (self.transport) {
            .plaintext => requested,
            else => combinedInterest(requested, self.transport.readiness()),
        };
        return self.interest;
    }

    pub fn deinit(self: *ManagedConnection) void {
        const fd = self.fd;
        deinitPhase(&self.phase);
        self.transport.deinit();
        self.lifecycle.deinit(fd);
        self.* = undefined;
    }

    pub fn expired(self: *const ManagedConnection, now_ms: u64) bool {
        return switch (self.phase) {
            .native_handshake => |h| h.deadline_ms != 0 and now_ms >= h.deadline_ms,
            .http1 => |h| h.phase_deadline_ms != 0 and now_ms >= h.phase_deadline_ms,
            .http2 => |h| h.idle_or_io_deadline_ms != 0 and now_ms >= h.idle_or_io_deadline_ms,
            .idle_http1 => false,
        };
    }
};

pub const ActiveRegistry = struct {
    allocator: std.mem.Allocator,
    mutex: compat.Mutex = .{},
    map: std.AutoHashMap(std.posix.fd_t, ManagedConnection),

    pub fn init(allocator: std.mem.Allocator) ActiveRegistry {
        return .{
            .allocator = allocator,
            .map = std.AutoHashMap(std.posix.fd_t, ManagedConnection).init(allocator),
        };
    }

    pub fn deinit(self: *ActiveRegistry) void {
        self.closeAll();
        self.map.deinit();
        self.* = undefined;
    }

    pub fn insert(self: *ActiveRegistry, conn: *ManagedConnection) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.map.contains(conn.fd)) return error.DuplicateConnection;
        try self.map.ensureUnusedCapacity(1);
        self.map.putAssumeCapacity(conn.fd, conn.*);
        conn.* = undefined;
    }

    pub fn contains(self: *ActiveRegistry, fd: std.posix.fd_t) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.map.contains(fd);
    }

    pub fn checkout(self: *ActiveRegistry, fd: std.posix.fd_t) ?ManagedConnection {
        self.mutex.lock();
        defer self.mutex.unlock();
        const removed = self.map.fetchRemove(fd) orelse return null;
        return removed.value;
    }

    pub fn rearm(self: *ActiveRegistry, conn: *ManagedConnection) !event_loop.Interest {
        const interest = conn.interest;
        try self.insert(conn);
        return interest;
    }

    pub fn close(self: *ActiveRegistry, fd: std.posix.fd_t) bool {
        self.mutex.lock();
        const removed = self.map.fetchRemove(fd);
        self.mutex.unlock();
        if (removed == null) return false;
        var conn = removed.?.value;
        conn.deinit();
        return true;
    }

    fn takeOne(self: *ActiveRegistry) ?ManagedConnection {
        self.mutex.lock();
        defer self.mutex.unlock();
        var it = self.map.iterator();
        const entry = it.next() orelse return null;
        const fd = entry.key_ptr.*;
        const removed = self.map.fetchRemove(fd).?;
        return removed.value;
    }

    pub fn closeAll(self: *ActiveRegistry) void {
        while (self.takeOne()) |taken| {
            var conn = taken;
            conn.deinit();
        }
    }

    pub fn count(self: *ActiveRegistry) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.map.count();
    }

    pub fn reapExpired(self: *ActiveRegistry, now_ms: u64, out: []ManagedConnection) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var out_len: usize = 0;
        while (out_len < out.len) {
            var expired_fd: ?std.posix.fd_t = null;
            var it = self.map.iterator();
            while (it.next()) |entry| {
                if (!entry.value_ptr.expired(now_ms)) continue;
                expired_fd = entry.key_ptr.*;
                break;
            }
            const fd = expired_fd orelse break;
            const removed = self.map.fetchRemove(fd).?;
            out[out_len] = removed.value;
            out_len += 1;
        }
        return out_len;
    }
};

fn deinitPhase(phase: *ConnectionPhase) void {
    switch (phase.*) {
        .http1 => |*h1| h1.deinit(),
        .http2 => |*h2| h2.deinit(),
        else => {},
    }
    phase.* = .idle_http1;
}

pub fn combinedInterest(requested: event_loop.Interest, readiness: encrypted_stream.Readiness) event_loop.Interest {
    return .{
        .read = requested.read or readiness.wants_read,
        .write = requested.write or readiness.wants_write,
    };
}

fn closeFd(fd: std.posix.fd_t) void {
    if (fd < 0) return;
    if (@import("builtin").os.tag == .linux) {
        _ = std.os.linux.close(fd);
    } else {
        _ = std.c.close(fd);
    }
}

test "plaintext downstream transport exposes read interest" {
    var transport = DownstreamTransport{ .plaintext = 90031 };
    try std.testing.expectEqual(@as(std.posix.fd_t, 90031), transport.rawFd());
    try std.testing.expectEqual(@as(usize, 0), transport.pendingPlaintext());
    try std.testing.expectEqual(event_loop.Interest{ .read = true }, transport.interest());
}

test "managed connection captures fd phase and initial interest" {
    var h1 = try Http1ConnectionState.init(std.testing.allocator, 1024);
    h1.served = 2;
    var managed = ManagedConnection.init(
        .{ .plaintext = -1 },
        .{ .http1 = h1 },
    );
    defer managed.deinit();
    try std.testing.expectEqual(@as(std.posix.fd_t, -1), managed.fd);
    try std.testing.expectEqual(event_loop.Interest{ .read = true }, managed.interest);
    try std.testing.expectEqual(@as(u32, 2), managed.phase.http1.served);
    _ = managed.updateInterest();
    try std.testing.expectEqual(event_loop.Interest{ .read = true }, managed.interest);
}

test "active registry checks out and rearms fd keyed connection ownership" {
    var registry = ActiveRegistry.init(std.testing.allocator);
    defer registry.deinit();

    const h1 = try Http1ConnectionState.init(std.testing.allocator, 1024);
    var managed = ManagedConnection.init(
        .{ .plaintext = -1 },
        .{ .http1 = h1 },
    );
    _ = managed.updateInterestFor(.{ .write = true });

    try registry.insert(&managed);
    try std.testing.expect(registry.contains(-1));
    try std.testing.expectEqual(@as(usize, 1), registry.count());

    var checked_out = registry.checkout(-1) orelse return error.TestExpectedConnection;
    try std.testing.expect(!registry.contains(-1));
    try std.testing.expect(checked_out.interest.write);
    try std.testing.expect(!checked_out.interest.read);

    _ = checked_out.updateInterestFor(.{ .read = true });
    const interest = try registry.rearm(&checked_out);
    try std.testing.expect(interest.read);
    try std.testing.expect(registry.close(-1));
    try std.testing.expectEqual(@as(usize, 0), registry.count());
}

test "active registry rejects duplicate fd without taking replacement ownership" {
    var registry = ActiveRegistry.init(std.testing.allocator);
    defer registry.deinit();

    var first = ManagedConnection.init(
        .{ .plaintext = -1 },
        .{ .native_handshake = .{} },
    );
    try registry.insert(&first);

    var duplicate = ManagedConnection.init(
        .{ .plaintext = -1 },
        .{ .native_handshake = .{} },
    );
    defer duplicate.deinit();

    try std.testing.expectError(error.DuplicateConnection, registry.insert(&duplicate));
    try std.testing.expect(registry.contains(-1));
}

test "active registry insertion failure leaves ownership with caller" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var registry = ActiveRegistry.init(failing.allocator());
    defer registry.deinit();

    var managed = ManagedConnection.init(
        .{ .plaintext = -1 },
        .{ .native_handshake = .{} },
    );
    defer managed.deinit();

    try std.testing.expectError(error.OutOfMemory, registry.insert(&managed));
    try std.testing.expectEqual(@as(std.posix.fd_t, -1), managed.fd);
}

test "active registry reaps expired protocol deadlines" {
    var registry = ActiveRegistry.init(std.testing.allocator);
    defer registry.deinit();

    var expired = ManagedConnection.init(
        .{ .plaintext = -1 },
        .{ .native_handshake = .{ .deadline_ms = 10 } },
    );
    try registry.insert(&expired);

    var live_h1 = try Http1ConnectionState.init(std.testing.allocator, 1024);
    live_h1.phase_deadline_ms = 50;
    var live = ManagedConnection.init(
        .{ .plaintext = -2 },
        .{ .http1 = live_h1 },
    );
    try registry.insert(&live);

    var out: [2]ManagedConnection = undefined;
    const count = registry.reapExpired(11, out[0..]);
    try std.testing.expectEqual(@as(usize, 1), count);
    var taken = out[0];
    defer taken.deinit();
    try std.testing.expectEqual(@as(std.posix.fd_t, -1), taken.fd);
    try std.testing.expect(!registry.contains(-1));
    try std.testing.expect(registry.contains(-2));
}

test "managed connection preserves protocol write interest for plaintext wait-write" {
    const h1 = try Http1ConnectionState.init(std.testing.allocator, 1024);
    var managed = ManagedConnection.init(
        .{ .plaintext = -1 },
        .{ .http1 = h1 },
    );
    defer managed.deinit();
    const interest = managed.updateInterestFor(.{ .write = true });
    try std.testing.expect(interest.write);
    try std.testing.expect(!interest.read);
}

test "combined interest keeps phase demand and TLS carrier readiness" {
    try std.testing.expectEqual(
        event_loop.Interest{ .read = true, .write = true },
        combinedInterest(.{ .read = true }, .{ .wants_write = true }),
    );
    try std.testing.expectEqual(
        event_loop.Interest{ .read = true, .write = true },
        combinedInterest(.{ .write = true }, .{ .wants_read = true }),
    );
}

test "http1 connection state retains arena backed response body across wait-write" {
    var state = try makeArenaBackedHttp1ResponseState(std.testing.allocator);
    defer state.deinit();

    var writer = PartialWriter.init(std.testing.allocator, 2048, 2);
    defer writer.deinit();

    var waits: usize = 0;
    while (true) {
        switch (try state.write_state.?.advance(&writer)) {
            .done => break,
            .wait_write => waits += 1,
        }
    }

    try std.testing.expect(waits > 0);
    const out = writer.output.items;
    const header_end = std.mem.indexOf(u8, out, "\r\n\r\n") orelse return error.TestExpectedHeaders;
    const body = state.response.?.body.?;
    try std.testing.expectEqualSlices(u8, body, out[header_end + 4 ..]);
}

test "http1 beginResponse is transactional on write-state allocation failure" {
    var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 2 });
    var state = try Http1ConnectionState.init(fail.allocator(), 1024);
    defer state.deinit();

    var response = response_mod.Response.init(std.testing.allocator);
    defer response.deinit();
    _ = response.setStatus(.ok)
        .setHeader("X-Owned", "yes")
        .setBodyOwned(try std.testing.allocator.dupe(u8, "owned body"));

    try std.testing.expectError(error.WriteFailed, state.beginResponse(response, true));
    try std.testing.expect(state.response == null);
    try std.testing.expect(state.write_state == null);
}

test "http2 connection state owns frame header payload hpack and outbound cursors" {
    var h2 = Http2ConnectionState.init(std.testing.allocator);
    defer h2.deinit();

    try h2.frame_payload.appendSlice(std.testing.allocator, "payload");
    try h2.header_block.appendSlice(std.testing.allocator, "headers");
    try h2.outbound.appendSlice(std.testing.allocator, "frame");
    h2.frame_header_offset = 4;
    h2.frame_payload_offset = 3;
    h2.outbound_offset = 2;

    try std.testing.expectEqual(@as(usize, 4), h2.frame_header_offset);
    try std.testing.expectEqual(@as(usize, 3), h2.frame_payload_offset);
    try std.testing.expectEqual(@as(usize, 2), h2.outbound_offset);
}

const PartialWriter = struct {
    allocator: std.mem.Allocator,
    output: std.ArrayList(u8) = .empty,
    max_chunk: usize,
    writes_before_block: usize,
    remaining_writes: usize,

    fn init(allocator: std.mem.Allocator, max_chunk: usize, writes_before_block: usize) PartialWriter {
        return .{
            .allocator = allocator,
            .max_chunk = max_chunk,
            .writes_before_block = writes_before_block,
            .remaining_writes = writes_before_block,
        };
    }

    fn deinit(self: *PartialWriter) void {
        self.output.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn write(self: *PartialWriter, bytes: []const u8) !usize {
        if (bytes.len == 0) return 0;
        if (self.remaining_writes == 0) {
            self.remaining_writes = self.writes_before_block;
            return error.WouldBlock;
        }
        self.remaining_writes -= 1;
        const n = @min(self.max_chunk, bytes.len);
        try self.output.appendSlice(self.allocator, bytes[0..n]);
        return n;
    }
};

fn makeArenaBackedHttp1ResponseState(allocator: std.mem.Allocator) !Http1ConnectionState {
    var state = try Http1ConnectionState.init(allocator, 4096);
    errdefer state.deinit();

    const arena_allocator = state.request_arena.allocator();
    const body = try arena_allocator.alloc(u8, 96 * 1024);
    for (body, 0..) |*byte, i| {
        byte.* = @intCast('a' + (i % 26));
    }
    var response = response_mod.Response.init(arena_allocator);
    _ = response.setStatus(.ok).setBody(body).setContentType("text/plain");
    try state.beginResponse(response, true);
    return state;
}
