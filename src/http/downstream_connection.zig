const std = @import("std");
const tls_core = @import("tls_core");
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
        if (self.write_state) |*write| {
            write.deinit();
            self.write_state = null;
        }
        if (self.response) |*existing| {
            existing.deinit();
            self.response = null;
        }

        self.response = response;
        self.include_response_body = include_body;
        self.write_state = try response_mod.ResponseWriteState.init(
            self.allocator,
            &self.response.?,
            include_body,
        );
    }

    pub fn deinit(self: *Http1ConnectionState) void {
        if (self.write_state) |*write| write.deinit();
        if (self.response) |*response| response.deinit();
        if (self.request) |*request| request.deinit();
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
    frame_payload: std.ArrayList(u8) = .empty,
    frame_payload_offset: usize = 0,
    outbound: std.ArrayList(u8) = .empty,
    outbound_offset: usize = 0,
    decoder: hpack.Decoder = hpack.Decoder.init(),
    header_block: std.ArrayList(u8) = .empty,
    conn_recv_window: i64 = 65_535,
    conn_send_window: i64 = 65_535,
    last_stream_id: u31 = 0,
    closing: bool = false,

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
    fd: std.posix.fd_t,
    transport: DownstreamTransport,
    phase: ConnectionPhase,
    interest: event_loop.Interest,

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
        self.interest = combinedInterest(requested, self.transport.readiness());
        return self.interest;
    }

    pub fn deinit(self: *ManagedConnection) void {
        deinitPhase(&self.phase);
        self.transport.deinit();
        self.* = undefined;
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

test "managed connection preserves protocol write interest for plaintext wait-write" {
    const h1 = try Http1ConnectionState.init(std.testing.allocator, 1024);
    var managed = ManagedConnection.init(
        .{ .plaintext = -1 },
        .{ .http1 = h1 },
    );
    defer managed.deinit();
    const interest = managed.updateInterestFor(.{ .write = true });
    try std.testing.expect(interest.write);
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
