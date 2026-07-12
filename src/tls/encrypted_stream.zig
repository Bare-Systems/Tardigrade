//! Nonblocking encrypted byte-stream contract for TLS-over-TCP.
//!
//! HTTP/1.1 and HTTP/2 should consume decrypted bytes and produce plaintext
//! writes without caring whether the TLS implementation underneath is OpenSSL
//! or the native record path. This module defines that small contract and the
//! native record-mode stream state that maps caller-fed ciphertext into
//! plaintext queues without blocking or growing unbounded buffers.

const std = @import("std");
const crypto = @import("crypto");
const algorithms = @import("algorithms.zig");
const events = @import("events.zig");
const record_codec = @import("record_codec.zig");
const record_epoch_bridge = @import("record_epoch_bridge.zig");

const provider = crypto.provider;

pub const Error = record_epoch_bridge.Error || error{
    WouldBlock,
    EndOfStream,
    StreamClosed,
    PlaintextBufferFull,
    CiphertextBufferFull,
};

pub const BackendKind = enum {
    openssl,
    pure_zig_record,
};

pub const Readiness = struct {
    wants_read: bool = false,
    wants_write: bool = false,
    can_read_plaintext: bool = false,
    can_write_plaintext: bool = false,
    peer_closed: bool = false,
};

pub const DriveResult = struct {
    made_progress: bool,
    readiness: Readiness,
};

pub const EncryptedStream = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        backendFn: *const fn (*anyopaque) BackendKind,
        readFn: *const fn (*anyopaque, []u8) Error!usize,
        writeFn: *const fn (*anyopaque, []const u8) Error!usize,
        closeFn: *const fn (*anyopaque) void,
        readinessFn: *const fn (*anyopaque) Readiness,
        driveFn: *const fn (*anyopaque) Error!DriveResult,
    };

    pub fn backend(self: EncryptedStream) BackendKind {
        return self.vtable.backendFn(self.ptr);
    }

    pub fn read(self: EncryptedStream, out: []u8) Error!usize {
        return self.vtable.readFn(self.ptr, out);
    }

    pub fn write(self: EncryptedStream, bytes: []const u8) Error!usize {
        return self.vtable.writeFn(self.ptr, bytes);
    }

    pub fn close(self: EncryptedStream) void {
        self.vtable.closeFn(self.ptr);
    }

    pub fn readiness(self: EncryptedStream) Readiness {
        return self.vtable.readinessFn(self.ptr);
    }

    pub fn drive(self: EncryptedStream) Error!DriveResult {
        return self.vtable.driveFn(self.ptr);
    }
};

pub const PureZigRecordStream = struct {
    pub const max_plaintext_queue = 32 * 1024;
    pub const max_ciphertext_queue = 4 * record_codec.max_ciphertext_record_len;
    pub const max_handshake_queue = 16 * 1024;

    bridge: record_epoch_bridge.Bridge,
    initial_parser: record_codec.Parser = record_codec.Parser.init(.plaintext),
    ciphertext_parser: record_codec.Parser = record_codec.Parser.init(.ciphertext),
    inbound_plaintext: ByteQueue(max_plaintext_queue, error.PlaintextBufferFull) = .{},
    outbound_ciphertext: ByteQueue(max_ciphertext_queue, error.CiphertextBufferFull) = .{},
    inbound_handshake: ByteQueue(max_handshake_queue, error.PlaintextBufferFull) = .{},
    closed: bool = false,
    peer_closed: bool = false,

    pub fn init(crypto_provider: provider.CryptoProvider, cipher_suite: algorithms.CipherSuite) PureZigRecordStream {
        return .{ .bridge = record_epoch_bridge.Bridge.init(crypto_provider, cipher_suite) };
    }

    pub fn deinit(self: *PureZigRecordStream) void {
        self.bridge.deinit();
        self.inbound_plaintext.clear();
        self.outbound_ciphertext.clear();
        self.inbound_handshake.clear();
        self.initial_parser.reset();
        self.ciphertext_parser.reset();
        self.closed = true;
        self.peer_closed = true;
    }

    pub fn stream(self: *PureZigRecordStream) EncryptedStream {
        return .{ .ptr = self, .vtable = &pure_zig_record_vtable };
    }

    pub fn applyEvent(self: *PureZigRecordStream, event: events.Event) Error!void {
        if (self.closed) return error.StreamClosed;
        var record_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
        if (try self.bridge.applyEvent(event, &record_buf)) |record| {
            try self.outbound_ciphertext.append(record);
        }
    }

    pub fn feedHandshakeCiphertext(self: *PureZigRecordStream, epoch: events.EncryptionEpoch, bytes: []const u8) Error!usize {
        if (self.closed) return error.StreamClosed;
        var sink = record_codec.RecordSink(8, record_codec.max_ciphertext_fragment_len * 8){};
        const parser = self.parserForEpoch(epoch);
        try parser.feed(bytes, &sink);
        try self.openHandshakeSink(epoch, &sink);
        return bytes.len;
    }

    pub fn readHandshake(self: *PureZigRecordStream, out: []u8) Error!usize {
        return self.inbound_handshake.read(out) orelse error.WouldBlock;
    }

    pub fn feedCiphertext(self: *PureZigRecordStream, bytes: []const u8) Error!usize {
        if (self.closed) return error.StreamClosed;
        var sink = record_codec.RecordSink(8, record_codec.max_ciphertext_fragment_len * 8){};
        try self.ciphertext_parser.feed(bytes, &sink);

        var plaintext_buf: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
        for (sink.items[0..sink.len]) |record| {
            const opened = try self.bridge.openApplicationData(record, &plaintext_buf);
            try self.inbound_plaintext.append(opened.inner.content);
        }
        return bytes.len;
    }

    pub fn markPeerClosed(self: *PureZigRecordStream) void {
        self.peer_closed = true;
    }

    pub fn readPlaintext(self: *PureZigRecordStream, out: []u8) Error!usize {
        if (self.closed) return error.StreamClosed;
        if (self.inbound_plaintext.read(out)) |n| return n;
        if (self.peer_closed) return error.EndOfStream;
        return error.WouldBlock;
    }

    pub fn writePlaintext(self: *PureZigRecordStream, bytes: []const u8) Error!usize {
        if (self.closed) return error.StreamClosed;
        if (bytes.len == 0) return 0;
        if (!self.bridge.handshake_complete) return error.WouldBlock;
        if (self.outbound_ciphertext.available() < record_codec.max_ciphertext_record_len) return error.WouldBlock;

        const n = @min(bytes.len, record_codec.max_plaintext_fragment_len);
        var record_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
        const record = try self.bridge.sealApplicationData(bytes[0..n], &record_buf);
        try self.outbound_ciphertext.append(record);
        return n;
    }

    pub fn drainCiphertext(self: *PureZigRecordStream, out: []u8) Error!usize {
        if (self.outbound_ciphertext.read(out)) |n| return n;
        if (self.closed) return error.StreamClosed;
        return error.WouldBlock;
    }

    pub fn readiness(self: *const PureZigRecordStream) Readiness {
        return .{
            .wants_read = !self.closed and !self.peer_closed and self.inbound_plaintext.available() > 0,
            .wants_write = self.outbound_ciphertext.len > 0,
            .can_read_plaintext = self.inbound_plaintext.len > 0,
            .can_write_plaintext = !self.closed and self.bridge.handshake_complete and self.outbound_ciphertext.available() >= record_codec.max_ciphertext_record_len,
            .peer_closed = self.peer_closed,
        };
    }

    pub fn drive(self: *PureZigRecordStream) Error!DriveResult {
        return .{ .made_progress = false, .readiness = self.readiness() };
    }

    pub fn queuedCiphertextLen(self: *const PureZigRecordStream) usize {
        return self.outbound_ciphertext.len;
    }

    fn parserForEpoch(self: *PureZigRecordStream, epoch: events.EncryptionEpoch) *record_codec.Parser {
        return switch (epoch) {
            .initial => &self.initial_parser,
            .handshake,
            .application,
            .zero_rtt,
            => &self.ciphertext_parser,
        };
    }

    fn openHandshakeSink(self: *PureZigRecordStream, epoch: events.EncryptionEpoch, sink: anytype) Error!void {
        var plaintext_buf: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
        for (sink.items[0..sink.len]) |record| {
            const opened = try self.bridge.openHandshake(epoch, record, &plaintext_buf);
            try self.inbound_handshake.append(opened.inner.content);
        }
    }
};

fn pureBackend(_: *anyopaque) BackendKind {
    return .pure_zig_record;
}

fn pureRead(ptr: *anyopaque, out: []u8) Error!usize {
    const self: *PureZigRecordStream = @ptrCast(@alignCast(ptr));
    return self.readPlaintext(out);
}

fn pureWrite(ptr: *anyopaque, bytes: []const u8) Error!usize {
    const self: *PureZigRecordStream = @ptrCast(@alignCast(ptr));
    return self.writePlaintext(bytes);
}

fn pureClose(ptr: *anyopaque) void {
    const self: *PureZigRecordStream = @ptrCast(@alignCast(ptr));
    self.closed = true;
}

fn pureReadiness(ptr: *anyopaque) Readiness {
    const self: *PureZigRecordStream = @ptrCast(@alignCast(ptr));
    return self.readiness();
}

fn pureDrive(ptr: *anyopaque) Error!DriveResult {
    const self: *PureZigRecordStream = @ptrCast(@alignCast(ptr));
    return self.drive();
}

const pure_zig_record_vtable = EncryptedStream.VTable{
    .backendFn = pureBackend,
    .readFn = pureRead,
    .writeFn = pureWrite,
    .closeFn = pureClose,
    .readinessFn = pureReadiness,
    .driveFn = pureDrive,
};

fn ByteQueue(comptime capacity: usize, comptime full_error: Error) type {
    return struct {
        buf: [capacity]u8 = undefined,
        len: usize = 0,

        const Self = @This();

        fn append(self: *Self, bytes: []const u8) Error!void {
            if (bytes.len > self.available()) return full_error;
            @memcpy(self.buf[self.len..][0..bytes.len], bytes);
            self.len += bytes.len;
        }

        fn read(self: *Self, out: []u8) ?usize {
            if (self.len == 0) return null;
            const n = @min(out.len, self.len);
            if (n == 0) return 0;
            @memcpy(out[0..n], self.buf[0..n]);
            std.mem.copyForwards(u8, self.buf[0 .. self.len - n], self.buf[n..self.len]);
            self.len -= n;
            return n;
        }

        fn available(self: *const Self) usize {
            return capacity - self.len;
        }

        fn clear(self: *Self) void {
            if (self.len > 0) @memset(self.buf[0..self.len], 0);
            self.len = 0;
        }
    };
}

fn testProvider() provider.CryptoProvider {
    const pure_zig = crypto.pure_zig;
    const State = struct {
        var entropy = pure_zig.DeterministicEntropy.init(0x353);
        var provider_state = pure_zig.Provider.init(entropy.entropy());
    };
    return State.provider_state.cryptoProvider();
}

fn secret(comptime fill: u8) [32]u8 {
    return [_]u8{fill} ** 32;
}

fn establish(client: *PureZigRecordStream, server: *PureZigRecordStream) !void {
    const client_hs = secret(0x11);
    const server_hs = secret(0x22);
    const client_app = secret(0x33);
    const server_app = secret(0x44);

    try client.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .write, .data = &client_hs } });
    try client.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .read, .data = &server_hs } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .read, .data = &client_hs } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .write, .data = &server_hs } });
    try client.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .write, .data = &client_app } });
    try client.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .read, .data = &server_app } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .read, .data = &client_app } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .write, .data = &server_app } });
    try client.applyEvent(.handshake_complete);
    try server.applyEvent(.handshake_complete);
}

fn pumpCiphertext(from: *PureZigRecordStream, to: *PureZigRecordStream, max_chunk: usize) !usize {
    var moved: usize = 0;
    var buf: [128]u8 = undefined;
    while (from.queuedCiphertextLen() > 0) {
        const n = try from.drainCiphertext(buf[0..@min(max_chunk, buf.len)]);
        moved += n;
        _ = try to.feedCiphertext(buf[0..n]);
    }
    return moved;
}

fn pumpHandshake(from: *PureZigRecordStream, to: *PureZigRecordStream, epoch: events.EncryptionEpoch, max_chunk: usize) !usize {
    var moved: usize = 0;
    var buf: [128]u8 = undefined;
    while (from.queuedCiphertextLen() > 0) {
        const n = try from.drainCiphertext(buf[0..@min(max_chunk, buf.len)]);
        moved += n;
        _ = try to.feedHandshakeCiphertext(epoch, buf[0..n]);
    }
    return moved;
}

fn testSocketPair() ![2]std.posix.fd_t {
    var fds: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    errdefer _ = std.c.close(fds[0]);
    errdefer _ = std.c.close(fds[1]);
    try setNonBlocking(fds[0]);
    try setNonBlocking(fds[1]);
    return fds;
}

fn setNonBlocking(fd: std.posix.fd_t) !void {
    const status_flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
    if (status_flags < 0) return error.FcntlFailed;
    const nonblock = @as(c_int, @bitCast(std.posix.O{ .NONBLOCK = true }));
    if (std.c.fcntl(fd, std.c.F.SETFL, status_flags | nonblock) < 0) return error.FcntlFailed;
}

fn flushStreamToFd(stream: *PureZigRecordStream, fd: std.posix.fd_t, max_chunk: usize) !usize {
    var moved: usize = 0;
    var buf: [32]u8 = undefined;
    while (stream.queuedCiphertextLen() > 0) {
        const n = try stream.drainCiphertext(buf[0..@min(max_chunk, buf.len)]);
        const written = std.c.write(fd, &buf, n);
        if (written < 0) return error.SocketWriteFailed;
        if (written == 0) return error.SocketWriteFailed;
        try testing.expectEqual(n, @as(usize, @intCast(written)));
        moved += n;
    }
    return moved;
}

fn readFdIntoStream(fd: std.posix.fd_t, stream: *PureZigRecordStream, max_chunk: usize) !usize {
    var moved: usize = 0;
    var buf: [32]u8 = undefined;
    while (true) {
        const n_raw = std.c.read(fd, &buf, @min(max_chunk, buf.len));
        if (n_raw < 0) {
            if (std.posix.errno(n_raw) == .AGAIN) return moved;
            return error.SocketReadFailed;
        }
        if (n_raw == 0) {
            stream.markPeerClosed();
            return moved;
        }
        const n: usize = @intCast(n_raw);
        moved += n;
        _ = try stream.feedCiphertext(buf[0..n]);
    }
}

const testing = std.testing;

test "pure Zig encrypted stream carries fragmented handshake and application data" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();

    try client.applyEvent(.{ .handshake_bytes = .{ .epoch = .initial, .data = "client hello" } });
    _ = try pumpHandshake(&client, &server, .initial, 3);
    var handshake_buf: [64]u8 = undefined;
    const client_hello_len = try server.readHandshake(&handshake_buf);
    try testing.expectEqualStrings("client hello", handshake_buf[0..client_hello_len]);

    try establish(&client, &server);
    const stream = client.stream();
    try testing.expectEqual(BackendKind.pure_zig_record, stream.backend());

    const written = try stream.write("hello from client");
    try testing.expectEqual(@as(usize, "hello from client".len), written);
    try testing.expect(stream.readiness().wants_write);

    const moved = try pumpCiphertext(&client, &server, 5);
    try testing.expect(moved > written);
    try testing.expect(!stream.readiness().wants_write);

    var plain: [64]u8 = undefined;
    const got = try server.stream().read(&plain);
    try testing.expectEqualStrings("hello from client", plain[0..got]);
}

test "pure Zig encrypted stream exchanges application data over nonblocking socketpair carrier" {
    const fds = try testSocketPair();
    defer _ = std.c.close(fds[0]);
    defer _ = std.c.close(fds[1]);

    const cp = testProvider();
    var client = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    try testing.expectEqual(@as(usize, "client to server".len), try client.stream().write("client to server"));
    try testing.expect((try flushStreamToFd(&client, fds[0], 4)) > "client to server".len);
    try testing.expect((try readFdIntoStream(fds[1], &server, 3)) > "client to server".len);

    var plain: [64]u8 = undefined;
    const server_read = try server.stream().read(&plain);
    try testing.expectEqualStrings("client to server", plain[0..server_read]);

    try testing.expectEqual(@as(usize, "server to client".len), try server.stream().write("server to client"));
    try testing.expect((try flushStreamToFd(&server, fds[1], 5)) > "server to client".len);
    try testing.expect((try readFdIntoStream(fds[0], &client, 2)) > "server to client".len);

    const client_read = try client.stream().read(&plain);
    try testing.expectEqualStrings("server to client", plain[0..client_read]);
    try testing.expectError(error.WouldBlock, client.stream().read(&plain));
}

test "encrypted stream reports would-block and stable readiness without busy-loop progress" {
    const cp = testProvider();
    var stream_state = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer stream_state.deinit();
    const stream = stream_state.stream();

    var buf: [8]u8 = undefined;
    try testing.expectError(error.WouldBlock, stream.read(&buf));
    try testing.expectError(error.WouldBlock, stream.write("x"));

    const before = stream.readiness();
    try testing.expect(before.wants_read);
    try testing.expect(!before.wants_write);
    try testing.expect(!before.can_read_plaintext);
    try testing.expect(!before.can_write_plaintext);

    const drive = try stream.drive();
    try testing.expect(!drive.made_progress);
    try testing.expectEqual(before, drive.readiness);
}

test "encrypted stream interface accepts OpenSSL-like and pure-Zig backends" {
    const FakeOpenSsl = struct {
        inbound: ByteQueue(64, error.PlaintextBufferFull) = .{},
        outbound: ByteQueue(64, error.CiphertextBufferFull) = .{},
        closed: bool = false,

        fn stream(self: *@This()) EncryptedStream {
            return .{ .ptr = self, .vtable = &vtable };
        }

        fn backend(_: *anyopaque) BackendKind {
            return .openssl;
        }

        fn read(ptr: *anyopaque, out: []u8) Error!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return self.inbound.read(out) orelse error.WouldBlock;
        }

        fn write(ptr: *anyopaque, bytes: []const u8) Error!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            const n = @min(bytes.len, self.outbound.available());
            if (n == 0) return error.WouldBlock;
            try self.outbound.append(bytes[0..n]);
            return n;
        }

        fn close(ptr: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.closed = true;
        }

        fn readiness(ptr: *anyopaque) Readiness {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return .{
                .wants_read = !self.closed,
                .wants_write = self.outbound.len > 0,
                .can_read_plaintext = self.inbound.len > 0,
                .can_write_plaintext = !self.closed and self.outbound.available() > 0,
                .peer_closed = false,
            };
        }

        fn drive(ptr: *anyopaque) Error!DriveResult {
            return .{ .made_progress = false, .readiness = readiness(ptr) };
        }

        const vtable = EncryptedStream.VTable{
            .backendFn = backend,
            .readFn = read,
            .writeFn = write,
            .closeFn = close,
            .readinessFn = readiness,
            .driveFn = drive,
        };
    };

    var fake = FakeOpenSsl{};
    var streams = [_]EncryptedStream{fake.stream()};
    try testing.expectEqual(BackendKind.openssl, streams[0].backend());
    try testing.expectEqual(@as(usize, 4), try streams[0].write("ping"));
    streams[0].close();
    try testing.expect(!streams[0].readiness().can_write_plaintext);

    const cp = testProvider();
    var native = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer native.deinit();
    streams[0] = native.stream();
    try testing.expectEqual(BackendKind.pure_zig_record, streams[0].backend());
}
