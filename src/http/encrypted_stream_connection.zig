const std = @import("std");
const encrypted_stream = @import("tls_core").encrypted_stream;

pub const EncryptedStreamHttpConnection = struct {
    stream: encrypted_stream.EncryptedStream,
    fd: std.posix.fd_t = -1,
    close_on_deinit: bool = false,

    pub fn init(stream: encrypted_stream.EncryptedStream) EncryptedStreamHttpConnection {
        return .{ .stream = stream };
    }

    pub fn initWithFd(stream: encrypted_stream.EncryptedStream, fd: std.posix.fd_t) EncryptedStreamHttpConnection {
        return .{ .stream = stream, .fd = fd };
    }

    pub fn deinit(self: *EncryptedStreamHttpConnection) void {
        if (self.close_on_deinit) self.stream.close();
        self.* = undefined;
    }

    pub fn read(self: *EncryptedStreamHttpConnection, out: []u8) encrypted_stream.Error!usize {
        if (out.len == 0) return 0;
        if (self.stream.readiness().can_read_plaintext) {
            return self.stream.read(out) catch |err| mapReadError(err);
        }
        while (true) {
            const driven = try self.stream.drive();
            if (driven.readiness.can_read_plaintext) {
                return self.stream.read(out) catch |err| mapReadError(err);
            }
            if (driven.readiness.peer_closed) return error.EndOfStream;
            if (!driven.made_progress) return error.WouldBlock;
        }
    }

    pub fn pending(self: *const EncryptedStreamHttpConnection) usize {
        const snapshot = self.stream.bufferSnapshot();
        return snapshot.current.inbound_plaintext;
    }

    pub fn pendingPlaintext(self: *const EncryptedStreamHttpConnection) usize {
        return self.pending();
    }

    pub fn readiness(self: *const EncryptedStreamHttpConnection) encrypted_stream.Readiness {
        return self.stream.readiness();
    }

    pub fn bufferSnapshot(self: *const EncryptedStreamHttpConnection) encrypted_stream.BufferSnapshot {
        return self.stream.bufferSnapshot();
    }

    pub fn rawFd(self: *const EncryptedStreamHttpConnection) std.posix.fd_t {
        return self.fd;
    }

    pub const Writer = struct {
        conn: *EncryptedStreamHttpConnection,

        pub fn write(self: Writer, data: []const u8) encrypted_stream.Error!usize {
            return self.conn.write(data);
        }

        /// Compatibility helper for existing synchronous serializers. A caller
        /// that needs to resume after WouldBlock must retain its own operation
        /// cursor and call `write()` instead.
        pub fn writeAll(self: Writer, data: []const u8) encrypted_stream.Error!void {
            return self.conn.writeAll(data);
        }

        pub fn writeByte(self: Writer, byte: u8) encrypted_stream.Error!void {
            return self.writeAll(&[_]u8{byte});
        }

        pub fn print(self: Writer, comptime fmt: []const u8, args: anytype) !void {
            var buf: [4096]u8 = undefined;
            const s = try std.fmt.bufPrint(&buf, fmt, args);
            return self.writeAll(s);
        }
    };

    pub fn writer(self: *EncryptedStreamHttpConnection) Writer {
        return .{ .conn = self };
    }

    pub fn write(self: *EncryptedStreamHttpConnection, bytes: []const u8) encrypted_stream.Error!usize {
        return self.writeRaw(bytes);
    }

    fn writeRaw(self: *EncryptedStreamHttpConnection, bytes: []const u8) encrypted_stream.Error!usize {
        if (bytes.len == 0) return 0;
        while (true) {
            if (self.stream.readiness().can_write_plaintext) {
                return self.stream.write(bytes);
            }
            const driven = try self.stream.drive();
            if (!driven.made_progress and !driven.readiness.can_write_plaintext) return error.WouldBlock;
        }
    }

    fn writeAll(self: *EncryptedStreamHttpConnection, data: []const u8) encrypted_stream.Error!void {
        var offset: usize = 0;
        while (offset < data.len) {
            const n = self.writeRaw(data[offset..]) catch |err| switch (err) {
                error.WouldBlock => return error.WouldBlock,
                else => return err,
            };
            if (n == 0) return error.WouldBlock;
            offset += n;
        }
    }

    fn mapReadError(err: encrypted_stream.Error) encrypted_stream.Error {
        return switch (err) {
            error.WouldBlock => error.WouldBlock,
            error.EndOfStream => error.EndOfStream,
            error.TruncatedStream => error.TruncatedStream,
            error.PeerFatalAlert => error.PeerFatalAlert,
            else => err,
        };
    }
};

test "adapter drains buffered plaintext before driving" {
    var fake = FakeStream{ .readiness_state = .{ .can_read_plaintext = true } };
    var conn = EncryptedStreamHttpConnection.init(fake.stream());
    var buf: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 4), try conn.read(&buf));
    try std.testing.expectEqualStrings("pong", buf[0..4]);
    try std.testing.expectEqual(@as(usize, 0), fake.drive_calls);
}

test "adapter returns WouldBlock when drive makes no progress" {
    var fake = FakeStream{};
    var conn = EncryptedStreamHttpConnection.init(fake.stream());
    var buf: [8]u8 = undefined;
    try std.testing.expectError(error.WouldBlock, conn.read(&buf));
    try std.testing.expectEqual(@as(usize, 1), fake.drive_calls);
}

test "adapter write reports partial progress without retaining serializer state" {
    var fake = FakeStream{
        .readiness_state = .{ .can_write_plaintext = true },
        .write_budget = 3,
    };
    var conn = EncryptedStreamHttpConnection.init(fake.stream());

    try std.testing.expectEqual(@as(usize, 3), try conn.write("abcdef"));
    try std.testing.expectEqualStrings("abc", fake.written[0..fake.written_len]);
    try std.testing.expectError(error.WouldBlock, conn.write("def"));

    fake.readiness_state.can_write_plaintext = true;
    fake.write_budget = 3;
    try std.testing.expectEqual(@as(usize, 3), try conn.write("def"));
    try std.testing.expectEqualStrings("abcdef", fake.written[0..fake.written_len]);
}

test "adapter writeAll has no artificial per-call cap" {
    const large_len = 96 * 1024;
    var fake = FakeStream{
        .readiness_state = .{ .can_write_plaintext = true },
        .write_budget = large_len,
        .max_chunk = 4096,
    };
    var conn = EncryptedStreamHttpConnection.init(fake.stream());

    var data: [large_len]u8 = undefined;
    @memset(&data, 'x');
    try conn.writer().writeAll(&data);

    try std.testing.expectEqual(@as(usize, large_len), fake.written_len);
    try std.testing.expectEqual(@as(usize, 0), fake.write_budget);
}

test "adapter writeAll returns WouldBlock without owning response cursor" {
    var fake = FakeStream{
        .readiness_state = .{ .can_write_plaintext = true },
        .write_budget = 3,
    };
    var conn = EncryptedStreamHttpConnection.init(fake.stream());

    try std.testing.expectError(error.WouldBlock, conn.writer().writeAll("abcdef"));
    try std.testing.expectEqualStrings("abc", fake.written[0..fake.written_len]);

    fake.readiness_state.can_write_plaintext = true;
    fake.write_budget = 3;
    try std.testing.expectEqual(@as(usize, 3), try conn.write("def"));
    try std.testing.expectEqualStrings("abcdef", fake.written[0..fake.written_len]);
}

const FakeStream = struct {
    payload: []const u8 = "pong",
    readiness_state: encrypted_stream.Readiness = .{},
    drive_calls: usize = 0,
    write_budget: usize = std.math.maxInt(usize),
    max_chunk: usize = std.math.maxInt(usize),
    written: [128 * 1024]u8 = undefined,
    written_len: usize = 0,

    fn stream(self: *FakeStream) encrypted_stream.EncryptedStream {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn backend(_: *anyopaque) encrypted_stream.BackendKind {
        return .pure_zig_record;
    }

    fn read(ptr: *anyopaque, out: []u8) encrypted_stream.Error!usize {
        const self: *FakeStream = @ptrCast(@alignCast(ptr));
        if (!self.readiness_state.can_read_plaintext) return error.WouldBlock;
        const n = @min(out.len, self.payload.len);
        @memcpy(out[0..n], self.payload[0..n]);
        self.readiness_state.can_read_plaintext = false;
        return n;
    }

    fn write(ptr: *anyopaque, bytes: []const u8) encrypted_stream.Error!usize {
        const self: *FakeStream = @ptrCast(@alignCast(ptr));
        if (!self.readiness_state.can_write_plaintext or self.write_budget == 0) {
            self.readiness_state.can_write_plaintext = false;
            return error.WouldBlock;
        }
        const n = @min(bytes.len, @min(self.max_chunk, @min(self.write_budget, self.written.len - self.written_len)));
        @memcpy(self.written[self.written_len .. self.written_len + n], bytes[0..n]);
        self.written_len += n;
        self.write_budget -= n;
        if (self.write_budget == 0) self.readiness_state.can_write_plaintext = false;
        return n;
    }

    fn close(_: *anyopaque) void {}

    fn readiness(ptr: *anyopaque) encrypted_stream.Readiness {
        const self: *FakeStream = @ptrCast(@alignCast(ptr));
        return self.readiness_state;
    }

    fn drive(ptr: *anyopaque) encrypted_stream.Error!encrypted_stream.DriveResult {
        const self: *FakeStream = @ptrCast(@alignCast(ptr));
        self.drive_calls += 1;
        return .{ .made_progress = false, .readiness = self.readiness_state };
    }

    fn bufferSnapshot(ptr: *anyopaque) encrypted_stream.BufferSnapshot {
        const self: *FakeStream = @ptrCast(@alignCast(ptr));
        return .{ .current = .{ .inbound_plaintext = if (self.readiness_state.can_read_plaintext) self.payload.len else 0 } };
    }

    const vtable = encrypted_stream.EncryptedStream.VTable{
        .backendFn = backend,
        .readFn = read,
        .writeFn = write,
        .closeFn = close,
        .readinessFn = readiness,
        .driveFn = drive,
        .bufferSnapshotFn = bufferSnapshot,
    };
};
