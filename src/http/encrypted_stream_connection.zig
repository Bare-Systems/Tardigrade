const std = @import("std");
const encrypted_stream = @import("tls_core").encrypted_stream;

pub const EncryptedStreamHttpConnection = struct {
    const max_pending_write = 64 * 1024;

    stream: encrypted_stream.EncryptedStream,
    fd: std.posix.fd_t = -1,
    close_on_deinit: bool = false,
    pending_write_buf: [max_pending_write]u8 = undefined,
    pending_write_len: usize = 0,
    pending_write_offset: usize = 0,

    pub fn init(stream: encrypted_stream.EncryptedStream) EncryptedStreamHttpConnection {
        return .{ .stream = stream };
    }

    pub fn initWithFd(stream: encrypted_stream.EncryptedStream, fd: std.posix.fd_t) EncryptedStreamHttpConnection {
        return .{ .stream = stream, .fd = fd };
    }

    pub fn deinit(self: *EncryptedStreamHttpConnection) void {
        if (self.close_on_deinit) self.stream.close();
        self.clearPendingWrite();
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

    fn write(self: *EncryptedStreamHttpConnection, bytes: []const u8) encrypted_stream.Error!usize {
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
        if (data.len == 0) return;
        if (self.pending_write_len == 0) {
            if (data.len > max_pending_write) return error.PlaintextBufferFull;
            @memcpy(self.pending_write_buf[0..data.len], data);
            self.pending_write_len = data.len;
            self.pending_write_offset = 0;
        } else {
            const pending_bytes = self.pending_write_buf[0..self.pending_write_len];
            if (!std.mem.eql(u8, pending_bytes, data)) return error.RetryOperationPending;
        }

        while (self.pending_write_offset < self.pending_write_len) {
            const n = self.write(self.pending_write_buf[self.pending_write_offset..self.pending_write_len]) catch |err| switch (err) {
                error.WouldBlock => return error.WouldBlock,
                else => return err,
            };
            if (n == 0) return error.WouldBlock;
            self.pending_write_offset += n;
        }
        self.clearPendingWrite();
    }

    fn clearPendingWrite(self: *EncryptedStreamHttpConnection) void {
        if (self.pending_write_len > 0) {
            @memset(self.pending_write_buf[0..self.pending_write_len], 0);
            self.pending_write_len = 0;
            self.pending_write_offset = 0;
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

test "adapter writeAll resumes partial writes without duplicating prefix" {
    var fake = FakeStream{
        .readiness_state = .{ .can_write_plaintext = true },
        .write_budget = 3,
    };
    var conn = EncryptedStreamHttpConnection.init(fake.stream());

    try std.testing.expectError(error.WouldBlock, conn.writer().writeAll("abcdef"));
    try std.testing.expectEqualStrings("abc", fake.written[0..fake.written_len]);
    try std.testing.expectEqual(@as(usize, 6), conn.pending_write_len);
    try std.testing.expectEqual(@as(usize, 3), conn.pending_write_offset);

    try std.testing.expectError(error.RetryOperationPending, conn.writer().writeAll("abcxyz"));

    fake.readiness_state.can_write_plaintext = true;
    fake.write_budget = 3;
    try conn.writer().writeAll("abcdef");
    try std.testing.expectEqualStrings("abcdef", fake.written[0..fake.written_len]);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_write_len);
}

const FakeStream = struct {
    payload: []const u8 = "pong",
    readiness_state: encrypted_stream.Readiness = .{},
    drive_calls: usize = 0,
    write_budget: usize = std.math.maxInt(usize),
    written: [64]u8 = undefined,
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
        const n = @min(bytes.len, @min(self.write_budget, self.written.len - self.written_len));
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
