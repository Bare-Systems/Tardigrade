const std = @import("std");
const builtin = @import("builtin");

pub const Io = std.Io;

var threaded_io: ?std.Io.Threaded = null;

fn inheritedEnviron() std.process.Environ {
    if (!builtin.link_libc) return .empty;

    const environ: [:null]?[*:0]u8 = switch (builtin.os.tag) {
        .wasi, .emscripten => environ: {
            const c_environ = std.c.environ;
            var env_count: usize = 0;
            while (c_environ[env_count] != null) : (env_count += 1) {}
            break :environ c_environ[0..env_count :null];
        },
        else => env: {
            const c_environ = std.c.environ;
            var env_count: usize = 0;
            while (c_environ[env_count] != null) : (env_count += 1) {}
            break :env c_environ[0..env_count :null];
        },
    };
    return .{ .block = .{ .slice = environ } };
}

fn activeThreadedIo() *std.Io.Threaded {
    if (threaded_io == null) {
        threaded_io = std.Io.Threaded.init(std.heap.c_allocator, .{
            .environ = inheritedEnviron(),
        });
    }
    return &threaded_io.?;
}

pub fn io() std.Io {
    return activeThreadedIo().io();
}

/// Drop-in replacement for std.net.Stream backed by Zig 0.16's std.Io runtime.
/// Preserves the old surface area expected by the codebase while routing
/// operations through the new reader/writer implementations.
pub const NetStream = struct {
    inner: ?std.Io.net.Stream = null,
    handle: std.posix.fd_t,

    pub const WriteError = anyerror;
    pub const ReadError = anyerror;

    pub fn close(self: NetStream) void {
        if (self.inner) |inner| {
            inner.close(io());
            return;
        }
        _ = std.c.close(self.handle);
    }

    pub fn writeAll(self: NetStream, data: []const u8) WriteError!void {
        if (self.inner == null) {
            var remaining = data;
            while (remaining.len > 0) {
                const n = std.c.write(self.handle, remaining.ptr, remaining.len);
                if (n <= 0) return error.WriteFailed;
                remaining = remaining[@as(usize, @intCast(n))..];
            }
            return;
        }

        var buf: [1024]u8 = undefined;
        var io_writer = self.inner.?.writer(io(), &buf);
        io_writer.interface.writeAll(data) catch |err| switch (err) {
            error.WriteFailed => return io_writer.err orelse err,
        };
        io_writer.interface.flush() catch |err| switch (err) {
            error.WriteFailed => return io_writer.err orelse err,
        };
    }

    pub fn read(self: NetStream, buf: []u8) ReadError!usize {
        if (self.inner == null) {
            return std.posix.read(self.handle, buf);
        }

        var scratch: [1]u8 = undefined;
        var io_reader = self.inner.?.reader(io(), &scratch);
        return io_reader.interface.readSliceShort(buf) catch |err| switch (err) {
            error.ReadFailed => return io_reader.err orelse err,
        };
    }

    pub fn print(self: NetStream, comptime fmt: []const u8, args: anytype) !void {
        const s = try std.fmt.allocPrint(std.heap.page_allocator, fmt, args);
        defer std.heap.page_allocator.free(s);
        try self.writeAll(s);
    }

    pub const Writer = struct {
        stream: NetStream,

        pub fn writeAll(self: Writer, data: []const u8) WriteError!void {
            try self.stream.writeAll(data);
        }

        pub fn writeByte(self: Writer, byte: u8) WriteError!void {
            try self.writeAll(&[_]u8{byte});
        }

        pub fn print(self: Writer, comptime fmt: []const u8, args: anytype) !void {
            try self.stream.print(fmt, args);
        }
    };

    pub fn writer(self: NetStream) Writer {
        return .{ .stream = self };
    }

    pub const Reader = struct {
        stream: NetStream,

        pub fn readNoEof(self: Reader, out: []u8) ReadError!void {
            var off: usize = 0;
            while (off < out.len) {
                const n = try self.stream.read(out[off..]);
                if (n == 0) return error.EndOfStream;
                off += n;
            }
        }

        pub fn readAllAlloc(self: Reader, allocator: std.mem.Allocator, max_bytes: usize) ReadError![]u8 {
            var out = std.array_list.Managed(u8).init(allocator);
            errdefer out.deinit();

            var buf: [4096]u8 = undefined;
            while (true) {
                const n = try self.stream.read(&buf);
                if (n == 0) break;
                try out.appendSlice(buf[0..n]);
                if (out.items.len > max_bytes) return error.StreamTooLong;
            }
            return out.toOwnedSlice();
        }
    };

    pub fn reader(self: NetStream) Reader {
        return .{ .stream = self };
    }
};

pub fn netStreamFromFd(fd: std.posix.fd_t) NetStream {
    return .{
        .inner = null,
        .handle = fd,
    };
}

/// Connect a TCP socket to host:port, returning a NetStream.
pub fn tcpConnectToHost(allocator: std.mem.Allocator, host: []const u8, port: u16) !NetStream {
    _ = allocator;
    const address = try std.Io.net.IpAddress.resolve(io(), host, port);
    const stream = try address.connect(io(), .{ .mode = .stream });
    return .{
        .inner = stream,
        .handle = stream.socket.handle,
    };
}

/// Connect to a Unix domain socket path, returning a NetStream.
pub fn connectUnixSocket(path: []const u8) !NetStream {
    const ua = try std.Io.net.UnixAddress.init(path);
    const stream = try ua.connect(io());
    return .{
        .inner = stream,
        .handle = stream.socket.handle,
    };
}

pub const NetConnection = struct {
    stream: NetStream,
};

pub const NetServer = struct {
    inner: std.Io.net.Server,

    pub fn accept(self: *NetServer) std.Io.net.Server.AcceptError!NetConnection {
        const stream = try self.inner.accept(io());
        return .{ .stream = .{
            .inner = stream,
            .handle = stream.socket.handle,
        } };
    }

    pub fn deinit(self: *NetServer) void {
        self.inner.deinit(io());
    }

    pub fn port(self: *const NetServer) u16 {
        return self.inner.socket.address.getPort();
    }
};

pub fn listenTcp(host: []const u8, port: u16) !NetServer {
    const address = try std.Io.net.IpAddress.parse(host, port);
    return .{ .inner = try address.listen(io(), .{ .reuse_address = true }) };
}

/// Drop-in replacement for std.Thread.Mutex using the new std.Io.Mutex API.
/// lock/unlock have no io or error parameter to match the old interface.
pub const Mutex = struct {
    inner: std.Io.Mutex = std.Io.Mutex.init,

    pub fn lock(self: *Mutex) void {
        self.inner.lockUncancelable(io());
    }

    pub fn unlock(self: *Mutex) void {
        self.inner.unlock(io());
    }

    pub fn tryLock(self: *Mutex) bool {
        return self.inner.tryLock();
    }
};

pub const Condition = struct {
    inner: std.Io.Condition = .init,

    pub fn wait(self: *Condition, mutex: *Mutex) void {
        self.inner.waitUncancelable(io(), &mutex.inner);
    }

    pub fn signal(self: *Condition) void {
        self.inner.signal(io());
    }

    pub fn broadcast(self: *Condition) void {
        self.inner.broadcast(io());
    }
};

pub const SockAddr = struct {
    storage: std.c.sockaddr.storage,
    len: std.posix.socklen_t,
};

pub fn ipAddressToSockAddr(address: std.Io.net.IpAddress) SockAddr {
    var storage = std.mem.zeroes(std.c.sockaddr.storage);
    switch (address) {
        .ip4 => |ip4| {
            const sin: *std.c.sockaddr.in = @ptrCast(&storage);
            sin.* = .{
                .port = std.mem.nativeToBig(u16, ip4.port),
                .addr = std.mem.readInt(u32, &ip4.bytes, .big),
            };
            return .{
                .storage = storage,
                .len = @sizeOf(std.c.sockaddr.in),
            };
        },
        .ip6 => |ip6| {
            const sin6: *std.c.sockaddr.in6 = @ptrCast(&storage);
            sin6.* = .{
                .port = std.mem.nativeToBig(u16, ip6.port),
                .flowinfo = 0,
                .addr = ip6.bytes,
                .scope_id = ip6.interface.index,
            };
            return .{
                .storage = storage,
                .len = @sizeOf(std.c.sockaddr.in6),
            };
        },
    }
}

pub fn parseIpAddress(host: []const u8, port: u16) !SockAddr {
    return ipAddressToSockAddr(try std.Io.net.IpAddress.parse(host, port));
}

pub fn resolveIpAddress(host: []const u8, port: u16) !SockAddr {
    return ipAddressToSockAddr(try std.Io.net.IpAddress.resolve(io(), host, port));
}

pub fn unixTimestamp() i64 {
    return std.Io.Clock.real.now(io()).toSeconds();
}

pub fn milliTimestamp() i64 {
    return std.Io.Clock.real.now(io()).toMilliseconds();
}

pub fn nanoTimestamp() i128 {
    return @intCast(std.Io.Clock.real.now(io()).toNanoseconds());
}

pub fn sleepNs(ns: u64) void {
    std.Io.sleep(io(), .fromNanoseconds(ns), .awake) catch {};
}

pub fn randomBytes(buffer: []u8) void {
    io().random(buffer);
}

pub fn trimRight(comptime T: type, slice: []const T, values_to_strip: []const T) []const T {
    return std.mem.trimEnd(T, slice, values_to_strip);
}

pub fn intToEnum(comptime E: type, integer: anytype) ?E {
    return std.enums.fromInt(E, integer);
}

pub fn stringifyAlloc(allocator: std.mem.Allocator, value: anytype, options: std.json.Stringify.Options) error{OutOfMemory}![]u8 {
    return std.json.Stringify.valueAlloc(allocator, value, options);
}

pub fn getEnvVarOwned(allocator: std.mem.Allocator, key: []const u8) error{ EnvironmentVariableNotFound, OutOfMemory }![]u8 {
    const key_z = try allocator.dupeZ(u8, key);
    defer allocator.free(key_z);

    const value = std.c.getenv(key_z.ptr) orelse return error.EnvironmentVariableNotFound;
    return allocator.dupe(u8, std.mem.span(value));
}

pub fn timingSafeEql(comptime T: type, a: T, b: T) bool {
    return std.crypto.timing_safe.eql(T, a, b);
}

pub const FmtSliceHexLower = struct {
    bytes: []const u8,

    pub fn format(self: FmtSliceHexLower, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{x}", .{self.bytes});
    }
};

pub fn fmtSliceHexLower(bytes: []const u8) FmtSliceHexLower {
    return .{ .bytes = bytes };
}

pub const FixedBufferStream = struct {
    writer_impl: std.Io.Writer,

    pub fn writer(self: *FixedBufferStream) *std.Io.Writer {
        return &self.writer_impl;
    }

    pub fn getWritten(self: *const FixedBufferStream) []u8 {
        return self.writer_impl.buffered();
    }
};

pub fn fixedBufferStream(buffer: []u8) FixedBufferStream {
    return .{ .writer_impl = .fixed(buffer) };
}

pub const CompatWriter = struct {
    inner: std.Io.File.Writer,

    pub fn writeAll(self: CompatWriter, data: []const u8) !void {
        var s = self;
        return s.inner.interface.writeAll(data);
    }

    pub fn print(self: CompatWriter, comptime fmt: []const u8, args: anytype) !void {
        var s = self;
        return s.inner.interface.print(fmt, args);
    }

    pub fn writeByte(self: CompatWriter, byte: u8) !void {
        return self.writeAll(&[_]u8{byte});
    }

    pub fn flush(self: *CompatWriter) !void {
        return self.inner.flush();
    }
};

pub fn stdoutWriter(buffer: []u8) CompatWriter {
    return .{ .inner = std.Io.File.stdout().writer(io(), buffer) };
}

pub fn stderrWriter(buffer: []u8) CompatWriter {
    return .{ .inner = std.Io.File.stderr().writer(io(), buffer) };
}

pub const FileStat = struct {
    inode: std.Io.File.INode,
    nlink: std.Io.File.NLink,
    size: u64,
    permissions: std.Io.File.Permissions,
    kind: std.Io.File.Kind,
    atime: ?i128,
    mtime: i128,
    ctime: i128,
    block_size: std.Io.File.BlockSize,
};

pub const FileCompat = struct {
    file: std.Io.File,

    pub fn close(self: *FileCompat) void {
        self.file.close(io());
    }

    pub fn writeAll(self: *FileCompat, bytes: []const u8) !void {
        try self.file.writeStreamingAll(io(), bytes);
    }

    pub fn readToEndAlloc(self: *FileCompat, allocator: std.mem.Allocator, limit: usize) ![]u8 {
        var buffer: [4096]u8 = undefined;
        var reader = self.file.reader(io(), &buffer);
        return reader.interface.allocRemaining(allocator, .limited(limit));
    }

    pub fn flush(self: *FileCompat) std.Io.File.SyncError!void {
        try self.file.sync(io());
    }

    pub fn stat(self: *FileCompat) std.Io.File.StatError!FileStat {
        const raw = try self.file.stat(io());
        return .{
            .inode = raw.inode,
            .nlink = raw.nlink,
            .size = raw.size,
            .permissions = raw.permissions,
            .kind = raw.kind,
            .atime = if (raw.atime) |value| @intCast(value.toNanoseconds()) else null,
            .mtime = @intCast(raw.mtime.toNanoseconds()),
            .ctime = @intCast(raw.ctime.toNanoseconds()),
            .block_size = raw.block_size,
        };
    }
};

pub fn openFileAbsolute(path: []const u8, flags: std.Io.Dir.OpenFileOptions) std.Io.File.OpenError!FileCompat {
    return .{ .file = try std.Io.Dir.openFileAbsolute(io(), path, flags) };
}

pub fn createFileAbsolute(path: []const u8, flags: std.Io.Dir.CreateFileOptions) std.Io.File.OpenError!FileCompat {
    return .{ .file = try std.Io.Dir.createFileAbsolute(io(), path, flags) };
}

pub const DirCompat = struct {
    dir: std.Io.Dir,

    pub fn createFile(self: DirCompat, sub_path: []const u8, flags: std.Io.Dir.CreateFileOptions) std.Io.File.OpenError!FileCompat {
        return .{ .file = try self.dir.createFile(io(), sub_path, flags) };
    }

    pub fn openFile(self: DirCompat, sub_path: []const u8, flags: std.Io.Dir.OpenFileOptions) std.Io.File.OpenError!FileCompat {
        return .{ .file = try self.dir.openFile(io(), sub_path, flags) };
    }

    pub fn writeFile(self: DirCompat, options: std.Io.Dir.WriteFileOptions) std.Io.Dir.WriteFileError!void {
        try self.dir.writeFile(io(), options);
    }

    pub fn readFileAlloc(self: DirCompat, allocator: std.mem.Allocator, sub_path: []const u8, limit: usize) std.Io.Dir.ReadFileAllocError![]u8 {
        return self.dir.readFileAlloc(io(), sub_path, allocator, .limited(limit));
    }

    pub fn realpathAlloc(self: DirCompat, allocator: std.mem.Allocator, sub_path: []const u8) std.Io.Dir.RealPathFileAllocError![]u8 {
        const raw = try self.dir.realPathFileAlloc(io(), sub_path, allocator);
        defer allocator.free(raw);
        return allocator.dupe(u8, raw);
    }

    pub fn makePath(self: DirCompat, sub_path: []const u8) std.Io.Dir.CreateDirPathError!void {
        try self.dir.createDirPath(io(), sub_path);
    }

    pub fn deleteFile(self: DirCompat, sub_path: []const u8) std.Io.Dir.DeleteFileError!void {
        try self.dir.deleteFile(io(), sub_path);
    }

    pub fn deleteTree(self: DirCompat, sub_path: []const u8) std.Io.Dir.DeleteTreeError!void {
        try self.dir.deleteTree(io(), sub_path);
    }

    pub fn statFile(self: DirCompat, sub_path: []const u8) std.Io.Dir.StatFileError!std.Io.File.Stat {
        return self.dir.statFile(io(), sub_path, .{});
    }

    pub fn openDir(self: DirCompat, sub_path: []const u8, options: std.Io.Dir.OpenOptions) std.Io.Dir.OpenError!DirCompat {
        return .{ .dir = try self.dir.openDir(io(), sub_path, options) };
    }

    pub fn close(self: DirCompat) void {
        self.dir.close(io());
    }

    pub fn access(self: DirCompat, sub_path: []const u8, options: std.Io.Dir.AccessOptions) std.Io.Dir.AccessError!void {
        return self.dir.access(io(), sub_path, options);
    }

    pub fn rename(self: DirCompat, old_sub_path: []const u8, new_dir: DirCompat, new_sub_path: []const u8) std.Io.Dir.RenameError!void {
        return self.dir.rename(old_sub_path, new_dir.dir, new_sub_path, io());
    }

    pub fn iterate(self: DirCompat) std.Io.Dir.Iterator {
        return self.dir.iterate();
    }
};

pub fn cwd() DirCompat {
    return .{ .dir = .cwd() };
}

pub fn wrapDir(dir: std.Io.Dir) DirCompat {
    return .{ .dir = dir };
}

test "milliTimestamp returns a positive value" {
    const ms = milliTimestamp();
    try std.testing.expect(ms > 0);
}

test "monotonicMs does not go backward" {
    // Just verify it's callable and returns a plausible value (> 0)
    const a = milliTimestamp();
    const b = milliTimestamp();
    try std.testing.expect(b >= a);
}

test "randomBytes fills buffer with data" {
    var buf1: [16]u8 = [_]u8{0} ** 16;
    var buf2: [16]u8 = [_]u8{0} ** 16;
    randomBytes(&buf1);
    randomBytes(&buf2);
    // Both filled (not all zeros — near-zero probability of collision)
    var all_zero1 = true;
    for (buf1) |b| if (b != 0) {
        all_zero1 = false;
        break;
    };
    try std.testing.expect(!all_zero1);
}

test "stringifyAlloc produces valid JSON for a simple struct" {
    const val = .{ .ok = true, .code = 42 };
    const json = try stringifyAlloc(std.testing.allocator, val, .{});
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.find(u8, json, "\"ok\":true") != null);
    try std.testing.expect(std.mem.find(u8, json, "\"code\":42") != null);
}

test "fixedBufferStream write and read back" {
    var buf: [32]u8 = undefined;
    var fbs = fixedBufferStream(&buf);
    try fbs.writer().writeAll("hello");
    try std.testing.expectEqualStrings("hello", fbs.getWritten());
}

test "trimRight removes trailing characters" {
    try std.testing.expectEqualStrings("foo", trimRight(u8, "foo   ", " "));
    try std.testing.expectEqualStrings("foo", trimRight(u8, "foo\n\r", "\r\n"));
    try std.testing.expectEqualStrings("", trimRight(u8, "   ", " "));
}

test "fmtSliceHexLower formats bytes as lowercase hex" {
    const hex = fmtSliceHexLower(&[_]u8{ 0xde, 0xad, 0xbe, 0xef });
    var buf: [64]u8 = undefined;
    var fbs = fixedBufferStream(&buf);
    try hex.format(fbs.writer());
    try std.testing.expectEqualStrings("deadbeef", fbs.getWritten());
}

test "DirCompat write and read file roundtrip" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = wrapDir(tmp.dir);
    try dir.writeFile(.{ .sub_path = "test.txt", .data = "hello zig" });
    const data = try dir.readFileAlloc(std.testing.allocator, "test.txt", 1024);
    defer std.testing.allocator.free(data);
    try std.testing.expectEqualStrings("hello zig", data);
}

test "DirCompat createFile and stat" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = wrapDir(tmp.dir);
    var f = try dir.createFile("out.txt", .{});
    try f.writeAll("data");
    f.close();
    const stat = try dir.statFile("out.txt");
    try std.testing.expect(stat.size > 0);
}
