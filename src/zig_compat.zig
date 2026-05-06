const std = @import("std");

pub const Io = std.Io;

pub fn io() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

/// Drop-in replacement for std.net.Stream using raw POSIX syscalls.
/// Provides writeAll/read/close/writer() interface compatible with anytype writers.
pub const NetStream = struct {
    handle: std.posix.fd_t,

    pub const WriteError = error{WriteFailed};
    pub const ReadError = error{ReadFailed};

    pub fn close(self: NetStream) void {
        _ = std.c.close(self.handle);
    }

    pub fn writeAll(self: NetStream, data: []const u8) WriteError!void {
        var remaining = data;
        while (remaining.len > 0) {
            const n = std.c.write(self.handle, remaining.ptr, remaining.len);
            if (n <= 0) return error.WriteFailed;
            remaining = remaining[@as(usize, @intCast(n))..];
        }
    }

    pub fn read(self: NetStream, buf: []u8) ReadError!usize {
        const n = std.c.read(self.handle, buf.ptr, buf.len);
        if (n < 0) return error.ReadFailed;
        return @intCast(n);
    }

    pub fn print(self: NetStream, comptime fmt: []const u8, args: anytype) !void {
        const s = try std.fmt.allocPrint(std.heap.page_allocator, fmt, args);
        defer std.heap.page_allocator.free(s);
        try self.writeAll(s);
    }

    /// Returns self so stream.writer().writeAll() works with anytype consumers.
    pub fn writer(self: NetStream) NetStream {
        return self;
    }
};

/// Connect a TCP socket to host:port, returning a NetStream.
pub fn tcpConnectToHost(allocator: std.mem.Allocator, host: []const u8, port: u16) !NetStream {
    _ = allocator;
    const address = try std.Io.net.IpAddress.resolve(io(), host, port);
    const stream = try address.connect(io(), .{ .mode = .stream });
    return NetStream{ .handle = stream.socket.handle };
}

/// Connect to a Unix domain socket path, returning a NetStream.
pub fn connectUnixSocket(path: []const u8) !NetStream {
    const ua = try std.Io.net.UnixAddress.init(path);
    const stream = try ua.connect(io());
    return NetStream{ .handle = stream.socket.handle };
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
