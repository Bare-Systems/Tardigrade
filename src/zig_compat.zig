//! I/O compatibility boundary for Tardigrade (see #211 and docs/CONCURRENCY.md).
//!
//! This module is the seam between the gateway and the still-evolving Zig
//! standard-library I/O (`std.Io`). High-level code — config, files, process,
//! logging, static assets — goes through the helpers here rather than reaching
//! into `std.Io`/`std.posix` directly, so a stdlib API churn is absorbed in one
//! place and those modules stay free of raw syscalls. Add new shared I/O
//! compatibility shims here before reaching into raw OS APIs from config,
//! file, CLI, cache, session, transcript, ACME, or other utility modules.
//!
//! Hot socket paths (`gateway_connection.zig`, `gateway_proxy.zig`, the
//! h2/UDP transports) deliberately use low-level `std.posix` for `poll`,
//! `SO_*TIMEO`, `TCP_NODELAY`, and address handling; that is the sanctioned
//! low-level layer. The only low-level calls outside those socket modules are
//! deliberate: raw `stderr` writes in `logger.zig`/`access_log.zig`, the
//! `access_log.zig` syslog UDP socket, and the `gateway_static_runtime.zig`
//! zero-copy `sendfile`/`socketpair` path. New code should not add raw
//! `std.posix` I/O to config/util modules.

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

    // `anyerror` because the backing std.Io stream error set is still in flux on
    // the pinned compiler; this is the root that makes downstream socket-I/O
    // signatures inferred-open. Narrowing these to a stable domain set is tracked
    // in #211 (I/O boundary) and unblocks further error-set narrowing (#210).
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
        var buf: [4096]u8 = undefined;
        const s = try std.fmt.bufPrint(&buf, fmt, args);
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
            // Format into a stack buffer to avoid heap allocation for the
            // common case of short header lines (< 4 KiB).
            var buf: [4096]u8 = undefined;
            const s = try std.fmt.bufPrint(&buf, fmt, args);
            try self.writeAll(s);
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

/// Disable Nagle's algorithm on a TCP socket (best-effort). Small HTTP/2 frame
/// writes (HEADERS, WINDOW_UPDATE) otherwise interact with the peer's delayed
/// ACK for a ~40 ms per-exchange stall on some stacks, which balloons upstream
/// latency and trips response timeouts under concurrency. Ignored on failure
/// (e.g. a non-TCP fd) since it is purely an optimisation.
pub fn setTcpNoDelay(fd: std.posix.fd_t) void {
    const one: c_int = 1;
    _ = std.c.setsockopt(fd, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, @ptrCast(&one), @sizeOf(c_int));
}

/// Connect a *blocking* TCP socket to host:port via std.c, bypassing the
/// std.Io event loop. Sockets created through `io()` are non-blocking and the
/// threaded backend panics ("programmer bug ... AGAIN") on a SO_*TIMEO EAGAIN,
/// so bounded transports that rely on SO_RCVTIMEO/SO_SNDTIMEO must own a plain
/// blocking fd. On a blocking socket a timed-out recv returns EAGAIN, which
/// std.posix.read maps to error.WouldBlock. Caller closes the fd.
pub fn connectBlockingTcp(host: []const u8, port: u16) !std.posix.fd_t {
    return connectBoundedTcp(host, port, 0);
}

/// Like `connectBlockingTcp`, but bounds the TCP connect itself (#171): with
/// `connect_timeout_ms > 0` the connect runs non-blocking, waits for
/// writability with `poll(2)` up to the deadline, checks `SO_ERROR`, and then
/// restores blocking mode. A plain blocking `connect()` is NOT interruptible
/// by `SO_SNDTIMEO`, so without this an unreachable-but-not-refusing origin
/// (SYN blackhole) stalls the calling worker for the kernel's own limit
/// (typically ~2 minutes). A timed-out connect returns `error.Timeout`, which
/// the proxy maps to 504 `upstream_timeout`. `0` preserves the old blocking
/// behavior. Caller closes the fd.
pub fn connectBoundedTcp(host: []const u8, port: u16, connect_timeout_ms: u32) !std.posix.fd_t {
    const resolved = try std.Io.net.IpAddress.resolve(io(), host, port);
    switch (resolved) {
        .ip4 => |ip4| {
            // Set every field by name (including the address family, which
            // ipAddressToSockAddr leaves zeroed) so connect() sees a valid
            // sockaddr regardless of the platform sockaddr_in layout.
            const sin: std.c.sockaddr.in = .{
                .family = std.posix.AF.INET,
                .port = std.mem.nativeToBig(u16, ip4.port),
                // sin_addr is in network byte order; the address octets are
                // already network-ordered, so bit-cast them directly (a
                // host-endian readInt would byte-swap them on little-endian).
                .addr = @bitCast(ip4.bytes),
                .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
            };
            const sock = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
            if (sock < 0) return error.SocketFailed;
            errdefer _ = std.c.close(sock);
            try connectFdBounded(sock, @ptrCast(&sin), @sizeOf(std.c.sockaddr.in), connect_timeout_ms);
            return sock;
        },
        .ip6 => |ip6| {
            const sin6: std.c.sockaddr.in6 = .{
                .family = std.posix.AF.INET6,
                .port = std.mem.nativeToBig(u16, ip6.port),
                .flowinfo = 0,
                .addr = ip6.bytes,
                .scope_id = ip6.interface.index,
            };
            const sock = std.c.socket(std.posix.AF.INET6, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
            if (sock < 0) return error.SocketFailed;
            errdefer _ = std.c.close(sock);
            try connectFdBounded(sock, @ptrCast(&sin6), @sizeOf(std.c.sockaddr.in6), connect_timeout_ms);
            return sock;
        },
    }
}

/// Connect `sock` to `addr`, bounded by `connect_timeout_ms` when non-zero
/// (non-blocking connect + poll + SO_ERROR, then blocking mode restored).
fn connectFdBounded(sock: std.posix.fd_t, addr: *const std.c.sockaddr, addr_len: std.posix.socklen_t, connect_timeout_ms: u32) !void {
    if (connect_timeout_ms == 0) {
        if (std.c.connect(sock, addr, addr_len) != 0) return error.ConnectionFailed;
        return;
    }

    const flags = std.c.fcntl(sock, std.posix.F.GETFL, @as(c_int, 0));
    if (flags < 0) return error.ConnectionFailed;
    const nonblock: c_int = @bitCast(@as(u32, @bitCast(std.posix.O{ .NONBLOCK = true })));
    if (std.c.fcntl(sock, std.posix.F.SETFL, flags | nonblock) < 0) return error.ConnectionFailed;

    const rc = std.c.connect(sock, addr, addr_len);
    if (rc != 0) {
        switch (std.posix.errno(rc)) {
            // EINTR: POSIX says the connect continues asynchronously — wait
            // for the result via poll like the EINPROGRESS case.
            .INPROGRESS, .INTR, .AGAIN => {},
            else => return error.ConnectionFailed,
        }
        var pfds = [_]std.posix.pollfd{.{
            .fd = sock,
            .events = std.posix.POLL.OUT,
            .revents = 0,
        }};
        const ready = std.posix.poll(&pfds, @intCast(@min(connect_timeout_ms, std.math.maxInt(i32)))) catch
            return error.ConnectionFailed;
        if (ready == 0) return error.Timeout;
        var so_err: c_int = 0;
        var so_len: std.posix.socklen_t = @sizeOf(c_int);
        if (std.c.getsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.ERROR, @ptrCast(&so_err), &so_len) != 0) {
            return error.ConnectionFailed;
        }
        if (so_err != 0) return error.ConnectionFailed;
    }

    if (std.c.fcntl(sock, std.posix.F.SETFL, flags) < 0) return error.ConnectionFailed;
}

/// Set SO_RCVTIMEO / SO_SNDTIMEO (0 disables the respective timeout).
pub fn setSocketTimeoutsMs(fd: std.posix.fd_t, recv_timeout_ms: u32, send_timeout_ms: u32) void {
    const recv_tv = std.posix.timeval{
        .sec = @intCast(recv_timeout_ms / 1000),
        .usec = @intCast((recv_timeout_ms % 1000) * 1000),
    };
    const send_tv = std.posix.timeval{
        .sec = @intCast(send_timeout_ms / 1000),
        .usec = @intCast((send_timeout_ms % 1000) * 1000),
    };
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&recv_tv)) catch {};
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&send_tv)) catch {};
}

/// Connect a *blocking* Unix-domain socket via std.c, bypassing the std.Io
/// event loop. See connectBlockingTcp for why bounded transports need a plain
/// blocking fd. Caller closes the fd.
pub fn connectBlockingUnix(path: []const u8) !std.posix.fd_t {
    var addr = std.mem.zeroes(std.c.sockaddr.un);
    addr.family = std.posix.AF.UNIX;
    if (path.len >= addr.path.len) return error.NameTooLong;
    @memcpy(addr.path[0..path.len], path);
    addr.path[path.len] = 0;
    const len: std.posix.socklen_t = @intCast(@offsetOf(std.c.sockaddr.un, "path") + path.len + 1);
    const sock = std.c.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
    if (sock < 0) return error.SocketFailed;
    errdefer _ = std.c.close(sock);
    if (std.c.connect(sock, @ptrCast(&addr), len) != 0) return error.ConnectionFailed;
    return sock;
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
                .family = std.posix.AF.INET,
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
                .family = std.posix.AF.INET6,
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
    std.Io.sleep(io(), .fromNanoseconds(ns), .awake) catch {}; // interrupt wakes are fine; caller requested a sleep, not a guarantee
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

test "ipAddressToSockAddr sets IPv4 family and length" {
    const addr = try parseIpAddress("127.0.0.1", 8443);
    try std.testing.expectEqual(std.posix.AF.INET, addr.storage.family);
    try std.testing.expectEqual(@as(std.posix.socklen_t, @sizeOf(std.c.sockaddr.in)), addr.len);
}

test "ipAddressToSockAddr sets IPv6 family and length" {
    const addr = try parseIpAddress("::1", 8443);
    try std.testing.expectEqual(std.posix.AF.INET6, addr.storage.family);
    try std.testing.expectEqual(@as(std.posix.socklen_t, @sizeOf(std.c.sockaddr.in6)), addr.len);
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
    fd: std.posix.fd_t,

    pub fn writeAll(self: *CompatWriter, data: []const u8) !void {
        if (builtin.is_test) return;
        var remaining = data;
        while (remaining.len > 0) {
            const written = std.c.write(self.fd, remaining.ptr, remaining.len);
            if (written <= 0) return error.WriteFailed;
            remaining = remaining[@as(usize, @intCast(written))..];
        }
    }

    pub fn print(self: *CompatWriter, comptime fmt: []const u8, args: anytype) !void {
        var buf: [4096]u8 = undefined;
        const rendered = try std.fmt.bufPrint(&buf, fmt, args);
        try self.writeAll(rendered);
    }

    pub fn writeByte(self: *CompatWriter, byte: u8) !void {
        return self.writeAll(&[_]u8{byte});
    }

    pub fn flush(self: *CompatWriter) !void {
        _ = self;
    }
};

pub fn stdoutWriter(buffer: []u8) CompatWriter {
    _ = buffer;
    return .{ .fd = std.Io.File.stdout().handle };
}

pub fn stderrWriter(buffer: []u8) CompatWriter {
    _ = buffer;
    return .{ .fd = std.Io.File.stderr().handle };
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

test "connectBoundedTcp connects, restores blocking mode, and round-trips" {
    // Raw blocking listener.
    const listen_fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    try std.testing.expect(listen_fd >= 0);
    defer _ = std.c.close(listen_fd);
    const sin: std.c.sockaddr.in = .{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 0),
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
        .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    try std.testing.expect(std.c.bind(listen_fd, @ptrCast(&sin), @sizeOf(std.c.sockaddr.in)) == 0);
    try std.testing.expect(std.c.listen(listen_fd, 8) == 0);
    var bound: std.c.sockaddr.in = undefined;
    var bound_len: std.posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    try std.testing.expect(std.c.getsockname(listen_fd, @ptrCast(&bound), &bound_len) == 0);
    const port = std.mem.bigToNative(u16, bound.port);

    const fd = try connectBoundedTcp("127.0.0.1", port, 2_000);
    defer _ = std.c.close(fd);

    // The bounded path must hand back a *blocking* fd — the transports rely on
    // SO_RCVTIMEO/SO_SNDTIMEO semantics that only apply to blocking sockets.
    const flags = std.c.fcntl(fd, std.posix.F.GETFL, @as(c_int, 0));
    try std.testing.expect(flags >= 0);
    const nonblock: c_int = @bitCast(@as(u32, @bitCast(std.posix.O{ .NONBLOCK = true })));
    try std.testing.expect((flags & nonblock) == 0);

    // And the connection actually works end-to-end.
    const conn = std.c.accept(listen_fd, null, null);
    try std.testing.expect(conn >= 0);
    defer _ = std.c.close(conn);
    const msg = "ping";
    try std.testing.expect(std.c.write(fd, msg.ptr, msg.len) == 4);
    var buf: [8]u8 = undefined;
    try std.testing.expect(std.c.read(conn, &buf, buf.len) == 4);
    try std.testing.expectEqualStrings("ping", buf[0..4]);
}

test "connectBoundedTcp bounds a connect that would otherwise hang" {
    // Saturate a backlog-1 listener that never accepts, so further connects
    // sit in the SYN queue (Linux behavior; on platforms where the kernel
    // refuses instead, the call fails fast and the bound trivially holds).
    const listen_fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    try std.testing.expect(listen_fd >= 0);
    defer _ = std.c.close(listen_fd);
    const sin: std.c.sockaddr.in = .{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 0),
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
        .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    try std.testing.expect(std.c.bind(listen_fd, @ptrCast(&sin), @sizeOf(std.c.sockaddr.in)) == 0);
    try std.testing.expect(std.c.listen(listen_fd, 1) == 0);
    var bound: std.c.sockaddr.in = undefined;
    var bound_len: std.posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    try std.testing.expect(std.c.getsockname(listen_fd, @ptrCast(&bound), &bound_len) == 0);
    const port = std.mem.bigToNative(u16, bound.port);

    var fillers: [8]std.posix.fd_t = undefined;
    var n_fillers: usize = 0;
    for (&fillers) |*slot| {
        slot.* = connectBoundedTcp("127.0.0.1", port, 250) catch break;
        n_fillers += 1;
    }
    defer for (fillers[0..n_fillers]) |f| {
        _ = std.c.close(f);
    };

    // Whatever the platform does with the probe (Linux: SYN-queue hang -> our
    // deadline; elsewhere: fast refusal or acceptance), it must return well
    // within the bound rather than the kernel's own multi-minute limit.
    const start_ms = milliTimestamp();
    const probe = connectBoundedTcp("127.0.0.1", port, 500);
    const elapsed_ms = milliTimestamp() - start_ms;
    if (probe) |fd| {
        _ = std.c.close(fd);
    } else |_| {}
    try std.testing.expect(elapsed_ms < 5_000);
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
