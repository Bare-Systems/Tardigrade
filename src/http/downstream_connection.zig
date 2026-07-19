const std = @import("std");
const tls_core = @import("tls_core");
const event_loop = @import("event_loop.zig");
const native_tls_connection = @import("native_tls_connection.zig");
const tls_termination = @import("tls_backend.zig");

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
    served: u32 = 0,
};

pub const Http2ConnectionState = struct {
    preface_offset: usize = 0,
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
        self.interest = self.transport.interest();
        return self.interest;
    }

    pub fn deinit(self: *ManagedConnection) void {
        self.transport.deinit();
        self.* = undefined;
    }
};

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
    var managed = ManagedConnection.init(
        .{ .plaintext = 90032 },
        .{ .http1 = .{ .served = 2 } },
    );
    try std.testing.expectEqual(@as(std.posix.fd_t, 90032), managed.fd);
    try std.testing.expectEqual(event_loop.Interest{ .read = true }, managed.interest);
    try std.testing.expectEqual(@as(u32, 2), managed.phase.http1.served);
    _ = managed.updateInterest();
    try std.testing.expectEqual(event_loop.Interest{ .read = true }, managed.interest);
}
