//! Native QUIC/H3 interop tool (#247 phase 5).
//!
//! A small out-of-process client and server built on the native connection
//! driver and H3 glue, used to exercise interoperability against external
//! implementations (ngtcp2/nghttp3 example clients/servers, quiche, aioquic).
//! External peers stay out of process; nothing foreign links into Tardigrade.
//!
//! Usage:
//!   h3_interop_tool server --port N --cert cert.der --key key.pkcs8.der \
//!       [--response-body STR] [--requests N] [--expect-hrr] [--verbose] \
//!       [--qlog-dir DIR] [--qlog-dialect current|qvis-legacy] [--keylog-path FILE]
//!   h3_interop_tool client --host A.B.C.D --port N --authority NAME \
//!       --path /p [--body STR] [--empty-initial-key-share] \
//!       [--reset-after-request] \
//!       [--expect-hrr] [--insecure | --pin cert.der] [--verbose] \
//!       [--qlog-dir DIR] [--qlog-dialect current|qvis-legacy] [--keylog-path FILE]
//!
//! `--qlog-dialect` defaults to `current` (the standard `QlogFileSeq`
//! header). Pass `qvis-legacy` only when generating an artifact meant to be
//! opened in the hosted qvis tool's older `.sqlog` loader (#625) — it is not
//! a standard-schema declaration and should not be used for other purposes.
//!
//! The client exits 0 once it has received a complete response (status and
//! body are printed to stdout). The server exits 0 after serving --requests
//! requests (default 1) and seeing the connection close or drain. --verbose
//! streams connection-driver events (packet, loss, PTO, key, state) to
//! stderr for debugging interop failures.

const std = @import("std");
const quic = @import("quic");
const http3 = @import("http3");
const matrix = @import("tls_interop_matrix");
const compat = @import("zig_compat");

const connection = quic.connection;
const tls_backend = quic.tls_backend;
const production_crypto = quic.tls_core.production_crypto;
const Connection = connection.Connection;
const H3 = http3.conn.Conn(Connection);
const posix = std.posix;

fn nowUs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000 + @as(u64, @intCast(ts.nsec)) / 1_000;
}

var verbose = false;

const ArtifactSink = struct {
    qlog_file: ?compat.FileCompat = null,
    keylog_fd: ?posix.fd_t = null,
    qlog_dropped_records: usize = 0,
    keylog_dropped_records: usize = 0,
    close_logged: bool = false,

    const qlog_record_max = http3.qlog.max_serialized_record_len;
    const keylog_record_max = 512;

    fn init(
        allocator: std.mem.Allocator,
        qlog_dir: []const u8,
        keylog_path: []const u8,
        mode: Args.Mode,
        group_id: []const u8,
        qlog_dialect: quic.qlog.HeaderDialect,
    ) !ArtifactSink {
        var sink = ArtifactSink{};
        errdefer sink.deinit();

        if (qlog_dir.len > 0) {
            try compat.cwd().makePath(qlog_dir);
            const path = try std.fmt.allocPrint(allocator, "{s}/{s}-{s}.sqlog", .{ qlog_dir, @tagName(mode), group_id });
            defer allocator.free(path);
            var file = try compat.cwd().createFile(path, .{ .read = false });
            errdefer file.close();
            var header_buf: [1024]u8 = undefined;
            const header = try quic.qlog.writeTraceHeader(.{
                .vantage_point = switch (mode) {
                    .client => .client,
                    .server => .server,
                },
                .group_id = group_id,
                .title = "tardigrade-h3-interop",
                .description = "Tardigrade HTTP/3 external interop debug trace",
            }, qlog_dialect, &header_buf);
            try file.writeAll(header);
            sink.qlog_file = file;
        }

        if (keylog_path.len > 0) {
            sink.keylog_fd = try openAppendOnly0600(keylog_path);
        }

        return sink;
    }

    fn deinit(self: *ArtifactSink) void {
        if (self.qlog_file) |*file| file.close();
        if (self.keylog_fd) |fd| _ = std.c.close(fd);
        self.* = undefined;
    }

    fn quicSink(self: *ArtifactSink) connection.EventSink {
        if (self.qlog_file == null) return .{ .emitFn = logEvent };
        return .{ .context = self, .emitFn = emitQuicEvent };
    }

    fn h3Sink(self: *ArtifactSink) http3.conn.EventSink {
        if (self.qlog_file == null) return .{};
        return .{ .context = self, .emitFn = emitH3Event };
    }

    fn keylogContext(self: *ArtifactSink, role: quic.tls_core.state.Role) quic.tls_core.keylog.Context {
        if (self.keylog_fd == null) return .{};
        return .{
            .enabled = true,
            .role = role,
            .sink = .{ .context = self, .emit_fn = emitKeylog },
        };
    }

    fn emitQuicQlog(self: *ArtifactSink, event: quic.qlog.Event) void {
        if (self.qlog_file == null) return;
        var bytes: [qlog_record_max]u8 = undefined;
        const line = quic.qlog.writeJson(.{ .time_us = nowUs(), .event = event }, &bytes) catch {
            self.qlog_dropped_records += 1;
            return;
        };
        if (self.qlog_file) |*file| file.writeAll(line) catch {
            self.qlog_dropped_records += 1;
        };
    }

    fn reportDiagnostics(self: *const ArtifactSink) void {
        if (self.qlog_dropped_records == 0 and self.keylog_dropped_records == 0) return;
        std.debug.print("h3-interop: artifact diagnostics qlog_dropped_records={d} keylog_dropped_records={d}\n", .{
            self.qlog_dropped_records,
            self.keylog_dropped_records,
        });
    }

    fn emitQuicEvent(ctx: ?*anyopaque, event: connection.Event) void {
        logEvent(null, event);
        const self: *ArtifactSink = @ptrCast(@alignCast(ctx.?));
        const qlog_event = quicEventToQlog(event) orelse return;
        switch (qlog_event) {
            .connection_closed => {
                if (self.close_logged) return;
                self.close_logged = true;
            },
            else => {},
        }
        self.emitQuicQlog(qlog_event);
    }

    fn emitH3Event(ctx: ?*anyopaque, event: http3.conn.Event) void {
        const self: *ArtifactSink = @ptrCast(@alignCast(ctx.?));
        const qlog_event = h3EventToQlog(event);
        var bytes: [qlog_record_max]u8 = undefined;
        const line = http3.qlog.writeJson(.{ .time_us = nowUs(), .event = qlog_event }, &bytes) catch {
            self.qlog_dropped_records += 1;
            return;
        };
        if (self.qlog_file) |*file| file.writeAll(line) catch {
            self.qlog_dropped_records += 1;
        };
    }

    fn emitKeylog(ctx: ?*anyopaque, entry: quic.tls_core.keylog.Entry) void {
        const self: *ArtifactSink = @ptrCast(@alignCast(ctx.?));
        var bytes: [keylog_record_max]u8 = undefined;
        const line = quic.tls_core.keylog.writeLine(entry, &bytes) catch {
            self.keylog_dropped_records += 1;
            return;
        };
        if (self.keylog_fd) |fd| writeAllFd(fd, line) catch {
            self.keylog_dropped_records += 1;
        };
    }

    fn openAppendOnly0600(path: []const u8) !posix.fd_t {
        const fd = try posix.openat(posix.AT.FDCWD, path, .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .APPEND = true,
            .CLOEXEC = true,
        }, 0o600);
        errdefer _ = std.c.close(fd);
        if (std.c.fchmod(fd, 0o600) != 0) return error.PermissionDenied;
        return fd;
    }

    fn writeAllFd(fd: posix.fd_t, bytes: []const u8) !void {
        var written: usize = 0;
        while (written < bytes.len) {
            const n = std.c.write(fd, bytes[written..].ptr, bytes.len - written);
            if (n < 0) return error.WriteFailed;
            if (n == 0) return error.WriteFailed;
            written += @intCast(n);
        }
    }
};

/// Plain sequential write(2) to fd 1. `Io.File.writer` uses positional
/// writes, which scribble over interleaved stderr output when both streams
/// are redirected to the same file (as interop scripts do with `2>&1`).
fn writeStdout(bytes: []const u8) void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = std.c.write(1, bytes.ptr + written, bytes.len - written);
        if (n <= 0) return;
        written += @intCast(n);
    }
}

fn logEvent(_: ?*anyopaque, event: connection.Event) void {
    if (!verbose) return;
    var buf: [256]u8 = undefined;
    const line = switch (event) {
        .state => |s| std.fmt.bufPrint(&buf, "state -> {s}", .{@tagName(s)}),
        .packet_received => |p| std.fmt.bufPrint(&buf, "rx space={s} pn={d} size={d}", .{ @tagName(p.space), p.packet_number, p.size }),
        .packet_sent => |p| std.fmt.bufPrint(&buf, "tx space={s} pn={d} size={d} ack_eliciting={}", .{ @tagName(p.space), p.packet_number, p.size, p.ack_eliciting }),
        .packet_dropped => |p| std.fmt.bufPrint(&buf, "drop reason={s} size={d}", .{ @tagName(p.reason), p.size }),
        .keys_discarded => |s| std.fmt.bufPrint(&buf, "keys discarded space={s}", .{@tagName(s)}),
        .handshake_complete => std.fmt.bufPrint(&buf, "handshake complete", .{}),
        .handshake_confirmed => std.fmt.bufPrint(&buf, "handshake confirmed", .{}),
        .pto_fired => |p| std.fmt.bufPrint(&buf, "pto space={s} count={d}", .{ @tagName(p.space), p.count }),
        .packets_acked => |p| std.fmt.bufPrint(&buf, "ack space={s} pn={d}", .{ @tagName(p.space), p.packet_number }),
        .packets_lost => |p| std.fmt.bufPrint(&buf, "loss space={s} type={?s} count={d} bytes={d}", .{ @tagName(p.space), if (p.packet_type) |kind| @tagName(kind) else null, p.lost_count, p.bytes }),
        .recovery_metrics_updated => |m| std.fmt.bufPrint(&buf, "recovery latest_rtt_us={?d} smoothed_rtt_us={?d} rttvar_us={?d} pto={d} cwnd={d} bif={d}", .{ m.latest_rtt_us, m.smoothed_rtt_us, m.rttvar_us, m.pto_count, m.congestion_window, m.bytes_in_flight }),
        .stream_reset => |s| std.fmt.bufPrint(&buf, "stream_reset id={d} code={d} local={}", .{ s.id, s.error_code, s.local }),
        .stop_sending => |s| std.fmt.bufPrint(&buf, "stop_sending id={d} code={d} local={}", .{ s.id, s.error_code, s.local }),
        .stream_state_changed => |s| std.fmt.bufPrint(&buf, "stream_state id={d} side={s} old={?s} new={s} trigger={?s}", .{ s.id, @tagName(s.side), if (s.old) |old| @tagName(old) else null, @tagName(s.new), if (s.trigger) |trigger| @tagName(trigger) else null }),
        .congestion_state_changed => |c| std.fmt.bufPrint(&buf, "congestion_state {s}->{s}", .{ @tagName(c.old), @tagName(c.new) }),
        .persistent_congestion => std.fmt.bufPrint(&buf, "persistent congestion", .{}),
        .flow_control_state_changed => |f| std.fmt.bufPrint(&buf, "flow_control scope={s} stream_id={?d} local={} {s}->{s}", .{ @tagName(f.scope), f.stream_id, f.local, @tagName(f.old), @tagName(f.new) }),
        .flow_control_blocked_received => |f| std.fmt.bufPrint(&buf, "flow_control_blocked_received scope={s} stream_id={?d}", .{ @tagName(f.scope), f.stream_id }),
        .local_close_started => |c| std.fmt.bufPrint(&buf, "close started code={d} app={}", .{ c.error_code, c.is_application }),
        .close_sent => |c| std.fmt.bufPrint(&buf, "close sent code={d} app={}", .{ c.error_code, c.is_application }),
        .close_received => |c| std.fmt.bufPrint(&buf, "close received code={d} app={}", .{ c.error_code, c.is_application }),
        .idle_timeout => std.fmt.bufPrint(&buf, "idle timeout", .{}),
        .path_validation_started => |p| std.fmt.bufPrint(&buf, "path validation started change={s} remote_port={d}", .{ @tagName(p.change), p.path.remote.port }),
        .path_validation_succeeded => |p| std.fmt.bufPrint(&buf, "path validation succeeded change={s} remote_port={d}", .{ @tagName(p.change), p.path.remote.port }),
        .path_validation_failed => |p| std.fmt.bufPrint(&buf, "path validation failed change={s} remote_port={d}", .{ @tagName(p.change), p.path.remote.port }),
        .path_migration_blocked => |p| std.fmt.bufPrint(&buf, "path blocked change={s} reason={s} remote_port={d}", .{ @tagName(p.change), @tagName(p.reason), p.path.remote.port }),
        .path_promoted => |p| std.fmt.bufPrint(&buf, "path promoted change={s} remote_port={d}", .{ @tagName(p.change), p.path.remote.port }),
        .pmtu_updated => |p| std.fmt.bufPrint(&buf, "pmtu {s} size={d} remote_port={d}", .{ @tagName(p.reason), p.size, p.path.remote.port }),
        // #256-E: the reason is what makes an interop transcript useful here.
        // "ECN turned off" is the expected outcome against a lot of real
        // networks, and which check rejected the peer's feedback is the
        // difference between a stripped codepoint and a peer that miscounts.
        .ecn_state_changed => |e| if (e.reason) |reason|
            std.fmt.bufPrint(&buf, "ecn {s} reason={s} remote_port={d}", .{ @tagName(e.state), @tagName(reason), e.path.remote.port })
        else
            std.fmt.bufPrint(&buf, "ecn {s} remote_port={d}", .{ @tagName(e.state), e.path.remote.port }),
        .zero_rtt_packet => |z| std.fmt.bufPrint(&buf, "zero_rtt_packet outcome={s} size={d}", .{ @tagName(z.outcome), z.size }),
        .early_data_decision => |d| std.fmt.bufPrint(&buf, "early_data_decision {s}", .{@tagName(d)}),
    } catch return;
    std.debug.print("h3-interop: {s}\n", .{line});
}

const Args = struct {
    pub const Mode = enum { client, server };

    mode: Mode,
    host: []const u8 = "127.0.0.1",
    port: u16 = 4433,
    authority: []const u8 = "tardigrade.test",
    path: []const u8 = "/",
    body: []const u8 = "",
    cert: []const u8 = "",
    key: []const u8 = "",
    pin: []const u8 = "",
    insecure: bool = false,
    response_body: []const u8 = "hello from tardigrade native h3\n",
    requests: usize = 1,
    timeout_ms: u64 = 15_000,
    empty_initial_key_share: bool = false,
    expect_hrr: bool = false,
    /// Send both STOP_SENDING and RESET_STREAM immediately after the request
    /// is on the wire, then keep driving QUIC briefly so an external server
    /// observes cancellation without waiting for idle timeout.
    reset_after_request: bool = false,
    reset_after_request_delay_ms: u64 = 0,
    qlog_dir: []const u8 = "",
    /// #625: `.current` (default) is the standard `QlogFileSeq` header; pass
    /// `--qlog-dialect qvis-legacy` only when the artifact is meant to be
    /// opened in the hosted qvis tool's older `.sqlog` loader.
    qlog_dialect: quic.qlog.HeaderDialect = .current,
    keylog_path: []const u8 = "",
    /// #338: the shared conformance-matrix negotiation tuple. Left empty, the
    /// tool offers QUIC's ordinary default policy exactly as before.
    config: matrix.Config = .{},
    /// #338: require the handshake to have selected exactly this protocol.
    /// Parity with `tls_interop_tool --expect-alpn` so a matrix row asserts
    /// the same things on either transport. `null` leaves ALPN unchecked
    /// (h3 is separately proven by `negotiatedH3()`).
    expect_alpn: ?[]const u8 = null,
};

/// The engine policy for this run: QUIC transport mode, h3 as the default
/// ALPN, and whatever the matrix row pinned. Built through the same
/// `matrix.Config` the record-transport tool uses, so "aes256-gcm-sha384 +
/// secp256r1 + ecdsa-p256-sha256" is one engine configuration regardless of
/// which transport is carrying it.
/// `args` is taken by pointer, not by value: the returned policy's
/// suite/group/signature slices point into `args.config`'s inline storage, so
/// a by-value parameter would hand back slices into a copy that dies with this
/// call.
fn quicPolicy(args: *const Args) quic.tls_core.policy.Policy {
    const default_alpns = [_]quic.tls_core.algorithms.ProtocolName{quic.tls_core.algorithms.alpn.h3};
    return args.config.policy(.quic, &default_alpns);
}

/// Emit the negotiated tuple in the shared matrix vocabulary, so a QUIC row
/// and a record row read identically in a CI log (#338).
fn reportNegotiated(args: Args, backend: *const tls_backend.Tls13Backend, saw_hrr: bool) void {
    std.debug.print("tls-interop: outcome=ok transport=quic role={s} suite={s} group={s} alpn={s} hrr={}\n", .{
        @tagName(args.mode),
        matrix.cipherSuiteName(backend.engine.negotiated_cipher_suite),
        matrix.namedGroupName(backend.engine.negotiated_named_group),
        backend.alpn,
        saw_hrr,
    });
}

/// Translate this transport's backend state into the shared `Negotiated`
/// value and apply the *same* validator the record transport uses (#338
/// review). Only this translation is transport-specific; the expectations
/// themselves must not be, or an identically-named matrix cell would come to
/// mean different things on the two carriers.
fn matrixTupleHolds(args: Args, backend: *const tls_backend.Tls13Backend) bool {
    var ignored: u8 = 0;
    return args.config.validateNegotiated(.{
        .cipher_suite = backend.engine.negotiated_cipher_suite,
        .named_group = backend.engine.negotiated_named_group,
        .alpn = backend.alpn,
    }, args.expect_alpn, &ignored, reportMismatch);
}

fn reportMismatch(_: *u8, mismatch: matrix.Mismatch) void {
    std.debug.print("h3-interop: expected {s} {s} but negotiated {s}\n", .{
        mismatch.dimension,
        mismatch.expected,
        mismatch.observed,
    });
}

fn parseArgs(allocator: std.mem.Allocator, init_args: std.process.Args) !Args {
    var it = init_args.iterate();
    _ = it.next(); // argv[0]
    const mode_str = it.next() orelse return error.MissingMode;
    var args = Args{
        .mode = if (std.mem.eql(u8, mode_str, "server")) .server else if (std.mem.eql(u8, mode_str, "client")) .client else return error.UnknownMode,
    };
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--verbose")) {
            verbose = true;
        } else if (std.mem.eql(u8, arg, "--insecure")) {
            args.insecure = true;
        } else if (std.mem.eql(u8, arg, "--empty-initial-key-share")) {
            args.empty_initial_key_share = true;
        } else if (std.mem.eql(u8, arg, "--expect-hrr")) {
            args.expect_hrr = true;
        } else if (std.mem.eql(u8, arg, "--reset-after-request")) {
            args.reset_after_request = true;
        } else if (std.mem.eql(u8, arg, "--reset-after-request-ms")) {
            args.reset_after_request = true;
            args.reset_after_request_delay_ms = try std.fmt.parseInt(u64, it.next() orelse return error.MissingValue, 10);
        } else if (std.mem.eql(u8, arg, "--host")) {
            args.host = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--port")) {
            args.port = try std.fmt.parseInt(u16, it.next() orelse return error.MissingValue, 10);
        } else if (std.mem.eql(u8, arg, "--authority")) {
            args.authority = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--path")) {
            args.path = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--body")) {
            args.body = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--cert")) {
            args.cert = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--key")) {
            args.key = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--pin")) {
            args.pin = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--response-body")) {
            args.response_body = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--requests")) {
            args.requests = try std.fmt.parseInt(usize, it.next() orelse return error.MissingValue, 10);
        } else if (std.mem.eql(u8, arg, "--timeout-ms")) {
            args.timeout_ms = try std.fmt.parseInt(u64, it.next() orelse return error.MissingValue, 10);
        } else if (std.mem.eql(u8, arg, "--cipher-suite")) {
            try args.config.addCipherSuite(try allocator.dupe(u8, it.next() orelse return error.MissingValue));
        } else if (std.mem.eql(u8, arg, "--group")) {
            try args.config.addNamedGroup(try allocator.dupe(u8, it.next() orelse return error.MissingValue));
        } else if (std.mem.eql(u8, arg, "--signature")) {
            try args.config.addSignatureScheme(try allocator.dupe(u8, it.next() orelse return error.MissingValue));
        } else if (std.mem.eql(u8, arg, "--alpn")) {
            try args.config.addAlpn(try allocator.dupe(u8, it.next() orelse return error.MissingValue));
        } else if (std.mem.eql(u8, arg, "--expect-alpn")) {
            args.expect_alpn = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--qlog-dir")) {
            args.qlog_dir = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else if (std.mem.eql(u8, arg, "--qlog-dialect")) {
            const value = it.next() orelse return error.MissingValue;
            args.qlog_dialect = if (std.mem.eql(u8, value, "current"))
                .current
            else if (std.mem.eql(u8, value, "qvis-legacy"))
                .qvis_legacy
            else
                return error.UnknownQlogDialect;
        } else if (std.mem.eql(u8, arg, "--keylog-path")) {
            args.keylog_path = try allocator.dupe(u8, it.next() orelse return error.MissingValue);
        } else {
            std.debug.print("h3-interop: unknown argument {s}\n", .{arg});
            return error.UnknownArgument;
        }
    }
    return args;
}

const UdpSocket = struct {
    fd: std.c.fd_t,
    /// The actually-bound local address (`getsockname` semantics): with
    /// `bind_port = 0` the OS assigns an ephemeral port only known after
    /// bind. Used as every `PathKey`'s local half for this socket.
    local: std.c.sockaddr.in,

    fn open(bind_port: u16) !UdpSocket {
        // macOS/BSD reject SOCK_CLOEXEC/SOCK_NONBLOCK in the socket type
        // (EPROTOTYPE); apply them via fcntl after creation instead.
        const fd = std.c.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
        if (fd < 0) return error.SocketFailed;
        errdefer _ = std.c.close(fd);
        const descriptor_flags = std.c.fcntl(fd, std.c.F.GETFD, @as(c_int, 0));
        if (descriptor_flags >= 0) _ = std.c.fcntl(fd, std.c.F.SETFD, descriptor_flags | std.c.FD_CLOEXEC);
        const status_flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
        if (status_flags >= 0) _ = std.c.fcntl(fd, std.c.F.SETFL, status_flags | @as(c_int, @bitCast(posix.O{ .NONBLOCK = true })));
        var bind_addr = std.c.sockaddr.in{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, bind_port),
            .addr = 0, // INADDR_ANY
        };
        if (std.c.bind(fd, @ptrCast(&bind_addr), @sizeOf(std.c.sockaddr.in)) != 0) return error.BindFailed;
        var bound: std.c.sockaddr.in = undefined;
        var bound_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
        if (std.c.getsockname(fd, @ptrCast(&bound), &bound_len) != 0) return error.GetSockNameFailed;
        return .{ .fd = fd, .local = bound };
    }

    fn close(self: *UdpSocket) void {
        _ = std.c.close(self.fd);
    }

    fn sendTo(self: *UdpSocket, peer: std.c.sockaddr.in, bytes: []const u8) !void {
        const sent = std.c.sendto(self.fd, bytes.ptr, bytes.len, 0, @ptrCast(&peer), @sizeOf(std.c.sockaddr.in));
        if (sent < 0 or @as(usize, @intCast(sent)) != bytes.len) return error.SendFailed;
    }

    fn recvFrom(self: *UdpSocket, buf: []u8, from: *std.c.sockaddr.in) !?[]u8 {
        var from_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
        const n = std.c.recvfrom(self.fd, buf.ptr, buf.len, 0, @ptrCast(from), &from_len);
        if (n < 0) {
            return switch (posix.errno(n)) {
                .AGAIN => null,
                .CONNREFUSED => null,
                else => error.RecvFailed,
            };
        }
        return buf[0..@intCast(n)];
    }

    fn waitReadable(self: *UdpSocket, timeout_ms: i32) !void {
        var fds = [_]posix.pollfd{
            .{ .fd = self.fd, .events = posix.POLL.IN, .revents = 0 },
        };
        _ = try posix.poll(&fds, timeout_ms);
    }
};

fn parseIp4(host: []const u8, port: u16) !std.c.sockaddr.in {
    var octets: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, host, '.');
    for (&octets) |*octet| {
        const part = it.next() orelse return error.InvalidAddress;
        octet.* = try std.fmt.parseInt(u8, part, 10);
    }
    if (it.next() != null) return error.InvalidAddress;
    return .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast(octets),
    };
}

/// Mirrors `http3_runtime.zig`'s conversion: `sockaddr_in`'s address/port are
/// already network-byte-order, so the octets bit-cast directly and only the
/// port needs an explicit big-to-native swap.
fn addressFromSockaddrIn(sa: std.c.sockaddr.in) quic.udp.Address {
    const octets: [4]u8 = @bitCast(sa.addr);
    return quic.udp.Address.ip4(octets, std.mem.bigToNative(u16, sa.port));
}

fn sockaddrInFromAddress(addr: quic.udp.Address) std.c.sockaddr.in {
    var octets: [4]u8 = undefined;
    @memcpy(&octets, addr.slice());
    return .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, addr.port),
        .addr = @bitCast(octets),
    };
}

/// Unused by ordinary on-path traffic (`PathManager` only consumes fresh
/// challenge entropy when a datagram starts a *new* candidate validation);
/// this tool talks to exactly one fixed external peer per run.
const test_challenge_entropy = [_]u8{0x5a} ** quic.path.path_challenge_len;

fn readFileAlloc(allocator: std.mem.Allocator, path: []const u8, max: usize) ![]u8 {
    const io = std.Io.Threaded.global_single_threaded.io();
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max));
}

fn randomBytes(buffer: []u8) void {
    std.Io.Threaded.global_single_threaded.io().random(buffer);
}

fn randomEntropy() tls_backend.Entropy {
    var entropy: tls_backend.Entropy = undefined;
    randomBytes(&entropy.hello_random);
    return entropy;
}

fn cidHex(cid: []const u8, out: []u8) []const u8 {
    const hex = "0123456789abcdef";
    const len = @min(cid.len, out.len / 2);
    for (cid[0..len], 0..) |byte, idx| {
        out[idx * 2] = hex[byte >> 4];
        out[idx * 2 + 1] = hex[byte & 0x0f];
    }
    return out[0 .. len * 2];
}

fn h3EventToQlog(event: http3.conn.Event) http3.qlog.Event {
    return switch (event) {
        .parameters_set => |parameters| .{ .parameters_set = .{
            .initiator = switch (parameters.initiator) {
                .local => .local,
                .remote => .remote,
            },
            .max_field_section_size = parameters.settings.max_field_section_size,
            .max_table_capacity = if (parameters.settings.qpack_max_table_capacity == 0) null else parameters.settings.qpack_max_table_capacity,
            .blocked_streams_count = if (parameters.settings.qpack_blocked_streams == 0) null else parameters.settings.qpack_blocked_streams,
            .extended_connect = if (parameters.settings.enable_connect_protocol) 1 else null,
            .h3_datagram = if (parameters.settings.h3_datagram) 1 else null,
        } },
        .stream_type_set => |stream| .{ .stream_type_set = .{
            .stream_id = stream.stream_id,
            .stream_type = h3StreamTypeToQlog(stream.stream_type),
        } },
        .frame_created => |created| .{ .frame = .{
            .direction = .created,
            .stream_id = created.stream_id,
            .frame = h3FrameToQlog(created.frame),
        } },
        .frame_parsed => |parsed| .{ .frame = .{
            .direction = .parsed,
            .stream_id = parsed.stream_id,
            .frame = h3FrameToQlog(parsed.frame),
        } },
        .priority_updated => |updated| .{ .priority_updated = .{
            .stream_id = updated.stream_id,
            .new = .{ .urgency = updated.urgency, .incremental = updated.incremental },
        } },
    };
}

fn h3FrameToQlog(event_frame: http3.conn.EventFrame) http3.qlog.Frame {
    return switch (event_frame) {
        .data => |d| .{ .data = .{ .raw_length = d.raw_length } },
        .headers => |h| .{ .headers = .{ .headers = h.fields, .raw_length = h.raw_length } },
        .settings => |s| .{ .settings = .{ .settings = @ptrCast(s.entries), .raw_length = s.raw_length } },
        .goaway => |g| .{ .goaway = .{ .id = g.id, .raw_length = g.raw_length } },
        .priority_update => |update| .{ .priority_update = switch (update) {
            .request => |r| .{ .request = .{ .stream_id = r.stream_id, .priority_field_value = r.field_value, .raw_length = r.raw_length } },
            .push => |p| .{ .push = .{ .push_id = p.push_id, .priority_field_value = p.field_value, .raw_length = p.raw_length } },
        } },
        .push_promise => |p| .{ .push_promise = .{ .push_id = p.push_id, .headers = p.fields, .raw_length = p.raw_length } },
        .cancel_push => |c| .{ .cancel_push = .{ .push_id = c.push_id, .raw_length = c.raw_length } },
        .max_push_id => |m| .{ .max_push_id = .{ .push_id = m.push_id, .raw_length = m.raw_length } },
        .unknown => |u| .{ .unknown = .{ .frame_type_bytes = u.frame_type_value, .raw_length = u.raw_length } },
        .malformed => |m| .{ .malformed = .{
            .frame_type = h3FrameTypeToQlog(m.frame_type),
            .frame_type_bytes = m.frame_type_value,
            .raw_length = m.raw_length,
        } },
    };
}

fn h3FrameTypeToQlog(typ: http3.frame.FrameType) http3.qlog.FrameType {
    return switch (typ) {
        .data => .data,
        .headers => .headers,
        .settings => .settings,
        .goaway => .goaway,
        .priority_update_request, .priority_update_push => .priority_update,
        .push_promise => .push_promise,
        .cancel_push => .cancel_push,
        .max_push_id => .max_push_id,
        .unknown => .unknown,
    };
}

fn h3StreamTypeToQlog(typ: http3.conn.EventStreamType) http3.qlog.StreamType {
    return switch (typ) {
        .request => .request,
        .control => .control,
        .push => .push,
        .qpack_encoder => .qpack_encode,
        .qpack_decoder => .qpack_decode,
        .unknown => .unknown,
    };
}

fn quicEventToQlog(event: connection.Event) ?quic.qlog.Event {
    return switch (event) {
        .state => null,
        .packet_received => |packet_event| .{ .packet_received = .{
            .packet_type = packetTypeForKind(packet_event.packet_type),
            .packet_number = packet_event.packet_number,
            .length = packet_event.size,
        } },
        .packet_sent => |packet_event| .{ .packet_sent = .{
            .packet_type = packetTypeForKind(packet_event.packet_type),
            .packet_number = packet_event.packet_number,
            .length = packet_event.size,
            .ack_eliciting = packet_event.ack_eliciting,
        } },
        .packet_dropped => |drop| .{ .packet_dropped = .{
            .trigger = dropReasonToQlog(drop.reason),
            .length = drop.size,
        } },
        .keys_discarded => null,
        .handshake_complete => .{ .handshake_progressed = .{ .stage = .application_keys_installed } },
        .handshake_confirmed => .{ .handshake_progressed = .{ .stage = .confirmed } },
        .pto_fired => |pto| .{ .recovery_metrics_updated = .{ .pto_count = @intCast(@min(pto.count, std.math.maxInt(u16))) } },
        .packets_acked => |acked| .{ .packets_acked = .{
            .packet_number_space = packetNumberSpaceToQlog(acked.space),
            .packet_number = acked.packet_number,
        } },
        .packets_lost => |lost| .{ .packets_lost = .{
            .packet_type = if (lost.packet_type) |kind| packetTypeForKind(kind) else null,
            .lost_count = lost.lost_count,
            .bytes = lost.bytes,
        } },
        .recovery_metrics_updated => |metrics| .{ .recovery_metrics_updated = .{
            .latest_rtt_ms = usToMs(metrics.latest_rtt_us),
            .smoothed_rtt_ms = usToMs(metrics.smoothed_rtt_us),
            .rtt_variance_ms = usToMs(metrics.rttvar_us),
            .pto_count = metrics.pto_count,
            .congestion_window = metrics.congestion_window,
            .bytes_in_flight = metrics.bytes_in_flight,
        } },
        .stream_reset => |reset| .{ .stream_reset = .{
            .kind = if (reset.local) .reset_sent else .reset_received,
            .stream_id = reset.id,
            .error_code = reset.error_code,
        } },
        .stop_sending => |stop| .{ .stream_reset = .{
            .kind = if (stop.local) .stop_sending_sent else .stop_sending_received,
            .stream_id = stop.id,
            .error_code = stop.error_code,
        } },
        .flow_control_state_changed => |blocked| switch (blocked.scope) {
            .connection => .{ .data_blocked = .{ .connection = .{
                .old = flowControlStateToQlog(blocked.old),
                .new = flowControlStateToQlog(blocked.new),
                .reason = .connection_flow_control,
            } } },
            .stream => .{ .data_blocked = .{ .stream = .{
                .stream_id = blocked.stream_id orelse 0,
                .old = flowControlStateToQlog(blocked.old),
                .new = flowControlStateToQlog(blocked.new),
                .reason = .stream_flow_control,
            } } },
        },
        .flow_control_blocked_received => |blocked| .{ .flow_control_blocked_received = .{
            .scope = switch (blocked.scope) {
                .connection => .connection,
                .stream => .stream,
            },
            .stream_id = blocked.stream_id,
        } },
        .local_close_started => |close| .{ .connection_closed = .{
            .trigger = if (close.is_application) .application else .@"error",
            .close_error = if (close.is_application) .{ .application_unknown = close.error_code } else .{ .connection_unknown = close.error_code },
        } },
        .close_sent => null,
        .close_received => |close| .{ .connection_closed = .{
            .trigger = if (close.is_application) .application else .@"error",
            .close_error = if (close.is_application) .{ .application_unknown = close.error_code } else .{ .connection_unknown = close.error_code },
        } },
        .idle_timeout => .{ .connection_closed = .{ .trigger = .idle_timeout } },
        .path_validation_started => .{ .path_validation = .{ .kind = .challenge_sent } },
        .path_validation_succeeded => .{ .path_validation = .{ .kind = .validated } },
        .path_validation_failed => .{ .path_validation = .{ .kind = .failed } },
        .path_migration_blocked => null,
        .path_promoted => |path| .{ .connection_migrated = .{ .new = switch (path.change) {
            .nat_rebinding => .probing_successful,
            .migration => .migration_complete,
        } } },
        .pmtu_updated, .zero_rtt_packet, .early_data_decision, .ecn_state_changed => null,
        .stream_state_changed => |stream| .{ .stream_state_updated = .{
            .stream_id = stream.id,
            .stream_side = streamSideToQlog(stream.side),
            .old = if (stream.old) |old| streamStateToQlog(old) else null,
            .new = streamStateToQlog(stream.new),
            .trigger = if (stream.trigger) |trigger| streamStateTriggerToQlog(trigger) else null,
        } },
        .congestion_state_changed => |congestion| .{ .congestion_state_updated = .{
            .old = congestionStateToQlog(congestion.old),
            .new = congestionStateToQlog(congestion.new),
        } },
        .persistent_congestion => .{ .persistent_congestion = .{} },
    };
}

fn flowControlStateToQlog(state: connection.FlowControlState) quic.qlog.BlockedState {
    return switch (state) {
        .blocked => .blocked,
        .unblocked => .unblocked,
    };
}

fn streamSideToQlog(side: connection.StreamSide) quic.qlog.StreamSide {
    return switch (side) {
        .sending => .sending,
        .receiving => .receiving,
    };
}

fn streamStateToQlog(state: connection.StreamSideState) quic.qlog.StreamState {
    return switch (state) {
        .open => .open,
        .closed => .closed,
    };
}

fn streamStateTriggerToQlog(trigger: connection.StreamStateTrigger) quic.qlog.StreamStateTrigger {
    return switch (trigger) {
        .local => .local,
        .remote => .remote,
    };
}

fn packetNumberSpaceToQlog(space: quic.recovery.PacketNumberSpace) quic.qlog.PacketNumberSpace {
    return switch (space) {
        .initial => .initial,
        .handshake => .handshake,
        .application => .application_data,
    };
}

fn congestionStateToQlog(state: connection.CongestionState) quic.qlog.CongestionState {
    return switch (state) {
        .slow_start => .slow_start,
        .congestion_avoidance => .congestion_avoidance,
        .recovery => .recovery,
    };
}

fn packetTypeForKind(kind: quic.packet.PacketKind) quic.qlog.PacketType {
    return switch (kind) {
        .initial => .initial,
        .zero_rtt => .zero_rtt,
        .handshake => .handshake,
        .one_rtt => .one_rtt,
        .retry => .retry,
        .version_negotiation => .version_negotiation,
    };
}

fn dropReasonToQlog(reason: connection.DropReason) quic.qlog.DropTrigger {
    return switch (reason) {
        .unknown_cid => .connection_unknown,
        .keys_unavailable => .key_unavailable,
        .undecryptable => .decryption_failure,
        .malformed => .invalid,
        .unsupported_version => .unsupported,
        .unexpected_type => .invalid,
    };
}

fn usToMs(value: ?u64) ?u64 {
    return if (value) |v| v / 1000 else null;
}

pub fn main(init: std.process.Init.Minimal) !void {
    // Short-lived tool: arena everything, reclaimed at exit.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = parseArgs(allocator, init.args) catch |err| {
        std.debug.print(
            "h3-interop: bad arguments ({s})\n" ++
                "usage: h3_interop_tool server --port N --cert cert.pem --key key.pem [--requests N] [--expect-hrr] [--qlog-dir DIR] [--qlog-dialect current|qvis-legacy] [--keylog-path FILE]\n" ++
                "       h3_interop_tool client --host IP --port N --authority NAME --path /p [--reset-after-request] [--empty-initial-key-share] [--expect-hrr] [--insecure|--pin cert.der] [--qlog-dir DIR] [--qlog-dialect current|qvis-legacy] [--keylog-path FILE]\n" ++
                "\nnegotiation (#338, shared vocabulary with tls_interop_tool):\n" ++
                matrix.flag_usage,
            .{@errorName(err)},
        );
        std.process.exit(2);
    };

    switch (args.mode) {
        .client => try runClient(allocator, args),
        .server => try runServer(allocator, args),
    }
}

fn runClient(allocator: std.mem.Allocator, args: Args) !void {
    const peer_addr = try parseIp4(args.host, args.port);
    var socket = try UdpSocket.open(0);
    defer socket.close();

    var local_cid: [8]u8 = undefined;
    randomBytes(&local_cid);
    var odcid: [8]u8 = undefined;
    randomBytes(&odcid);
    var group_id_buf: [16]u8 = undefined;
    var artifacts = try ArtifactSink.init(allocator, args.qlog_dir, args.keylog_path, .client, cidHex(&odcid, &group_id_buf), args.qlog_dialect);
    defer artifacts.deinit();
    defer artifacts.reportDiagnostics();
    if (args.keylog_path.len > 0) {
        std.debug.print("h3-interop: WARNING keylog enabled; {s} permits decrypting captured traffic\n", .{args.keylog_path});
    }
    artifacts.emitQuicQlog(.{ .connection_started = .{
        .odcid_len = @intCast(odcid.len),
        .scid_len = @intCast(local_cid.len),
        .dcid_len = @intCast(odcid.len),
    } });

    const trust: tls_backend.Trust = if (args.pin.len > 0) blk: {
        const pinned = try readFileAlloc(allocator, args.pin, 64 * 1024);
        break :blk .{ .pinned_certificate = pinned };
    } else .insecure_no_verification;
    if (args.pin.len == 0 and !args.insecure) {
        std.debug.print("h3-interop: client needs --pin cert.der or --insecure\n", .{});
        artifacts.reportDiagnostics();
        std.process.exit(2);
    }

    const client_path = quic.path.PathKey{
        .local = addressFromSockaddrIn(socket.local),
        .remote = addressFromSockaddrIn(peer_addr),
    };
    const client_options = tls_backend.ClientOptions{
        .initial_key_share_mode = if (args.empty_initial_key_share) .empty else .normal,
    };
    // A real OS-backed provider, owned for this process's lifetime (#490
    // review): this tool drives real network handshakes against real peers,
    // so ephemeral X25519 keys must not be predictable the way a
    // deterministic test provider's would be.
    var crypto_provider_entropy = production_crypto.OsEntropy{};
    var crypto_provider_state = production_crypto.Provider.init(crypto_provider_entropy.entropy());
    const crypto_provider = crypto_provider_state.cryptoProvider();
    var backend = tls_backend.Tls13Backend.initClientWithPolicyAndOptions(randomEntropy(), crypto_provider, trust, quicPolicy(&args), client_options);
    const keylog_context = artifacts.keylogContext(.client);
    const client = try Connection.init(allocator, .{
        .role = .client,
        .local_cid = &local_cid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .tls = backend.backend(),
        .crypto_provider = crypto_provider,
        .now_us = nowUs(),
        .events = artifacts.quicSink(),
        .tls_keylog_context = keylog_context,
        .allow_unverified_certificate = args.insecure,
        .initial_path = client_path,
    });
    defer client.deinit();

    var h3 = H3.init(allocator, .client);
    defer h3.deinit();
    if (artifacts.qlog_file != null) h3.setEventSink(artifacts.h3Sink());

    var request_id: ?u64 = null;
    var request_sent_at_us: ?u64 = null;
    var reset_sent_at_us: ?u64 = null;
    const deadline = nowUs() + args.timeout_ms * 1_000;
    var success = false;

    while (nowUs() < deadline) {
        const now = nowUs();
        var out: [2048]u8 = undefined;
        while (client.pollTransmitOnPath(&out, now)) |t| {
            try socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
        }
        var next: u64 = now + 50_000;
        if (client.nextTimeoutUs()) |t| next = @min(next, t);
        try socket.waitReadable(@intCast(@min((next -| now) / 1_000 + 1, 50)));
        var in: [2048]u8 = undefined;
        var from: std.c.sockaddr.in = undefined;
        while (try socket.recvFrom(&in, &from)) |datagram| {
            try client.ingestOnPath(datagram, client_path, test_challenge_entropy, nowUs());
        }
        client.onTimeout(nowUs());

        if (client.state() == .closed or client.state() == .draining) break;
        if (client.isEstablished()) {
            if (request_id == null) {
                std.debug.print("h3-interop: established, alpn_h3={}\n", .{client.negotiatedH3()});
                try h3.start(client);
                request_id = try h3.sendRequest(client, .{
                    .authority = args.authority,
                    .path = args.path,
                    .body = args.body,
                });
                request_sent_at_us = nowUs();
            }
            try h3.pump(client);
            if (args.reset_after_request and reset_sent_at_us == null) {
                if (nowUs() -| request_sent_at_us.? >= args.reset_after_request_delay_ms * std.time.us_per_ms) {
                    try client.stopSending(request_id.?, 0x010c); // H3_REQUEST_CANCELLED
                    try client.resetStream(request_id.?, 0x010c);
                    reset_sent_at_us = nowUs();
                }
            }
            if (reset_sent_at_us) |sent_at| {
                if (nowUs() -| sent_at >= 200 * std.time.us_per_ms) {
                    success = true;
                    break;
                }
                continue;
            }
            if (request_id) |id| {
                if (try h3.pollResponse(id)) |response| {
                    var line: [8192]u8 = undefined;
                    writeStdout(std.fmt.bufPrint(&line, "status: {d}\n", .{response.status}) catch "");
                    for (response.headers) |header| {
                        writeStdout(std.fmt.bufPrint(&line, "{s}: {s}\n", .{ header.name, header.value }) catch "");
                    }
                    writeStdout("\n");
                    writeStdout(response.body);
                    h3.releaseResponse(id);
                    success = true;
                    break;
                }
            }
        }
    }

    if (!success) {
        std.debug.print("h3-interop: client failed: state={s} handshake_error={any}\n", .{
            @tagName(client.state()),
            client.handshakeFailure(),
        });
        artifacts.reportDiagnostics();
        std.process.exit(1);
    }
    const saw_hrr = backend.engine.core.retry_state == .hrr_received;
    std.debug.print("h3-interop: tls retry_state={s}\n", .{@tagName(backend.engine.core.retry_state)});
    reportNegotiated(args, &backend, saw_hrr);
    if (args.expect_hrr and !saw_hrr) {
        std.debug.print("h3-interop: expected HelloRetryRequest but none was observed\n", .{});
        artifacts.reportDiagnostics();
        std.process.exit(1);
    }
    if (!matrixTupleHolds(args, &backend)) {
        artifacts.reportDiagnostics();
        std.process.exit(1);
    }
    // Orderly close.
    client.close(0, "done", nowUs());
    var out: [2048]u8 = undefined;
    while (client.pollTransmitOnPath(&out, nowUs())) |t| {
        try socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
    }
    std.debug.print("h3-interop: client ok\n", .{});
}

fn runServer(allocator: std.mem.Allocator, args: Args) !void {
    if (args.cert.len == 0 or args.key.len == 0) {
        std.debug.print("h3-interop: server needs --cert and --key (PEM or DER)\n", .{});
        std.process.exit(2);
    }
    // #338: loaded through the production identity loader rather than
    // `Identity.initPkcs8` directly, so a matrix row can hand this tool the
    // same PEM files it hands `tls_interop_tool` -- and so RSA identities
    // (whose import needs an entropy source for its primality witnesses)
    // work here at all.
    var identity_entropy = production_crypto.OsEntropy{};
    var loaded = try quic.tls_core.identity_loader.loadIdentity(allocator, args.cert, args.key, identity_entropy.entropy());
    defer loaded.deinit();
    const identity = loaded.identity;

    var socket = try UdpSocket.open(args.port);
    defer socket.close();
    std.debug.print("h3-interop: server listening on udp port {d}\n", .{args.port});

    var served: usize = 0;
    const deadline = nowUs() + args.timeout_ms * 1_000;
    var saw_hrr = false;

    // One connection at a time: enough for focused interop runs, and each
    // connection exercises the full accept path.
    accept_loop: while (nowUs() < deadline) {
        // Wait for the first Initial of a new connection.
        var first: [2048]u8 = undefined;
        var peer: std.c.sockaddr.in = undefined;
        try socket.waitReadable(100);
        const first_datagram = (try socket.recvFrom(&first, &peer)) orelse continue;
        const parsed = quic.packet.parsePacket(first_datagram, 8) catch continue;
        if (parsed.kind != .initial) continue;
        std.debug.print("h3-interop: initial from client, dcid_len={d} scid_len={d}\n", .{
            parsed.dcid.len, parsed.scid.len,
        });

        const server_path = quic.path.PathKey{
            .local = addressFromSockaddrIn(socket.local),
            .remote = addressFromSockaddrIn(peer),
        };
        // A real OS-backed provider, owned for this process's lifetime
        // (#490 review) — see the matching comment in `runClient`.
        var crypto_provider_entropy = production_crypto.OsEntropy{};
        var crypto_provider_state = production_crypto.Provider.init(crypto_provider_entropy.entropy());
        const crypto_provider = crypto_provider_state.cryptoProvider();
        var backend = tls_backend.Tls13Backend.initServerWithPolicy(randomEntropy(), crypto_provider, identity, quicPolicy(&args));
        var group_id_buf: [16]u8 = undefined;
        var artifacts = try ArtifactSink.init(allocator, args.qlog_dir, args.keylog_path, .server, cidHex(parsed.dcid, &group_id_buf), args.qlog_dialect);
        defer artifacts.deinit();
        defer artifacts.reportDiagnostics();
        if (args.keylog_path.len > 0) {
            std.debug.print("h3-interop: WARNING keylog enabled; {s} permits decrypting captured traffic\n", .{args.keylog_path});
        }
        artifacts.emitQuicQlog(.{ .connection_started = .{
            .odcid_len = @intCast(parsed.dcid.len),
            .scid_len = @intCast(parsed.scid.len),
            .dcid_len = @intCast(parsed.dcid.len),
        } });
        const keylog_context = artifacts.keylogContext(.server);
        const server = try Connection.init(allocator, .{
            .role = .server,
            .local_cid = parsed.dcid,
            .original_destination_cid = parsed.dcid,
            .initial_secret_dcid = parsed.dcid,
            .peer_cid = parsed.scid,
            .tls = backend.backend(),
            .crypto_provider = crypto_provider,
            .now_us = nowUs(),
            .events = artifacts.quicSink(),
            .tls_keylog_context = keylog_context,
            .initial_path = server_path,
        });
        defer server.deinit();
        var h3 = H3.init(allocator, .server);
        defer h3.deinit();
        if (artifacts.qlog_file != null) h3.setEventSink(artifacts.h3Sink());
        try server.ingestOnPath(first_datagram, server_path, test_challenge_entropy, nowUs());

        var h3_started = false;
        while (nowUs() < deadline) {
            const now = nowUs();
            var out: [2048]u8 = undefined;
            while (server.pollTransmitOnPath(&out, now)) |t| {
                try socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
            }
            var next: u64 = now + 50_000;
            if (server.nextTimeoutUs()) |t| next = @min(next, t);
            try socket.waitReadable(@intCast(@min((next -| now) / 1_000 + 1, 50)));
            var in: [2048]u8 = undefined;
            while (try socket.recvFrom(&in, &peer)) |datagram| {
                // Only this connection's DCID is routable; a new Initial for a
                // different connection would start a new accept cycle.
                // Recompute the ingress path per datagram (not the fixed
                // `server_path` above): an interop peer that migrates or
                // rebinds sends from a different address than the one that
                // opened the connection.
                const ingress_path = quic.path.PathKey{ .local = server_path.local, .remote = addressFromSockaddrIn(peer) };
                try server.ingestOnPath(datagram, ingress_path, test_challenge_entropy, nowUs());
            }
            server.onTimeout(nowUs());

            switch (server.state()) {
                .closed, .draining, .closing => {
                    saw_hrr = saw_hrr or backend.engine.core.retry_state == .hrr_sent;
                    std.debug.print("h3-interop: connection ended state={s} served={d} handshake_error={any}\n", .{
                        @tagName(server.state()),
                        served,
                        server.handshakeFailure(),
                    });
                    if (served >= args.requests) break :accept_loop;
                    continue :accept_loop;
                },
                else => {},
            }
            if (server.isEstablished()) {
                if (!h3_started) {
                    std.debug.print("h3-interop: established, alpn_h3={}\n", .{server.negotiatedH3()});
                    reportNegotiated(args, &backend, backend.engine.core.retry_state == .hrr_sent);
                    if (!matrixTupleHolds(args, &backend)) {
                        artifacts.reportDiagnostics();
                        std.process.exit(1);
                    }
                    try h3.start(server);
                    h3_started = true;
                }
                try h3.pump(server);
                if (try h3.pollRequest()) |incoming| {
                    const body_len: usize = switch (incoming.exchange.body) {
                        .buffered => |body| body.len,
                        else => 0,
                    };
                    std.debug.print("h3-interop: request {s} {s} authority={s} body_len={d}\n", .{
                        incoming.exchange.request.method,
                        incoming.exchange.request.path,
                        incoming.exchange.request.authority,
                        body_len,
                    });
                    try h3.sendResponse(server, incoming.stream_id, 200, &.{
                        .{ .name = "server", .value = "tardigrade-native-h3" },
                    }, args.response_body);
                    served += 1;
                    std.debug.print("h3-interop: served {d}/{d}\n", .{ served, args.requests });
                }
            }
        }
        saw_hrr = saw_hrr or backend.engine.core.retry_state == .hrr_sent;
    }

    if (served < args.requests) {
        std.debug.print("h3-interop: server timed out with served={d}/{d}\n", .{ served, args.requests });
        std.process.exit(1);
    }
    if (args.qlog_dir.len > 0 or args.keylog_path.len > 0) {
        std.debug.print("h3-interop: artifacts qlog_dir={s} keylog_path={s}\n", .{ args.qlog_dir, args.keylog_path });
    }
    std.debug.print("h3-interop: tls hello_retry_request={}\n", .{saw_hrr});
    if (args.expect_hrr and !saw_hrr) {
        std.debug.print("h3-interop: expected HelloRetryRequest but none was observed\n", .{});
        std.process.exit(1);
    }
    std.debug.print("h3-interop: server ok, served={d}\n", .{served});
}

const testing = std.testing;

test "artifact sink appends keylog lines across repeated connection sinks" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const allocator = testing.allocator;
    const root = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const keylog_path = try std.fmt.allocPrint(allocator, "{s}/native-server.keys", .{root});
    defer allocator.free(keylog_path);

    const random_a = [_]u8{0x11} ** quic.tls_core.keylog.client_random_len;
    const random_b = [_]u8{0x22} ** quic.tls_core.keylog.client_random_len;
    const secret_a = [_]u8{0xaa} ** 32;
    const secret_b = [_]u8{0xbb} ** 32;

    var first = try ArtifactSink.init(allocator, "", keylog_path, .server, "first", .current);
    var first_context = first.keylogContext(.server);
    try first_context.setClientRandom(&random_a);
    first_context.emitSecret(.handshake, .write, &secret_a);
    first.deinit();

    var second = try ArtifactSink.init(allocator, "", keylog_path, .server, "second", .current);
    var second_context = second.keylogContext(.server);
    try second_context.setClientRandom(&random_b);
    second_context.emitSecret(.handshake, .write, &secret_b);
    second.deinit();

    const contents = try compat.cwd().readFileAlloc(allocator, keylog_path, 4096);
    defer allocator.free(contents);
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, contents, "SERVER_HANDSHAKE_TRAFFIC_SECRET"));
    try testing.expect(std.mem.indexOf(u8, contents, "1111111111111111111111111111111111111111111111111111111111111111") != null);
    try testing.expect(std.mem.indexOf(u8, contents, "2222222222222222222222222222222222222222222222222222222222222222") != null);
    const stat = try compat.cwd().statFile(keylog_path);
    try testing.expectEqual(@as(u32, 0o600), @intFromEnum(stat.permissions) & 0o777);
}

test "artifact sink writes qlog header connection start and representative events" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const allocator = testing.allocator;
    const root = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const qlog_dir = try std.fmt.allocPrint(allocator, "{s}/qlog", .{root});
    defer allocator.free(qlog_dir);

    var sink = try ArtifactSink.init(allocator, qlog_dir, "", .server, "0011223344556677", .current);
    sink.emitQuicQlog(.{ .connection_started = .{
        .odcid_len = 8,
        .scid_len = 8,
        .dcid_len = 8,
    } });
    sink.emitQuicQlog(.{ .packet_sent = .{
        .packet_type = .initial,
        .packet_number = 1,
        .length = 1200,
        .ack_eliciting = true,
    } });
    sink.h3Sink().emit(.{ .frame_created = .{
        .stream_id = 0,
        .frame = .{ .data = .{ .raw_length = 5 } },
    } });
    sink.deinit();

    const qlog_path = try std.fmt.allocPrint(allocator, "{s}/server-0011223344556677.sqlog", .{qlog_dir});
    defer allocator.free(qlog_path);
    const contents = try compat.cwd().readFileAlloc(allocator, qlog_path, 4096);
    defer allocator.free(contents);
    try testing.expect(std.mem.indexOf(u8, contents, "\"file_schema\":\"urn:ietf:params:qlog:file:sequential\"") != null);
    try testing.expect(std.mem.indexOf(u8, contents, "\"name\":\"quic:connection_started\"") != null);
    try testing.expect(std.mem.indexOf(u8, contents, "\"name\":\"quic:packet_sent\"") != null);
    try testing.expect(std.mem.indexOf(u8, contents, "\"name\":\"http3:frame_created\"") != null);
}
