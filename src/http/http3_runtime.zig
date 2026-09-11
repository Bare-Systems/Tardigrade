//! Native HTTP/3 downstream listener runtime (#328).
//!
//! Runs Tardigrade's HTTP/3 endpoint entirely on the native Zig QUIC/H3
//! stack: the connection driver in `src/quic/connection.zig` plus the H3
//! session glue in `src/http3/conn.zig`. One background thread owns one UDP
//! socket, routes datagrams to connections by Destination Connection ID,
//! schedules wakeups from the drivers' timer deadlines, and bridges decoded
//! requests to the gateway's `RequestHandler`.
//!
//! ngtcp2/nghttp3 are gone from the build (#328); they remain available only
//! as out-of-process interop peers under `scripts/interop/`.
//!
//! TLS identity: the runtime owns no certificate or key material. It borrows
//! a provider-neutral `tls_core.credentials.CredentialProvider` from the
//! composition root (#392) — the same provider instance that authenticates
//! native TCP TLS — and hands it to each accepted QUIC connection's TLS
//! backend. Without a provider the QUIC listener stays unbootstrapped with a
//! logged warning while TCP continues to serve.

const builtin = @import("builtin");
const compat = @import("zig_compat");
const std = @import("std");
const early_data_policy = @import("early_data.zig");
const http3_session = @import("http3_session.zig");
const logger_mod = @import("logger.zig");
const metrics_mod = @import("metrics.zig");
const response_mod = @import("response.zig");
const stream_transport = @import("stream_transport");
const quic = @import("quic");
const http3 = @import("http3");
const tls_core = @import("tls_core");
const crypto_pkg = @import("crypto");
const test_quic_crypto = @import("test_quic_crypto");

const Connection = quic.connection.Connection;
const H3 = http3.conn.Conn(Connection);
const posix = std.posix;

pub const StreamRequest = http3_session.StreamRequest;
pub const Response = response_mod.Response;
pub const Logger = logger_mod.Logger;
/// Re-exported so a caller wiring `Config`'s `quic_transport_metrics_cb`
/// (whose signature already names this type) can spell the callback's
/// parameter type without a second, separately declared dependency on
/// `metrics.zig` -- the same re-export shape as `Response`/`Logger` above.
pub const QuicTransportDelta = metrics_mod.QuicTransportDelta;

pub const EffectiveAdvertisementState = enum {
    disabled,
    configured_unavailable,
    ready_advertisement_disabled,
    advertising,
    clearing,
    draining,
};

pub const Http3RuntimeError = error{
    OutOfMemory,
    DependencyUnavailable,
    NotYetImplemented,
    BindFailed,
    TlsBootstrapFailed,
    InvalidH3Settings,
};

pub const RequestHandler = *const fn (
    allocator: std.mem.Allocator,
    request: *const http3_session.StreamRequest,
    response: *response_mod.Response,
    user_data: ?*anyopaque,
) anyerror!void;

pub const Config = struct {
    listen_host: []const u8,
    quic_port: u16,
    /// Borrowed local credential provider shared with the TCP TLS path. The
    /// owner must outlive this runtime and every QUIC connection it accepts.
    credential_provider: ?tls_core.credentials.CredentialProvider = null,
    /// #488: borrowed process-shared native resumption runtime, shared with
    /// the native TCP TLS path. `null` (the default) leaves resumption
    /// fully disabled for QUIC/H3: no resolver is installed on any accepted
    /// connection and no ticket is ever issued.
    resumption_runtime: ?*tls_core.resumption_runtime.Runtime = null,
    /// #368 Slice 2: borrowed process-shared anti-replay gate, the same
    /// instance shared with the native TCP TLS path — installed
    /// independently of `resumption_runtime` on every accepted connection's
    /// backend so QUIC/H3 can never fall back to worker-local replay
    /// bookkeeping. `null` (the default) leaves the backend's own default
    /// gate in place, which fails closed (`.unavailable`) for 0-RTT.
    early_data_replay_gate: ?tls_core.tls13_backend.EarlyDataReplayGate = null,
    tls_min_version: []const u8 = "1.3",
    tls_max_version: []const u8 = "1.3",
    enable_0rtt: bool = false,
    h3_settings: http3.frame.Settings = .{},
    /// Per-request application body ceiling enforced while HTTP/3 DATA is
    /// ingested, before the complete request is handed to gateway middleware.
    max_request_body_bytes: usize = http3.session.RequestStream.default_max_body_len,
    /// Aggregate dynamic request-assembly budget across concurrent streams.
    max_buffered_request_bytes: usize = http3.conn.default_max_buffered_request_bytes,
    connection_migration: bool = false,
    retry_policy: quic.config.RetryPolicy = .off,
    /// Operator-facing ceiling on the size of datagrams this listener
    /// **sends**, clamped into `[quic.datagram.base_size,
    /// quic.datagram.max_size]`. It is not a receive limit: the
    /// `max_udp_payload_size` this endpoint advertises is its own receive
    /// capacity and is fixed by the transport's buffers, not by this knob
    /// (#256-A). Nor is it the size on the wire — DPLPMTUD (#256-B) starts
    /// every path at the RFC 9000 §14 floor and only raises it as far as a
    /// probe is actually acknowledged, so this bounds what discovery may find.
    /// The default is the one authoritative value in `quic.datagram` rather
    /// than a second knob that can drift from it; the transport lowers it
    /// further whenever the peer advertises less receive capacity.
    max_datagram_size: usize = quic.datagram.max_size,
    /// Optional `SO_RCVBUF`/`SO_SNDBUF` targets for the listener socket
    /// (#256-D). Advisory in both directions: a kernel that refuses or trims
    /// a request still gets a working listener, and the default (`null`,
    /// leave the kernel's own sizing alone) is the right answer unless
    /// measurements say otherwise. What the kernel actually granted is read
    /// back and published on `Snapshot.udp_buffers`.
    udp_buffer_tuning: quic.udp.BufferTuning = .{},
    /// Whether to run ECN on this listener (#256-E, RFC 9000 §13.4). On by
    /// default because it is safe by construction: the runtime turns it on
    /// only after the kernel agrees to report received codepoints, and the
    /// transport turns it off again per path the moment the peer's feedback
    /// stops adding up — a path that cannot carry markings ends up in ordinary
    /// non-ECN operation, never in an error. Set false to keep every datagram
    /// unmarked regardless of platform support.
    ecn_enabled: bool = true,
    request_handler: ?RequestHandler = null,
    request_handler_ctx: ?*anyopaque = null,
    early_data_compat_metrics_ctx: ?*anyopaque = null,
    early_data_compat_metrics_cb: ?*const fn (*anyopaque, metrics_mod.H3EarlyDataCompatDecision) void = null,
    /// #523: the QUIC/H3 server's authoritative 0-RTT accept/reject decision
    /// (`quic.connection.Event.early_data_decision`), bridged out of every
    /// accepted connection's `EventSink`. `null` (the default) leaves the
    /// event unobserved — never silently required.
    quic_early_data_decision_metrics_ctx: ?*anyopaque = null,
    quic_early_data_decision_metrics_cb: ?*const fn (*anyopaque, metrics_mod.QuicEarlyDataDecision) void = null,
    /// #523: per-packet 0-RTT authentication/admission outcomes
    /// (`quic.connection.Event.zero_rtt_packet`), bridged the same way.
    quic_zero_rtt_packet_metrics_ctx: ?*anyopaque = null,
    quic_zero_rtt_packet_metrics_cb: ?*const fn (*anyopaque, metrics_mod.QuicZeroRttPacketOutcome) void = null,
    quic_transport_metrics_ctx: ?*anyopaque = null,
    quic_transport_metrics_cb: ?*const fn (*anyopaque, metrics_mod.QuicTransportDelta) void = null,
    quic_connections_active_metrics_ctx: ?*anyopaque = null,
    quic_connections_active_metrics_cb: ?*const fn (*anyopaque, usize) void = null,
    quic_handshake_failure_metrics_ctx: ?*anyopaque = null,
    quic_handshake_failure_metrics_cb: ?*const fn (*anyopaque, metrics_mod.QuicHandshakeFailureStage) void = null,
    h3_request_latency_metrics_ctx: ?*anyopaque = null,
    h3_request_latency_metrics_cb: ?*const fn (*anyopaque, u64) void = null,
    /// Optional H3 qlog sink. Defaults to no-op; concrete file ownership stays
    /// in the composition root and sink errors must not affect protocol state.
    h3_qlog_sink: http3.qlog.Sink = .{},
    /// Optional QUIC qlog sink. Defaults to no-op; concrete file ownership
    /// stays in the composition root and sink errors must not affect protocol
    /// state.
    quic_qlog_sink: quic.qlog.Sink = .{},
    /// Optional per-connection H3 qlog sink factory. When set, this overrides
    /// `h3_qlog_sink` for accepted connections and lets the composition root
    /// route H3 events to the same connection trace as QUIC events.
    h3_qlog_sink_factory_ctx: ?*anyopaque = null,
    h3_qlog_sink_factory_cb: ?*const fn (?*anyopaque, u64) http3.qlog.Sink = null,
    /// Optional per-connection QUIC qlog sink factory. Use the same handle as
    /// `h3_qlog_sink_factory_cb` so a composition root can interleave both
    /// namespaces into one `.sqlog`.
    quic_qlog_sink_factory_ctx: ?*anyopaque = null,
    quic_qlog_sink_factory_cb: ?*const fn (?*anyopaque, u64) quic.qlog.Sink = null,
    /// Optional runtime-owned artifact writer for concrete qlog files.
    qlog_artifacts_ctx: ?*anyopaque = null,
    quic_qlog_artifact_cb: ?*const fn (*anyopaque, u64, quic.qlog.Record) void = null,
    h3_qlog_artifact_cb: ?*const fn (*anyopaque, u64, http3.qlog.Record) void = null,
    qlog_artifact_close_cb: ?*const fn (*anyopaque, u64) void = null,
    /// Optional TLS keylog context copied into every accepted QUIC handshake.
    /// The TLS engine emits secrets to this callback only; file handling stays
    /// in the composition root.
    tls_keylog_context: tls_core.keylog.Context = .{},
};

pub const ObservabilityArtifacts = struct {
    state: *State,

    const qlog_record_max = 4096;
    const keylog_record_max = 256;
    const data_queue_capacity = 256;
    const close_queue_capacity = max_connections;
    const ArtifactKind = enum { qlog, keylog };

    pub const Diagnostics = struct {
        qlog_write_errors: usize = 0,
        keylog_write_errors: usize = 0,
        qlog_dropped_records: usize = 0,
        keylog_dropped_records: usize = 0,
    };

    const Trace = struct {
        path: []u8,
        file: compat.FileCompat,

        fn deinit(self: *Trace, allocator: std.mem.Allocator) void {
            self.file.close();
            allocator.free(self.path);
            allocator.destroy(self);
        }
    };

    const DataCommand = union(enum) {
        qlog: struct {
            handle: u64,
            bytes: [qlog_record_max]u8,
            len: usize,
        },
        keylog: struct {
            bytes: [keylog_record_max]u8,
            len: usize,
        },
        close_trace: CloseCommand,
    };

    const CloseCommand = struct {
        handle: u64,
        after_seq: u64,
    };

    const State = struct {
        allocator: std.mem.Allocator,
        logger: ?*Logger,
        qlog_dir: []const u8,
        keylog_path: []const u8,
        traces: std.AutoHashMap(u64, *Trace),
        keylog_fd: ?posix.fd_t = null,
        mutex: compat.Mutex = .{},
        wake: compat.Semaphore = .{},
        wake_pending: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        queue: [data_queue_capacity + 1]DataCommand = undefined,
        queue_head: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        queue_tail: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        close_queue: [close_queue_capacity + 1]CloseCommand = undefined,
        close_queue_head: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        close_queue_tail: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        accepted_seq: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        processed_seq: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
        close_all_after_seq: std.atomic.Value(u64) = std.atomic.Value(u64).init(std.math.maxInt(u64)),
        worker_active: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        stopping: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        qlog_capture_abandoned: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        thread: ?std.Thread = null,
        qlog_write_errors: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        keylog_write_errors: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        qlog_dropped_records: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        keylog_dropped_records: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        qlog_write_error_reported: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        keylog_write_error_reported: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        qlog_drop_reported: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        keylog_drop_reported: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        drop_diagnostic_pending: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

        fn init(allocator: std.mem.Allocator, logger: ?*Logger, qlog_dir: []const u8, keylog_path: []const u8) !*State {
            const state = try allocator.create(State);
            state.* = .{
                .allocator = allocator,
                .logger = logger,
                .qlog_dir = qlog_dir,
                .keylog_path = keylog_path,
                .traces = std.AutoHashMap(u64, *Trace).init(allocator),
            };
            errdefer {
                state.deinitStorage();
                allocator.destroy(state);
            }
            if (qlog_dir.len > 0) try compat.cwd().makePath(qlog_dir);
            if (keylog_path.len > 0) state.keylog_fd = try openAppendOnly0600(keylog_path);
            state.thread = try std.Thread.spawn(.{}, workerMain, .{state});
            return state;
        }

        fn deinit(self: *State) void {
            self.stopping.store(true, .release);
            self.wakeWriter();
            if (self.thread) |thread| thread.join();
            self.logFinalDiagnostics();
            self.deinitStorage();
            self.allocator.destroy(self);
        }

        fn deinitStorage(self: *State) void {
            var it = self.traces.valueIterator();
            while (it.next()) |trace| trace.*.deinit(self.allocator);
            self.traces.deinit();
            if (self.keylog_fd) |fd| {
                _ = std.c.close(fd);
                self.keylog_fd = null;
            }
        }

        fn diagnostics(self: *const State) Diagnostics {
            return .{
                .qlog_write_errors = self.qlog_write_errors.load(.monotonic),
                .keylog_write_errors = self.keylog_write_errors.load(.monotonic),
                .qlog_dropped_records = self.qlog_dropped_records.load(.monotonic),
                .keylog_dropped_records = self.keylog_dropped_records.load(.monotonic),
            };
        }

        fn logFinalDiagnostics(self: *const State) void {
            const d = self.diagnostics();
            if (d.qlog_write_errors == 0 and d.keylog_write_errors == 0 and d.qlog_dropped_records == 0 and d.keylog_dropped_records == 0) return;
            if (self.logger) |logger| {
                logger.warn(null, "HTTP/3 observability artifacts ended with qlog_write_errors={d} keylog_write_errors={d} qlog_dropped_records={d} keylog_dropped_records={d}", .{
                    d.qlog_write_errors,
                    d.keylog_write_errors,
                    d.qlog_dropped_records,
                    d.keylog_dropped_records,
                });
            }
        }

        fn noteWriteError(self: *State, comptime kind: ArtifactKind, err: anyerror) void {
            const first = switch (kind) {
                .qlog => self.qlog_write_error_reported.cmpxchgStrong(false, true, .acq_rel, .acquire) == null,
                .keylog => self.keylog_write_error_reported.cmpxchgStrong(false, true, .acq_rel, .acquire) == null,
            };
            switch (kind) {
                .qlog => _ = self.qlog_write_errors.fetchAdd(1, .monotonic),
                .keylog => _ = self.keylog_write_errors.fetchAdd(1, .monotonic),
            }
            if (first) if (self.logger) |logger| {
                logger.warn(null, "HTTP/3 observability artifact write failed kind={s} error={s}", .{ @tagName(kind), @errorName(err) });
            };
        }

        fn noteDrop(self: *State, comptime kind: ArtifactKind) void {
            switch (kind) {
                .qlog => _ = self.qlog_dropped_records.fetchAdd(1, .monotonic),
                .keylog => _ = self.keylog_dropped_records.fetchAdd(1, .monotonic),
            }
            self.drop_diagnostic_pending.store(true, .release);
            self.wakeWriter();
        }

        fn qlogEnabled(self: *const State) bool {
            return self.qlog_dir.len > 0 and !self.qlog_capture_abandoned.load(.acquire);
        }

        fn wakeWriter(self: *State) void {
            if (!self.wake_pending.swap(true, .acq_rel)) self.wake.post();
        }

        fn awaitWork(self: *State) void {
            while (!self.hasWork() and !self.stopping.load(.acquire)) {
                self.wake_pending.store(false, .release);
                if (self.hasWork() or self.stopping.load(.acquire)) return;
                self.wake.wait();
            }
        }

        fn tryEnqueue(self: *State, comptime kind: ArtifactKind, command: DataCommand) void {
            if (self.stopping.load(.acquire)) {
                self.noteDrop(kind);
                return;
            }
            const tail = self.queue_tail.load(.monotonic);
            const next = advanceIndex(tail, self.queue.len);
            if (next == self.queue_head.load(.acquire)) {
                self.noteDrop(kind);
                return;
            }
            self.queue[tail] = command;
            _ = self.accepted_seq.fetchAdd(1, .release);
            self.queue_tail.store(next, .release);
            self.wakeWriter();
        }

        fn tryEnqueueCloseData(self: *State, close: CloseCommand) bool {
            if (self.stopping.load(.acquire)) return false;
            const tail = self.queue_tail.load(.monotonic);
            const next = advanceIndex(tail, self.queue.len);
            if (next == self.queue_head.load(.acquire)) return false;
            self.queue[tail] = .{ .close_trace = close };
            self.queue_tail.store(next, .release);
            self.wakeWriter();
            return true;
        }

        fn enqueueClose(self: *State, handle: u64) void {
            if (self.stopping.load(.acquire)) return;
            const close = CloseCommand{
                .handle = handle,
                .after_seq = self.accepted_seq.load(.acquire),
            };
            const tail = self.close_queue_tail.load(.monotonic);
            const next = advanceIndex(tail, self.close_queue.len);
            if (next == self.close_queue_head.load(.acquire)) {
                if (self.tryEnqueueCloseData(close)) return;
                self.qlog_capture_abandoned.store(true, .release);
                self.noteDrop(.qlog);
                self.requestCloseAll(close.after_seq);
                self.wakeWriter();
                return;
            }
            self.close_queue[tail] = close;
            self.close_queue_tail.store(next, .release);
            self.wakeWriter();
        }

        fn requestCloseAll(self: *State, after_seq: u64) void {
            var current = self.close_all_after_seq.load(.acquire);
            while (after_seq < current) {
                if (self.close_all_after_seq.cmpxchgWeak(current, after_seq, .acq_rel, .acquire)) |actual| {
                    current = actual;
                } else {
                    return;
                }
            }
        }

        fn hasData(self: *const State) bool {
            return self.queue_head.load(.acquire) != self.queue_tail.load(.acquire);
        }

        fn hasClose(self: *const State) bool {
            return self.close_queue_head.load(.acquire) != self.close_queue_tail.load(.acquire);
        }

        fn pendingCloseAll(self: *const State) bool {
            return self.close_all_after_seq.load(.acquire) != std.math.maxInt(u64);
        }

        fn popData(self: *State) ?DataCommand {
            const head = self.queue_head.load(.monotonic);
            if (head == self.queue_tail.load(.acquire)) return null;
            const command = self.queue[head];
            self.queue_head.store(advanceIndex(head, self.queue.len), .release);
            return command;
        }

        fn peekClose(self: *const State) ?CloseCommand {
            const head = self.close_queue_head.load(.monotonic);
            if (head == self.close_queue_tail.load(.acquire)) return null;
            return self.close_queue[head];
        }

        fn popClose(self: *State) ?CloseCommand {
            const head = self.close_queue_head.load(.monotonic);
            if (head == self.close_queue_tail.load(.acquire)) return null;
            const command = self.close_queue[head];
            self.close_queue_head.store(advanceIndex(head, self.close_queue.len), .release);
            return command;
        }

        fn closeReady(self: *const State, close: CloseCommand) bool {
            return self.processed_seq.load(.acquire) >= close.after_seq;
        }

        fn dataQueueLen(self: *const State) usize {
            const head = self.queue_head.load(.acquire);
            const tail = self.queue_tail.load(.acquire);
            return if (tail >= head) tail - head else self.queue.len - head + tail;
        }

        fn closeQueueLen(self: *const State) usize {
            const head = self.close_queue_head.load(.acquire);
            const tail = self.close_queue_tail.load(.acquire);
            return if (tail >= head) tail - head else self.close_queue.len - head + tail;
        }

        fn hasWork(self: *const State) bool {
            return self.hasData() or self.hasClose() or self.pendingCloseAll() or self.drop_diagnostic_pending.load(.acquire);
        }

        fn waitIdle(self: *State) void {
            while (self.hasWork() or self.worker_active.load(.acquire)) {
                std.Thread.yield() catch {};
            }
        }

        fn traceCount(self: *State) usize {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.traces.count();
        }

        fn closeTraceOnWriter(self: *State, handle: u64) void {
            if (self.traces.fetchRemove(handle)) |kv| kv.value.deinit(self.allocator);
        }

        fn closeAllTracesOnWriter(self: *State) void {
            var it = self.traces.valueIterator();
            while (it.next()) |trace| trace.*.deinit(self.allocator);
            self.traces.clearRetainingCapacity();
        }
    };

    pub fn init(allocator: std.mem.Allocator, qlog_dir: []const u8, keylog_path: []const u8) !ObservabilityArtifacts {
        return initWithLogger(allocator, null, qlog_dir, keylog_path);
    }

    pub fn initWithLogger(allocator: std.mem.Allocator, logger: ?*Logger, qlog_dir: []const u8, keylog_path: []const u8) !ObservabilityArtifacts {
        return .{ .state = try State.init(allocator, logger, qlog_dir, keylog_path) };
    }

    pub fn deinit(self: *ObservabilityArtifacts) void {
        self.state.deinit();
        self.* = undefined;
    }

    pub fn qlogEnabled(self: *const ObservabilityArtifacts) bool {
        return self.state.qlogEnabled();
    }

    pub fn keylogContext(self: *ObservabilityArtifacts) tls_core.keylog.Context {
        if (self.state.keylog_fd == null) return .{};
        return .{
            .enabled = true,
            .role = .server,
            .sink = .{ .context = self, .emit_fn = emitKeylog },
        };
    }

    pub fn writeQuicRecord(ctx: *anyopaque, handle: u64, record: quic.qlog.Record) void {
        const self: *ObservabilityArtifacts = @ptrCast(@alignCast(ctx));
        if (!self.qlogEnabled()) return;
        var bytes: [qlog_record_max]u8 = undefined;
        const line = quic.qlog.writeJson(record, &bytes) catch {
            self.state.noteDrop(.qlog);
            return;
        };
        self.state.tryEnqueue(.qlog, .{ .qlog = .{ .handle = handle, .bytes = bytes, .len = line.len } });
    }

    pub fn writeH3Record(ctx: *anyopaque, handle: u64, record: http3.qlog.Record) void {
        const self: *ObservabilityArtifacts = @ptrCast(@alignCast(ctx));
        if (!self.qlogEnabled()) return;
        var bytes: [qlog_record_max]u8 = undefined;
        const line = http3.qlog.writeJson(record, &bytes) catch {
            self.state.noteDrop(.qlog);
            return;
        };
        self.state.tryEnqueue(.qlog, .{ .qlog = .{ .handle = handle, .bytes = bytes, .len = line.len } });
    }

    pub fn closeTrace(ctx: *anyopaque, handle: u64) void {
        const self: *ObservabilityArtifacts = @ptrCast(@alignCast(ctx));
        if (!self.qlogEnabled()) return;
        self.state.enqueueClose(handle);
    }

    fn emitKeylog(ctx: ?*anyopaque, entry: tls_core.keylog.Entry) void {
        const self: *ObservabilityArtifacts = @ptrCast(@alignCast(ctx.?));
        var bytes: [keylog_record_max]u8 = undefined;
        const line = tls_core.keylog.writeLine(entry, &bytes) catch {
            self.state.noteDrop(.keylog);
            return;
        };
        self.state.tryEnqueue(.keylog, .{ .keylog = .{ .bytes = bytes, .len = line.len } });
    }

    pub fn waitIdle(self: *ObservabilityArtifacts) void {
        self.state.waitIdle();
    }

    pub fn traceCount(self: *ObservabilityArtifacts) usize {
        return self.state.traceCount();
    }

    pub fn diagnostics(self: *const ObservabilityArtifacts) Diagnostics {
        return self.state.diagnostics();
    }

    fn advanceIndex(index: usize, len: usize) usize {
        return if (index + 1 == len) 0 else index + 1;
    }

    fn workerMain(state: *State) void {
        while (true) {
            state.awaitWork();

            const close_all_after_seq = state.close_all_after_seq.load(.acquire);
            if (close_all_after_seq != std.math.maxInt(u64) and state.processed_seq.load(.acquire) >= close_all_after_seq) {
                state.worker_active.store(true, .release);
                state.closeAllTracesOnWriter();
                state.close_all_after_seq.store(std.math.maxInt(u64), .release);
                state.worker_active.store(false, .release);
            }

            if (state.peekClose()) |close| {
                if (state.closeReady(close)) {
                    state.worker_active.store(true, .release);
                    _ = state.popClose();
                    state.closeTraceOnWriter(close.handle);
                    state.worker_active.store(false, .release);
                    continue;
                }
            }

            if (state.hasData()) {
                state.worker_active.store(true, .release);
                const command = state.popData() orelse {
                    state.worker_active.store(false, .release);
                    continue;
                };
                processCommand(state, command);
                switch (command) {
                    .qlog, .keylog => _ = state.processed_seq.fetchAdd(1, .release),
                    .close_trace => {},
                }
                state.worker_active.store(false, .release);
                logPendingDrops(state);
                continue;
            }

            logPendingDrops(state);
            if (state.stopping.load(.acquire)) break;
        }
    }

    fn logPendingDrops(state: *State) void {
        if (!state.drop_diagnostic_pending.swap(false, .acq_rel)) return;
        const d = state.diagnostics();
        if (state.logger) |logger| {
            if (d.qlog_dropped_records != 0 and state.qlog_drop_reported.cmpxchgStrong(false, true, .acq_rel, .acquire) == null) {
                logger.warn(null, "HTTP/3 observability artifact records dropped kind=qlog count={d}", .{d.qlog_dropped_records});
            }
            if (d.keylog_dropped_records != 0 and state.keylog_drop_reported.cmpxchgStrong(false, true, .acq_rel, .acquire) == null) {
                logger.warn(null, "HTTP/3 observability artifact records dropped kind=keylog count={d}", .{d.keylog_dropped_records});
            }
        }
    }

    fn processCommand(state: *State, command: DataCommand) void {
        switch (command) {
            .qlog => |record| {
                const trace = traceFor(state, record.handle) catch |err| {
                    state.noteWriteError(.qlog, err);
                    return;
                };
                trace.file.writeAll(record.bytes[0..record.len]) catch |err| {
                    state.noteWriteError(.qlog, err);
                };
            },
            .keylog => |record| {
                const fd = state.keylog_fd orelse return;
                writeAllFd(fd, record.bytes[0..record.len]) catch |err| {
                    state.noteWriteError(.keylog, err);
                };
            },
            .close_trace => |close| state.closeTraceOnWriter(close.handle),
        }
    }

    fn traceFor(state: *State, handle: u64) !*Trace {
        if (state.traces.get(handle)) |trace| return trace;

        var attempts: usize = 0;
        while (attempts < 1024) : (attempts += 1) {
            const path = if (attempts == 0)
                try std.fmt.allocPrint(state.allocator, "{s}/quic-{x:0>16}.sqlog", .{ state.qlog_dir, handle })
            else
                try std.fmt.allocPrint(state.allocator, "{s}/quic-{x:0>16}-{d}.sqlog", .{ state.qlog_dir, handle, attempts });
            errdefer state.allocator.free(path);
            var file = compat.cwd().createFile(path, .{
                .read = false,
                .truncate = false,
                .exclusive = true,
                .permissions = @enumFromInt(0o600),
            }) catch |err| switch (err) {
                error.PathAlreadyExists => {
                    state.allocator.free(path);
                    continue;
                },
                else => return err,
            };
            errdefer file.close();
            var group_buf: [32]u8 = undefined;
            var header_buf: [1024]u8 = undefined;
            const header = try quic.qlog.writeTraceHeader(.{
                .group_id = try std.fmt.bufPrint(&group_buf, "{x:0>16}", .{handle}),
                .vantage_point = .server,
            }, .current, &header_buf);
            try file.writeAll(header);
            const trace = try state.allocator.create(Trace);
            trace.* = .{ .path = path, .file = file };
            try state.traces.put(handle, trace);
            return trace;
        }
        return error.QlogPathCollision;
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

/// Half-open admission limits (#328 review). The native stack does not send
/// Retry, so an off-path spoofer can forge Initial packets. Rather than
/// implement address validation now, we bound the state a spoofer can pin: a
/// global connection cap, a per-source-IP cap, immediate teardown of an Initial
/// that authenticates nothing, and a handshake deadline well under the idle
/// timeout so half-open connections are reaped promptly.
const max_connections: usize = 1024;
const max_connections_per_source: u32 = 32;
const handshake_timeout_us: u64 = 10 * std.time.us_per_s;
const cid_generation_retries: usize = 16;
/// The listener never sleeps longer than this in one pass, so a connection
/// whose state changed without arming a deadline is still revisited promptly.
const max_loop_wait_us: u64 = 100 * std.time.us_per_ms;

/// Wait for the QUIC socket to become readable, or for a deadline — with
/// finer resolution than `poll(2)` can express (#256-C).
///
/// `poll` takes an integer number of milliseconds. That was fine when every
/// deadline this loop computed came from a timer measured in milliseconds, and
/// it stopped being fine when pacing started producing them: on a fast path
/// the interval between two datagrams is tens of microseconds, and rounding
/// each release up to 1 ms caps the listener at one burst per millisecond no
/// matter what the congestion window and RTT actually permit. So the wait uses
/// whatever nanosecond-resolution primitive the platform has.
///
/// `poll` remains the fallback, and it is a safe one rather than a broken one:
/// a platform that lands there sleeps at millisecond granularity exactly as
/// this loop always did. It sends at a coarser cadence, not an incorrect one —
/// the pacer is still what decides *whether* a datagram may leave.
const SocketWaiter = struct {
    fd: posix.fd_t,
    /// BSD `kqueue` descriptor, or `-1` on platforms that do not use one —
    /// including a BSD where `kqueue` failed, which simply falls back.
    kq: i32 = -1,

    const uses_kqueue = switch (builtin.os.tag) {
        .macos, .ios, .tvos, .watchos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => true,
        else => false,
    };

    /// A valid pointer for the list `kevent` is told to read zero entries
    /// from. The kernel never dereferences it, but handing a syscall an
    /// `undefined` pointer is undefined behaviour on this side of the call
    /// regardless of what the other side does with it.
    const no_events: [0]std.c.Kevent = .{};

    /// Every reference to `std.c.Kevent`/`EVFILT`/`EV` sits inside a branch on
    /// this comptime-known flag, so it is never *analysed* off the BSDs — on
    /// Linux `std.c.Kevent` resolves to `void` and naming its fields would not
    /// merely be dead code, it would fail to compile.
    fn init(fd: posix.fd_t) SocketWaiter {
        var self = SocketWaiter{ .fd = fd };
        if (uses_kqueue) {
            if (fd < 0) return self;
            const kq = std.c.kqueue();
            if (kq < 0) return self;
            // Registered once, level-triggered: every later `kevent` call is a
            // pure wait with no changelist, which is what keeps the hot path
            // to a single syscall.
            const change = [_]std.c.Kevent{.{
                .ident = @intCast(fd),
                .filter = std.c.EVFILT.READ,
                .flags = std.c.EV.ADD,
                .fflags = 0,
                .data = 0,
                .udata = 0,
            }};
            if (std.c.kevent(kq, &change, 1, @constCast(&no_events), 0, null) < 0) {
                _ = std.c.close(kq);
                return self;
            }
            self.kq = kq;
        }
        return self;
    }

    fn deinit(self: *SocketWaiter) void {
        if (self.kq >= 0) _ = std.c.close(self.kq);
        self.kq = -1;
    }

    /// Sleep until the socket is readable or `timeout_us` elapses. Errors are
    /// swallowed deliberately: every one of them means "stopped waiting early",
    /// and the loop's next pass re-derives what to do from connection state
    /// rather than from what this call returned.
    fn wait(self: *SocketWaiter, timeout_us: u64) void {
        const ts = std.posix.timespec{
            .sec = @intCast(timeout_us / std.time.us_per_s),
            .nsec = @intCast((timeout_us % std.time.us_per_s) * std.time.ns_per_us),
        };
        if (uses_kqueue) {
            if (self.kq >= 0) {
                var event: [1]std.c.Kevent = undefined;
                _ = std.c.kevent(self.kq, &no_events, 0, &event, 1, &ts);
                return;
            }
        }
        var fds = [_]posix.pollfd{
            .{ .fd = self.fd, .events = posix.POLL.IN, .revents = 0 },
        };
        if (builtin.os.tag == .linux) {
            _ = posix.ppoll(&fds, &ts, null) catch {};
            return;
        }
        _ = posix.poll(&fds, pollTimeoutMs(timeout_us)) catch {};
    }

    /// `poll`'s millisecond timeout for a microsecond deadline. Rounds *up* so
    /// the loop never wakes before the deadline it computed and re-runs a pass
    /// that can do nothing; a sub-millisecond deadline therefore becomes 1 ms,
    /// which is the resolution limit this fallback exists to acknowledge.
    fn pollTimeoutMs(timeout_us: u64) i32 {
        const ms = (timeout_us + std.time.us_per_ms - 1) / std.time.us_per_ms;
        return @intCast(@min(@max(ms, 1), max_loop_wait_us / std.time.us_per_ms));
    }
};

const ParkedH3Retry = struct {
    stream_id: u64,
    started_us: u64,
    continuation: http3_session.StreamRequest.Early425RetryContinuation,

    fn deinit(self: *ParkedH3Retry, allocator: std.mem.Allocator) void {
        self.continuation.deinit(allocator);
        self.* = undefined;
    }
};

const RemovalReason = enum {
    unauthenticated_initial,
    handshake_timeout,
    protocol_failure,
    administrative,
};

pub const Snapshot = struct {
    quic_port: u16 = 0,
    server_bootstrapped: bool = false,
    datagrams_seen: usize = 0,
    bytes_seen: usize = 0,
    zero_rtt_packets_seen: usize = 0,
    tracked_connections: usize = 0,
    native_connections: usize = 0,
    native_reads_attempted: usize = 0,
    native_read_calls: usize = 0,
    handshakes_completed: usize = 0,
    stream_bytes_received: usize = 0,
    stream_chunks_received: usize = 0,
    requests_completed: usize = 0,
    packets_emitted: usize = 0,
    bytes_emitted: usize = 0,
    migration_events: usize = 0,
    retry_packets_sent: usize = 0,
    retry_tokens_accepted: usize = 0,
    invalid_tokens: usize = 0,
    path_challenges_sent: usize = 0,
    path_validations_succeeded: usize = 0,
    path_validations_failed: usize = 0,
    path_response_mismatches: usize = 0,
    nat_rebindings: usize = 0,
    migrations: usize = 0,
    migrations_blocked: usize = 0,
    migrations_blocked_no_peer_cid: usize = 0,
    last_error_code: i32 = 0,
    draining: bool = false,
    h3_goaway_sent: usize = 0,
    h3_drain_request_rejections: usize = 0,
    active_cid_routes: usize = 0,
    /// What the kernel actually granted for this listener's socket buffers
    /// (#256-D) — read back at bind time, never the requested value. Fixed
    /// for the life of the socket, so unlike every counter above it is
    /// written once at init.
    udp_buffers: quic.udp.EffectiveBufferTuning = .{},
    /// Whether this listener is running ECN at all (#256-E): the operator
    /// asked for it *and* the kernel agreed to report received codepoints.
    /// Fixed for the life of the socket unless a marked send is refused, which
    /// clears it — so a benchmark run records the state that actually applied.
    ecn_enabled: bool = false,
    /// Folded from every connection's transport counters, so an operator can
    /// tell "ECN is on and working" from "ECN is on and every path turned it
    /// off". `ecn_paths_disabled` is expected to be non-zero on the open
    /// internet and is not an error condition.
    ecn_marked_sent: usize = 0,
    ecn_paths_validated: usize = 0,
    ecn_paths_disabled: usize = 0,
    ecn_ce_received: usize = 0,
    /// #256-G: QUIC packet counters folded from every connection's transport
    /// metrics, the same way `ecn_marked_sent` etc. are folded above. These
    /// are UDP-datagram-level packet counts (one QUIC packet per datagram in
    /// this transport, no coalescing), not HTTP/3 request counts.
    packets_sent: usize = 0,
    packets_received: usize = 0,
    /// #256-G: DPLPMTUD probe/black-hole counters folded from `quic.connection.Metrics`
    /// (`pmtu_probes_sent`/`pmtu_black_holes`, populated by #256-B). Previously
    /// only readable from inside a connection; this is the smallest bridge
    /// needed to make them benchmark/status-visible per #256-G, not a new
    /// observability subsystem (#255 remains the canonical owner of that).
    pmtu_probes_sent: usize = 0,
    pmtu_black_holes: usize = 0,
    /// #256-G: effective PLPMTU (path MTU the transport actually sends at,
    /// see `quic.pmtu.Controller.sendSize()`) observed across folded
    /// connections' *active* path. A single listener can have many
    /// concurrent connections/paths with different discovered values, so a
    /// lone "the PLPMTU" gauge would be misleading for anything but a
    /// benchmark that guarantees exactly one connection. Instead:
    ///   - `plpmtu_last_bytes` is the active-path PLPMTU of whichever
    ///     connection was most recently folded — the right value to read for
    ///     a single-connection benchmark run, but not a listener-wide
    ///     aggregate for production traffic with many concurrent paths.
    ///   - `plpmtu_lifetime_min_bytes`/`plpmtu_lifetime_max_bytes` are the
    ///     smallest/largest active-path PLPMTU observed across every fold
    ///     since this listener started. They are named `lifetime_*`
    ///     deliberately (#256-G review): they never reset, so on a listener
    ///     that has served more than one connection or more than one
    ///     benchmark scenario, `lifetime_min_bytes` reads 1200 forever after
    ///     the first connection's startup fold, regardless of what every
    ///     later path converged to. They describe "has this listener ever
    ///     seen a path stuck below the maximum" over its whole running
    ///     time — not a per-scenario, per-benchmark-pass, or even per-
    ///     connection figure, and not evidence that paths in any particular
    ///     benchmark run did or did not converge. A benchmark wanting a
    ///     scenario-scoped PLPMTU spread would need a connection-scoped
    ///     snapshot this runtime does not currently take; `plpmtu_last_bytes`
    ///     is the closest available proxy for "what a benchmark pass saw."
    plpmtu_last_bytes: usize = 0,
    plpmtu_lifetime_min_bytes: usize = 0,
    plpmtu_lifetime_max_bytes: usize = 0,

    pub fn handshakeState(self: Snapshot) []const u8 {
        if (!self.server_bootstrapped) return "bootstrap_incomplete";
        if (self.handshakes_completed > 0) return "complete";
        if (self.native_connections > 0) return "connection_created";
        if (self.datagrams_seen > 0) return "datagram_seen";
        return "idle";
    }
};

/// One accepted QUIC connection with its HTTP/3 session state.
const ConnEntry = struct {
    const QuicObserver = struct {
        runtime: *Runtime,
        connection_handle: u64,
        qlog_sink: quic.qlog.Sink = .{},
        qlog_artifacts_ctx: ?*anyopaque = null,
        qlog_artifact_cb: ?*const fn (*anyopaque, u64, quic.qlog.Record) void = null,
        qlog_artifact_close_cb: ?*const fn (*anyopaque, u64) void = null,
        close_logged: bool = false,
        handshake_stage: metrics_mod.QuicHandshakeFailureStage = .initial,
        handshake_succeeded: bool = false,
        administrative_close: bool = false,
    };

    const H3Observer = struct {
        runtime: *Runtime,
        connection_handle: u64,
        qlog_sink: http3.qlog.Sink = .{},
        qlog_artifacts_ctx: ?*anyopaque = null,
        qlog_artifact_cb: ?*const fn (*anyopaque, u64, http3.qlog.Record) void = null,
    };

    backend: *quic.tls_backend.Tls13Backend,
    conn: *Connection,
    h3: H3,
    quic_observer: QuicObserver = undefined,
    h3_observer: H3Observer = undefined,
    h3_started: bool = false,
    /// Source IPv4 address of the Initial that opened the connection,
    /// immutable for the connection's lifetime. Used only for half-open
    /// admission accounting (increment/decrement/teardown) — never for
    /// routing egress, since the active path can now change and every
    /// `pollTransmitOnPath` datagram already carries its own destination.
    admission_source_ip: u32,
    cid_len: usize,
    /// Monotonic microseconds when the connection was accepted; used to reap
    /// connections that never complete the handshake.
    accepted_at_us: u64,
    owned_cids: [quic.cid.max_local_active_cids]quic.cid.ConnectionId = undefined,
    owned_cid_count: usize = 0,
    /// Set exactly once this connection has attempted post-handshake ticket
    /// issuance (successfully or not) — issuance is best-effort and must
    /// never be retried on the same connection (#488).
    ticket_issue_attempted: bool = false,
    drain_goaway_sent: bool = false,
    handshake_failure_recorded: bool = false,
    highest_admitted_request_stream_id: ?u64 = null,
    drain_goaway_boundary: ?u64 = null,
    last_path_metrics: quic.path.Metrics = .{},
    /// The connection's transport counters as of the last fold, so the
    /// listener snapshot accumulates deltas rather than re-adding totals
    /// (#256-E). Same pattern as `last_path_metrics`.
    last_transport_metrics: quic.connection.Metrics = .{},
    last_stream_metrics: quic.stream.Metrics = .{},
    last_tls_metrics: quic.tls_adapter.Metrics = .{},
    parked_h3_retries: std.ArrayList(ParkedH3Retry) = .empty,
    pending_h3_responses: std.ArrayList(PendingH3Response) = .empty,

    fn deinit(self: *ConnEntry, allocator: std.mem.Allocator) void {
        for (self.parked_h3_retries.items) |*parked| parked.deinit(allocator);
        self.parked_h3_retries.deinit(allocator);
        for (self.pending_h3_responses.items) |*pending| pending.deinit(allocator);
        self.pending_h3_responses.deinit(allocator);
        self.h3.deinit();
        self.conn.deinit();
        allocator.destroy(self.backend);
    }
};

const PendingH3Response = struct {
    stream_id: u64,
    started_us: u64,
    headers: []stream_transport.Header,
    header_names: [][]u8,
    header_values: [][]u8,
    body: []u8,
    send_state: H3.ResponseSendState,

    fn init(
        allocator: std.mem.Allocator,
        stream_id: u64,
        started_us: u64,
        status: u16,
        headers: []const stream_transport.Header,
        body: []const u8,
    ) !PendingH3Response {
        const owned_headers = try allocator.alloc(stream_transport.Header, headers.len);
        errdefer allocator.free(owned_headers);
        const header_names = try allocator.alloc([]u8, headers.len);
        errdefer allocator.free(header_names);
        const header_values = try allocator.alloc([]u8, headers.len);
        errdefer allocator.free(header_values);

        var copied: usize = 0;
        errdefer {
            for (header_names[0..copied]) |name| allocator.free(name);
            for (header_values[0..copied]) |value| allocator.free(value);
        }
        for (headers, 0..) |header, i| {
            const name = try allocator.dupe(u8, header.name);
            const value = allocator.dupe(u8, header.value) catch |err| {
                allocator.free(name);
                return err;
            };
            owned_headers[i] = .{ .name = name, .value = value };
            header_names[i] = name;
            header_values[i] = value;
            copied += 1;
        }

        const owned_body = try allocator.dupe(u8, body);
        errdefer allocator.free(owned_body);

        return .{
            .stream_id = stream_id,
            .started_us = started_us,
            .headers = owned_headers,
            .header_names = header_names,
            .header_values = header_values,
            .body = owned_body,
            .send_state = H3.ResponseSendState.init(status, owned_headers, owned_body),
        };
    }

    fn deinit(self: *PendingH3Response, allocator: std.mem.Allocator) void {
        for (self.header_names) |name| allocator.free(name);
        for (self.header_values) |value| allocator.free(value);
        allocator.free(self.header_names);
        allocator.free(self.header_values);
        allocator.free(self.headers);
        allocator.free(self.body);
        self.* = undefined;
    }
};

/// The Retry token key ring and the process stateless-reset key are the
/// only long-lived secrets `Runtime` owns. Grouping them here makes their
/// lifecycle (installed at `init`, wiped on teardown or a later init
/// failure) independently testable via `deinit` — including calling the
/// exact cleanup the production owner uses — without fighting
/// `Runtime.deinit`'s own trailing `self.* = undefined`, which
/// safety-checked builds use to poison-fill the *entire* enclosing struct
/// and would otherwise make any post-deinit byte-level assertion on these
/// fields meaningless.
const RuntimeSecrets = struct {
    retry_tokens: quic.path.RetryTokens = .{},
    stateless_reset_key: [32]u8 = [_]u8{0} ** 32,

    fn deinit(self: *RuntimeSecrets) void {
        self.retry_tokens.keys.deinit();
        crypto_pkg.secrets.secureZero(&self.stateless_reset_key);
    }
};

pub const Runtime = struct {
    allocator: std.mem.Allocator,
    socket_fd: std.c.fd_t,
    thread: ?std.Thread,
    logger: *logger_mod.Logger,
    quic_port: u16,
    /// The actually-bound local UDP address (`getsockname` semantics), used
    /// as every connection's and `PathKey`'s local half. Resolved once at
    /// bind time so a `quic_port = 0` (OS-assigned ephemeral port) test still
    /// gets a real, routable local address instead of the requested `0`.
    local_address: quic.udp.Address,
    request_handler: ?RequestHandler,
    request_handler_ctx: ?*anyopaque,
    credential_provider: ?tls_core.credentials.CredentialProvider,
    resumption_runtime: ?*tls_core.resumption_runtime.Runtime,
    early_data_replay_gate: ?tls_core.tls13_backend.EarlyDataReplayGate,
    /// #523: whether the native QUIC 0-RTT carrier is actually composed and
    /// enabled — see `zeroRttCarrierEnabled`. Drives both `quic_config`'s
    /// `zero_rtt_enabled` gate and whether `accept()` installs a server
    /// early-data policy on new connections' TLS backends.
    zero_rtt_enabled: bool,
    retry_policy: quic.config.RetryPolicy,
    secrets: RuntimeSecrets,
    quic_config: quic.config.Config,
    h3_settings: http3.frame.Settings,
    max_request_body_bytes: usize = http3.session.RequestStream.default_max_body_len,
    max_buffered_request_bytes: usize = http3.conn.default_max_buffered_request_bytes,
    h3_application_compat: [http3.early_data.encoded_snapshot_len]u8 = undefined,
    h3_application_compat_len: usize = 0,
    early_data_compat_metrics_ctx: ?*anyopaque = null,
    early_data_compat_metrics_cb: ?*const fn (*anyopaque, metrics_mod.H3EarlyDataCompatDecision) void = null,
    quic_early_data_decision_metrics_ctx: ?*anyopaque = null,
    quic_early_data_decision_metrics_cb: ?*const fn (*anyopaque, metrics_mod.QuicEarlyDataDecision) void = null,
    quic_zero_rtt_packet_metrics_ctx: ?*anyopaque = null,
    quic_zero_rtt_packet_metrics_cb: ?*const fn (*anyopaque, metrics_mod.QuicZeroRttPacketOutcome) void = null,
    quic_transport_metrics_ctx: ?*anyopaque = null,
    quic_transport_metrics_cb: ?*const fn (*anyopaque, metrics_mod.QuicTransportDelta) void = null,
    quic_connections_active_metrics_ctx: ?*anyopaque = null,
    quic_connections_active_metrics_cb: ?*const fn (*anyopaque, usize) void = null,
    quic_handshake_failure_metrics_ctx: ?*anyopaque = null,
    quic_handshake_failure_metrics_cb: ?*const fn (*anyopaque, metrics_mod.QuicHandshakeFailureStage) void = null,
    h3_request_latency_metrics_ctx: ?*anyopaque = null,
    h3_request_latency_metrics_cb: ?*const fn (*anyopaque, u64) void = null,
    h3_qlog_sink: http3.qlog.Sink = .{},
    quic_qlog_sink: quic.qlog.Sink = .{},
    h3_qlog_sink_factory_ctx: ?*anyopaque = null,
    h3_qlog_sink_factory_cb: ?*const fn (?*anyopaque, u64) http3.qlog.Sink = null,
    quic_qlog_sink_factory_ctx: ?*anyopaque = null,
    quic_qlog_sink_factory_cb: ?*const fn (?*anyopaque, u64) quic.qlog.Sink = null,
    qlog_artifacts_ctx: ?*anyopaque = null,
    quic_qlog_artifact_cb: ?*const fn (*anyopaque, u64, quic.qlog.Record) void = null,
    h3_qlog_artifact_cb: ?*const fn (*anyopaque, u64, http3.qlog.Record) void = null,
    qlog_artifact_close_cb: ?*const fn (*anyopaque, u64) void = null,
    tls_keylog_context: tls_core.keylog.Context = .{},
    snapshot_mutex: compat.Mutex = .{},
    snapshot_state: Snapshot,
    stopping: std.atomic.Value(bool),
    drain_requested: std.atomic.Value(bool),
    drain_deadline_us: std.atomic.Value(u64),
    /// The concrete `CryptoProvider` backend for native QUIC packet
    /// protection (#490). This is the native HTTP/QUIC composition root:
    /// `src/quic/` never selects a backend itself, only this module does,
    /// via `tls_core.production_crypto.Provider` (the pure-Zig backend) fed
    /// by real OS entropy.
    crypto_provider_entropy: tls_core.production_crypto.OsEntropy = .{},
    crypto_provider_state: tls_core.production_crypto.Provider = undefined,
    /// Whether outbound datagrams may carry an ECN control message (#256-E).
    /// Starts as whatever the receive-side configuration established, and is
    /// cleared for good if the kernel ever refuses the send-side control
    /// message — the two are separate capabilities on some platforms, and one
    /// refusal is enough to know marking will never work here.
    ecn_send_enabled: bool = false,

    /// Erase `crypto_provider_state` to the boundary type for a `Connection`.
    /// Borrows `self`, so the returned value must not outlive this `Runtime`
    /// (true for every connection it accepts, since it outlives them all).
    fn cryptoProvider(self: *Runtime) crypto_pkg.provider.CryptoProvider {
        return self.crypto_provider_state.cryptoProvider();
    }

    pub fn init(allocator: std.mem.Allocator, logger: *logger_mod.Logger, cfg: Config) Http3RuntimeError!Runtime {
        const address = compat.parseIpAddress(cfg.listen_host, cfg.quic_port) catch |err| {
            logger.warn(null, "http3: listen address parse failed: {s}", .{@errorName(err)});
            return error.BindFailed;
        };
        const sa_family = @as(*const std.c.sockaddr, @ptrCast(&address.storage)).family;
        const fd = openUdpSocket(sa_family);
        if (fd < 0) return error.BindFailed;
        errdefer _ = std.c.close(fd);

        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&@as(c_int, 1))) catch {}; // REUSEADDR is advisory; bind proceeds regardless
        // DPLPMTUD's precondition (#256-B). Advisory to the *listener* — a
        // kernel that refuses it still serves QUIC — but binding on discovery:
        // without it a probe can be fragmented and its acknowledgement would
        // measure reassembly instead of the path.
        const no_fragment = configureNoFragment(fd, sa_family);
        if (!no_fragment) {
            logger.warn(null, "http3: no-fragmentation socket policy unavailable; path MTU discovery held at {d} bytes", .{quic.datagram.base_size});
        }
        // ECN's precondition (#256-E). Marking is only worth doing if the peer
        // can be observed marking back, so the *receive* side is what gates
        // it: without received codepoints there is nothing to put in ACK_ECN,
        // the peer's own validation fails, and this endpoint would be marking
        // into a feedback loop it cannot close. Advisory to the listener —
        // refusing it costs a congestion signal, not correctness.
        const ecn_receive = cfg.ecn_enabled and configureEcnReceive(fd, sa_family);
        if (cfg.ecn_enabled and !ecn_receive) {
            logger.warn(null, "http3: ECN unavailable on this platform or socket; running without explicit congestion notification", .{});
        }
        // Advisory, and applied before `bind` so the socket is never briefly
        // reachable with a buffer the operator did not ask for (#256-D).
        const udp_buffers = tuneSocketBuffers(fd, cfg.udp_buffer_tuning);
        logSocketBufferOutcome(logger, "receive", udp_buffers.recv);
        logSocketBufferOutcome(logger, "send", udp_buffers.send);
        const bind_rc = std.c.bind(fd, @ptrCast(&address.storage), @intCast(address.len));
        if (bind_rc != 0) {
            logger.warn(null, "http3: udp bind failed: {s}", .{@tagName(posix.errno(bind_rc))});
            return error.BindFailed;
        }

        // Resolve the actually-bound local address/port (`getsockname`): with
        // `quic_port = 0` the OS assigns an ephemeral port only known now.
        var local_address = quic.udp.Address.ip4(.{ 0, 0, 0, 0 }, cfg.quic_port);
        if (sa_family == posix.AF.INET) {
            var bound: std.c.sockaddr.in = undefined;
            var bound_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
            if (std.c.getsockname(fd, @ptrCast(&bound), &bound_len) == 0) {
                local_address = addressFromSockaddrIn(bound);
            }
        }

        var runtime = Runtime{
            .allocator = allocator,
            .socket_fd = fd,
            .thread = null,
            .logger = logger,
            .quic_port = cfg.quic_port,
            .local_address = local_address,
            .request_handler = cfg.request_handler,
            .request_handler_ctx = cfg.request_handler_ctx,
            .credential_provider = cfg.credential_provider,
            .resumption_runtime = cfg.resumption_runtime,
            .early_data_replay_gate = cfg.early_data_replay_gate,
            .zero_rtt_enabled = zeroRttCarrierEnabled(cfg),
            .retry_policy = cfg.retry_policy,
            .secrets = .{},
            .quic_config = quicConfigFrom(cfg, no_fragment, ecn_receive),
            .ecn_send_enabled = ecn_receive,
            .h3_settings = cfg.h3_settings,
            .max_request_body_bytes = cfg.max_request_body_bytes,
            .max_buffered_request_bytes = cfg.max_buffered_request_bytes,
            .early_data_compat_metrics_ctx = cfg.early_data_compat_metrics_ctx,
            .early_data_compat_metrics_cb = cfg.early_data_compat_metrics_cb,
            .quic_early_data_decision_metrics_ctx = cfg.quic_early_data_decision_metrics_ctx,
            .quic_early_data_decision_metrics_cb = cfg.quic_early_data_decision_metrics_cb,
            .quic_zero_rtt_packet_metrics_ctx = cfg.quic_zero_rtt_packet_metrics_ctx,
            .quic_zero_rtt_packet_metrics_cb = cfg.quic_zero_rtt_packet_metrics_cb,
            .quic_transport_metrics_ctx = cfg.quic_transport_metrics_ctx,
            .quic_transport_metrics_cb = cfg.quic_transport_metrics_cb,
            .quic_connections_active_metrics_ctx = cfg.quic_connections_active_metrics_ctx,
            .quic_connections_active_metrics_cb = cfg.quic_connections_active_metrics_cb,
            .quic_handshake_failure_metrics_ctx = cfg.quic_handshake_failure_metrics_ctx,
            .quic_handshake_failure_metrics_cb = cfg.quic_handshake_failure_metrics_cb,
            .h3_request_latency_metrics_ctx = cfg.h3_request_latency_metrics_ctx,
            .h3_request_latency_metrics_cb = cfg.h3_request_latency_metrics_cb,
            .h3_qlog_sink = cfg.h3_qlog_sink,
            .quic_qlog_sink = cfg.quic_qlog_sink,
            .h3_qlog_sink_factory_ctx = cfg.h3_qlog_sink_factory_ctx,
            .h3_qlog_sink_factory_cb = cfg.h3_qlog_sink_factory_cb,
            .quic_qlog_sink_factory_ctx = cfg.quic_qlog_sink_factory_ctx,
            .quic_qlog_sink_factory_cb = cfg.quic_qlog_sink_factory_cb,
            .qlog_artifacts_ctx = cfg.qlog_artifacts_ctx,
            .quic_qlog_artifact_cb = cfg.quic_qlog_artifact_cb,
            .h3_qlog_artifact_cb = cfg.h3_qlog_artifact_cb,
            .qlog_artifact_close_cb = cfg.qlog_artifact_close_cb,
            .tls_keylog_context = cfg.tls_keylog_context,
            .snapshot_state = .{
                .quic_port = cfg.quic_port,
                .udp_buffers = udp_buffers,
                .ecn_enabled = ecn_receive,
            },
            .stopping = std.atomic.Value(bool).init(false),
            .drain_requested = std.atomic.Value(bool).init(false),
            .drain_deadline_us = std.atomic.Value(u64).init(0),
            .crypto_provider_state = undefined,
        };
        runtime.crypto_provider_state = tls_core.production_crypto.Provider.init(runtime.crypto_provider_entropy.entropy());
        var retry_key: [quic.path.token_key_len]u8 = undefined;
        compat.randomBytes(&retry_key);
        runtime.secrets.retry_tokens.keys.install(0, &retry_key);
        crypto_pkg.secrets.secureZero(&retry_key);
        compat.randomBytes(&runtime.secrets.stateless_reset_key);
        errdefer runtime.secrets.deinit();
        http3.frame.validateLocallySupportedSettings(runtime.h3_settings) catch return error.InvalidH3Settings;
        runtime.h3_application_compat_len = (http3.early_data.encodeSettingsSnapshot(
            runtime.h3_settings,
            &runtime.h3_application_compat,
        ) catch return error.InvalidH3Settings).len;

        if (cfg.enable_0rtt and !runtime.zero_rtt_enabled) {
            logger.warn(null, "http3: enable_0rtt requires both resumption_runtime and early_data_replay_gate to be configured; continuing with 0-RTT disabled", .{});
        }
        if (cfg.retry_policy == .address_validation) {
            logger.info(null, "http3: QUIC Retry address validation enabled", .{});
        }
        if (!std.mem.eql(u8, cfg.tls_min_version, "1.3") or !std.mem.eql(u8, cfg.tls_max_version, "1.3")) {
            logger.warn(null, "http3: native QUIC requires TLS 1.3; ignoring tls_min_version={s}/tls_max_version={s}", .{ cfg.tls_min_version, cfg.tls_max_version });
        }
        if (cfg.credential_provider == null) {
            logger.warn(null, "http3: no TLS credential provider configured; QUIC bootstrap incomplete.", .{});
        }
        runtime.snapshot_state.server_bootstrapped = runtime.credential_provider != null;
        return runtime;
    }

    pub fn start(self: *Runtime) void {
        if (self.thread != null) return;
        self.thread = std.Thread.spawn(.{}, loopMain, .{self}) catch null;
    }

    pub fn deinit(self: *Runtime) void {
        self.stopping.store(true, .release);
        if (self.thread) |thread| thread.join();
        _ = std.c.close(self.socket_fd);
        self.secrets.deinit();
        self.* = undefined;
    }

    pub fn snapshot(self: *Runtime) Snapshot {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        return self.snapshot_state;
    }

    pub fn beginDrain(self: *Runtime, deadline_us: u64) void {
        if (self.drain_requested.swap(true, .acq_rel)) return;
        self.drain_deadline_us.store(deadline_us, .release);
        self.snapshot_mutex.lock();
        self.snapshot_state.draining = true;
        self.snapshot_mutex.unlock();
        self.logger.info(null, "http3: graceful drain started deadline_us={d}", .{deadline_us});
    }

    pub fn isDrained(self: *Runtime) bool {
        const snap = self.snapshot();
        return snap.tracked_connections == 0;
    }

    fn nowUs() u64 {
        var ts: std.c.timespec = undefined;
        _ = std.c.clock_gettime(.MONOTONIC, &ts);
        return @as(u64, @intCast(ts.sec)) * 1_000_000 + @as(u64, @intCast(ts.nsec)) / 1_000;
    }

    pub fn nowUsPublic() u64 {
        return nowUs();
    }

    fn loopMain(self: *Runtime) void {
        self.serve() catch |err| {
            self.logger.warn(null, "http3: listener loop terminated: {s}", .{@errorName(err)});
        };
    }

    fn serve(self: *Runtime) !void {
        const allocator = self.allocator;
        var connections = std.AutoHashMap(u64, *ConnEntry).init(allocator);
        var routes = quic.cid.CidRoutingTable.init(allocator);
        // Half-open admission accounting, keyed on the source IPv4 address.
        var per_ip = std.AutoHashMap(u32, u32).init(allocator);
        var next_handle: u64 = 1;
        var waiter = SocketWaiter.init(self.socket_fd);
        defer {
            waiter.deinit();
            self.removeAllConnections(&connections, &routes, &per_ip);
            connections.deinit();
            routes.deinit();
            per_ip.deinit();
        }

        while (!self.stopping.load(.acquire)) {
            const now = nowUs();
            const draining = self.drain_requested.load(.acquire);
            const drain_deadline = self.drain_deadline_us.load(.acquire);
            const drain_expired = draining and drain_deadline != 0 and now >= drain_deadline;

            // 1) Timers and transmission for every connection.
            var wake_us: u64 = now + 100_000;
            {
                const Reap = struct {
                    handle: u64,
                    reason: RemovalReason,
                };
                var reap: [16]Reap = undefined;
                var reap_count: usize = 0;
                var it = connections.iterator();
                while (it.next()) |kv| {
                    const entry = kv.value_ptr.*;
                    entry.conn.onTimeout(now);
                    self.syncCidRoutes(entry, &routes);
                    self.maintainLocalCidRoutes(entry, kv.key_ptr.*, &routes);
                    self.foldPathMetrics(entry);
                    if (draining and !entry.drain_goaway_sent) self.sendDrainGoaway(entry);
                    self.drainConnectionTransmits(entry, now);
                    const handshake_timed_out = handshakeTimedOutForRemoval(entry, now);
                    if (drain_expired and !handshake_timed_out) {
                        self.closeForDrainDeadline(entry, now);
                    } else if (!drain_expired) {
                        self.pumpH3(entry, now);
                    }
                    self.drainConnectionTransmits(entry, now);
                    // #256-E: while the socket cannot mark, every live
                    // connection is kept told — not once on the pass that
                    // discovered it. A one-shot flag would miss every entry
                    // this iterator had already walked past when the rejection
                    // happened, and those connections would go on counting
                    // marks for datagrams that left Not-ECT. Idempotent.
                    if (!self.ecn_send_enabled) entry.conn.disableEcnUnsupported();
                    // Reap closed connections and half-open connections that
                    // blew the handshake deadline (spoofed/stalled Initials).
                    if (entry.conn.state() == .closed or handshake_timed_out) {
                        if (reap_count < reap.len) {
                            reap[reap_count] = .{
                                .handle = kv.key_ptr.*,
                                .reason = reapRemovalReason(entry, handshake_timed_out),
                            };
                            reap_count += 1;
                        }
                        continue;
                    }
                    wake_us = connectionWakeUs(entry, now, wake_us);
                }
                for (reap[0..reap_count]) |r| {
                    self.removeConnection(&connections, &routes, &per_ip, r.handle, r.reason);
                }
            }
            if (draining and connections.count() == 0) break;

            // 2) Sleep until the earliest deadline or socket readability.
            waiter.wait(@min(wake_us -| nowUs(), max_loop_wait_us));

            // 3) Ingest every waiting datagram.
            var buf: [quic.datagram.max_size]u8 = undefined;
            var from: std.c.sockaddr.storage = undefined;
            while (true) {
                var from_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.storage);
                const received = receiveDatagram(self.socket_fd, &buf, &from, &from_len);
                const n = received.result;
                if (n < 0) {
                    const e = posix.errno(n);
                    if (e == .AGAIN) break;
                    if (e == .CONNREFUSED or e == .CONNRESET) continue;
                    break;
                }
                if (n == 0) continue;
                const datagram = buf[0..@intCast(n)];
                if (from.family != posix.AF.INET) continue;
                const peer: *const std.c.sockaddr.in = @ptrCast(&from);
                self.ingest(&connections, &routes, &per_ip, &next_handle, datagram, peer.*, received.ecn, nowUs());
            }
        }
    }

    fn ingest(
        self: *Runtime,
        connections: *std.AutoHashMap(u64, *ConnEntry),
        routes: *quic.cid.CidRoutingTable,
        per_ip: *std.AutoHashMap(u32, u32),
        next_handle: *u64,
        datagram: []const u8,
        peer: std.c.sockaddr.in,
        ingress_ecn: quic.udp.Ecn,
        now: u64,
    ) void {
        self.noteDatagram(datagram.len);

        // Route by DCID. Long headers carry the DCID length; short headers
        // need the connection's own CID length, which the client chose per
        // connection — try each active length.
        var handle: ?u64 = null;
        var freshly_accepted = false;
        if (datagram.len > 0 and datagram[0] & 0x80 != 0) {
            if (quic.packet.parsePacket(datagram, 0)) |parsed| {
                handle = routes.lookup(parsed.dcid);
                if (handle == null and parsed.kind == .initial) {
                    handle = self.accept(connections, routes, per_ip, next_handle, parsed, peer, now);
                    freshly_accepted = handle != null;
                }
                if (parsed.kind == .zero_rtt) self.noteZeroRtt();
            } else |_| {
                return;
            }
        } else {
            var it = connections.iterator();
            while (it.next()) |kv| {
                const entry = kv.value_ptr.*;
                if (datagram.len < 1 + entry.cid_len) continue;
                if (routes.lookup(datagram[1..][0..entry.cid_len])) |found| {
                    handle = found;
                    break;
                }
            }
        }
        const found = handle orelse return;
        const entry = connections.get(found) orelse return;

        const was_established = entry.conn.isEstablished();
        // `packets_received` only advances after AEAD open succeeds, so its
        // delta tells us whether this datagram authenticated — without trusting
        // its source address.
        const packets_before = entry.conn.metrics.packets_received;
        // The path this datagram claims to arrive on. Unauthenticated packets
        // never create path state or move the active path (`ingestOnPath`
        // only credits/classifies post-AEAD), so recording it before ingest
        // is safe regardless of whether it turns out spoofed.
        const active_before = entry.conn.activePathKey();
        const ingress_remote = addressFromSockaddrIn(peer);
        const ingress_path = quic.path.PathKey{ .local = self.local_address, .remote = ingress_remote };
        var challenge_entropy: [quic.path.path_challenge_len]u8 = undefined;
        compat.randomBytes(&challenge_entropy);
        entry.conn.ingestOnPathWithEcn(datagram, ingress_path, ingress_ecn, challenge_entropy, now) catch {
            if (freshly_accepted) self.removeConnection(connections, routes, per_ip, found, .protocol_failure);
            return;
        };
        self.syncCidRoutes(entry, routes);
        self.maintainLocalCidRoutes(entry, found, routes);
        self.foldPathMetrics(entry);
        const authenticated = entry.conn.metrics.packets_received > packets_before;
        switch (classifyIngest(freshly_accepted, authenticated, !active_before.remote.eql(ingress_remote))) {
            // A just-accepted connection whose first datagram authenticates
            // nothing is an unsolicited or spoofed Initial: drop the half-open
            // state now instead of holding it until the handshake deadline.
            .drop_unauthenticated => {
                self.removeConnection(connections, routes, per_ip, found, .unauthenticated_initial);
                return;
            },
            // `Connection` owns migration validation; runtime counters fold
            // authoritative validated outcomes from `PathManager` metrics.
            .migrated => {},
            .keep => {},
        }

        if (!was_established and entry.conn.isEstablished()) {
            self.noteHandshakeComplete();
        }
        self.maybeIssueSessionTicket(entry);

        self.drainConnectionTransmits(entry, now);
        self.pumpH3(entry, now);
        self.drainConnectionTransmits(entry, now);
    }

    fn accept(
        self: *Runtime,
        connections: *std.AutoHashMap(u64, *ConnEntry),
        routes: *quic.cid.CidRoutingTable,
        per_ip: *std.AutoHashMap(u32, u32),
        next_handle: *u64,
        parsed: quic.packet.ParsedPacket,
        peer: std.c.sockaddr.in,
        now: u64,
    ) ?u64 {
        if (self.drain_requested.load(.acquire)) return null;
        const credential_provider = self.credential_provider orelse return null;
        if (parsed.dcid.len < 8 or parsed.scid.len == 0) return null;
        const retry_context: ?quic.path.RetryContext = switch (self.classifyRetry(routes, parsed, peer, now)) {
            .accept_unvalidated => null,
            .accept_validated => |ctx| ctx,
            .drop => return null,
        };
        // Bound half-open state before allocating anything for this Initial.
        if (!admissionAllowed(connections.count(), per_ip.get(peer.addr) orelse 0)) return null;
        const allocator = self.allocator;

        const backend = allocator.create(quic.tls_backend.Tls13Backend) catch return null;
        var entropy: quic.tls_backend.Entropy = undefined;
        compat.randomBytes(&entropy.hello_random);
        backend.* = quic.tls_backend.Tls13Backend.initServerWithProvider(entropy, self.cryptoProvider(), credential_provider);
        // #488: install the same process-shared server resolver used by
        // native TCP, before the handshake can start — `Connection.init`
        // below arms the responder.
        if (self.resumption_runtime) |runtime| {
            backend.setResumeCompatibilityPolicy(.{ .transport = .ignore, .application = .ignore }) catch {
                allocator.destroy(backend);
                return null;
            };
            backend.setEarlyDataApplicationCompat(.{
                .format_id = http3.early_data.format_id,
                .format_version = http3.early_data.format_version,
                .bytes = self.h3_application_compat[0..self.h3_application_compat_len],
            }) catch {
                allocator.destroy(backend);
                return null;
            };
            backend.setEarlyDataCompatibilityGate(.{
                .ctx = self,
                .decideFn = h3EarlyDataCompatibility,
            }) catch {
                allocator.destroy(backend);
                return null;
            };
            backend.setResumptionDecisionObserver(runtime.backendDecisionObserver(.quic)) catch {
                allocator.destroy(backend);
                return null;
            };
            if (runtime.serverResolver()) |resolver| {
                backend.setServerPskResolver(resolver) catch {
                    allocator.destroy(backend);
                    return null;
                };
            }
        }
        // #368 Slice 2: independent of `resumption_runtime` above — the
        // same process-scoped replay store shared with every native TCP
        // worker, not a per-connection or per-protocol concern.
        if (self.early_data_replay_gate) |gate| {
            backend.setEarlyDataReplayGate(gate) catch {
                allocator.destroy(backend);
                return null;
            };
            // #523: only actually enable the server's early-data accept path
            // once composition confirmed a resumption runtime, replay gate,
            // and the QUIC carrier are all present (`zeroRttCarrierEnabled`)
            // — mirrors `native_tls_connection.zig`'s identical gate for TCP.
            if (self.zero_rtt_enabled) {
                backend.setServerEarlyDataPolicy(.{ .enabled = true }) catch {
                    allocator.destroy(backend);
                    return null;
                };
            }
        }

        const conn = Connection.init(allocator, .{
            .role = .server,
            .config = self.quic_config,
            .local_cid = parsed.dcid,
            .original_destination_cid = if (retry_context) |ctx| ctx.original_dcid.slice() else parsed.dcid,
            .retry_source_cid = if (retry_context) |ctx| ctx.retry_scid.slice() else null,
            .initial_secret_dcid = if (retry_context) |ctx| ctx.retry_scid.slice() else parsed.dcid,
            .peer_cid = parsed.scid,
            .tls = backend.backend(),
            .crypto_provider = self.cryptoProvider(),
            .now_us = now,
            .initial_path = .{ .local = self.local_address, .remote = addressFromSockaddrIn(peer) },
            .initial_address_validated = retry_context != null,
            .stateless_reset_key = &self.secrets.stateless_reset_key,
            .events = .{},
            .tls_keylog_context = self.tls_keylog_context,
        }) catch {
            allocator.destroy(backend);
            return null;
        };

        const entry = allocator.create(ConnEntry) catch {
            conn.deinit();
            allocator.destroy(backend);
            return null;
        };
        const handle = next_handle.*;
        next_handle.* += 1;
        const h3_sink = if (self.h3_qlog_sink_factory_cb) |factory|
            factory(self.h3_qlog_sink_factory_ctx, handle)
        else
            self.h3_qlog_sink;
        const quic_sink = if (self.quic_qlog_sink_factory_cb) |factory|
            factory(self.quic_qlog_sink_factory_ctx, handle)
        else
            self.quic_qlog_sink;
        var h3 = H3.initWithSettings(allocator, .server, self.h3_settings);
        h3.max_request_body_bytes = self.max_request_body_bytes;
        h3.max_buffered_request_bytes = self.max_buffered_request_bytes;
        entry.* = .{
            .backend = backend,
            .conn = conn,
            .h3 = h3,
            .quic_observer = .{
                .runtime = self,
                .connection_handle = handle,
                .qlog_sink = quic_sink,
                .qlog_artifacts_ctx = self.qlog_artifacts_ctx,
                .qlog_artifact_cb = self.quic_qlog_artifact_cb,
                .qlog_artifact_close_cb = self.qlog_artifact_close_cb,
            },
            .h3_observer = .{
                .runtime = self,
                .connection_handle = handle,
                .qlog_sink = h3_sink,
                .qlog_artifacts_ctx = self.qlog_artifacts_ctx,
                .qlog_artifact_cb = self.h3_qlog_artifact_cb,
            },
            .admission_source_ip = peer.addr,
            .cid_len = parsed.dcid.len,
            .accepted_at_us = now,
        };
        entry.conn.events = .{ .context = &entry.quic_observer, .emitFn = quicConnectionEvent };
        if (h3EventSinkFor(&entry.h3_observer)) |event_sink| {
            entry.h3.setEventSink(event_sink);
        }

        const cid = quic.cid.ConnectionId.init(parsed.dcid) catch {
            entry.deinit(allocator);
            allocator.destroy(entry);
            return null;
        };
        entry.owned_cids[0] = cid;
        entry.owned_cid_count = 1;
        routes.insert(cid, handle) catch {
            entry.deinit(allocator);
            allocator.destroy(entry);
            return null;
        };
        self.noteCidRouteCount(routes.count());
        connections.put(handle, entry) catch {
            routes.remove(cid);
            self.noteCidRouteCount(routes.count());
            entry.deinit(allocator);
            allocator.destroy(entry);
            return null;
        };
        incPerIp(per_ip, peer.addr) catch {
            _ = connections.remove(handle);
            routes.remove(cid);
            self.noteCidRouteCount(routes.count());
            entry.deinit(allocator);
            allocator.destroy(entry);
            return null;
        };
        self.noteConnectionAccepted();
        emitQuicQlog(&entry.quic_observer, now, .{ .connection_started = .{ .dcid_len = @intCast(@min(parsed.dcid.len, std.math.maxInt(u8))) } });
        self.recordQuicConnectionsActive(connections.count());
        if (retry_context != null) self.noteRetryTokenAccepted();
        return handle;
    }

    const RetryAcceptDecision = union(enum) {
        accept_unvalidated,
        accept_validated: quic.path.RetryContext,
        drop,
    };

    fn classifyRetry(
        self: *Runtime,
        routes: *quic.cid.CidRoutingTable,
        parsed: quic.packet.ParsedPacket,
        peer: std.c.sockaddr.in,
        now: u64,
    ) RetryAcceptDecision {
        if (self.retry_policy == .off) {
            return if (parsed.version == quic.packet.quic_v1) .accept_unvalidated else .drop;
        }
        const remote = addressFromSockaddrIn(peer);
        if (parsed.token.len == 0) {
            if (parsed.version != quic.packet.quic_v1) return .drop;
            self.issueRetry(routes, parsed, peer, remote, now);
            return .drop;
        }
        const ctx = self.secrets.retry_tokens.validateRetry(parsed.token, remote, now) catch {
            self.noteInvalidToken();
            return .drop;
        };
        if (parsed.version != quic.packet.quic_v1 or ctx.quic_version != parsed.version or !std.mem.eql(u8, parsed.dcid, ctx.retry_scid.slice())) {
            self.noteInvalidToken();
            return .drop;
        }
        return .{ .accept_validated = ctx };
    }

    fn issueRetry(
        self: *Runtime,
        routes: *quic.cid.CidRoutingTable,
        parsed: quic.packet.ParsedPacket,
        peer: std.c.sockaddr.in,
        remote: quic.udp.Address,
        now: u64,
    ) void {
        const retry_scid = self.generateRetryScid(routes, parsed.dcid.len, parsed.dcid) orelse return;
        var nonce: [quic.path.token_nonce_len]u8 = undefined;
        compat.randomBytes(&nonce);
        var token_buf: [quic.path.max_token_len]u8 = undefined;
        const token = self.secrets.retry_tokens.issueRetry(parsed.dcid, retry_scid.slice(), parsed.version, remote, now, nonce, &token_buf) catch return;
        var retry_buf: [512]u8 = undefined;
        const retry = quic.packet.writeRetryV1(parsed.dcid, parsed.scid, retry_scid.slice(), token, &retry_buf) catch return;
        // Unmarked: a Retry is sent before any connection state exists, so
        // there is no path whose ECN validation could ever account for it.
        if (self.sendDatagram(peer, retry, .not_ect)) {
            self.noteRetryPacketSent();
        }
    }

    fn generateRetryScid(self: *Runtime, routes: *quic.cid.CidRoutingTable, cid_len: usize, original_dcid: []const u8) ?quic.cid.ConnectionId {
        _ = self;
        var entropy: [quic.udp.MaxConnectionIdLen]u8 = undefined;
        for (0..cid_generation_retries) |_| {
            compat.randomBytes(&entropy);
            const candidate = quic.cid.generateCid(&entropy, @intCast(cid_len)) catch return null;
            if (std.mem.eql(u8, candidate.slice(), original_dcid)) continue;
            if (routes.contains(candidate)) continue;
            return candidate;
        }
        return null;
    }

    /// Remove a tracked connection: drop its CID route, release its per-source
    /// admission slot, and free its state. Safe to call with a stale handle.
    fn removeConnection(
        self: *Runtime,
        connections: *std.AutoHashMap(u64, *ConnEntry),
        routes: *quic.cid.CidRoutingTable,
        per_ip: *std.AutoHashMap(u32, u32),
        handle: u64,
        reason: RemovalReason,
    ) void {
        if (connections.fetchRemove(handle)) |kv| {
            self.foldPathMetrics(kv.value);
            if (reason != .administrative and !kv.value.quic_observer.handshake_succeeded and !kv.value.handshake_failure_recorded) {
                kv.value.handshake_failure_recorded = true;
                self.recordQuicHandshakeFailure(kv.value.quic_observer.handshake_stage);
            }
            for (kv.value.owned_cids[0..kv.value.owned_cid_count]) |cid| routes.remove(cid);
            self.noteCidRouteCount(routes.count());
            decPerIp(per_ip, kv.value.admission_source_ip);
            if (kv.value.quic_observer.qlog_artifact_close_cb) |close| {
                if (kv.value.quic_observer.qlog_artifacts_ctx) |artifact_ctx| {
                    close(artifact_ctx, handle);
                }
            }
            kv.value.deinit(self.allocator);
            self.allocator.destroy(kv.value);
            self.noteConnectionClosed();
            self.recordQuicConnectionsActive(connections.count());
        }
    }

    fn removeAllConnections(
        self: *Runtime,
        connections: *std.AutoHashMap(u64, *ConnEntry),
        routes: *quic.cid.CidRoutingTable,
        per_ip: *std.AutoHashMap(u32, u32),
    ) void {
        while (connections.count() != 0) {
            var it = connections.keyIterator();
            const handle = it.next().?.*;
            self.removeConnection(connections, routes, per_ip, handle, .administrative);
        }
    }

    fn closeForDrainDeadline(_: *Runtime, entry: *ConnEntry, now: u64) void {
        switch (entry.conn.state()) {
            .closing, .draining, .closed => {},
            else => {
                entry.quic_observer.administrative_close = true;
                entry.conn.close(0x0100, "h3 drain deadline", now);
            },
        }
    }

    fn handshakeTimedOutForRemoval(entry: *const ConnEntry, now: u64) bool {
        return !entry.quic_observer.administrative_close and
            !entry.quic_observer.handshake_succeeded and
            now -| entry.accepted_at_us > handshake_timeout_us;
    }

    fn reapRemovalReason(entry: *const ConnEntry, handshake_timed_out: bool) RemovalReason {
        if (entry.quic_observer.administrative_close) return .administrative;
        if (handshake_timed_out) return .handshake_timeout;
        return .protocol_failure;
    }

    fn syncCidRoutes(self: *Runtime, entry: *ConnEntry, routes: *quic.cid.CidRoutingTable) void {
        var active: [quic.cid.max_local_active_cids]quic.cid.ConnectionId = undefined;
        const active_count = entry.conn.copyActiveLocalCids(&active);
        var i: usize = 0;
        while (i < entry.owned_cid_count) {
            if (!cidSliceContains(active[0..active_count], entry.owned_cids[i])) {
                routes.remove(entry.owned_cids[i]);
                self.noteCidRouteCount(routes.count());
                entry.owned_cids[i] = entry.owned_cids[entry.owned_cid_count - 1];
                entry.owned_cid_count -= 1;
                continue;
            }
            i += 1;
        }
    }

    fn maintainLocalCidRoutes(self: *Runtime, entry: *ConnEntry, handle: u64, routes: *quic.cid.CidRoutingTable) void {
        while (entry.conn.needsLocalCid() and entry.owned_cid_count < entry.owned_cids.len) {
            var cid_value: ?quic.cid.ConnectionId = null;
            var entropy: [quic.udp.MaxConnectionIdLen]u8 = undefined;
            for (0..cid_generation_retries) |_| {
                compat.randomBytes(&entropy);
                const candidate = quic.cid.generateCid(&entropy, @intCast(entry.cid_len)) catch return;
                if (routes.contains(candidate)) continue;
                cid_value = candidate;
                break;
            }
            const cid = cid_value orelse return;
            switch (registerLocalCidRoute(entry, handle, routes, cid)) {
                .registered => self.noteCidRouteCount(routes.count()),
                .collision => continue,
                .queue_failed => return,
            }
        }
    }

    const RegisterLocalCidRouteResult = enum {
        registered,
        collision,
        queue_failed,
    };

    fn registerLocalCidRoute(entry: *ConnEntry, handle: u64, routes: *quic.cid.CidRoutingTable, cid: quic.cid.ConnectionId) RegisterLocalCidRouteResult {
        routes.insert(cid, handle) catch |err| switch (err) {
            error.CidCollision => return .collision,
            error.OutOfMemory => return .queue_failed,
        };
        entry.conn.advertiseLocalCid(cid) catch {
            routes.remove(cid);
            return .queue_failed;
        };
        entry.owned_cids[entry.owned_cid_count] = cid;
        entry.owned_cid_count += 1;
        return .registered;
    }

    fn pumpH3(self: *Runtime, entry: *ConnEntry, now: u64) void {
        const established = entry.conn.isEstablished();
        // The control stream/SETTINGS flight only ever goes out once
        // established — QUIC packet building itself already refuses to
        // transmit any `.application`-space frame before `self.state_ ==
        // .established` (see `buildPacket`), so this is establishment-only
        // by construction, not just by this early return.
        if (established and !entry.h3_started) {
            entry.h3.start(entry.conn) catch return;
            entry.h3_started = true;
        }
        // #523: accepted 0-RTT STREAM bytes must reach H3 during the
        // early-data window, not sit unread until the handshake completes —
        // otherwise the replay-safe/425 request-safety decision never runs
        // as early data at all. Safe to pump pre-establishment even for an
        // ordinary (non-0-RTT) connection: `acceptStream`/`readStream` are
        // no-ops until something actually populated the stream layer, and
        // any response `serveRequest` queues still can't reach the wire
        // until `.application` packet building unlocks at establishment.
        if (!established and !self.zero_rtt_enabled) return;
        // #546: a peer request stream that arrives at/above `local_goaway_id`
        // is rejected by `entry.h3.pump()` itself, during admission, before
        // it can ever become a `pollRequest()`-visible `IncomingRequest` —
        // the boundary-rejection branch below never sees it. That's a
        // distinct, mutually-exclusive rejection owner from this one, so
        // fold its delta into the same snapshot counter here, unconditionally
        // (a result-first shape, not inside the `catch`) so an unrelated
        // protocol error from this same `pump()` call can't suppress an
        // already-real rejection that happened earlier in the same call.
        const rejected_before = entry.h3.metrics.goaway_request_rejections;
        const pump_result = entry.h3.pump(entry.conn);
        const rejected_after = entry.h3.metrics.goaway_request_rejections;
        self.noteDrainRequestRejections(@intCast(rejected_after - rejected_before));
        pump_result catch |err| {
            // An H3-level protocol error closes the connection with the
            // specific RFC 9114 §8.1 code the session layer recorded.
            const code = entry.h3.closeCode();
            self.logger.warn(null, "http3: session error {s} (close code 0x{x}); closing connection", .{ @errorName(err), code });
            entry.conn.close(code, "h3 protocol error", now);
            return;
        };
        self.resumePendingH3Responses(entry, now);
        self.resumeParkedH3Retries(entry);
        while (true) {
            const incoming = entry.h3.pollRequest() catch {
                entry.conn.close(entry.h3.closeCode(), "h3 request error", now);
                return;
            } orelse break;
            if (self.drain_requested.load(.acquire)) {
                const boundary = entry.drain_goaway_boundary orelse drainBoundaryAfter(entry.highest_admitted_request_stream_id);
                entry.drain_goaway_boundary = boundary;
                if (requestRejectedByDrainBoundary(incoming.stream_id, boundary)) {
                    entry.conn.resetStream(incoming.stream_id, 0x010b) catch {}; // H3_REQUEST_REJECTED
                    entry.h3.finishRequest(incoming.stream_id);
                    self.noteDrainRequestRejections(1);
                    self.noteRequestCompletedWithLatency(now, nowUs());
                    continue;
                }
            }
            self.serveRequest(entry, incoming, now);
        }
    }

    fn sendDrainGoaway(self: *Runtime, entry: *ConnEntry) void {
        if (!entry.conn.isEstablished() or !entry.h3_started) return;
        const boundary = entry.drain_goaway_boundary orelse drainBoundaryAfter(entry.highest_admitted_request_stream_id);
        entry.drain_goaway_boundary = boundary;
        entry.h3.sendGoaway(entry.conn, boundary) catch |err| {
            self.logger.warn(null, "http3: failed to queue GOAWAY during drain: {s}", .{@errorName(err)});
            return;
        };
        entry.drain_goaway_sent = true;
        self.noteDrainGoawaySent();
    }

    fn serveRequest(self: *Runtime, entry: *ConnEntry, incoming: H3.IncomingRequest, now: u64) void {
        entry.highest_admitted_request_stream_id = maxOptional(entry.highest_admitted_request_stream_id, incoming.stream_id);
        entry.conn.setStreamSchedulingHint(incoming.stream_id, .{
            .urgency = incoming.priority.urgency,
            .incremental = incoming.priority.incremental,
        }) catch {};
        const allocator = self.allocator;
        const handler = self.request_handler orelse {
            self.sendStatusResponse(entry, incoming.stream_id, 404, now);
            return;
        };

        var request = buildStreamRequest(allocator, incoming.exchange) catch {
            self.sendInternalErrorResponse(entry, incoming.stream_id, now);
            return;
        };
        defer request.deinit();
        request.client_ip = formatAddressHostAlloc(allocator, entry.conn.activePathKey().remote) catch {
            self.sendInternalErrorResponse(entry, incoming.stream_id, now);
            return;
        };
        request.stream_id = incoming.stream_id;
        request.transport_early = incoming.transport_early;
        request.downstream_handshake_complete = entry.conn.isEstablished();
        request.downstream_handshake = .{
            .ctx = entry.conn,
            .is_complete_fn = h3DownstreamHandshakeComplete,
            .wait_or_drive_fn = h3DownstreamWaitOrDriveHandshake,
        };
        var park_ctx = H3ParkContext{ .runtime = self, .entry = entry, .stream_id = incoming.stream_id, .started_us = now };
        request.park_early_425_retry = .{
            .ctx = &park_ctx,
            .park_fn = parkH3Early425Retry,
        };

        var response = response_mod.Response.init(allocator);
        defer response.deinit();
        handler(allocator, &request, &response, self.request_handler_ctx) catch |err| {
            if (err == error.Http3RequestParked) return;
            self.logger.warn(null, "http3: request handler failed: {s}", .{@errorName(err)});
            self.sendInternalErrorResponse(entry, incoming.stream_id, now);
            return;
        };

        self.sendHandlerResponse(entry, incoming.stream_id, &response, now);
    }

    fn resumeParkedH3Retries(self: *Runtime, entry: *ConnEntry) void {
        self.resumeParkedH3RetriesForEntry(entry);
    }

    fn resumeParkedH3RetriesForEntry(self: *Runtime, entry: anytype) void {
        if (!entry.conn.isEstablished()) return;
        self.resumeEstablishedParkedH3Retries(entry);
    }

    fn resumeEstablishedParkedH3Retries(self: *Runtime, entry: anytype) void {
        while (entry.parked_h3_retries.items.len != 0) {
            var parked = entry.parked_h3_retries.orderedRemove(0);
            defer parked.deinit(self.allocator);

            var response = response_mod.Response.init(self.allocator);
            defer response.deinit();
            parked.continuation.run(self.allocator, &response) catch |err| {
                self.logger.warn(null, "http3: parked request retry failed: {s}", .{@errorName(err)});
                self.sendInternalErrorResponse(entry, parked.stream_id, parked.started_us);
                continue;
            };
            self.sendHandlerResponse(entry, parked.stream_id, &response, parked.started_us);
        }
    }

    fn sendStatusResponse(self: *Runtime, entry: anytype, stream_id: u64, status: u16, started_us: u64) void {
        self.queueH3Response(entry, stream_id, started_us, status, &.{}, "", "terminal");
    }

    fn sendHandlerResponse(self: *Runtime, entry: anytype, stream_id: u64, response: *const response_mod.Response, started_us: u64) void {
        var headers_buf: [64]stream_transport.Header = undefined;
        var header_count: usize = 0;
        for (response.headers.iterator()) |header| {
            if (header_count == headers_buf.len) break;
            headers_buf[header_count] = .{ .name = header.name, .value = header.value };
            header_count += 1;
        }
        self.queueH3Response(
            entry,
            stream_id,
            started_us,
            response.status.code(),
            headers_buf[0..header_count],
            response.body orelse "",
            "response",
        );
    }

    fn sendInternalErrorResponse(self: *Runtime, entry: anytype, stream_id: u64, started_us: u64) void {
        self.queueH3Response(entry, stream_id, started_us, 500, &.{}, "", "fallback");
    }

    fn queueH3Response(
        self: *Runtime,
        entry: anytype,
        stream_id: u64,
        started_us: u64,
        status: u16,
        headers: []const stream_transport.Header,
        body: []const u8,
        label: []const u8,
    ) void {
        var state = H3.ResponseSendState.init(status, headers, body);
        const done = entry.h3.sendResponseProgress(entry.conn, stream_id, &state) catch |err| {
            self.logger.warn(null, "http3: {s} response send failed: {s}", .{ label, @errorName(err) });
            entry.conn.resetStream(stream_id, 0x0102) catch {}; // H3_INTERNAL_ERROR
            entry.h3.finishRequest(stream_id);
            self.noteRequestCompletedWithLatency(started_us, nowUs());
            return;
        };
        if (done) {
            self.noteRequestCompletedWithLatency(started_us, nowUs());
            return;
        }

        var pending = PendingH3Response.init(self.allocator, stream_id, started_us, status, headers, body) catch |err| {
            self.logger.warn(null, "http3: {s} response allocation failed: {s}", .{ label, @errorName(err) });
            entry.conn.resetStream(stream_id, 0x0102) catch {}; // H3_INTERNAL_ERROR
            entry.h3.finishRequest(stream_id);
            self.noteRequestCompletedWithLatency(started_us, nowUs());
            return;
        };
        pending.send_state = state;
        pending.send_state.headers = pending.headers;
        pending.send_state.body = pending.body;

        entry.pending_h3_responses.append(self.allocator, pending) catch |err| {
            self.logger.warn(null, "http3: failed to park {s} response after backpressure: {s}", .{ label, @errorName(err) });
            entry.conn.resetStream(stream_id, 0x0102) catch {}; // H3_INTERNAL_ERROR
            entry.h3.finishRequest(stream_id);
            self.noteRequestCompletedWithLatency(started_us, nowUs());
            pending.deinit(self.allocator);
            return;
        };
    }

    fn resumePendingH3Responses(self: *Runtime, entry: anytype, now: u64) void {
        _ = now;
        var i: usize = 0;
        while (i < entry.pending_h3_responses.items.len) {
            var done = false;
            const stream_id = entry.pending_h3_responses.items[i].stream_id;
            const started_us = entry.pending_h3_responses.items[i].started_us;
            done = entry.h3.sendResponseProgress(
                entry.conn,
                stream_id,
                &entry.pending_h3_responses.items[i].send_state,
            ) catch |err| {
                self.logger.warn(null, "http3: parked response send failed: {s}", .{@errorName(err)});
                entry.conn.resetStream(stream_id, 0x0102) catch {}; // H3_INTERNAL_ERROR
                entry.h3.finishRequest(stream_id);
                self.noteRequestCompletedWithLatency(started_us, nowUs());
                var failed = entry.pending_h3_responses.orderedRemove(i);
                failed.deinit(self.allocator);
                continue;
            };
            if (!done) {
                i += 1;
                continue;
            }
            self.noteRequestCompletedWithLatency(started_us, nowUs());
            var completed = entry.pending_h3_responses.orderedRemove(i);
            completed.deinit(self.allocator);
        }
    }

    /// Fold one connection's deadlines into the loop's sleep deadline.
    ///
    /// Two independent sources, and the pacing one is the reason this exists
    /// (#256-C). A connection the pacer is holding data back for has no timer
    /// to fire — `drainConnectionTransmits` has already stopped producing
    /// datagrams for it, and none of `nextTimeoutUs`'s deadlines knows the
    /// send path is waiting — so without `nextSendTimeUs` here the data would
    /// sit until the next unrelated wakeup or the 100 ms loop floor.
    ///
    /// The converse matters as much: `nextSendTimeUs` is null unless something
    /// is genuinely paced out and is always strictly in the future, so this
    /// neither wakes an idle listener nor lets a busy one spin on a deadline
    /// that has already passed.
    ///
    /// Split out of `serve` so the selection is testable without a socket.
    fn connectionWakeUs(entry: *ConnEntry, now: u64, current: u64) u64 {
        var wake = current;
        if (entry.conn.nextTimeoutUs()) |deadline| wake = @min(wake, deadline);
        if (entry.conn.nextSendTimeUs(now)) |release| wake = @min(wake, release);
        return wake;
    }

    /// Send one transport-produced datagram, carrying the ECN codepoint the
    /// transport asked for (#256-E). `mark` is `.not_ect` for every datagram
    /// on a path that is not marking, which is the plain-`sendto` path.
    /// Drain one connection's pending datagrams.
    ///
    /// Checks the send-side ECN capability after every datagram rather than
    /// once per pass: the refusal is discovered *inside* a send, and the rest
    /// of this drain would otherwise keep building packets the transport counts
    /// as marked while the socket emits them Not-ECT.
    ///
    /// Stops when the transport declines — including when the pacer is what
    /// declines (#256-C). The bounded burst is what keeps this drain from
    /// flushing a whole congestion window in one pass, and the deadline
    /// `connectionWakeUs` folds in is what brings the loop back for the rest.
    fn drainConnectionTransmits(self: *Runtime, entry: *ConnEntry, now: u64) void {
        var out: [quic.datagram.max_size]u8 = undefined;
        while (entry.conn.pollTransmitOnPath(&out, now)) |t| {
            _ = self.sendDatagram(sockaddrInFromAddress(t.path.remote), t.bytes, t.ecn);
            if (!self.ecn_send_enabled) entry.conn.disableEcnUnsupported();
        }
    }

    /// Tell every live connection that the socket cannot mark. Idempotent, and
    /// safe to call on every pass.
    fn applyEcnCapabilityLoss(
        self: *Runtime,
        connections: *std.AutoHashMap(u64, *ConnEntry),
    ) void {
        if (self.ecn_send_enabled) return;
        var it = connections.iterator();
        while (it.next()) |kv| kv.value_ptr.*.conn.disableEcnUnsupported();
    }

    fn sendDatagram(self: *Runtime, peer: std.c.sockaddr.in, datagram: []const u8, mark: quic.udp.Ecn) bool {
        const effective_mark = if (self.ecn_send_enabled) mark else .not_ect;
        const outcome = sendDatagramTo(self.socket_fd, &peer, datagram, effective_mark);
        if (outcome.ecn_rejected) self.noteEcnSendRejected();
        const sent = outcome.result;
        const ok = sent >= 0 and @as(usize, @intCast(sent)) == datagram.len;
        if (ok) {
            self.notePacketOut(datagram.len);
        }
        return ok;
    }

    /// The kernel refused the ECN control message, so this listener can read
    /// the codepoint but not set it (#256-E review).
    ///
    /// Turning off the send shim alone is not enough: `quic_config` is copied
    /// into every accepted `Connection`, so future connections would keep
    /// entering ECN testing, counting marks, and waiting for ACK_ECN for
    /// datagrams that actually left Not-ECT — with the snapshot simultaneously
    /// reporting ECN off. So the capability is withdrawn at the transport
    /// boundary too, and live connections are told explicitly (which is a
    /// different thing from a path failing validation).
    ///
    /// Separated from `sendDatagram` so it is unit-testable without a kernel
    /// that rejects the option.
    fn noteEcnSendRejected(self: *Runtime) void {
        if (!self.ecn_send_enabled) return;
        self.ecn_send_enabled = false;
        self.quic_config.ecn_enabled = false;
        self.snapshot_mutex.lock();
        self.snapshot_state.ecn_enabled = false;
        self.snapshot_mutex.unlock();
        self.logger.warn(null, "http3: kernel refused the ECN send option; continuing without explicit congestion notification", .{});
    }

    fn h3DownstreamHandshakeComplete(ctx: *anyopaque) bool {
        const conn: *Connection = @ptrCast(@alignCast(ctx));
        return conn.isEstablished();
    }

    fn h3DownstreamWaitOrDriveHandshake(ctx: *anyopaque) anyerror!void {
        const conn: *Connection = @ptrCast(@alignCast(ctx));
        conn.driveAuthentication(nowUs());
    }

    const H3ParkContext = struct {
        runtime: *Runtime,
        entry: *ConnEntry,
        stream_id: u64,
        started_us: u64,
    };

    fn parkH3Early425Retry(ctx: *anyopaque, continuation: http3_session.StreamRequest.Early425RetryContinuation) anyerror!void {
        const park_ctx: *H3ParkContext = @ptrCast(@alignCast(ctx));
        try park_ctx.entry.parked_h3_retries.append(park_ctx.runtime.allocator, .{
            .stream_id = park_ctx.stream_id,
            .started_us = park_ctx.started_us,
            .continuation = continuation,
        });
    }

    /// #488: best-effort, exactly-once post-handshake ticket issuance for
    /// this connection. A failure here is swallowed rather than tearing
    /// down an otherwise usable connection — never retried afterward.
    fn maybeIssueSessionTicket(self: *Runtime, entry: *ConnEntry) void {
        if (entry.ticket_issue_attempted) return;
        const runtime = self.resumption_runtime orelse return;
        if (!entry.conn.isEstablished()) return;
        entry.ticket_issue_attempted = true;
        self.issueSessionTicket(entry, runtime) catch |err| {
            runtime.observer.ticketIssue(.quic, runtime.config.mode, switch (err) {
                error.StatefulCapacityRefused => .rejected,
                else => .failed,
            });
            return;
        };
        runtime.observer.ticketIssue(.quic, runtime.config.mode, .success);
    }

    fn issueSessionTicket(self: *Runtime, entry: *ConnEntry, runtime: *tls_core.resumption_runtime.Runtime) !void {
        const allocator = self.allocator;
        const now_unix_ms = runtime.nowUnixMs();

        var ticket_nonce: [8]u8 = undefined;
        try runtime.provider.randomBytes(&ticket_nonce);
        var age_add_bytes: [4]u8 = undefined;
        try runtime.provider.randomBytes(&age_add_bytes);
        const ticket_age_add = std.mem.readInt(u32, &age_add_bytes, .big);

        const limits = runtime.config.session_limits;
        var prepared = try entry.conn.prepareNewSessionTicket(allocator, .{
            .ticket_lifetime = runtime.config.ticket_lifetime_seconds,
            .ticket_age_add = ticket_age_add,
            .ticket_nonce = &ticket_nonce,
            .issued_at_unix_ms = now_unix_ms,
            // RFC 9001 §4.6.1: a QUIC NewSessionTicket that advertises 0-RTT
            // capability carries the fixed sentinel 0xffffffff — QUIC early
            // data isn't bounded by this TLS-record byte cap (that's the
            // job of QUIC flow control and `ServerEarlyDataPolicy`), and
            // the field must be omitted (`null`) entirely when the carrier
            // isn't actually composed, or a client would offer 0-RTT the
            // server can never accept.
            .max_early_data_size = if (self.zero_rtt_enabled) std.math.maxInt(u32) else null,
        }, limits);
        defer prepared.deinit();

        const scratch = try allocator.alloc(u8, runtime.maxIdentityLen());
        defer {
            crypto_pkg.secrets.secureZero(scratch);
            allocator.free(scratch);
        }
        var identity = try runtime.createIdentity(&prepared.state, now_unix_ms, scratch);
        defer identity.deinit();

        entry.conn.emitPreparedNewSessionTicket(&prepared, identity.slice(), limits) catch |err| {
            runtime.rollbackIdentity(&identity);
            return err;
        };
    }

    fn h3EarlyDataCompatibility(ctx: *anyopaque, candidate: tls_core.tls13_backend.EarlyDataCompatibilityCandidate) tls_core.tls13_backend.EarlyDataCompatibilityDecision {
        const self: *Runtime = @ptrCast(@alignCast(ctx));

        // #523: the early-specific gate — deliberately independent of
        // `ResumeCompatibilityPolicy` (`accept()` sets `.transport = .ignore`
        // there so *ordinary* 1-RTT resumption never depends on transport
        // parameters) — is the only owner that may reject *early data
        // specifically* for a remembered QUIC transport snapshot that no
        // longer holds. RFC 9001 §4.6.1: an endpoint that accepts 0-RTT must
        // not have reduced any limit the client's early data would rely on
        // below what was remembered.
        const transport = candidate.remembered_transport orelse {
            self.recordH3EarlyDataCompat(.missing_state);
            return .transport_incompatible;
        };
        if (transport.format_id != quic_transport_parameters_extension_type or
            transport.format_version != quic_transport_parameters_compat_format_version)
        {
            self.recordH3EarlyDataCompat(.transport_incompatible);
            return .transport_incompatible;
        }
        const remembered_transport = quic.tls_backend.decodeTransportParameters(transport.bytes) catch {
            self.recordH3EarlyDataCompat(.transport_incompatible);
            return .transport_incompatible;
        };
        const current_transport = self.quic_config.transportParameters() catch {
            self.recordH3EarlyDataCompat(.transport_incompatible);
            return .transport_incompatible;
        };
        if (!quicEarlyDataTransportCompatible(remembered_transport, current_transport)) {
            self.recordH3EarlyDataCompat(.transport_incompatible);
            return .transport_incompatible;
        }

        const app = candidate.remembered_application orelse {
            self.recordH3EarlyDataCompat(.missing_state);
            return .application_incompatible;
        };

        return switch (http3.early_data.compatibility(.{
            .format_id = app.format_id,
            .format_version = app.format_version,
            .bytes = app.bytes,
        }, self.h3_settings)) {
            .compatible => blk: {
                self.recordH3EarlyDataCompat(.compatible);
                break :blk .compatible;
            },
            .missing_state => blk: {
                self.recordH3EarlyDataCompat(.missing_state);
                break :blk .application_incompatible;
            },
            .malformed_state, .settings_incompatible => blk: {
                self.recordH3EarlyDataCompat(.settings_incompatible);
                break :blk .application_incompatible;
            },
        };
    }

    fn recordH3EarlyDataCompat(self: *Runtime, decision: metrics_mod.H3EarlyDataCompatDecision) void {
        const cb = self.early_data_compat_metrics_cb orelse return;
        const cb_ctx = self.early_data_compat_metrics_ctx orelse return;
        cb(cb_ctx, decision);
    }

    fn recordQuicEarlyDataDecision(self: *Runtime, decision: metrics_mod.QuicEarlyDataDecision) void {
        const cb = self.quic_early_data_decision_metrics_cb orelse return;
        const cb_ctx = self.quic_early_data_decision_metrics_ctx orelse return;
        cb(cb_ctx, decision);
    }

    fn recordQuicZeroRttPacket(self: *Runtime, outcome: metrics_mod.QuicZeroRttPacketOutcome) void {
        const cb = self.quic_zero_rtt_packet_metrics_cb orelse return;
        const cb_ctx = self.quic_zero_rtt_packet_metrics_ctx orelse return;
        cb(cb_ctx, outcome);
    }

    fn recordQuicTransportDelta(self: *Runtime, delta: metrics_mod.QuicTransportDelta) void {
        const cb = self.quic_transport_metrics_cb orelse return;
        const cb_ctx = self.quic_transport_metrics_ctx orelse return;
        cb(cb_ctx, delta);
    }

    fn recordQuicConnectionsActive(self: *Runtime, active: usize) void {
        const cb = self.quic_connections_active_metrics_cb orelse return;
        const cb_ctx = self.quic_connections_active_metrics_ctx orelse return;
        cb(cb_ctx, active);
    }

    fn recordQuicHandshakeFailure(self: *Runtime, stage: metrics_mod.QuicHandshakeFailureStage) void {
        const cb = self.quic_handshake_failure_metrics_cb orelse return;
        const cb_ctx = self.quic_handshake_failure_metrics_ctx orelse return;
        cb(cb_ctx, stage);
    }

    fn recordH3RequestCompleted(self: *Runtime, latency_ms: u64) void {
        const cb = self.h3_request_latency_metrics_cb orelse return;
        const cb_ctx = self.h3_request_latency_metrics_ctx orelse return;
        cb(cb_ctx, latency_ms);
    }

    fn h3ConnectionEvent(ctx: ?*anyopaque, event: http3.conn.Event) void {
        const observer: *ConnEntry.H3Observer = @ptrCast(@alignCast(ctx.?));
        const qlog_event = h3EventToQlog(event) orelse return;
        const record = http3.qlog.Record{ .time_us = nowUs(), .event = qlog_event };
        observer.qlog_sink.emit(record);
        if (observer.qlog_artifact_cb) |emit| {
            if (observer.qlog_artifacts_ctx) |artifact_ctx| {
                emit(artifact_ctx, observer.connection_handle, record);
            }
        }
    }

    fn h3EventSinkFor(observer: *ConnEntry.H3Observer) ?http3.conn.EventSink {
        if (observer.qlog_sink.emit_fn == null and observer.qlog_artifact_cb == null) return null;
        return .{ .context = observer, .emitFn = h3ConnectionEvent };
    }

    fn h3EventToQlog(event: http3.conn.Event) ?http3.qlog.Event {
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

    /// #523: bridges `quic.connection.Event`s from every accepted
    /// connection into the composition root's metrics — without this,
    /// `accept()` would construct connections with no `EventSink` at all
    /// and the typed TLS decision / per-packet 0-RTT outcomes would be
    /// silently discarded. Path lifecycle events are logged with bounded
    /// enum/family context only; no connection IDs, tokens, packet payloads,
    /// or IP addresses are emitted.
    fn quicConnectionEvent(ctx: ?*anyopaque, event: quic.connection.Event) void {
        const observer: *ConnEntry.QuicObserver = @ptrCast(@alignCast(ctx.?));
        const self = observer.runtime;
        if (observer.qlog_sink.isEnabled() or observer.qlog_artifact_cb != null) {
            if (quicEventToQlog(event)) |qlog_event| {
                switch (qlog_event) {
                    .connection_closed => {
                        if (observer.close_logged) return;
                        observer.close_logged = true;
                    },
                    else => {},
                }
                emitQuicQlog(observer, nowUs(), qlog_event);
            }
        }
        switch (event) {
            .state => |state| {
                if (state == .established) observer.handshake_succeeded = true;
            },
            .packet_received => |packet| {
                if (packet.space == .handshake) observer.handshake_stage = .handshake;
            },
            .early_data_decision => |decision| {
                const mapped: metrics_mod.QuicEarlyDataDecision = switch (decision) {
                    .not_attempted => return,
                    .accepted => .accepted,
                    .disabled => .disabled,
                    .ticket_not_capable => .ticket_not_capable,
                    .selected_identity_not_zero => .selected_identity_not_zero,
                    .age_skew => .age_skew,
                    .transport_incompatible => .transport_incompatible,
                    .application_incompatible => .application_incompatible,
                    .replay_rejected => .replay_rejected,
                    .replay_unavailable => .replay_unavailable,
                    .resource_limited => .resource_limited,
                };
                self.recordQuicEarlyDataDecision(mapped);
            },
            .zero_rtt_packet => |packet| {
                const mapped: metrics_mod.QuicZeroRttPacketOutcome = switch (packet.outcome) {
                    .accepted => .accepted,
                    .keys_unavailable => .keys_unavailable,
                    .authentication_failed => .authentication_failed,
                    .duplicate => .duplicate,
                    .malformed => .malformed,
                };
                self.recordQuicZeroRttPacket(mapped);
            },
            .path_validation_started => |path| {
                self.logger.info(null, "http3: QUIC path validation started change={s} family={s}", .{
                    @tagName(path.change),
                    @tagName(path.path.remote.family),
                });
            },
            .path_validation_succeeded => |path| {
                self.logger.info(null, "http3: QUIC path validation succeeded change={s} family={s}", .{
                    @tagName(path.change),
                    @tagName(path.path.remote.family),
                });
            },
            .path_validation_failed => |path| {
                self.logger.info(null, "http3: QUIC path validation failed change={s} family={s}", .{
                    @tagName(path.change),
                    @tagName(path.path.remote.family),
                });
            },
            .path_migration_blocked => |blocked| {
                self.logger.warn(null, "http3: QUIC path migration blocked change={s} reason={s} family={s}", .{
                    @tagName(blocked.change),
                    @tagName(blocked.reason),
                    @tagName(blocked.path.remote.family),
                });
            },
            .path_promoted => |path| {
                self.logger.info(null, "http3: QUIC path promoted change={s} family={s}", .{
                    @tagName(path.change),
                    @tagName(path.path.remote.family),
                });
            },
            else => {},
        }
    }

    fn emitQuicQlog(observer: *ConnEntry.QuicObserver, time_us: u64, event: quic.qlog.Event) void {
        const record = quic.qlog.Record{ .time_us = time_us, .event = event };
        observer.qlog_sink.emit(record);
        if (observer.qlog_artifact_cb) |emit| {
            if (observer.qlog_artifacts_ctx) |artifact_ctx| {
                emit(artifact_ctx, observer.connection_handle, record);
            }
        }
    }

    fn quicEventToQlog(event: quic.connection.Event) ?quic.qlog.Event {
        return switch (event) {
            .state => |state| switch (state) {
                .handshaking, .established, .closing, .draining, .closed => null,
            },
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
                .close_error = if (close.is_application)
                    .{ .application_unknown = close.error_code }
                else
                    .{ .connection_unknown = close.error_code },
            } },
            .close_sent => null,
            .close_received => |close| .{ .connection_closed = .{
                .trigger = if (close.is_application) .application else .@"error",
                .close_error = if (close.is_application)
                    .{ .application_unknown = close.error_code }
                else
                    .{ .connection_unknown = close.error_code },
            } },
            .idle_timeout => .{ .connection_closed = .{ .trigger = .idle_timeout } },
            .path_validation_started => .{ .path_validation = .{ .kind = .challenge_sent } },
            .path_validation_succeeded => .{ .path_validation = .{ .kind = .validated } },
            .path_validation_failed => .{ .path_validation = .{ .kind = .failed } },
            .path_promoted => |path| .{ .connection_migrated = .{ .new = switch (path.change) {
                .nat_rebinding => .probing_successful,
                .migration => .migration_complete,
            } } },
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
            .path_migration_blocked, .pmtu_updated => null,
            .keys_discarded, .zero_rtt_packet, .early_data_decision, .ecn_state_changed => null,
        };
    }

    fn flowControlStateToQlog(state: quic.connection.FlowControlState) quic.qlog.BlockedState {
        return switch (state) {
            .blocked => .blocked,
            .unblocked => .unblocked,
        };
    }

    fn streamSideToQlog(side: quic.connection.StreamSide) quic.qlog.StreamSide {
        return switch (side) {
            .sending => .sending,
            .receiving => .receiving,
        };
    }

    fn streamStateToQlog(state: quic.connection.StreamSideState) quic.qlog.StreamState {
        return switch (state) {
            .open => .open,
            .closed => .closed,
        };
    }

    fn streamStateTriggerToQlog(trigger: quic.connection.StreamStateTrigger) quic.qlog.StreamStateTrigger {
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

    fn congestionStateToQlog(state: quic.connection.CongestionState) quic.qlog.CongestionState {
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

    fn dropReasonToQlog(reason: quic.connection.DropReason) quic.qlog.DropTrigger {
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

    fn noteConnectionAccepted(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.native_connections += 1;
        self.snapshot_state.tracked_connections += 1;
    }

    fn noteConnectionClosed(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.native_connections -|= 1;
        self.snapshot_state.tracked_connections -|= 1;
        if (self.snapshot_state.tracked_connections == 0) self.snapshot_state.draining = false;
    }

    fn noteCidRouteCount(self: *Runtime, count: usize) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.active_cid_routes = count;
    }

    fn noteDrainGoawaySent(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.h3_goaway_sent += 1;
    }

    fn noteDrainRequestRejections(self: *Runtime, count: usize) void {
        if (count == 0) return;
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.h3_drain_request_rejections += count;
    }

    fn noteHandshakeComplete(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.handshakes_completed += 1;
    }

    fn noteRequestCompletedWithLatency(self: *Runtime, started_us: u64, finished_us: u64) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.requests_completed += 1;
        self.recordH3RequestCompleted((finished_us -| started_us) / std.time.us_per_ms);
    }

    fn foldPathMetrics(self: *Runtime, entry: *ConnEntry) void {
        const current = entry.conn.pathMetrics();
        const previous = entry.last_path_metrics;
        entry.last_path_metrics = current;

        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        const nat = current.nat_rebindings -| previous.nat_rebindings;
        const migrations = current.migrations -| previous.migrations;
        self.snapshot_state.path_challenges_sent += @intCast(current.path_challenges_sent -| previous.path_challenges_sent);
        self.snapshot_state.path_validations_succeeded += @intCast(current.path_validations_succeeded -| previous.path_validations_succeeded);
        self.snapshot_state.path_validations_failed += @intCast(current.path_validations_failed -| previous.path_validations_failed);
        self.snapshot_state.path_response_mismatches += @intCast(current.path_response_mismatches -| previous.path_response_mismatches);
        self.snapshot_state.nat_rebindings += @intCast(nat);
        self.snapshot_state.migrations += @intCast(migrations);
        self.snapshot_state.migrations_blocked += @intCast(current.migrations_blocked -| previous.migrations_blocked);
        self.snapshot_state.migrations_blocked_no_peer_cid += @intCast(current.migrations_blocked_no_peer_cid -| previous.migrations_blocked_no_peer_cid);
        self.snapshot_state.migration_events += @intCast(nat +| migrations);

        // #256-E: ECN is transport state, but the interesting question is a
        // listener-wide one — is marking working here at all — so the
        // per-connection counters fold into the same snapshot.
        const transport = entry.conn.metrics;
        const last = entry.last_transport_metrics;
        entry.last_transport_metrics = transport;
        self.snapshot_state.ecn_marked_sent += @intCast(transport.ecn_marked_sent -| last.ecn_marked_sent);
        self.snapshot_state.ecn_paths_validated += @intCast(transport.ecn_validated -| last.ecn_validated);
        self.snapshot_state.ecn_paths_disabled += @intCast(transport.ecn_disabled -| last.ecn_disabled);
        self.snapshot_state.ecn_ce_received += @intCast(transport.ecn_ce_received -| last.ecn_ce_received);

        // #256-G: packet counts and DPLPMTUD probe/black-hole counts, folded
        // the same way as the ECN counters above.
        self.snapshot_state.packets_sent += @intCast(transport.packets_sent -| last.packets_sent);
        self.snapshot_state.packets_received += @intCast(transport.packets_received -| last.packets_received);
        self.snapshot_state.pmtu_probes_sent += @intCast(transport.pmtu_probes_sent -| last.pmtu_probes_sent);
        self.snapshot_state.pmtu_black_holes += @intCast(transport.pmtu_black_holes -| last.pmtu_black_holes);

        const active_plpmtu = entry.conn.paths.activePlpmtu().sendSize();
        self.snapshot_state.plpmtu_last_bytes = active_plpmtu;
        if (self.snapshot_state.plpmtu_lifetime_min_bytes == 0 or active_plpmtu < self.snapshot_state.plpmtu_lifetime_min_bytes) {
            self.snapshot_state.plpmtu_lifetime_min_bytes = active_plpmtu;
        }
        if (active_plpmtu > self.snapshot_state.plpmtu_lifetime_max_bytes) {
            self.snapshot_state.plpmtu_lifetime_max_bytes = active_plpmtu;
        }

        const stream_metrics = if (entry.conn.streams) |streams| streams.metrics else quic.stream.Metrics{};
        const last_stream = entry.last_stream_metrics;
        entry.last_stream_metrics = stream_metrics;
        const tls_metrics = entry.conn.adapter.metrics;
        const last_tls = entry.last_tls_metrics;
        entry.last_tls_metrics = tls_metrics;
        self.recordQuicTransportDelta(.{
            .amplification_blocked = current.amplification_blocked_sends -| previous.amplification_blocked_sends,
            .pto = transport.pto_count_total -| last.pto_count_total,
            .packets_lost = transport.packets_lost -| last.packets_lost,
            .stream_resets = stream_metrics.reset_streams -| last_stream.reset_streams,
            .connection_flow_blocked = stream_metrics.data_blocked_events -| last_stream.data_blocked_events,
            .stream_flow_blocked = stream_metrics.stream_data_blocked_events -| last_stream.stream_data_blocked_events,
            .deprotection_failures = tls_metrics.deprotection_failures -| last_tls.deprotection_failures,
        });
    }

    fn noteRetryPacketSent(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.retry_packets_sent += 1;
        self.recordQuicTransportDelta(.{ .retry = 1 });
    }

    fn noteRetryTokenAccepted(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.retry_tokens_accepted += 1;
    }

    fn noteInvalidToken(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.invalid_tokens += 1;
    }

    fn noteDatagram(self: *Runtime, len: usize) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.datagrams_seen += 1;
        self.snapshot_state.bytes_seen += len;
        self.recordQuicTransportDelta(.{ .bytes_received = @intCast(len) });
    }

    fn noteZeroRtt(self: *Runtime) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.zero_rtt_packets_seen += 1;
    }

    fn notePacketOut(self: *Runtime, len: usize) void {
        self.snapshot_mutex.lock();
        defer self.snapshot_mutex.unlock();
        self.snapshot_state.packets_emitted += 1;
        self.snapshot_state.bytes_emitted += len;
        self.recordQuicTransportDelta(.{ .bytes_sent = @intCast(len) });
    }
};

/// Convert the protocol-neutral `stream_transport.Exchange` into the
/// gateway-facing `StreamRequest`, preserving the `:path` query string and
/// mapping `:authority` to a Host header when absent.
fn buildStreamRequest(allocator: std.mem.Allocator, exchange: stream_transport.Exchange) !http3_session.StreamRequest {
    var assembler = http3_session.StreamAssembler.init(allocator);
    defer assembler.deinit();

    var fields: [131]http3_session.HeaderField = undefined;
    fields[0] = .{ .name = ":method", .value = exchange.request.method };
    fields[1] = .{ .name = ":path", .value = exchange.request.path };
    fields[2] = .{ .name = ":authority", .value = exchange.request.authority };
    var count: usize = 3;
    for (exchange.request.headers) |header| {
        if (count == fields.len) return error.TooManyHeaders;
        fields[count] = .{ .name = header.name, .value = header.value };
        count += 1;
    }
    try assembler.appendHeaderBlock(fields[0..count]);
    switch (exchange.body) {
        .buffered => |body| try assembler.appendBody(body),
        else => {},
    }
    return assembler.finish();
}

fn formatAddressHostAlloc(allocator: std.mem.Allocator, address: quic.udp.Address) ![]u8 {
    return switch (address.family) {
        .ip4 => std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
            address.bytes[0], address.bytes[1], address.bytes[2], address.bytes[3],
        }),
        .ip6 => std.fmt.allocPrint(allocator, "{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}", .{
            std.mem.readInt(u16, address.bytes[0..2], .big),
            std.mem.readInt(u16, address.bytes[2..4], .big),
            std.mem.readInt(u16, address.bytes[4..6], .big),
            std.mem.readInt(u16, address.bytes[6..8], .big),
            std.mem.readInt(u16, address.bytes[8..10], .big),
            std.mem.readInt(u16, address.bytes[10..12], .big),
            std.mem.readInt(u16, address.bytes[12..14], .big),
            std.mem.readInt(u16, address.bytes[14..16], .big),
        }),
    };
}

/// Map the operator-facing runtime config onto the native QUIC transport
/// config.
/// `no_fragment` is whether the listener's socket actually established the
/// no-IP-fragmentation contract DPLPMTUD requires (RFC 8899 §3). Without it
/// the discovery ceiling collapses to the RFC 9000 §14 floor regardless of
/// what the operator configured: a probe that the kernel may fragment cannot
/// measure a path MTU, and raising the send size on that evidence would be
/// worse than never discovering anything.
fn quicConfigFrom(cfg: Config, no_fragment: bool, ecn: bool) quic.config.Config {
    const configured = std.math.clamp(cfg.max_datagram_size, quic.datagram.base_size, quic.datagram.max_size);
    return .{
        .max_send_udp_payload_size = if (no_fragment) configured else quic.datagram.base_size,
        // Only the socket owner can answer this, which is why the transport
        // default is off: `quic/config.zig` has no way to know whether the
        // codepoint can be set or read (#256-E).
        .ecn_enabled = ecn,
        .zero_rtt_enabled = zeroRttCarrierEnabled(cfg),
        .retry_policy = cfg.retry_policy,
        .migration_policy = if (cfg.connection_migration) .full else .nat_rebinding_only,
    };
}

/// #523: the QUIC 0-RTT carrier may only be enabled once every dependency it
/// relies on is actually present — `enable_0rtt` alone must never install a
/// usable early-data path. Without a resumption runtime there is no PSK
/// resolver to select a session, and without the replay gate the backend's
/// default gate fails closed (`.unavailable`) for every attempt anyway, so
/// gating here keeps that fail-closed behavior visible instead of quietly
/// letting every 0-RTT attempt dead-end downstream.
/// TLS extension type carrying the QUIC transport-parameters extension —
/// matches what `quic.tls_backend` stamps as the remembered/current
/// transport-compat snapshot's `format_id`, without needing that internal
/// constant exported.
const quic_transport_parameters_extension_type: u16 = @intFromEnum(tls_core.algorithms.ExtensionType.quic_transport_parameters);

/// The snapshot format version `quic.tls_backend.localTransportCompat` /
/// `peerTransportCompat` stamp on every remembered-transport `CompatView`
/// (hardcoded `1` there) — validated here before decoding so a
/// version-mismatched snapshot from a future encoding change fails closed
/// as `.transport_incompatible` rather than being decoded under the wrong
/// assumptions.
const quic_transport_parameters_compat_format_version: u16 = 1;

/// RFC 9000 §7.4.1 / RFC 9001 §4.6.1's no-reduction set: a 0-RTT attempt is
/// only transport-compatible if none of the limits it depends on — or that
/// the client otherwise remembers as a standing guarantee from the prior
/// connection — have been reduced since the ticket was issued.
/// `initial_max_stream_data_bidi_local` and `active_connection_id_limit`
/// are included even though they don't gate the early-data window itself
/// (server never sends 0-RTT, and CIDs aren't consumed by 0-RTT admission):
/// RFC 9000 §7.4.1 requires the full remembered parameter set to hold, not
/// just the ones 0-RTT immediately exercises.
fn quicEarlyDataTransportCompatible(remembered: quic.config.TransportParameters, current: quic.config.TransportParameters) bool {
    return current.initial_max_data >= remembered.initial_max_data and
        current.initial_max_stream_data_bidi_local >= remembered.initial_max_stream_data_bidi_local and
        current.initial_max_stream_data_bidi_remote >= remembered.initial_max_stream_data_bidi_remote and
        current.initial_max_stream_data_uni >= remembered.initial_max_stream_data_uni and
        current.initial_max_streams_bidi >= remembered.initial_max_streams_bidi and
        current.initial_max_streams_uni >= remembered.initial_max_streams_uni and
        current.active_connection_id_limit >= remembered.active_connection_id_limit;
}

fn zeroRttCarrierEnabled(cfg: Config) bool {
    if (!cfg.enable_0rtt) return false;
    // A non-null dependency isn't necessarily a *usable* one: a resumption
    // runtime constructed with `.mode = .disabled` still exists but yields
    // no PSK resolver, and a default-constructed `EarlyDataReplayGate`
    // (`decideFn == null`) exists but fails closed on every attempt. Either
    // would leave `accept()` composing a carrier that can never actually
    // accept 0-RTT — check the thing that matters, not just presence.
    const runtime = cfg.resumption_runtime orelse return false;
    if (runtime.serverResolver() == null) return false;
    const gate = cfg.early_data_replay_gate orelse return false;
    if (gate.decideFn == null) return false;
    return true;
}

/// Convert a source/destination IPv4 `sockaddr_in` into the protocol-neutral
/// `quic.udp.Address` used for `PathKey` construction. `sin_addr`/`sin_port`
/// are already network-byte-order, so the address octets bit-cast directly
/// (a host-endian read would byte-swap them on little-endian) and only the
/// port needs an explicit big-to-native swap.
fn addressFromSockaddrIn(sa: std.c.sockaddr.in) quic.udp.Address {
    const octets: [4]u8 = @bitCast(sa.addr);
    return quic.udp.Address.ip4(octets, std.mem.bigToNative(u16, sa.port));
}

/// The inverse of `addressFromSockaddrIn`, for sending a `Transmit`'s
/// destination back out over the IPv4 UDP socket.
fn sockaddrInFromAddress(addr: quic.udp.Address) std.c.sockaddr.in {
    var octets: [4]u8 = undefined;
    @memcpy(&octets, addr.slice());
    return .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, addr.port),
        .addr = @bitCast(octets),
        .zero = [_]u8{0} ** 8,
    };
}

/// Whether a new half-open connection may be admitted given the current global
/// and per-source connection counts. Bounds the state an off-path spoofer can
/// pin with forged Initials (the native stack sends no Retry).
fn admissionAllowed(total: usize, per_source: u32) bool {
    return total < max_connections and per_source < max_connections_per_source;
}

fn maxOptional(current: ?u64, candidate: u64) u64 {
    return if (current) |value| @max(value, candidate) else candidate;
}

fn drainBoundaryAfter(highest_admitted_request_stream_id: ?u64) u64 {
    const highest = highest_admitted_request_stream_id orelse return 0;
    return highest +| 4;
}

fn requestRejectedByDrainBoundary(stream_id: u64, boundary: u64) bool {
    return stream_id >= boundary;
}

/// What to do with a tracked connection after ingesting a datagram, decided
/// purely from whether the datagram authenticated (the post-AEAD
/// `packets_received` delta), whether the connection was just accepted for this
/// datagram, and whether the source address differs from the connection's.
const IngestOutcome = enum {
    /// Process normally (transmit, pump H3).
    keep,
    /// A freshly accepted connection whose first datagram authenticated
    /// nothing — an unsolicited or spoofed Initial. Tear it down.
    drop_unauthenticated,
    /// An authenticated packet arrived from a new source. Record the migration
    /// event; the runtime does not follow it.
    migrated,
};

fn classifyIngest(freshly_accepted: bool, authenticated: bool, source_changed: bool) IngestOutcome {
    if (freshly_accepted and !authenticated) return .drop_unauthenticated;
    if (authenticated and !freshly_accepted and source_changed) return .migrated;
    return .keep;
}

fn incPerIp(per_ip: *std.AutoHashMap(u32, u32), addr: u32) !void {
    const gop = try per_ip.getOrPut(addr);
    if (!gop.found_existing) gop.value_ptr.* = 0;
    gop.value_ptr.* += 1;
}

fn decPerIp(per_ip: *std.AutoHashMap(u32, u32), addr: u32) void {
    if (per_ip.getPtr(addr)) |count| {
        count.* -= 1;
        if (count.* == 0) _ = per_ip.remove(addr);
    }
}

fn cidSliceContains(cids: []const quic.cid.ConnectionId, needle: quic.cid.ConnectionId) bool {
    for (cids) |cid| {
        if (std.mem.eql(u8, cid.slice(), needle.slice())) return true;
    }
    return false;
}

/// The IPv4/IPv6 socket options that disable source fragmentation on this
/// platform, or null where no such API has been verified.
///
/// These are *not* portable across the BSDs and must not be grouped: Apple's
/// `<netinet/in.h>` defines IPv4 `IP_DONTFRAG` as 28, FreeBSD's defines it as
/// 67, and OpenBSD uses option 28 for `IP_IPSEC_REMOTE_AUTH` entirely. Since
/// this helper's return value is the gate that unlocks discovery above 1200, a
/// wrong constant that some kernel happens to *accept* would report success
/// without ever setting DF — the exact false-positive the gate exists to
/// prevent. An unverified platform therefore returns null and stays on the
/// conservative 1200-byte policy rather than guessing.
const NoFragmentOptions = struct {
    level_v4: u32,
    option_v4: u32,
    level_v6: u32,
    option_v6: u32,
    /// Linux's `IP_PMTUDISC_PROBE` is a mode value; the DF-only platforms set
    /// a boolean instead.
    value: c_int,
};

const no_fragment_options: ?NoFragmentOptions = switch (builtin.os.tag) {
    // `IP_PMTUDISC_PROBE` sets DF *and* ignores the kernel's cached path MTU,
    // which RFC 8899 §4.5 requires so DPLPMTUD is the thing in control.
    .linux => .{
        .level_v4 = posix.IPPROTO.IP,
        .option_v4 = std.os.linux.IP.MTU_DISCOVER,
        .level_v6 = posix.IPPROTO.IPV6,
        .option_v6 = std.os.linux.IPV6.MTU_DISCOVER,
        .value = std.os.linux.IP.PMTUDISC_PROBE,
    },
    // Darwin: IP_DONTFRAG (28) / IPV6_DONTFRAG (62) from <netinet/in.h> and
    // <netinet6/in6.h>; not exposed by Zig's darwin bindings. DF only — there
    // is no probe mode, so a kernel-cached PMTU can still bound a probe. That
    // costs discovery reach, never soundness: a probe the kernel refuses to
    // send simply fails, and a failed probe never validates a size.
    .macos, .ios, .tvos, .watchos => .{
        .level_v4 = posix.IPPROTO.IP,
        .option_v4 = 28,
        .level_v6 = posix.IPPROTO.IPV6,
        .option_v6 = 62,
        .value = 1,
    },
    // FreeBSD: IP_DONTFRAG is 67 there, *not* Darwin's 28.
    .freebsd => .{
        .level_v4 = posix.IPPROTO.IP,
        .option_v4 = 67,
        .level_v6 = posix.IPPROTO.IPV6,
        .option_v6 = 62,
        .value = 1,
    },
    // NetBSD/OpenBSD/DragonFly expose no IPv4 no-fragment option this code has
    // verified, so they take the conservative path rather than a guess.
    else => null,
};

/// Whether this platform has a verified no-source-fragmentation API at all.
/// Discovery above the RFC 9000 §14 floor is gated on it.
const no_fragment_supported = no_fragment_options != null;

/// RFC 8899 §3 / RFC 9000 §14: a DPLPMTUD probe only measures a path MTU if
/// the IP layer puts it on the wire as one *unfragmented* datagram. Where the
/// kernel is free to source-fragment, an acknowledged 2048-byte probe proves
/// the peer reassembled two fragments — not that the path carries 2048 bytes —
/// and discovery would happily raise the send size on that false evidence.
/// RFC 9000 §14 independently forbids fragmenting QUIC datagrams at all.
///
/// So the no-fragmentation contract is a *precondition* for discovering
/// anything above the floor, not a tuning detail. This returns whether the
/// kernel accepted one; `Runtime.init` holds discovery at 1200 when it did
/// not, which is the conservative policy #256's acceptance criteria allow as
/// the alternative to DPLPMTUD.
fn configureNoFragment(fd: std.c.fd_t, sa_family: u32) bool {
    const options = no_fragment_options orelse return false;
    const is_v6 = sa_family == posix.AF.INET6;
    const level = if (is_v6) options.level_v6 else options.level_v4;
    const option = if (is_v6) options.option_v6 else options.option_v4;
    const value = options.value;
    posix.setsockopt(fd, @intCast(level), @intCast(option), std.mem.asBytes(&value)) catch return false;
    return true;
}

// ---------------------------------------------------------------------------
// ECN socket support (#256-E).
//
// The transport decides *whether* to mark and what a peer's feedback means
// (`quic/ecn.zig`); everything here is the platform half it cannot own —
// asking the kernel to put ECT(0) in the IP header of one specific datagram,
// and reading the field back off a received one. Both need ancillary control
// messages, which is why they are `sendmsg`/`recvmsg` rather than socket-wide
// options: ECN is validated per path, and a socket-wide `IP_TOS` would mark
// every connection on the listener alike with no way to stop marking on the
// one path whose validation failed.
// ---------------------------------------------------------------------------

/// The IP header option numbers this ECN implementation uses, per platform.
///
/// Named per OS rather than guessed, for the same reason `no_fragment_options`
/// is: the numeric values differ between Linux, Darwin, and the BSDs, and a
/// wrong constant that some kernel happens to accept would read as a working
/// ECN path while marking nothing. An unverified platform gets `null` and the
/// listener runs without ECN, which is a supported, tested state.
const EcnSocketOptions = struct {
    /// `setsockopt` that turns on delivery of the received codepoint.
    recv_enable_v4: u32,
    recv_enable_v6: u32,
    /// The `cmsg_type` a received codepoint arrives under, which is not always
    /// the same number as the option that enabled it.
    recv_cmsg_v4: u32,
    recv_cmsg_v6: u32,
    /// The `cmsg_type` used to set the field on one outbound datagram.
    send_cmsg_v4: u32,
    send_cmsg_v6: u32,
};

const ecn_socket_options: ?EcnSocketOptions = switch (builtin.os.tag) {
    // Linux: IP_TOS=1, IP_RECVTOS=13, IPV6_TCLASS=67, IPV6_RECVTCLASS=66
    // (<linux/in.h>, <linux/in6.h>). Received IPv4 codepoints arrive under
    // IP_TOS, *not* under the IP_RECVTOS that enabled them.
    .linux => .{
        .recv_enable_v4 = 13,
        .recv_enable_v6 = 66,
        .recv_cmsg_v4 = 1,
        .recv_cmsg_v6 = 67,
        .send_cmsg_v4 = 1,
        .send_cmsg_v6 = 67,
    },
    // Darwin: IP_TOS=3, IP_RECVTOS=27 (<netinet/in.h>), IPV6_TCLASS=36,
    // IPV6_RECVTCLASS=35 (<netinet6/in6.h>). Here the received IPv4 codepoint
    // *does* arrive under IP_RECVTOS.
    .macos, .ios, .tvos, .watchos => .{
        .recv_enable_v4 = 27,
        .recv_enable_v6 = 35,
        .recv_cmsg_v4 = 27,
        .recv_cmsg_v6 = 36,
        .send_cmsg_v4 = 3,
        .send_cmsg_v6 = 36,
    },
    // FreeBSD: IP_TOS=3, IP_RECVTOS=68, IPV6_TCLASS=61, IPV6_RECVTCLASS=57.
    .freebsd => .{
        .recv_enable_v4 = 68,
        .recv_enable_v6 = 57,
        .recv_cmsg_v4 = 68,
        .recv_cmsg_v6 = 61,
        .send_cmsg_v4 = 3,
        .send_cmsg_v6 = 61,
    },
    else => null,
};

const ecn_supported = ecn_socket_options != null;

/// RFC 3168 §5: the ECN field is the low two bits of the IPv4 TOS byte / IPv6
/// traffic class. The other six are DSCP and are none of this stack's
/// business — reading them would turn an operator's traffic-class marking into
/// a spurious congestion signal.
fn ecnFromTrafficClass(byte: u8) quic.udp.Ecn {
    return switch (byte & 0x03) {
        0b00 => .not_ect,
        0b01 => .ect1,
        0b10 => .ect0,
        0b11 => .ce,
        else => unreachable,
    };
}

fn trafficClassFromEcn(mark: quic.udp.Ecn) ?c_int {
    return switch (mark) {
        .not_ect => 0b00,
        .ect1 => 0b01,
        .ect0 => 0b10,
        .ce => 0b11,
        // "The receive path could not tell" is not a codepoint to send.
        .unavailable => null,
    };
}

/// `CMSG_ALIGN`'s alignment, which is *not* the platform word everywhere.
///
/// Linux aligns to `sizeof(size_t)`; Darwin's `CMSG_DATA`/`CMSG_SPACE` use
/// `__DARWIN_ALIGN32`, i.e. `sizeof(uint32_t)`, so on 64-bit Darwin the payload
/// begins 12 bytes into a control message rather than 16. Assuming the word
/// size on both is not a subtle bug: the ECN payload would be read four bytes
/// past where the kernel wrote it, every received codepoint would come back
/// `.unavailable`, and ECN would look like a network problem on every macOS
/// host. The BSDs align to `register_t`, which is the word.
const cmsg_alignment: usize = switch (builtin.os.tag) {
    .macos, .ios, .tvos, .watchos => @alignOf(u32),
    else => @alignOf(usize),
};

fn cmsgAlign(len: usize) usize {
    return (len + cmsg_alignment - 1) & ~(cmsg_alignment - 1);
}

/// `CMSG_DATA`'s offset from the header: the header size, aligned up.
const cmsg_data_offset: usize = cmsgAlign(@sizeOf(std.c.cmsghdr));

fn cmsgSpace(payload_len: usize) usize {
    return cmsg_data_offset + cmsgAlign(payload_len);
}

fn cmsgLen(payload_len: usize) usize {
    return cmsg_data_offset + payload_len;
}

/// Room for one control message carrying a `c_int` — the only ancillary data
/// this listener sends or expects. A kernel with more to say sets `MSG_CTRUNC`
/// and the extra is simply not read.
const ecn_control_len: usize = cmsgSpace(@sizeOf(c_int));

/// Ask the kernel to report the received ECN codepoint on this socket
/// (#256-E). Advisory: a refusal leaves a listener that serves QUIC normally
/// and simply never reports a codepoint, which the transport reads as
/// `.unavailable` rather than as an unmarked datagram.
fn configureEcnReceive(fd: std.c.fd_t, sa_family: u32) bool {
    const options = ecn_socket_options orelse return false;
    const is_v6 = sa_family == posix.AF.INET6;
    const option = if (is_v6) options.recv_enable_v6 else options.recv_enable_v4;
    const value: c_int = 1;
    posix.setsockopt(fd, if (is_v6) posix.IPPROTO.IPV6 else posix.IPPROTO.IP, @intCast(option), std.mem.asBytes(&value)) catch return false;
    return true;
}

/// One received datagram: the `recvmsg` return value verbatim (negative on
/// error, so the caller's errno handling is unchanged) and the ECN codepoint
/// its IP header carried.
const ReceivedDatagram = struct {
    result: isize,
    ecn: quic.udp.Ecn = .unavailable,
};

/// Receive one datagram with its ancillary metadata. `recvmsg` rather than
/// `recvfrom` because the codepoint only arrives as a control message; the
/// source address comes back identically either way.
fn receiveDatagram(
    fd: std.c.fd_t,
    buf: []u8,
    from: *std.c.sockaddr.storage,
    from_len: *std.c.socklen_t,
) ReceivedDatagram {
    var control: [ecn_control_len]u8 align(@alignOf(usize)) = undefined;
    var iov = [_]std.c.iovec{.{ .base = buf.ptr, .len = buf.len }};
    var msg = std.mem.zeroes(std.c.msghdr);
    msg.name = @ptrCast(from);
    msg.namelen = from_len.*;
    msg.iov = &iov;
    msg.iovlen = 1;
    msg.control = &control;
    msg.controllen = @intCast(control.len);

    const n = std.c.recvmsg(fd, &msg, 0);
    if (n < 0) return .{ .result = n };
    from_len.* = msg.namelen;
    return .{
        .result = n,
        .ecn = ecnFromControl(&control, @intCast(msg.controllen), from.family),
    };
}

/// Send one datagram, asking the kernel to put `mark` in its IP header when
/// the transport called for one (#256-E). Returns the `sendmsg`/`sendto`
/// result and whether the ECN control message was refused, which is the
/// listener's cue to stop attempting it.
const SentDatagram = struct {
    result: isize,
    /// True when this send carried an ECN control message and the kernel
    /// rejected the call outright. Distinguished from an ordinary send failure
    /// because it is a statement about the *capability*, not about this packet.
    ecn_rejected: bool = false,
};

fn sendDatagramTo(
    fd: std.c.fd_t,
    peer: *const std.c.sockaddr.in,
    datagram: []const u8,
    mark: quic.udp.Ecn,
) SentDatagram {
    const options = ecn_socket_options;
    const traffic_class: ?c_int = if (options == null) null else trafficClassFromEcn(mark);
    // `.not_ect` is the default state of the field, so an unmarked datagram
    // needs no control message at all — which keeps the common path a plain
    // `sendto` and means a kernel that rejects the cmsg only ever affects
    // listeners that are actually marking.
    if (traffic_class == null or traffic_class.? == 0) {
        return .{ .result = std.c.sendto(fd, datagram.ptr, datagram.len, 0, @ptrCast(peer), @sizeOf(std.c.sockaddr.in)) };
    }

    var control: [ecn_control_len]u8 align(@alignOf(usize)) = std.mem.zeroes([ecn_control_len]u8);
    const header: *align(cmsg_alignment) std.c.cmsghdr = @ptrCast(@alignCast(&control[0]));
    header.len = @intCast(cmsgLen(@sizeOf(c_int)));
    header.level = if (peer.family == posix.AF.INET6) posix.IPPROTO.IPV6 else posix.IPPROTO.IP;
    header.type = @intCast(if (peer.family == posix.AF.INET6) options.?.send_cmsg_v6 else options.?.send_cmsg_v4);
    const value: c_int = traffic_class.?;
    @memcpy(control[cmsg_data_offset..][0..@sizeOf(c_int)], std.mem.asBytes(&value));

    var iov = [_]std.c.iovec_const{.{ .base = datagram.ptr, .len = datagram.len }};
    var msg = std.mem.zeroes(std.c.msghdr_const);
    msg.name = @ptrCast(peer);
    msg.namelen = @sizeOf(std.c.sockaddr.in);
    msg.iov = &iov;
    msg.iovlen = 1;
    msg.control = &control;
    msg.controllen = @intCast(cmsgSpace(@sizeOf(c_int)));

    const sent = std.c.sendmsg(fd, &msg, 0);
    if (sent >= 0) return .{ .result = sent };
    // A kernel that will not accept the control message rejects every marked
    // send the same way, so retrying this one unmarked both delivers the
    // datagram and tells the caller to stop asking. Losing the mark is safe in
    // the direction that matters: the transport counted a marked packet the
    // peer will report as unmarked, which its own validation reads as marks
    // being stripped and answers by turning ECN off.
    if (isEcnControlRejection(posix.errno(sent))) {
        return .{
            .result = std.c.sendto(fd, datagram.ptr, datagram.len, 0, @ptrCast(peer), @sizeOf(std.c.sockaddr.in)),
            .ecn_rejected = true,
        };
    }
    return .{ .result = sent };
}

/// Whether a `sendmsg` failure is the kernel refusing the ECN control message
/// rather than an ordinary transient send failure. Deliberately narrow:
/// treating a full send buffer or an unreachable host as "this platform cannot
/// mark" would disable ECN for the life of the listener on the strength of one
/// bad moment.
fn isEcnControlRejection(err: posix.E) bool {
    return switch (err) {
        .INVAL, .NOPROTOOPT, .OPNOTSUPP, .PERM, .AFNOSUPPORT => true,
        else => false,
    };
}

/// The ECN codepoint carried by the control messages `recvmsg` returned, or
/// `.unavailable` when the kernel reported none — a socket without the option,
/// a platform without the constants, or a truncated control buffer.
fn ecnFromControl(control: []const u8, controllen: usize, sa_family: u32) quic.udp.Ecn {
    const options = ecn_socket_options orelse return .unavailable;
    const is_v6 = sa_family == posix.AF.INET6;
    const want_level: c_int = if (is_v6) posix.IPPROTO.IPV6 else posix.IPPROTO.IP;
    const want_type: c_int = @intCast(if (is_v6) options.recv_cmsg_v6 else options.recv_cmsg_v4);

    const limit = @min(controllen, control.len);
    var offset: usize = 0;
    while (offset + cmsg_data_offset <= limit) {
        const header: *align(cmsg_alignment) const std.c.cmsghdr = @ptrCast(@alignCast(&control[offset]));
        const len: usize = @intCast(header.len);
        if (len < cmsg_data_offset or offset + len > limit) break;
        if (header.level == want_level and header.type == want_type) {
            const payload = control[offset + cmsg_data_offset .. offset + len];
            // Kernels are inconsistent about the width: Linux delivers the
            // IPv4 TOS as a single byte and the IPv6 traffic class as an int,
            // and the BSDs differ again. Only the low byte of the value ever
            // matters, and it is the first byte on every little-endian target
            // this runs on — but read the width the kernel actually used
            // rather than assuming one, so a big-endian port does not silently
            // read the wrong end of an int.
            if (payload.len == 0) return .unavailable;
            if (payload.len >= @sizeOf(c_int)) {
                var value: c_int = 0;
                @memcpy(std.mem.asBytes(&value), payload[0..@sizeOf(c_int)]);
                return ecnFromTrafficClass(@truncate(@as(u32, @bitCast(value))));
            }
            return ecnFromTrafficClass(payload[0]);
        }
        offset += cmsgAlign(len);
    }
    return .unavailable;
}

/// Read one socket buffer size back with `getsockopt`. Returns null when the
/// readback fails, which is reported as such rather than being papered over
/// with the requested value: the whole reason to read back is that the number
/// the kernel chose and the number that was asked for routinely differ.
fn socketBufferBytes(fd: std.c.fd_t, option: u32) ?usize {
    var value: c_int = 0;
    var len: posix.socklen_t = @sizeOf(c_int);
    if (std.c.getsockopt(fd, posix.SOL.SOCKET, option, &value, &len) != 0) return null;
    if (len != @sizeOf(c_int) or value < 0) return null;
    return @intCast(value);
}

/// Restate a `getsockopt` reading in the units the request was made in, which
/// is the only basis on which "did the kernel grant this?" can be answered.
///
/// Linux stores `SO_RCVBUF`/`SO_SNDBUF` as twice the requested size — the
/// extra half is `sk_buff` bookkeeping, not payload capacity — and reports the
/// doubled figure. Comparing that figure against the request would report a
/// grant whenever the kernel gave *more than half* of what was asked for: a
/// 256 KiB request on a host whose `net.core.rmem_max` is 208 KiB reads back
/// as 416 KiB and would look like a success, which is precisely the silent
/// clamp this readback exists to expose.
///
/// This lives here rather than in `src/quic/udp.zig` because it is a fact
/// about the host's socket API, not about QUIC.
fn grantedBufferBytes(reported: usize) usize {
    return if (builtin.os.tag == .linux) reported / 2 else reported;
}

/// Apply one direction's requested socket buffer size and report what the
/// kernel did with it (#256-D).
///
/// Advisory by construction. `SO_RCVBUF`/`SO_SNDBUF` are performance knobs:
/// every failure mode here — refused, trimmed to a system ceiling, unreadable
/// — still leaves a listener that serves QUIC correctly, so none of them
/// returns an error. What they must not do is fail *silently*, which is why
/// the value is always read back: Linux caps a request at `net.core.rmem_max`
/// while returning success from `setsockopt`, so a listener asking for 16 MiB
/// on a stock kernel gets ~208 KiB and no indication of it.
fn tuneSocketBuffer(fd: std.c.fd_t, option: u32, requested: ?usize) quic.udp.BufferOutcome {
    // Nothing requested still reads back: the kernel default is the number
    // that explains a benchmark run or a report of unexplained loss, and it
    // is only knowable from inside this process.
    const want = requested orelse
        return quic.udp.classifyBufferOutcome(null, false, .{ .reported_bytes = socketBufferBytes(fd, option) });
    const clamped = quic.udp.clampBufferBytes(want);
    const value: c_int = @intCast(clamped);
    const accepted = if (posix.setsockopt(fd, posix.SOL.SOCKET, option, std.mem.asBytes(&value))) |_| true else |_| false;
    const reported = socketBufferBytes(fd, option);
    return quic.udp.classifyBufferOutcome(clamped, accepted, .{
        .reported_bytes = reported,
        .granted_bytes = if (reported) |bytes| grantedBufferBytes(bytes) else null,
    });
}

fn tuneSocketBuffers(fd: std.c.fd_t, tuning: quic.udp.BufferTuning) quic.udp.EffectiveBufferTuning {
    return .{
        .recv = tuneSocketBuffer(fd, posix.SO.RCVBUF, tuning.recv_bytes),
        .send = tuneSocketBuffer(fd, posix.SO.SNDBUF, tuning.send_bytes),
    };
}

/// The host-wide ceiling an operator has to raise before a larger per-socket
/// request can be granted. Named per platform because these are not the same
/// knob: Linux bounds each direction separately, the BSDs bound the total.
const socket_buffer_ceiling_hint = switch (builtin.os.tag) {
    .linux => "net.core.rmem_max/net.core.wmem_max",
    .macos, .ios, .tvos, .watchos, .freebsd, .netbsd, .openbsd, .dragonfly => "kern.ipc.maxsockbuf",
    else => "the host socket buffer ceiling",
};

/// Report one direction's tuning result. A granted request is `info`; every
/// outcome where the operator did not get what they configured is `warn`,
/// because the listener will otherwise run indefinitely with a buffer nobody
/// chose and no way to tell from outside the process.
fn logSocketBufferOutcome(
    logger: *logger_mod.Logger,
    direction: []const u8,
    outcome: quic.udp.BufferOutcome,
) void {
    const effective = outcome.effective_bytes orelse 0;
    switch (outcome.status) {
        .default => if (outcome.effective_bytes != null) {
            logger.info(null, "http3: udp {s} buffer at kernel default effective_bytes={d}", .{ direction, effective });
        },
        // `granted_bytes` is the request-comparable reading and `effective_bytes`
        // the raw one the kernel will report to anyone who inspects the socket.
        // Both are logged: on Linux they differ by design, and an operator
        // checking the two against each other should find them consistent.
        .applied => logger.info(null, "http3: udp {s} buffer applied requested_bytes={d} granted_bytes={d} effective_bytes={d}", .{
            direction,
            outcome.requested_bytes orelse 0,
            outcome.granted_bytes orelse 0,
            effective,
        }),
        .clamped => logger.warn(null, "http3: udp {s} buffer clamped by the kernel requested_bytes={d} granted_bytes={d} effective_bytes={d}; raise {s} on the host or lower the configured request", .{
            direction,
            outcome.requested_bytes orelse 0,
            outcome.granted_bytes orelse 0,
            effective,
            socket_buffer_ceiling_hint,
        }),
        .unverified => logger.warn(null, "http3: udp {s} buffer requested_bytes={d} accepted but could not be read back; effective size unknown", .{
            direction,
            outcome.requested_bytes orelse 0,
        }),
        .unsupported => logger.warn(null, "http3: udp {s} buffer request rejected by the kernel requested_bytes={d}; kernel default in effect", .{
            direction,
            outcome.requested_bytes orelse 0,
        }),
    }
}

/// Create a non-blocking, close-on-exec UDP socket for `sa_family`. Returns a
/// negative fd on failure (caller inspects `errno`). macOS/BSD reject
/// `SOCK_CLOEXEC`/`SOCK_NONBLOCK` in the socket `type` argument (EPROTOTYPE),
/// unlike Linux, so the flags are applied with `fcntl` after creation to keep
/// the listener working on both platforms.
fn openUdpSocket(sa_family: u32) std.c.fd_t {
    const fd = std.c.socket(@intCast(sa_family), posix.SOCK.DGRAM, posix.IPPROTO.UDP);
    if (fd < 0) return fd;
    const descriptor_flags = std.c.fcntl(fd, std.c.F.GETFD, @as(c_int, 0));
    if (descriptor_flags >= 0) _ = std.c.fcntl(fd, std.c.F.SETFD, descriptor_flags | std.c.FD_CLOEXEC);
    const status_flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
    if (status_flags >= 0) _ = std.c.fcntl(fd, std.c.F.SETFL, status_flags | @as(c_int, @bitCast(posix.O{ .NONBLOCK = true })));
    return fd;
}

const testing = std.testing;

const H3QlogRecorder = struct {
    records: std.ArrayList(http3.qlog.Record) = .empty,

    fn deinit(self: *H3QlogRecorder, allocator: std.mem.Allocator) void {
        for (self.records.items) |record| freeRecord(allocator, record);
        self.records.deinit(allocator);
    }

    fn sink(self: *H3QlogRecorder) http3.qlog.Sink {
        return .{ .context = self, .emit_fn = emit };
    }

    fn emit(ctx: ?*anyopaque, record: http3.qlog.Record) void {
        const self: *H3QlogRecorder = @ptrCast(@alignCast(ctx.?));
        self.records.append(testing.allocator, cloneRecord(testing.allocator, record) catch unreachable) catch unreachable;
    }

    fn cloneFields(allocator: std.mem.Allocator, fields: []const http3.qpack.HeaderField) ![]const http3.qpack.HeaderField {
        const copy = try allocator.alloc(http3.qpack.HeaderField, fields.len);
        errdefer allocator.free(copy);
        for (fields, 0..) |field, i| {
            const name = try allocator.dupe(u8, field.name);
            errdefer allocator.free(name);
            const value = try allocator.dupe(u8, field.value);
            errdefer allocator.free(value);
            copy[i] = .{ .name = name, .value = value };
        }
        return copy;
    }

    fn freeFields(allocator: std.mem.Allocator, fields: []const http3.qpack.HeaderField) void {
        for (fields) |field| {
            allocator.free(field.name);
            allocator.free(field.value);
        }
        allocator.free(fields);
    }

    fn cloneFrame(allocator: std.mem.Allocator, event_frame: http3.qlog.Frame) !http3.qlog.Frame {
        return switch (event_frame) {
            .headers => |h| .{ .headers = .{ .headers = try cloneFields(allocator, h.headers), .raw_length = h.raw_length } },
            .settings => |s| .{ .settings = .{ .settings = try allocator.dupe(http3.qlog.QlogSetting, s.settings), .raw_length = s.raw_length } },
            .priority_update => |update| .{ .priority_update = switch (update) {
                .request => |r| .{ .request = .{
                    .stream_id = r.stream_id,
                    .priority_field_value = try allocator.dupe(u8, r.priority_field_value),
                    .raw_length = r.raw_length,
                } },
                .push => |p| .{ .push = .{
                    .push_id = p.push_id,
                    .priority_field_value = try allocator.dupe(u8, p.priority_field_value),
                    .raw_length = p.raw_length,
                } },
            } },
            .push_promise => |p| .{ .push_promise = .{
                .push_id = p.push_id,
                .headers = try cloneFields(allocator, p.headers),
                .raw_length = p.raw_length,
            } },
            else => event_frame,
        };
    }

    fn freeFrame(allocator: std.mem.Allocator, event_frame: http3.qlog.Frame) void {
        switch (event_frame) {
            .headers => |h| freeFields(allocator, h.headers),
            .settings => |s| allocator.free(s.settings),
            .priority_update => |update| switch (update) {
                .request => |r| allocator.free(r.priority_field_value),
                .push => |p| allocator.free(p.priority_field_value),
            },
            .push_promise => |p| freeFields(allocator, p.headers),
            else => {},
        }
    }

    fn cloneRecord(allocator: std.mem.Allocator, record: http3.qlog.Record) !http3.qlog.Record {
        return .{ .time_us = record.time_us, .event = switch (record.event) {
            .frame => |f| .{ .frame = .{ .direction = f.direction, .stream_id = f.stream_id, .frame = try cloneFrame(allocator, f.frame) } },
            else => record.event,
        } };
    }

    fn freeRecord(allocator: std.mem.Allocator, record: http3.qlog.Record) void {
        switch (record.event) {
            .frame => |f| freeFrame(allocator, f.frame),
            else => {},
        }
    }
};

const QuicQlogRecorder = struct {
    records: std.ArrayList(quic.qlog.Record) = .empty,

    fn deinit(self: *QuicQlogRecorder, allocator: std.mem.Allocator) void {
        self.records.deinit(allocator);
    }

    fn sink(self: *QuicQlogRecorder) quic.qlog.Sink {
        return .{ .context = self, .emit_fn = emit };
    }

    fn emit(ctx: ?*anyopaque, record: quic.qlog.Record) void {
        const self: *QuicQlogRecorder = @ptrCast(@alignCast(ctx.?));
        self.records.append(std.testing.allocator, record) catch unreachable;
    }
};

test "http3 runtime: QUIC qlog adapter preserves normalized transport events" {
    try testing.expectEqual(
        quic.qlog.Event{ .packets_acked = .{ .packet_number_space = .application_data, .packet_number = 11 } },
        Runtime.quicEventToQlog(.{ .packets_acked = .{ .space = .application, .packet_number = 11 } }).?,
    );
    try testing.expectEqual(
        quic.qlog.Event{ .packets_lost = .{ .packet_type = .one_rtt, .lost_count = 3, .bytes = 3600 } },
        Runtime.quicEventToQlog(.{ .packets_lost = .{ .space = .application, .packet_type = .one_rtt, .lost_count = 3, .bytes = 3600 } }).?,
    );
    try testing.expectEqual(
        quic.qlog.Event{ .packet_received = .{ .packet_type = .zero_rtt, .packet_number = 7, .length = 1200 } },
        Runtime.quicEventToQlog(.{ .packet_received = .{ .space = .application, .packet_type = .zero_rtt, .packet_number = 7, .size = 1200 } }).?,
    );
    try testing.expectEqual(
        quic.qlog.Event{ .recovery_metrics_updated = .{ .latest_rtt_ms = 12, .smoothed_rtt_ms = 10, .rtt_variance_ms = 3, .pto_count = 2, .congestion_window = 12000, .bytes_in_flight = 6000 } },
        Runtime.quicEventToQlog(.{ .recovery_metrics_updated = .{ .latest_rtt_us = 12_900, .smoothed_rtt_us = 10_100, .rttvar_us = 3_999, .pto_count = 2, .congestion_window = 12000, .bytes_in_flight = 6000 } }).?,
    );
    try testing.expectEqual(
        quic.qlog.Event{ .stream_reset = .{ .kind = .stop_sending_received, .stream_id = 8, .error_code = 42 } },
        Runtime.quicEventToQlog(.{ .stop_sending = .{ .id = 8, .error_code = 42, .local = false } }).?,
    );
    try testing.expectEqual(
        quic.qlog.Event{ .data_blocked = .{ .stream = .{ .stream_id = 12, .old = .unblocked, .new = .blocked, .reason = .stream_flow_control } } },
        Runtime.quicEventToQlog(.{ .flow_control_state_changed = .{ .scope = .stream, .stream_id = 12, .local = true, .old = .unblocked, .new = .blocked } }).?,
    );
    try testing.expectEqual(
        quic.qlog.Event{ .flow_control_blocked_received = .{ .scope = .stream, .stream_id = 12 } },
        Runtime.quicEventToQlog(.{ .flow_control_blocked_received = .{ .scope = .stream, .stream_id = 12 } }).?,
    );
    try testing.expectEqual(
        quic.qlog.Event{ .stream_state_updated = .{ .stream_id = 4, .stream_side = .receiving, .old = .open, .new = .closed, .trigger = .remote } },
        Runtime.quicEventToQlog(.{ .stream_state_changed = .{ .id = 4, .side = .receiving, .old = .open, .new = .closed, .trigger = .remote } }).?,
    );
    try testing.expectEqual(
        quic.qlog.Event{ .congestion_state_updated = .{ .old = .slow_start, .new = .recovery } },
        Runtime.quicEventToQlog(.{ .congestion_state_changed = .{ .old = .slow_start, .new = .recovery } }).?,
    );
    try testing.expectEqual(quic.qlog.Event{ .persistent_congestion = .{} }, Runtime.quicEventToQlog(.persistent_congestion).?);
    try testing.expectEqual(
        quic.qlog.Event{ .connection_closed = .{ .trigger = .idle_timeout } },
        Runtime.quicEventToQlog(.idle_timeout).?,
    );
    try testing.expectEqual(
        quic.qlog.Event{ .connection_closed = .{ .trigger = .application, .close_error = .{ .application_unknown = 42 } } },
        Runtime.quicEventToQlog(.{ .local_close_started = .{ .error_code = 42, .is_application = true } }).?,
    );
    try testing.expect(Runtime.quicEventToQlog(.{ .close_sent = .{ .error_code = 42, .is_application = true } }) == null);
}

test "http3 runtime: QUIC qlog observer logs only first semantic close" {
    var runtime: Runtime = undefined;
    var recorder = QuicQlogRecorder{};
    defer recorder.deinit(testing.allocator);
    var observer = ConnEntry.QuicObserver{
        .runtime = &runtime,
        .connection_handle = 1,
        .qlog_sink = recorder.sink(),
    };

    Runtime.quicConnectionEvent(&observer, .{ .local_close_started = .{ .error_code = 42, .is_application = true } });
    Runtime.quicConnectionEvent(&observer, .{ .close_received = .{ .error_code = 7, .is_application = false } });
    Runtime.quicConnectionEvent(&observer, .idle_timeout);

    try testing.expectEqual(@as(usize, 1), recorder.records.items.len);
    try testing.expectEqual(quic.qlog.Event{ .connection_closed = .{ .trigger = .application, .close_error = .{ .application_unknown = 42 } } }, recorder.records.items[0].event);
}

test "http3 runtime: H3 qlog events route through connection-scoped observers" {
    var first = H3QlogRecorder{};
    defer first.deinit(testing.allocator);
    var second = H3QlogRecorder{};
    defer second.deinit(testing.allocator);

    var first_observer = ConnEntry.H3Observer{
        .runtime = undefined,
        .connection_handle = 1,
        .qlog_sink = first.sink(),
    };
    var second_observer = ConnEntry.H3Observer{
        .runtime = undefined,
        .connection_handle = 2,
        .qlog_sink = second.sink(),
    };

    Runtime.h3ConnectionEvent(&first_observer, .{ .stream_type_set = .{ .stream_id = 0, .stream_type = .request } });
    Runtime.h3ConnectionEvent(&second_observer, .{ .stream_type_set = .{ .stream_id = 0, .stream_type = .request } });

    try testing.expectEqual(@as(usize, 1), first.records.items.len);
    try testing.expectEqual(@as(usize, 1), second.records.items.len);
    try testing.expectEqual(http3.qlog.Event{ .stream_type_set = .{ .stream_id = 0, .stream_type = .request } }, first.records.items[0].event);
    try testing.expectEqual(http3.qlog.Event{ .stream_type_set = .{ .stream_id = 0, .stream_type = .request } }, second.records.items[0].event);
}

test "http3 runtime: no-op H3 qlog sink does not install connection event observer" {
    var no_op_observer = ConnEntry.H3Observer{
        .runtime = undefined,
        .connection_handle = 1,
        .qlog_sink = .{},
    };
    try testing.expect(Runtime.h3EventSinkFor(&no_op_observer) == null);

    var recorder = H3QlogRecorder{};
    defer recorder.deinit(testing.allocator);
    var enabled_observer = ConnEntry.H3Observer{
        .runtime = undefined,
        .connection_handle = 2,
        .qlog_sink = recorder.sink(),
    };
    try testing.expect(Runtime.h3EventSinkFor(&enabled_observer) != null);
}

test "http3 runtime: H3 qlog adapter preserves typed event payloads" {
    var recorder = H3QlogRecorder{};
    defer recorder.deinit(testing.allocator);

    var observer = ConnEntry.H3Observer{
        .runtime = undefined,
        .connection_handle = 1,
        .qlog_sink = recorder.sink(),
    };

    const settings = http3.frame.Settings{
        .qpack_max_table_capacity = 128,
        .max_field_section_size = 4096,
        .qpack_blocked_streams = 7,
    };
    const setting_entries = [_]http3.conn.EventSetting{
        .{ .id_value = 0x01, .value = 128 },
        .{ .id_value = 0x06, .value = 4096 },
        .{ .id_value = 0x07, .value = 7 },
    };
    const fields = [_]http3.qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/trace" },
    };

    Runtime.h3ConnectionEvent(&observer, .{ .parameters_set = .{ .initiator = .local, .settings = settings } });
    Runtime.h3ConnectionEvent(&observer, .{ .frame_parsed = .{ .stream_id = 0, .frame = .{ .settings = .{ .entries = &setting_entries, .raw_length = 9 } } } });
    Runtime.h3ConnectionEvent(&observer, .{ .frame_parsed = .{ .stream_id = 4, .frame = .{ .headers = .{ .fields = &fields, .raw_length = 12 } } } });
    Runtime.h3ConnectionEvent(&observer, .{ .frame_created = .{ .stream_id = 0, .frame = .{ .goaway = .{ .id = 12, .raw_length = 2 } } } });
    Runtime.h3ConnectionEvent(&observer, .{ .frame_parsed = .{ .stream_id = 0, .frame = .{ .priority_update = .{ .request = .{ .stream_id = 8, .field_value = "u=2", .raw_length = 7 } } } } });
    Runtime.h3ConnectionEvent(&observer, .{ .frame_parsed = .{ .stream_id = 4, .frame = .{ .push_promise = .{ .push_id = 3, .fields = &fields, .raw_length = 10 } } } });

    try testing.expectEqual(@as(usize, 6), recorder.records.items.len);
    switch (recorder.records.items[0].event) {
        .parameters_set => |event| {
            try testing.expectEqual(http3.qlog.Initiator.local, event.initiator.?);
            try testing.expectEqual(@as(u64, 128), event.max_table_capacity.?);
            try testing.expectEqual(@as(u64, 4096), event.max_field_section_size.?);
            try testing.expectEqual(@as(u64, 7), event.blocked_streams_count.?);
        },
        else => return error.TestUnexpectedResult,
    }
    switch (recorder.records.items[1].event) {
        .frame => |event| switch (event.frame) {
            .settings => |frame_event| {
                try testing.expectEqual(@as(u64, 0x01), frame_event.settings[0].id_value);
                try testing.expectEqual(@as(u64, 128), frame_event.settings[0].value);
                try testing.expectEqual(@as(u64, 0x06), frame_event.settings[1].id_value);
                try testing.expectEqual(@as(u64, 4096), frame_event.settings[1].value);
                try testing.expectEqual(@as(usize, 9), frame_event.raw_length.?);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
    switch (recorder.records.items[2].event) {
        .frame => |event| switch (event.frame) {
            .headers => |frame_event| {
                try testing.expectEqualStrings(":path", frame_event.headers[1].name);
                try testing.expectEqualStrings("/trace", frame_event.headers[1].value);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
    switch (recorder.records.items[3].event) {
        .frame => |event| switch (event.frame) {
            .goaway => |frame_event| try testing.expectEqual(@as(u64, 12), frame_event.id),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
    switch (recorder.records.items[4].event) {
        .frame => |event| switch (event.frame) {
            .priority_update => |update| switch (update) {
                .request => |frame_event| {
                    try testing.expectEqual(@as(u64, 8), frame_event.stream_id);
                    try testing.expectEqualStrings("u=2", frame_event.priority_field_value);
                },
                else => return error.TestUnexpectedResult,
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
    switch (recorder.records.items[5].event) {
        .frame => |event| switch (event.frame) {
            .push_promise => |frame_event| {
                try testing.expectEqual(@as(u64, 3), frame_event.push_id);
                try testing.expectEqualStrings(":method", frame_event.headers[0].name);
                try testing.expectEqualStrings("GET", frame_event.headers[0].value);
            },
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

const RuntimeCidHarness = struct {
    client_backend: quic.tls_backend.Tls13Backend,
    server_backend: *quic.tls_backend.Tls13Backend,
    // Owned, per-instance deterministic TLS-engine provider storage (#490
    // review), not the shared `test_quic_crypto.testHandshakeProvider()`
    // stream: every harness instance gets its own independent entropy.
    client_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{},
    server_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{},
    client: *Connection,
    entry: *ConnEntry,
    now_us: u64 = 1_000_000,

    const client_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_path = quic.path.PathKey{
        .local = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 42_000),
        .remote = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 42_001),
    };
    const server_path = quic.path.PathKey{
        .local = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 42_001),
        .remote = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 42_000),
    };
    const no_challenge = [_]u8{0} ** quic.path.path_challenge_len;

    fn init(allocator: std.mem.Allocator, credential_provider: tls_core.credentials.CredentialProvider) !*RuntimeCidHarness {
        const self = try allocator.create(RuntimeCidHarness);
        errdefer allocator.destroy(self);
        const server_backend = try allocator.create(quic.tls_backend.Tls13Backend);
        errdefer allocator.destroy(server_backend);
        const entry = try allocator.create(ConnEntry);
        errdefer allocator.destroy(entry);
        // #490: seed the deterministic provider storage in `self`'s
        // already-allocated (stable) memory first, then re-thread it
        // through the literal below — see `Smoke.init`'s matching comment
        // in tests/quic_h3_smoke.zig for why this ordering matters.
        const client_crypto_provider = self.client_provider_storage.init(0x442_c);
        const server_crypto_provider = self.server_provider_storage.init(0x442_5);
        server_backend.* = quic.tls_backend.Tls13Backend.initServerWithProvider(
            .{ .hello_random = [_]u8{0x51} ** 32 },
            server_crypto_provider,
            credential_provider,
        );
        self.* = .{
            .client_provider_storage = self.client_provider_storage,
            .server_provider_storage = self.server_provider_storage,
            .client_backend = quic.tls_backend.Tls13Backend.initClient(
                .{ .hello_random = [_]u8{0xc1} ** 32 },
                client_crypto_provider,
                .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
            ),
            .server_backend = server_backend,
            .client = undefined,
            .entry = entry,
        };
        self.client = try Connection.init(allocator, .{
            .role = .client,
            .local_cid = &client_cid,
            .original_destination_cid = &odcid,
            .initial_secret_dcid = &odcid,
            .peer_cid = &odcid,
            .tls = self.client_backend.backend(),
            .crypto_provider = test_quic_crypto.testDefaultProvider(),
            .now_us = self.now_us,
            .initial_path = client_path,
        });
        errdefer self.client.deinit();
        const server = try Connection.init(allocator, .{
            .role = .server,
            .local_cid = &odcid,
            .original_destination_cid = &odcid,
            .initial_secret_dcid = &odcid,
            .peer_cid = &client_cid,
            .tls = server_backend.backend(),
            .crypto_provider = test_quic_crypto.testDefaultProvider(),
            .now_us = self.now_us,
            .initial_path = server_path,
            .stateless_reset_key = &([_]u8{0x44} ** 32),
        });
        entry.* = .{
            .backend = server_backend,
            .conn = server,
            .h3 = H3.initWithSettings(allocator, .server, .{}),
            .quic_observer = .{ .runtime = undefined, .connection_handle = 0 },
            .h3_observer = .{ .runtime = undefined, .connection_handle = 0 },
            .admission_source_ip = 0x0100007f,
            .cid_len = odcid.len,
            .accepted_at_us = self.now_us,
        };
        entry.owned_cids[0] = try quic.cid.ConnectionId.init(&odcid);
        entry.owned_cid_count = 1;
        try self.pump();
        return self;
    }

    fn deinit(self: *RuntimeCidHarness, allocator: std.mem.Allocator) void {
        self.client.deinit();
        self.entry.deinit(allocator);
        allocator.destroy(self.entry);
        allocator.destroy(self);
    }

    fn pump(self: *RuntimeCidHarness) !void {
        var rounds: usize = 0;
        while (rounds < 64) : (rounds += 1) {
            var progressed = false;
            var buf: [2048]u8 = undefined;
            while (self.client.pollTransmitOnPath(&buf, self.now_us)) |t| {
                try self.entry.conn.ingestOnPath(t.bytes, server_path, no_challenge, self.now_us);
                progressed = true;
                self.now_us += 500;
            }
            while (self.entry.conn.pollTransmitOnPath(&buf, self.now_us)) |t| {
                try self.client.ingestOnPath(t.bytes, client_path, no_challenge, self.now_us);
                progressed = true;
                self.now_us += 500;
            }
            if (!progressed) break;
        }
        try testing.expect(self.client.isEstablished());
        try testing.expect(self.entry.conn.isEstablished());
    }
};

test "http3 runtime metrics: bulk cleanup flushes final transport deltas and clears active gauge" {
    const allocator = testing.allocator;
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-runtime-metrics-cleanup-test");
    var capture = RuntimeMetricCapture{};
    var runtime = try Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .quic_transport_metrics_ctx = &capture,
        .quic_transport_metrics_cb = RuntimeMetricCapture.onDelta,
        .quic_connections_active_metrics_ctx = &capture,
        .quic_connections_active_metrics_cb = RuntimeMetricCapture.onActive,
        .quic_handshake_failure_metrics_ctx = &capture,
        .quic_handshake_failure_metrics_cb = RuntimeMetricCapture.onHandshakeFailure,
    });
    defer runtime.deinit();

    var harness = try RuntimeCidHarness.init(allocator, fixed.provider());
    errdefer harness.deinit(allocator);
    harness.entry.conn.metrics.pto_count_total += 2;
    harness.entry.conn.metrics.packets_lost += 3;
    harness.entry.conn.adapter.metrics.deprotection_failures += 4;

    var connections = std.AutoHashMap(u64, *ConnEntry).init(allocator);
    defer connections.deinit();
    var routes = quic.cid.CidRoutingTable.init(allocator);
    defer routes.deinit();
    var per_ip = std.AutoHashMap(u32, u32).init(allocator);
    defer per_ip.deinit();
    try connections.put(7, harness.entry);
    try routes.insert(harness.entry.owned_cids[0], 7);
    try incPerIp(&per_ip, harness.entry.admission_source_ip);
    runtime.recordQuicConnectionsActive(connections.count());

    runtime.removeAllConnections(&connections, &routes, &per_ip);

    try testing.expectEqual(@as(usize, 0), connections.count());
    try testing.expectEqual(@as(usize, 0), routes.count());
    try testing.expectEqual(@as(usize, 0), per_ip.count());
    try testing.expectEqual(@as(usize, 0), capture.last_active);
    try testing.expect(capture.active_calls >= 2);
    try testing.expectEqual(@as(u64, 2), capture.delta.pto);
    try testing.expectEqual(@as(u64, 3), capture.delta.packets_lost);
    try testing.expectEqual(@as(u64, 4), capture.delta.deprotection_failures);
    try testing.expectEqual(@as(usize, 0), capture.handshake_failures);

    harness.client.deinit();
    allocator.destroy(harness);
}

test "http3 runtime metrics: MAX_STREAMS pressure is not stream byte flow-control pressure" {
    const allocator = testing.allocator;
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-runtime-stream-limit-metrics-test");
    var capture = RuntimeMetricCapture{};
    var runtime = try Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .quic_transport_metrics_ctx = &capture,
        .quic_transport_metrics_cb = RuntimeMetricCapture.onDelta,
    });
    defer runtime.deinit();

    var harness = try RuntimeCidHarness.init(allocator, fixed.provider());
    defer harness.deinit(allocator);
    if (harness.entry.conn.streams == null) {
        harness.entry.conn.streams = quic.stream.StreamManager.init(
            allocator,
            .server,
            harness.entry.conn.local_params,
            harness.entry.conn.peerTransportParameters().?,
        );
    }
    harness.entry.conn.streams.?.metrics.streams_blocked_events += 5;
    runtime.foldPathMetrics(harness.entry);
    try testing.expectEqual(@as(u64, 0), capture.delta.stream_flow_blocked);

    harness.entry.conn.streams.?.metrics.stream_data_blocked_events += 2;
    runtime.foldPathMetrics(harness.entry);
    try testing.expectEqual(@as(u64, 2), capture.delta.stream_flow_blocked);
}

test "#256-G: foldPathMetrics folds packet counts and PMTU probe/black-hole counts into the snapshot" {
    const allocator = testing.allocator;
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-runtime-pmtu-packet-snapshot-test");
    var runtime = try Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
    });
    defer runtime.deinit();

    var harness = try RuntimeCidHarness.init(allocator, fixed.provider());
    defer harness.deinit(allocator);

    try testing.expectEqual(@as(usize, 0), runtime.snapshot().packets_sent);
    try testing.expectEqual(@as(usize, 0), runtime.snapshot().packets_received);
    try testing.expectEqual(@as(usize, 0), runtime.snapshot().pmtu_probes_sent);
    try testing.expectEqual(@as(usize, 0), runtime.snapshot().pmtu_black_holes);

    // The harness's own setup (CID registration/handshake bookkeeping) may
    // already have sent/received a handful of packets on `harness.entry.conn`
    // before this test ever touches it, so measure everything from here as a
    // delta against a first fold rather than assuming a zero baseline —
    // exactly the relative-delta semantics `foldPathMetrics` itself applies
    // to every other counter.
    runtime.foldPathMetrics(harness.entry);
    const base = runtime.snapshot();

    harness.entry.conn.metrics.packets_sent += 10;
    harness.entry.conn.metrics.packets_received += 8;
    harness.entry.conn.metrics.pmtu_probes_sent += 2;
    runtime.foldPathMetrics(harness.entry);

    var snap = runtime.snapshot();
    try testing.expectEqual(@as(usize, 10), snap.packets_sent - base.packets_sent);
    try testing.expectEqual(@as(usize, 8), snap.packets_received - base.packets_received);
    try testing.expectEqual(@as(usize, 2), snap.pmtu_probes_sent - base.pmtu_probes_sent);
    try testing.expectEqual(base.pmtu_black_holes, snap.pmtu_black_holes);
    // The active path starts at the DPLPMTUD base size — never zero, and
    // last/min/max agree on it since only one path has folded so far.
    try testing.expect(snap.plpmtu_last_bytes > 0);
    try testing.expectEqual(snap.plpmtu_last_bytes, snap.plpmtu_lifetime_min_bytes);
    try testing.expectEqual(snap.plpmtu_last_bytes, snap.plpmtu_lifetime_max_bytes);

    // A second fold only adds the *delta* since the last fold, matching every
    // other counter folded here (ECN, retry, etc.) — not the raw connection
    // total re-added on top.
    const after_first = snap.packets_sent;
    harness.entry.conn.metrics.packets_sent += 5;
    harness.entry.conn.metrics.pmtu_black_holes += 1;
    runtime.foldPathMetrics(harness.entry);
    snap = runtime.snapshot();
    try testing.expectEqual(@as(usize, 5), snap.packets_sent - after_first);
    try testing.expectEqual(@as(usize, 1), snap.pmtu_black_holes - base.pmtu_black_holes);
}

test "http3 runtime metrics: handshake failures use removal reason and observed stage" {
    const allocator = testing.allocator;
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-runtime-handshake-stage-metrics-test");
    var capture = RuntimeMetricCapture{};
    var runtime = try Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .quic_handshake_failure_metrics_ctx = &capture,
        .quic_handshake_failure_metrics_cb = RuntimeMetricCapture.onHandshakeFailure,
    });
    defer runtime.deinit();

    var initial = try RuntimeCidHarness.init(allocator, fixed.provider());
    errdefer initial.deinit(allocator);
    initial.entry.conn.state_ = .handshaking;
    initial.entry.quic_observer = .{ .runtime = &runtime, .connection_handle = 1 };
    var initial_connections = std.AutoHashMap(u64, *ConnEntry).init(allocator);
    defer initial_connections.deinit();
    var initial_routes = quic.cid.CidRoutingTable.init(allocator);
    defer initial_routes.deinit();
    var initial_per_ip = std.AutoHashMap(u32, u32).init(allocator);
    defer initial_per_ip.deinit();
    try initial_connections.put(1, initial.entry);
    try initial_routes.insert(initial.entry.owned_cids[0], 1);
    try incPerIp(&initial_per_ip, initial.entry.admission_source_ip);
    runtime.removeConnection(&initial_connections, &initial_routes, &initial_per_ip, 1, .unauthenticated_initial);
    initial.client.deinit();
    allocator.destroy(initial);

    var handshake = try RuntimeCidHarness.init(allocator, fixed.provider());
    errdefer handshake.deinit(allocator);
    handshake.entry.conn.state_ = .handshaking;
    handshake.entry.quic_observer = .{ .runtime = &runtime, .connection_handle = 2 };
    Runtime.quicConnectionEvent(&handshake.entry.quic_observer, .{ .packet_received = .{ .space = .handshake, .packet_type = .handshake, .packet_number = 1, .size = 64 } });
    var hs_connections = std.AutoHashMap(u64, *ConnEntry).init(allocator);
    defer hs_connections.deinit();
    var hs_routes = quic.cid.CidRoutingTable.init(allocator);
    defer hs_routes.deinit();
    var hs_per_ip = std.AutoHashMap(u32, u32).init(allocator);
    defer hs_per_ip.deinit();
    try hs_connections.put(2, handshake.entry);
    try hs_routes.insert(handshake.entry.owned_cids[0], 2);
    try incPerIp(&hs_per_ip, handshake.entry.admission_source_ip);
    runtime.removeConnection(&hs_connections, &hs_routes, &hs_per_ip, 2, .handshake_timeout);
    handshake.client.deinit();
    allocator.destroy(handshake);

    var administrative = try RuntimeCidHarness.init(allocator, fixed.provider());
    errdefer administrative.deinit(allocator);
    administrative.entry.conn.state_ = .handshaking;
    administrative.entry.quic_observer = .{ .runtime = &runtime, .connection_handle = 3 };
    var admin_connections = std.AutoHashMap(u64, *ConnEntry).init(allocator);
    defer admin_connections.deinit();
    var admin_routes = quic.cid.CidRoutingTable.init(allocator);
    defer admin_routes.deinit();
    var admin_per_ip = std.AutoHashMap(u32, u32).init(allocator);
    defer admin_per_ip.deinit();
    try admin_connections.put(3, administrative.entry);
    try admin_routes.insert(administrative.entry.owned_cids[0], 3);
    try incPerIp(&admin_per_ip, administrative.entry.admission_source_ip);
    runtime.removeAllConnections(&admin_connections, &admin_routes, &admin_per_ip);
    administrative.client.deinit();
    allocator.destroy(administrative);

    var established_closed = try RuntimeCidHarness.init(allocator, fixed.provider());
    errdefer established_closed.deinit(allocator);
    established_closed.entry.conn.state_ = .closing;
    established_closed.entry.quic_observer = .{ .runtime = &runtime, .connection_handle = 4 };
    Runtime.quicConnectionEvent(&established_closed.entry.quic_observer, .{ .state = .established });
    var closed_connections = std.AutoHashMap(u64, *ConnEntry).init(allocator);
    defer closed_connections.deinit();
    var closed_routes = quic.cid.CidRoutingTable.init(allocator);
    defer closed_routes.deinit();
    var closed_per_ip = std.AutoHashMap(u32, u32).init(allocator);
    defer closed_per_ip.deinit();
    try closed_connections.put(4, established_closed.entry);
    try closed_routes.insert(established_closed.entry.owned_cids[0], 4);
    try incPerIp(&closed_per_ip, established_closed.entry.admission_source_ip);
    runtime.removeConnection(&closed_connections, &closed_routes, &closed_per_ip, 4, .protocol_failure);
    established_closed.client.deinit();
    allocator.destroy(established_closed);

    var established_old = try RuntimeCidHarness.init(allocator, fixed.provider());
    errdefer established_old.deinit(allocator);
    established_old.entry.conn.state_ = .closed;
    established_old.entry.accepted_at_us = 0;
    established_old.entry.quic_observer = .{ .runtime = &runtime, .connection_handle = 5 };
    Runtime.quicConnectionEvent(&established_old.entry.quic_observer, .{ .state = .established });
    var old_connections = std.AutoHashMap(u64, *ConnEntry).init(allocator);
    defer old_connections.deinit();
    var old_routes = quic.cid.CidRoutingTable.init(allocator);
    defer old_routes.deinit();
    var old_per_ip = std.AutoHashMap(u32, u32).init(allocator);
    defer old_per_ip.deinit();
    try old_connections.put(5, established_old.entry);
    try old_routes.insert(established_old.entry.owned_cids[0], 5);
    try incPerIp(&old_per_ip, established_old.entry.admission_source_ip);
    runtime.removeConnection(&old_connections, &old_routes, &old_per_ip, 5, .handshake_timeout);
    established_old.client.deinit();
    allocator.destroy(established_old);

    var tls_complete_failed = try RuntimeCidHarness.init(allocator, fixed.provider());
    errdefer tls_complete_failed.deinit(allocator);
    tls_complete_failed.entry.conn.state_ = .closing;
    tls_complete_failed.entry.quic_observer = .{ .runtime = &runtime, .connection_handle = 6 };
    Runtime.quicConnectionEvent(&tls_complete_failed.entry.quic_observer, .{ .packet_received = .{ .space = .handshake, .packet_type = .handshake, .packet_number = 2, .size = 80 } });
    Runtime.quicConnectionEvent(&tls_complete_failed.entry.quic_observer, .handshake_complete);
    var tls_failed_connections = std.AutoHashMap(u64, *ConnEntry).init(allocator);
    defer tls_failed_connections.deinit();
    var tls_failed_routes = quic.cid.CidRoutingTable.init(allocator);
    defer tls_failed_routes.deinit();
    var tls_failed_per_ip = std.AutoHashMap(u32, u32).init(allocator);
    defer tls_failed_per_ip.deinit();
    try tls_failed_connections.put(6, tls_complete_failed.entry);
    try tls_failed_routes.insert(tls_complete_failed.entry.owned_cids[0], 6);
    try incPerIp(&tls_failed_per_ip, tls_complete_failed.entry.admission_source_ip);
    runtime.removeConnection(&tls_failed_connections, &tls_failed_routes, &tls_failed_per_ip, 6, .protocol_failure);
    tls_complete_failed.client.deinit();
    allocator.destroy(tls_complete_failed);

    var drain_race = try RuntimeCidHarness.init(allocator, fixed.provider());
    errdefer drain_race.deinit(allocator);
    drain_race.entry.conn.state_ = .closing;
    drain_race.entry.quic_observer = .{ .runtime = &runtime, .connection_handle = 7 };
    Runtime.quicConnectionEvent(&drain_race.entry.quic_observer, .{ .packet_received = .{ .space = .handshake, .packet_type = .handshake, .packet_number = 3, .size = 96 } });
    runtime.closeForDrainDeadline(drain_race.entry, drain_race.now_us);
    try testing.expect(!drain_race.entry.quic_observer.administrative_close);
    var drain_race_connections = std.AutoHashMap(u64, *ConnEntry).init(allocator);
    defer drain_race_connections.deinit();
    var drain_race_routes = quic.cid.CidRoutingTable.init(allocator);
    defer drain_race_routes.deinit();
    var drain_race_per_ip = std.AutoHashMap(u32, u32).init(allocator);
    defer drain_race_per_ip.deinit();
    try drain_race_connections.put(7, drain_race.entry);
    try drain_race_routes.insert(drain_race.entry.owned_cids[0], 7);
    try incPerIp(&drain_race_per_ip, drain_race.entry.admission_source_ip);
    const drain_race_reason: RemovalReason = if (drain_race.entry.quic_observer.administrative_close) .administrative else .protocol_failure;
    runtime.removeConnection(&drain_race_connections, &drain_race_routes, &drain_race_per_ip, 7, drain_race_reason);
    drain_race.client.deinit();
    allocator.destroy(drain_race);

    var timeout_on_drain = try RuntimeCidHarness.init(allocator, fixed.provider());
    errdefer timeout_on_drain.deinit(allocator);
    timeout_on_drain.entry.conn.state_ = .handshaking;
    timeout_on_drain.entry.accepted_at_us = 0;
    timeout_on_drain.entry.quic_observer = .{ .runtime = &runtime, .connection_handle = 8 };
    const drain_now = handshake_timeout_us + 1;
    const timeout_before_drain = Runtime.handshakeTimedOutForRemoval(timeout_on_drain.entry, drain_now);
    try testing.expect(timeout_before_drain);
    if (!timeout_before_drain) runtime.closeForDrainDeadline(timeout_on_drain.entry, drain_now);
    try testing.expect(!timeout_on_drain.entry.quic_observer.administrative_close);
    var timeout_connections = std.AutoHashMap(u64, *ConnEntry).init(allocator);
    defer timeout_connections.deinit();
    var timeout_routes = quic.cid.CidRoutingTable.init(allocator);
    defer timeout_routes.deinit();
    var timeout_per_ip = std.AutoHashMap(u32, u32).init(allocator);
    defer timeout_per_ip.deinit();
    try timeout_connections.put(8, timeout_on_drain.entry);
    try timeout_routes.insert(timeout_on_drain.entry.owned_cids[0], 8);
    try incPerIp(&timeout_per_ip, timeout_on_drain.entry.admission_source_ip);
    runtime.removeConnection(
        &timeout_connections,
        &timeout_routes,
        &timeout_per_ip,
        8,
        Runtime.reapRemovalReason(timeout_on_drain.entry, timeout_before_drain),
    );
    timeout_on_drain.client.deinit();
    allocator.destroy(timeout_on_drain);

    try testing.expectEqual(@as(usize, 5), capture.handshake_failures);
    try testing.expectEqual(@as(usize, 2), capture.handshake_failures_by_stage[0]);
    try testing.expectEqual(@as(usize, 3), capture.handshake_failures_by_stage[1]);
}

test "http3 runtime metrics: rendered Prometheus deltas are not double-counted across folds" {
    const allocator = testing.allocator;
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-runtime-served-metrics-delta-test");
    var bridge = MetricsBridgeCapture{ .metrics = metrics_mod.Metrics.init() };
    var runtime = try Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .quic_transport_metrics_ctx = &bridge,
        .quic_transport_metrics_cb = MetricsBridgeCapture.onDelta,
    });
    defer runtime.deinit();

    var harness = try RuntimeCidHarness.init(allocator, fixed.provider());
    defer harness.deinit(allocator);
    if (harness.entry.conn.streams == null) {
        harness.entry.conn.streams = quic.stream.StreamManager.init(
            allocator,
            .server,
            harness.entry.conn.local_params,
            harness.entry.conn.peerTransportParameters().?,
        );
    }

    runtime.noteRetryPacketSent();
    harness.entry.conn.paths.metrics.amplification_blocked_sends += 2;
    harness.entry.conn.metrics.pto_count_total += 3;
    harness.entry.conn.metrics.packets_lost += 4;
    harness.entry.conn.streams.?.metrics.reset_streams += 5;
    harness.entry.conn.streams.?.metrics.data_blocked_events += 6;
    harness.entry.conn.streams.?.metrics.stream_data_blocked_events += 7;
    harness.entry.conn.adapter.metrics.deprotection_failures += 8;
    runtime.foldPathMetrics(harness.entry);
    {
        const prom = try bridge.metrics.toPrometheus(allocator);
        defer allocator.free(prom);
        try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_retry_total 1\n") != null);
        try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_amplification_blocked_total 2\n") != null);
        try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_pto_total 3\n") != null);
        try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_packets_lost_total 4\n") != null);
        try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_stream_resets_total 5\n") != null);
        try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_flow_control_blocked_total{scope=\"connection\"} 6\n") != null);
        try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_flow_control_blocked_total{scope=\"stream\"} 7\n") != null);
        try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_deprotection_failures_total 8\n") != null);
    }

    runtime.foldPathMetrics(harness.entry);
    {
        const prom = try bridge.metrics.toPrometheus(allocator);
        defer allocator.free(prom);
        try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_amplification_blocked_total 2\n") != null);
        try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_pto_total 3\n") != null);
        try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_packets_lost_total 4\n") != null);
        try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_stream_resets_total 5\n") != null);
        try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_flow_control_blocked_total{scope=\"connection\"} 6\n") != null);
        try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_flow_control_blocked_total{scope=\"stream\"} 7\n") != null);
        try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_deprotection_failures_total 8\n") != null);
    }

    harness.entry.conn.paths.metrics.amplification_blocked_sends += 1;
    harness.entry.conn.metrics.pto_count_total += 1;
    harness.entry.conn.metrics.packets_lost += 1;
    harness.entry.conn.streams.?.metrics.reset_streams += 1;
    harness.entry.conn.streams.?.metrics.data_blocked_events += 1;
    harness.entry.conn.streams.?.metrics.stream_data_blocked_events += 1;
    harness.entry.conn.adapter.metrics.deprotection_failures += 1;
    runtime.foldPathMetrics(harness.entry);
    {
        const prom = try bridge.metrics.toPrometheus(allocator);
        defer allocator.free(prom);
        try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_amplification_blocked_total 3\n") != null);
        try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_pto_total 4\n") != null);
        try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_packets_lost_total 5\n") != null);
        try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_stream_resets_total 6\n") != null);
        try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_flow_control_blocked_total{scope=\"connection\"} 7\n") != null);
        try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_flow_control_blocked_total{scope=\"stream\"} 8\n") != null);
        try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_deprotection_failures_total 9\n") != null);
    }
}

test "http3 runtime metrics: failed Retry UDP send does not increment sent counters" {
    const allocator = testing.allocator;
    var logger = logger_mod.Logger.init(.err, "http3-runtime-retry-send-failure-test");
    var bridge = MetricsBridgeCapture{ .metrics = metrics_mod.Metrics.init() };
    var runtime = try Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .retry_policy = .address_validation,
        .quic_transport_metrics_ctx = &bridge,
        .quic_transport_metrics_cb = MetricsBridgeCapture.onDelta,
    });
    _ = std.c.close(runtime.socket_fd);
    runtime.socket_fd = -1;
    defer {
        runtime.socket_fd = -1;
        runtime.deinit();
    }

    var routes = quic.cid.CidRoutingTable.init(allocator);
    defer routes.deinit();
    const dcid = [_]u8{0x44} ** 8;
    const scid = [_]u8{0x55} ** 8;
    runtime.issueRetry(
        &routes,
        .{ .kind = .initial, .version = quic.packet.quic_v1, .dcid = &dcid, .scid = &scid },
        sockaddrInFromAddress(quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 4444)),
        quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 4444),
        1_000_000,
    );

    const prom = try bridge.metrics.toPrometheus(allocator);
    defer allocator.free(prom);
    try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_retry_total 0\n") != null);
    try testing.expect(std.mem.find(u8, prom, "tardigrade_quic_bytes_sent_total 0\n") != null);
}

test "stream request bridge maps exchange fields and Host" {
    const allocator = testing.allocator;
    var request = try buildStreamRequest(allocator, .{
        .request = .{
            .method = "POST",
            .scheme = "https",
            .authority = "example.com",
            .path = "/api?x=1",
            .headers = &.{.{ .name = "content-type", .value = "application/json" }},
        },
        .body = .{ .buffered = @constCast("{}") },
    });
    defer request.deinit();
    try testing.expectEqualStrings("POST", request.method);
    try testing.expectEqualStrings("/api?x=1", request.path);
    try testing.expectEqualStrings("example.com", request.authority.?);
    try testing.expectEqualStrings("example.com", request.headers.get("Host").?);
    try testing.expectEqualStrings("application/json", request.headers.get("content-type").?);
    try testing.expectEqualStrings("{}", request.body);
}

test "quicConfigFrom clamps datagram size into the work-buffer range" {
    // Below the QUIC minimum snaps up to 1200.
    try testing.expectEqual(@as(u64, 1200), quicConfigFrom(.{
        .listen_host = "::",
        .quic_port = 443,
        .max_datagram_size = 512,
    }, true, false).max_send_udp_payload_size);
    // Above the 2048-byte work buffer snaps down.
    try testing.expectEqual(@as(u64, 2048), quicConfigFrom(.{
        .listen_host = "::",
        .quic_port = 443,
        .max_datagram_size = 9000,
    }, true, false).max_send_udp_payload_size);
    // An in-range value passes through, and default migration allows validated
    // same-IP NAT rebinding while still advertising disable_active_migration.
    const mid = quicConfigFrom(.{ .listen_host = "::", .quic_port = 443, .max_datagram_size = 1350 }, true, false);
    try testing.expectEqual(@as(u64, 1350), mid.max_send_udp_payload_size);
    try testing.expectEqual(quic.config.MigrationPolicy.nat_rebinding_only, mid.migration_policy);
    try testing.expectEqual(quic.config.RetryPolicy.off, mid.retry_policy);
    try testing.expectEqual(quic.config.MigrationPolicy.full, quicConfigFrom(.{
        .listen_host = "::",
        .quic_port = 443,
        .connection_migration = true,
    }, true, false).migration_policy);
    try testing.expectEqual(quic.config.RetryPolicy.address_validation, quicConfigFrom(.{
        .listen_host = "::",
        .quic_port = 443,
        .retry_policy = .address_validation,
    }, true, false).retry_policy);
}

test "quicConfigFrom: the runtime is the socket owner that opts discovery in" {
    // #256-A: neither layer carries a second datagram-size *value* that can
    // drift — both come from `quic.datagram`. #256-B splits the two defaults
    // on purpose, though: the transport cannot see a socket, so it stays at
    // the floor, and this runtime raises the ceiling only because it just
    // established the no-fragmentation contract on the socket it owns.
    const runtime_default = Config{ .listen_host = "::", .quic_port = 443 };
    try testing.expectEqual(quic.datagram.max_size, runtime_default.max_datagram_size);
    try testing.expectEqual(
        @as(u64, quic.datagram.base_size),
        (quic.config.Config{}).max_send_udp_payload_size,
    );
    const mapped = quicConfigFrom(runtime_default, true, false);
    try testing.expectEqual(
        @as(u64, quic.datagram.max_size),
        mapped.max_send_udp_payload_size,
    );
    // ... and without that contract it falls back to the transport's own
    // conservative default rather than the operator's ceiling.
    try testing.expectEqual(
        (quic.config.Config{}).max_send_udp_payload_size,
        quicConfigFrom(runtime_default, false, false).max_send_udp_payload_size,
    );
    // The advertised receive capacity is a property of the transport's
    // buffers, not of this operator knob, so the knob must not move it.
    try testing.expectEqual(
        (quic.config.Config{}).max_udp_payload_size,
        mapped.max_udp_payload_size,
    );
    try testing.expectEqual(
        quic.datagram.max_size,
        quicConfigFrom(.{ .listen_host = "::", .quic_port = 443, .max_datagram_size = 1350 }, true, false).max_udp_payload_size,
    );
}

test "http3 runtime: receive buffers match the advertised receive capacity" {
    // The `max_udp_payload_size` this endpoint promises the peer must not
    // exceed what the listener and connection can actually deprotect.
    const advertised = (quic.config.Config{}).max_udp_payload_size;
    try testing.expectEqual(@as(u64, quic.datagram.max_size), advertised);
    try testing.expectEqual(quic.datagram.max_size, quic.connection.max_receive_datagram_size);
}

test "http3 runtime: spare CID route is registered before NEW_CONNECTION_ID is pollable" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-cid-route-order-test");
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
    });
    defer runtime.deinit();
    var harness = try RuntimeCidHarness.init(testing.allocator, fixed.provider());
    defer harness.deinit(testing.allocator);

    var routes = quic.cid.CidRoutingTable.init(testing.allocator);
    defer routes.deinit();
    const handle: u64 = 7;
    const initial = harness.entry.owned_cids[0];
    try routes.insert(initial, handle);
    try testing.expect(routes.contains(initial));
    try testing.expectEqual(@as(usize, 1), harness.entry.owned_cid_count);
    try testing.expectEqual(@as(usize, 0), harness.entry.conn.pending_new_connection_ids.items.len);

    runtime.maintainLocalCidRoutes(harness.entry, handle, &routes);
    try testing.expectEqual(@as(usize, 2), harness.entry.owned_cid_count);
    try testing.expectEqual(@as(usize, 1), harness.entry.conn.pending_new_connection_ids.items.len);
    const spare = harness.entry.owned_cids[1];
    try testing.expect(routes.contains(spare));

    var out: [2048]u8 = undefined;
    _ = harness.entry.conn.pollTransmitOnPath(&out, harness.now_us) orelse return error.TestExpectedEqual;
    try testing.expectEqual(@as(usize, 0), harness.entry.conn.pending_new_connection_ids.items.len);
}

test "http3 runtime: CID route collision rolls back without stealing an existing route" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var harness = try RuntimeCidHarness.init(testing.allocator, fixed.provider());
    defer harness.deinit(testing.allocator);

    var routes = quic.cid.CidRoutingTable.init(testing.allocator);
    defer routes.deinit();
    const handle: u64 = 7;
    const collision_owner: u64 = 99;
    const candidate = try quic.cid.ConnectionId.init(&.{ 9, 8, 7, 6, 5, 4, 3, 2 });
    try routes.insert(harness.entry.owned_cids[0], handle);
    try routes.insert(candidate, collision_owner);

    const before_routes = routes.count();
    const before_owned = harness.entry.owned_cid_count;
    const before_pending = harness.entry.conn.pending_new_connection_ids.items.len;
    try testing.expectEqual(Runtime.RegisterLocalCidRouteResult.collision, Runtime.registerLocalCidRoute(harness.entry, handle, &routes, candidate));
    try testing.expectEqual(before_routes, routes.count());
    try testing.expectEqual(before_owned, harness.entry.owned_cid_count);
    try testing.expectEqual(before_pending, harness.entry.conn.pending_new_connection_ids.items.len);
    try testing.expectEqual(@as(?u64, collision_owner), routes.lookup(candidate.slice()));
}

/// Queue a response far larger than one burst on the harness's server
/// connection and pin the window and RTT, so what holds the send path back is
/// the pacer rather than the sub-millisecond RTT the in-process handshake
/// leaves behind (see the matching fixture in `quic/connection.zig`). Returns
/// with the opening burst already spent at `harness.now_us`.
fn spendPacingBurst(harness: *RuntimeCidHarness, cwnd: usize, srtt_us: u64) !void {
    const sid = try harness.client.openStream(.bidi);
    _ = try harness.client.writeStream(sid, "request", false);
    try harness.pump();
    _ = try harness.entry.conn.writeStream(sid, &[_]u8{0xab} ** (64 * 1024), false);

    harness.entry.conn.recovery.rtt = quic.recovery.RttEstimator.init(25_000);
    harness.entry.conn.recovery.rtt.update(srtt_us, 0);
    const congestion = &harness.entry.conn.recovery.congestion;
    congestion.congestion_window = cwnd;
    congestion.ssthresh = cwnd;
    congestion.bytes_in_flight = 0;
    congestion.pacer = .{};

    var out: [quic.datagram.max_size]u8 = undefined;
    var emitted: usize = 0;
    while (harness.entry.conn.pollTransmitOnPath(&out, harness.now_us)) |_| emitted += 1;
    try testing.expect(emitted > 0);
    try testing.expect(emitted <= quic.recovery.default_pacer_burst_packets);
}

test "http3 runtime: the loop's sleep deadline follows the pacing release" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var harness = try RuntimeCidHarness.init(testing.allocator, fixed.provider());
    defer harness.deinit(testing.allocator);

    // The loop's own idle ceiling, which every other deadline competes with.
    const floor = harness.now_us + 100_000;
    const quiet = Runtime.connectionWakeUs(harness.entry, harness.now_us, floor);
    try testing.expectEqual(@as(?u64, null), harness.entry.conn.nextSendTimeUs(harness.now_us));

    try spendPacingBurst(harness, 64 * 1024, 100_000);
    const now = harness.now_us;

    // Held back by the pacer and by nothing else, and the release beats every
    // timer deadline — so a loop that folded in only `nextTimeoutUs` would
    // sleep straight past the moment this data became eligible.
    const release = harness.entry.conn.nextSendTimeUs(now) orelse return error.TestExpectedEqual;
    try testing.expect(release > now);
    try testing.expect(release < quiet);
    try testing.expectEqual(release, Runtime.connectionWakeUs(harness.entry, now, floor));

    // And sleeping until it is productive: the send path yields again there.
    var out: [quic.datagram.max_size]u8 = undefined;
    try testing.expect(harness.entry.conn.pollTransmitOnPath(&out, release) != null);
}

test "http3 runtime: a connection with nothing paced contributes no wakeup of its own" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var harness = try RuntimeCidHarness.init(testing.allocator, fixed.provider());
    defer harness.deinit(testing.allocator);

    try spendPacingBurst(harness, 64 * 1024, 100_000);
    const now = harness.now_us;

    // Congestion control is the harder gate, and when it is what a connection
    // is waiting on there is no pacing wakeup to schedule: the loss and PTO
    // timers already in `nextTimeoutUs` are what should bring the loop back.
    const congestion = &harness.entry.conn.recovery.congestion;
    congestion.bytes_in_flight = congestion.congestion_window;
    try testing.expectEqual(@as(?u64, null), harness.entry.conn.nextSendTimeUs(now));

    const floor = now + 100_000;
    const timers = harness.entry.conn.nextTimeoutUs() orelse floor;
    try testing.expectEqual(@min(floor, timers), Runtime.connectionWakeUs(harness.entry, now, floor));
}

test "http3 runtime: retired CIDs stop routing, replenish, and teardown removes every route" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-cid-teardown-test");
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
    });
    defer runtime.deinit();
    var harness = try RuntimeCidHarness.init(testing.allocator, fixed.provider());
    defer {
        harness.client.deinit();
        testing.allocator.destroy(harness);
    }

    var routes = quic.cid.CidRoutingTable.init(testing.allocator);
    defer routes.deinit();
    const handle: u64 = 7;
    const initial = harness.entry.owned_cids[0];
    try routes.insert(initial, handle);
    runtime.maintainLocalCidRoutes(harness.entry, handle, &routes);
    const spare = harness.entry.owned_cids[1];
    try testing.expect(routes.contains(spare));

    var out: [2048]u8 = undefined;
    _ = harness.entry.conn.pollTransmitOnPath(&out, harness.now_us) orelse return error.TestExpectedEqual;
    _ = try harness.entry.conn.local_cids.?.retire(.{ .sequence = 1 });
    runtime.syncCidRoutes(harness.entry, &routes);
    try testing.expect(!routes.contains(spare));
    try testing.expectEqual(@as(?u64, null), routes.lookup(spare.slice()));

    runtime.maintainLocalCidRoutes(harness.entry, handle, &routes);
    try testing.expectEqual(@as(usize, 2), harness.entry.owned_cid_count);
    try testing.expect(routes.contains(initial));
    const replacement = for (harness.entry.owned_cids[0..harness.entry.owned_cid_count]) |cid| {
        if (!std.mem.eql(u8, cid.slice(), initial.slice())) break cid;
    } else return error.TestExpectedEqual;
    try testing.expect(!std.mem.eql(u8, replacement.slice(), spare.slice()));
    try testing.expect(routes.contains(replacement));

    var connections = std.AutoHashMap(u64, *ConnEntry).init(testing.allocator);
    defer connections.deinit();
    var per_ip = std.AutoHashMap(u32, u32).init(testing.allocator);
    defer per_ip.deinit();
    const admission_ip = harness.entry.admission_source_ip;
    try connections.put(handle, harness.entry);
    try incPerIp(&per_ip, admission_ip);
    runtime.removeConnection(&connections, &routes, &per_ip, handle, .administrative);
    try testing.expectEqual(@as(usize, 0), connections.count());
    try testing.expectEqual(@as(usize, 0), routes.count());
    try testing.expectEqual(@as(?u32, null), per_ip.get(admission_ip));
}

test "quicEarlyDataTransportCompatible (#523): rejects any reduced limit in the full RFC 9000 §7.4.1 set" {
    const base = quic.config.TransportParameters{
        .max_idle_timeout_ms = 1000,
        .active_connection_id_limit = 4,
        .max_udp_payload_size = 1200,
        .initial_max_data = 100,
        .initial_max_stream_data_bidi_local = 50,
        .initial_max_stream_data_bidi_remote = 50,
        .initial_max_stream_data_uni = 25,
        .initial_max_streams_bidi = 10,
        .initial_max_streams_uni = 5,
        .disable_active_migration = true,
    };

    // Identical parameters are always compatible.
    try testing.expect(quicEarlyDataTransportCompatible(base, base));

    // Raising every limit (including the two the second-pass review added)
    // stays compatible.
    var raised = base;
    raised.initial_max_data += 1;
    raised.active_connection_id_limit += 1;
    raised.initial_max_stream_data_bidi_local += 1;
    try testing.expect(quicEarlyDataTransportCompatible(base, raised));

    // Reducing `active_connection_id_limit` alone is rejected.
    var reduced_cid = base;
    reduced_cid.active_connection_id_limit -= 1;
    try testing.expect(!quicEarlyDataTransportCompatible(base, reduced_cid));

    // Reducing `initial_max_stream_data_bidi_local` alone is rejected.
    var reduced_bidi_local = base;
    reduced_bidi_local.initial_max_stream_data_bidi_local -= 1;
    try testing.expect(!quicEarlyDataTransportCompatible(base, reduced_bidi_local));
}

test "h3EarlyDataCompatibility (#523): rejects a remembered snapshot with the wrong format_version before decoding" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-transport-version-test");
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
    });
    defer runtime.deinit();

    const candidate: tls_core.tls13_backend.EarlyDataCompatibilityCandidate = .{
        .remembered_transport = .{
            .format_id = quic_transport_parameters_extension_type,
            .format_version = quic_transport_parameters_compat_format_version + 1,
            .bytes = "not even valid transport parameter bytes",
        },
    };
    try testing.expectEqual(
        tls_core.tls13_backend.EarlyDataCompatibilityDecision.transport_incompatible,
        Runtime.h3EarlyDataCompatibility(@ptrCast(&runtime), candidate),
    );
}

test "h3EarlyDataCompatibility (#523): rejects a live QUIC transport limit reduced below the remembered snapshot" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-transport-reduced-test");
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
    });
    defer runtime.deinit();

    const remembered_params = try runtime.quic_config.transportParameters();
    var encoded: [quic.tls_backend.max_transport_parameters_len]u8 = undefined;
    const encoded_bytes = try quic.tls_backend.encodeTransportParameters(remembered_params, &encoded);

    const candidate: tls_core.tls13_backend.EarlyDataCompatibilityCandidate = .{
        .remembered_transport = .{
            .format_id = quic_transport_parameters_extension_type,
            .format_version = quic_transport_parameters_compat_format_version,
            .bytes = encoded_bytes,
        },
    };

    // Identical to the live configuration: transport-compatible, so the
    // decision falls through to the application/H3-SETTINGS check next —
    // which fails closed as `.application_incompatible` here since this
    // candidate supplies no `remembered_application` at all. That's the
    // proof the transport check itself passed, not a transport rejection.
    try testing.expectEqual(
        tls_core.tls13_backend.EarlyDataCompatibilityDecision.application_incompatible,
        Runtime.h3EarlyDataCompatibility(@ptrCast(&runtime), candidate),
    );

    // Reduce a live limit below what was remembered.
    runtime.quic_config.initial_max_streams_bidi -= 1;
    try testing.expectEqual(
        tls_core.tls13_backend.EarlyDataCompatibilityDecision.transport_incompatible,
        Runtime.h3EarlyDataCompatibility(@ptrCast(&runtime), candidate),
    );
}

test "quicConfigFrom (#523): enable_0rtt alone never enables the 0-RTT carrier" {
    var entropy = tls_core.production_crypto.OsEntropy{};
    var provider_state = tls_core.production_crypto.Provider.init(entropy.entropy());
    var resumption = try tls_core.resumption_runtime.Runtime.init(
        testing.allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = fixedNowUnixMsForTest },
        provider_state.cryptoProvider(),
    );
    defer resumption.deinit();

    var store = try tls_core.early_data_replay.LocalStore.init(testing.allocator, .{}, 0, 0);
    defer store.deinit();
    var gate_adapter = tls_core.early_data_replay.GateAdapter.init(store.store());
    const gate = gate_adapter.gate();

    // No dependencies at all.
    try testing.expect(!quicConfigFrom(.{ .listen_host = "::", .quic_port = 443, .enable_0rtt = true }, true, false).zero_rtt_enabled);
    // Only a resumption runtime.
    try testing.expect(!quicConfigFrom(.{
        .listen_host = "::",
        .quic_port = 443,
        .enable_0rtt = true,
        .resumption_runtime = &resumption,
    }, true, false).zero_rtt_enabled);
    // Only a replay gate.
    try testing.expect(!quicConfigFrom(.{
        .listen_host = "::",
        .quic_port = 443,
        .enable_0rtt = true,
        .early_data_replay_gate = gate,
    }, true, false).zero_rtt_enabled);
    // Both dependencies present but `enable_0rtt` false (the default): still disabled.
    try testing.expect(!quicConfigFrom(.{
        .listen_host = "::",
        .quic_port = 443,
        .resumption_runtime = &resumption,
        .early_data_replay_gate = gate,
    }, true, false).zero_rtt_enabled);
    // Every dependency present: the carrier actually enables.
    try testing.expect(quicConfigFrom(.{
        .listen_host = "::",
        .quic_port = 443,
        .enable_0rtt = true,
        .resumption_runtime = &resumption,
        .early_data_replay_gate = gate,
    }, true, false).zero_rtt_enabled);
}

fn expectInvalidH3SettingsAtRuntimeInit(settings: http3.frame.Settings) !void {
    var logger = logger_mod.Logger.init(.err, "http3-invalid-settings-test");
    try testing.expectError(error.InvalidH3Settings, Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .h3_settings = settings,
    }));
}

test "runtime init rejects unsupported local H3 setting qpack_max_table_capacity" {
    try expectInvalidH3SettingsAtRuntimeInit(.{ .qpack_max_table_capacity = 1 });
}

test "runtime init rejects unsupported local H3 setting qpack_blocked_streams" {
    try expectInvalidH3SettingsAtRuntimeInit(.{ .qpack_blocked_streams = 1 });
}

test "runtime init rejects unsupported local H3 setting enable_connect_protocol" {
    try expectInvalidH3SettingsAtRuntimeInit(.{ .enable_connect_protocol = true });
}

test "runtime init rejects unsupported local H3 setting h3_datagram" {
    try expectInvalidH3SettingsAtRuntimeInit(.{ .h3_datagram = true });
}

test "runtime init rejects unsupported local H3 setting max_field_section_size" {
    try expectInvalidH3SettingsAtRuntimeInit(.{ .max_field_section_size = 1024 });
}

test "RuntimeSecrets.deinit wipes the retry token key ring and the stateless reset key" {
    var logger = logger_mod.Logger.init(.err, "http3-runtime-deinit-wipe-test");
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
    });
    // Exercise `RuntimeSecrets.deinit()` directly — the exact cleanup
    // `Runtime.deinit()` delegates to via `self.secrets.deinit()` — rather
    // than the full `Runtime.deinit()`, whose trailing `self.* = undefined`
    // poison-fills the *whole* struct in safety-checked builds. That would
    // overwrite these zeroed bytes with poison before any post-deinit byte
    // check ran, making the wipe unobservable regardless of whether it
    // happened. `RuntimeSecrets` has no such trailing assignment, so its
    // fields stay genuinely inspectable after `deinit()`. Close the socket
    // by hand since we're bypassing `Runtime.deinit()`.
    defer _ = std.c.close(runtime.socket_fd);

    // Capture raw pointers into the still-installed key storage before the
    // wipe: asserting only that lookups fail afterward would also pass an
    // implementation that never touched the key bytes, only an occupancy
    // flag/length.
    const key0_ptr: *const [quic.path.token_key_len]u8 = &runtime.secrets.retry_tokens.keys.keys[0].bytes;
    const reset_key_ptr = &runtime.secrets.stateless_reset_key;

    var saw_key_nonzero = false;
    for (key0_ptr) |b| {
        if (b != 0) saw_key_nonzero = true;
    }
    try testing.expect(saw_key_nonzero);
    var saw_reset_nonzero = false;
    for (reset_key_ptr) |b| {
        if (b != 0) saw_reset_nonzero = true;
    }
    try testing.expect(saw_reset_nonzero);

    runtime.secrets.deinit();

    for (key0_ptr) |byte| try testing.expectEqual(@as(u8, 0), byte);
    for (reset_key_ptr) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "admissionAllowed enforces global and per-source caps at the boundary" {
    // Under both caps: admitted.
    try testing.expect(admissionAllowed(0, 0));
    try testing.expect(admissionAllowed(max_connections - 1, max_connections_per_source - 1));
    // At the global cap: rejected regardless of per-source count.
    try testing.expect(!admissionAllowed(max_connections, 0));
    try testing.expect(!admissionAllowed(max_connections + 1, 0));
    // At the per-source cap: rejected regardless of global room.
    try testing.expect(!admissionAllowed(0, max_connections_per_source));
    try testing.expect(!admissionAllowed(0, max_connections_per_source + 1));
    // Either cap alone is sufficient to reject.
    try testing.expect(!admissionAllowed(max_connections, max_connections_per_source));
}

test "drainBoundaryAfter permits admitted client-bidi streams" {
    try testing.expectEqual(@as(u64, 0), drainBoundaryAfter(null));
    try testing.expectEqual(@as(u64, 4), drainBoundaryAfter(0));
    try testing.expectEqual(@as(u64, 12), drainBoundaryAfter(8));

    try testing.expect(!requestRejectedByDrainBoundary(0, 4));
    try testing.expect(requestRejectedByDrainBoundary(4, 4));
    try testing.expect(requestRejectedByDrainBoundary(8, 4));
}

test "http3 runtime (#546): a request stream rejected by Conn.pump() at local_goaway_id folds into Snapshot.h3_drain_request_rejections" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-goaway-admission-fold-test");
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
    });
    defer runtime.deinit();
    var harness = try RuntimeCidHarness.init(testing.allocator, fixed.provider());
    defer harness.deinit(testing.allocator);

    // Install the local GOAWAY boundary directly on the H3 session, exactly
    // as the "H3 conn: sent GOAWAY rejects boundary..." unit test does in
    // conn.zig — this isolates the admission-time rejection path from the
    // full drain/GOAWAY-frame machinery, which is covered separately by the
    // `drain_requested` branch this test does not touch.
    harness.entry.h3.local_goaway_id = 0;

    // The client's first bidi stream (id 0) lands exactly at that boundary,
    // so `entry.h3.pump()` rejects it during admission before it can ever
    // reach `pollRequest()` — the ordering this issue's UDP smoke flake
    // depended on being observable.
    var request_bytes: [128]u8 = undefined;
    const bytes = buildH3RequestBytesForTest("GET", "/after-goaway", "example.com", &request_bytes);
    const stream_id = try harness.client.openStream(.bidi);
    try testing.expectEqual(@as(u64, 0), stream_id);
    _ = try harness.client.writeStream(stream_id, bytes, true);
    try harness.pump();

    runtime.pumpH3(harness.entry, harness.now_us);

    try testing.expectEqual(@as(u64, 1), harness.entry.h3.metrics.goaway_request_rejections);
    try testing.expectEqual(@as(u32, 0), harness.entry.h3.requests.count());
    try testing.expectEqual(@as(usize, 1), runtime.snapshot().h3_drain_request_rejections);
}

test "http3 runtime (#546): drain boundary request rejection counts one terminal H3 request" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-drain-boundary-rejection-metrics-test");
    var latency = H3LatencyCapture{};
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .h3_request_latency_metrics_ctx = &latency,
        .h3_request_latency_metrics_cb = H3LatencyCapture.onLatency,
    });
    defer runtime.deinit();
    var harness = try RuntimeCidHarness.init(testing.allocator, fixed.provider());
    defer harness.deinit(testing.allocator);

    var request_bytes: [128]u8 = undefined;
    const bytes = buildH3RequestBytesForTest("GET", "/during-drain", "example.com", &request_bytes);
    const stream_id = try harness.client.openStream(.bidi);
    try testing.expectEqual(@as(u64, 0), stream_id);
    _ = try harness.client.writeStream(stream_id, bytes, true);
    try harness.pump();

    runtime.drain_requested.store(true, .release);
    runtime.pumpH3(harness.entry, harness.now_us);

    try testing.expectEqual(@as(usize, 1), runtime.snapshot().h3_drain_request_rejections);
    try testing.expectEqual(@as(usize, 1), runtime.snapshot().requests_completed);
    try testing.expectEqual(@as(usize, 1), latency.count);
}

test "http3 runtime metrics: handler error counts one terminal H3 request" {
    const Handler = struct {
        fn fail(
            _: std.mem.Allocator,
            _: *const http3_session.StreamRequest,
            _: *response_mod.Response,
            _: ?*anyopaque,
        ) anyerror!void {
            return error.IntentionalHandlerFailure;
        }
    };
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-handler-error-metrics-test");
    var latency = H3LatencyCapture{};
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .request_handler = Handler.fail,
        .h3_request_latency_metrics_ctx = &latency,
        .h3_request_latency_metrics_cb = H3LatencyCapture.onLatency,
    });
    defer runtime.deinit();
    var harness = try RuntimeCidHarness.init(testing.allocator, fixed.provider());
    defer harness.deinit(testing.allocator);

    runtime.serveRequest(harness.entry, .{
        .stream_id = 0,
        .exchange = .{
            .request = .{
                .method = "GET",
                .scheme = "https",
                .authority = "example.com",
                .path = "/handler-error",
            },
            .body = .none,
        },
        .transport_early = false,
        .priority = .{},
    }, harness.now_us);

    try testing.expectEqual(@as(usize, 1), latency.count);
    try testing.expectEqual(@as(usize, 1), runtime.snapshot().requests_completed);
}

test "classifyIngest routes spoofed Initials, migration, and normal traffic" {
    // Freshly accepted + first datagram authenticates nothing -> spoofed
    // Initial, torn down. The source-changed flag never overrides this: a
    // freshly accepted entry's peer is exactly the datagram's source.
    try testing.expectEqual(IngestOutcome.drop_unauthenticated, classifyIngest(true, false, false));
    try testing.expectEqual(IngestOutcome.drop_unauthenticated, classifyIngest(true, false, true));

    // Freshly accepted + authenticated (a legitimate Initial) -> keep and let
    // the handshake proceed.
    try testing.expectEqual(IngestOutcome.keep, classifyIngest(true, true, false));

    // Established connection, authenticated packet from a new source -> counted
    // as a migration attempt, not followed.
    try testing.expectEqual(IngestOutcome.migrated, classifyIngest(false, true, true));

    // Authenticated packet from the same source -> ordinary traffic.
    try testing.expectEqual(IngestOutcome.keep, classifyIngest(false, true, false));

    // Unauthenticated packet from a new source on an existing connection is
    // ignored (never promoted to a migration event): the source is untrusted.
    try testing.expectEqual(IngestOutcome.keep, classifyIngest(false, false, true));
    try testing.expectEqual(IngestOutcome.keep, classifyIngest(false, false, false));
}

test "per-source admission counter increments and prunes to empty" {
    var per_ip = std.AutoHashMap(u32, u32).init(testing.allocator);
    defer per_ip.deinit();
    try incPerIp(&per_ip, 0x0100007f);
    try incPerIp(&per_ip, 0x0100007f);
    try testing.expectEqual(@as(u32, 2), per_ip.get(0x0100007f).?);
    decPerIp(&per_ip, 0x0100007f);
    try testing.expectEqual(@as(u32, 1), per_ip.get(0x0100007f).?);
    decPerIp(&per_ip, 0x0100007f);
    try testing.expect(per_ip.get(0x0100007f) == null);
    // Decrementing an unknown address is a no-op, not a crash.
    decPerIp(&per_ip, 0xdeadbeef);
}

const TestParkedContinuationState = struct {
    run_calls: usize = 0,
    deinit_calls: usize = 0,
    fail_run: bool = false,

    fn run(ctx: *anyopaque, allocator: std.mem.Allocator, response: *response_mod.Response) !void {
        _ = allocator;
        const self: *TestParkedContinuationState = @ptrCast(@alignCast(ctx));
        self.run_calls += 1;
        if (self.fail_run) return error.TestParkedContinuationFailed;
        _ = response.setStatus(.ok).setBody("resumed");
    }

    fn deinit(ctx: *anyopaque, allocator: std.mem.Allocator) void {
        _ = allocator;
        const self: *TestParkedContinuationState = @ptrCast(@alignCast(ctx));
        self.deinit_calls += 1;
    }

    fn continuation(self: *TestParkedContinuationState) http3_session.StreamRequest.Early425RetryContinuation {
        return .{
            .ctx = self,
            .resume_fn = run,
            .deinit_fn = deinit,
        };
    }
};

const TestH3ResumeConn = struct {
    established: bool = false,
    reset_calls: usize = 0,
    last_reset_stream_id: u64 = 0,

    fn isEstablished(self: *TestH3ResumeConn) bool {
        return self.established;
    }

    fn resetStream(self: *TestH3ResumeConn, stream_id: u64, code: u64) !void {
        _ = code;
        self.reset_calls += 1;
        self.last_reset_stream_id = stream_id;
    }
};

const TestH3ResumeSession = struct {
    pub const ResponseSendState = H3.ResponseSendState;

    send_calls: usize = 0,
    ok_sends: usize = 0,
    internal_error_sends: usize = 0,
    finish_calls: usize = 0,
    send_fail: bool = false,
    backpressure_before_success: usize = 0,
    last_status: u16 = 0,
    last_stream_id: u64 = 0,
    last_body_len: usize = 0,

    fn sendResponseProgress(
        self: *TestH3ResumeSession,
        conn: *TestH3ResumeConn,
        stream_id: u64,
        state: *ResponseSendState,
    ) !bool {
        _ = conn;
        self.send_calls += 1;
        self.last_status = state.status;
        self.last_stream_id = stream_id;
        self.last_body_len = state.body.len;
        if (state.status == 200) self.ok_sends += 1;
        if (state.status == 500) self.internal_error_sends += 1;
        if (self.send_fail) return error.StreamBackpressure;
        if (self.backpressure_before_success > 0) {
            self.backpressure_before_success -= 1;
            return false;
        }
        self.finishRequest(stream_id);
        return true;
    }

    fn finishRequest(self: *TestH3ResumeSession, stream_id: u64) void {
        self.finish_calls += 1;
        self.last_stream_id = stream_id;
    }
};

const TestH3ResumeEntry = struct {
    conn: *TestH3ResumeConn,
    h3: TestH3ResumeSession = .{},
    parked_h3_retries: std.ArrayList(ParkedH3Retry) = .empty,
    pending_h3_responses: std.ArrayList(PendingH3Response) = .empty,

    fn deinit(self: *TestH3ResumeEntry, allocator: std.mem.Allocator) void {
        for (self.parked_h3_retries.items) |*parked| parked.deinit(allocator);
        self.parked_h3_retries.deinit(allocator);
        for (self.pending_h3_responses.items) |*pending| pending.deinit(allocator);
        self.pending_h3_responses.deinit(allocator);
    }
};

const H3LatencyCapture = struct {
    count: usize = 0,
    last_ms: u64 = 0,

    fn onLatency(ctx: *anyopaque, latency_ms: u64) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.count += 1;
        self.last_ms = latency_ms;
    }
};

const RuntimeMetricCapture = struct {
    active_calls: usize = 0,
    last_active: usize = 0,
    delta: metrics_mod.QuicTransportDelta = .{},
    handshake_failures: usize = 0,
    handshake_failures_by_stage: [2]usize = .{ 0, 0 },

    fn onActive(ctx: *anyopaque, active: usize) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.active_calls += 1;
        self.last_active = active;
    }

    fn onDelta(ctx: *anyopaque, delta: metrics_mod.QuicTransportDelta) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.delta.retry += delta.retry;
        self.delta.amplification_blocked += delta.amplification_blocked;
        self.delta.pto += delta.pto;
        self.delta.packets_lost += delta.packets_lost;
        self.delta.bytes_sent += delta.bytes_sent;
        self.delta.bytes_received += delta.bytes_received;
        self.delta.stream_resets += delta.stream_resets;
        self.delta.connection_flow_blocked += delta.connection_flow_blocked;
        self.delta.stream_flow_blocked += delta.stream_flow_blocked;
        self.delta.deprotection_failures += delta.deprotection_failures;
    }

    fn onHandshakeFailure(ctx: *anyopaque, stage: metrics_mod.QuicHandshakeFailureStage) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.handshake_failures += 1;
        const idx: usize = switch (stage) {
            .initial => 0,
            .handshake => 1,
        };
        self.handshake_failures_by_stage[idx] += 1;
    }
};

const MetricsBridgeCapture = struct {
    metrics: metrics_mod.Metrics,

    fn onActive(ctx: *anyopaque, active: usize) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.metrics.setQuicConnectionsActive(active);
    }

    fn onDelta(ctx: *anyopaque, delta: metrics_mod.QuicTransportDelta) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.metrics.recordQuicTransportDelta(delta);
    }

    fn onHandshakeFailure(ctx: *anyopaque, stage: metrics_mod.QuicHandshakeFailureStage) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.metrics.recordQuicHandshakeFailure(stage);
    }

    fn onLatency(ctx: *anyopaque, latency_ms: u64) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.metrics.recordH3RequestLatency(latency_ms);
    }
};

test "parked H3 retry resumes only after connection establishment" {
    const allocator = testing.allocator;
    var logger = logger_mod.Logger.init(.err, "http3-parked-resume-test");
    var latency = H3LatencyCapture{};
    var runtime = try Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .h3_request_latency_metrics_ctx = &latency,
        .h3_request_latency_metrics_cb = H3LatencyCapture.onLatency,
    });
    defer runtime.deinit();

    var conn = TestH3ResumeConn{};
    var entry = TestH3ResumeEntry{ .conn = &conn };
    defer entry.deinit(allocator);
    var continuation = TestParkedContinuationState{};
    try entry.parked_h3_retries.append(allocator, .{
        .stream_id = 11,
        .started_us = 1,
        .continuation = continuation.continuation(),
    });

    runtime.resumeParkedH3RetriesForEntry(&entry);
    try testing.expectEqual(@as(usize, 1), entry.parked_h3_retries.items.len);
    try testing.expectEqual(@as(usize, 0), continuation.run_calls);
    try testing.expectEqual(@as(usize, 0), entry.h3.send_calls);

    conn.established = true;
    runtime.resumeParkedH3RetriesForEntry(&entry);
    try testing.expectEqual(@as(usize, 0), entry.parked_h3_retries.items.len);
    try testing.expectEqual(@as(usize, 1), continuation.run_calls);
    try testing.expectEqual(@as(usize, 1), continuation.deinit_calls);
    try testing.expectEqual(@as(usize, 1), entry.h3.send_calls);
    try testing.expectEqual(@as(u16, 200), entry.h3.last_status);
    try testing.expectEqual(@as(u64, 11), entry.h3.last_stream_id);
    try testing.expectEqual(@as(usize, 1), latency.count);
    try testing.expect(latency.last_ms > 0);
}

test "H3 runtime parks backpressured response and resumes completion once" {
    const allocator = testing.allocator;
    var logger = logger_mod.Logger.init(.err, "http3-response-backpressure-test");
    var latency = H3LatencyCapture{};
    var runtime = try Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .h3_request_latency_metrics_ctx = &latency,
        .h3_request_latency_metrics_cb = H3LatencyCapture.onLatency,
    });
    defer runtime.deinit();

    var conn = TestH3ResumeConn{ .established = true };
    var entry = TestH3ResumeEntry{
        .conn = &conn,
        .h3 = .{ .backpressure_before_success = 1 },
    };
    defer entry.deinit(allocator);

    const body = try allocator.alloc(u8, quic.connection.max_stream_send_buffer + 1);
    defer allocator.free(body);
    @memset(body, 0xab);

    runtime.queueH3Response(&entry, 17, 1, 200, &.{.{ .name = "server", .value = "tardigrade" }}, body, "test");

    try testing.expectEqual(@as(usize, 1), entry.h3.send_calls);
    try testing.expectEqual(@as(usize, 1), entry.pending_h3_responses.items.len);
    try testing.expectEqual(@as(usize, 0), conn.reset_calls);
    try testing.expectEqual(@as(usize, 0), entry.h3.finish_calls);
    try testing.expectEqual(@as(usize, 0), latency.count);
    try testing.expectEqual(@as(usize, quic.connection.max_stream_send_buffer + 1), entry.h3.last_body_len);

    runtime.resumePendingH3Responses(&entry, 2);

    try testing.expectEqual(@as(usize, 2), entry.h3.send_calls);
    try testing.expectEqual(@as(usize, 0), entry.pending_h3_responses.items.len);
    try testing.expectEqual(@as(usize, 0), conn.reset_calls);
    try testing.expectEqual(@as(usize, 1), entry.h3.finish_calls);
    try testing.expectEqual(@as(u64, 17), entry.h3.last_stream_id);
    try testing.expectEqual(@as(usize, 1), latency.count);
    try testing.expect(latency.last_ms > 0);
}

test "parked H3 retry fallback send failure resets and finishes stream once" {
    const allocator = testing.allocator;
    var logger = logger_mod.Logger.init(.err, "http3-parked-fallback-test");
    var runtime = try Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
    });
    defer runtime.deinit();

    var conn = TestH3ResumeConn{ .established = true };
    var entry = TestH3ResumeEntry{
        .conn = &conn,
        .h3 = .{ .send_fail = true },
    };
    defer entry.deinit(allocator);
    var continuation = TestParkedContinuationState{ .fail_run = true };
    try entry.parked_h3_retries.append(allocator, .{
        .stream_id = 13,
        .started_us = 1,
        .continuation = continuation.continuation(),
    });

    runtime.resumeParkedH3RetriesForEntry(&entry);

    try testing.expectEqual(@as(usize, 0), entry.parked_h3_retries.items.len);
    try testing.expectEqual(@as(usize, 1), continuation.run_calls);
    try testing.expectEqual(@as(usize, 1), continuation.deinit_calls);
    try testing.expectEqual(@as(usize, 1), entry.h3.send_calls);
    try testing.expectEqual(@as(usize, 1), conn.reset_calls);
    try testing.expectEqual(@as(usize, 1), entry.h3.finish_calls);
    try testing.expectEqual(@as(u64, 13), conn.last_reset_stream_id);
    try testing.expectEqual(@as(u64, 13), entry.h3.last_stream_id);
}

test "H3 terminal response send failures are counted exactly once" {
    const allocator = testing.allocator;
    var logger = logger_mod.Logger.init(.err, "http3-terminal-send-failure-metrics-test");
    var latency = H3LatencyCapture{};
    var runtime = try Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .h3_request_latency_metrics_ctx = &latency,
        .h3_request_latency_metrics_cb = H3LatencyCapture.onLatency,
    });
    defer runtime.deinit();

    var conn = TestH3ResumeConn{ .established = true };
    var entry = TestH3ResumeEntry{
        .conn = &conn,
        .h3 = .{ .send_fail = true },
    };
    defer entry.deinit(allocator);
    var response = response_mod.Response.init(allocator);
    defer response.deinit();
    response.status = .ok;

    runtime.sendHandlerResponse(&entry, 41, &response, 1);
    try testing.expectEqual(@as(usize, 1), latency.count);
    try testing.expectEqual(@as(usize, 1), entry.h3.send_calls);
    try testing.expectEqual(@as(usize, 1), conn.reset_calls);
    try testing.expectEqual(@as(usize, 1), entry.h3.finish_calls);

    runtime.sendInternalErrorResponse(&entry, 43, 1);
    try testing.expectEqual(@as(usize, 2), latency.count);
    try testing.expectEqual(@as(usize, 2), entry.h3.send_calls);
    try testing.expectEqual(@as(usize, 2), conn.reset_calls);
    try testing.expectEqual(@as(usize, 2), entry.h3.finish_calls);
}

test "failed parked H3 retry does not stop later parked retry" {
    const allocator = testing.allocator;
    var logger = logger_mod.Logger.init(.err, "http3-parked-drain-test");
    var runtime = try Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
    });
    defer runtime.deinit();

    var conn = TestH3ResumeConn{ .established = true };
    var entry = TestH3ResumeEntry{ .conn = &conn };
    defer entry.deinit(allocator);
    var failed = TestParkedContinuationState{ .fail_run = true };
    var resumed = TestParkedContinuationState{};
    try entry.parked_h3_retries.append(allocator, .{
        .stream_id = 21,
        .started_us = 1,
        .continuation = failed.continuation(),
    });
    try entry.parked_h3_retries.append(allocator, .{
        .stream_id = 23,
        .started_us = 1,
        .continuation = resumed.continuation(),
    });

    runtime.resumeParkedH3RetriesForEntry(&entry);

    try testing.expectEqual(@as(usize, 0), entry.parked_h3_retries.items.len);
    try testing.expectEqual(@as(usize, 1), failed.run_calls);
    try testing.expectEqual(@as(usize, 1), failed.deinit_calls);
    try testing.expectEqual(@as(usize, 1), resumed.run_calls);
    try testing.expectEqual(@as(usize, 1), resumed.deinit_calls);
    try testing.expectEqual(@as(usize, 2), entry.h3.send_calls);
    try testing.expectEqual(@as(usize, 1), entry.h3.internal_error_sends);
    try testing.expectEqual(@as(usize, 1), entry.h3.ok_sends);
    try testing.expectEqual(@as(usize, 0), conn.reset_calls);
    try testing.expectEqual(@as(u64, 23), entry.h3.last_stream_id);
}

test "failed parked H3 retry reset path does not stop later parked retry" {
    const allocator = testing.allocator;
    var logger = logger_mod.Logger.init(.err, "http3-parked-reset-drain-test");
    var runtime = try Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
    });
    defer runtime.deinit();

    var conn = TestH3ResumeConn{ .established = true };
    var entry = TestH3ResumeEntry{
        .conn = &conn,
        .h3 = .{ .send_fail = true },
    };
    defer entry.deinit(allocator);
    var failed = TestParkedContinuationState{ .fail_run = true };
    var resumed = TestParkedContinuationState{};
    try entry.parked_h3_retries.append(allocator, .{
        .stream_id = 31,
        .started_us = 1,
        .continuation = failed.continuation(),
    });
    try entry.parked_h3_retries.append(allocator, .{
        .stream_id = 33,
        .started_us = 1,
        .continuation = resumed.continuation(),
    });

    runtime.resumeParkedH3RetriesForEntry(&entry);

    try testing.expectEqual(@as(usize, 0), entry.parked_h3_retries.items.len);
    try testing.expectEqual(@as(usize, 1), failed.run_calls);
    try testing.expectEqual(@as(usize, 1), failed.deinit_calls);
    try testing.expectEqual(@as(usize, 1), resumed.run_calls);
    try testing.expectEqual(@as(usize, 1), resumed.deinit_calls);
    try testing.expectEqual(@as(usize, 2), entry.h3.send_calls);
    try testing.expectEqual(@as(usize, 2), conn.reset_calls);
    try testing.expectEqual(@as(usize, 2), entry.h3.finish_calls);
    try testing.expectEqual(@as(u64, 33), conn.last_reset_stream_id);
}

test "runtime borrows the credential provider and owns no key material" {
    // Structural guarantee (#392): the runtime has no owned identity, DER, or
    // key buffers to leak — only the borrowed provider handle.
    comptime {
        for (@typeInfo(Runtime).@"struct".fields) |field| {
            std.debug.assert(!std.mem.eql(u8, field.name, "identity"));
            std.debug.assert(!std.mem.eql(u8, field.name, "cert_der"));
            std.debug.assert(!std.mem.eql(u8, field.name, "key_der"));
        }
    }

    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-test");

    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
    });
    try testing.expect(runtime.snapshot().server_bootstrapped);
    runtime.deinit();

    // Tearing the runtime down must not release the shared provider: the
    // same instance keeps serving native TCP TLS selections.
    var selection = tls_core.credentials.SelectionContext{
        .role = .server,
        .server_name = null,
        .peer_signature_schemes = &.{0x0807},
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = "h2",
        .auth_policy = .{},
    };
    switch (try fixed.provider().selectCredential(&selection)) {
        .complete => |credential| credential.release(),
        .pending => return error.TestUnexpectedPending,
    }

    var unbootstrapped = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
    });
    try testing.expect(!unbootstrapped.snapshot().server_bootstrapped);
    unbootstrapped.deinit();
}

fn fixedNowUnixMsForTest(_: *anyopaque) i64 {
    return 1000;
}

test "runtime borrows the resumption runtime and installs it per accepted connection" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-resumption-test");

    var entropy = tls_core.production_crypto.OsEntropy{};
    var provider_state = tls_core.production_crypto.Provider.init(entropy.entropy());
    var resumption = try tls_core.resumption_runtime.Runtime.init(
        testing.allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = fixedNowUnixMsForTest },
        provider_state.cryptoProvider(),
    );
    defer resumption.deinit();

    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .resumption_runtime = &resumption,
    });
    defer runtime.deinit();

    try testing.expectEqual(@as(?*tls_core.resumption_runtime.Runtime, &resumption), runtime.resumption_runtime);
}

test "runtime borrows the early-data replay gate independently of the resumption runtime" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-replay-gate-test");

    var store = try tls_core.early_data_replay.LocalStore.init(testing.allocator, .{}, 0, 0);
    defer store.deinit();
    var adapter = tls_core.early_data_replay.GateAdapter.init(store.store());
    const gate = adapter.gate();

    // No `resumption_runtime` supplied: the replay gate must still install,
    // proving it is not gated on resumption plumbing.
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .early_data_replay_gate = gate,
    });
    defer runtime.deinit();

    const installed = runtime.early_data_replay_gate orelse return error.TestExpectedEqual;
    try testing.expectEqual(gate.ctx, installed.ctx);
    try testing.expectEqual(gate.decideFn, installed.decideFn);
}

test "runtime (#523): enable_0rtt enables the carrier only with complete composition, fails closed otherwise" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-0rtt-composition-test");

    var entropy = tls_core.production_crypto.OsEntropy{};
    var provider_state = tls_core.production_crypto.Provider.init(entropy.entropy());
    var resumption = try tls_core.resumption_runtime.Runtime.init(
        testing.allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = fixedNowUnixMsForTest },
        provider_state.cryptoProvider(),
    );
    defer resumption.deinit();

    var store = try tls_core.early_data_replay.LocalStore.init(testing.allocator, .{}, 0, 0);
    defer store.deinit();
    var gate_adapter = tls_core.early_data_replay.GateAdapter.init(store.store());
    const gate = gate_adapter.gate();

    // enable_0rtt requested but the replay gate is missing: fails closed.
    var incomplete = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .resumption_runtime = &resumption,
        .enable_0rtt = true,
    });
    defer incomplete.deinit();
    try testing.expect(!incomplete.zero_rtt_enabled);
    try testing.expect(!incomplete.quic_config.zero_rtt_enabled);

    // `enable_0rtt = false` (the default) stays disabled even with full
    // composition otherwise present.
    var disabled = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .resumption_runtime = &resumption,
        .early_data_replay_gate = gate,
    });
    defer disabled.deinit();
    try testing.expect(!disabled.zero_rtt_enabled);

    // Every dependency present: the carrier actually enables, and that same
    // decision reaches the QUIC transport config `accept()` hands every new
    // connection.
    var complete = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .resumption_runtime = &resumption,
        .early_data_replay_gate = gate,
        .enable_0rtt = true,
    });
    defer complete.deinit();
    try testing.expect(complete.zero_rtt_enabled);
    try testing.expect(complete.quic_config.zero_rtt_enabled);
}

test "runtime (#523): a present-but-unusable resumption runtime or replay gate still fails closed" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-0rtt-usability-test");

    var entropy = tls_core.production_crypto.OsEntropy{};
    var provider_state = tls_core.production_crypto.Provider.init(entropy.entropy());

    // A `.mode = .disabled` resumption runtime is non-null but yields no PSK
    // resolver (`serverResolver() == null`) — `accept()` would install no
    // resolver at all, so the carrier must not report itself enabled.
    var disabled_mode_resumption = try tls_core.resumption_runtime.Runtime.init(
        testing.allocator,
        .{ .mode = .disabled },
        .{ .ctx = undefined, .nowUnixMsFn = fixedNowUnixMsForTest },
        provider_state.cryptoProvider(),
    );
    defer disabled_mode_resumption.deinit();

    var store = try tls_core.early_data_replay.LocalStore.init(testing.allocator, .{}, 0, 0);
    defer store.deinit();
    var gate_adapter = tls_core.early_data_replay.GateAdapter.init(store.store());
    const usable_gate = gate_adapter.gate();

    var disabled_mode = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .resumption_runtime = &disabled_mode_resumption,
        .early_data_replay_gate = usable_gate,
        .enable_0rtt = true,
    });
    defer disabled_mode.deinit();
    try testing.expect(!disabled_mode.zero_rtt_enabled);

    // A default-constructed `EarlyDataReplayGate` (`decideFn == null`) is
    // non-null but fails closed (`.unavailable`) for every attempt on its
    // own — installing it doesn't make the carrier usable either.
    var usable_resumption = try tls_core.resumption_runtime.Runtime.init(
        testing.allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = fixedNowUnixMsForTest },
        provider_state.cryptoProvider(),
    );
    defer usable_resumption.deinit();

    var unconfigured_gate = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .resumption_runtime = &usable_resumption,
        .early_data_replay_gate = .{},
        .enable_0rtt = true,
    });
    defer unconfigured_gate.deinit();
    try testing.expect(!unconfigured_gate.zero_rtt_enabled);

    // Sanity: both dependencies actually usable enables it, confirming the
    // two cases above are real negatives and not an over-broad check.
    var usable = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .resumption_runtime = &usable_resumption,
        .early_data_replay_gate = usable_gate,
        .enable_0rtt = true,
    });
    defer usable.deinit();
    try testing.expect(usable.zero_rtt_enabled);
}

test "issueSessionTicket (#523): the production issuer advertises QUIC 0-RTT capability only when the carrier is enabled" {
    const allocator = testing.allocator;
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-ticket-issuance-test");

    var entropy = tls_core.production_crypto.OsEntropy{};
    var provider_state = tls_core.production_crypto.Provider.init(entropy.entropy());
    var resumption = try tls_core.resumption_runtime.Runtime.init(
        testing.allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = fixedNowUnixMsForTest },
        provider_state.cryptoProvider(),
    );
    defer resumption.deinit();

    var store = try tls_core.early_data_replay.LocalStore.init(testing.allocator, .{}, 0, 0);
    defer store.deinit();
    var gate_adapter = tls_core.early_data_replay.GateAdapter.init(store.store());
    const gate = gate_adapter.gate();

    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .resumption_runtime = &resumption,
        .early_data_replay_gate = gate,
        .enable_0rtt = true,
    });
    defer runtime.deinit();
    try testing.expect(runtime.zero_rtt_enabled);

    // Build a real, established client/server QUIC pair directly (not via
    // `runtime.accept()`, which needs a real UDP round trip) —
    // `prepareNewSessionTicket` requires a genuine post-handshake
    // resumption master secret, so there is no shortcut around a real
    // handshake. This mirrors `quic.connection`'s own private `TestPair`,
    // which isn't reachable from this file.
    const client_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_path = quic.path.PathKey{
        .local = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_200),
        .remote = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_201),
    };
    const server_path = quic.path.PathKey{
        .local = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_201),
        .remote = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_200),
    };
    const no_challenge = [_]u8{0} ** quic.path.path_challenge_len;

    var client_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
    var client_backend = try quic.tls_backend.Tls13Backend.initClientWithAllocator(
        allocator,
        .{ .hello_random = [_]u8{0xc1} ** 32 },
        client_provider_storage.init(0x442_c),
        .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
    );

    const Capture = struct {
        retained: tls_core.session.ClientTicketState = .{},
        count: usize = 0,

        fn now(_: *anyopaque) i64 {
            return 1000;
        }
        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            ticket.cloneInto(testing.allocator, &self.retained) catch unreachable;
            self.count += 1;
        }
    };
    var capture = Capture{};
    defer capture.retained.deinit();
    try client_backend.engine.setSessionTicketConsumer(allocator, tls_core.session.Limits.default, .{
        .ctx = &capture,
        .nowUnixMsFn = Capture.now,
        .onTicketFn = Capture.onTicket,
    });

    const backend = try allocator.create(quic.tls_backend.Tls13Backend);
    var backend_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
    backend.* = quic.tls_backend.Tls13Backend.initServerWithProvider(
        .{ .hello_random = [_]u8{0x51} ** 32 },
        backend_provider_storage.init(0x442_5),
        fixed.provider(),
    );

    const client = try Connection.init(allocator, .{
        .role = .client,
        .local_cid = &client_cid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .peer_cid = &odcid,
        .tls = client_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = 1_000_000,
        .initial_path = client_path,
    });
    defer client.deinit();
    const server_conn = try Connection.init(allocator, .{
        .role = .server,
        .local_cid = &odcid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .peer_cid = &client_cid,
        .tls = backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = 1_000_000,
        .initial_path = server_path,
    });

    var entry = ConnEntry{
        .backend = backend,
        .conn = server_conn,
        .h3 = H3.initWithSettings(allocator, .server, .{}),
        .admission_source_ip = 0,
        .cid_len = odcid.len,
        .accepted_at_us = 1_000_000,
    };
    defer entry.deinit(allocator);

    var rounds: usize = 0;
    while (rounds < 64) : (rounds += 1) {
        var progressed = false;
        var buf: [2048]u8 = undefined;
        while (client.pollTransmitOnPath(&buf, 1_000_000)) |t| {
            try entry.conn.ingestOnPath(t.bytes, server_path, no_challenge, 1_000_000);
            progressed = true;
        }
        while (entry.conn.pollTransmitOnPath(&buf, 1_000_000)) |t| {
            try client.ingestOnPath(t.bytes, client_path, no_challenge, 1_000_000);
            progressed = true;
        }
        if (!progressed) break;
    }
    try testing.expect(client.isEstablished());
    try testing.expect(entry.conn.isEstablished());

    try runtime.issueSessionTicket(&entry, &resumption);

    // Deliver the queued NewSessionTicket CRYPTO data to the client.
    var rounds2: usize = 0;
    while (rounds2 < 16) : (rounds2 += 1) {
        var progressed = false;
        var buf: [2048]u8 = undefined;
        while (entry.conn.pollTransmitOnPath(&buf, 1_000_000)) |t| {
            try client.ingestOnPath(t.bytes, client_path, no_challenge, 1_000_000);
            progressed = true;
        }
        while (client.pollTransmitOnPath(&buf, 1_000_000)) |t| {
            try entry.conn.ingestOnPath(t.bytes, server_path, no_challenge, 1_000_000);
            progressed = true;
        }
        if (!progressed) break;
    }

    try testing.expectEqual(@as(usize, 1), capture.count);
    // #523: the production issuer must advertise QUIC 0-RTT capability with
    // the RFC 9001 §4.6.1 sentinel now that the carrier is actually
    // enabled — a ticket a resumed client can genuinely attempt 0-RTT with,
    // not one silently limited to resume-only.
    try testing.expectEqual(
        tls_core.session.EarlyDataPolicy{ .early_data_capable = std.math.maxInt(u32) },
        capture.retained.common.early_data,
    );
}

/// #523 test-only: seal a 0-RTT wire packet exactly the way a real client
/// sender would, mirroring `quic.connection`'s private `sealTestZeroRttPacket`
/// (not reachable from this file). The helper uses the resumed ticket's
/// early-data profile, so a receiver with the same profile and bytes installed
/// at `.zero_rtt read` genuinely decrypts this.
fn sealZeroRttPacketForTest(
    dcid: []const u8,
    scid: []const u8,
    secret: [quic.tls_adapter.traffic_secret_len]u8,
    pn: u64,
    plaintext: []const u8,
    out: []u8,
) []u8 {
    var sender = quic.tls_adapter.QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
    sender.installEarlyDataParameters(.{
        .cipher_suite = @intFromEnum(tls_core.algorithms.CipherSuite.tls_aes_128_gcm_sha256),
        .transcript_hash = .sha256,
    }) catch unreachable;
    sender.setZeroRttEnabled(true);
    sender.installSecret(quic.tls_adapter.Secret.init(.zero_rtt, .write, &secret) catch unreachable);

    const pn_len: u3 = quic.packet.packetNumberLength(pn, null);
    const written = quic.packet.writeLongHeader(.zero_rtt, quic.packet.quic_v1, dcid, scid, "", pn_len, out) catch unreachable;
    const pn_offset = written.pn_offset;

    var padded: [1024]u8 = undefined;
    const sample_min = (4 - @as(usize, pn_len)) + quic.tls_adapter.header_protection_sample_len - quic.tls_adapter.packet_protection_tag_len;
    const padded_len = @max(plaintext.len, sample_min);
    @memcpy(padded[0..plaintext.len], plaintext);
    @memset(padded[plaintext.len..padded_len], 0);

    // The Length field precedes `pn_offset` and is covered by the AEAD
    // associated data, so it must be patched before sealing.
    quic.packet.patchLongHeaderLength(out, written.length_offset, pn_len + padded_len + quic.tls_adapter.packet_protection_tag_len);

    const truncated = quic.packet.truncatePacketNumber(pn, pn_len);
    var pn_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &pn_bytes, truncated, .big);
    @memcpy(out[pn_offset..][0..pn_len], pn_bytes[4 - @as(usize, pn_len) ..][0..pn_len]);

    const header = out[0 .. pn_offset + pn_len];
    var keys = (sender.protectionKeys(.zero_rtt, .write) catch unreachable).?;
    defer keys.deinit();
    _ = sender.sealPacketPayload(.zero_rtt, .write, pn, header, padded[0..padded_len], out[pn_offset + pn_len ..]) catch unreachable;

    var sample: [quic.tls_adapter.header_protection_sample_len]u8 = undefined;
    @memcpy(&sample, out[pn_offset + 4 ..][0..quic.tls_adapter.header_protection_sample_len]);
    keys.applyHeaderProtectionWithProvider(sender.provider, &out[0], out[pn_offset..][0..pn_len], sample) catch unreachable;

    return out[0 .. pn_offset + pn_len + padded_len + quic.tls_adapter.packet_protection_tag_len];
}

/// #523 test-only: encode a real HTTP/3 request (QPACK HEADERS frame, no
/// body) — the same primitives `http3.conn.Conn.sendRequest` uses — so the
/// production H3 request parser genuinely has to decode this, not a
/// synthetic shortcut.
fn buildH3RequestBytesForTest(method: []const u8, path: []const u8, authority: []const u8, out: []u8) []const u8 {
    var fields = [_]http3.qpack.HeaderField{
        .{ .name = ":method", .value = method },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = authority },
        .{ .name = ":path", .value = path },
    };
    var block: [256]u8 = undefined;
    const header_block = http3.qpack.encode(&fields, &block) catch unreachable;
    return http3.frame.encodeKnownFrame(.headers, header_block, out) catch unreachable;
}

/// #523 test-only: an embedder-shaped request handler using the actual
/// shared, transport-neutral early-data policy (`http.early_data.decide`,
/// the same primitive `gateway_handlers.zig`'s production routing uses) —
/// not a second, test-invented safety layer. `action_class = .local`
/// mirrors an origin server (not a reverse proxy), the shape
/// `http3_runtime.Config.request_handler` is meant for.
const TestEarlyDataHandlerState = struct {
    executed_local: usize = 0,
    rejected_too_early: usize = 0,
    last_method_buf: [8]u8 = undefined,
    last_method_len: usize = 0,
};

fn testEarlyDataAwareHandler(
    _: std.mem.Allocator,
    request: *const http3_session.StreamRequest,
    response: *response_mod.Response,
    user_data: ?*anyopaque,
) anyerror!void {
    const state: *TestEarlyDataHandlerState = @ptrCast(@alignCast(user_data.?));
    const decision = early_data_policy.decide(.{
        .replay_exposed = request.transport_early,
        .transport_early = request.transport_early,
        .inbound_marker = false,
        .method_safe = early_data_policy.methodSafe(request.method),
        .route_replay_safe = true,
        .action_class = .local,
        .proxy_origin_rfc8470 = false,
    });
    switch (decision) {
        .too_early => {
            state.rejected_too_early += 1;
            response.status = .too_early;
        },
        .ordinary, .execute_local => {
            state.executed_local += 1;
            const len = @min(request.method.len, state.last_method_buf.len);
            @memcpy(state.last_method_buf[0..len], request.method[0..len]);
            state.last_method_len = len;
            response.status = .ok;
        },
        .forward_rfc8470, .defer_until_handshake => unreachable, // action_class = .local never yields these
    }
}

test "http3 (#523): a replay-safe early request reaches the local handler exactly once; an unsafe one is rejected without dispatch; ordinary post-handshake requests still work" {
    const allocator = testing.allocator;
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-early-request-matrix-test");

    var server_entropy = tls_core.production_crypto.OsEntropy{};
    var server_provider_state = tls_core.production_crypto.Provider.init(server_entropy.entropy());
    var resumption = try tls_core.resumption_runtime.Runtime.init(
        testing.allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = fixedNowUnixMsForTest },
        server_provider_state.cryptoProvider(),
    );
    defer resumption.deinit();

    // A separate client-side runtime instance for storing/looking up the
    // client's own tickets — the server-side `resumption` above and this
    // one play distinct roles, exactly as they would across two real
    // processes, matching the pattern the #488 connection-level tests use.
    var client_entropy = tls_core.production_crypto.OsEntropy{};
    var client_provider_state = tls_core.production_crypto.Provider.init(client_entropy.entropy());
    var client_resumption = try tls_core.resumption_runtime.Runtime.init(
        testing.allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = fixedNowUnixMsForTest },
        client_provider_state.cryptoProvider(),
    );
    defer client_resumption.deinit();

    // `LocalStore`'s real `claim()` path reads real wall-clock time
    // (`trampolineClaim` → `zig_compat.milliTimestamp()`), while this
    // test's resumption clock is a small fixed value for determinism —
    // those would never agree on a retention window. An always-allow gate
    // still installs through the exact same `EarlyDataReplayGate` seam
    // production composition uses (proving that seam, not a second policy
    // layer); `LocalStore`'s own real-clock claim behavior has its own
    // dedicated test coverage elsewhere.
    const AlwaysAllow = struct {
        fn decide(_: *anyopaque, _: tls_core.tls13_backend.EarlyDataReplayCandidate) tls_core.tls13_backend.EarlyDataReplayDecision {
            return .allow;
        }
    };
    var replay_ctx: u8 = 0;
    const gate: tls_core.tls13_backend.EarlyDataReplayGate = .{ .ctx = &replay_ctx, .decideFn = AlwaysAllow.decide };

    var handler_state = TestEarlyDataHandlerState{};
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .resumption_runtime = &resumption,
        .early_data_replay_gate = gate,
        .enable_0rtt = true,
        .request_handler = testEarlyDataAwareHandler,
        .request_handler_ctx = &handler_state,
    });
    defer runtime.deinit();
    try testing.expect(runtime.zero_rtt_enabled);

    // Phase 1: a real handshake, then a real ticket obtained from the
    // production issuance path (`runtime.issueSessionTicket`), not a
    // manually-constructed one.
    const client_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_path = quic.path.PathKey{
        .local = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_300),
        .remote = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_301),
    };
    const server_path = quic.path.PathKey{
        .local = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_301),
        .remote = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_300),
    };
    const no_challenge = [_]u8{0} ** quic.path.path_challenge_len;

    var client_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
    var client_backend = try quic.tls_backend.Tls13Backend.initClientWithAllocator(
        allocator,
        .{ .hello_random = [_]u8{0xc1} ** 32 },
        client_provider_storage.init(0x442_c),
        .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
    );

    const Capture = struct {
        runtime: *tls_core.resumption_runtime.Runtime,
        retained: tls_core.session.ClientTicketState = .{},
        stored: tls_core.session_cache.StoreResult = undefined,
        count: usize = 0,
        fn now(_: *anyopaque) i64 {
            return 1000;
        }
        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            ticket.cloneInto(testing.allocator, &self.retained) catch unreachable;
            self.stored = self.runtime.storeClientTicket(ticket);
            self.count += 1;
        }
    };
    var capture = Capture{ .runtime = &client_resumption };
    defer capture.retained.deinit();
    try client_backend.engine.setSessionTicketConsumer(allocator, tls_core.session.Limits.default, .{
        .ctx = &capture,
        .nowUnixMsFn = Capture.now,
        .onTicketFn = Capture.onTicket,
    });

    const backend1 = try allocator.create(quic.tls_backend.Tls13Backend);
    var backend1_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
    backend1.* = quic.tls_backend.Tls13Backend.initServerWithProvider(
        .{ .hello_random = [_]u8{0x51} ** 32 },
        backend1_provider_storage.init(0x442_5),
        fixed.provider(),
    );
    // Native QUIC 1-RTT resumption deliberately ignores connection-specific
    // transport/application snapshots for *ordinary* resumption matching
    // (mirrors `accept()`'s own `.transport = .ignore` — see
    // `h3EarlyDataCompatibility`'s doc comment) — without this, the ticket's
    // `common.transport_compat` gets stamped non-null and the phase-2
    // candidate lookup below (which intentionally supplies no
    // transport/application compat context) would miss on origin-digest
    // mismatch rather than genuinely testing 0-RTT compatibility.
    const resume_policy: tls_core.tls13_backend.Tls13Backend.ResumeCompatibilityPolicy = .{ .transport = .ignore, .application = .ignore };
    try client_backend.setResumeCompatibilityPolicy(resume_policy);
    try backend1.setResumeCompatibilityPolicy(resume_policy);

    const client1 = try Connection.init(allocator, .{
        .role = .client,
        .local_cid = &client_cid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .peer_cid = &odcid,
        .tls = client_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = 1_000_000,
        .initial_path = client_path,
    });
    defer client1.deinit();
    const server_conn1 = try Connection.init(allocator, .{
        .role = .server,
        .local_cid = &odcid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .peer_cid = &client_cid,
        .tls = backend1.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = 1_000_000,
        .initial_path = server_path,
    });

    var entry1 = ConnEntry{
        .backend = backend1,
        .conn = server_conn1,
        .h3 = H3.initWithSettings(allocator, .server, .{}),
        .admission_source_ip = 0,
        .cid_len = odcid.len,
        .accepted_at_us = 1_000_000,
    };
    defer entry1.deinit(allocator);

    {
        var rounds: usize = 0;
        while (rounds < 64) : (rounds += 1) {
            var progressed = false;
            var buf: [2048]u8 = undefined;
            while (client1.pollTransmitOnPath(&buf, 1_000_000)) |t| {
                try entry1.conn.ingestOnPath(t.bytes, server_path, no_challenge, 1_000_000);
                progressed = true;
            }
            while (entry1.conn.pollTransmitOnPath(&buf, 1_000_000)) |t| {
                try client1.ingestOnPath(t.bytes, client_path, no_challenge, 1_000_000);
                progressed = true;
            }
            if (!progressed) break;
        }
    }
    try testing.expect(client1.isEstablished());
    try testing.expect(entry1.conn.isEstablished());

    try runtime.issueSessionTicket(&entry1, &resumption);
    {
        var rounds: usize = 0;
        while (rounds < 16) : (rounds += 1) {
            var progressed = false;
            var buf: [2048]u8 = undefined;
            while (entry1.conn.pollTransmitOnPath(&buf, 1_000_000)) |t| {
                try client1.ingestOnPath(t.bytes, client_path, no_challenge, 1_000_000);
                progressed = true;
            }
            while (client1.pollTransmitOnPath(&buf, 1_000_000)) |t| {
                try entry1.conn.ingestOnPath(t.bytes, server_path, no_challenge, 1_000_000);
                progressed = true;
            }
            if (!progressed) break;
        }
    }
    try testing.expectEqual(@as(usize, 1), capture.count);
    try testing.expectEqual(tls_core.session_cache.StoreResult.stored, capture.stored);

    // Phase 2: a fresh resumed connection actually attempting/accepting
    // 0-RTT, composed exactly the way `accept()` wires it in production.
    const candidate: tls_core.session.CandidateContext = .{
        .cipher_suite = capture.retained.common.cipher_suite,
        .server_name = if (capture.retained.common.server_name) |*s| s.slice() else null,
        .application_protocol = if (capture.retained.common.application_protocol) |*a| a.slice() else null,
        .auth_binding = capture.retained.common.auth_binding,
        .transport_compat = null,
        .application_compat = null,
    };
    var lookup = client_resumption.lookupClientOffers(candidate);
    defer lookup.deinit();
    try testing.expect(lookup == .hit);

    var client_provider_storage2: test_quic_crypto.HandshakeProviderStorage = .{};
    var client_backend2 = quic.tls_backend.Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0xe1} ** 32 },
        client_provider_storage2.init(0x442_c),
        .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
    );
    var clock_dummy: u8 = 0;
    const ClientClock = struct {
        fn now(_: *anyopaque) i64 {
            return 2000;
        }
    };
    try client_backend2.engine.setClientPskOfferLease(&lookup.hit, &clock_dummy, ClientClock.now);
    try client_backend2.setResumeCompatibilityPolicy(.{ .transport = .ignore, .application = .ignore });
    try client_backend2.setClientEarlyDataIntent(.{ .enabled = true, .max_bytes = 65536 });

    const backend2 = try allocator.create(quic.tls_backend.Tls13Backend);
    var backend2_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
    backend2.* = quic.tls_backend.Tls13Backend.initServerWithProvider(
        .{ .hello_random = [_]u8{0xe2} ** 32 },
        backend2_provider_storage.init(0x442_5),
        fixed.provider(),
    );
    try backend2.setResumeCompatibilityPolicy(.{ .transport = .ignore, .application = .ignore });
    try backend2.setServerPskResolver(resumption.serverResolver().?);
    try backend2.setEarlyDataReplayGate(gate);
    try backend2.setServerEarlyDataPolicy(.{ .enabled = true });

    const client2 = try Connection.init(allocator, .{
        .role = .client,
        .config = .{ .zero_rtt_enabled = true },
        .local_cid = &client_cid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .peer_cid = &odcid,
        .tls = client_backend2.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = 2_000_000,
        .initial_path = client_path,
    });
    defer client2.deinit();

    // There is no production client-side 0-RTT transmit path — the two
    // fabricated 0-RTT packets below are sealed by a throwaway sender
    // adapter operating entirely outside `client2`'s own connection state
    // (see `sealZeroRttPacketForTest`) — so without this, `client2`'s own
    // `StreamManager` would have no record of stream ids 40/44 at all. Once
    // established, the server refreshes send credit for every stream it
    // knows about (`StreamManager.refreshPeerParams`) and each early
    // request's H3 response travels back on that same bidi stream id, both
    // of which `client2` would otherwise reject as `error.UnknownStream`,
    // aborting the connection before it could ever serve a later request.
    // Bring `client2`'s stream layer up early — mirroring
    // `Connection.ensureEarlyStreamManager`, which never runs client-side
    // since a client never receives a `.zero_rtt`-level packet itself — and
    // seed it with placeholder `Stream` entries at exactly those two ids,
    // standing in for the state a real client would already have from
    // having opened them itself before transmitting its own early data.
    client2.streams = quic.stream.StreamManager.init(allocator, .client, client2.local_params, client2.local_params);
    inline for (.{ @as(quic.stream.StreamId, 40), @as(quic.stream.StreamId, 44) }) |placeholder_id| {
        const placeholder = try allocator.create(quic.stream.Stream);
        placeholder.* = .{
            .id = placeholder_id,
            .role = .client,
            .typ = .bidi,
            .init = .client,
            .initial_recv_window = client2.local_params.initial_max_stream_data_bidi_local,
            .max_recv_data = client2.local_params.initial_max_stream_data_bidi_local,
            .max_send_data = 0,
        };
        try client2.streams.?.streams.put(placeholder_id, placeholder);
    }

    const server_conn2 = try Connection.init(allocator, .{
        .role = .server,
        .config = .{ .zero_rtt_enabled = true },
        .local_cid = &odcid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .peer_cid = &client_cid,
        .tls = backend2.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = 2_000_000,
        .initial_path = server_path,
    });

    var entry2 = ConnEntry{
        .backend = backend2,
        .conn = server_conn2,
        .h3 = H3.initWithSettings(allocator, .server, .{}),
        .admission_source_ip = 0,
        .cid_len = odcid.len,
        .accepted_at_us = 2_000_000,
    };
    defer entry2.deinit(allocator);

    // Drive only the client's first flight so the server accepts 0-RTT and
    // installs its read key, but is not yet established — the actual
    // early-data window this test targets.
    {
        var buf: [2048]u8 = undefined;
        while (client2.pollTransmitOnPath(&buf, 2_000_000)) |t| {
            try entry2.conn.ingestOnPath(t.bytes, server_path, no_challenge, 2_000_000);
        }
    }
    try testing.expect(!entry2.conn.isEstablished());
    try testing.expect(entry2.conn.adapter.hasProtectionKeys(.zero_rtt, .read) catch unreachable);

    const real_secret = entry2.conn.adapter.secret(.zero_rtt, .read).?.slice()[0..quic.tls_adapter.traffic_secret_len].*;

    // Two real, QPACK-encoded 0-RTT H3 requests on distinct stream ids
    // (40/44, staying clear of the ids the client's own stream manager will
    // naturally hand out later for the ordinary post-handshake request) —
    // a replay-safe GET and a replay-unsafe POST.
    var get_h3: [128]u8 = undefined;
    const get_bytes = buildH3RequestBytesForTest("GET", "/safe", "example.com", &get_h3);
    var get_frame_buf: [160]u8 = undefined;
    const get_frame_len = try quic.frame.encodeStream(40, 0, get_bytes, true, &get_frame_buf);
    var get_wire: [512]u8 = undefined;
    const get_datagram = sealZeroRttPacketForTest(&odcid, &client_cid, real_secret, 0, get_frame_buf[0..get_frame_len], &get_wire);
    try entry2.conn.ingestOnPath(get_datagram, server_path, no_challenge, 2_000_000);

    var post_h3: [128]u8 = undefined;
    const post_bytes = buildH3RequestBytesForTest("POST", "/unsafe", "example.com", &post_h3);
    var post_frame_buf: [160]u8 = undefined;
    const post_frame_len = try quic.frame.encodeStream(44, 0, post_bytes, true, &post_frame_buf);
    var post_wire: [512]u8 = undefined;
    const post_datagram = sealZeroRttPacketForTest(&odcid, &client_cid, real_secret, 1, post_frame_buf[0..post_frame_len], &post_wire);
    try entry2.conn.ingestOnPath(post_datagram, server_path, no_challenge, 2_000_000);

    // The two fabricated 0-RTT packets above used application-space packet
    // numbers 0 and 1 through a throwaway sender adapter alongside (not
    // through) `client2`'s own transmit path — there is no real client
    // 0-RTT transmit path to drive instead (see `sealZeroRttPacketForTest`).
    // The server's ACKs for those packet numbers raise `client2`'s own
    // `largest_peer_acked` for this space once received; advance `client2`'s
    // own send counter to match what the server has already recorded as
    // used, so `client2`'s later real packets don't collide with (and get
    // authenticated as duplicates of, or worse — encoded with a packet
    // number `packetNumberLength` asserts is impossible relative to an
    // already-higher acked value — see RFC 9000 §17.1) those already-
    // consumed numbers.
    client2.next_pn[@intFromEnum(quic.recovery.PacketNumberSpace.application)] = 2;

    // Drive H3 during the early-data window — before establishment. This is
    // exactly `pumpH3`, the function the second-pass review's finding #2
    // required to work pre-establishment.
    runtime.pumpH3(&entry2, 2_000_000);

    // The safe GET reached the local-execution path exactly once; the
    // unsafe POST was rejected by the shared early-data policy without
    // ever reaching that path — proving the safety decision, not just
    // QUIC-level STREAM delivery.
    try testing.expectEqual(@as(usize, 1), handler_state.executed_local);
    try testing.expectEqualStrings("GET", handler_state.last_method_buf[0..handler_state.last_method_len]);
    try testing.expectEqual(@as(usize, 1), handler_state.rejected_too_early);

    // The rest of the handshake completes normally on the *same* connection
    // that just attempted 0-RTT — accepted/rejected early requests don't
    // derail ordinary 1-RTT completion. This is where the queued 425 for
    // the unsafe POST above (and the 200 for the safe GET) actually reach
    // the wire: the placeholder streams seeded above let `client2` accept
    // the server's MAX_STREAM_DATA credit renewal and each response's
    // STREAM frames on ids 40/44 without erroring `UnknownStream`.
    {
        var rounds: usize = 0;
        while (rounds < 64) : (rounds += 1) {
            var progressed = false;
            var buf: [2048]u8 = undefined;
            while (client2.pollTransmitOnPath(&buf, 2_000_000)) |t| {
                try entry2.conn.ingestOnPath(t.bytes, server_path, no_challenge, 2_000_000);
                progressed = true;
            }
            while (entry2.conn.pollTransmitOnPath(&buf, 2_000_000)) |t| {
                try client2.ingestOnPath(t.bytes, client_path, no_challenge, 2_000_000);
                progressed = true;
            }
            runtime.pumpH3(&entry2, 2_000_000);
            if (!progressed) break;
        }
    }
    try testing.expect(client2.isEstablished());
    try testing.expect(entry2.conn.isEstablished());

    // Ordinary (non-early) request post-handshake, on that *same*
    // connection: even an otherwise-unsafe method dispatches normally once
    // established, proving the 425 above was strictly an early-data-window
    // decision, not a permanent rejection of that route — and proving the
    // connection that attempted 0-RTT is itself genuinely usable
    // afterward, not just some other, cleaner connection. `openStream`
    // hands out id 0 (the first *real* client-opened bidi stream — the
    // placeholder ids 40/44 above bypassed `openLocal`'s counter entirely),
    // so there is no collision with the fabricated early streams.
    const ordinary_id = try client2.openStream(.bidi);
    var ordinary_h3: [128]u8 = undefined;
    const ordinary_bytes = buildH3RequestBytesForTest("POST", "/ordinary", "example.com", &ordinary_h3);
    _ = try client2.writeStream(ordinary_id, ordinary_bytes, true);
    {
        var rounds: usize = 0;
        while (rounds < 32) : (rounds += 1) {
            var progressed = false;
            var buf: [2048]u8 = undefined;
            while (client2.pollTransmitOnPath(&buf, 2_000_000)) |t| {
                try entry2.conn.ingestOnPath(t.bytes, server_path, no_challenge, 2_000_000);
                progressed = true;
            }
            while (entry2.conn.pollTransmitOnPath(&buf, 2_000_000)) |t| {
                try client2.ingestOnPath(t.bytes, client_path, no_challenge, 2_000_000);
                progressed = true;
            }
            runtime.pumpH3(&entry2, 2_000_000);
            if (!progressed) break;
        }
    }
    try testing.expectEqual(@as(usize, 2), handler_state.executed_local);
    try testing.expectEqualStrings("POST", handler_state.last_method_buf[0..handler_state.last_method_len]);
    try testing.expectEqual(@as(usize, 1), handler_state.rejected_too_early);

    // Handler counters only prove the local dispatch/rejection decision —
    // decode the actual bytes `client2` received on the wire to prove the
    // responses themselves were transmitted: the safe GET's 200 on stream
    // 40, and — the specific proof this review round required — the
    // unsafe POST's 425 on stream 44, showing the queued early-rejection
    // response genuinely reached the client once 1-RTT became
    // send-capable, not just that a counter was incremented server-side.
    try expectH3ResponseStatusForTest(client2, 40, "200");
    try expectH3ResponseStatusForTest(client2, 44, "425");
}

/// #523 test-only: read a stream to EOF-of-buffer and decode its first H3
/// frame as a QPACK HEADERS block, asserting `:status` matches `expected`.
fn expectH3ResponseStatusForTest(conn: *Connection, stream_id: quic.stream.StreamId, expected_status: []const u8) !void {
    var buf: [512]u8 = undefined;
    const result = try conn.readStream(stream_id, &buf);
    const raw = try http3.frame.decodeFrame(buf[0..result.len]);
    try testing.expectEqual(http3.frame.FrameType.headers, raw.typ);

    var fields: [8]http3.qpack.HeaderField = undefined;
    var scratch: [256]u8 = undefined;
    const count = try http3.qpack.decode(raw.payload, &fields, &scratch);
    for (fields[0..count]) |field| {
        if (std.mem.eql(u8, field.name, ":status")) {
            try testing.expectEqualStrings(expected_status, field.value);
            return;
        }
    }
    return error.MissingStatusField;
}

const H3EarlyDataRejectionScenario = struct {
    // Always an installed, decideFn-non-null gate — never absent. Production
    // `accept()` always wires a real gate (`zeroRttCarrierEnabled` refuses
    // to enable 0-RTT at all otherwise); modeling "the replay store is
    // unavailable" as literally no gate installed would test a composition
    // that can never occur in production. An operationally-unavailable
    // store is instead a real, installed gate whose `decide` always returns
    // `.unavailable` (see the replay-store-unavailable test below).
    replay_gate: tls_core.tls13_backend.EarlyDataReplayGate,
    mutate: *const fn (*Runtime) void,
    // The H3 SETTINGS snapshot `backend1` remembers into the ticket at
    // issuance time. Defaults to `.{}`, matching the runtime's own (always
    // default — see below) live `h3_settings` exactly, so every scenario
    // except the application-incompatible one is fully app-compatible and
    // isolates its own specific rejection reason. The application-
    // incompatible scenario overrides this to a *stricter remembered*
    // value instead of reducing the runtime's *live* settings: phase 2's
    // H3 session is initialized with `runtime.h3_settings` (mirroring
    // `accept()`), and that must stay within
    // `validateLocallySupportedSettings`'s bounds or the H3 session never
    // starts at all (see "H3 conn: start rejects unsupported
    // max_field_section_size" in `src/http3/conn.zig`) — silently breaking
    // the same-connection 1-RTT fallback this whole matrix is proving.
    remembered_app_settings: http3.frame.Settings = .{},
    expect_decision: metrics_mod.QuicEarlyDataDecision,
};

fn h3EarlyDataRejectionNoMutation(_: *Runtime) void {}

fn h3EarlyDataRejectionReduceTransportLimit(runtime: *Runtime) void {
    runtime.quic_config.initial_max_streams_bidi -= 1;
}

/// Shared production-shaped scaffold for #523's "0-RTT rejected -> same
/// resumed connection still serves a real H3 request over 1-RTT" matrix.
/// Phase 1 mirrors `accept()`'s exact composition (including the H3
/// application-compat snapshot installed at ticket-issuance time — omitting
/// it left a prior version of this test able to pass for the wrong
/// rejection reason, since a ticket with no remembered application state at
/// all resolves to `.application_incompatible` regardless of the transport
/// snapshot). Phase 2 wires the *real* `Runtime.h3EarlyDataCompatibility`
/// gate and the *real* `Runtime.quicConnectionEvent` bridge production uses,
/// so the typed early-data decision this asserts on is the one that would
/// actually reach metrics in production, not a synthetic stand-in.
fn expectH3EarlyDataRejectionFallsBackToRealRequest(scenario: H3EarlyDataRejectionScenario) !void {
    const allocator = testing.allocator;
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-early-request-rejection-matrix-test");

    var server_entropy = tls_core.production_crypto.OsEntropy{};
    var server_provider_state = tls_core.production_crypto.Provider.init(server_entropy.entropy());
    var resumption = try tls_core.resumption_runtime.Runtime.init(
        testing.allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = fixedNowUnixMsForTest },
        server_provider_state.cryptoProvider(),
    );
    defer resumption.deinit();

    var client_entropy = tls_core.production_crypto.OsEntropy{};
    var client_provider_state = tls_core.production_crypto.Provider.init(client_entropy.entropy());
    var client_resumption = try tls_core.resumption_runtime.Runtime.init(
        testing.allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = fixedNowUnixMsForTest },
        client_provider_state.cryptoProvider(),
    );
    defer client_resumption.deinit();

    var handler_state = TestEarlyDataHandlerState{};

    const DecisionCapture = struct {
        count: usize = 0,
        last: ?metrics_mod.QuicEarlyDataDecision = null,
        fn onDecision(ctx: *anyopaque, decision: metrics_mod.QuicEarlyDataDecision) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.count += 1;
            self.last = decision;
        }
    };
    var decision_capture = DecisionCapture{};

    const PacketCapture = struct {
        count: usize = 0,
        last: ?metrics_mod.QuicZeroRttPacketOutcome = null,
        fn onPacket(ctx: *anyopaque, outcome: metrics_mod.QuicZeroRttPacketOutcome) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.count += 1;
            self.last = outcome;
        }
    };
    var packet_capture = PacketCapture{};

    // The scenario's gate is the *runtime's own* configured gate — not a
    // separate placeholder — so this proves the full production ownership
    // chain: the process-shared gate configured on `Runtime` (what
    // `accept()` actually reads) is the one driving the TLS decision, not
    // just that some TLS backend behaves correctly with a gate handed to it
    // directly.
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .resumption_runtime = &resumption,
        .early_data_replay_gate = scenario.replay_gate,
        .enable_0rtt = true,
        .request_handler = testEarlyDataAwareHandler,
        .request_handler_ctx = &handler_state,
        .quic_early_data_decision_metrics_ctx = &decision_capture,
        .quic_early_data_decision_metrics_cb = DecisionCapture.onDecision,
        .quic_zero_rtt_packet_metrics_ctx = &packet_capture,
        .quic_zero_rtt_packet_metrics_cb = PacketCapture.onPacket,
    });
    defer runtime.deinit();
    try testing.expect(runtime.zero_rtt_enabled);

    // Phase 1: a real handshake, then a real ticket obtained from the
    // production issuance path. `server_conn1` is explicitly constructed
    // with the runtime's own live `quic_config` (mirrors `accept()`'s
    // `.config = self.quic_config`) so the transport-parameters snapshot
    // the ticket remembers is exactly what `Runtime.h3EarlyDataCompatibility`
    // will later compare a possibly-mutated live config against.
    const client_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_path = quic.path.PathKey{
        .local = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_310),
        .remote = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_311),
    };
    const server_path = quic.path.PathKey{
        .local = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_311),
        .remote = quic.udp.Address.ip4(.{ 127, 0, 0, 1 }, 41_310),
    };
    const no_challenge = [_]u8{0} ** quic.path.path_challenge_len;

    var client_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
    var client_backend = try quic.tls_backend.Tls13Backend.initClientWithAllocator(
        allocator,
        .{ .hello_random = [_]u8{0xc1} ** 32 },
        client_provider_storage.init(0x442_c),
        .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
    );

    const Capture = struct {
        runtime: *tls_core.resumption_runtime.Runtime,
        retained: tls_core.session.ClientTicketState = .{},
        stored: tls_core.session_cache.StoreResult = undefined,
        count: usize = 0,
        fn now(_: *anyopaque) i64 {
            return 1000;
        }
        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            ticket.cloneInto(testing.allocator, &self.retained) catch unreachable;
            self.stored = self.runtime.storeClientTicket(ticket);
            self.count += 1;
        }
    };
    var capture = Capture{ .runtime = &client_resumption };
    defer capture.retained.deinit();
    try client_backend.engine.setSessionTicketConsumer(allocator, tls_core.session.Limits.default, .{
        .ctx = &capture,
        .nowUnixMsFn = Capture.now,
        .onTicketFn = Capture.onTicket,
    });

    const backend1 = try allocator.create(quic.tls_backend.Tls13Backend);
    var backend1_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
    backend1.* = quic.tls_backend.Tls13Backend.initServerWithProvider(
        .{ .hello_random = [_]u8{0x51} ** 32 },
        backend1_provider_storage.init(0x442_5),
        fixed.provider(),
    );
    const resume_policy: tls_core.tls13_backend.Tls13Backend.ResumeCompatibilityPolicy = .{ .transport = .ignore, .application = .ignore };
    try client_backend.setResumeCompatibilityPolicy(resume_policy);
    try backend1.setResumeCompatibilityPolicy(resume_policy);
    // Mirror production `accept()`'s installation of the H3 application
    // compat snapshot at ticket-issuance time — without this, the ticket
    // has no remembered application state at all, and a scenario meant to
    // isolate one specific rejection reason could actually be passing for a
    // different one (`application_incompatible` via `missing_state`)
    // instead. Encoded fresh from `scenario.remembered_app_settings` rather
    // than reusing `runtime.h3_application_compat` directly: every scenario
    // but the application-incompatible one leaves this at `.{}`, which
    // encodes identically to the runtime's own default `h3_settings`, so
    // this is a distinction without a difference for them — but the
    // application-incompatible scenario needs a *stricter remembered*
    // snapshot than the (always locally-supported-default) live settings.
    var remembered_app_compat_buf: [http3.early_data.encoded_snapshot_len]u8 = undefined;
    const remembered_app_compat_bytes = try http3.early_data.encodeSettingsSnapshot(scenario.remembered_app_settings, &remembered_app_compat_buf);
    try backend1.setEarlyDataApplicationCompat(.{
        .format_id = http3.early_data.format_id,
        .format_version = http3.early_data.format_version,
        .bytes = remembered_app_compat_bytes,
    });

    const client1 = try Connection.init(allocator, .{
        .role = .client,
        .local_cid = &client_cid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .peer_cid = &odcid,
        .tls = client_backend.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = 1_000_000,
        .initial_path = client_path,
    });
    defer client1.deinit();
    const server_conn1 = try Connection.init(allocator, .{
        .role = .server,
        .config = runtime.quic_config,
        .local_cid = &odcid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .peer_cid = &client_cid,
        .tls = backend1.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = 1_000_000,
        .initial_path = server_path,
    });

    var entry1 = ConnEntry{
        .backend = backend1,
        .conn = server_conn1,
        .h3 = H3.initWithSettings(allocator, .server, .{}),
        .admission_source_ip = 0,
        .cid_len = odcid.len,
        .accepted_at_us = 1_000_000,
    };
    defer entry1.deinit(allocator);

    {
        var rounds: usize = 0;
        while (rounds < 64) : (rounds += 1) {
            var progressed = false;
            var buf: [2048]u8 = undefined;
            while (client1.pollTransmitOnPath(&buf, 1_000_000)) |t| {
                try entry1.conn.ingestOnPath(t.bytes, server_path, no_challenge, 1_000_000);
                progressed = true;
            }
            while (entry1.conn.pollTransmitOnPath(&buf, 1_000_000)) |t| {
                try client1.ingestOnPath(t.bytes, client_path, no_challenge, 1_000_000);
                progressed = true;
            }
            if (!progressed) break;
        }
    }
    try testing.expect(client1.isEstablished());
    try testing.expect(entry1.conn.isEstablished());

    try runtime.issueSessionTicket(&entry1, &resumption);
    {
        var rounds: usize = 0;
        while (rounds < 16) : (rounds += 1) {
            var progressed = false;
            var buf: [2048]u8 = undefined;
            while (entry1.conn.pollTransmitOnPath(&buf, 1_000_000)) |t| {
                try client1.ingestOnPath(t.bytes, client_path, no_challenge, 1_000_000);
                progressed = true;
            }
            while (client1.pollTransmitOnPath(&buf, 1_000_000)) |t| {
                try entry1.conn.ingestOnPath(t.bytes, server_path, no_challenge, 1_000_000);
                progressed = true;
            }
            if (!progressed) break;
        }
    }
    try testing.expectEqual(@as(usize, 1), capture.count);
    try testing.expectEqual(tls_core.session_cache.StoreResult.stored, capture.stored);

    // The scenario's specific mutation, applied only now — so the ticket
    // just issued above remembered the *pre*-mutation state.
    scenario.mutate(&runtime);

    // Phase 2: a fresh resumed connection attempting 0-RTT, wired with the
    // *real* `Runtime.h3EarlyDataCompatibility` gate and the *real*
    // `Runtime.quicConnectionEvent` bridge exactly as production's
    // `accept()` composes them — unlike the accepted-case test below, which
    // intentionally bypasses both (its `backend2` never installs either),
    // this proves the actual typed decision that would reach metrics.
    const candidate: tls_core.session.CandidateContext = .{
        .cipher_suite = capture.retained.common.cipher_suite,
        .server_name = if (capture.retained.common.server_name) |*s| s.slice() else null,
        .application_protocol = if (capture.retained.common.application_protocol) |*a| a.slice() else null,
        .auth_binding = capture.retained.common.auth_binding,
        .transport_compat = null,
        .application_compat = null,
    };
    var lookup = client_resumption.lookupClientOffers(candidate);
    defer lookup.deinit();
    try testing.expect(lookup == .hit);

    var client_provider_storage2: test_quic_crypto.HandshakeProviderStorage = .{};
    var client_backend2 = quic.tls_backend.Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0xe1} ** 32 },
        client_provider_storage2.init(0x442_c),
        .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
    );
    var clock_dummy: u8 = 0;
    const ClientClock = struct {
        fn now(_: *anyopaque) i64 {
            return 2000;
        }
    };
    try client_backend2.engine.setClientPskOfferLease(&lookup.hit, &clock_dummy, ClientClock.now);
    try client_backend2.setResumeCompatibilityPolicy(.{ .transport = .ignore, .application = .ignore });
    try client_backend2.setClientEarlyDataIntent(.{ .enabled = true, .max_bytes = 65536 });

    const backend2 = try allocator.create(quic.tls_backend.Tls13Backend);
    var backend2_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
    backend2.* = quic.tls_backend.Tls13Backend.initServerWithProvider(
        .{ .hello_random = [_]u8{0xe2} ** 32 },
        backend2_provider_storage.init(0x442_5),
        fixed.provider(),
    );
    try backend2.setResumeCompatibilityPolicy(.{ .transport = .ignore, .application = .ignore });
    try backend2.setServerPskResolver(resumption.serverResolver().?);
    // Sourced from `runtime.early_data_replay_gate`, not `scenario.replay_gate`
    // directly — the same process-shared value `accept()` reads.
    try backend2.setEarlyDataReplayGate(runtime.early_data_replay_gate.?);
    try backend2.setServerEarlyDataPolicy(.{ .enabled = true });
    try backend2.setEarlyDataCompatibilityGate(.{ .ctx = &runtime, .decideFn = Runtime.h3EarlyDataCompatibility });

    const client2 = try Connection.init(allocator, .{
        .role = .client,
        .config = .{ .zero_rtt_enabled = true },
        .local_cid = &client_cid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .peer_cid = &odcid,
        .tls = client_backend2.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = 2_000_000,
        .initial_path = client_path,
    });
    defer client2.deinit();
    var quic_observer2 = ConnEntry.QuicObserver{
        .runtime = &runtime,
        .connection_handle = 2,
    };
    const server_conn2 = try Connection.init(allocator, .{
        .role = .server,
        .config = runtime.quic_config,
        .local_cid = &odcid,
        .original_destination_cid = &odcid,
        .initial_secret_dcid = &odcid,
        .peer_cid = &client_cid,
        .tls = backend2.backend(),
        .crypto_provider = test_quic_crypto.testDefaultProvider(),
        .now_us = 2_000_000,
        .initial_path = server_path,
        .events = .{ .context = &quic_observer2, .emitFn = Runtime.quicConnectionEvent },
    });

    var entry2 = ConnEntry{
        .backend = backend2,
        .conn = server_conn2,
        .quic_observer = quic_observer2,
        // Mirrors `accept()`'s `self.h3_settings` (line ~585) — for the
        // application-incompatible scenario, `scenario.mutate` just changed
        // this live value, so phase 2's actual H3 session must run under
        // those same (mutated) SETTINGS, not silently fall back to defaults.
        .h3 = H3.initWithSettings(allocator, .server, runtime.h3_settings),
        .admission_source_ip = 0,
        .cid_len = odcid.len,
        .accepted_at_us = 2_000_000,
    };
    defer entry2.deinit(allocator);

    // Drive only the client's first flight — enough for the server to run
    // the resumption/early-data decision — then confirm 0-RTT was genuinely
    // rejected (no `.zero_rtt` read key installed) and that the *specific*
    // typed decision this scenario is testing is exactly what was recorded,
    // through the same production metrics bridge `accept()` uses.
    {
        var buf: [2048]u8 = undefined;
        while (client2.pollTransmitOnPath(&buf, 2_000_000)) |t| {
            try entry2.conn.ingestOnPath(t.bytes, server_path, no_challenge, 2_000_000);
        }
    }
    try testing.expect(!(entry2.conn.adapter.hasProtectionKeys(.zero_rtt, .read) catch unreachable));
    try testing.expectEqual(@as(usize, 1), decision_capture.count);
    try testing.expectEqual(scenario.expect_decision, decision_capture.last.?);

    // Prove rejection actually suppresses early delivery, not just that no
    // read key exists: the client's own TLS engine still derives and would
    // use a real 0-RTT write secret regardless of what the server's gate
    // decides (it can't know the decision in advance) — extract that real
    // secret and seal a genuine QPACK-encoded H3 GET as an early 0-RTT
    // packet, exactly as a real client attempting (and having rejected)
    // early data would send. The server can't have a matching read key (see
    // above), so this must be dropped as `keys_unavailable` before ever
    // reaching the frame/H3 layer — not merely "no packet was sent".
    {
        const client_write_secret = client2.adapter.secret(.zero_rtt, .write).?.slice()[0..quic.tls_adapter.traffic_secret_len].*;
        var early_h3: [128]u8 = undefined;
        const early_bytes = buildH3RequestBytesForTest("GET", "/early-after-rejection", "example.com", &early_h3);
        var early_frame_buf: [160]u8 = undefined;
        const early_frame_len = try quic.frame.encodeStream(40, 0, early_bytes, true, &early_frame_buf);
        var early_wire: [512]u8 = undefined;
        const early_datagram = sealZeroRttPacketForTest(&odcid, &client_cid, client_write_secret, 0, early_frame_buf[0..early_frame_len], &early_wire);
        try entry2.conn.ingestOnPath(early_datagram, server_path, no_challenge, 2_000_000);
        runtime.pumpH3(&entry2, 2_000_000);
    }
    try testing.expectEqual(@as(usize, 1), packet_capture.count);
    try testing.expectEqual(metrics_mod.QuicZeroRttPacketOutcome.keys_unavailable, packet_capture.last.?);
    try testing.expectEqual(@as(usize, 0), handler_state.executed_local);
    try testing.expectEqual(@as(usize, 0), handler_state.rejected_too_early);

    // The rest of the handshake completes normally as ordinary 1-RTT
    // resumption on this *same* connection — rejection is strictly an
    // early-data-window decision, not a rejection of the connection itself.
    {
        var rounds: usize = 0;
        while (rounds < 64) : (rounds += 1) {
            var progressed = false;
            var buf: [2048]u8 = undefined;
            while (client2.pollTransmitOnPath(&buf, 2_000_000)) |t| {
                try entry2.conn.ingestOnPath(t.bytes, server_path, no_challenge, 2_000_000);
                progressed = true;
            }
            while (entry2.conn.pollTransmitOnPath(&buf, 2_000_000)) |t| {
                try client2.ingestOnPath(t.bytes, client_path, no_challenge, 2_000_000);
                progressed = true;
            }
            if (!progressed) break;
        }
    }
    try testing.expect(client2.isEstablished());
    try testing.expect(entry2.conn.isEstablished());

    // A real H3 request over 1-RTT, on this *same* connection that just had
    // its 0-RTT attempt rejected — the same-connection fallback proof the
    // review asked for, through `Runtime.pumpH3` and the shared handler.
    const request_id = try client2.openStream(.bidi);
    var request_h3: [128]u8 = undefined;
    const request_bytes = buildH3RequestBytesForTest("GET", "/after-rejection", "example.com", &request_h3);
    _ = try client2.writeStream(request_id, request_bytes, true);
    {
        var rounds: usize = 0;
        while (rounds < 32) : (rounds += 1) {
            var progressed = false;
            var buf: [2048]u8 = undefined;
            while (client2.pollTransmitOnPath(&buf, 2_000_000)) |t| {
                try entry2.conn.ingestOnPath(t.bytes, server_path, no_challenge, 2_000_000);
                progressed = true;
            }
            while (entry2.conn.pollTransmitOnPath(&buf, 2_000_000)) |t| {
                try client2.ingestOnPath(t.bytes, client_path, no_challenge, 2_000_000);
                progressed = true;
            }
            runtime.pumpH3(&entry2, 2_000_000);
            if (!progressed) break;
        }
    }
    try testing.expectEqual(@as(usize, 1), handler_state.executed_local);
    try testing.expectEqualStrings("GET", handler_state.last_method_buf[0..handler_state.last_method_len]);
    try testing.expectEqual(@as(usize, 0), handler_state.rejected_too_early);
}

test "http3 (#523): replay-rejected 0-RTT falls back to a real H3 request over 1-RTT, same connection" {
    const AlwaysReplay = struct {
        fn decide(_: *anyopaque, _: tls_core.tls13_backend.EarlyDataReplayCandidate) tls_core.tls13_backend.EarlyDataReplayDecision {
            return .replay;
        }
    };
    var replay_ctx: u8 = 0;
    try expectH3EarlyDataRejectionFallsBackToRealRequest(.{
        .replay_gate = .{ .ctx = &replay_ctx, .decideFn = AlwaysReplay.decide },
        .mutate = h3EarlyDataRejectionNoMutation,
        .expect_decision = .replay_rejected,
    });
}

test "http3 (#523): replay-store-unavailable 0-RTT falls back to a real H3 request over 1-RTT, same connection" {
    // Models an operationally-unavailable replay store (e.g. the process
    // shared store failing open a lookup) as a real, installed gate whose
    // `decide` always reports `.unavailable` — not the absence of a gate,
    // which `zeroRttCarrierEnabled` never lets a production composition
    // reach in the first place.
    const AlwaysUnavailable = struct {
        fn decide(_: *anyopaque, _: tls_core.tls13_backend.EarlyDataReplayCandidate) tls_core.tls13_backend.EarlyDataReplayDecision {
            return .unavailable;
        }
    };
    var replay_ctx: u8 = 0;
    try expectH3EarlyDataRejectionFallsBackToRealRequest(.{
        .replay_gate = .{ .ctx = &replay_ctx, .decideFn = AlwaysUnavailable.decide },
        .mutate = h3EarlyDataRejectionNoMutation,
        .expect_decision = .replay_unavailable,
    });
}

test "http3 (#523): transport-incompatible 0-RTT rejected by the real Runtime.h3EarlyDataCompatibility gate falls back to a real H3 request over 1-RTT, same connection" {
    const AlwaysAllow = struct {
        fn decide(_: *anyopaque, _: tls_core.tls13_backend.EarlyDataReplayCandidate) tls_core.tls13_backend.EarlyDataReplayDecision {
            return .allow;
        }
    };
    var replay_ctx: u8 = 0;
    try expectH3EarlyDataRejectionFallsBackToRealRequest(.{
        .replay_gate = .{ .ctx = &replay_ctx, .decideFn = AlwaysAllow.decide },
        .mutate = h3EarlyDataRejectionReduceTransportLimit,
        .expect_decision = .transport_incompatible,
    });
}

test "http3 (#523): application-incompatible (H3 SETTINGS) 0-RTT rejected by the real Runtime.h3EarlyDataCompatibility gate falls back to a real H3 request over 1-RTT, same connection" {
    const AlwaysAllow = struct {
        fn decide(_: *anyopaque, _: tls_core.tls13_backend.EarlyDataReplayCandidate) tls_core.tls13_backend.EarlyDataReplayDecision {
            return .allow;
        }
    };
    var replay_ctx: u8 = 0;
    try expectH3EarlyDataRejectionFallsBackToRealRequest(.{
        .replay_gate = .{ .ctx = &replay_ctx, .decideFn = AlwaysAllow.decide },
        .mutate = h3EarlyDataRejectionNoMutation,
        // A stricter *remembered* QPACK dynamic-table capacity than the
        // live (always-default, `qpack_max_table_capacity == 0`) settings
        // phase 2 actually runs under: `qpackMaxTableCompatible` treats
        // `remembered == 0` as vacuously compatible, so this field can only
        // ever produce `.settings_incompatible` by remembering *more* than
        // the always-zero live default — never by reducing the live side
        // (see `H3EarlyDataRejectionScenario.remembered_app_settings`).
        .remembered_app_settings = .{ .qpack_max_table_capacity = 4096 },
        .expect_decision = .application_incompatible,
    });
}

test "accept() (#523): wires an EventSink into every accepted connection so 0-RTT events reach metrics instead of being silently discarded" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-event-wiring-test");

    const Capture = struct {
        decisions: usize = 0,
        packets: usize = 0,

        fn onDecision(ctx: *anyopaque, _: metrics_mod.QuicEarlyDataDecision) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.decisions += 1;
        }
        fn onPacket(ctx: *anyopaque, _: metrics_mod.QuicZeroRttPacketOutcome) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.packets += 1;
        }
    };
    var capture = Capture{};

    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .quic_early_data_decision_metrics_ctx = &capture,
        .quic_early_data_decision_metrics_cb = Capture.onDecision,
        .quic_zero_rtt_packet_metrics_ctx = &capture,
        .quic_zero_rtt_packet_metrics_cb = Capture.onPacket,
    });
    defer runtime.deinit();

    var connections = std.AutoHashMap(u64, *ConnEntry).init(testing.allocator);
    defer {
        var it = connections.valueIterator();
        while (it.next()) |entry| {
            entry.*.deinit(testing.allocator);
            testing.allocator.destroy(entry.*);
        }
        connections.deinit();
    }
    var routes = quic.cid.CidRoutingTable.init(testing.allocator);
    defer routes.deinit();
    var per_ip = std.AutoHashMap(u32, u32).init(testing.allocator);
    defer per_ip.deinit();
    var next_handle: u64 = 1;

    const dcid = [_]u8{0x11} ** 8;
    const scid = [_]u8{0x22} ** 8;
    const parsed = quic.packet.ParsedPacket{
        .kind = .initial,
        .version = quic.packet.quic_v1,
        .dcid = &dcid,
        .scid = &scid,
    };
    const peer = std.c.sockaddr.in{ .family = posix.AF.INET, .port = 0, .addr = 0, .zero = [_]u8{0} ** 8 };

    const handle = runtime.accept(&connections, &routes, &per_ip, &next_handle, parsed, peer, 1_000_000);
    try testing.expect(handle != null);
    const entry = connections.get(handle.?).?;

    // Prove `accept()` genuinely attached a non-default `EventSink` (not
    // just left it at its `.{}` no-op default) by emitting directly through
    // it — this is what a real handshake's `Event.early_data_decision` /
    // `Event.zero_rtt_packet` emissions from inside `Connection` would
    // otherwise reach and, before this fix, never did.
    entry.conn.events.emit(.{ .early_data_decision = .disabled });
    entry.conn.events.emit(.{ .zero_rtt_packet = .{ .outcome = .keys_unavailable, .size = 0 } });
    try testing.expectEqual(@as(usize, 1), capture.decisions);
    try testing.expectEqual(@as(usize, 1), capture.packets);
}

fn deinitTestConnections(connections: *std.AutoHashMap(u64, *ConnEntry), allocator: std.mem.Allocator) void {
    var it = connections.valueIterator();
    while (it.next()) |entry| {
        entry.*.deinit(allocator);
        allocator.destroy(entry.*);
    }
    connections.deinit();
}

fn testPeerSockaddr(port: u16) std.c.sockaddr.in {
    return .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
        .zero = [_]u8{0} ** 8,
    };
}

test "http3 runtime Retry sends tokenless Initials without allocating connection state" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-retry-tokenless-test");
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .retry_policy = .address_validation,
    });
    defer runtime.deinit();

    var connections = std.AutoHashMap(u64, *ConnEntry).init(testing.allocator);
    defer deinitTestConnections(&connections, testing.allocator);
    var routes = quic.cid.CidRoutingTable.init(testing.allocator);
    defer routes.deinit();
    var per_ip = std.AutoHashMap(u32, u32).init(testing.allocator);
    defer per_ip.deinit();
    var next_handle: u64 = 1;

    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{0x22} ** 8;
    const parsed = quic.packet.ParsedPacket{
        .kind = .initial,
        .version = quic.packet.quic_v1,
        .dcid = &odcid,
        .scid = &client_scid,
        .token = &.{},
    };

    const handle = runtime.accept(&connections, &routes, &per_ip, &next_handle, parsed, testPeerSockaddr(44_330), 1_000_000);
    try testing.expectEqual(@as(?u64, null), handle);
    try testing.expectEqual(@as(usize, 0), connections.count());
    try testing.expectEqual(@as(usize, 0), routes.count());
    try testing.expectEqual(@as(usize, 0), per_ip.count());
    const snapshot = runtime.snapshot();
    try testing.expectEqual(@as(usize, 1), snapshot.retry_packets_sent);
    try testing.expectEqual(@as(usize, 0), snapshot.retry_tokens_accepted);
    try testing.expectEqual(@as(usize, 0), snapshot.invalid_tokens);
    try testing.expectEqual(@as(usize, 0), snapshot.tracked_connections);
}

test "http3 runtime Retry drops invalid tokens without sending a second Retry" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-retry-invalid-token-test");
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .retry_policy = .address_validation,
    });
    defer runtime.deinit();

    var connections = std.AutoHashMap(u64, *ConnEntry).init(testing.allocator);
    defer deinitTestConnections(&connections, testing.allocator);
    var routes = quic.cid.CidRoutingTable.init(testing.allocator);
    defer routes.deinit();
    var per_ip = std.AutoHashMap(u32, u32).init(testing.allocator);
    defer per_ip.deinit();
    var next_handle: u64 = 1;

    const retry_scid = [_]u8{0x44} ** 8;
    const client_scid = [_]u8{0x22} ** 8;
    const parsed = quic.packet.ParsedPacket{
        .kind = .initial,
        .version = quic.packet.quic_v1,
        .dcid = &retry_scid,
        .scid = &client_scid,
        .token = "tampered",
    };

    const handle = runtime.accept(&connections, &routes, &per_ip, &next_handle, parsed, testPeerSockaddr(44_331), 1_000_000);
    try testing.expectEqual(@as(?u64, null), handle);
    try testing.expectEqual(@as(usize, 0), connections.count());
    const snapshot = runtime.snapshot();
    try testing.expectEqual(@as(usize, 0), snapshot.retry_packets_sent);
    try testing.expectEqual(@as(usize, 0), snapshot.retry_tokens_accepted);
    try testing.expectEqual(@as(usize, 1), snapshot.invalid_tokens);
}

test "http3 runtime Retry accepts validated tokens with split CID roles and validated path" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-retry-valid-token-test");
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .retry_policy = .address_validation,
    });
    defer runtime.deinit();

    var connections = std.AutoHashMap(u64, *ConnEntry).init(testing.allocator);
    defer deinitTestConnections(&connections, testing.allocator);
    var routes = quic.cid.CidRoutingTable.init(testing.allocator);
    defer routes.deinit();
    var per_ip = std.AutoHashMap(u32, u32).init(testing.allocator);
    defer per_ip.deinit();
    var next_handle: u64 = 1;

    const now: u64 = 1_000_000;
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const retry_scid = [_]u8{ 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
    const client_scid = [_]u8{0x22} ** 8;
    const peer = testPeerSockaddr(44_332);
    var token_buf: [quic.path.max_token_len]u8 = undefined;
    const token = try runtime.secrets.retry_tokens.issueRetry(
        &odcid,
        &retry_scid,
        quic.packet.quic_v1,
        addressFromSockaddrIn(peer),
        now,
        [_]u8{0x59} ** quic.path.token_nonce_len,
        &token_buf,
    );
    const parsed = quic.packet.ParsedPacket{
        .kind = .initial,
        .version = quic.packet.quic_v1,
        .dcid = &retry_scid,
        .scid = &client_scid,
        .token = token,
    };

    const handle = runtime.accept(&connections, &routes, &per_ip, &next_handle, parsed, peer, now + 500);
    try testing.expect(handle != null);
    const entry = connections.get(handle.?).?;
    try testing.expectEqual(@as(usize, 1), connections.count());
    try testing.expectEqual(@as(usize, 1), routes.count());
    try testing.expect(routes.contains(try quic.cid.ConnectionId.init(&retry_scid)));
    try testing.expectEqualStrings(&retry_scid, entry.conn.localCid());
    try testing.expectEqualStrings(&odcid, entry.conn.original_dcid.slice());
    try testing.expect(entry.conn.retry_scid != null);
    try testing.expectEqualStrings(&retry_scid, entry.conn.retry_scid.?.slice());
    try testing.expect(entry.conn.paths.activePath().anti_amplification.validated);
    const snapshot = runtime.snapshot();
    try testing.expectEqual(@as(usize, 0), snapshot.retry_packets_sent);
    try testing.expectEqual(@as(usize, 1), snapshot.retry_tokens_accepted);
    try testing.expectEqual(@as(usize, 0), snapshot.invalid_tokens);
    try testing.expectEqual(@as(usize, 1), snapshot.tracked_connections);
}

test "http3 runtime Retry rejects valid tokens replayed with the wrong Retry SCID" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-retry-wrong-scid-test");
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .retry_policy = .address_validation,
    });
    defer runtime.deinit();

    var connections = std.AutoHashMap(u64, *ConnEntry).init(testing.allocator);
    defer deinitTestConnections(&connections, testing.allocator);
    var routes = quic.cid.CidRoutingTable.init(testing.allocator);
    defer routes.deinit();
    var per_ip = std.AutoHashMap(u32, u32).init(testing.allocator);
    defer per_ip.deinit();
    var next_handle: u64 = 1;

    const now: u64 = 1_000_000;
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const retry_scid = [_]u8{ 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
    const wrong_retry_scid = [_]u8{ 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68 };
    const client_scid = [_]u8{0x22} ** 8;
    const peer = testPeerSockaddr(44_333);
    var token_buf: [quic.path.max_token_len]u8 = undefined;
    const token = try runtime.secrets.retry_tokens.issueRetry(
        &odcid,
        &retry_scid,
        quic.packet.quic_v1,
        addressFromSockaddrIn(peer),
        now,
        [_]u8{0x5a} ** quic.path.token_nonce_len,
        &token_buf,
    );
    const parsed = quic.packet.ParsedPacket{
        .kind = .initial,
        .version = quic.packet.quic_v1,
        .dcid = &wrong_retry_scid,
        .scid = &client_scid,
        .token = token,
    };

    const handle = runtime.accept(&connections, &routes, &per_ip, &next_handle, parsed, peer, now + 500);
    try testing.expectEqual(@as(?u64, null), handle);
    try testing.expectEqual(@as(usize, 0), connections.count());
    try testing.expectEqual(@as(usize, 0), routes.count());
    try testing.expectEqual(@as(usize, 0), per_ip.count());
    const snapshot = runtime.snapshot();
    try testing.expectEqual(@as(usize, 0), snapshot.retry_packets_sent);
    try testing.expectEqual(@as(usize, 0), snapshot.retry_tokens_accepted);
    try testing.expectEqual(@as(usize, 1), snapshot.invalid_tokens);
}

test "http3 runtime Retry counts valid tokens replayed with the wrong QUIC version as invalid" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-retry-wrong-version-test");
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .retry_policy = .address_validation,
    });
    defer runtime.deinit();

    var connections = std.AutoHashMap(u64, *ConnEntry).init(testing.allocator);
    defer deinitTestConnections(&connections, testing.allocator);
    var routes = quic.cid.CidRoutingTable.init(testing.allocator);
    defer routes.deinit();
    var per_ip = std.AutoHashMap(u32, u32).init(testing.allocator);
    defer per_ip.deinit();
    var next_handle: u64 = 1;

    const now: u64 = 1_000_000;
    const odcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const retry_scid = [_]u8{ 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
    const client_scid = [_]u8{0x22} ** 8;
    const peer = testPeerSockaddr(44_334);
    var token_buf: [quic.path.max_token_len]u8 = undefined;
    const token = try runtime.secrets.retry_tokens.issueRetry(
        &odcid,
        &retry_scid,
        quic.packet.quic_v1,
        addressFromSockaddrIn(peer),
        now,
        [_]u8{0x5b} ** quic.path.token_nonce_len,
        &token_buf,
    );
    const parsed = quic.packet.ParsedPacket{
        .kind = .initial,
        .version = 0xff00_001d,
        .dcid = &retry_scid,
        .scid = &client_scid,
        .token = token,
    };

    const handle = runtime.accept(&connections, &routes, &per_ip, &next_handle, parsed, peer, now + 500);
    try testing.expectEqual(@as(?u64, null), handle);
    try testing.expectEqual(@as(usize, 0), connections.count());
    try testing.expectEqual(@as(usize, 0), routes.count());
    try testing.expectEqual(@as(usize, 0), per_ip.count());
    const snapshot = runtime.snapshot();
    try testing.expectEqual(@as(usize, 0), snapshot.retry_packets_sent);
    try testing.expectEqual(@as(usize, 0), snapshot.retry_tokens_accepted);
    try testing.expectEqual(@as(usize, 1), snapshot.invalid_tokens);
}

test "runtime resolves the actual bound local address, including an OS-assigned port, from quic_port = 0" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-port0-test");

    // `quic_port = 0` asks the OS for an ephemeral port; every connection's
    // and PathKey's local half must reflect the address `getsockname`
    // actually resolved, not the requested `0` (#515 required test: UDP
    // port-0 local-address resolution round-trips through runtime PathKey
    // construction).
    var runtime = try Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
    });
    defer runtime.deinit();

    try testing.expectEqual(quic.udp.AddressFamily.ip4, runtime.local_address.family);
    try testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, runtime.local_address.slice());
    try testing.expect(runtime.local_address.port != 0);
    // The configured (requested) port is unaffected; only the resolved
    // local address reflects what the OS actually bound.
    try testing.expectEqual(@as(u16, 0), runtime.quic_port);
}

test "sockaddr_in <-> quic.udp.Address conversion round-trips family, octets, and port" {
    const original = std.c.sockaddr.in{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 44_321),
        .addr = @bitCast([4]u8{ 198, 51, 100, 7 }),
    };
    const address = addressFromSockaddrIn(original);
    try testing.expectEqual(quic.udp.AddressFamily.ip4, address.family);
    try testing.expectEqualSlices(u8, &[_]u8{ 198, 51, 100, 7 }, address.slice());
    try testing.expectEqual(@as(u16, 44_321), address.port);

    // Every `Transmit.path.remote` a connection returns is sent through this
    // exact conversion (`sendDatagram(sockaddrInFromAddress(t.path.remote),
    // t.bytes)`, never a cached or fixed peer): round-tripping it back must
    // reproduce the original wire address exactly.
    const round_tripped = sockaddrInFromAddress(address);
    try testing.expectEqual(original.family, round_tripped.family);
    try testing.expectEqual(original.port, round_tripped.port);
    try testing.expectEqual(original.addr, round_tripped.addr);
}

test {
    std.testing.refAllDecls(@This());
}

test "http3 runtime: DPLPMTUD stays at the floor without the no-fragmentation contract" {
    // RFC 8899 §3: an acknowledged large probe only measures the path if the
    // datagram was not fragmented. A listener that could not establish that
    // contract must not discover above the RFC 9000 §14 floor, whatever the
    // operator configured.
    const raised = Config{ .listen_host = "::", .quic_port = 443, .max_datagram_size = quic.datagram.max_size };
    try testing.expectEqual(
        @as(u64, quic.datagram.max_size),
        quicConfigFrom(raised, true, false).max_send_udp_payload_size,
    );
    try testing.expectEqual(
        @as(u64, quic.datagram.base_size),
        quicConfigFrom(raised, false, false).max_send_udp_payload_size,
    );
    // The advertised receive capacity is a property of this endpoint's
    // buffers and is unaffected either way.
    try testing.expectEqual(
        quicConfigFrom(raised, true, false).max_udp_payload_size,
        quicConfigFrom(raised, false, false).max_udp_payload_size,
    );
}

test "http3 runtime: the no-fragmentation contract is established exactly where it is claimed" {
    // Runs on every platform. Where the OS is one this code has verified, the
    // option must actually be accepted by the kernel — not merely attempted.
    // Where it is not, `configureNoFragment` must report failure so the
    // ceiling collapses, rather than guessing a constant and reporting
    // success without ever setting DF.
    for ([_]u32{ posix.AF.INET, posix.AF.INET6 }) |family| {
        const fd = openUdpSocket(family);
        if (fd < 0) continue;
        defer _ = std.c.close(fd);
        try testing.expectEqual(no_fragment_supported, configureNoFragment(fd, family));
    }
}

test "http3 runtime: socket buffer sizes are read back from the kernel, not assumed" {
    // #256-D: the request and the grant are different numbers on every
    // platform — Linux returns roughly double, and caps at a sysctl the
    // process cannot see — so what gets reported has to come from
    // `getsockopt` on the real socket.
    const fd = openUdpSocket(posix.AF.INET);
    if (fd < 0) return error.SkipZigTest;
    defer _ = std.c.close(fd);

    // Nothing requested: still read back, because benchmark metadata and
    // operator diagnostics want the number whether or not it was chosen here.
    const untouched = tuneSocketBuffers(fd, .{});
    try testing.expectEqual(quic.udp.BufferTuningStatus.default, untouched.recv.status);
    try testing.expectEqual(quic.udp.BufferTuningStatus.default, untouched.send.status);
    try testing.expectEqual(@as(?usize, null), untouched.recv.requested_bytes);
    try testing.expect(untouched.recv.effective_bytes != null);
    try testing.expect(untouched.send.effective_bytes != null);

    // A satisfiable request, *derived from this host* rather than assumed: no
    // fixed constant is below every kernel's ceiling, and a hardcoded one that
    // happens to pass says nothing about the grant path. Half of what the
    // socket already has is inside any ceiling that produced that default.
    const recv_request = quic.udp.clampBufferBytes(grantedBufferBytes(untouched.recv.effective_bytes.?) / 2);
    const send_request = quic.udp.clampBufferBytes(grantedBufferBytes(untouched.send.effective_bytes.?) / 2);
    const tuned = tuneSocketBuffers(fd, .{ .recv_bytes = recv_request, .send_bytes = send_request });
    try testing.expectEqual(quic.udp.BufferTuningStatus.applied, tuned.recv.status);
    try testing.expectEqual(quic.udp.BufferTuningStatus.applied, tuned.send.status);
    try testing.expectEqual(@as(?usize, recv_request), tuned.recv.requested_bytes);

    // The grant is judged in request units. On Linux the raw reading is about
    // twice that; asserting on the raw reading instead would pass for the
    // wrong reason there.
    try testing.expect(tuned.recv.granted_bytes.? >= recv_request);
    try testing.expect(tuned.send.granted_bytes.? >= send_request);
    try testing.expectEqual(grantedBufferBytes(tuned.recv.effective_bytes.?), tuned.recv.granted_bytes.?);
}

test "http3 runtime: a real kernel's answer to the largest request is classified consistently" {
    // The clamp *regression* is the deterministic classifier test in
    // `quic.udp`; this checks the same policy against a real kernel, where the
    // answer depends on the host. Asking for the maximum will be capped almost
    // everywhere, but a deliberately tuned host can grant it — and a
    // correctness test must not fail because someone raised their socket
    // ceiling. So this asserts the invariants that must hold either way rather
    // than demanding a particular verdict.
    const fd = openUdpSocket(posix.AF.INET);
    if (fd < 0) return error.SkipZigTest;
    defer _ = std.c.close(fd);

    const outcome = tuneSocketBuffer(fd, posix.SO.RCVBUF, quic.udp.max_buffer_bytes);
    if (outcome.status == .unsupported or outcome.status == .unverified) return error.SkipZigTest;
    try testing.expectEqual(@as(?usize, quic.udp.max_buffer_bytes), outcome.requested_bytes);

    // Whatever the kernel decided, the verdict follows from the
    // request-comparable reading and nothing else. On Linux the raw reading of
    // a capped buffer is doubled and can exceed the request outright, so a
    // `clamped` verdict alongside an `effective_bytes` larger than the request
    // is precisely the false positive this pins shut.
    const granted = outcome.granted_bytes.?;
    switch (outcome.status) {
        .clamped => try testing.expect(granted < quic.udp.max_buffer_bytes),
        .applied => try testing.expect(granted >= quic.udp.max_buffer_bytes),
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(grantedBufferBytes(outcome.effective_bytes.?), granted);
}

test "http3 runtime: only Linux restates socket buffer readings" {
    // The doubling is a Linux storage detail, not a portable one: Darwin and
    // the BSDs report what was set. Halving elsewhere would invent a clamp
    // that never happened and warn on every correctly applied request.
    const reported: usize = 8 * 1024 * 1024;
    const expected: usize = if (builtin.os.tag == .linux) reported / 2 else reported;
    try testing.expectEqual(expected, grantedBufferBytes(reported));
}

test "http3 runtime: an oversized buffer request never reaches the kernel as one" {
    // `setsockopt(SO_RCVBUF)` takes a `c_int`. An operator typo must be
    // clamped to something the ABI can express — handing it over unclamped
    // would truncate to a negative size — and the clamped value is what gets
    // reported, so the log never claims a request that was not made.
    const fd = openUdpSocket(posix.AF.INET);
    if (fd < 0) return error.SkipZigTest;
    defer _ = std.c.close(fd);

    const outcome = tuneSocketBuffer(fd, posix.SO.RCVBUF, std.math.maxInt(usize));
    try testing.expectEqual(@as(?usize, quic.udp.max_buffer_bytes), outcome.requested_bytes);
    // Whatever the kernel decided, this stays advisory: a refusal or a clamp
    // is reported, never raised.
    try testing.expect(outcome.status != .default);
}

test "http3 runtime: the largest possible buffer request still yields a working listener" {
    // Socket buffer sizing is a performance setting. Whatever the host makes
    // of a maximum-sized request — granting it, capping it, refusing it — the
    // listener must still come up bound and bootstrapped, with the outcome
    // published for diagnosis instead of failing startup.
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-test");

    var runtime = Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .udp_buffer_tuning = .{ .recv_bytes = quic.udp.max_buffer_bytes, .send_bytes = quic.udp.max_buffer_bytes },
    }) catch return error.SkipZigTest;
    defer runtime.deinit();

    try testing.expect(runtime.snapshot().server_bootstrapped);
    const buffers = runtime.snapshot().udp_buffers;
    try testing.expectEqual(@as(?usize, quic.udp.max_buffer_bytes), buffers.recv.requested_bytes);
    try testing.expectEqual(@as(?usize, quic.udp.max_buffer_bytes), buffers.send.requested_bytes);
    // The listener publishes what it got, so a clamp is diagnosable from
    // outside the process rather than showing up as unexplained loss.
    try testing.expect(buffers.recv.status != .default);
    if (buffers.recv.effective_bytes) |effective| try testing.expect(effective > 0);
}

test "http3 runtime: an untuned listener still reports its socket buffers" {
    // The default path: nothing configured, kernel sizing left alone, and the
    // effective values still published so benchmark runs and support tickets
    // record what the socket actually had.
    var logger = logger_mod.Logger.init(.err, "http3-test");
    var runtime = Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
    }) catch return error.SkipZigTest;
    defer runtime.deinit();

    const buffers = runtime.snapshot().udp_buffers;
    try testing.expectEqual(quic.udp.BufferTuningStatus.default, buffers.recv.status);
    try testing.expectEqual(quic.udp.BufferTuningStatus.default, buffers.send.status);
    try testing.expectEqual(@as(?usize, null), buffers.recv.requested_bytes);
    try testing.expect(buffers.recv.effective_bytes != null);
    try testing.expect(buffers.send.effective_bytes != null);
}

test "http3 runtime: only verified platforms claim no-fragmentation support" {
    // The list here is the same one `docs/HTTP3_ROLLOUT.md` names. BSD is not
    // one platform: Darwin's IP_DONTFRAG is 28 and FreeBSD's is 67, and
    // OpenBSD uses 28 for something else entirely, so the families cannot be
    // grouped and the unverified ones must stay conservative.
    const expected = switch (builtin.os.tag) {
        .linux, .macos, .ios, .tvos, .watchos, .freebsd => true,
        else => false,
    };
    try testing.expectEqual(expected, no_fragment_supported);
}

// ---------------------------------------------------------------------------
// ECN socket support (#256-E).
//
// The state machine these feed is tested deterministically in `quic/ecn.zig`
// and end to end in `quic/connection.zig`; what is left here is the part that
// can only be checked against a real kernel, plus the pure conversions between
// an IP traffic-class byte and the transport's codepoint model.
// ---------------------------------------------------------------------------

test "http3 runtime: only verified platforms claim ECN support" {
    // Same rule as the no-fragmentation table: these option numbers differ
    // per OS, and a wrong constant that a kernel happens to accept would read
    // as a working ECN path while marking nothing. Unverified platforms run
    // without ECN, which is a supported state.
    const expected = switch (builtin.os.tag) {
        .linux, .macos, .ios, .tvos, .watchos, .freebsd => true,
        else => false,
    };
    try testing.expectEqual(expected, ecn_supported);
}

test "http3 runtime: the ECN field is the low two bits and nothing else" {
    // RFC 3168 §5. The upper six bits are DSCP — an operator's traffic-class
    // marking — and reading them as congestion would turn ordinary QoS
    // configuration into a signal to halve the window.
    try testing.expectEqual(quic.udp.Ecn.not_ect, ecnFromTrafficClass(0b0000_0000));
    try testing.expectEqual(quic.udp.Ecn.ect1, ecnFromTrafficClass(0b0000_0001));
    try testing.expectEqual(quic.udp.Ecn.ect0, ecnFromTrafficClass(0b0000_0010));
    try testing.expectEqual(quic.udp.Ecn.ce, ecnFromTrafficClass(0b0000_0011));
    // A DSCP-marked packet (CS5 = 0b101000_00) is still not-ECT.
    try testing.expectEqual(quic.udp.Ecn.not_ect, ecnFromTrafficClass(0b1010_0000));
    try testing.expectEqual(quic.udp.Ecn.ect0, ecnFromTrafficClass(0b1010_0010));

    try testing.expectEqual(@as(?c_int, 0b10), trafficClassFromEcn(.ect0));
    try testing.expectEqual(@as(?c_int, 0b11), trafficClassFromEcn(.ce));
    try testing.expectEqual(@as(?c_int, 0), trafficClassFromEcn(.not_ect));
    // "Could not observe one" is not a codepoint that can be sent.
    try testing.expectEqual(@as(?c_int, null), trafficClassFromEcn(.unavailable));
}

test "http3 runtime: an absent or unrelated control message reads as unavailable" {
    if (!ecn_supported) return error.SkipZigTest;
    var control: [ecn_control_len]u8 align(@alignOf(usize)) = std.mem.zeroes([ecn_control_len]u8);

    // No control data at all: the socket cannot report a codepoint, which is
    // `.unavailable` and emphatically not `.not_ect` — reporting "unmarked"
    // would make a peer's working marking look stripped.
    try testing.expectEqual(quic.udp.Ecn.unavailable, ecnFromControl(&control, 0, posix.AF.INET));

    // A well-formed control message for something else is skipped rather than
    // misread as a traffic class.
    const header: *align(cmsg_alignment) std.c.cmsghdr = @ptrCast(@alignCast(&control[0]));
    header.len = @intCast(cmsgLen(@sizeOf(c_int)));
    header.level = posix.SOL.SOCKET;
    header.type = 0x7f;
    try testing.expectEqual(
        quic.udp.Ecn.unavailable,
        ecnFromControl(&control, cmsgSpace(@sizeOf(c_int)), posix.AF.INET),
    );

    // A header claiming more data than the buffer holds is refused rather than
    // read past — control data comes from the kernel, but the length arithmetic
    // is this code's to get right.
    header.level = posix.IPPROTO.IP;
    header.type = @intCast(ecn_socket_options.?.recv_cmsg_v4);
    header.len = @intCast(cmsgLen(@sizeOf(c_int)) + 4096);
    try testing.expectEqual(
        quic.udp.Ecn.unavailable,
        ecnFromControl(&control, cmsgSpace(@sizeOf(c_int)), posix.AF.INET),
    );
}

test "http3 runtime: a received traffic-class control message yields its codepoint" {
    if (!ecn_supported) return error.SkipZigTest;
    var control: [ecn_control_len]u8 align(@alignOf(usize)) = std.mem.zeroes([ecn_control_len]u8);
    const header: *align(cmsg_alignment) std.c.cmsghdr = @ptrCast(@alignCast(&control[0]));
    header.level = posix.IPPROTO.IP;
    header.type = @intCast(ecn_socket_options.?.recv_cmsg_v4);

    // Kernels disagree on the width they deliver this in — Linux hands back a
    // single byte for IPv4, an int for IPv6, and the BSDs differ again — so
    // both are read rather than one being assumed.
    header.len = @intCast(cmsgLen(1));
    control[cmsg_data_offset] = 0b11;
    try testing.expectEqual(quic.udp.Ecn.ce, ecnFromControl(&control, cmsgSpace(1), posix.AF.INET));

    header.len = @intCast(cmsgLen(@sizeOf(c_int)));
    const value: c_int = 0b10;
    @memcpy(control[cmsg_data_offset..][0..@sizeOf(c_int)], std.mem.asBytes(&value));
    try testing.expectEqual(
        quic.udp.Ecn.ect0,
        ecnFromControl(&control, cmsgSpace(@sizeOf(c_int)), posix.AF.INET),
    );
}

test "http3 runtime: a marked datagram survives a real loopback socket" {
    // The one thing no state-machine test can establish: that this platform's
    // option numbers, control-message layout, and alignment arithmetic are
    // right, end to end, against the kernel that will actually carry the
    // traffic. Everything above this line would pass with the constants wrong.
    if (!ecn_supported) return error.SkipZigTest;

    const receiver = openUdpSocket(posix.AF.INET);
    if (receiver < 0) return error.SkipZigTest;
    defer _ = std.c.close(receiver);
    if (!configureEcnReceive(receiver, posix.AF.INET)) return error.SkipZigTest;

    var bind_address = std.c.sockaddr.in{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f00_0001),
        .zero = [_]u8{0} ** 8,
    };
    if (std.c.bind(receiver, @ptrCast(&bind_address), @sizeOf(std.c.sockaddr.in)) != 0) return error.SkipZigTest;
    var bound: std.c.sockaddr.in = undefined;
    var bound_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
    if (std.c.getsockname(receiver, @ptrCast(&bound), &bound_len) != 0) return error.SkipZigTest;

    const sender = openUdpSocket(posix.AF.INET);
    if (sender < 0) return error.SkipZigTest;
    defer _ = std.c.close(sender);

    const outcome = sendDatagramTo(sender, &bound, "ecn", .ect0);
    // A kernel that refuses the control message is a real, supported outcome:
    // the datagram still went out, unmarked, and the listener stops asking.
    if (outcome.ecn_rejected) return error.SkipZigTest;
    try testing.expectEqual(@as(isize, 3), outcome.result);

    var buf: [64]u8 = undefined;
    var from: std.c.sockaddr.storage = undefined;
    var from_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.storage);
    var attempts: usize = 0;
    const received = while (attempts < 200) : (attempts += 1) {
        const attempt = receiveDatagram(receiver, &buf, &from, &from_len);
        if (attempt.result >= 0) break attempt;
        if (posix.errno(attempt.result) != .AGAIN) return error.SkipZigTest;
        compat.sleepNs(1 * std.time.ns_per_ms);
    } else return error.SkipZigTest;

    try testing.expectEqualStrings("ecn", buf[0..@intCast(received.result)]);
    try testing.expectEqual(quic.udp.Ecn.ect0, received.ecn);
}

test "http3 runtime: an unmarked datagram reports not-ECT, not unavailable" {
    // The negative control for the test above: with the receive option on, a
    // datagram that really was unmarked must come back as `.not_ect` so the
    // peer's validation can distinguish "your marks were stripped" from "I
    // cannot see marks at all".
    if (!ecn_supported) return error.SkipZigTest;

    const receiver = openUdpSocket(posix.AF.INET);
    if (receiver < 0) return error.SkipZigTest;
    defer _ = std.c.close(receiver);
    if (!configureEcnReceive(receiver, posix.AF.INET)) return error.SkipZigTest;

    var bind_address = std.c.sockaddr.in{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7f00_0001),
        .zero = [_]u8{0} ** 8,
    };
    if (std.c.bind(receiver, @ptrCast(&bind_address), @sizeOf(std.c.sockaddr.in)) != 0) return error.SkipZigTest;
    var bound: std.c.sockaddr.in = undefined;
    var bound_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
    if (std.c.getsockname(receiver, @ptrCast(&bound), &bound_len) != 0) return error.SkipZigTest;

    const sender = openUdpSocket(posix.AF.INET);
    if (sender < 0) return error.SkipZigTest;
    defer _ = std.c.close(sender);
    const outcome = sendDatagramTo(sender, &bound, "plain", .not_ect);
    try testing.expectEqual(@as(isize, 5), outcome.result);
    try testing.expect(!outcome.ecn_rejected);

    var buf: [64]u8 = undefined;
    var from: std.c.sockaddr.storage = undefined;
    var from_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.storage);
    var attempts: usize = 0;
    const received = while (attempts < 200) : (attempts += 1) {
        const attempt = receiveDatagram(receiver, &buf, &from, &from_len);
        if (attempt.result >= 0) break attempt;
        if (posix.errno(attempt.result) != .AGAIN) return error.SkipZigTest;
        compat.sleepNs(1 * std.time.ns_per_ms);
    } else return error.SkipZigTest;
    try testing.expectEqual(quic.udp.Ecn.not_ect, received.ecn);
}

test "http3 runtime: a listener publishes whether ECN is actually running" {
    var logger = logger_mod.Logger.init(.err, "http3-ecn-test");
    var runtime = Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
    }) catch return error.SkipZigTest;
    defer runtime.deinit();

    // On by default, but only *actually* on where the kernel agreed to report
    // received codepoints — the snapshot reports what applied, not what was
    // asked for, because that is what a benchmark run has to record.
    try testing.expectEqual(ecn_supported, runtime.snapshot().ecn_enabled);
    try testing.expectEqual(ecn_supported, runtime.quic_config.ecn_enabled);
    try testing.expectEqual(ecn_supported, runtime.ecn_send_enabled);
}

test "http3 runtime: an operator can turn ECN off outright" {
    var logger = logger_mod.Logger.init(.err, "http3-ecn-off-test");
    var runtime = Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .ecn_enabled = false,
    }) catch return error.SkipZigTest;
    defer runtime.deinit();

    try testing.expect(!runtime.snapshot().ecn_enabled);
    try testing.expect(!runtime.quic_config.ecn_enabled);
    try testing.expect(!runtime.ecn_send_enabled);
    try testing.expectEqual(@as(usize, 0), runtime.snapshot().ecn_marked_sent);
}

test "http3 runtime: a socket that cannot mark withdraws ECN from the transport too" {
    // #256-E review: turning off only the send shim would leave
    // `quic_config.ecn_enabled` true, so every connection accepted afterwards
    // would still enter ECN testing and count marks for datagrams that
    // actually left Not-ECT — while the snapshot reported ECN off. Separated
    // from `sendDatagram` so this is provable without a kernel that rejects
    // the control message.
    var logger = logger_mod.Logger.init(.err, "http3-ecn-reject-test");
    var runtime = Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
    }) catch return error.SkipZigTest;
    defer runtime.deinit();
    if (!runtime.ecn_send_enabled) return error.SkipZigTest;
    try testing.expect(runtime.quic_config.ecn_enabled);

    runtime.noteEcnSendRejected();

    try testing.expect(!runtime.ecn_send_enabled);
    // The capability is withdrawn where new connections read it ...
    try testing.expect(!runtime.quic_config.ecn_enabled);
    // ... the snapshot agrees ...
    try testing.expect(!runtime.snapshot().ecn_enabled);
    // ... and the capability stays withdrawn, which is what
    // `applyEcnCapabilityLoss` keys off on every subsequent pass.
    try testing.expect(!runtime.ecn_send_enabled);

    // Idempotent.
    runtime.noteEcnSendRejected();
    try testing.expect(!runtime.ecn_send_enabled);
    try testing.expect(!runtime.quic_config.ecn_enabled);
}

test "http3 runtime: every live connection is told the socket cannot mark (#256-E review)" {
    // The rejection is discovered inside a send, part-way through the
    // connection table. A one-shot "pending" flag would only reach entries the
    // iterator had not yet walked past; the rest would keep counting marks for
    // datagrams that left Not-ECT. So the capability loss is applied on every
    // pass, for every connection, until the process restarts.
    var fixed = tls_core.credentials.FixedCredentialProvider.init(
        tls_core.credentials.testdata.identity(),
        tls_core.credentials.testdata.ignoredEntropy(),
    );
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-ecn-sweep-test");
    var runtime = Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
    }) catch return error.SkipZigTest;
    defer runtime.deinit();
    if (!runtime.ecn_send_enabled) return error.SkipZigTest;

    var connections = std.AutoHashMap(u64, *ConnEntry).init(testing.allocator);
    defer deinitTestConnections(&connections, testing.allocator);
    var routes = quic.cid.CidRoutingTable.init(testing.allocator);
    defer routes.deinit();
    var per_ip = std.AutoHashMap(u32, u32).init(testing.allocator);
    defer per_ip.deinit();
    var next_handle: u64 = 1;

    // Two live connections, accepted before the capability is lost.
    var handles: [2]u64 = undefined;
    for (&handles, 0..) |*handle, index| {
        const dcid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, @intCast(index) };
        const scid = [_]u8{ 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, @intCast(index) };
        handle.* = runtime.accept(&connections, &routes, &per_ip, &next_handle, .{
            .kind = .initial,
            .version = quic.packet.quic_v1,
            .dcid = &dcid,
            .scid = &scid,
            .token = "",
        }, testPeerSockaddr(@intCast(45_000 + index)), 1_000_000) orelse
            return error.SkipZigTest;
    }
    try testing.expectEqual(@as(usize, 2), connections.count());
    for (handles) |handle| {
        try testing.expect(connections.get(handle).?.conn.cfg.ecn_enabled);
    }

    runtime.noteEcnSendRejected();
    runtime.applyEcnCapabilityLoss(&connections);

    // Both — not just whichever one the rejection happened on.
    for (handles) |handle| {
        const conn = connections.get(handle).?.conn;
        try testing.expect(!conn.cfg.ecn_enabled);
        try testing.expectEqual(quic.udp.Ecn.not_ect, conn.ecnCodepoint());
        const marked_before = conn.metrics.ecn_marked_sent;
        var out: [quic.datagram.max_size]u8 = undefined;
        while (conn.pollTransmitOnPath(&out, 1_000_000)) |t| {
            try testing.expectEqual(quic.udp.Ecn.not_ect, t.ecn);
        }
        try testing.expectEqual(marked_before, conn.metrics.ecn_marked_sent);
    }
}

test "http3 runtime: a low-RTT connection hands the loop a sub-millisecond deadline" {
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var harness = try RuntimeCidHarness.init(testing.allocator, fixed.provider());
    defer harness.deinit(testing.allocator);

    // 1.25 × 480 kB over a 10 ms RTT — a datacentre or loopback path, and the
    // case #256 exists for. One datagram every ~20 µs.
    try spendPacingBurst(harness, 480 * 1024, 10_000);
    const now = harness.now_us;

    const release = harness.entry.conn.nextSendTimeUs(now) orelse return error.TestExpectedEqual;
    try testing.expect(release > now);
    try testing.expect(release - now < std.time.us_per_ms);
    try testing.expectEqual(release, Runtime.connectionWakeUs(harness.entry, now, now + max_loop_wait_us));

    // The deadline reaches the wait primitive in microseconds. Rounding it to
    // an integer-millisecond `poll` timeout — what this loop did before
    // #256-C — would sleep ~50 pacing intervals past it, and with a bounded
    // burst that caps the listener at one burst per millisecond however much
    // window and RTT allow.
    try testing.expect(SocketWaiter.pollTimeoutMs(release - now) == 1);
    try testing.expect(release - now < SocketWaiter.pollTimeoutMs(release - now) * std.time.us_per_ms);
}

test "http3 runtime: the socket waiter rounds its fallback up and clamps to the loop ceiling" {
    // Never round *down*: a wait that returns before its deadline costs the
    // loop a whole pass that can produce nothing.
    try testing.expectEqual(@as(i32, 1), SocketWaiter.pollTimeoutMs(1));
    try testing.expectEqual(@as(i32, 1), SocketWaiter.pollTimeoutMs(999));
    try testing.expectEqual(@as(i32, 1), SocketWaiter.pollTimeoutMs(1_000));
    try testing.expectEqual(@as(i32, 2), SocketWaiter.pollTimeoutMs(1_001));

    // A zero deadline still blocks for a tick rather than spinning the loop.
    try testing.expectEqual(@as(i32, 1), SocketWaiter.pollTimeoutMs(0));

    // And never past the loop's own ceiling.
    try testing.expectEqual(@as(i32, 100), SocketWaiter.pollTimeoutMs(max_loop_wait_us));
    try testing.expectEqual(@as(i32, 100), SocketWaiter.pollTimeoutMs(10 * max_loop_wait_us));
}

test "http3 runtime: the socket waiter takes a sub-millisecond path where the platform has one" {
    const fd = std.c.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
    if (fd < 0) return error.SkipZigTest;
    defer _ = std.c.close(fd);

    var waiter = SocketWaiter.init(fd);
    defer waiter.deinit();

    // Linux waits with `ppoll` and needs no descriptor; the BSDs need a
    // `kqueue` and this asserts one was actually obtained, so a silent
    // fallback to millisecond `poll` on a platform that has better cannot pass
    // unnoticed.
    if (SocketWaiter.uses_kqueue) try testing.expect(waiter.kq >= 0);

    // A sub-millisecond wait on a socket with nothing to read must return, not
    // hang or fail. Deliberately no assertion on elapsed time: this is a real
    // syscall against a shared scheduler, and the deadline is a floor on how
    // long it sleeps, never a ceiling.
    waiter.wait(200);
}

test "http3 runtime: observability artifacts follow accepted connection lifecycle" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_root = try compat.wrapDir(tmp.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(tmp_root);
    const qlog_dir = try std.fmt.allocPrint(testing.allocator, "{s}/qlogs", .{tmp_root});
    defer testing.allocator.free(qlog_dir);

    var artifacts = try ObservabilityArtifacts.init(testing.allocator, qlog_dir, "");
    defer artifacts.deinit();

    var fixed = tls_core.credentials.FixedCredentialProvider.init(
        tls_core.credentials.testdata.identity(),
        tls_core.credentials.testdata.ignoredEntropy(),
    );
    defer fixed.deinit();
    var logger = logger_mod.Logger.init(.err, "http3-artifacts-test");
    var runtime = Runtime.init(testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .qlog_artifacts_ctx = &artifacts,
        .quic_qlog_artifact_cb = ObservabilityArtifacts.writeQuicRecord,
        .h3_qlog_artifact_cb = ObservabilityArtifacts.writeH3Record,
        .qlog_artifact_close_cb = ObservabilityArtifacts.closeTrace,
    }) catch return error.SkipZigTest;
    defer runtime.deinit();

    var connections = std.AutoHashMap(u64, *ConnEntry).init(testing.allocator);
    defer connections.deinit();
    var routes = quic.cid.CidRoutingTable.init(testing.allocator);
    defer routes.deinit();
    var per_ip = std.AutoHashMap(u32, u32).init(testing.allocator);
    defer per_ip.deinit();
    var next_handle: u64 = 1;

    const dcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const scid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7 };
    const handle = runtime.accept(&connections, &routes, &per_ip, &next_handle, .{
        .kind = .initial,
        .version = quic.packet.quic_v1,
        .dcid = &dcid,
        .scid = &scid,
        .token = "",
    }, testPeerSockaddr(44_300), 1_000_000) orelse return error.SkipZigTest;
    defer runtime.removeConnection(&connections, &routes, &per_ip, handle, .administrative);
    artifacts.waitIdle();

    const entry = connections.get(handle).?;
    Runtime.h3ConnectionEvent(&entry.h3_observer, .{ .stream_type_set = .{ .stream_id = 0, .stream_type = .control } });
    artifacts.waitIdle();
    try testing.expectEqual(@as(usize, 1), artifacts.traceCount());

    const path = try std.fmt.allocPrint(testing.allocator, "{s}/quic-0000000000000001.sqlog", .{qlog_dir});
    defer testing.allocator.free(path);
    const contents = try compat.cwd().readFileAlloc(testing.allocator, path, 8192);
    defer testing.allocator.free(contents);

    try testing.expect(std.mem.indexOf(u8, contents, "\"file_schema\":\"urn:ietf:params:qlog:file:sequential\"") != null);
    try testing.expect(std.mem.indexOf(u8, contents, "\"group_id\":\"0000000000000001\"") != null);
    try testing.expect(std.mem.indexOf(u8, contents, "\"name\":\"quic:connection_started\"") != null);
    try testing.expect(std.mem.indexOf(u8, contents, "\"name\":\"http3:stream_type_set\"") != null);
    try testing.expectEqual(@as(usize, 3), std.mem.count(u8, contents, &[_]u8{quic.qlog.record_separator}));
    runtime.removeConnection(&connections, &routes, &per_ip, handle, .administrative);
    artifacts.waitIdle();
    try testing.expectEqual(@as(usize, 0), artifacts.traceCount());

    const dcid2 = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    const scid2 = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const handle2 = runtime.accept(&connections, &routes, &per_ip, &next_handle, .{
        .kind = .initial,
        .version = quic.packet.quic_v1,
        .dcid = &dcid2,
        .scid = &scid2,
        .token = "",
    }, testPeerSockaddr(44_301), 1_100_000) orelse return error.SkipZigTest;
    defer runtime.removeConnection(&connections, &routes, &per_ip, handle2, .administrative);
    artifacts.waitIdle();
    try testing.expectEqual(@as(usize, 1), artifacts.traceCount());
    runtime.removeConnection(&connections, &routes, &per_ip, handle2, .administrative);
    artifacts.waitIdle();
    try testing.expectEqual(@as(usize, 0), artifacts.traceCount());

    const d = artifacts.diagnostics();
    try testing.expectEqual(@as(usize, 0), d.qlog_write_errors);
    try testing.expectEqual(@as(usize, 0), d.qlog_dropped_records);
}

test "http3 runtime: observability artifacts keep adjacent low-volume records" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_root = try compat.wrapDir(tmp.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(tmp_root);
    const qlog_dir = try std.fmt.allocPrint(testing.allocator, "{s}/qlogs", .{tmp_root});
    defer testing.allocator.free(qlog_dir);

    var artifacts = try ObservabilityArtifacts.init(testing.allocator, qlog_dir, "");
    defer artifacts.deinit();

    const handle: u64 = 1;
    for (0..64) |i| {
        ObservabilityArtifacts.writeQuicRecord(&artifacts, handle, .{
            .time_us = @intCast(i),
            .event = .{ .connection_started = .{ .dcid_len = 8 } },
        });
        ObservabilityArtifacts.writeH3Record(&artifacts, handle, .{
            .time_us = @intCast(i),
            .event = .{ .stream_type_set = .{ .stream_id = @intCast(i), .stream_type = .control } },
        });
        artifacts.waitIdle();
    }

    const d = artifacts.diagnostics();
    try testing.expectEqual(@as(usize, 0), d.qlog_dropped_records);
    try testing.expectEqual(@as(usize, 1), artifacts.traceCount());
    ObservabilityArtifacts.closeTrace(&artifacts, handle);
    artifacts.waitIdle();
    try testing.expectEqual(@as(usize, 0), artifacts.traceCount());
}

test "http3 runtime: observability artifact close commands survive saturated data queue" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_root = try compat.wrapDir(tmp.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(tmp_root);

    var state = ObservabilityArtifacts.State{
        .allocator = testing.allocator,
        .logger = null,
        .qlog_dir = "",
        .keylog_path = "",
        .traces = std.AutoHashMap(u64, *ObservabilityArtifacts.Trace).init(testing.allocator),
    };
    defer state.deinitStorage();

    const empty_record: [ObservabilityArtifacts.qlog_record_max]u8 = undefined;
    for (0..ObservabilityArtifacts.data_queue_capacity) |_| {
        state.tryEnqueue(.qlog, .{ .qlog = .{ .handle = 999, .bytes = empty_record, .len = 0 } });
    }

    const close_count = 16;
    for (0..close_count) |i| {
        const handle: u64 = @intCast(i + 1);
        const path = try std.fmt.allocPrint(testing.allocator, "{s}/trace-{d}.sqlog", .{ tmp_root, handle });
        errdefer testing.allocator.free(path);
        var file = try compat.cwd().createFile(path, .{ .read = false, .truncate = true });
        errdefer file.close();
        const trace = try testing.allocator.create(ObservabilityArtifacts.Trace);
        trace.* = .{ .path = path, .file = file };
        try state.traces.put(handle, trace);
        state.enqueueClose(handle);
    }

    try testing.expectEqual(@as(usize, ObservabilityArtifacts.data_queue_capacity), state.dataQueueLen());
    try testing.expectEqual(@as(usize, close_count), state.closeQueueLen());
    try testing.expectEqual(@as(usize, close_count), state.traces.count());

    while (state.popData() != null) _ = state.processed_seq.fetchAdd(1, .release);
    while (state.popClose()) |close| state.closeTraceOnWriter(close.handle);
    try testing.expectEqual(@as(usize, 0), state.traces.count());

    const d = state.diagnostics();
    try testing.expectEqual(@as(usize, 0), d.qlog_dropped_records);
    try testing.expectEqual(@as(usize, 0), d.keylog_dropped_records);
}

test "http3 runtime: observability artifact close barriers do not starve behind newer data" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_root = try compat.wrapDir(tmp.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(tmp_root);

    var state = ObservabilityArtifacts.State{
        .allocator = testing.allocator,
        .logger = null,
        .qlog_dir = "",
        .keylog_path = "",
        .traces = std.AutoHashMap(u64, *ObservabilityArtifacts.Trace).init(testing.allocator),
    };
    defer state.deinitStorage();

    const handle: u64 = 42;
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/trace-{d}.sqlog", .{ tmp_root, handle });
    errdefer testing.allocator.free(path);
    var file = try compat.cwd().createFile(path, .{ .read = false, .truncate = true });
    errdefer file.close();
    const trace = try testing.allocator.create(ObservabilityArtifacts.Trace);
    trace.* = .{ .path = path, .file = file };
    try state.traces.put(handle, trace);

    const empty_record: [ObservabilityArtifacts.qlog_record_max]u8 = undefined;
    state.tryEnqueue(.qlog, .{ .qlog = .{ .handle = handle, .bytes = empty_record, .len = 0 } });
    state.enqueueClose(handle);
    state.tryEnqueue(.qlog, .{ .qlog = .{ .handle = 999, .bytes = empty_record, .len = 0 } });

    try testing.expectEqual(@as(usize, 2), state.dataQueueLen());
    try testing.expectEqual(@as(usize, 1), state.closeQueueLen());
    try testing.expectEqual(@as(usize, 1), state.traces.count());

    _ = state.popData().?;
    _ = state.processed_seq.fetchAdd(1, .release);
    const close = state.peekClose().?;
    try testing.expect(state.closeReady(close));
    _ = state.popClose();
    state.closeTraceOnWriter(close.handle);
    try testing.expectEqual(@as(usize, 0), state.traces.count());
    try testing.expectEqual(@as(usize, 1), state.dataQueueLen());
}

test "http3 runtime: observability artifact data handoff is visible as worker-active" {
    var state = ObservabilityArtifacts.State{
        .allocator = testing.allocator,
        .logger = null,
        .qlog_dir = "",
        .keylog_path = "",
        .traces = std.AutoHashMap(u64, *ObservabilityArtifacts.Trace).init(testing.allocator),
    };
    defer state.deinitStorage();

    const empty_record: [ObservabilityArtifacts.keylog_record_max]u8 = undefined;
    state.tryEnqueue(.keylog, .{ .keylog = .{ .bytes = empty_record, .len = 0 } });

    state.worker_active.store(true, .release);
    const command = state.popData() orelse return error.TestExpectedEqual;
    try testing.expectEqual(@as(usize, 0), state.dataQueueLen());
    try testing.expect(state.worker_active.load(.acquire));
    ObservabilityArtifacts.processCommand(&state, command);
    _ = state.processed_seq.fetchAdd(1, .release);
    state.worker_active.store(false, .release);
    state.waitIdle();
}

test "http3 runtime: observability artifact semaphore wake handles single record and deinit" {
    for (0..64) |i| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const tmp_root = try compat.wrapDir(tmp.dir).realpathAlloc(testing.allocator, ".");
        defer testing.allocator.free(tmp_root);
        const qlog_dir = try std.fmt.allocPrint(testing.allocator, "{s}/qlogs-{d}", .{ tmp_root, i });
        defer testing.allocator.free(qlog_dir);

        var artifacts = try ObservabilityArtifacts.init(testing.allocator, qlog_dir, "");
        ObservabilityArtifacts.writeQuicRecord(&artifacts, 1, .{
            .time_us = @intCast(i),
            .event = .{ .connection_started = .{ .dcid_len = 8 } },
        });
        artifacts.waitIdle();
        try testing.expectEqual(@as(usize, 1), artifacts.traceCount());
        artifacts.deinit();
    }
}

test "http3 runtime: observability artifact close overflow preserves exact close intent" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_root = try compat.wrapDir(tmp.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(tmp_root);

    var state = ObservabilityArtifacts.State{
        .allocator = testing.allocator,
        .logger = null,
        .qlog_dir = "",
        .keylog_path = "",
        .traces = std.AutoHashMap(u64, *ObservabilityArtifacts.Trace).init(testing.allocator),
    };
    defer state.deinitStorage();

    const active_handle: u64 = 999_999;
    const active_path = try std.fmt.allocPrint(testing.allocator, "{s}/trace-{d}.sqlog", .{ tmp_root, active_handle });
    errdefer testing.allocator.free(active_path);
    var active_file = try compat.cwd().createFile(active_path, .{ .read = false, .truncate = true });
    errdefer active_file.close();
    const active_trace = try testing.allocator.create(ObservabilityArtifacts.Trace);
    active_trace.* = .{ .path = active_path, .file = active_file };
    try state.traces.put(active_handle, active_trace);

    for (0..ObservabilityArtifacts.close_queue_capacity + 1) |i| {
        const handle: u64 = @intCast(i + 1);
        const path = try std.fmt.allocPrint(testing.allocator, "{s}/trace-{d}.sqlog", .{ tmp_root, handle });
        errdefer testing.allocator.free(path);
        var file = try compat.cwd().createFile(path, .{ .read = false, .truncate = true });
        errdefer file.close();
        const trace = try testing.allocator.create(ObservabilityArtifacts.Trace);
        trace.* = .{ .path = path, .file = file };
        try state.traces.put(handle, trace);
        state.enqueueClose(handle);
    }

    try testing.expectEqual(@as(usize, ObservabilityArtifacts.close_queue_capacity), state.closeQueueLen());
    try testing.expectEqual(@as(usize, 1), state.dataQueueLen());
    try testing.expect(!state.pendingCloseAll());
    try testing.expectEqual(@as(usize, ObservabilityArtifacts.close_queue_capacity + 2), state.traces.count());

    while (state.popClose()) |close| state.closeTraceOnWriter(close.handle);
    const command = state.popData() orelse return error.TestExpectedEqual;
    ObservabilityArtifacts.processCommand(&state, command);
    try testing.expect(state.traces.get(active_handle) != null);
    try testing.expectEqual(@as(usize, 1), state.traces.count());
}

test "http3 runtime: observability artifact saturated close overflow abandons future qlog capture" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_root = try compat.wrapDir(tmp.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(tmp_root);

    var state = ObservabilityArtifacts.State{
        .allocator = testing.allocator,
        .logger = null,
        .qlog_dir = tmp_root,
        .keylog_path = "",
        .traces = std.AutoHashMap(u64, *ObservabilityArtifacts.Trace).init(testing.allocator),
    };
    defer state.deinitStorage();

    const empty_record: [ObservabilityArtifacts.qlog_record_max]u8 = undefined;
    for (0..ObservabilityArtifacts.data_queue_capacity) |_| {
        state.tryEnqueue(.qlog, .{ .qlog = .{ .handle = 999, .bytes = empty_record, .len = 0 } });
    }
    for (0..ObservabilityArtifacts.close_queue_capacity) |i| {
        state.enqueueClose(@intCast(i + 1));
    }

    state.enqueueClose(100_000);
    try testing.expect(state.pendingCloseAll());
    try testing.expect(!state.qlogEnabled());
    try testing.expectEqual(@as(usize, ObservabilityArtifacts.data_queue_capacity), state.dataQueueLen());
    try testing.expectEqual(@as(usize, ObservabilityArtifacts.close_queue_capacity), state.closeQueueLen());

    const d = state.diagnostics();
    try testing.expectEqual(@as(usize, 1), d.qlog_dropped_records);
}

test "http3 runtime: observability artifacts append TLS keylog lines through shared formatter" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_root = try compat.wrapDir(tmp.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(tmp_root);
    const keylog_path = try std.fmt.allocPrint(testing.allocator, "{s}/http3.keys", .{tmp_root});
    defer testing.allocator.free(keylog_path);

    var artifacts = try ObservabilityArtifacts.init(testing.allocator, "", keylog_path);
    defer artifacts.deinit();

    var context = artifacts.keylogContext();
    const random = [_]u8{0x11} ** tls_core.keylog.client_random_len;
    try context.setClientRandom(&random);
    context.emitSecret(.handshake, .write, &[_]u8{ 0xaa, 0xbb });
    artifacts.waitIdle();

    const contents = try compat.cwd().readFileAlloc(testing.allocator, keylog_path, 1024);
    defer testing.allocator.free(contents);
    try testing.expect(std.mem.startsWith(u8, contents, "SERVER_HANDSHAKE_TRAFFIC_SECRET "));
    try testing.expect(std.mem.endsWith(u8, contents, " aabb\n"));
    const d = artifacts.diagnostics();
    try testing.expectEqual(@as(usize, 0), d.keylog_write_errors);
    try testing.expectEqual(@as(usize, 0), d.keylog_dropped_records);
}

test "http3 runtime: keylog initialization tightens permissive existing files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_root = try compat.wrapDir(tmp.dir).realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(tmp_root);
    const keylog_path = try std.fmt.allocPrint(testing.allocator, "{s}/http3.keys", .{tmp_root});
    defer testing.allocator.free(keylog_path);

    var file = try compat.cwd().createFile(keylog_path, .{
        .read = false,
        .truncate = true,
        .exclusive = true,
        .permissions = @enumFromInt(0o644),
    });
    file.close();

    var artifacts = try ObservabilityArtifacts.init(testing.allocator, "", keylog_path);
    defer artifacts.deinit();
    const stat = try compat.cwd().statFile(keylog_path);
    try testing.expectEqual(@as(u16, 0), @as(u16, @intCast(@intFromEnum(stat.permissions) & 0o077)));

    var context = artifacts.keylogContext();
    const random = [_]u8{0x33} ** tls_core.keylog.client_random_len;
    try context.setClientRandom(&random);
    context.emitSecret(.handshake, .write, &[_]u8{0xcc});
    artifacts.waitIdle();

    const contents = try compat.cwd().readFileAlloc(testing.allocator, keylog_path, 1024);
    defer testing.allocator.free(contents);
    try testing.expect(std.mem.endsWith(u8, contents, " cc\n"));
}
