//! Nonblocking encrypted byte-stream contract for TLS-over-TCP.
//!
//! HTTP/1.1 and HTTP/2 should consume decrypted bytes and produce plaintext
//! writes without caring whether the TLS implementation underneath is OpenSSL
//! or the native record path. This module defines that small contract and the
//! native record-mode stream state that maps caller-fed ciphertext into
//! plaintext queues without blocking or growing unbounded buffers.

const std = @import("std");
const builtin = @import("builtin");
const crypto = @import("crypto");
const algorithms = @import("algorithms.zig");
const alerts = @import("alerts.zig");
const engine = @import("engine.zig");
const events = @import("events.zig");
const keylog = @import("keylog.zig");
const key_update = @import("key_update.zig");
const record_codec = @import("record_codec.zig");
const record_epoch_bridge = @import("record_epoch_bridge.zig");
const record_size = @import("record_size.zig");
const tls_state = @import("state.zig");
const tls13_transport = @import("tls13_transport.zig");

const provider = crypto.provider;

/// Error set carried by the transport-neutral TLS 1.3 engine contract.
pub const RecordHandshakeError = tls13_transport.Error;

/// The canonical record-mode handshake transport contract (#408): protocol
/// events keyed on `events.EncryptionEpoch`, no decoded transport-parameter
/// payload, reusing the shared transport-neutral contract and
/// `engine.Driver` rather than a parallel driver of its own.
pub const RecordTransport = tls13_transport.Contract;
/// The injected backend seam: a concrete TLS 1.3 engine (wired from a module
/// above `tls_core`, e.g. the pure-Zig engine wrapped for record mode) drives
/// the handshake through this vtable and reports keying/negotiation results
/// through the shared `EventSink`.
pub const RecordHandshakeBackend = RecordTransport.Backend;
/// The shared engine driver instantiated for record mode. `PureZigRecordStream`
/// owns one of these and progresses it inside `drive()`.
pub const RecordHandshakeDriver = engine.Driver(RecordTransport);

pub const Error = RecordHandshakeError || record_epoch_bridge.Error || error{
    WouldBlock,
    EndOfStream,
    StreamClosed,
    InvalidBufferLimits,
    PlaintextBufferFull,
    CiphertextBufferFull,
    UnsupportedRecordContent,
    CarrierInputBufferFull,
    SocketPairFailed,
    FcntlFailed,
    SocketReadFailed,
    SocketWriteFailed,
    MalformedAlert,
    PeerFatalAlert,
    TruncatedStream,
    /// A `.handshake` epoch discard landed with a not-yet-complete record
    /// still buffered in `ciphertext_parser`. See `applyEvent`.
    PartialRecordAtEpochTransition,
    RetryOperationPending,
};

const Lifecycle = enum {
    handshaking,
    open,
    closing,
    closed,
    failed,
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

pub const Watermark = struct {
    low: usize,
    high: usize,
    hard: usize,

    fn validate(self: Watermark, capacity: usize, reserve: usize) Error!void {
        if (self.low == 0 or self.high == 0 or self.hard == 0) return error.InvalidBufferLimits;
        if (!(self.low < self.high and self.high <= self.hard)) return error.InvalidBufferLimits;
        if (self.hard > capacity) return error.InvalidBufferLimits;
        if (self.hard < reserve) return error.InvalidBufferLimits;
    }
};

pub const BufferLimits = struct {
    inbound_ciphertext: Watermark,
    inbound_plaintext: Watermark,
    outbound_ciphertext: Watermark,
    handshake: Watermark,

    pub fn defaults() BufferLimits {
        return .{
            .inbound_ciphertext = defaultWatermark(PureZigRecordStream.max_carrier_input_queue, record_codec.max_ciphertext_record_len),
            .inbound_plaintext = defaultWatermark(PureZigRecordStream.max_plaintext_queue, record_codec.max_plaintext_fragment_len),
            .outbound_ciphertext = defaultWatermark(PureZigRecordStream.max_ciphertext_queue, PureZigRecordStream.handshake_output_reserve),
            .handshake = defaultWatermark(PureZigRecordStream.max_handshake_queue, record_codec.max_plaintext_fragment_len),
        };
    }

    pub fn validate(self: BufferLimits) Error!void {
        try self.inbound_ciphertext.validate(PureZigRecordStream.max_carrier_input_queue, record_codec.max_ciphertext_record_len);
        try self.inbound_plaintext.validate(PureZigRecordStream.max_plaintext_queue, record_codec.max_plaintext_fragment_len);
        try self.outbound_ciphertext.validate(PureZigRecordStream.max_ciphertext_queue, PureZigRecordStream.handshake_output_reserve);
        try self.handshake.validate(PureZigRecordStream.max_handshake_queue, record_codec.max_plaintext_fragment_len);
    }

    fn defaultWatermark(capacity: usize, reserve: usize) Watermark {
        const low = @max(@as(usize, 1), @min(capacity / 4, capacity - 1));
        _ = reserve;
        const high_candidate = @max(low + 1, (capacity * 3) / 4);
        return .{
            .low = low,
            .high = @min(high_candidate, capacity),
            .hard = capacity,
        };
    }
};

pub const QueueBytes = struct {
    inbound_ciphertext: usize = 0,
    inbound_plaintext: usize = 0,
    outbound_ciphertext: usize = 0,
    handshake: usize = 0,

    pub fn total(self: QueueBytes) usize {
        return self.inbound_ciphertext + self.inbound_plaintext + self.outbound_ciphertext + self.handshake;
    }
};

pub const QueueCounters = struct {
    inbound_ciphertext: u64 = 0,
    inbound_plaintext: u64 = 0,
    outbound_ciphertext: u64 = 0,
    handshake: u64 = 0,

    fn increment(self: *QueueCounters, queue: BufferQueue) void {
        switch (queue) {
            .inbound_ciphertext => self.inbound_ciphertext += 1,
            .inbound_plaintext => self.inbound_plaintext += 1,
            .outbound_ciphertext => self.outbound_ciphertext += 1,
            .handshake => self.handshake += 1,
        }
    }
};

/// Uses `std.math.divCeil`'s `@divFloor(numerator - 1, denominator) + 1`
/// form rather than the `(bytes_len + chunk_size - 1) / chunk_size` idiom,
/// so a synthetic near-`usize`-max `bytes_len` -- the #493 "overflow-
/// adjacent synthetic limits" case -- never overflows this addition, unlike
/// the naive form; mirrors `record_epoch_bridge.zig`'s `chunkCount`. The
/// `Error!` return exists for parity with that helper's signature, not
/// because this one can itself overflow.
fn handshakeRecordCount(bytes_len: usize) record_codec.Error!usize {
    if (bytes_len == 0) return 0;
    return std.math.divCeil(usize, bytes_len, record_codec.max_plaintext_fragment_len) catch error.RecordTooLarge;
}

pub const BufferCounters = struct {
    inbound_read_pauses: u64 = 0,
    inbound_read_resumes: u64 = 0,
    plaintext_write_pauses: u64 = 0,
    plaintext_write_resumes: u64 = 0,
    hard_limits: QueueCounters = .{},
    stalled_drives: u64 = 0,
};

pub const PauseState = struct {
    inbound_read_paused: bool = false,
    plaintext_write_paused: bool = false,
};

pub const AccountingBoundary = enum {
    complete_stream_owned,
    backend_opaque,
};

pub const BufferSnapshot = struct {
    current: QueueBytes = .{},
    peak: QueueBytes = .{},
    peak_total: usize = 0,
    limits: ?BufferLimits = null,
    limits_enforced: bool = false,
    pause_state: PauseState = .{},
    counters: BufferCounters = .{},
    accounting_boundary: AccountingBoundary = .complete_stream_owned,
};

const BufferQueue = enum {
    inbound_ciphertext,
    inbound_plaintext,
    outbound_ciphertext,
    handshake,
};

fn PlaintextProvenanceQueue(comptime capacity: usize) type {
    return struct {
        buf: [capacity]bool = [_]bool{false} ** capacity,
        len: usize = 0,

        const Self = @This();

        fn append(self: *Self, byte_len: usize, transport_early: bool) Error!void {
            if (byte_len > self.available()) return error.PlaintextBufferFull;
            @memset(self.buf[self.len..][0..byte_len], transport_early);
            self.len += byte_len;
        }

        fn discard(self: *Self, byte_len: usize) usize {
            const n = @min(byte_len, self.len);
            var early_prefix_len: usize = 0;
            while (early_prefix_len < n and self.buf[early_prefix_len]) {
                early_prefix_len += 1;
            }
            const old_len = self.len;
            const remaining = old_len - n;
            std.mem.copyForwards(bool, self.buf[0..remaining], self.buf[n..old_len]);
            @memset(self.buf[remaining..old_len], false);
            self.len = remaining;
            return early_prefix_len;
        }

        fn available(self: *const Self) usize {
            return capacity - self.len;
        }

        fn clear(self: *Self) void {
            @memset(self.buf[0..self.len], false);
            self.len = 0;
        }
    };
}

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
        bufferSnapshotFn: *const fn (*anyopaque) BufferSnapshot,
        currentReadEarlyPrefixLenFn: ?*const fn (*anyopaque) usize = null,
    };

    pub fn backend(self: EncryptedStream) BackendKind {
        return self.vtable.backendFn(self.ptr);
    }

    pub fn read(self: EncryptedStream, out: []u8) Error!usize {
        return self.vtable.readFn(self.ptr, out);
    }

    /// Attempts to write plaintext. After a nonblocking write returns
    /// `WouldBlock`, backends that depend on same-operation retries may require
    /// the original write slice to be retried before any other plaintext I/O.
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

    pub fn bufferSnapshot(self: EncryptedStream) BufferSnapshot {
        return self.vtable.bufferSnapshotFn(self.ptr);
    }

    pub fn currentReadEarlyPrefixLen(self: EncryptedStream) usize {
        const cb = self.vtable.currentReadEarlyPrefixLenFn orelse return 0;
        return cb(self.ptr);
    }
};

/// Shared open-stream assertions used by each production backend's tests.
pub fn expectOpenIdleConformance(stream: EncryptedStream, expected_backend: BackendKind) !void {
    try std.testing.expectEqual(expected_backend, stream.backend());

    const readiness = stream.readiness();
    try std.testing.expect(readiness.wants_read);
    try std.testing.expect(!readiness.wants_write);
    try std.testing.expect(!readiness.can_read_plaintext);
    try std.testing.expect(readiness.can_write_plaintext);
    try std.testing.expect(!readiness.peer_closed);

    var scratch: [8]u8 = undefined;
    try std.testing.expectError(error.WouldBlock, stream.read(&scratch));
    const blocked = stream.readiness();
    try std.testing.expect(blocked.wants_read);
    try std.testing.expect(!blocked.wants_write);
    try std.testing.expect(!blocked.can_read_plaintext);
    try std.testing.expect(!blocked.peer_closed);

    const driven = try stream.drive();
    try std.testing.expect(!driven.made_progress);
    try std.testing.expectEqual(blocked, driven.readiness);
}

pub fn expectClosedConformance(stream: EncryptedStream) !void {
    var scratch: [8]u8 = undefined;
    try std.testing.expectError(error.StreamClosed, stream.read(&scratch));
    try std.testing.expectError(error.StreamClosed, stream.write("after-close"));
    const readiness = stream.readiness();
    try std.testing.expect(!readiness.wants_read);
    try std.testing.expect(!readiness.wants_write);
    try std.testing.expect(!readiness.can_read_plaintext);
    try std.testing.expect(!readiness.can_write_plaintext);
    const driven = try stream.drive();
    try std.testing.expect(!driven.made_progress);
    try std.testing.expectEqual(readiness, driven.readiness);
}

pub fn expectLatchedFailureConformance(stream: EncryptedStream, expected_error: anyerror) !void {
    var scratch: [8]u8 = undefined;
    try std.testing.expectError(expected_error, stream.read(&scratch));
    try std.testing.expectError(expected_error, stream.write("after-failure"));
    try std.testing.expectError(expected_error, stream.drive());
    const readiness = stream.readiness();
    try std.testing.expect(!readiness.wants_read);
    try std.testing.expect(!readiness.wants_write);
    try std.testing.expect(!readiness.can_read_plaintext);
    try std.testing.expect(!readiness.can_write_plaintext);
}

pub const Carrier = struct {
    ptr: *anyopaque,
    readFn: *const fn (*anyopaque, []u8) Error!usize,
    writeFn: *const fn (*anyopaque, []const u8) Error!usize,
    closeFn: ?*const fn (*anyopaque) void = null,
    /// When false, the caller owns the carrier handle and must close it. When
    /// true, `PureZigRecordStream.deinit`, fatal failure, and completed close
    /// call `closeFn` exactly once through the stream.
    owns_handle: bool = false,

    pub fn read(self: Carrier, out: []u8) Error!usize {
        return self.readFn(self.ptr, out);
    }

    pub fn write(self: Carrier, bytes: []const u8) Error!usize {
        return self.writeFn(self.ptr, bytes);
    }

    pub fn close(self: Carrier) void {
        if (self.closeFn) |closeFn| closeFn(self.ptr);
    }
};

pub const PureZigRecordStream = struct {
    pub const max_plaintext_queue = 32 * 1024;
    pub const max_ciphertext_queue = 4 * record_codec.max_ciphertext_record_len;
    pub const max_carrier_input_queue = 4 * record_codec.max_ciphertext_record_len;
    pub const max_handshake_queue = 16 * 1024;
    const drive_read_budget = 2 * record_codec.max_ciphertext_record_len;
    const drive_write_budget = 2 * record_codec.max_ciphertext_record_len;
    const drive_record_budget = 8;
    const drive_read_chunk = 4096;
    /// Worst-case serialized output a single borrowed driver event batch can
    /// produce (the shared `EventSink` bounds a batch to a few handshake-bytes
    /// events, each sealing into at most one record). `drive()` refuses to
    /// progress the backend unless the outbound queue has at least this much
    /// room, so an entire batch can be serialized atomically -- no partial
    /// application that would then have to overwrite the still-borrowed sink.
    const handshake_output_reserve = 3 * record_codec.max_ciphertext_record_len;
    /// RFC 7301 caps a single ALPN protocol name at 255 bytes.
    const max_alpn_len = 255;
    /// Bounded deadline for flushing a terminal fatal alert to a carrier that
    /// never drains (peer gone, permanently full): after this many `drive()`
    /// attempts the stream latches the preserved failure regardless, so a stuck
    /// carrier cannot wedge the failure forever.
    const max_terminal_flush_attempts = 16;

    bridge: record_epoch_bridge.Bridge,
    /// Handshake role retained for record-mode authentication policy. Clients
    /// require an explicitly verified server certificate by default; servers
    /// do not require client authentication in the current profile.
    role: tls_state.Role,
    /// Explicit opt-in for backends configured without certificate
    /// verification. This mirrors the QUIC driver's policy and keeps
    /// `.certificate(.not_checked)` from silently opening a client stream.
    allow_unverified_certificate: bool = false,
    /// The shared TLS handshake driver, present only when a concrete backend was
    /// injected (`initWithBackend`/`initWithCarrierAndBackend`). Absent for the
    /// lower-level record-plumbing paths that drive events in by hand.
    handshake_driver: ?RecordHandshakeDriver = null,
    /// Guards the driver against a second teardown (its backend `deinit` is not
    /// idempotent). Set once `teardownDriver` runs; the driver value is left in
    /// place afterward so its securely-wiped sink stays observable.
    driver_torn_down: bool = false,
    handshake_started: bool = false,
    /// Explicit protocol epochs for inbound and outbound records. Tracked as a
    /// deliberate state machine rather than inferred from which keys happen to
    /// be installed: after the server installs its application read secret the
    /// peer's next record (its Finished) is still handshake-epoch, so key
    /// presence alone cannot pick the epoch. `read`/`write` advance to
    /// `.handshake` when that direction's handshake secret installs and to
    /// `.application` only at authenticated `handshake_complete`.
    read_epoch: events.EncryptionEpoch = .initial,
    write_epoch: events.EncryptionEpoch = .initial,
    initial_parser: record_codec.Parser = record_codec.Parser.init(.plaintext),
    ciphertext_parser: record_codec.Parser = record_codec.Parser.init(.ciphertext),
    inbound_carrier: ByteQueue(max_carrier_input_queue, error.CarrierInputBufferFull) = .{},
    inbound_plaintext: ByteQueue(max_plaintext_queue, error.PlaintextBufferFull) = .{},
    inbound_plaintext_provenance: PlaintextProvenanceQueue(max_plaintext_queue) = .{},
    outbound_ciphertext: ByteQueue(max_ciphertext_queue, error.CiphertextBufferFull) = .{},
    inbound_handshake: ByteQueue(max_handshake_queue, error.PlaintextBufferFull) = .{},
    /// Proactive `KeyUpdate` policy (#357), disabled by default. See
    /// `keyUpdateDue` — this stream reports the threshold but never acts on it
    /// by itself.
    key_update_limits: key_update.UsageLimits = .{},
    buffer_limits: BufferLimits = BufferLimits.defaults(),
    buffer_peaks: QueueBytes = .{},
    peak_total_owned: usize = 0,
    buffer_counters: BufferCounters = .{},
    read_backpressured: bool = false,
    write_backpressured: bool = false,
    /// Negotiated ALPN protocol captured from the handshake, retained behind
    /// `negotiatedAlpn()` for later HTTP dispatch (out of scope here, #356).
    alpn_storage: [max_alpn_len]u8 = undefined,
    alpn_len: usize = 0,
    alpn_captured: bool = false,
    /// Optional stream-owned client ALPN policy. Negotiated metadata alone is
    /// insufficient: a client that requires a protocol must reject both a
    /// different server selection and a missing ALPN extension.
    expected_alpn_storage: [max_alpn_len]u8 = undefined,
    expected_alpn_len: usize = 0,
    require_alpn: bool = false,
    certificate_state: events.CertificateState = .not_checked,
    /// The description of the fatal alert the peer sent, retained alongside
    /// the resulting `error.PeerFatalAlert` (#338). The error alone says only
    /// *that* the peer rejected us; conformance work and operator diagnostics
    /// need to know *which* RFC 8446 §6 failure class it chose, and a peer's
    /// alert description is public wire data, never secret. Diagnostic only --
    /// nothing in the stream's own state machine reads it.
    peer_alert: ?alerts.AlertDescription = null,
    /// A terminal handshake failure whose emitted fatal alert is being flushed
    /// to the carrier before the stream latches closed (`drive()` step 13). The
    /// underlying failure is preserved regardless of whether the alert lands.
    pending_terminal: ?Error = null,
    /// Bounded flush attempts spent draining a pending terminal alert.
    terminal_flush_attempts: usize = 0,
    carrier: ?Carrier = null,
    lifecycle: Lifecycle = .handshaking,
    peer_closed: bool = false,
    carrier_eof: bool = false,
    close_notify_queued: bool = false,
    pending_terminal_read_error: ?Error = null,
    last_read_early_prefix_len: usize = 0,
    zero_rtt_sent: u64 = 0,
    zero_rtt_accepted: u64 = 0,
    rejected_early_bytes: u64 = 0,
    failed: ?Error = null,

    pub fn init(role: tls_state.Role, crypto_provider: provider.CryptoProvider, cipher_suite: algorithms.CipherSuite) PureZigRecordStream {
        // Only a server's initial-epoch parser may ever legally see the
        // RFC 8446 SS5.1 ClientHello compatibility version (0x0301), and only
        // for the first record it consumes; every other parser instance stays
        // strict. See record_codec.VersionPolicy.
        const initial_policy: record_codec.VersionPolicy = if (role == .server)
            .allow_initial_client_hello_compat
        else
            .strict;
        return .{
            .bridge = record_epoch_bridge.Bridge.init(crypto_provider, cipher_suite),
            .role = role,
            .initial_parser = record_codec.Parser.initWithVersionPolicy(.plaintext, initial_policy),
        };
    }

    pub fn initWithLimits(
        role: tls_state.Role,
        crypto_provider: provider.CryptoProvider,
        cipher_suite: algorithms.CipherSuite,
        limits: BufferLimits,
    ) Error!PureZigRecordStream {
        try limits.validate();
        var stream_state = init(role, crypto_provider, cipher_suite);
        stream_state.buffer_limits = limits;
        return stream_state;
    }

    pub fn initWithCarrier(role: tls_state.Role, crypto_provider: provider.CryptoProvider, cipher_suite: algorithms.CipherSuite, carrier: Carrier) PureZigRecordStream {
        std.debug.assert(!carrier.owns_handle or carrier.closeFn != null);
        var stream_state = init(role, crypto_provider, cipher_suite);
        stream_state.carrier = carrier;
        return stream_state;
    }

    pub fn initWithCarrierAndLimits(
        role: tls_state.Role,
        crypto_provider: provider.CryptoProvider,
        cipher_suite: algorithms.CipherSuite,
        carrier: Carrier,
        limits: BufferLimits,
    ) Error!PureZigRecordStream {
        std.debug.assert(!carrier.owns_handle or carrier.closeFn != null);
        var stream_state = try initWithLimits(role, crypto_provider, cipher_suite, limits);
        stream_state.carrier = carrier;
        return stream_state;
    }

    /// Like `init`, but the stream owns a shared TLS handshake driver over the
    /// injected `backend`. `drive()` then starts and progresses the real
    /// handshake itself rather than relying on callers to hand-apply events.
    pub fn initWithBackend(
        allocator: std.mem.Allocator,
        role: tls_state.Role,
        crypto_provider: provider.CryptoProvider,
        cipher_suite: algorithms.CipherSuite,
        backend: RecordHandshakeBackend,
    ) Error!PureZigRecordStream {
        var stream_state = init(role, crypto_provider, cipher_suite);
        if (role == .client) try backend.setPostHandshakeAllocator(allocator);
        stream_state.handshake_driver = RecordHandshakeDriver.init(role, backend);
        return stream_state;
    }

    pub fn initWithBackendAndLimits(
        allocator: std.mem.Allocator,
        role: tls_state.Role,
        crypto_provider: provider.CryptoProvider,
        cipher_suite: algorithms.CipherSuite,
        backend: RecordHandshakeBackend,
        limits: BufferLimits,
    ) Error!PureZigRecordStream {
        var stream_state = try initWithLimits(role, crypto_provider, cipher_suite, limits);
        if (role == .client) try backend.setPostHandshakeAllocator(allocator);
        stream_state.handshake_driver = RecordHandshakeDriver.init(role, backend);
        return stream_state;
    }

    /// `initWithBackend` plus a nonblocking carrier, the production shape: a
    /// real backend driving a real handshake over a real byte-stream carrier.
    pub fn initWithCarrierAndBackend(
        allocator: std.mem.Allocator,
        role: tls_state.Role,
        crypto_provider: provider.CryptoProvider,
        cipher_suite: algorithms.CipherSuite,
        carrier: Carrier,
        backend: RecordHandshakeBackend,
    ) Error!PureZigRecordStream {
        std.debug.assert(!carrier.owns_handle or carrier.closeFn != null);
        var stream_state = try initWithBackend(allocator, role, crypto_provider, cipher_suite, backend);
        stream_state.carrier = carrier;
        return stream_state;
    }

    pub fn initWithCarrierBackendAndLimits(
        allocator: std.mem.Allocator,
        role: tls_state.Role,
        crypto_provider: provider.CryptoProvider,
        cipher_suite: algorithms.CipherSuite,
        carrier: Carrier,
        backend: RecordHandshakeBackend,
        limits: BufferLimits,
    ) Error!PureZigRecordStream {
        std.debug.assert(!carrier.owns_handle or carrier.closeFn != null);
        var stream_state = try initWithBackendAndLimits(allocator, role, crypto_provider, cipher_suite, backend, limits);
        stream_state.carrier = carrier;
        return stream_state;
    }

    pub fn setKeylogContext(self: *PureZigRecordStream, context: keylog.Context) Error!void {
        if (self.handshake_started) return error.InvalidHandshakeState;
        const driver = if (self.handshake_driver) |*d| d else return error.InvalidHandshakeState;
        var owned = context;
        owned.role = self.role;
        driver.sink.keylog_context = owned;
    }

    /// The ALPN protocol negotiated by the handshake, or null if none was seen.
    pub fn negotiatedAlpn(self: *const PureZigRecordStream) ?[]const u8 {
        if (!self.alpn_captured) return null;
        return self.alpn_storage[0..self.alpn_len];
    }

    /// True only after the TLS handshake has authenticated and application
    /// data is legal. ALPN may be absent for explicit HTTP/1.1 fallback, so
    /// protocol dispatch must gate on this state rather than ALPN presence.
    pub fn applicationDataOpen(self: *const PureZigRecordStream) bool {
        return self.lifecycle == .open and self.bridge.handshake_complete;
    }

    pub fn currentReadTransportEarly(self: *const PureZigRecordStream) bool {
        return self.last_read_early_prefix_len > 0;
    }

    pub fn currentReadEarlyPrefixLen(self: *const PureZigRecordStream) usize {
        return self.last_read_early_prefix_len;
    }

    /// Require the peer to negotiate exactly `protocol`. Configure this before
    /// the handshake starts; the value is copied because caller storage need
    /// not outlive construction.
    pub fn setExpectedAlpn(self: *PureZigRecordStream, protocol: []const u8) Error!void {
        if (self.handshake_started) return error.InvalidHandshakeState;
        if (protocol.len == 0 or protocol.len > max_alpn_len) return error.MalformedHandshake;
        if (self.expected_alpn_len > 0) @memset(self.expected_alpn_storage[0..self.expected_alpn_len], 0);
        @memcpy(self.expected_alpn_storage[0..protocol.len], protocol);
        self.expected_alpn_len = protocol.len;
        self.require_alpn = true;
    }

    /// Install the local record-padding policy (RFC 8446 §5.4, #359).
    ///
    /// Padding is a privacy control, not a performance one: it hides how many
    /// content bytes each record carried, and costs bandwidth and AEAD work
    /// for every byte it adds. It is never negotiated, so this is a local
    /// setting with no wire signal — and it is deliberately separate from
    /// `record_size_limit`, which *is* negotiated and bounds what the padding
    /// may grow into.
    pub fn setRecordPadding(self: *PureZigRecordStream, padding: record_size.PaddingPolicy) Error!void {
        return self.bridge.setRecordPadding(padding);
    }

    /// The connection's negotiated `record_size_limit` state (#359). Before
    /// the handshake settles it reports this endpoint's own advertisement with
    /// no peer value, which is the same thing an un-negotiated connection
    /// means.
    pub fn recordSizeLimits(self: *const PureZigRecordStream) record_size.Limits {
        return self.bridge.record_size_limits;
    }

    /// Observable record-sizing effects: writes narrowed by the peer's limit,
    /// padding actually emitted, and inbound records refused for exceeding
    /// our own advertisement.
    pub fn recordSizeCounters(self: *const PureZigRecordStream) record_size.Counters {
        return self.bridge.record_size_counters;
    }

    /// Mirror the backend's negotiated record-size state into the bridge that
    /// actually seals and opens records. Idempotent: re-reading a settled
    /// negotiation installs the same values.
    fn refreshRecordSizeLimits(self: *PureZigRecordStream) Error!void {
        const driver = if (self.handshake_driver) |*d| d else return;
        try self.bridge.setRecordSizeLimits(driver.backend.recordSizeLimits());
    }

    /// The peer certificate validation outcome the backend reported.
    pub fn certificateState(self: *const PureZigRecordStream) events.CertificateState {
        return self.certificate_state;
    }

    /// The description of the fatal alert the peer sent, when the stream
    /// failed with `error.PeerFatalAlert` (#338). `null` when the peer sent no
    /// fatal alert -- including when *this* side is the one that rejected the
    /// handshake, whose own alert is derived from its typed failure through
    /// `alerts.fromHandshakeError`.
    pub fn peerAlert(self: *const PureZigRecordStream) ?alerts.AlertDescription {
        return self.peer_alert;
    }

    pub fn deinit(self: *PureZigRecordStream) void {
        self.teardownDriver();
        self.bridge.deinit();
        self.clearOwnedQueues();
        self.clearHandshakeMetadata();
        self.initial_parser.reset();
        self.ciphertext_parser.reset();
        self.closeCarrier();
        self.lifecycle = .closed;
        self.peer_closed = true;
        self.carrier_eof = false;
        self.close_notify_queued = false;
        self.pending_terminal_read_error = null;
        self.last_read_early_prefix_len = 0;
        self.zero_rtt_sent = 0;
        self.zero_rtt_accepted = 0;
        self.rejected_early_bytes = 0;
        self.pending_terminal = null;
        self.terminal_flush_attempts = 0;
        self.failed = null;
    }

    /// Tear the shared handshake driver down exactly once. `Driver.deinit`
    /// securely wipes any traffic secret still copied into its borrowed event
    /// sink and releases the backend, per the contract's teardown rule. The
    /// driver value is deliberately left in place (rather than nulled) so its
    /// wiped sink remains observable; `driver_torn_down` prevents a second,
    /// non-idempotent backend `deinit`.
    fn teardownDriver(self: *PureZigRecordStream) void {
        if (self.driver_torn_down) return;
        if (self.handshake_driver) |*driver| driver.deinit();
        self.driver_torn_down = true;
    }

    /// Wipe captured ALPN/certificate negotiation metadata back to its initial
    /// state, so no residue survives teardown or a fatal failure.
    fn clearHandshakeMetadata(self: *PureZigRecordStream) void {
        if (self.alpn_len > 0) @memset(self.alpn_storage[0..self.alpn_len], 0);
        self.alpn_len = 0;
        self.alpn_captured = false;
        if (self.expected_alpn_len > 0) @memset(self.expected_alpn_storage[0..self.expected_alpn_len], 0);
        self.expected_alpn_len = 0;
        self.require_alpn = false;
        self.certificate_state = .not_checked;
        self.read_epoch = .initial;
        self.write_epoch = .initial;
        self.handshake_started = false;
    }

    pub fn stream(self: *PureZigRecordStream) EncryptedStream {
        return .{ .ptr = self, .vtable = &pure_zig_record_vtable };
    }

    pub fn bufferSnapshot(self: *const PureZigRecordStream) BufferSnapshot {
        return .{
            .current = self.currentQueueBytes(),
            .peak = self.buffer_peaks,
            .peak_total = self.peak_total_owned,
            .limits = self.buffer_limits,
            .limits_enforced = true,
            .pause_state = .{
                .inbound_read_paused = self.read_backpressured,
                .plaintext_write_paused = self.write_backpressured,
            },
            .counters = self.buffer_counters,
            .accounting_boundary = .complete_stream_owned,
        };
    }

    fn currentQueueBytes(self: *const PureZigRecordStream) QueueBytes {
        return .{
            .inbound_ciphertext = self.inboundCiphertextOwned(),
            .inbound_plaintext = self.inbound_plaintext.len,
            .outbound_ciphertext = self.outbound_ciphertext.len,
            .handshake = self.inbound_handshake.len,
        };
    }

    fn inboundCiphertextOwned(self: *const PureZigRecordStream) usize {
        return self.inbound_carrier.len + self.initial_parser.len + self.ciphertext_parser.len;
    }

    fn updateQueuePeaks(self: *PureZigRecordStream) void {
        const current = self.currentQueueBytes();
        self.buffer_peaks.inbound_ciphertext = @max(self.buffer_peaks.inbound_ciphertext, current.inbound_ciphertext);
        self.buffer_peaks.inbound_plaintext = @max(self.buffer_peaks.inbound_plaintext, current.inbound_plaintext);
        self.buffer_peaks.outbound_ciphertext = @max(self.buffer_peaks.outbound_ciphertext, current.outbound_ciphertext);
        self.buffer_peaks.handshake = @max(self.buffer_peaks.handshake, current.handshake);
        self.peak_total_owned = @max(self.peak_total_owned, current.total());
    }

    fn watermarkFor(self: *const PureZigRecordStream, queue: BufferQueue) Watermark {
        return switch (queue) {
            .inbound_ciphertext => self.buffer_limits.inbound_ciphertext,
            .inbound_plaintext => self.buffer_limits.inbound_plaintext,
            .outbound_ciphertext => self.buffer_limits.outbound_ciphertext,
            .handshake => self.buffer_limits.handshake,
        };
    }

    fn hasHardRoom(self: *const PureZigRecordStream, queue: BufferQueue, current_len: usize, needed: usize) bool {
        const hard = self.watermarkFor(queue).hard;
        return needed <= hard and current_len <= hard - needed;
    }

    fn rejectHardLimit(self: *PureZigRecordStream, queue: BufferQueue, err: Error) Error {
        self.buffer_counters.hard_limits.increment(queue);
        return err;
    }

    fn refreshBackpressure(self: *PureZigRecordStream) void {
        const limits = self.buffer_limits;
        const inbound_ciphertext = self.inboundCiphertextOwned();
        const read_high = inbound_ciphertext >= limits.inbound_ciphertext.high or
            self.inbound_plaintext.len >= limits.inbound_plaintext.high or
            self.inbound_handshake.len >= limits.handshake.high;
        const read_low = inbound_ciphertext <= limits.inbound_ciphertext.low and
            self.inbound_plaintext.len <= limits.inbound_plaintext.low and
            self.inbound_handshake.len <= limits.handshake.low;
        if (!self.read_backpressured and read_high) {
            self.read_backpressured = true;
            self.buffer_counters.inbound_read_pauses += 1;
        } else if (self.read_backpressured and read_low) {
            self.read_backpressured = false;
            self.buffer_counters.inbound_read_resumes += 1;
        }

        const write_high = self.outbound_ciphertext.len >= limits.outbound_ciphertext.high;
        const write_low = self.outbound_ciphertext.len <= limits.outbound_ciphertext.low;
        if (!self.write_backpressured and write_high) {
            self.write_backpressured = true;
            self.buffer_counters.plaintext_write_pauses += 1;
        } else if (self.write_backpressured and write_low) {
            self.write_backpressured = false;
            self.buffer_counters.plaintext_write_resumes += 1;
        }
    }

    fn noteQueueMutation(self: *PureZigRecordStream) void {
        self.updateQueuePeaks();
        self.refreshBackpressure();
    }

    /// Complete an orderly close. Beyond dropping every owned buffer this also
    /// releases the two other holders of secret-bearing state -- the handshake
    /// driver (whose borrowed `EventSink` may still hold copied traffic-secret
    /// scratch until `Driver.deinit()`, per the transport contract) and the
    /// bridge's key material. A `.closed` stream rejects every entry point, so
    /// no record can ever be sealed or opened again and nothing here can be
    /// needed again; holding either until an eventual outer `deinit()` is
    /// retention without a purpose. This is the same teardown order `deinit()`
    /// and `fail()` use, for the orderly path.
    fn finishClose(self: *PureZigRecordStream) void {
        self.teardownDriver();
        self.clearOwnedQueues();
        self.bridge.deinit();
        self.lifecycle = .closed;
    }

    fn clearOwnedQueues(self: *PureZigRecordStream) void {
        self.inbound_carrier.clear();
        self.inbound_plaintext.clear();
        self.inbound_plaintext_provenance.clear();
        self.outbound_ciphertext.clear();
        self.inbound_handshake.clear();
        self.initial_parser.reset();
        self.ciphertext_parser.reset();
        self.read_backpressured = false;
        self.write_backpressured = false;
    }

    fn appendInboundCarrier(self: *PureZigRecordStream, bytes: []const u8) Error!void {
        if (!self.hasHardRoom(.inbound_ciphertext, self.inboundCiphertextOwned(), bytes.len)) return self.rejectHardLimit(.inbound_ciphertext, error.CarrierInputBufferFull);
        try self.inbound_carrier.append(bytes);
        self.noteQueueMutation();
    }

    fn appendInboundPlaintext(self: *PureZigRecordStream, bytes: []const u8, transport_early: bool) Error!void {
        if (!self.hasHardRoom(.inbound_plaintext, self.inbound_plaintext.len, bytes.len)) return self.rejectHardLimit(.inbound_plaintext, error.PlaintextBufferFull);
        try self.inbound_plaintext_provenance.append(bytes.len, transport_early);
        try self.inbound_plaintext.append(bytes);
        self.noteQueueMutation();
    }

    fn appendInboundHandshake(self: *PureZigRecordStream, bytes: []const u8) Error!void {
        if (!self.hasHardRoom(.handshake, self.inbound_handshake.len, bytes.len)) return self.rejectHardLimit(.handshake, error.PlaintextBufferFull);
        try self.inbound_handshake.append(bytes);
        self.noteQueueMutation();
    }

    fn appendOutboundCiphertext(self: *PureZigRecordStream, bytes: []const u8) Error!void {
        if (!self.hasHardRoom(.outbound_ciphertext, self.outbound_ciphertext.len, bytes.len)) return self.rejectHardLimit(.outbound_ciphertext, error.CiphertextBufferFull);
        try self.outbound_ciphertext.append(bytes);
        self.noteQueueMutation();
    }

    fn canReserveOutboundRecord(self: *const PureZigRecordStream) bool {
        return self.outbound_ciphertext.available() >= record_codec.max_ciphertext_record_len and
            self.hasHardRoom(.outbound_ciphertext, self.outbound_ciphertext.len, record_codec.max_ciphertext_record_len);
    }

    fn canReserveOutboundHandshakeBytes(self: *PureZigRecordStream, epoch: events.EncryptionEpoch, bytes_len: usize) Error!bool {
        const needed = try self.bridge.sealedHandshakeLen(epoch, bytes_len);
        return self.outbound_ciphertext.available() >= needed and
            self.hasHardRoom(.outbound_ciphertext, self.outbound_ciphertext.len, needed);
    }

    fn emitHandshakeRecords(self: *PureZigRecordStream, epoch: events.EncryptionEpoch, bytes: []const u8) Error!void {
        if (!try self.canReserveOutboundHandshakeBytes(epoch, bytes.len)) return error.WouldBlock;

        // #359: RFC 8449 §4 exempts unprotected records ("Unprotected
        // messages are not subject to this limit"), so the initial epoch's
        // plaintext ClientHello/ServerHello keeps the full protocol fragment
        // even against a peer that advertised a smaller limit.
        const chunk = if (epoch == .initial)
            record_codec.max_plaintext_fragment_len
        else
            self.bridge.outboundContentMax();
        var offset: usize = 0;
        while (offset < bytes.len) {
            const take = @min(chunk, bytes.len - offset);
            var record_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
            const record = self.bridge.sealHandshake(epoch, bytes[offset..][0..take], &record_buf) catch |err| return self.fail(err);
            self.appendOutboundCiphertext(record) catch |err| return self.fail(err);
            offset += take;
        }
    }

    fn canReserveHandshakeOutputBatch(self: *PureZigRecordStream) bool {
        return self.outbound_ciphertext.available() >= handshake_output_reserve and
            self.hasHardRoom(.outbound_ciphertext, self.outbound_ciphertext.len, handshake_output_reserve);
    }

    fn activeInboundParser(self: *const PureZigRecordStream) *const record_codec.Parser {
        if (self.bridge.handshake_complete) return &self.ciphertext_parser;
        return switch (self.read_epoch) {
            .initial => &self.initial_parser,
            .handshake, .application, .zero_rtt => &self.ciphertext_parser,
        };
    }

    fn inboundCiphertextReadRoom(self: *const PureZigRecordStream) Error!usize {
        const owned = self.inboundCiphertextOwned();
        const hard = self.buffer_limits.inbound_ciphertext.hard;
        if (owned >= hard) return 0;
        const hard_room = hard - owned;
        const parser = self.activeInboundParser();
        const queued = self.inbound_carrier.slice();
        if (parser.len > 0) return @min(hard_room, try parser.pendingRecordBytesNeededWith(queued));
        const high = self.buffer_limits.inbound_ciphertext.high;
        const high_room = if (owned < high) high - owned else 0;
        return @min(hard_room, high_room);
    }

    fn inboundDestinationReserve(parser: *const record_codec.Parser, bytes: []const u8) Error!?usize {
        const payload_len = try parser.pendingRecordPayloadLenWith(bytes) orelse return null;
        // A TLSInnerPlaintext payload cannot contribute more than one plaintext
        // fragment to either destination queue, even when ciphertext overhead
        // makes its encoded payload larger.
        return @min(payload_len, record_codec.max_plaintext_fragment_len);
    }

    fn hasInboundDestinationReserveFor(self: *const PureZigRecordStream, parser: *const record_codec.Parser, bytes: []const u8) Error!bool {
        const needed = try inboundDestinationReserve(parser, bytes) orelse return true;
        return self.inbound_plaintext.available() >= needed and
            self.inbound_handshake.available() >= needed and
            self.hasHardRoom(.inbound_plaintext, self.inbound_plaintext.len, needed) and
            self.hasHardRoom(.handshake, self.inbound_handshake.len, needed);
    }

    fn hasRuntimeInboundDestinationReserve(self: *const PureZigRecordStream) Error!bool {
        return self.hasInboundDestinationReserveFor(self.activeInboundParser(), self.inbound_carrier.slice());
    }

    fn canContinueParser(self: *const PureZigRecordStream, parser: *const record_codec.Parser, queued: []const u8) bool {
        if (parser.len == 0 or self.inboundCiphertextOwned() >= self.buffer_limits.inbound_ciphertext.hard) return false;
        return (parser.pendingRecordBytesNeededWith(queued) catch return false) > 0;
    }

    fn canContinueActiveRecord(self: *const PureZigRecordStream) bool {
        return self.canContinueParser(self.activeInboundParser(), self.inbound_carrier.slice());
    }

    pub fn applyEvent(self: *PureZigRecordStream, event: events.Event) Error!void {
        if (self.failed) |err| return err;
        if (self.lifecycle == .closed or self.lifecycle == .failed or self.lifecycle == .closing) return error.StreamClosed;
        if (event == .handshake_bytes) {
            const needed = try self.bridge.sealedHandshakeLen(event.handshake_bytes.epoch, event.handshake_bytes.data.len);
            if (!self.hasHardRoom(.outbound_ciphertext, self.outbound_ciphertext.len, needed)) return self.rejectHardLimit(.outbound_ciphertext, error.WouldBlock);
            if (self.outbound_ciphertext.available() < needed) return error.WouldBlock;
        }
        if (event == .handshake_bytes) {
            self.emitHandshakeRecords(event.handshake_bytes.epoch, event.handshake_bytes.data) catch |err| return self.fail(err);
        } else {
            var record_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
            if (self.bridge.applyEvent(event, &record_buf) catch |err| return self.fail(err)) |record| {
                self.appendOutboundCiphertext(record) catch |err| return self.fail(err);
            }
        }
        // The initial epoch's plaintext parser is only safe to keep once
        // its keys are gone: nothing should ever arrive at that epoch
        // again after discard, so drop any partially-buffered state along
        // with it. Never reset `ciphertext_parser` here: it is shared
        // across the handshake and application epochs, and bytes already
        // buffered there may belong to the next (application) record.
        if (event == .discard_epoch) try self.applyDiscardSideEffects(event.discard_epoch);
        if (event == .handshake_complete) self.lifecycle = .open;
    }

    /// Best-effort established-connection post-handshake queueing. Unlike
    /// `applyEvent`, queue or sealing failure is reported to the caller without
    /// calling `fail()` and without closing an otherwise usable connection.
    pub fn tryQueuePostHandshake(self: *PureZigRecordStream, event: events.Event) Error!void {
        if (self.failed) |err| return err;
        if (self.lifecycle == .closed or self.lifecycle == .failed or self.lifecycle == .closing) return error.StreamClosed;
        if (!self.applicationDataOpen()) return error.HandshakeNotComplete;
        if (event != .handshake_bytes or event.handshake_bytes.epoch != .application) return error.InvalidHandshakeState;
        const needed = try self.bridge.sealedHandshakeLen(event.handshake_bytes.epoch, event.handshake_bytes.data.len);
        if (!self.hasHardRoom(.outbound_ciphertext, self.outbound_ciphertext.len, needed)) return self.rejectHardLimit(.outbound_ciphertext, error.WouldBlock);
        if (self.outbound_ciphertext.available() < needed) return error.WouldBlock;

        var offset: usize = 0;
        // #359: post-handshake messages (NewSessionTicket, KeyUpdate) travel in
        // protected application-epoch records, so they are subject to the
        // peer's `record_size_limit` exactly as application data is. The
        // `sealedHandshakeLen` reservation above already sizes itself from the
        // same bound.
        const chunk = self.bridge.outboundContentMax();
        while (offset < event.handshake_bytes.data.len) {
            const take = @min(chunk, event.handshake_bytes.data.len - offset);
            var record_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
            const record = try self.bridge.sealHandshake(.application, event.handshake_bytes.data[offset..][0..take], &record_buf);
            try self.appendOutboundCiphertext(record);
            offset += take;
        }
    }

    /// The record-layer side effects of an epoch discard, shared by the manual
    /// `applyEvent` path and the driver-owned path (`applyDriverOutcome`).
    fn applyDiscardSideEffects(self: *PureZigRecordStream, epoch: events.EncryptionEpoch) Error!void {
        // The initial epoch's plaintext parser is only safe to keep once its
        // keys are gone: nothing should ever arrive at that epoch again after
        // discard, so drop any partially-buffered state along with it. Never
        // reset `ciphertext_parser` here: it is shared across the handshake and
        // application epochs, and bytes already buffered there may belong to
        // the next (application) record.
        if (epoch == .initial) self.initial_parser.reset();
        // `ciphertext_parser` is fed through `feedOne`'s exact-consumption
        // contract, so it only ever holds a genuinely incomplete record -- any
        // legitimate next-record suffix stays in the caller/carrier buffer
        // instead. A nonzero `len` here at the `.handshake` epoch boundary
        // therefore means a record started under handshake keys and has not
        // finished, and its remaining bytes are about to be fed and opened
        // under application keys instead. That is exactly the stale
        // partial-record state the epoch transition must clear or reject; there
        // is no way to safely resume mid-record across a key change, so fail
        // the stream closed rather than silently reinterpreting those bytes
        // under the wrong epoch.
        if (epoch == .handshake and self.ciphertext_parser.len != 0) {
            return self.fail(error.PartialRecordAtEpochTransition);
        }
    }

    // ── Driver-owned handshake progression (#410) ───────────────────────────
    //
    // When a backend was injected, `PureZigRecordStream` owns the shared
    // `engine.Driver` and progresses a real TLS 1.3 handshake inside `drive()`:
    // it starts the driver once, routes opened handshake plaintext into it, and
    // applies every emitted event (sealing outbound handshake bytes, installing
    // traffic secrets, tracking epochs, discarding keys, capturing ALPN/cert
    // state, completing, and carrying a terminal fatal alert) before the next
    // driver call. Callers no longer hand-install secrets or declare completion.

    fn driverPresent(self: *PureZigRecordStream) bool {
        return self.handshake_driver != null and !self.driver_torn_down;
    }

    /// Start the handshake driver exactly once. Refuses to progress until the
    /// outbound queue can absorb a full event batch, so the client's first
    /// flight is never partially serialized. Returns true if it started here.
    fn startHandshakeIfNeeded(self: *PureZigRecordStream) Error!bool {
        if (!self.driverPresent() or self.handshake_started) return false;
        if (self.bridge.handshake_complete or self.lifecycle != .handshaking) return false;
        if (!self.canReserveHandshakeOutputBatch()) return false;
        self.handshake_started = true;
        const driver = &self.handshake_driver.?;
        const outcome = driver.startOutcome({});
        try self.applyDriverOutcome(outcome);
        return true;
    }

    /// Feed one opened handshake message into the driver and apply the events it
    /// emits. Caller must have preflighted `handshake_output_reserve` so the
    /// whole emitted batch serializes atomically.
    fn driveReceive(self: *PureZigRecordStream, epoch: events.EncryptionEpoch, content: []const u8) Error!void {
        const driver = &self.handshake_driver.?;
        const outcome = driver.receiveOutcome(epoch, content);
        try self.applyDriverOutcome(outcome);
    }

    /// Poll a parked asynchronous authentication operation (#334) once and apply
    /// whatever the backend emits — the client's certificate flight, the
    /// server's, or a peer-verification verdict. A no-op unless the backend has
    /// suspended; requires output headroom so an emitted flight serializes
    /// atomically. Returns true only for observable progress: terminal failure,
    /// emitted events, or a pending operation resolving.
    fn resumeAuthIfPending(self: *PureZigRecordStream) Error!bool {
        if (!self.driverPresent()) return false;
        const driver = &self.handshake_driver.?;
        if (!driver.authPending()) return false;
        if (!self.canReserveHandshakeOutputBatch()) return false;
        const outcome = driver.resumeAuthOutcome();
        const emitted_or_failed = outcome.sink.len != 0 or outcome.terminal_error != null;
        try self.applyDriverOutcome(outcome);
        return emitted_or_failed or !driver.authPending();
    }

    /// Apply one borrowed driver event batch. Every payload slice is consumed,
    /// copied, or serialized here, before any subsequent driver call resets the
    /// sink. A terminal backend error is deferred (with its fatal alert queued)
    /// rather than propagated, so `drive()` can flush the alert before latching.
    fn applyDriverOutcome(self: *PureZigRecordStream, outcome: RecordHandshakeDriver.Outcome) Error!void {
        var fatal_alert: ?alerts.AlertDescription = null;
        const sink = outcome.sink;
        // #359: pull the negotiated record-size state *before* serializing
        // this batch's `handshake_bytes`. The ordering is load-bearing on both
        // roles: a server learns the client's limit from the ClientHello it
        // just consumed and must already honor it in the EncryptedExtensions
        // flight this very batch emits, and a client learns the server's limit
        // from EncryptedExtensions and must honor it in the Finished that
        // follows in the same batch.
        // A retroactive `RecordSizeLimitExceeded` here means the peer answered
        // extension 28 and then exceeded the value it had just agreed to.
        // RFC 8446 §6 makes that a fatal `record_overflow`, so it is deferred
        // (alert queued, then latched) rather than torn down silently.
        self.refreshRecordSizeLimits() catch |err| {
            self.deferHandshakeFailure(err, null);
            return;
        };
        // A completion batch may contain application secrets, Client Finished,
        // and handshake-key discard before `handshake_complete`. Validate the
        // batch's final authentication/ALPN state first so policy failure sends
        // its alert with the existing handshake keys and applies none of those
        // success effects.
        if (self.completionPolicyError(sink)) |err| {
            self.deferHandshakeFailure(err, findEmittedFatalAlert(sink));
            return;
        }
        for (sink.items[0..sink.len]) |event| {
            switch (event) {
                .handshake_bytes => |hb| {
                    self.emitHandshakeRecords(hb.epoch, hb.data) catch |err| return self.fail(err);
                },
                // #564: must be applied before this batch's own traffic
                // secrets are installed below — `EventSink.emitNegotiatedParameters`'s
                // contract guarantees the backend emits it first — so
                // `self.bridge.installTrafficSecret` derives `TrafficKeys`
                // for the suite this connection actually negotiated.
                .negotiated_parameters, .early_data_parameters => |params| {
                    self.bridge.cipher_suite = algorithms.fromInt(algorithms.CipherSuite, params.cipher_suite) orelse
                        return self.fail(error.MalformedHandshake);
                },
                .traffic_secret => |ts| {
                    self.bridge.installTrafficSecret(ts.epoch, ts.direction, ts.data) catch |err| return self.fail(err);
                    self.advanceEpochOnSecret(ts.epoch, ts.direction);
                },
                // #357. Position in the batch is the protocol: the write-side
                // update follows the `handshake_bytes` arm that already sealed
                // our own `KeyUpdate` under the outgoing generation, and the
                // read-side update follows the record the peer's `KeyUpdate`
                // arrived in. Applying events in order is therefore what puts
                // each direction's boundary in the right place -- this arm
                // must not be hoisted or deferred.
                .key_update => |update| {
                    self.bridge.updateTrafficSecretWithKeylog(update.direction, &sink.keylog_context) catch |err| return self.fail(err);
                },
                .alpn => |protocol| {
                    try self.captureAlpn(protocol);
                    if (self.alpnPolicyError(protocol)) |err| {
                        self.deferHandshakeFailure(err, fatal_alert);
                        break;
                    }
                },
                .certificate => |cert_state| {
                    self.certificate_state = cert_state;
                    // The concrete backend emits the certificate result and
                    // defers the policy decision to its driver (its own core is
                    // already marked failed on an invalid result and it stops
                    // producing output). Record mode must convert an invalid
                    // certificate into a terminal failure here, or the stream
                    // would stall in `.handshaking` forever. Stop applying later
                    // success events in the same batch so a bogus
                    // `handshake_complete` after it can never open the stream.
                    if (cert_state == .invalid or
                        (self.role == .client and
                            cert_state == .not_checked and
                            !self.allow_unverified_certificate))
                    {
                        self.deferHandshakeFailure(error.CertificateInvalid, fatal_alert);
                        break;
                    }
                },
                .discard_epoch => |epoch| {
                    self.bridge.discardEpoch(epoch) catch |err| return self.fail(err);
                    try self.applyDiscardSideEffects(epoch);
                },
                .handshake_complete => {
                    self.bridge.markHandshakeComplete() catch |err| return self.fail(err);
                    self.read_epoch = .application;
                    self.write_epoch = .application;
                    self.lifecycle = .open;
                    if (self.handshake_driver) |*driver| driver.complete();
                },
                // Record mode carries no QUIC transport parameters (#410).
                .peer_transport_parameters => {},
                .fatal_alert => |desc| fatal_alert = desc,
            }
        }
        // A terminal backend error (e.g. the wrapper surfacing a deferred
        // ALPN-mismatch) becomes the pending failure, unless a policy event
        // above already latched a more specific one.
        if (self.pending_terminal == null) {
            if (outcome.terminal_error) |err| self.deferHandshakeFailure(err, fatal_alert);
        }
    }

    /// Validate the final policy state represented by a completion batch before
    /// applying any event from it. Event payloads are borrowed from `sink` and
    /// are used only during this synchronous preflight.
    fn completionPolicyError(self: *const PureZigRecordStream, sink: *const RecordTransport.EventSink) ?Error {
        var certificate = self.certificate_state;
        var selected_alpn = self.negotiatedAlpn();
        var completes = false;

        for (sink.items[0..sink.len]) |event| switch (event) {
            .certificate => |state| certificate = state,
            .alpn => |protocol| {
                if (protocol.len > max_alpn_len) return error.MalformedHandshake;
                selected_alpn = protocol;
            },
            .handshake_complete => completes = true,
            else => {},
        };

        if (!completes) return null;
        if (self.role == .client and !self.allow_unverified_certificate and certificate != .valid) {
            return error.CertificateInvalid;
        }
        return self.alpnPolicyError(selected_alpn);
    }

    fn alpnPolicyError(self: *const PureZigRecordStream, selected: ?[]const u8) ?Error {
        if (!self.require_alpn) return null;
        const protocol = selected orelse return error.AlpnMismatch;
        if (!std.mem.eql(u8, protocol, self.expected_alpn_storage[0..self.expected_alpn_len])) {
            return error.AlpnMismatch;
        }
        return null;
    }

    fn findEmittedFatalAlert(sink: *const RecordTransport.EventSink) ?alerts.AlertDescription {
        var emitted: ?alerts.AlertDescription = null;
        for (sink.items[0..sink.len]) |event| {
            if (event == .fatal_alert) emitted = event.fatal_alert;
        }
        return emitted;
    }

    /// Handshake secrets advance the explicit record epoch one step. TLS 1.3
    /// then advances each application direction when that side has installed
    /// the corresponding traffic secret, not only when the whole handshake is
    /// complete: after a server sends Finished it must seal client-auth alerts
    /// with application write keys, while it still reads the client's Finished
    /// under handshake keys.
    fn advanceEpochOnSecret(self: *PureZigRecordStream, epoch: events.EncryptionEpoch, direction: events.SecretDirection) void {
        switch (epoch) {
            .handshake => switch (direction) {
                .read => self.read_epoch = epoch,
                .write => self.write_epoch = epoch,
            },
            .application => switch (direction) {
                .read => {
                    if (self.role == .client) self.read_epoch = .application;
                },
                .write => {
                    if (self.role == .server) self.write_epoch = .application;
                },
            },
            .initial, .zero_rtt => {},
        }
    }

    /// RFC 9846 §5's middlebox-compat `change_cipher_spec` window opens
    /// only after the first ClientHello has been *sent or received* -- not
    /// merely "a handshake record fragment has arrived". A driver is free
    /// to buffer an incomplete handshake message across several records
    /// and only report progress once it has a complete one (so a peer
    /// could otherwise splice `partial ClientHello record -> dummy CCS ->
    /// rest of ClientHello` and have the CCS wrongly tolerated by a
    /// fragment-counting check). `read_epoch`/`write_epoch` leaving
    /// `.initial` is not that either by accident: it only happens as a
    /// side effect of `advanceEpochOnSecret`, which only runs once the
    /// driver has derived real handshake traffic secrets -- which for the
    /// server requires a fully reassembled, accepted ClientHello, and for
    /// the client only happens after it has itself sent one. So this reuses
    /// existing driver-completion state rather than tracking ClientHello
    /// receipt a second, independent way. The client side still checks
    /// `handshake_started` specifically: generating and sending its own
    /// ClientHello is what flips that flag, and happens before either
    /// epoch could plausibly move for a client that hasn't received
    /// anything back yet.
    ///
    /// #338: the epoch proxy alone is *not* sufficient for a server that
    /// answered ClientHello1 with a HelloRetryRequest. An HRR flight derives
    /// no traffic secrets, so both epochs are still `.initial` even though a
    /// complete ClientHello has demonstrably been accepted -- and RFC 8446
    /// §5.1 has a middlebox-compatibility client send `change_cipher_spec`
    /// immediately after receiving the HRR, before ClientHello2. Rejecting it
    /// there made the record transport unable to complete an HRR handshake
    /// with essentially any real client (found by the external conformance
    /// matrix against `openssl s_client -groups P-256:X25519`). Asking the
    /// backend whether it has sent an HRR keeps the original property intact:
    /// it is still driver-completion state, still only true after a fully
    /// reassembled and accepted ClientHello, so a CCS spliced into the middle
    /// of a partial ClientHello is rejected exactly as before.
    fn firstClientHelloAccepted(self: *const PureZigRecordStream) bool {
        if (self.role == .client) return self.handshake_started;
        if (self.read_epoch != .initial or self.write_epoch != .initial) return true;
        // Captured by pointer: the driver embeds a multi-kilobyte `EventSink`,
        // and this runs once per inbound change_cipher_spec record.
        if (self.handshake_driver) |*driver| return driver.backend.helloRetryRequestSent();
        return false;
    }

    /// Capture the negotiated ALPN. RFC 7301 caps a protocol name at 255 bytes;
    /// a longer value can only be a backend bug or malformed peer data, so fail
    /// closed rather than silently truncating (which would change the protocol).
    fn captureAlpn(self: *PureZigRecordStream, protocol: []const u8) Error!void {
        if (protocol.len > max_alpn_len) return self.fail(error.MalformedHandshake);
        @memcpy(self.alpn_storage[0..protocol.len], protocol);
        self.alpn_len = protocol.len;
        self.alpn_captured = true;
    }

    /// Record a terminal handshake failure without immediately latching, first
    /// queuing any emitted fatal alert into the normal bounded outbound queue.
    /// `drive()` then flushes that output within a bounded write budget and
    /// latches the preserved error only once it drains (or the flush deadline
    /// fires) -- never by a hidden synchronous retry-and-discard.
    fn deferHandshakeFailure(self: *PureZigRecordStream, err: Error, emitted_alert: ?alerts.AlertDescription) void {
        const alert = emitted_alert orelse mappedFatalAlert(err);
        if (alert) |desc| self.queueFatalAlert(desc);
        self.pending_terminal = err;
        self.terminal_flush_attempts = 0;
    }

    /// Convert record-transport handshake policy failures into their canonical
    /// TLS fatal alerts when a backend did not emit a more specific alert.
    fn mappedFatalAlert(err: Error) ?alerts.AlertDescription {
        return switch (err) {
            error.MalformedHandshake,
            error.IllegalParameter,
            error.UnexpectedHandshakeMessage,
            error.CertificateInvalid,
            error.AlpnMismatch,
            error.SecretExportFailed,
            error.InvalidHandshakeState,
            error.NoApplicableCredential,
            error.CredentialProviderFailed,
            error.ClientCertificateRequired,
            error.DecryptError,
            error.MissingExtension,
            error.UnsupportedCertificate,
            // #338: no-overlap and version-negotiation failures carry their
            // own RFC-mandated alerts (handshake_failure, protocol_version).
            error.NoMutualParameters,
            error.UnsupportedProtocolVersion,
            => alerts.fromHandshakeError(@errorCast(err)),
            // #359: RFC 8446 §6 names `record_overflow` for a record longer
            // than the receiver accepts, which is exactly what a peer that
            // ignored our `record_size_limit` sent us.
            error.RecordSizeLimitExceeded => .record_overflow,
            else => null,
        };
    }

    /// Best-effort: seal a fatal alert at the current write epoch into the
    /// outbound queue. Silently skips if keys or capacity are unavailable --
    /// a lost alert must never erase the underlying handshake failure.
    fn queueFatalAlert(self: *PureZigRecordStream, desc: alerts.AlertDescription) void {
        if (!self.canReserveOutboundRecord()) return;
        const payload = [_]u8{ 2, @intFromEnum(desc) }; // level = fatal(2)
        var alert_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
        const record = switch (self.write_epoch) {
            .initial => record_codec.encodePlaintextRecord(.alert, &payload, &alert_buf) catch return,
            .handshake, .application => self.bridge.sealProtected(self.write_epoch, .alert, &payload, &alert_buf) catch return,
            .zero_rtt => return,
        };
        self.appendOutboundCiphertext(record) catch return;
    }

    pub fn feedHandshakeCiphertext(self: *PureZigRecordStream, epoch: events.EncryptionEpoch, bytes: []const u8) Error!usize {
        if (self.failed) |err| return err;
        if (self.lifecycle == .closed or self.lifecycle == .failed) return error.StreamClosed;
        const owned = self.inboundCiphertextOwned();
        const hard = self.buffer_limits.inbound_ciphertext.hard;
        if (owned >= hard) return self.rejectHardLimit(.inbound_ciphertext, error.WouldBlock);
        const feed_len = @min(bytes.len, hard - owned);
        var sink = record_codec.RecordSink(1, record_codec.max_ciphertext_fragment_len){};
        const parser = self.parserForEpoch(epoch);
        if (self.read_backpressured and !self.canContinueParser(parser, &.{})) return error.WouldBlock;
        if (inboundDestinationReserve(parser, bytes[0..feed_len]) catch |err| return self.fail(err)) |reserve| {
            if (!self.hasHardRoom(.handshake, self.inbound_handshake.len, reserve)) return self.rejectHardLimit(.handshake, error.WouldBlock);
            if (self.inbound_handshake.available() < reserve) return error.WouldBlock;
        }
        const consumed = feedUntilOneRecord(parser, bytes[0..feed_len], &sink) catch |err| return self.fail(err);
        self.noteQueueMutation();
        self.openHandshakeSink(epoch, &sink) catch |err| return self.fail(err);
        return consumed;
    }

    pub fn readHandshake(self: *PureZigRecordStream, out: []u8) Error!usize {
        if (self.failed) |err| return err;
        if (self.lifecycle == .closed or self.lifecycle == .failed) return error.StreamClosed;
        if (self.inbound_handshake.read(out)) |n| {
            self.noteQueueMutation();
            return n;
        }
        try self.raisePendingTerminalError();
        return error.WouldBlock;
    }

    pub fn feedCiphertext(self: *PureZigRecordStream, bytes: []const u8) Error!usize {
        return self.feedCiphertextInternal(bytes, true);
    }

    fn feedCiphertextInternal(self: *PureZigRecordStream, bytes: []const u8, comptime direct_external_feed: bool) Error!usize {
        if (self.failed) |err| return err;
        if (self.lifecycle == .closed or self.lifecycle == .failed) return error.StreamClosed;
        if (self.peer_closed) return bytes.len;
        if (!direct_external_feed) {
            if (!self.canProcessCarrierInput()) return error.WouldBlock;
        }
        var feed_bytes = bytes;
        if (direct_external_feed) {
            const owned = self.inboundCiphertextOwned();
            const hard = self.buffer_limits.inbound_ciphertext.hard;
            if (owned >= hard) return self.rejectHardLimit(.inbound_ciphertext, error.WouldBlock);
            if (self.read_backpressured and !self.canContinueParser(&self.ciphertext_parser, &.{})) return error.WouldBlock;
            feed_bytes = bytes[0..@min(bytes.len, hard - owned)];
        }
        var sink = record_codec.RecordSink(1, record_codec.max_ciphertext_fragment_len){};
        if (inboundDestinationReserve(&self.ciphertext_parser, feed_bytes) catch |err| return self.fail(err)) |reserve| {
            if (!self.hasHardRoom(.inbound_plaintext, self.inbound_plaintext.len, reserve)) {
                if (direct_external_feed) return self.rejectHardLimit(.inbound_plaintext, error.WouldBlock);
                return error.WouldBlock;
            }
            if (!self.hasHardRoom(.handshake, self.inbound_handshake.len, reserve)) {
                if (direct_external_feed) return self.rejectHardLimit(.handshake, error.WouldBlock);
                return error.WouldBlock;
            }
            if (self.inbound_plaintext.available() < reserve or self.inbound_handshake.available() < reserve) return error.WouldBlock;
        }
        const consumed = feedUntilOneRecord(&self.ciphertext_parser, feed_bytes, &sink) catch |err| return self.fail(err);
        if (direct_external_feed or consumed == 0) self.noteQueueMutation();

        var plaintext_buf: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
        for (sink.items[0..sink.len]) |record| {
            const opened = self.bridge.openProtected(.application, record, &plaintext_buf) catch |err| return self.fail(err);
            switch (opened.inner.content_type) {
                .application_data => self.appendInboundPlaintext(opened.inner.content, false) catch |err| return self.fail(err),
                .handshake => {
                    if (self.driverPresent()) {
                        try self.driveReceive(.application, opened.inner.content);
                    } else {
                        self.appendInboundHandshake(opened.inner.content) catch |err| return self.fail(err);
                    }
                },
                .alert => self.handleAlert(opened.inner.content) catch |err| return self.fail(err),
                .change_cipher_spec => return self.fail(error.UnsupportedRecordContent),
            }
        }
        return consumed;
    }

    /// Queues a locally initiated post-handshake `KeyUpdate` (#357).
    ///
    /// The emitted batch is applied in order by `applyDriverOutcome`: the
    /// `KeyUpdate` record is sealed under the outgoing keys first, then the
    /// write-side advance replaces them, so the message the peer needs in
    /// order to follow the transition is itself readable under the generation
    /// it is announcing the end of.
    ///
    /// `.update_requested` additionally obliges the peer to advance *its*
    /// sending keys. That is the only way to refresh the keys this endpoint
    /// *reads* under, since a direction's chain can only ever be advanced by
    /// its sender — so a caller that wants both directions refreshed must use
    /// this form rather than calling twice.
    ///
    /// Fails with `error.InvalidHandshakeState` before the handshake completes
    /// or on a backend whose transport has no `KeyUpdate`, and `error.WouldBlock`
    /// when the outbound queue has no room to serialize the batch atomically —
    /// the same admission rule every other emitted handshake batch follows.
    pub fn requestKeyUpdate(self: *PureZigRecordStream, request: key_update.Request) Error!void {
        if (self.failed) |err| return err;
        if (self.pending_terminal) |err| return err;
        if (self.pending_terminal_read_error) |err| return err;
        if (self.lifecycle != .open or !self.bridge.handshake_complete) return error.InvalidHandshakeState;
        const driver = if (self.driverPresent()) &self.handshake_driver.? else return error.InvalidHandshakeState;
        if (!driver.supportsKeyUpdate()) return error.InvalidHandshakeState;
        if (!self.canReserveHandshakeOutputBatch()) return error.WouldBlock;
        const outcome = driver.requestKeyUpdateOutcome(request);
        try self.applyDriverOutcome(outcome);
        try self.raisePendingTerminalError();
    }

    /// Proactive-update policy (#357). Defaults to disabled, so configuring
    /// nothing keeps a connection's wire behavior exactly as it was.
    pub fn setKeyUpdateLimits(self: *PureZigRecordStream, limits: key_update.UsageLimits) void {
        self.key_update_limits = limits;
    }

    /// Whether the configured usage limit has been reached for the *sending*
    /// direction. This is the hook, not the trigger: nothing in `drive()`
    /// consults it, so acting on it stays an explicit `requestKeyUpdate` call
    /// by the owner, who is the only layer that knows whether stalling the
    /// stream to emit one is acceptable right now.
    pub fn keyUpdateDue(self: *const PureZigRecordStream) bool {
        return self.key_update_limits.reached(self.bridge.applicationRecordsSealed());
    }

    /// How many times each direction has advanced its application traffic
    /// secret. Exposed for observability and tests: it distinguishes "the keys
    /// rolled" from "the same keys are still in place", which no amount of
    /// looking at ciphertext can.
    pub fn keyUpdateGenerations(self: *const PureZigRecordStream) struct { read: u64, write: u64 } {
        return .{ .read = self.bridge.read_key_generation, .write = self.bridge.write_key_generation };
    }

    pub fn markPeerEof(self: *PureZigRecordStream) Error!void {
        if (self.peer_closed) return;
        self.carrier_eof = true;
        return self.deferTerminalReadError(error.TruncatedStream);
    }

    pub fn readPlaintext(self: *PureZigRecordStream, out: []u8) Error!usize {
        if (self.failed) |err| return err;
        if (self.pending_terminal) |err| return err;
        if (self.lifecycle == .closed or self.lifecycle == .failed) return error.StreamClosed;
        if (self.inbound_plaintext.read(out)) |n| {
            self.last_read_early_prefix_len = self.inbound_plaintext_provenance.discard(n);
            self.noteQueueMutation();
            return n;
        }
        self.last_read_early_prefix_len = 0;
        try self.raisePendingTerminalError();
        if (self.peer_closed) return error.EndOfStream;
        return error.WouldBlock;
    }

    pub fn writePlaintext(self: *PureZigRecordStream, bytes: []const u8) Error!usize {
        if (self.failed) |err| return err;
        if (self.pending_terminal) |err| return err;
        if (self.lifecycle == .closing or self.lifecycle == .closed or self.lifecycle == .failed) return error.StreamClosed;
        if (self.pending_terminal_read_error) |err| return err;
        if (bytes.len == 0) return 0;
        const write_epoch: events.EncryptionEpoch = if (self.lifecycle == .open and self.bridge.handshake_complete)
            .application
        else if (self.bridge.hasWriteKeys(.zero_rtt))
            .zero_rtt
        else
            return error.WouldBlock;
        if (self.write_backpressured) return error.WouldBlock;
        if (!self.hasHardRoom(.outbound_ciphertext, self.outbound_ciphertext.len, record_codec.max_ciphertext_record_len)) return self.rejectHardLimit(.outbound_ciphertext, error.WouldBlock);
        if (self.outbound_ciphertext.available() < record_codec.max_ciphertext_record_len) return error.WouldBlock;

        // #359: one record per call, sized by whichever bound is tighter --
        // the protocol fragment maximum or the peer's advertised
        // `record_size_limit`. A short return is already this API's contract
        // (callers loop), so a narrower peer limit costs more calls rather
        // than an error.
        const content_max = self.bridge.outboundContentMax();
        const n = @min(bytes.len, content_max);
        if (content_max < record_codec.max_plaintext_fragment_len and bytes.len > content_max) {
            self.bridge.record_size_counters.peer_limited_writes +|= 1;
        }
        if (write_epoch == .zero_rtt) {
            const max_early = if (self.handshake_driver) |*driver| driver.backend.earlyDataMaxBytes() else return error.WouldBlock;
            if (self.zero_rtt_sent >= max_early) return error.WouldBlock;
            const remaining: usize = @intCast(max_early - self.zero_rtt_sent);
            if (remaining == 0) return error.WouldBlock;
            const bounded_n = @min(n, remaining);
            var record_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
            const record = self.bridge.sealProtected(write_epoch, .application_data, bytes[0..bounded_n], &record_buf) catch |err| return self.fail(err);
            self.appendOutboundCiphertext(record) catch |err| return self.fail(err);
            self.zero_rtt_sent += bounded_n;
            return bounded_n;
        }
        var record_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
        const record = self.bridge.sealProtected(write_epoch, .application_data, bytes[0..n], &record_buf) catch |err| return self.fail(err);
        self.appendOutboundCiphertext(record) catch |err| return self.fail(err);
        return n;
    }

    pub fn drainCiphertext(self: *PureZigRecordStream, out: []u8) Error!usize {
        if (self.failed) |err| return err;
        if (self.outbound_ciphertext.read(out)) |n| {
            self.noteQueueMutation();
            return n;
        }
        if (self.lifecycle == .closed or self.lifecycle == .failed) return error.StreamClosed;
        return error.WouldBlock;
    }

    pub fn peekCiphertext(self: *const PureZigRecordStream) []const u8 {
        if (self.failed != null or self.lifecycle == .closed or self.lifecycle == .failed) return &.{};
        return self.outbound_ciphertext.slice();
    }

    pub fn consumeCiphertext(self: *PureZigRecordStream, count: usize) Error!void {
        if (self.failed) |err| return err;
        try self.outbound_ciphertext.discard(count);
        self.noteQueueMutation();
        if (self.lifecycle == .closing and self.carrier == null and self.close_notify_queued and self.outbound_ciphertext.len == 0) {
            self.finishClose();
        }
    }

    pub fn readiness(self: *const PureZigRecordStream) Readiness {
        if (self.failed != null or self.lifecycle == .failed or self.lifecycle == .closed) {
            return .{ .peer_closed = self.peer_closed };
        }
        // A pending terminal failure is draining its queued fatal alert: the
        // only useful action is a write, so advertise write readiness while
        // output remains and nothing else. No new reads, no plaintext I/O.
        if (self.pending_terminal != null) {
            return .{ .wants_write = self.outbound_ciphertext.len != 0, .peer_closed = self.peer_closed };
        }
        const pending_terminal_read_ready = self.pending_terminal_read_error != null and !self.hasBufferedInboundContent();
        const auth_pending = self.authStillPending();
        const zero_rtt_write_ready = self.zeroRttWriteReady();
        return .{
            .wants_read = !auth_pending and !self.carrier_eof and self.canAcceptCarrierRead(),
            .wants_write = self.outbound_ciphertext.len > 0 or (self.lifecycle == .closing and !self.close_notify_queued),
            .can_read_plaintext = self.inbound_plaintext.len > 0 or pending_terminal_read_ready,
            .can_write_plaintext = self.pending_terminal_read_error == null and
                ((self.lifecycle == .open and self.bridge.handshake_complete) or zero_rtt_write_ready) and
                !self.write_backpressured and
                self.canReserveOutboundRecord(),
            .peer_closed = self.peer_closed,
        };
    }

    fn zeroRttWriteReady(self: *const PureZigRecordStream) bool {
        if (!self.bridge.hasWriteKeys(.zero_rtt)) return false;
        if (self.handshake_driver) |*driver| {
            return self.zero_rtt_sent < driver.backend.earlyDataMaxBytes();
        }
        return false;
    }

    pub fn drive(self: *PureZigRecordStream) Error!DriveResult {
        if (self.failed) |err| return err;
        var made_progress = false;
        if (self.lifecycle == .closed or self.lifecycle == .failed) {
            return .{ .made_progress = false, .readiness = self.readiness() };
        }

        // A pending terminal handshake failure takes priority over all other
        // work. Flush its queued output (the fatal alert, behind any earlier
        // handshake bytes it sits after) within the bounded write budget while
        // preserving the root error, and latch only once the queue drains or
        // the bounded flush deadline fires. This is the sole socket write on
        // this path -- readiness advertises `wants_write` so the event loop
        // drives us back when the carrier is writable, rather than a hidden
        // synchronous retry that would discard the alert on `WouldBlock`.
        if (self.pending_terminal) |root| {
            const flushed = self.flushPendingAlert();
            if (flushed > 0) {
                made_progress = true;
                self.terminal_flush_attempts = 0;
            } else {
                self.terminal_flush_attempts += 1;
            }
            if (self.outbound_ciphertext.len == 0 or self.terminal_flush_attempts >= max_terminal_flush_attempts) {
                return self.fail(root);
            }
            return .{ .made_progress = made_progress, .readiness = self.readiness() };
        }

        if (self.lifecycle == .closing and !self.bridge.handshake_complete) {
            if (try self.queueCloseNotify()) made_progress = true;
            return .{ .made_progress = made_progress, .readiness = self.readiness() };
        }

        // Start the shared handshake driver exactly once (client: emits the
        // initial flight; server: arms the responder). The carrier write loop
        // below flushes whatever it queued.
        if (try self.startHandshakeIfNeeded()) made_progress = true;

        // Poll a parked asynchronous authentication operation (#334): an
        // external signer/verifier/selector may have suspended the handshake,
        // and each drive tick advances it toward resolution.
        if (try self.resumeAuthIfPending()) made_progress = true;

        if (self.carrier) |carrier| {
            var written_total: usize = 0;
            while (self.outbound_ciphertext.len > 0 and written_total < drive_write_budget) {
                const written = carrier.write(self.peekCiphertext()) catch |err| switch (err) {
                    error.WouldBlock => 0,
                    else => return self.fail(err),
                };
                if (written == 0) break;
                try self.consumeCiphertext(written);
                written_total += written;
                made_progress = true;
            }

            if (try self.queueCloseNotify()) made_progress = true;

            var wrote_close_notify = false;
            while (self.outbound_ciphertext.len > 0 and written_total < drive_write_budget) {
                const written = carrier.write(self.peekCiphertext()) catch |err| switch (err) {
                    error.WouldBlock => 0,
                    else => return self.fail(err),
                };
                if (written == 0) break;
                try self.consumeCiphertext(written);
                written_total += written;
                made_progress = true;
                wrote_close_notify = true;
            }

            if (self.lifecycle == .closing and self.close_notify_queued and self.outbound_ciphertext.len == 0 and wrote_close_notify) {
                self.finishClose();
                self.closeCarrier();
                made_progress = true;
                return .{ .made_progress = made_progress, .readiness = self.readiness() };
            }

            var record_budget_remaining: usize = drive_record_budget;
            if (!self.authStillPending()) {
                if (try self.processCarrierInputBudget(&record_budget_remaining)) made_progress = true;
            }

            var read_total: usize = 0;
            while (!self.authStillPending() and !self.carrier_eof and read_total < drive_read_budget and self.canAcceptCarrierRead() and self.inbound_carrier.available() > 0) {
                var buf: [drive_read_chunk]u8 = undefined;
                const read_room = self.inboundCiphertextReadRoom() catch |err| return self.fail(err);
                const read_cap = @min(buf.len, @min(self.inbound_carrier.available(), @min(drive_read_budget - read_total, read_room)));
                if (read_cap == 0) {
                    self.refreshBackpressure();
                    break;
                }
                const maybe_read_len = carrier.read(buf[0..read_cap]) catch |err| switch (err) {
                    error.WouldBlock => null,
                    error.EndOfStream => eof: {
                        self.carrier_eof = true;
                        made_progress = true;
                        break :eof null;
                    },
                    else => return self.fail(err),
                };
                if (maybe_read_len) |read_len| {
                    if (read_len == 0) {
                        self.carrier_eof = true;
                        made_progress = true;
                    } else {
                        self.appendInboundCarrier(buf[0..read_len]) catch |err| return self.fail(err);
                        read_total += read_len;
                        made_progress = true;
                        if (try self.processCarrierInputBudget(&record_budget_remaining)) made_progress = true;
                    }
                } else {
                    break;
                }
            }
            if (!self.authStillPending() and self.carrier_eof) {
                if (try self.handleCarrierEof(&record_budget_remaining)) made_progress = true;
            }
        } else if (self.lifecycle == .closing) {
            if (try self.queueCloseNotify()) made_progress = true;
            if (self.close_notify_queued and self.outbound_ciphertext.len == 0) {
                self.finishClose();
                made_progress = true;
            }
        } else if (!self.authStillPending()) {
            if (try self.processCarrierInput(drive_record_budget)) made_progress = true;
        }

        if (self.lifecycle == .closing and self.carrier != null and self.close_notify_queued and self.outbound_ciphertext.len == 0) {
            self.finishClose();
            self.closeCarrier();
            made_progress = true;
        }
        if (!made_progress and (self.read_backpressured or self.write_backpressured)) {
            self.buffer_counters.stalled_drives += 1;
        }
        return .{ .made_progress = made_progress, .readiness = self.readiness() };
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
            if (epoch == .initial and record.content_type == .alert) {
                try self.handleAlert(record.payload);
                continue;
            }
            // See the matching comment and RFC citation in
            // `feedHandshakeToDriver`: middlebox-compat change_cipher_spec,
            // dropped unopened since it was never encrypted, only inside
            // the RFC-defined post-ClientHello/pre-peer-Finished window.
            if (record.content_type == .change_cipher_spec) {
                if (record.payload.len != 1 or record.payload[0] != 0x01 or !self.firstClientHelloAccepted() or self.bridge.handshake_complete) {
                    return self.fail(error.UnexpectedRecordContent);
                }
                continue;
            }
            const opened = try self.bridge.openProtected(epoch, record, &plaintext_buf);
            switch (opened.inner.content_type) {
                .handshake => try self.appendInboundHandshake(opened.inner.content),
                .alert => try self.handleAlert(opened.inner.content),
                .application_data,
                .change_cipher_spec,
                => return self.fail(error.UnexpectedRecordContent),
            }
        }
    }

    fn handleAlert(self: *PureZigRecordStream, alert: []const u8) Error!void {
        if (alert.len != 2) return self.fail(error.MalformedAlert);
        const description: alerts.AlertDescription = std.enums.fromInt(alerts.AlertDescription, alert[1]) orelse return self.fail(error.PeerFatalAlert);
        if (description == .close_notify) {
            self.peer_closed = true;
            return;
        }
        if (description == .user_canceled) return;
        // Recorded before failing so the failure class survives the teardown
        // (#338). Only the first fatal alert is kept: it is the one that
        // actually ended the connection.
        if (self.peer_alert == null) self.peer_alert = description;
        return self.fail(error.PeerFatalAlert);
    }

    fn handleCarrierEof(self: *PureZigRecordStream, record_budget_remaining: *usize) Error!bool {
        if (self.peer_closed) return false;
        const made_progress = try self.processCarrierInputBudget(record_budget_remaining);
        if (self.peer_closed) return made_progress;
        if (self.inbound_carrier.len > 0) return made_progress;
        try self.deferTerminalReadError(error.TruncatedStream);
        return made_progress;
    }

    fn feedCarrierCiphertext(self: *PureZigRecordStream, bytes: []const u8) Error!usize {
        if (self.bridge.handshake_complete) return self.feedCiphertextInternal(bytes, false);
        if (self.driverPresent()) {
            // A terminal handshake failure is pending its alert flush; stop
            // consuming carrier records until `drive()` latches it.
            if (self.pending_terminal != null) return error.WouldBlock;
            // Preflight so a full emitted event batch serializes atomically; if
            // the outbound queue is too full, wait for the carrier to drain.
            if (!self.canReserveHandshakeOutputBatch()) return error.WouldBlock;
            return self.feedHandshakeToDriver(self.read_epoch, bytes);
        }
        const epoch: events.EncryptionEpoch = if (self.bridge.hasReadKeys(.handshake)) .handshake else .initial;
        return self.feedHandshakeCiphertext(epoch, bytes);
    }

    /// Parse one record at `epoch`, open it through the bridge, and route the
    /// plaintext: handshake content into the driver (applying its events),
    /// alerts through alert handling, anything else fails closed.
    fn feedHandshakeToDriver(self: *PureZigRecordStream, epoch: events.EncryptionEpoch, bytes: []const u8) Error!usize {
        var sink = record_codec.RecordSink(1, record_codec.max_ciphertext_fragment_len){};
        const parser = self.parserForEpoch(epoch);
        if (!(self.hasInboundDestinationReserveFor(parser, bytes) catch |err| return self.fail(err))) return error.WouldBlock;
        const consumed = feedUntilOneRecord(parser, bytes, &sink) catch |err| return self.fail(err);
        if (consumed == 0) self.noteQueueMutation();
        var plaintext_buf: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
        for (sink.items[0..sink.len]) |record| {
            if (epoch == .initial and record.content_type == .alert) {
                try self.handleAlert(record.payload);
                continue;
            }
            // RFC 9846 §5 (RFC 8446 Appendix D.4's mechanism, carried
            // forward): a middlebox-compatibility-mode peer sends an
            // unprotected single-byte {0x01} change_cipher_spec record,
            // which carries no protocol meaning and MUST be dropped without
            // further processing rather than opened through the bridge (it
            // was never encrypted, so `openProtected` would try to decrypt
            // an unprotected record) -- but only inside the RFC-defined
            // window: after the first ClientHello has been sent or
            // received, and before the peer's Finished has been received.
            // Outside that window (including here, before it) it is an
            // unexpected record and must abort, not be silently dropped.
            // `parseHeader` already bounds it to exactly one byte; any other
            // payload is the "any other change_cipher_spec value" case the
            // RFC also requires aborting the handshake for.
            if (record.content_type == .change_cipher_spec) {
                if (record.payload.len != 1 or record.payload[0] != 0x01 or !self.firstClientHelloAccepted() or self.bridge.handshake_complete) {
                    return self.fail(error.UnexpectedRecordContent);
                }
                continue;
            }
            const opened = self.openHandshakeRecord(epoch, record, &plaintext_buf) catch |err| switch (err) {
                error.AuthenticationFailed => {
                    if (epoch == .handshake and self.mayDiscardRejectedEarlyRecord(record)) continue;
                    return self.fail(err);
                },
                else => return self.fail(err),
            };
            switch (opened.inner.content_type) {
                .handshake => try self.driveReceive(opened.epoch, opened.inner.content),
                .application_data => {
                    if (opened.epoch != .zero_rtt) return self.fail(error.UnexpectedRecordContent);
                    const max_early = self.handshake_driver.?.backend.earlyDataMaxBytes();
                    if (self.zero_rtt_accepted + opened.inner.content.len > max_early) {
                        return self.fail(error.IllegalParameter);
                    }
                    self.zero_rtt_accepted += opened.inner.content.len;
                    self.appendInboundPlaintext(opened.inner.content, true) catch |err| return self.fail(err);
                },
                .alert => try self.handleAlert(opened.inner.content),
                .change_cipher_spec,
                => return self.fail(error.UnexpectedRecordContent),
            }
            // A deferred terminal failure means the driver rejected this
            // message; stop opening further coalesced records under it.
            if (self.pending_terminal != null) break;
        }
        return consumed;
    }

    fn openHandshakeRecord(
        self: *PureZigRecordStream,
        epoch: events.EncryptionEpoch,
        record: record_codec.Record,
        out: []u8,
    ) Error!record_epoch_bridge.OpenedRecord {
        if (epoch == .handshake and
            self.role == .server and
            !self.bridge.handshake_complete and
            self.bridge.hasReadKeys(.zero_rtt))
        {
            return self.bridge.openProtected(.zero_rtt, record, out) catch |early_err| switch (early_err) {
                error.AuthenticationFailed => self.bridge.openProtected(epoch, record, out),
                else => early_err,
            };
        }
        return self.bridge.openProtected(epoch, record, out);
    }

    fn shouldDiscardUnauthenticatedEarlyRecord(self: *const PureZigRecordStream, epoch: events.EncryptionEpoch) bool {
        return self.role == .server and
            epoch == .handshake and
            !self.bridge.handshake_complete and
            self.handshake_driver != null and
            self.handshake_driver.?.backend.earlyDataAttempted();
    }

    fn mayDiscardRejectedEarlyRecord(self: *PureZigRecordStream, record: record_codec.Record) bool {
        if (!self.shouldDiscardUnauthenticatedEarlyRecord(.handshake)) return false;
        const plaintext_limit = self.handshake_driver.?.backend.earlyDataDiscardLimit();
        if (plaintext_limit == 0) return false;
        const limit = rejectedEarlyWireLimit(plaintext_limit);
        const wire_len: u64 = @intCast(record_codec.header_len + record.payload.len);
        if (self.rejected_early_bytes + wire_len > limit) return false;
        self.rejected_early_bytes += wire_len;
        return true;
    }

    fn rejectedEarlyWireLimit(plaintext_limit: u32) u64 {
        if (plaintext_limit == 0) return 0;
        const overhead_per_record = record_codec.header_len + 1 + 16;
        const records = @as(u64, plaintext_limit) + 1;
        return @as(u64, plaintext_limit) + records * overhead_per_record;
    }

    /// A torn-down driver is never polled again: `finishClose`/`fail`/`deinit`
    /// release the backend, and `drive()` can reach this predicate later in the
    /// same call after an in-loop `queueCloseNotify` completed the close.
    fn authStillPending(self: *const PureZigRecordStream) bool {
        if (self.driver_torn_down) return false;
        if (self.handshake_driver) |*driver| return driver.authPending();
        return false;
    }

    /// Best-effort nonblocking flush of a queued fatal alert to the carrier
    /// before the stream latches closed. Returns bytes written.
    fn flushPendingAlert(self: *PureZigRecordStream) usize {
        const carrier = self.carrier orelse return 0;
        var flushed: usize = 0;
        while (self.outbound_ciphertext.len > 0 and flushed < drive_write_budget) {
            const written = carrier.write(self.peekCiphertext()) catch |err| switch (err) {
                error.WouldBlock => return flushed,
                else => return flushed,
            };
            if (written == 0) return flushed;
            self.consumeCiphertext(written) catch return flushed;
            flushed += written;
        }
        return flushed;
    }

    fn canAcceptCarrierRead(self: *const PureZigRecordStream) bool {
        return self.canProcessCarrierInput() and
            (!self.read_backpressured or self.canContinueActiveRecord()) and
            self.inbound_carrier.available() > 0 and
            (self.inboundCiphertextReadRoom() catch return false) > 0 and
            (self.hasRuntimeInboundDestinationReserve() catch return false);
    }

    fn canProcessCarrierInput(self: *const PureZigRecordStream) bool {
        return self.lifecycle != .closed and self.lifecycle != .failed and self.lifecycle != .closing and !self.peer_closed;
    }

    fn queueCloseNotify(self: *PureZigRecordStream) Error!bool {
        if (self.lifecycle != .closing or self.close_notify_queued) return false;
        if (!self.bridge.handshake_complete) {
            self.finishClose();
            self.closeCarrier();
            return true;
        }
        if (self.outbound_ciphertext.len > 0) return false;
        if (!self.canReserveOutboundRecord()) return false;
        var alert_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
        const close_notify = self.bridge.sealProtected(.application, .alert, &.{ 1, 0 }, &alert_buf) catch |err| return self.fail(err);
        self.appendOutboundCiphertext(close_notify) catch |err| return self.fail(err);
        self.close_notify_queued = true;
        return true;
    }

    fn processCarrierInputBudget(self: *PureZigRecordStream, record_budget_remaining: *usize) Error!bool {
        const initial_budget = record_budget_remaining.*;
        while (!self.authStillPending() and record_budget_remaining.* > 0 and self.inbound_carrier.len > 0 and self.canProcessCarrierInput()) {
            const pending = self.inbound_carrier.slice();
            const consumed = self.feedCarrierCiphertext(pending) catch |err| switch (err) {
                error.WouldBlock => break,
                else => return err,
            };
            if (consumed == 0) break;
            try self.inbound_carrier.discard(consumed);
            self.noteQueueMutation();
            record_budget_remaining.* -= 1;
        }
        return record_budget_remaining.* != initial_budget;
    }

    fn processCarrierInput(self: *PureZigRecordStream, record_budget: usize) Error!bool {
        var record_budget_remaining = record_budget;
        return self.processCarrierInputBudget(&record_budget_remaining);
    }

    fn hasBufferedInboundContent(self: *const PureZigRecordStream) bool {
        return self.inbound_plaintext.len > 0 or self.inbound_handshake.len > 0;
    }

    fn deferTerminalReadError(self: *PureZigRecordStream, err: Error) Error!void {
        if (self.hasBufferedInboundContent()) {
            self.pending_terminal_read_error = err;
            return;
        }
        return self.fail(err);
    }

    fn raisePendingTerminalError(self: *PureZigRecordStream) Error!void {
        const err = self.pending_terminal_read_error orelse return;
        if (self.hasBufferedInboundContent()) return;
        return self.fail(err);
    }

    fn closeCarrier(self: *PureZigRecordStream) void {
        if (self.carrier) |carrier| {
            std.debug.assert(!carrier.owns_handle or carrier.closeFn != null);
            if (carrier.owns_handle) carrier.close();
            self.carrier = null;
        }
    }

    fn fail(self: *PureZigRecordStream, err: Error) Error {
        self.failed = err;
        self.lifecycle = .failed;
        self.clearOwnedQueues();
        self.clearHandshakeMetadata();
        self.initial_parser.reset();
        self.ciphertext_parser.reset();
        self.pending_terminal_read_error = null;
        self.pending_terminal = null;
        self.terminal_flush_attempts = 0;
        self.zero_rtt_sent = 0;
        self.zero_rtt_accepted = 0;
        self.rejected_early_bytes = 0;
        self.teardownDriver();
        self.bridge.deinit();
        self.closeCarrier();
        return err;
    }
};

fn feedUntilOneRecord(parser: *record_codec.Parser, bytes: []const u8, sink: anytype) Error!usize {
    const result = try parser.feedOne(bytes, sink);
    return result.consumed;
}

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
    if (self.lifecycle == .handshaking or self.lifecycle == .open) self.lifecycle = .closing;
}

fn pureReadiness(ptr: *anyopaque) Readiness {
    const self: *PureZigRecordStream = @ptrCast(@alignCast(ptr));
    return self.readiness();
}

fn pureDrive(ptr: *anyopaque) Error!DriveResult {
    const self: *PureZigRecordStream = @ptrCast(@alignCast(ptr));
    return self.drive();
}

fn pureBufferSnapshot(ptr: *anyopaque) BufferSnapshot {
    const self: *PureZigRecordStream = @ptrCast(@alignCast(ptr));
    return self.bufferSnapshot();
}

fn pureCurrentReadEarlyPrefixLen(ptr: *anyopaque) usize {
    const self: *PureZigRecordStream = @ptrCast(@alignCast(ptr));
    return self.currentReadEarlyPrefixLen();
}

const pure_zig_record_vtable = EncryptedStream.VTable{
    .backendFn = pureBackend,
    .readFn = pureRead,
    .writeFn = pureWrite,
    .closeFn = pureClose,
    .readinessFn = pureReadiness,
    .driveFn = pureDrive,
    .bufferSnapshotFn = pureBufferSnapshot,
    .currentReadEarlyPrefixLenFn = pureCurrentReadEarlyPrefixLen,
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
            self.discard(n) catch unreachable;
            return n;
        }

        fn slice(self: *const Self) []const u8 {
            return self.buf[0..self.len];
        }

        fn discard(self: *Self, count: usize) Error!void {
            if (count > self.len) return error.WouldBlock;
            const old_len = self.len;
            const remaining = old_len - count;
            std.mem.copyForwards(u8, self.buf[0..remaining], self.buf[count..old_len]);
            @memset(self.buf[remaining..old_len], 0);
            self.len = remaining;
        }

        fn available(self: *const Self) usize {
            return capacity - self.len;
        }

        fn clear(self: *Self) void {
            @memset(self.buf[0..], 0);
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

/// A secret buffer wide enough for any supported suite's digest length, so a
/// SHA-384 suite can be driven from the same helper as a SHA-256 one.
fn wideSecret(comptime fill: u8) [provider.max_digest_len]u8 {
    return [_]u8{fill} ** provider.max_digest_len;
}

fn establish(client: *PureZigRecordStream, server: *PureZigRecordStream) !void {
    return establishForSuite(client, server, .tls_aes_128_gcm_sha256);
}

/// `establish`, for a caller-chosen suite: the traffic-secret length a bridge
/// accepts is that suite's transcript-hash digest length, so a SHA-384 suite
/// needs 48-byte secrets rather than 32.
fn establishForSuite(client: *PureZigRecordStream, server: *PureZigRecordStream, suite: algorithms.CipherSuite) !void {
    const secret_len = algorithms.transcriptHash(suite).digestLength();
    const client_hs_buf = wideSecret(0x11);
    const server_hs_buf = wideSecret(0x22);
    const client_app_buf = wideSecret(0x33);
    const server_app_buf = wideSecret(0x44);
    const client_hs = client_hs_buf[0..secret_len];
    const server_hs = server_hs_buf[0..secret_len];
    const client_app = client_app_buf[0..secret_len];
    const server_app = server_app_buf[0..secret_len];

    try client.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .write, .data = client_hs } });
    try client.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .read, .data = server_hs } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .read, .data = client_hs } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .write, .data = server_hs } });
    try client.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .write, .data = client_app } });
    try client.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .read, .data = server_app } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .read, .data = client_app } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .write, .data = server_app } });
    try client.applyEvent(.{ .discard_epoch = .initial });
    try server.applyEvent(.{ .discard_epoch = .initial });
    try client.applyEvent(.{ .discard_epoch = .handshake });
    try server.applyEvent(.{ .discard_epoch = .handshake });
    try client.applyEvent(.handshake_complete);
    try server.applyEvent(.handshake_complete);
}

fn pumpCiphertext(from: *PureZigRecordStream, to: *PureZigRecordStream, max_chunk: usize) !usize {
    var moved: usize = 0;
    var buf: [128]u8 = undefined;
    while (from.queuedCiphertextLen() > 0) {
        const n = try from.drainCiphertext(buf[0..@min(max_chunk, buf.len)]);
        moved += n;
        try feedAllCiphertext(to, buf[0..n]);
    }
    return moved;
}

fn pumpHandshake(from: *PureZigRecordStream, to: *PureZigRecordStream, epoch: events.EncryptionEpoch, max_chunk: usize) !usize {
    var moved: usize = 0;
    var buf: [128]u8 = undefined;
    while (from.queuedCiphertextLen() > 0) {
        const n = try from.drainCiphertext(buf[0..@min(max_chunk, buf.len)]);
        moved += n;
        try feedAllHandshake(to, epoch, buf[0..n]);
    }
    return moved;
}

fn feedAllCiphertext(stream: *PureZigRecordStream, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const consumed = try stream.feedCiphertext(bytes[offset..]);
        if (consumed == 0) return error.WouldBlock;
        offset += consumed;
    }
}

fn feedAllHandshake(stream: *PureZigRecordStream, epoch: events.EncryptionEpoch, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const consumed = try stream.feedHandshakeCiphertext(epoch, bytes[offset..]);
        if (consumed == 0) return error.WouldBlock;
        offset += consumed;
    }
}

fn testSocketPair() ![2]std.posix.fd_t {
    var fds: [2]std.posix.fd_t = undefined;
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds);
        if (linux.errno(rc) != .SUCCESS) return error.SocketPairFailed;
    } else {
        if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    }
    errdefer closeFd(fds[0]);
    errdefer closeFd(fds[1]);
    try setNonBlocking(fds[0]);
    try setNonBlocking(fds[1]);
    return fds;
}

fn closeFd(fd: std.posix.fd_t) void {
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.close(fd);
    } else {
        _ = std.c.close(fd);
    }
}

fn setNonBlocking(fd: std.posix.fd_t) !void {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const status_flags = linux.fcntl(fd, linux.F.GETFL, 0);
        if (linux.errno(status_flags) != .SUCCESS) return error.FcntlFailed;
        const nonblock: usize = @intCast(@as(u32, @bitCast(linux.O{ .NONBLOCK = true })));
        const rc = linux.fcntl(fd, linux.F.SETFL, status_flags | nonblock);
        if (linux.errno(rc) != .SUCCESS) return error.FcntlFailed;
    } else {
        const status_flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
        if (status_flags < 0) return error.FcntlFailed;
        const nonblock = @as(c_int, @bitCast(std.posix.O{ .NONBLOCK = true }));
        if (std.c.fcntl(fd, std.c.F.SETFL, status_flags | nonblock) < 0) return error.FcntlFailed;
    }
}

fn flushStreamToFd(stream: *PureZigRecordStream, fd: std.posix.fd_t, max_chunk: usize) !usize {
    var moved: usize = 0;
    while (stream.queuedCiphertextLen() > 0) {
        const pending = stream.peekCiphertext();
        const n = @min(max_chunk, pending.len);
        const written = writeFd(fd, pending[0..n]) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
        if (written == 0) break;
        try stream.consumeCiphertext(written);
        moved += written;
    }
    return moved;
}

fn readFdIntoStream(fd: std.posix.fd_t, stream: *PureZigRecordStream, max_chunk: usize) !usize {
    var moved: usize = 0;
    var buf: [32]u8 = undefined;
    while (true) {
        const n = readFd(fd, buf[0..@min(max_chunk, buf.len)]) catch |err| switch (err) {
            error.WouldBlock => return moved,
            else => return err,
        };
        if (n == 0) {
            try stream.markPeerEof();
            return moved;
        }
        moved += n;
        try feedAllCiphertext(stream, buf[0..n]);
    }
}

fn readFd(fd: std.posix.fd_t, out: []u8) Error!usize {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.read(fd, out.ptr, out.len);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            else => error.SocketReadFailed,
        };
    }
    const rc = std.c.read(fd, out.ptr, out.len);
    if (rc < 0) {
        if (std.posix.errno(rc) == .AGAIN) return error.WouldBlock;
        return error.SocketReadFailed;
    }
    return @intCast(rc);
}

fn writeFd(fd: std.posix.fd_t, bytes: []const u8) Error!usize {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.write(fd, bytes.ptr, bytes.len);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            else => error.SocketWriteFailed,
        };
    }
    const rc = std.c.write(fd, bytes.ptr, bytes.len);
    if (rc < 0) {
        if (std.posix.errno(rc) == .AGAIN) return error.WouldBlock;
        return error.SocketWriteFailed;
    }
    return @intCast(rc);
}

const testing = std.testing;

test "pure Zig encrypted stream carries fragmented handshake and application data" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
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

    try server.applyEvent(.{ .handshake_bytes = .{ .epoch = .application, .data = "ticket" } });
    _ = try pumpCiphertext(&server, &client, 4);
    const ticket_len = try client.readHandshake(&plain);
    try testing.expectEqualStrings("ticket", plain[0..ticket_len]);

    var alert_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const close_notify = try server.bridge.sealProtected(.application, .alert, &.{ 1, 0 }, &alert_buf);
    try server.outbound_ciphertext.append(close_notify);
    _ = try pumpCiphertext(&server, &client, 3);
    try testing.expectError(error.EndOfStream, client.stream().read(&plain));
}

test "encrypted stream backpressure is atomic around record protection state" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    client.outbound_ciphertext.len = PureZigRecordStream.max_ciphertext_queue - 1;
    const write_seq = client.bridge.write_application.?.sequence;
    try testing.expectError(error.WouldBlock, client.applyEvent(.{ .handshake_bytes = .{ .epoch = .application, .data = "retryable" } }));
    try testing.expectEqual(write_seq, client.bridge.write_application.?.sequence);
    client.outbound_ciphertext.len = 0;

    _ = try client.stream().write("retryable plaintext");
    var record_bytes: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const record_len = try client.drainCiphertext(&record_bytes);
    server.inbound_plaintext.len = PureZigRecordStream.max_plaintext_queue;
    const read_seq = server.bridge.read_application.?.sequence;
    try testing.expectError(error.WouldBlock, server.feedCiphertext(record_bytes[0..record_len]));
    try testing.expectEqual(read_seq, server.bridge.read_application.?.sequence);
    server.inbound_plaintext.len = 0;
}

fn testBufferLimits() BufferLimits {
    return .{
        .inbound_ciphertext = .{ .low = 32, .high = 64, .hard = PureZigRecordStream.max_carrier_input_queue },
        .inbound_plaintext = .{ .low = 4, .high = 8, .hard = PureZigRecordStream.max_plaintext_queue },
        .outbound_ciphertext = .{ .low = 24, .high = 48, .hard = PureZigRecordStream.max_ciphertext_queue },
        .handshake = .{ .low = 4, .high = 8, .hard = PureZigRecordStream.max_handshake_queue },
    };
}

test "TLS buffer defaults validate and expose bounded snapshot" {
    const limits = BufferLimits.defaults();
    try limits.validate();

    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    try expectOpenIdleConformance(client.stream(), .pure_zig_record);
    const snapshot = client.stream().bufferSnapshot();
    try testing.expectEqual(@as(usize, 0), snapshot.current.total());
    try testing.expect(snapshot.limits_enforced);
    try testing.expectEqual(limits.outbound_ciphertext.hard, snapshot.limits.?.outbound_ciphertext.hard);
    try testing.expect(!snapshot.pause_state.inbound_read_paused);
    try testing.expect(!snapshot.pause_state.plaintext_write_paused);
    try testing.expectEqual(AccountingBoundary.complete_stream_owned, snapshot.accounting_boundary);
}

test "handshakeRecordCount stays overflow-safe at a synthetic near-usize-max bytes_len" {
    try testing.expectEqual(@as(usize, 0), try handshakeRecordCount(0));
    try testing.expectEqual(@as(usize, 1), try handshakeRecordCount(record_codec.max_plaintext_fragment_len));
    try testing.expectEqual(@as(usize, 2), try handshakeRecordCount(record_codec.max_plaintext_fragment_len + 1));
    try testing.expectEqual(
        try std.math.divCeil(usize, std.math.maxInt(usize), record_codec.max_plaintext_fragment_len),
        try handshakeRecordCount(std.math.maxInt(usize)),
    );
}

test "record stream maximum emitted ticket fits four-record ciphertext queue" {
    try std.testing.expectEqual(4 * record_codec.max_ciphertext_record_len, PureZigRecordStream.max_ciphertext_queue);
    const bytes_len = tls13_transport.max_emitted_new_session_ticket_message_len;
    const records = try handshakeRecordCount(bytes_len);
    const protected_len = bytes_len + records * (record_codec.header_len + 1 + 16);
    try std.testing.expect(protected_len <= PureZigRecordStream.max_ciphertext_queue);
}

test "TLS buffer policy rejects invalid watermarks and over-capacity hard limits" {
    var limits = BufferLimits.defaults();
    limits.inbound_plaintext.low = 0;
    try testing.expectError(error.InvalidBufferLimits, limits.validate());

    limits = BufferLimits.defaults();
    limits.inbound_plaintext.low = limits.inbound_plaintext.high;
    try testing.expectError(error.InvalidBufferLimits, limits.validate());

    limits = BufferLimits.defaults();
    limits.outbound_ciphertext.high = limits.outbound_ciphertext.hard + 1;
    try testing.expectError(error.InvalidBufferLimits, limits.validate());

    limits = BufferLimits.defaults();
    limits.handshake.hard = record_codec.max_plaintext_fragment_len - 1;
    try testing.expectError(error.InvalidBufferLimits, limits.validate());

    limits = BufferLimits.defaults();
    limits.inbound_ciphertext.hard = PureZigRecordStream.max_carrier_input_queue + 1;
    try testing.expectError(error.InvalidBufferLimits, limits.validate());
}

test "TLS buffer policy rejects invalid combinations for every queue" {
    inline for (.{ "inbound_ciphertext", "inbound_plaintext", "outbound_ciphertext", "handshake" }) |field| {
        var zero = BufferLimits.defaults();
        @field(zero, field).low = 0;
        try testing.expectError(error.InvalidBufferLimits, zero.validate());

        var ordered = BufferLimits.defaults();
        @field(ordered, field).low = @field(ordered, field).high;
        try testing.expectError(error.InvalidBufferLimits, ordered.validate());

        var high_over_hard = BufferLimits.defaults();
        @field(high_over_hard, field).high = @field(high_over_hard, field).hard + 1;
        try testing.expectError(error.InvalidBufferLimits, high_over_hard.validate());

        var over_capacity = BufferLimits.defaults();
        @field(over_capacity, field).hard += 1;
        try testing.expectError(error.InvalidBufferLimits, over_capacity.validate());
    }

    var inbound_below_reserve = BufferLimits.defaults();
    inbound_below_reserve.inbound_ciphertext.hard = record_codec.max_ciphertext_record_len - 1;
    try testing.expectError(error.InvalidBufferLimits, inbound_below_reserve.validate());

    var plaintext_below_reserve = BufferLimits.defaults();
    plaintext_below_reserve.inbound_plaintext.hard = record_codec.max_plaintext_fragment_len - 1;
    try testing.expectError(error.InvalidBufferLimits, plaintext_below_reserve.validate());

    var outbound_below_reserve = BufferLimits.defaults();
    outbound_below_reserve.outbound_ciphertext.hard = PureZigRecordStream.handshake_output_reserve - 1;
    try testing.expectError(error.InvalidBufferLimits, outbound_below_reserve.validate());

    var handshake_below_reserve = BufferLimits.defaults();
    handshake_below_reserve.handshake.hard = record_codec.max_plaintext_fragment_len - 1;
    try testing.expectError(error.InvalidBufferLimits, handshake_below_reserve.validate());
}

test "fragmented records count parser-owned inbound ciphertext bytes" {
    const cp = testProvider();
    var stream_state = try PureZigRecordStream.initWithLimits(.server, cp, .tls_aes_128_gcm_sha256, testBufferLimits());
    defer stream_state.deinit();

    const payload = "fragmented";
    var record: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const encoded = try record_codec.encodePlaintextRecord(.handshake, payload, &record);

    try testing.expectEqual(@as(usize, 2), try stream_state.feedHandshakeCiphertext(.initial, encoded[0..2]));
    var snapshot = stream_state.stream().bufferSnapshot();
    try testing.expectEqual(@as(usize, 2), snapshot.current.inbound_ciphertext);
    try testing.expectEqual(@as(usize, 2), snapshot.peak.inbound_ciphertext);
    try testing.expectEqual(@as(usize, 0), snapshot.current.handshake);

    try testing.expectEqual(@as(usize, 3), try stream_state.feedHandshakeCiphertext(.initial, encoded[2..5]));
    snapshot = stream_state.stream().bufferSnapshot();
    try testing.expectEqual(@as(usize, 5), snapshot.current.inbound_ciphertext);
    try testing.expectEqual(@as(usize, 5), snapshot.peak.inbound_ciphertext);

    try testing.expectEqual(encoded.len - 5, try stream_state.feedHandshakeCiphertext(.initial, encoded[5..]));
    snapshot = stream_state.stream().bufferSnapshot();
    try testing.expectEqual(@as(usize, 0), snapshot.current.inbound_ciphertext);
    try testing.expectEqual(@as(usize, 5), snapshot.peak.inbound_ciphertext);
    try testing.expectEqual(payload.len, snapshot.current.handshake);
}

test "direct fragmented feed hard rejection leaves parser bytes retryable" {
    const cp = testProvider();
    var stream_state = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer stream_state.deinit();
    stream_state.buffer_limits.inbound_ciphertext = .{
        .low = 1,
        .high = record_codec.max_ciphertext_record_len,
        .hard = record_codec.max_ciphertext_record_len,
    };
    stream_state.initial_parser.len = record_codec.max_ciphertext_record_len;
    stream_state.noteQueueMutation();

    const before = stream_state.stream().bufferSnapshot();
    try testing.expectEqual(record_codec.max_ciphertext_record_len, before.current.inbound_ciphertext);
    try testing.expectError(error.WouldBlock, stream_state.feedHandshakeCiphertext(.initial, &.{ 1, 2 }));
    const after = stream_state.stream().bufferSnapshot();
    try testing.expectEqual(before.current.inbound_ciphertext, after.current.inbound_ciphertext);
    try testing.expectEqual(@as(usize, record_codec.max_ciphertext_record_len), stream_state.initial_parser.len);
    try testing.expectEqual(@as(u64, 1), after.counters.hard_limits.inbound_ciphertext);
}

test "carrier reads cap at runtime high before hard limit" {
    const SourceCarrier = struct {
        bytes: []const u8,
        offset: usize = 0,
        expected_read_caps: []const usize,
        read_index: usize = 0,
        read_armed: bool = true,

        fn rearm(self: *@This()) void {
            self.read_armed = true;
        }

        fn carrier(self: *@This()) Carrier {
            return .{ .ptr = self, .readFn = read, .writeFn = write };
        }

        fn read(ptr: *anyopaque, out: []u8) Error!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (!self.read_armed) return error.WouldBlock;
            if (self.offset == self.bytes.len) return error.WouldBlock;
            testing.expect(self.read_index < self.expected_read_caps.len) catch unreachable;
            testing.expectEqual(self.expected_read_caps[self.read_index], out.len) catch unreachable;
            self.read_index += 1;
            self.read_armed = false;
            const n = @min(out.len, self.bytes.len - self.offset);
            @memcpy(out[0..n], self.bytes[self.offset..][0..n]);
            self.offset += n;
            return n;
        }

        fn write(_: *anyopaque, _: []const u8) Error!usize {
            return error.WouldBlock;
        }
    };

    const cp = testProvider();
    const inbound_high = 64;
    var stream_state = try PureZigRecordStream.initWithLimits(.server, cp, .tls_aes_128_gcm_sha256, .{
        .inbound_ciphertext = .{
            .low = 4,
            .high = inbound_high,
            .hard = record_codec.max_ciphertext_record_len,
        },
        .inbound_plaintext = .{
            .low = 4,
            .high = PureZigRecordStream.max_plaintext_queue,
            .hard = PureZigRecordStream.max_plaintext_queue,
        },
        .outbound_ciphertext = BufferLimits.defaults().outbound_ciphertext,
        .handshake = .{
            .low = 4,
            .high = PureZigRecordStream.max_handshake_queue,
            .hard = PureZigRecordStream.max_handshake_queue,
        },
    });
    defer stream_state.deinit();
    var peer = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer peer.deinit();
    try establish(&peer, &stream_state);

    var payload = [_]u8{'x'} ** 128;
    try testing.expectEqual(payload.len, try peer.stream().write(&payload));
    var records: [record_codec.max_ciphertext_record_len * 2]u8 = undefined;
    const first_len = try peer.drainCiphertext(records[0..record_codec.max_ciphertext_record_len]);
    try testing.expect(first_len > inbound_high);
    try testing.expectEqual(payload.len, try peer.stream().write(&payload));
    const second_len = try peer.drainCiphertext(records[first_len..]);
    const expected_read_caps = [_]usize{ inbound_high, first_len - inbound_high, inbound_high };
    var carrier = SourceCarrier{
        .bytes = records[0 .. first_len + second_len],
        .expected_read_caps = &expected_read_caps,
    };
    stream_state.carrier = carrier.carrier();

    const first = try stream_state.stream().drive();
    try testing.expect(first.made_progress);
    try testing.expectEqual(inbound_high, carrier.offset);
    try testing.expect(stream_state.stream().bufferSnapshot().pause_state.inbound_read_paused);

    carrier.rearm();
    const continued = try stream_state.stream().drive();
    try testing.expect(continued.made_progress);
    try testing.expectEqual(first_len, carrier.offset);
    try testing.expect(!continued.readiness.wants_read);
    const snapshot = stream_state.stream().bufferSnapshot();
    try testing.expectEqual(@as(usize, 0), snapshot.current.inbound_ciphertext);
    try testing.expect(snapshot.peak.inbound_ciphertext <= first_len);
    try testing.expect(!snapshot.pause_state.plaintext_write_paused);
    try testing.expectEqual(@as(u64, 0), snapshot.counters.hard_limits.inbound_ciphertext);
    try testing.expectEqual(@as(u64, 1), snapshot.counters.inbound_read_pauses);

    var out: [payload.len]u8 = undefined;
    try testing.expectEqual(payload.len, try stream_state.stream().read(&out));
    try testing.expectEqualSlices(u8, &payload, &out);
    const resumed = stream_state.stream().bufferSnapshot();
    try testing.expectEqual(@as(usize, 0), resumed.current.inbound_ciphertext);
    try testing.expect(!resumed.pause_state.inbound_read_paused);
    try testing.expectEqual(@as(u64, 1), resumed.counters.inbound_read_resumes);

    carrier.rearm();
    const next_record = try stream_state.stream().drive();
    try testing.expect(next_record.made_progress);
    try testing.expectEqual(first_len + inbound_high, carrier.offset);
    try testing.expectEqual(inbound_high, stream_state.ciphertext_parser.len);
}

test "internal carrier parser transfer does not double count partial records" {
    const cp = testProvider();
    var stream_state = try PureZigRecordStream.initWithLimits(.server, cp, .tls_aes_128_gcm_sha256, .{
        .inbound_ciphertext = .{ .low = 32, .high = 64, .hard = record_codec.max_ciphertext_record_len },
        .inbound_plaintext = BufferLimits.defaults().inbound_plaintext,
        .outbound_ciphertext = BufferLimits.defaults().outbound_ciphertext,
        .handshake = BufferLimits.defaults().handshake,
    });
    defer stream_state.deinit();
    var peer = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer peer.deinit();
    try establish(&peer, &stream_state);

    try testing.expectEqual(@as(usize, 128), try peer.stream().write(&([_]u8{'p'} ** 128)));
    var record: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const record_len = try peer.drainCiphertext(&record);
    try testing.expect(record_len > 40);

    try stream_state.inbound_carrier.append(record[0..40]);
    stream_state.noteQueueMutation();
    var budget: usize = 1;
    try testing.expect(try stream_state.processCarrierInputBudget(&budget));

    const snapshot = stream_state.stream().bufferSnapshot();
    try testing.expectEqual(@as(usize, 40), snapshot.current.inbound_ciphertext);
    try testing.expectEqual(@as(usize, 40), snapshot.peak.inbound_ciphertext);
    try testing.expect(!snapshot.pause_state.inbound_read_paused);
}

test "direct coalesced feed counts only consumed borrowed record against inbound hard limit" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = try PureZigRecordStream.initWithLimits(.server, cp, .tls_aes_128_gcm_sha256, .{
        .inbound_ciphertext = .{
            .low = 4,
            .high = record_codec.max_ciphertext_record_len,
            .hard = record_codec.max_ciphertext_record_len,
        },
        .inbound_plaintext = BufferLimits.defaults().inbound_plaintext,
        .outbound_ciphertext = BufferLimits.defaults().outbound_ciphertext,
        .handshake = BufferLimits.defaults().handshake,
    });
    defer server.deinit();
    try establish(&client, &server);

    var coalesced: [record_codec.max_ciphertext_record_len * 2]u8 = undefined;
    var payload = [_]u8{'m'} ** record_codec.max_plaintext_fragment_len;
    try testing.expectEqual(payload.len, try client.stream().write(&payload));
    const first_len = try client.drainCiphertext(coalesced[0..record_codec.max_ciphertext_record_len]);
    try testing.expectEqual(payload.len, try client.stream().write(&payload));
    const second_len = try client.drainCiphertext(coalesced[first_len..]);

    const consumed = try server.feedCiphertext(coalesced[0 .. first_len + second_len]);
    try testing.expectEqual(first_len, consumed);
    var snapshot = server.stream().bufferSnapshot();
    try testing.expectEqual(@as(u64, 0), snapshot.counters.hard_limits.inbound_ciphertext);
    try testing.expectEqual(@as(usize, 0), snapshot.current.inbound_ciphertext);

    var out: [record_codec.max_plaintext_fragment_len]u8 = undefined;
    try testing.expectEqual(payload.len, try server.stream().read(&out));
    try testing.expectEqualSlices(u8, &payload, &out);
    try testing.expectEqual(second_len, try server.feedCiphertext(coalesced[first_len .. first_len + second_len]));
    snapshot = server.stream().bufferSnapshot();
    try testing.expectEqual(@as(u64, 0), snapshot.counters.hard_limits.inbound_ciphertext);
}

test "outbound ciphertext high-low hysteresis gates plaintext writes exactly once" {
    const cp = testProvider();
    var client = try PureZigRecordStream.initWithLimits(.client, cp, .tls_aes_128_gcm_sha256, testBufferLimits());
    defer client.deinit();
    var server = try PureZigRecordStream.initWithLimits(.server, cp, .tls_aes_128_gcm_sha256, testBufferLimits());
    defer server.deinit();
    try establish(&client, &server);

    var writes: usize = 0;
    while (client.stream().readiness().can_write_plaintext) : (writes += 1) {
        _ = try client.stream().write("pause-me");
    }
    try testing.expect(writes > 0);

    var snapshot = client.stream().bufferSnapshot();
    try testing.expect(snapshot.current.outbound_ciphertext >= snapshot.limits.?.outbound_ciphertext.high);
    try testing.expect(snapshot.pause_state.plaintext_write_paused);
    try testing.expectEqual(@as(u64, 1), snapshot.counters.plaintext_write_pauses);
    try testing.expectEqual(@as(u64, 0), snapshot.counters.plaintext_write_resumes);
    try testing.expectError(error.WouldBlock, client.stream().write("blocked"));
    try testing.expectEqual(@as(u64, 1), client.stream().bufferSnapshot().counters.plaintext_write_pauses);

    var drained: [record_codec.max_ciphertext_record_len]u8 = undefined;
    while (client.stream().bufferSnapshot().current.outbound_ciphertext > snapshot.limits.?.outbound_ciphertext.low) {
        _ = try client.drainCiphertext(drained[0..1]);
    }
    snapshot = client.stream().bufferSnapshot();
    try testing.expect(!snapshot.pause_state.plaintext_write_paused);
    try testing.expect(snapshot.current.outbound_ciphertext <= snapshot.limits.?.outbound_ciphertext.low);
    try testing.expectEqual(@as(u64, 1), snapshot.counters.plaintext_write_resumes);
    try testing.expect(client.stream().readiness().can_write_plaintext);
}

test "inbound plaintext high-low hysteresis gates carrier reads and resumes below low" {
    const cp = testProvider();
    var client = try PureZigRecordStream.initWithLimits(.client, cp, .tls_aes_128_gcm_sha256, testBufferLimits());
    defer client.deinit();
    var server = try PureZigRecordStream.initWithLimits(.server, cp, .tls_aes_128_gcm_sha256, testBufferLimits());
    defer server.deinit();
    try establish(&client, &server);

    _ = try client.stream().write("0123456789");
    var record: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const record_len = try client.drainCiphertext(&record);
    try feedAllCiphertext(&server, record[0..record_len]);

    var snapshot = server.stream().bufferSnapshot();
    try testing.expect(snapshot.current.inbound_plaintext >= snapshot.limits.?.inbound_plaintext.high);
    try testing.expect(snapshot.pause_state.inbound_read_paused);
    try testing.expect(!server.stream().readiness().wants_read);
    try testing.expectEqual(@as(u64, 1), snapshot.counters.inbound_read_pauses);

    const stable = server.stream().readiness();
    try testing.expectEqual(stable, server.stream().readiness());
    try testing.expectEqual(@as(u64, 1), server.stream().bufferSnapshot().counters.inbound_read_pauses);

    var plain: [16]u8 = undefined;
    _ = try server.stream().read(plain[0..6]);
    snapshot = server.stream().bufferSnapshot();
    try testing.expect(snapshot.current.inbound_plaintext <= snapshot.limits.?.inbound_plaintext.low);
    try testing.expect(!snapshot.pause_state.inbound_read_paused);
    try testing.expectEqual(@as(u64, 1), snapshot.counters.inbound_read_resumes);
    try testing.expect(server.stream().readiness().wants_read);
}

test "paused drive reports no progress and counts stalls without transition inflation" {
    const cp = testProvider();
    var client = try PureZigRecordStream.initWithLimits(.client, cp, .tls_aes_128_gcm_sha256, testBufferLimits());
    defer client.deinit();
    var server = try PureZigRecordStream.initWithLimits(.server, cp, .tls_aes_128_gcm_sha256, testBufferLimits());
    defer server.deinit();
    try establish(&client, &server);

    _ = try client.stream().write("0123456789");
    var record: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const record_len = try client.drainCiphertext(&record);
    try feedAllCiphertext(&server, record[0..record_len]);

    const first = try server.stream().drive();
    const second = try server.stream().drive();
    try testing.expect(!first.made_progress);
    try testing.expect(!second.made_progress);
    try testing.expectEqual(first.readiness, second.readiness);

    const snapshot = server.stream().bufferSnapshot();
    try testing.expect(snapshot.pause_state.inbound_read_paused);
    try testing.expectEqual(@as(u64, 1), snapshot.counters.inbound_read_pauses);
    try testing.expectEqual(@as(u64, 0), snapshot.counters.inbound_read_resumes);
    try testing.expectEqual(@as(u64, 2), snapshot.counters.stalled_drives);
}

test "internal destination hard backpressure does not inflate hard-limit counters" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = try PureZigRecordStream.initWithLimits(.server, cp, .tls_aes_128_gcm_sha256, .{
        .inbound_ciphertext = BufferLimits.defaults().inbound_ciphertext,
        .inbound_plaintext = .{
            .low = 1,
            .high = 2,
            .hard = record_codec.max_plaintext_fragment_len,
        },
        .outbound_ciphertext = BufferLimits.defaults().outbound_ciphertext,
        .handshake = BufferLimits.defaults().handshake,
    });
    defer server.deinit();
    try establish(&client, &server);

    try testing.expectEqual(@as(usize, 5), try client.stream().write("block"));
    var record: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const record_len = try client.drainCiphertext(&record);
    try server.inbound_carrier.append(record[0..record_len]);
    server.inbound_plaintext.len = record_codec.max_plaintext_fragment_len - 4;
    server.noteQueueMutation();

    for (0..2) |_| {
        const result = try server.stream().drive();
        try testing.expect(!result.made_progress);
    }

    const snapshot = server.stream().bufferSnapshot();
    try testing.expect(snapshot.pause_state.inbound_read_paused);
    try testing.expectEqual(@as(u64, 0), snapshot.counters.hard_limits.inbound_plaintext);
    try testing.expectEqual(@as(u64, 2), snapshot.counters.stalled_drives);
}

test "queued carrier header prefix blocks socket reads until destination room returns" {
    const SourceCarrier = struct {
        bytes: []const u8,
        offset: usize = 0,
        reads: usize = 0,

        fn carrier(self: *@This()) Carrier {
            return .{ .ptr = self, .readFn = read, .writeFn = write };
        }

        fn read(ptr: *anyopaque, out: []u8) Error!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (self.offset == self.bytes.len) return error.WouldBlock;
            const n = @min(out.len, self.bytes.len - self.offset);
            @memcpy(out[0..n], self.bytes[self.offset..][0..n]);
            self.offset += n;
            self.reads += 1;
            return n;
        }

        fn write(_: *anyopaque, _: []const u8) Error!usize {
            return error.WouldBlock;
        }
    };

    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = try PureZigRecordStream.initWithLimits(.server, cp, .tls_aes_128_gcm_sha256, .{
        .inbound_ciphertext = .{ .low = 8, .high = 16, .hard = record_codec.max_ciphertext_record_len },
        .inbound_plaintext = .{ .low = 1, .high = 2, .hard = record_codec.max_plaintext_fragment_len },
        .outbound_ciphertext = BufferLimits.defaults().outbound_ciphertext,
        .handshake = BufferLimits.defaults().handshake,
    });
    defer server.deinit();
    try establish(&client, &server);

    try testing.expectEqual(@as(usize, 5), try client.stream().write("block"));
    var record: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const record_len = try client.drainCiphertext(&record);
    @memcpy(server.ciphertext_parser.pending[0..4], record[0..4]);
    server.ciphertext_parser.len = 4;
    try server.inbound_carrier.append(record[4..5]);
    server.inbound_plaintext.len = record_codec.max_plaintext_fragment_len - 1;
    server.noteQueueMutation();

    var carrier = SourceCarrier{ .bytes = record[5..record_len] };
    server.carrier = carrier.carrier();
    for (0..2) |_| {
        const result = try server.stream().drive();
        try testing.expect(!result.made_progress);
        try testing.expect(!result.readiness.wants_read);
    }
    try testing.expectEqual(@as(usize, 0), carrier.reads);
    const blocked = server.stream().bufferSnapshot();
    try testing.expectEqual(@as(u64, 0), blocked.counters.hard_limits.inbound_plaintext);
    try testing.expectEqual(@as(u64, 2), blocked.counters.stalled_drives);

    server.inbound_plaintext.len = 0;
    server.noteQueueMutation();
    const resumed = try server.stream().drive();
    try testing.expect(resumed.made_progress);
    try testing.expect(carrier.reads > 0);
}

test "direct ciphertext hard rejection is counted independently of socket readiness" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    server.inbound_carrier.len = server.buffer_limits.inbound_ciphertext.hard;
    server.noteQueueMutation();
    try testing.expect(!server.stream().readiness().wants_read);
    try testing.expect(!server.stream().readiness().wants_read);
    try testing.expectEqual(@as(u64, 0), server.stream().bufferSnapshot().counters.hard_limits.inbound_ciphertext);

    const read_sequence = server.bridge.read_application.?.sequence;
    try testing.expectError(error.WouldBlock, server.feedCiphertext("blocked"));
    try testing.expectEqual(read_sequence, server.bridge.read_application.?.sequence);
    try testing.expectEqual(@as(usize, server.buffer_limits.inbound_ciphertext.hard), server.inbound_carrier.len);
    try testing.expectEqual(@as(u64, 1), server.stream().bufferSnapshot().counters.hard_limits.inbound_ciphertext);
}

test "hard-limit write rejection leaves sequence and queue unchanged" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    client.buffer_limits.outbound_ciphertext = .{
        .low = 1,
        .high = PureZigRecordStream.handshake_output_reserve,
        .hard = PureZigRecordStream.handshake_output_reserve,
    };
    client.outbound_ciphertext.len = PureZigRecordStream.handshake_output_reserve - 1;
    const before_seq = client.bridge.write_application.?.sequence;
    const before_len = client.outbound_ciphertext.len;
    try testing.expect(!client.stream().readiness().can_write_plaintext);
    try testing.expect(!client.stream().readiness().can_write_plaintext);
    try testing.expectEqual(@as(u64, 0), client.stream().bufferSnapshot().counters.hard_limits.outbound_ciphertext);
    try testing.expectError(error.WouldBlock, client.stream().write("no-mutate"));
    try testing.expectEqual(before_seq, client.bridge.write_application.?.sequence);
    try testing.expectEqual(before_len, client.outbound_ciphertext.len);

    const snapshot = client.stream().bufferSnapshot();
    try testing.expectEqual(@as(u64, 1), snapshot.counters.hard_limits.outbound_ciphertext);
}

test "capacity probes do not increment hard-limit counters while output is stalled" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();

    client.buffer_limits.outbound_ciphertext = .{
        .low = 1,
        .high = PureZigRecordStream.handshake_output_reserve,
        .hard = PureZigRecordStream.handshake_output_reserve,
    };
    client.outbound_ciphertext.len = PureZigRecordStream.handshake_output_reserve - 1;

    for (0..3) |_| {
        try testing.expect(!client.canReserveHandshakeOutputBatch());
        try testing.expectEqual(@as(u64, 0), client.stream().bufferSnapshot().counters.hard_limits.outbound_ciphertext);
    }

    try testing.expectError(error.WouldBlock, client.applyEvent(.{ .handshake_bytes = .{ .epoch = .initial, .data = "blocked" } }));
    try testing.expectEqual(@as(u64, 1), client.stream().bufferSnapshot().counters.hard_limits.outbound_ciphertext);
}

test "handshake buffer backpressure is independent of application plaintext" {
    const cp = testProvider();
    var client = try PureZigRecordStream.initWithLimits(.client, cp, .tls_aes_128_gcm_sha256, testBufferLimits());
    defer client.deinit();
    var server = try PureZigRecordStream.initWithLimits(.server, cp, .tls_aes_128_gcm_sha256, testBufferLimits());
    defer server.deinit();

    try client.applyEvent(.{ .handshake_bytes = .{ .epoch = .initial, .data = "handshake!" } });
    _ = try pumpHandshake(&client, &server, .initial, record_codec.max_ciphertext_record_len);

    var snapshot = server.stream().bufferSnapshot();
    try testing.expectEqual(@as(usize, 0), snapshot.current.inbound_plaintext);
    try testing.expect(snapshot.current.handshake >= snapshot.limits.?.handshake.high);
    try testing.expect(snapshot.pause_state.inbound_read_paused);

    var handshake_buf: [32]u8 = undefined;
    const n = try server.readHandshake(handshake_buf[0..6]);
    try testing.expectEqual(@as(usize, 6), n);
    snapshot = server.stream().bufferSnapshot();
    try testing.expect(snapshot.current.handshake <= snapshot.limits.?.handshake.low);
    try testing.expect(!snapshot.pause_state.inbound_read_paused);
}

test "buffer snapshot totals peaks and teardown current bytes are accurate" {
    const cp = testProvider();
    var client = try PureZigRecordStream.initWithLimits(.client, cp, .tls_aes_128_gcm_sha256, testBufferLimits());
    var server = try PureZigRecordStream.initWithLimits(.server, cp, .tls_aes_128_gcm_sha256, testBufferLimits());
    defer server.deinit();
    try establish(&client, &server);

    _ = try client.stream().write("snapshot");
    var snapshot = client.stream().bufferSnapshot();
    try testing.expect(snapshot.current.outbound_ciphertext > 0);
    try testing.expectEqual(snapshot.current.total(), snapshot.current.inbound_ciphertext + snapshot.current.inbound_plaintext + snapshot.current.outbound_ciphertext + snapshot.current.handshake);
    try testing.expect(snapshot.peak.outbound_ciphertext >= snapshot.current.outbound_ciphertext);
    try testing.expect(snapshot.peak_total >= snapshot.current.total());

    client.deinit();
    snapshot = client.stream().bufferSnapshot();
    try testing.expectEqual(@as(usize, 0), snapshot.current.total());
    try testing.expect(snapshot.peak_total > 0);
}

test "byte queues wipe discarded and cleared storage" {
    var queue = ByteQueue(16, error.PlaintextBufferFull){};

    try queue.append("secret");
    try queue.discard(3);
    try testing.expectEqualStrings("ret", queue.slice());
    try testing.expect(std.mem.allEqual(u8, queue.buf[3..6], 0));

    queue.clear();
    try testing.expectEqual(@as(usize, 0), queue.len);
    try testing.expect(std.mem.allEqual(u8, queue.buf[0..], 0));
}

test "terminal cleanup clears parser-owned ciphertext and queued plaintext" {
    const cp = testProvider();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);

    @memcpy(server.initial_parser.pending[0.."initial-secret".len], "initial-secret");
    server.initial_parser.len = "initial-secret".len;
    @memcpy(server.ciphertext_parser.pending[0.."cipher-secret".len], "cipher-secret");
    server.ciphertext_parser.len = "cipher-secret".len;
    try server.inbound_plaintext.append("plain-secret");
    server.noteQueueMutation();

    try testing.expect(server.stream().bufferSnapshot().current.total() > 0);
    server.deinit();

    const snapshot = server.stream().bufferSnapshot();
    try testing.expectEqual(@as(usize, 0), snapshot.current.total());
    try testing.expectEqual(@as(usize, 0), server.initial_parser.len);
    try testing.expectEqual(@as(usize, 0), server.ciphertext_parser.len);
    try testing.expectEqual(@as(usize, 0), server.inbound_plaintext.len);
    try testing.expect(std.mem.indexOf(u8, server.initial_parser.pending[0..], "initial-secret") == null);
    try testing.expect(std.mem.indexOf(u8, server.ciphertext_parser.pending[0..], "cipher-secret") == null);
    try testing.expect(std.mem.indexOf(u8, server.inbound_plaintext.buf[0..], "plain-secret") == null);
}

test "encrypted stream coalesced record backpressure consumes only retry-safe records" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    var coalesced: [record_codec.max_ciphertext_record_len * 2]u8 = undefined;
    try testing.expectEqual(@as(usize, 3), try client.stream().write("one"));
    const first_len = try client.drainCiphertext(coalesced[0..record_codec.max_ciphertext_record_len]);
    try testing.expectEqual(@as(usize, 3), try client.stream().write("two"));
    const second_len = try client.drainCiphertext(coalesced[first_len..]);
    const total_len = first_len + second_len;

    server.inbound_plaintext.len = PureZigRecordStream.max_plaintext_queue - record_codec.max_plaintext_fragment_len;
    const read_seq = server.bridge.read_application.?.sequence;
    const consumed = try server.feedCiphertext(coalesced[0..total_len]);
    try testing.expectEqual(first_len, consumed);
    try testing.expectEqual(read_seq + 1, server.bridge.read_application.?.sequence);
    try testing.expectEqual(second_len, try server.feedCiphertext(coalesced[consumed..total_len]));
    try testing.expectEqual(read_seq + 2, server.bridge.read_application.?.sequence);
}

test "encrypted stream callers preserve partial feed suffixes across record boundaries" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    var coalesced: [record_codec.max_ciphertext_record_len * 2]u8 = undefined;
    try testing.expectEqual(@as(usize, 5), try client.stream().write("first"));
    const first_len = try client.drainCiphertext(coalesced[0..record_codec.max_ciphertext_record_len]);
    try testing.expectEqual(@as(usize, 6), try client.stream().write("second"));
    const second_len = try client.drainCiphertext(coalesced[first_len..]);

    const boundary_split = first_len + 2;
    try feedAllCiphertext(&server, coalesced[0..boundary_split]);
    try feedAllCiphertext(&server, coalesced[boundary_split .. first_len + second_len]);

    var plain: [16]u8 = undefined;
    const first_read = try server.stream().read(plain[0..5]);
    try testing.expectEqualStrings("first", plain[0..first_read]);
    const second_read = try server.stream().read(&plain);
    try testing.expectEqualStrings("second", plain[0..second_read]);
}

test "pure Zig encrypted stream exchanges application data over nonblocking socketpair carrier" {
    const fds = try testSocketPair();
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
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

test "encrypted stream drive retains ciphertext across partial carrier writes" {
    const MemoryCarrier = struct {
        written: ByteQueue(256, error.CiphertextBufferFull) = .{},
        max_write: usize = 3,

        fn carrier(self: *@This()) Carrier {
            return .{ .ptr = self, .readFn = read, .writeFn = write };
        }

        fn read(_: *anyopaque, _: []u8) Error!usize {
            return error.WouldBlock;
        }

        fn write(ptr: *anyopaque, bytes: []const u8) Error!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            const n = @min(bytes.len, self.max_write);
            if (n == 0) return error.WouldBlock;
            try self.written.append(bytes[0..n]);
            return n;
        }
    };

    const cp = testProvider();
    var carrier = MemoryCarrier{};
    var stream_state = PureZigRecordStream.initWithCarrier(.client, cp, .tls_aes_128_gcm_sha256, carrier.carrier());
    defer stream_state.deinit();
    var peer = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer peer.deinit();
    try establish(&stream_state, &peer);

    _ = try stream_state.stream().write("partial write");
    const initial = stream_state.queuedCiphertextLen();
    const first = try stream_state.stream().drive();
    try testing.expect(first.made_progress);
    try testing.expectEqual(initial, carrier.written.len + stream_state.queuedCiphertextLen());
    try testing.expect(carrier.written.len >= carrier.max_write);

    if (stream_state.queuedCiphertextLen() == 0) return;

    try testing.expectEqual(initial - carrier.written.len, stream_state.queuedCiphertextLen());

    const after_first = carrier.written.len;
    const second = try stream_state.stream().drive();
    try testing.expect(second.made_progress);
    try testing.expect(carrier.written.len > after_first);
    try testing.expectEqual(initial - carrier.written.len, stream_state.queuedCiphertextLen());
}

test "encrypted stream drive routes pre-application carrier records by epoch" {
    const SourceCarrier = struct {
        bytes: []const u8,
        offset: usize = 0,

        fn carrier(self: *@This()) Carrier {
            return .{ .ptr = self, .readFn = read, .writeFn = write };
        }

        fn read(ptr: *anyopaque, out: []u8) Error!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (self.offset == self.bytes.len) return error.WouldBlock;
            const n = @min(out.len, self.bytes.len - self.offset);
            @memcpy(out[0..n], self.bytes[self.offset..][0..n]);
            self.offset += n;
            return n;
        }

        fn write(_: *anyopaque, _: []const u8) Error!usize {
            return error.WouldBlock;
        }
    };

    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();

    try client.applyEvent(.{ .handshake_bytes = .{ .epoch = .initial, .data = "client hello" } });
    var initial_record: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const initial_len = try client.drainCiphertext(&initial_record);
    var initial_source = SourceCarrier{ .bytes = initial_record[0..initial_len] };
    server.carrier = initial_source.carrier();
    while (initial_source.offset < initial_source.bytes.len) {
        const result = try server.stream().drive();
        try testing.expect(result.made_progress);
    }

    var handshake_buf: [64]u8 = undefined;
    const initial_read = try server.readHandshake(&handshake_buf);
    try testing.expectEqualStrings("client hello", handshake_buf[0..initial_read]);

    const client_hs = secret(0x11);
    try client.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .write, .data = &client_hs } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .read, .data = &client_hs } });
    try client.applyEvent(.{ .handshake_bytes = .{ .epoch = .handshake, .data = "finished" } });
    var handshake_record: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const handshake_len = try client.drainCiphertext(&handshake_record);
    var handshake_source = SourceCarrier{ .bytes = handshake_record[0..handshake_len] };
    server.carrier = handshake_source.carrier();
    while (handshake_source.offset < handshake_source.bytes.len) {
        const result = try server.stream().drive();
        try testing.expect(result.made_progress);
    }

    const handshake_read = try server.readHandshake(&handshake_buf);
    try testing.expectEqualStrings("finished", handshake_buf[0..handshake_read]);
}

test "encrypted stream drive treats EOF without close_notify as truncation" {
    const EofCarrier = struct {
        fn carrier(self: *@This()) Carrier {
            return .{ .ptr = self, .readFn = read, .writeFn = write };
        }

        fn read(_: *anyopaque, _: []u8) Error!usize {
            return 0;
        }

        fn write(_: *anyopaque, _: []const u8) Error!usize {
            return error.WouldBlock;
        }
    };

    const cp = testProvider();
    var carrier = EofCarrier{};
    var stream_state = PureZigRecordStream.initWithCarrier(.client, cp, .tls_aes_128_gcm_sha256, carrier.carrier());
    defer stream_state.deinit();

    try testing.expectError(error.TruncatedStream, stream_state.stream().drive());
    try testing.expectEqual(Lifecycle.failed, stream_state.lifecycle);

    var buf: [8]u8 = undefined;
    try testing.expectError(error.TruncatedStream, stream_state.stream().read(&buf));
}

test "encrypted stream accepts EOF after close_notify" {
    const cp = testProvider();
    var stream_state = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer stream_state.deinit();
    var peer = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer peer.deinit();
    try establish(&stream_state, &peer);

    var alert_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const close_notify = try peer.bridge.sealProtected(.application, .alert, &.{ 1, 0 }, &alert_buf);
    try feedAllCiphertext(&stream_state, close_notify);
    try stream_state.markPeerEof();
    try testing.expect(stream_state.stream().readiness().peer_closed);

    var buf: [8]u8 = undefined;
    try testing.expectError(error.EndOfStream, stream_state.stream().read(&buf));
}

test "encrypted stream preserves caller-fed plaintext before deferred truncation" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    try testing.expectEqual(@as(usize, "authenticated".len), try server.stream().write("authenticated"));
    var record: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const record_len = try server.drainCiphertext(&record);
    try feedAllCiphertext(&client, record[0..record_len]);

    try client.markPeerEof();
    const pending = client.stream().readiness();
    try testing.expect(pending.can_read_plaintext);
    try testing.expect(!pending.can_write_plaintext);
    try testing.expectError(error.TruncatedStream, client.stream().write("after EOF"));

    var plaintext: [32]u8 = undefined;
    const read = try client.stream().read(&plaintext);
    try testing.expectEqualStrings("authenticated", plaintext[0..read]);
    const drained = client.stream().readiness();
    try testing.expect(drained.can_read_plaintext);
    try testing.expect(!drained.can_write_plaintext);
    try testing.expectError(error.TruncatedStream, client.stream().read(&plaintext));
    try testing.expectEqual(Lifecycle.failed, client.lifecycle);
}

test "encrypted stream carrier EOF exposes deferred truncation after plaintext read" {
    const SourceThenEofCarrier = struct {
        bytes: []const u8,
        offset: usize = 0,

        fn carrier(self: *@This()) Carrier {
            return .{ .ptr = self, .readFn = read, .writeFn = write };
        }

        fn read(ptr: *anyopaque, out: []u8) Error!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (self.offset == self.bytes.len) return 0;
            const n = @min(out.len, self.bytes.len - self.offset);
            @memcpy(out[0..n], self.bytes[self.offset..][0..n]);
            self.offset += n;
            return n;
        }

        fn write(_: *anyopaque, _: []const u8) Error!usize {
            return error.WouldBlock;
        }
    };

    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    try testing.expectEqual(@as(usize, "carrier-data".len), try server.stream().write("carrier-data"));
    var record: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const record_len = try server.drainCiphertext(&record);
    var carrier = SourceThenEofCarrier{ .bytes = record[0..record_len] };
    client.carrier = carrier.carrier();

    const result = try client.stream().drive();
    try testing.expect(result.made_progress);
    try testing.expect(result.readiness.can_read_plaintext);
    try testing.expect(!result.readiness.peer_closed);

    var plaintext: [32]u8 = undefined;
    const read = try client.stream().read(&plaintext);
    try testing.expectEqualStrings("carrier-data", plaintext[0..read]);
    const drained = client.stream().readiness();
    try testing.expect(drained.can_read_plaintext);
    try testing.expect(!drained.can_write_plaintext);
    try testing.expectError(error.TruncatedStream, client.stream().write("after EOF"));
    try testing.expectError(error.TruncatedStream, client.stream().read(&plaintext));
    try testing.expectEqual(Lifecycle.failed, client.lifecycle);
}

test "encrypted stream preserves record budget after EOF before truncation decision" {
    const SourceThenEofCarrier = struct {
        bytes: []const u8,
        offset: usize = 0,

        fn carrier(self: *@This()) Carrier {
            return .{ .ptr = self, .readFn = read, .writeFn = write };
        }

        fn read(ptr: *anyopaque, out: []u8) Error!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (self.offset == self.bytes.len) return 0;
            const n = @min(out.len, self.bytes.len - self.offset);
            @memcpy(out[0..n], self.bytes[self.offset..][0..n]);
            self.offset += n;
            return n;
        }

        fn write(_: *anyopaque, _: []const u8) Error!usize {
            return error.WouldBlock;
        }
    };

    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    var records: [4096]u8 = undefined;
    var len: usize = 0;
    for (0..17) |i| {
        var plaintext: [1]u8 = .{@intCast('a' + i)};
        try testing.expectEqual(@as(usize, 1), try server.stream().write(&plaintext));
        len += try server.drainCiphertext(records[len..]);
    }
    var alert_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const close_notify = try server.bridge.sealProtected(.application, .alert, &.{ 1, 0 }, &alert_buf);
    @memcpy(records[len..][0..close_notify.len], close_notify);
    len += close_notify.len;

    var carrier = SourceThenEofCarrier{ .bytes = records[0..len] };
    client.carrier = carrier.carrier();

    const first = try client.stream().drive();
    try testing.expect(first.made_progress);
    try testing.expect(!first.readiness.peer_closed);
    try testing.expectEqual(@as(usize, len), carrier.offset);

    const second = try client.stream().drive();
    try testing.expect(second.made_progress);
    try testing.expect(!second.readiness.peer_closed);

    const third = try client.stream().drive();
    try testing.expect(third.made_progress);
    try testing.expect(third.readiness.peer_closed);

    var plaintext: [32]u8 = undefined;
    const read = try client.stream().read(&plaintext);
    try testing.expectEqualStrings("abcdefghijklmnopq", plaintext[0..read]);
    try testing.expectError(error.EndOfStream, client.stream().read(&plaintext));
}

test "encrypted stream fatal and malformed alerts latch terminal failure" {
    const cp = testProvider();
    inline for (.{
        .{ .payload = &.{ 2, @intFromEnum(alerts.AlertDescription.unexpected_message) }, .expected = error.PeerFatalAlert },
        .{ .payload = &.{ 1, @intFromEnum(alerts.AlertDescription.unexpected_message) }, .expected = error.PeerFatalAlert },
        .{ .payload = &.{1}, .expected = error.MalformedAlert },
        .{ .payload = &.{ 2, 0xff }, .expected = error.PeerFatalAlert },
    }) |case| {
        var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
        defer client.deinit();
        var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
        defer server.deinit();
        try establish(&client, &server);

        var alert_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
        const alert_record = try server.bridge.sealProtected(.application, .alert, case.payload, &alert_buf);
        try testing.expectError(case.expected, feedAllCiphertext(&client, alert_record));
        try testing.expectEqual(Lifecycle.failed, client.lifecycle);
        try expectLatchedFailureConformance(client.stream(), case.expected);
    }
}

test "encrypted stream treats close_notify as close regardless of alert level" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    var alert_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const close_notify = try server.bridge.sealProtected(.application, .alert, &.{ 2, @intFromEnum(alerts.AlertDescription.close_notify) }, &alert_buf);
    try feedAllCiphertext(&client, close_notify);

    var buf: [8]u8 = undefined;
    try testing.expectError(error.EndOfStream, client.stream().read(&buf));
}

test "encrypted stream treats user_canceled as non-fatal warning alert" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    var alert_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const user_canceled = try server.bridge.sealProtected(.application, .alert, &.{ 1, @intFromEnum(alerts.AlertDescription.user_canceled) }, &alert_buf);
    try feedAllCiphertext(&client, user_canceled);
    try testing.expect(!client.readiness().peer_closed);

    var buf: [8]u8 = undefined;
    try testing.expectError(error.WouldBlock, client.stream().read(&buf));
}

test "encrypted stream routes handshake epoch alerts through alert handling" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();

    const server_hs = secret(0x22);
    try client.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .read, .data = &server_hs } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .write, .data = &server_hs } });

    var alert_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const fatal_alert = try server.bridge.sealProtected(.handshake, .alert, &.{ 2, @intFromEnum(alerts.AlertDescription.unexpected_message) }, &alert_buf);
    try testing.expectError(error.PeerFatalAlert, feedAllHandshake(&client, .handshake, fatal_alert));
    try testing.expectEqual(Lifecycle.failed, client.lifecycle);
    try expectLatchedFailureConformance(client.stream(), error.PeerFatalAlert);
}

test "encrypted stream routes initial plaintext alerts through alert handling" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();

    var alert_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const alert_record = try record_codec.encodePlaintextRecord(.alert, &.{ 2, @intFromEnum(alerts.AlertDescription.protocol_version) }, &alert_buf);
    try testing.expectError(error.PeerFatalAlert, feedAllHandshake(&client, .initial, alert_record));
    try testing.expectEqual(Lifecycle.failed, client.lifecycle);
    try expectLatchedFailureConformance(client.stream(), error.PeerFatalAlert);
}

test "encrypted stream duplicate close_notify and data after close are ignored" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    var close_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const close_notify = try server.bridge.sealProtected(.application, .alert, &.{ 1, 0 }, &close_buf);
    try feedAllCiphertext(&client, close_notify);
    try testing.expect(client.readiness().peer_closed);

    var second_close_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const second_close = try server.bridge.sealProtected(.application, .alert, &.{ 1, 0 }, &second_close_buf);
    try feedAllCiphertext(&client, second_close);

    try testing.expectEqual(@as(usize, "ignored".len), try server.stream().write("ignored"));
    var app_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const app_len = try server.drainCiphertext(&app_buf);
    try feedAllCiphertext(&client, app_buf[0..app_len]);

    var buf: [16]u8 = undefined;
    try testing.expectError(error.EndOfStream, client.stream().read(&buf));
}

test "encrypted stream keeps write side open after peer close_notify" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    var client_close_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const client_close = try client.bridge.sealProtected(.application, .alert, &.{ 1, 0 }, &client_close_buf);
    try feedAllCiphertext(&server, client_close);

    var scratch: [8]u8 = undefined;
    try testing.expectError(error.EndOfStream, server.stream().read(&scratch));
    const one_sided = server.stream().readiness();
    try testing.expect(one_sided.peer_closed);
    try testing.expect(one_sided.can_write_plaintext);

    const final_payload = "server-final";
    try testing.expectEqual(@as(usize, final_payload.len), try server.stream().write(final_payload));
    _ = try pumpCiphertext(&server, &client, 7);
    var client_plaintext: [final_payload.len]u8 = undefined;
    const client_read = try client.stream().read(&client_plaintext);
    try testing.expectEqualStrings(final_payload, client_plaintext[0..client_read]);

    server.stream().close();
    _ = try server.stream().drive();
    var server_close: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const close_len = try server.drainCiphertext(&server_close);
    try feedAllCiphertext(&client, server_close[0..close_len]);
    try testing.expectError(error.EndOfStream, client.stream().read(&scratch));
}

test "encrypted stream close sends close_notify before closing owned carrier" {
    const ClosingCarrier = struct {
        written: ByteQueue(record_codec.max_ciphertext_record_len, error.CiphertextBufferFull) = .{},
        max_write: usize = 3,
        closed: bool = false,

        fn carrier(self: *@This()) Carrier {
            return .{ .ptr = self, .readFn = read, .writeFn = write, .closeFn = close, .owns_handle = true };
        }

        fn read(_: *anyopaque, _: []u8) Error!usize {
            return error.WouldBlock;
        }

        fn write(ptr: *anyopaque, bytes: []const u8) Error!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            const n = @min(bytes.len, self.max_write);
            if (n == 0) return error.WouldBlock;
            try self.written.append(bytes[0..n]);
            return n;
        }

        fn close(ptr: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.closed = true;
        }
    };

    const cp = testProvider();
    var carrier = ClosingCarrier{};
    var stream_state = PureZigRecordStream.initWithCarrier(.client, cp, .tls_aes_128_gcm_sha256, carrier.carrier());
    defer stream_state.deinit();
    var peer = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer peer.deinit();
    try establish(&stream_state, &peer);

    stream_state.stream().close();
    var iterations: usize = 0;
    while (stream_state.lifecycle != .closed and iterations < record_codec.max_ciphertext_record_len) : (iterations += 1) {
        _ = try stream_state.stream().drive();
    }
    try testing.expectEqual(Lifecycle.closed, stream_state.lifecycle);
    try testing.expect(carrier.closed);
    try testing.expect(carrier.written.len > 0);
    try expectClosedConformance(stream_state.stream());

    try feedAllCiphertext(&peer, carrier.written.slice());
    var buf: [8]u8 = undefined;
    try testing.expectError(error.EndOfStream, peer.stream().read(&buf));
}

test "encrypted stream close during handshake releases owned carrier once" {
    const CountingCarrier = struct {
        close_count: usize = 0,

        fn carrier(self: *@This()) Carrier {
            return .{ .ptr = self, .readFn = read, .writeFn = write, .closeFn = close, .owns_handle = true };
        }

        fn read(_: *anyopaque, _: []u8) Error!usize {
            return error.WouldBlock;
        }

        fn write(_: *anyopaque, _: []const u8) Error!usize {
            return error.WouldBlock;
        }

        fn close(ptr: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.close_count += 1;
        }
    };

    const cp = testProvider();
    var carrier = CountingCarrier{};
    var stream_state = PureZigRecordStream.initWithCarrier(.client, cp, .tls_aes_128_gcm_sha256, carrier.carrier());

    stream_state.stream().close();
    const result = try stream_state.stream().drive();
    try testing.expect(result.made_progress);
    try testing.expectEqual(Lifecycle.closed, stream_state.lifecycle);
    try testing.expectEqual(@as(usize, 1), carrier.close_count);

    stream_state.deinit();
    try testing.expectEqual(@as(usize, 1), carrier.close_count);
}

test "encrypted stream close during handshake drops queued output before closing owned carrier" {
    const BlockingCarrier = struct {
        close_count: usize = 0,

        fn carrier(self: *@This()) Carrier {
            return .{ .ptr = self, .readFn = read, .writeFn = write, .closeFn = close, .owns_handle = true };
        }

        fn read(_: *anyopaque, _: []u8) Error!usize {
            return error.WouldBlock;
        }

        fn write(_: *anyopaque, _: []const u8) Error!usize {
            return error.WouldBlock;
        }

        fn close(ptr: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.close_count += 1;
        }
    };

    const cp = testProvider();
    var carrier = BlockingCarrier{};
    var stream_state = PureZigRecordStream.initWithCarrier(.client, cp, .tls_aes_128_gcm_sha256, carrier.carrier());

    try stream_state.applyEvent(.{ .handshake_bytes = .{ .epoch = .initial, .data = "queued client hello" } });
    try testing.expect(stream_state.queuedCiphertextLen() > 0);

    stream_state.stream().close();
    const result = try stream_state.stream().drive();
    try testing.expect(result.made_progress);
    try testing.expectEqual(Lifecycle.closed, stream_state.lifecycle);
    try testing.expectEqual(@as(usize, 0), stream_state.queuedCiphertextLen());
    try testing.expectEqual(@as(usize, 1), carrier.close_count);

    stream_state.deinit();
    try testing.expectEqual(@as(usize, 1), carrier.close_count);
}

test "encrypted stream close during handshake does not write queued output" {
    const WritableCarrier = struct {
        written: usize = 0,
        close_count: usize = 0,

        fn carrier(self: *@This()) Carrier {
            return .{ .ptr = self, .readFn = read, .writeFn = write, .closeFn = close, .owns_handle = true };
        }

        fn read(_: *anyopaque, _: []u8) Error!usize {
            return error.WouldBlock;
        }

        fn write(ptr: *anyopaque, bytes: []const u8) Error!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.written += bytes.len;
            return bytes.len;
        }

        fn close(ptr: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.close_count += 1;
        }
    };

    const cp = testProvider();
    var carrier = WritableCarrier{};
    var stream_state = PureZigRecordStream.initWithCarrier(.client, cp, .tls_aes_128_gcm_sha256, carrier.carrier());

    try stream_state.applyEvent(.{ .handshake_bytes = .{ .epoch = .initial, .data = "queued client hello" } });
    try testing.expect(stream_state.queuedCiphertextLen() > 0);

    stream_state.stream().close();
    const result = try stream_state.stream().drive();
    try testing.expect(result.made_progress);
    try testing.expectEqual(Lifecycle.closed, stream_state.lifecycle);
    try testing.expectEqual(@as(usize, 0), stream_state.queuedCiphertextLen());
    try testing.expectEqual(@as(usize, 0), carrier.written);
    try testing.expectEqual(@as(usize, 1), carrier.close_count);

    stream_state.deinit();
    try testing.expectEqual(@as(usize, 1), carrier.close_count);
}

test "encrypted stream close flushes queued app data before close_notify" {
    const ClosingCarrier = struct {
        written: ByteQueue(2 * record_codec.max_ciphertext_record_len, error.CiphertextBufferFull) = .{},
        max_write: usize,
        closed: bool = false,

        fn carrier(self: *@This()) Carrier {
            return .{ .ptr = self, .readFn = read, .writeFn = write, .closeFn = close, .owns_handle = true };
        }

        fn read(_: *anyopaque, _: []u8) Error!usize {
            return error.WouldBlock;
        }

        fn write(ptr: *anyopaque, bytes: []const u8) Error!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            const n = @min(bytes.len, self.max_write);
            if (n == 0) return error.WouldBlock;
            try self.written.append(bytes[0..n]);
            return n;
        }

        fn close(ptr: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.closed = true;
        }
    };

    const cp = testProvider();
    inline for (.{ record_codec.max_ciphertext_record_len, 3 }) |max_write| {
        var carrier = ClosingCarrier{ .max_write = max_write };
        var stream_state = PureZigRecordStream.initWithCarrier(.client, cp, .tls_aes_128_gcm_sha256, carrier.carrier());
        defer stream_state.deinit();
        var peer = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
        defer peer.deinit();
        try establish(&stream_state, &peer);

        try testing.expectEqual(@as(usize, "queued app".len), try stream_state.stream().write("queued app"));
        stream_state.stream().close();
        var iterations: usize = 0;
        while (stream_state.lifecycle != .closed and iterations < record_codec.max_ciphertext_record_len) : (iterations += 1) {
            _ = try stream_state.stream().drive();
        }
        try testing.expectEqual(Lifecycle.closed, stream_state.lifecycle);
        try testing.expect(carrier.closed);

        try feedAllCiphertext(&peer, carrier.written.slice());
        var plain: [32]u8 = undefined;
        const got = try peer.stream().read(&plain);
        try testing.expectEqualStrings("queued app", plain[0..got]);
        try testing.expectError(error.EndOfStream, peer.stream().read(&plain));
    }
}

test "encrypted stream manual close drains one close_notify and becomes closed" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    client.stream().close();
    const queued = try client.stream().drive();
    try testing.expect(queued.made_progress);
    try testing.expect(client.queuedCiphertextLen() > 0);

    var close_notify: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const n = try client.drainCiphertext(&close_notify);
    try feedAllCiphertext(&server, close_notify[0..n]);
    _ = try client.stream().drive();
    try testing.expectEqual(Lifecycle.closed, client.lifecycle);
    try testing.expectEqual(@as(usize, 0), client.queuedCiphertextLen());

    var buf: [8]u8 = undefined;
    try testing.expectError(error.EndOfStream, server.stream().read(&buf));
}

test "encrypted stream fatal parser errors latch and close owned carrier" {
    const ClosingCarrier = struct {
        closed: bool = false,

        fn carrier(self: *@This()) Carrier {
            return .{ .ptr = self, .readFn = read, .writeFn = write, .closeFn = close, .owns_handle = true };
        }

        fn read(_: *anyopaque, _: []u8) Error!usize {
            return error.WouldBlock;
        }

        fn write(_: *anyopaque, _: []const u8) Error!usize {
            return error.WouldBlock;
        }

        fn close(ptr: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.closed = true;
        }
    };

    const cp = testProvider();
    var carrier = ClosingCarrier{};
    var stream_state = PureZigRecordStream.initWithCarrier(.client, cp, .tls_aes_128_gcm_sha256, carrier.carrier());
    defer stream_state.deinit();

    try testing.expectError(error.InvalidRecordType, stream_state.feedCiphertext(&.{ 0xff, 0x03, 0x03, 0x00, 0x00 }));
    try testing.expectEqual(Lifecycle.failed, stream_state.lifecycle);
    try testing.expect(carrier.closed);
    try expectLatchedFailureConformance(stream_state.stream(), error.InvalidRecordType);
}

test "encrypted stream fatal failure clears queued handshake and ciphertext helpers" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();

    try client.applyEvent(.{ .handshake_bytes = .{ .epoch = .initial, .data = "queued hello" } });
    var initial_record: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const initial_len = try client.drainCiphertext(&initial_record);
    try feedAllHandshake(&server, .initial, initial_record[0..initial_len]);
    try server.applyEvent(.{ .handshake_bytes = .{ .epoch = .initial, .data = "queued response" } });
    try testing.expect(server.queuedCiphertextLen() > 0);

    try testing.expectEqual(error.InvalidRecordType, server.fail(error.InvalidRecordType));
    try testing.expectEqual(Lifecycle.failed, server.lifecycle);

    var buf: [64]u8 = undefined;
    try testing.expectError(error.InvalidRecordType, server.readHandshake(&buf));
    try testing.expectError(error.InvalidRecordType, server.drainCiphertext(&buf));
    try testing.expectEqual(@as(usize, 0), server.peekCiphertext().len);
}

test "encrypted stream authentication failures latch and close owned carrier" {
    const ClosingCarrier = struct {
        closed: bool = false,

        fn carrier(self: *@This()) Carrier {
            return .{ .ptr = self, .readFn = read, .writeFn = write, .closeFn = close, .owns_handle = true };
        }

        fn read(_: *anyopaque, _: []u8) Error!usize {
            return error.WouldBlock;
        }

        fn write(_: *anyopaque, _: []const u8) Error!usize {
            return error.WouldBlock;
        }

        fn close(ptr: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.closed = true;
        }
    };

    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    try testing.expectEqual(@as(usize, 6), try client.stream().write("cipher"));
    var record: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const record_len = try client.drainCiphertext(&record);
    record[record_len - 1] ^= 0xff;

    var carrier = ClosingCarrier{};
    server.carrier = carrier.carrier();
    try testing.expectError(error.AuthenticationFailed, server.feedCiphertext(record[0..record_len]));
    try testing.expectEqual(Lifecycle.failed, server.lifecycle);
    try testing.expect(carrier.closed);
    try testing.expectError(error.AuthenticationFailed, server.stream().drive());
}

test "encrypted stream reports would-block and stable readiness without busy-loop progress" {
    const cp = testProvider();
    var stream_state = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
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

    stream_state.initial_parser.pending[0..5].* = .{ 22, 3, 3, 0, 2 };
    stream_state.initial_parser.len = 5;
    stream_state.inbound_handshake.len = PureZigRecordStream.max_handshake_queue - 1;
    stream_state.noteQueueMutation();
    try testing.expect(!stream.readiness().wants_read);
    const blocked = try stream.drive();
    try testing.expect(!blocked.made_progress);
    try testing.expect(!blocked.readiness.wants_read);
    stream_state.inbound_handshake.len = 0;
    stream_state.initial_parser.reset();
    stream_state.noteQueueMutation();

    const drive = try stream.drive();
    try testing.expect(!drive.made_progress);
    try testing.expectEqual(before, drive.readiness);
}

test "pending authentication empty poll suppresses read readiness and makes no progress" {
    const cp = testProvider();
    var duplex = Duplex{ .max_chunk = record_codec.max_ciphertext_record_len };
    try duplex.s2c.append("peer bytes waiting");
    var backend = ScriptedRecordBackend{ .role = .client, .auth_pending = true, .auth_pending_polls = 10 };
    var stream_state = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .client, cp, .tls_aes_128_gcm_sha256, duplex.clientCarrier(), backend.recordBackend());
    defer stream_state.deinit();
    stream_state.handshake_started = true;
    const stream = stream_state.stream();

    const before = stream.readiness();
    try testing.expect(!before.wants_read);
    try testing.expect(!before.wants_write);

    const driven = try stream.drive();
    try testing.expect(!driven.made_progress);
    try testing.expect(!driven.readiness.wants_read);
    try testing.expectEqual(@as(usize, 1), backend.auth_poll_count);
    try testing.expectEqual(@as(usize, "peer bytes waiting".len), duplex.s2c.len);

    backend.auth_pending = false;
    const ready = stream.readiness();
    try testing.expect(ready.wants_read);
}

test "pure-Zig encrypted stream satisfies shared open-idle conformance" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    try expectOpenIdleConformance(client.stream(), .pure_zig_record);
}

test "encrypted stream interface accepts vtable-shaped and pure-Zig backends" {
    // This remains a vtable shape smoke test; production backends run the
    // shared conformance helpers above and in the OpenSSL adapter tests.
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

        fn bufferSnapshot(ptr: *anyopaque) BufferSnapshot {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return .{
                .current = .{
                    .inbound_plaintext = self.inbound.len,
                    .outbound_ciphertext = self.outbound.len,
                },
                .peak = .{
                    .inbound_plaintext = self.inbound.len,
                    .outbound_ciphertext = self.outbound.len,
                },
                .peak_total = self.inbound.len + self.outbound.len,
                .pause_state = .{ .plaintext_write_paused = self.closed or self.outbound.available() == 0 },
                .accounting_boundary = .backend_opaque,
            };
        }

        const vtable = EncryptedStream.VTable{
            .backendFn = backend,
            .readFn = read,
            .writeFn = write,
            .closeFn = close,
            .readinessFn = readiness,
            .driveFn = drive,
            .bufferSnapshotFn = bufferSnapshot,
        };
    };

    var fake = FakeOpenSsl{};
    var streams = [_]EncryptedStream{fake.stream()};
    try testing.expectEqual(BackendKind.openssl, streams[0].backend());
    try testing.expectEqual(@as(usize, 4), try streams[0].write("ping"));
    streams[0].close();
    try testing.expect(!streams[0].readiness().can_write_plaintext);

    const cp = testProvider();
    var native = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer native.deinit();
    streams[0] = native.stream();
    try testing.expectEqual(BackendKind.pure_zig_record, streams[0].backend());
}

const MockHttpInterest = struct {
    register_read: bool,
    register_write: bool,
    accept_plaintext: bool,
    consume_plaintext: bool,
    read_paused: bool,
    write_paused: bool,
};

fn mockHttpInterest(stream: EncryptedStream) MockHttpInterest {
    const readiness = stream.readiness();
    const snapshot = stream.bufferSnapshot();
    return .{
        .register_read = readiness.wants_read,
        .register_write = readiness.wants_write,
        .accept_plaintext = readiness.can_write_plaintext,
        .consume_plaintext = readiness.can_read_plaintext,
        .read_paused = snapshot.pause_state.inbound_read_paused,
        .write_paused = snapshot.pause_state.plaintext_write_paused,
    };
}

test "backend-neutral mock HTTP consumer observes TLS backpressure without casts" {
    const FakePausedOpenSsl = struct {
        fn stream(self: *@This()) EncryptedStream {
            return .{ .ptr = self, .vtable = &vtable };
        }

        fn backend(_: *anyopaque) BackendKind {
            return .openssl;
        }

        fn read(_: *anyopaque, _: []u8) Error!usize {
            return error.WouldBlock;
        }

        fn write(_: *anyopaque, _: []const u8) Error!usize {
            return error.WouldBlock;
        }

        fn close(_: *anyopaque) void {}

        fn readiness(_: *anyopaque) Readiness {
            return .{ .wants_write = true };
        }

        fn drive(_: *anyopaque) Error!DriveResult {
            return .{ .made_progress = false, .readiness = .{ .wants_write = true } };
        }

        fn bufferSnapshot(_: *anyopaque) BufferSnapshot {
            return .{
                .pause_state = .{ .inbound_read_paused = true, .plaintext_write_paused = true },
                .accounting_boundary = .backend_opaque,
            };
        }

        const vtable = EncryptedStream.VTable{
            .backendFn = backend,
            .readFn = read,
            .writeFn = write,
            .closeFn = close,
            .readinessFn = readiness,
            .driveFn = drive,
            .bufferSnapshotFn = bufferSnapshot,
        };
    };

    const cp = testProvider();
    var native = try PureZigRecordStream.initWithLimits(.client, cp, .tls_aes_128_gcm_sha256, testBufferLimits());
    defer native.deinit();
    var peer = try PureZigRecordStream.initWithLimits(.server, cp, .tls_aes_128_gcm_sha256, testBufferLimits());
    defer peer.deinit();
    try establish(&native, &peer);

    while (native.stream().readiness().can_write_plaintext) {
        _ = try native.stream().write("pause-me");
    }
    const native_interest = mockHttpInterest(native.stream());
    try testing.expect(native_interest.register_read);
    try testing.expect(native_interest.register_write);
    try testing.expect(!native_interest.accept_plaintext);
    try testing.expect(!native_interest.consume_plaintext);
    try testing.expect(!native_interest.read_paused);
    try testing.expect(native_interest.write_paused);

    var fake = FakePausedOpenSsl{};
    const fake_interest = mockHttpInterest(fake.stream());
    try testing.expect(!fake_interest.register_read);
    try testing.expect(fake_interest.register_write);
    try testing.expect(!fake_interest.accept_plaintext);
    try testing.expect(!fake_interest.consume_plaintext);
    try testing.expect(fake_interest.read_paused);
    try testing.expect(fake_interest.write_paused);
    try testing.expectEqual(AccountingBoundary.backend_opaque, fake.stream().bufferSnapshot().accounting_boundary);
}

test "server-role stream accepts the 0x0301 ClientHello compatibility version once, client-role does not" {
    const cp = testProvider();

    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    // A real (unfragmented) ClientHello handshake message: msg_type=1, a
    // 3-byte big-endian length, then the body -- the compatibility window
    // tracks this length across records, so a payload without a real
    // length field would either falsely close or falsely hold the window
    // open.
    const client_hello_body = "client hello";
    var client_hello_message: [4 + client_hello_body.len]u8 = undefined;
    client_hello_message[0] = 1;
    client_hello_message[1] = 0;
    client_hello_message[2] = 0;
    client_hello_message[3] = client_hello_body.len;
    @memcpy(client_hello_message[4..], client_hello_body);

    var compat_client_hello: [64]u8 = undefined;
    const record = try record_codec.encodePlaintextRecord(.handshake, &client_hello_message, &compat_client_hello);
    compat_client_hello[1] = 0x03;
    compat_client_hello[2] = 0x01;
    const consumed = try server.feedHandshakeCiphertext(.initial, compat_client_hello[0..record.len]);
    try testing.expectEqual(record.len, consumed);
    var out: [32]u8 = undefined;
    const n = try server.readHandshake(&out);
    try testing.expectEqualSlices(u8, &client_hello_message, out[0..n]);

    // A second plaintext record on the same server stream must be strict.
    var strict_record: [64]u8 = undefined;
    const second = try record_codec.encodePlaintextRecord(.handshake, "second", &strict_record);
    strict_record[1] = 0x03;
    strict_record[2] = 0x01;
    try testing.expectError(error.InvalidRecordVersion, server.feedHandshakeCiphertext(.initial, strict_record[0..second.len]));

    // A client-role stream never accepts 0x0301, including on its first record.
    var client = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var compat_server_hello: [64]u8 = undefined;
    const third = try record_codec.encodePlaintextRecord(.handshake, "server hello", &compat_server_hello);
    compat_server_hello[1] = 0x03;
    compat_server_hello[2] = 0x01;
    try testing.expectError(error.InvalidRecordVersion, client.feedHandshakeCiphertext(.initial, compat_server_hello[0..third.len]));
}

test "middlebox-compat change_cipher_spec before any ClientHello is rejected, not silently dropped" {
    const cp = testProvider();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();

    // RFC 9846 §5's window opens only after the first ClientHello has been
    // sent or received. A server that has not accepted any handshake
    // message yet (`read_epoch`/`write_epoch` still `.initial`) must not
    // accept one just because the wire shape matches -- otherwise a peer
    // could smuggle this in as the very first bytes on the connection.
    try testing.expectError(error.UnexpectedRecordContent, server.feedHandshakeCiphertext(.initial, &.{ 20, 3, 3, 0, 1, 1 }));
}

test "middlebox-compat change_cipher_spec after ClientHello, before peer Finished, is dropped without disrupting the handshake" {
    const cp = testProvider();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();

    const client_hs = secret(0x51);
    const server_hs = secret(0x52);
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .read, .data = &client_hs } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .write, .data = &server_hs } });
    // `applyEvent` (unlike the real per-record driver path) does not itself
    // advance `read_epoch`/`write_epoch` as a side effect of installing a
    // secret, so set them directly: simulates the server already having
    // accepted a complete ClientHello (the actual message content and
    // driver plumbing, including the adversarial fragmented-ClientHello
    // case, is exercised in `tls13_backend_tests.zig`; this test isolates
    // the CCS acceptance-window check itself).
    server.read_epoch = .handshake;
    server.write_epoch = .handshake;

    // {0x14, 03, 03, 00, 01, 01}: an unprotected, single-byte compat CCS at
    // the handshake epoch -- RFC 9846 §5 requires this be dropped, not
    // opened through the bridge (it was never encrypted) or treated as a
    // handshake failure, inside its defined window.
    const consumed = try server.feedHandshakeCiphertext(.handshake, &.{ 20, 3, 3, 0, 1, 1 });
    try testing.expectEqual(@as(usize, 6), consumed);
    try testing.expectEqual(@as(?Error, null), server.failed);

    // The connection is still usable afterward: real handshake content at
    // the same epoch, sealed by an independent peer holding the matching
    // write key, still reaches `readHandshake` normally.
    var sender = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer sender.deinit();
    try sender.bridge.installTrafficSecret(.handshake, .write, &client_hs);
    var record_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const record = try sender.bridge.sealHandshake(.handshake, "hello", &record_buf);
    _ = try server.feedHandshakeCiphertext(.handshake, record);
    var out: [16]u8 = undefined;
    const n = try server.readHandshake(&out);
    try testing.expectEqualSlices(u8, "hello", out[0..n]);
}

test "middlebox-compat change_cipher_spec after peer Finished (handshake already complete) is rejected" {
    const cp = testProvider();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();

    const client_hs = secret(0x51);
    const server_hs = secret(0x52);
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .read, .data = &client_hs } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .write, .data = &server_hs } });
    server.read_epoch = .handshake;
    server.write_epoch = .handshake;
    // Simulates the handshake already having completed (peer's Finished
    // already received and processed) without exercising the full
    // application-key-installation precondition chain
    // `Bridge.markHandshakeComplete()` requires -- this test isolates the
    // CCS acceptance-window check's late-arrival boundary specifically.
    server.bridge.handshake_complete = true;

    try testing.expectError(error.UnexpectedRecordContent, server.feedHandshakeCiphertext(.handshake, &.{ 20, 3, 3, 0, 1, 1 }));
}

test "a malformed change_cipher_spec at the handshake epoch aborts instead of silently passing" {
    const cp = testProvider();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();

    const client_hs = secret(0x51);
    const server_hs = secret(0x52);
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .read, .data = &client_hs } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .write, .data = &server_hs } });
    server.read_epoch = .handshake;
    server.write_epoch = .handshake;

    // Same envelope, wrong payload byte (RFC 9846: "any other
    // change_cipher_spec value... MUST abort the handshake").
    try testing.expectError(error.UnexpectedRecordContent, server.feedHandshakeCiphertext(.handshake, &.{ 20, 3, 3, 0, 1, 0 }));
}

test "handshake epoch discard fails closed when ciphertext_parser still holds a partial record" {
    const cp = testProvider();
    var server = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();

    const client_hs = secret(0x51);
    const server_hs = secret(0x52);
    const client_app = secret(0x53);
    const server_app = secret(0x54);
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .read, .data = &client_hs } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .write, .data = &server_hs } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .read, .data = &client_app } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .write, .data = &server_app } });

    // A record header declaring 10 payload bytes, with only 3 delivered:
    // ciphertext_parser buffers it (feedOne's exact-consumption contract
    // means this can only be a genuinely incomplete record, never a
    // legitimate next-record suffix) and never completes it.
    _ = try server.feedHandshakeCiphertext(.handshake, &.{ 23, 3, 3, 0, 10, 1, 2, 3 });

    try testing.expectError(error.PartialRecordAtEpochTransition, server.applyEvent(.{ .discard_epoch = .handshake }));
    // The stream is latched failed with that same error afterward.
    try testing.expectError(error.PartialRecordAtEpochTransition, server.applyEvent(.handshake_complete));
}

// ── Driver-owned handshake progression (#410) ───────────────────────────────
//
// A deterministic scripted record backend that completes a compact handshake
// through the shared `engine.Driver` seam the stream now owns, so `drive()` can
// be proven end to end without fabricated secrets or hand-applied events. Both
// roles emit the *same* fixed secrets per direction, so the two bridges derive
// matching keys -- the record layer only opens what the peer really sealed. The
// production socket-pair proof with the real pure-Zig TLS engine lives in the
// `quic` module, where that backend is visible (#410, module layering).

const ScriptedRecordBackend = struct {
    role: tls_state.Role,
    /// Send a hello the server will reject, to drive the failure path.
    bad_hello: bool = false,
    /// Client-side adversarial knobs used to prove record-mode policy rather
    /// than trusting an injected backend's event stream.
    selected_alpn: ?[]const u8 = "h1",
    emit_certificate: bool = true,
    received_client_finished: bool = false,
    auth_pending: bool = false,
    auth_pending_polls: usize = 0,
    auth_poll_count: usize = 0,
    /// How many times the stream released this backend. `Driver.deinit` is not
    /// idempotent, so this must never exceed one.
    deinit_count: usize = 0,
    /// #359: the server's handshake-epoch Finished payload. Oversizing it is
    /// how a row makes the server put more on the wire than it agreed to.
    server_finished: []const u8 = "SF",
    /// #359: the negotiated `record_size_limit` state this scripted backend
    /// reports, standing in for a real handshake's advertisements.
    record_size_limits: record_size.Limits = .{},
    /// #359: what to report *after* the peer's handshake-epoch flight has been
    /// processed, standing in for a client learning the server's answer from
    /// EncryptedExtensions. Before that, `record_size_limits` is reported —
    /// which is the window in which the server's own flight has already been
    /// opened against the protocol maximum.
    record_size_limits_after_flight: ?record_size.Limits = null,
    handshake_flight_seen: bool = false,

    const hs_c2s = secret(0x11);
    const hs_s2c = secret(0x22);
    const app_c2s = secret(0x33);
    const app_s2c = secret(0x44);

    fn recordBackend(self: *ScriptedRecordBackend) RecordHandshakeBackend {
        return .{
            .ptr = self,
            .startFn = start,
            .receiveFn = receive,
            .authPendingFn = authPending,
            .resumeFn = resumeAuth,
            .deinitFn = backendDeinit,
            .recordSizeLimitsFn = recordSizeLimits,
        };
    }

    fn backendDeinit(ptr: *anyopaque) void {
        const self: *ScriptedRecordBackend = @ptrCast(@alignCast(ptr));
        self.deinit_count += 1;
    }

    fn recordSizeLimits(ptr: *anyopaque) record_size.Limits {
        const self: *ScriptedRecordBackend = @ptrCast(@alignCast(ptr));
        if (self.handshake_flight_seen) {
            if (self.record_size_limits_after_flight) |limits| return limits;
        }
        return self.record_size_limits;
    }

    fn start(ptr: *anyopaque, role: tls_state.Role, _: void, sink: *RecordTransport.EventSink) RecordHandshakeError!void {
        const self: *ScriptedRecordBackend = @ptrCast(@alignCast(ptr));
        std.debug.assert(self.role == role);
        if (role != .client) return; // server arms and waits for the client hello
        try sink.emitHandshakeBytes(.initial, if (self.bad_hello) "BAD" else "CH");
    }

    fn receive(ptr: *anyopaque, epoch: events.EncryptionEpoch, bytes: []const u8, sink: *RecordTransport.EventSink) RecordHandshakeError!void {
        const self: *ScriptedRecordBackend = @ptrCast(@alignCast(ptr));
        switch (self.role) {
            .server => {
                if (epoch == .initial and std.mem.eql(u8, bytes, "CH")) {
                    try sink.emitHandshakeBytes(.initial, "SH");
                    try sink.emitSecret(.handshake, .read, &hs_c2s);
                    try sink.emitSecret(.handshake, .write, &hs_s2c);
                    try sink.emitDiscardEpoch(.initial);
                    try sink.emitHandshakeBytes(.handshake, self.server_finished);
                    try sink.emitSecret(.application, .read, &app_c2s);
                    try sink.emitSecret(.application, .write, &app_s2c);
                } else if (epoch == .handshake and std.mem.eql(u8, bytes, "CF")) {
                    self.received_client_finished = true;
                    try sink.emitDiscardEpoch(.handshake);
                    try sink.emitHandshakeComplete();
                } else {
                    // Transport policy (#354): synthesize the fatal alert the
                    // peer must receive, then surface the terminal error. The
                    // driver's `receiveOutcome` keeps both observable together.
                    try sink.emitFatalAlert(.unexpected_message);
                    return error.UnexpectedHandshakeMessage;
                }
            },
            .client => {
                if (epoch == .initial and std.mem.eql(u8, bytes, "SH")) {
                    try sink.emitSecret(.handshake, .write, &hs_c2s);
                    try sink.emitSecret(.handshake, .read, &hs_s2c);
                    try sink.emitDiscardEpoch(.initial);
                    if (self.selected_alpn) |protocol| try sink.emitAlpn(protocol);
                    // #359: `startsWith` rather than `eql` so a row can make the
                    // server's Finished large enough to need one oversized
                    // record; "SF" alone still matches.
                } else if (epoch == .handshake and std.mem.startsWith(u8, bytes, "SF")) {
                    self.handshake_flight_seen = true;
                    try sink.emitSecret(.application, .write, &app_c2s);
                    try sink.emitSecret(.application, .read, &app_s2c);
                    // The secure record-stream default requires a client-side
                    // certificate decision before authenticated completion.
                    if (self.emit_certificate) try sink.emitCertificate(.valid);
                    try sink.emitHandshakeBytes(.handshake, "CF");
                    try sink.emitDiscardEpoch(.handshake);
                    try sink.emitHandshakeComplete();
                } else {
                    try sink.emitFatalAlert(.unexpected_message);
                    return error.UnexpectedHandshakeMessage;
                }
            },
        }
    }

    fn authPending(ptr: *anyopaque) bool {
        const self: *ScriptedRecordBackend = @ptrCast(@alignCast(ptr));
        return self.auth_pending;
    }

    fn resumeAuth(ptr: *anyopaque, _: *RecordTransport.EventSink) RecordHandshakeError!void {
        const self: *ScriptedRecordBackend = @ptrCast(@alignCast(ptr));
        if (!self.auth_pending) return;
        self.auth_poll_count += 1;
        if (self.auth_pending_polls > 0) {
            self.auth_pending_polls -= 1;
            return;
        }
        self.auth_pending = false;
    }
};

/// An in-memory bidirectional byte carrier for two streams, with a per-call
/// chunk cap so tests can force fragmented reads and partial writes.
const Duplex = struct {
    const Buf = ByteQueue(max_ciphertext_queue, error.CiphertextBufferFull);
    c2s: Buf = .{},
    s2c: Buf = .{},
    max_chunk: usize,
    /// When true the server's carrier write returns `WouldBlock`, modelling a
    /// backpressured send side so a pending fatal alert cannot drain yet.
    block_s2c: bool = false,

    const max_ciphertext_queue = PureZigRecordStream.max_ciphertext_queue;

    fn clientCarrier(self: *Duplex) Carrier {
        return .{ .ptr = self, .readFn = clientRead, .writeFn = clientWrite };
    }

    fn serverCarrier(self: *Duplex) Carrier {
        return .{ .ptr = self, .readFn = serverRead, .writeFn = serverWrite };
    }

    fn clientWrite(ptr: *anyopaque, bytes: []const u8) Error!usize {
        const self: *Duplex = @ptrCast(@alignCast(ptr));
        return self.push(&self.c2s, bytes);
    }

    fn clientRead(ptr: *anyopaque, out: []u8) Error!usize {
        const self: *Duplex = @ptrCast(@alignCast(ptr));
        return self.pull(&self.s2c, out);
    }

    fn serverWrite(ptr: *anyopaque, bytes: []const u8) Error!usize {
        const self: *Duplex = @ptrCast(@alignCast(ptr));
        if (self.block_s2c) return error.WouldBlock;
        return self.push(&self.s2c, bytes);
    }

    fn serverRead(ptr: *anyopaque, out: []u8) Error!usize {
        const self: *Duplex = @ptrCast(@alignCast(ptr));
        return self.pull(&self.c2s, out);
    }

    fn push(self: *Duplex, buf: *Buf, bytes: []const u8) Error!usize {
        const n = @min(bytes.len, @min(self.max_chunk, buf.available()));
        if (n == 0) return error.WouldBlock;
        buf.append(bytes[0..n]) catch return error.WouldBlock;
        return n;
    }

    fn pull(self: *Duplex, buf: *Buf, out: []u8) Error!usize {
        if (buf.len == 0) return error.WouldBlock;
        const n = @min(out.len, @min(self.max_chunk, buf.len));
        @memcpy(out[0..n], buf.slice()[0..n]);
        buf.discard(n) catch unreachable;
        return n;
    }
};

fn driveBothUntil(client: *PureZigRecordStream, server: *PureZigRecordStream, done: *const fn (*PureZigRecordStream, *PureZigRecordStream) bool) !void {
    var rounds: usize = 0;
    while (rounds < 1000) : (rounds += 1) {
        const c = try client.stream().drive();
        const s = try server.stream().drive();
        if (done(client, server)) return;
        if (!c.made_progress and !s.made_progress) return error.Stalled;
    }
    return error.Stalled;
}

fn bothComplete(client: *PureZigRecordStream, server: *PureZigRecordStream) bool {
    return client.bridge.handshake_complete and server.bridge.handshake_complete;
}

const DriverPairErrors = struct {
    client: ?anyerror = null,
    server: ?anyerror = null,
};

fn driveDriverPairUntilBothErrors(client: *PureZigRecordStream, server: *PureZigRecordStream) DriverPairErrors {
    var errors = DriverPairErrors{};
    var rounds: usize = 0;
    while (rounds < 1000) : (rounds += 1) {
        if (errors.client == null) {
            _ = client.stream().drive() catch |err| {
                errors.client = err;
            };
        }
        if (errors.server == null) {
            _ = server.stream().drive() catch |err| {
                errors.server = err;
            };
        }
        if (errors.client != null and errors.server != null) return errors;
    }
    return errors;
}

test "pure-Zig encrypted stream completes a driver-owned handshake over a fragmented duplex carrier" {
    const cp = testProvider();
    inline for (.{ 1, 2, 3, 7, 64, record_codec.max_ciphertext_record_len }) |chunk| {
        var duplex = Duplex{ .max_chunk = chunk };
        var client_backend = ScriptedRecordBackend{ .role = .client };
        var server_backend = ScriptedRecordBackend{ .role = .server };
        var client = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .client, cp, .tls_aes_128_gcm_sha256, duplex.clientCarrier(), client_backend.recordBackend());
        defer client.deinit();
        try client.setExpectedAlpn("h1");
        var server = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .server, cp, .tls_aes_128_gcm_sha256, duplex.serverCarrier(), server_backend.recordBackend());
        defer server.deinit();

        // No test-only establish(): both sides install genuine derived secrets
        // and reach completion purely by pumping drive().
        try driveBothUntil(&client, &server, bothComplete);
        try testing.expect(client.bridge.handshake_complete);
        try testing.expect(server.bridge.handshake_complete);
        try testing.expect(client.lifecycle == .open and server.lifecycle == .open);
        try testing.expectEqualStrings("h1", client.negotiatedAlpn().?);
        try testing.expectEqual(events.EncryptionEpoch.application, client.read_epoch);
        try testing.expectEqual(events.EncryptionEpoch.application, server.write_epoch);

        // Application plaintext flows both ways after the real handshake.
        try testing.expectEqual(@as(usize, 11), try client.stream().write("ping-client"));
        try driveBothUntil(&client, &server, struct {
            fn done(_: *PureZigRecordStream, s: *PureZigRecordStream) bool {
                return s.readiness().can_read_plaintext;
            }
        }.done);
        var buf: [32]u8 = undefined;
        try testing.expectEqualStrings("ping-client", buf[0..try server.stream().read(&buf)]);

        try testing.expectEqual(@as(usize, 11), try server.stream().write("pong-server"));
        try driveBothUntil(&client, &server, struct {
            fn done(c: *PureZigRecordStream, _: *PureZigRecordStream) bool {
                return c.readiness().can_read_plaintext;
            }
        }.done);
        try testing.expectEqualStrings("pong-server", buf[0..try client.stream().read(&buf)]);

        // Orderly close_notify shutdown from the client.
        client.stream().close();
        try driveBothUntil(&client, &server, struct {
            fn done(c: *PureZigRecordStream, s: *PureZigRecordStream) bool {
                return c.lifecycle == .closed and s.readiness().peer_closed;
            }
        }.done);
        try testing.expectError(error.EndOfStream, server.stream().read(&buf));
    }
}

test "driver-owned client rejects an unoffered ALPN before sending Finished" {
    const cp = testProvider();
    var duplex = Duplex{ .max_chunk = record_codec.max_ciphertext_record_len };
    var client_backend = ScriptedRecordBackend{ .role = .client, .selected_alpn = "h2" };
    var server_backend = ScriptedRecordBackend{ .role = .server };
    var client = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .client, cp, .tls_aes_128_gcm_sha256, duplex.clientCarrier(), client_backend.recordBackend());
    defer client.deinit();
    try client.setExpectedAlpn("h1");
    var server = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .server, cp, .tls_aes_128_gcm_sha256, duplex.serverCarrier(), server_backend.recordBackend());
    defer server.deinit();

    const errors = driveDriverPairUntilBothErrors(&client, &server);
    try testing.expectEqual(@as(?anyerror, error.AlpnMismatch), errors.client);
    try testing.expectEqual(@as(?anyerror, error.PeerFatalAlert), errors.server);
    try testing.expectEqual(alerts.AlertDescription.no_application_protocol, PureZigRecordStream.mappedFatalAlert(error.AlpnMismatch).?);
    try testing.expect(!client.bridge.handshake_complete);
    try testing.expect(!server.bridge.handshake_complete);
    try testing.expect(!server_backend.received_client_finished);
    try expectLatchedFailureConformance(client.stream(), error.AlpnMismatch);
}

test "driver-owned client requires ALPN before completion" {
    const cp = testProvider();
    var duplex = Duplex{ .max_chunk = record_codec.max_ciphertext_record_len };
    var client_backend = ScriptedRecordBackend{ .role = .client, .selected_alpn = null };
    var server_backend = ScriptedRecordBackend{ .role = .server };
    var client = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .client, cp, .tls_aes_128_gcm_sha256, duplex.clientCarrier(), client_backend.recordBackend());
    defer client.deinit();
    try client.setExpectedAlpn("h1");
    var server = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .server, cp, .tls_aes_128_gcm_sha256, duplex.serverCarrier(), server_backend.recordBackend());
    defer server.deinit();

    const errors = driveDriverPairUntilBothErrors(&client, &server);
    try testing.expectEqual(@as(?anyerror, error.AlpnMismatch), errors.client);
    try testing.expectEqual(@as(?anyerror, error.PeerFatalAlert), errors.server);
    try testing.expect(!client.bridge.handshake_complete);
    try testing.expect(!server.bridge.handshake_complete);
    try testing.expect(!server_backend.received_client_finished);
    try expectLatchedFailureConformance(client.stream(), error.AlpnMismatch);
}

test "completion policy preflight rejects a missing certificate before sending Finished" {
    const cp = testProvider();
    var duplex = Duplex{ .max_chunk = record_codec.max_ciphertext_record_len };
    var client_backend = ScriptedRecordBackend{ .role = .client, .emit_certificate = false };
    var server_backend = ScriptedRecordBackend{ .role = .server };
    var client = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .client, cp, .tls_aes_128_gcm_sha256, duplex.clientCarrier(), client_backend.recordBackend());
    defer client.deinit();
    try client.setExpectedAlpn("h1");
    var server = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .server, cp, .tls_aes_128_gcm_sha256, duplex.serverCarrier(), server_backend.recordBackend());
    defer server.deinit();

    const errors = driveDriverPairUntilBothErrors(&client, &server);
    try testing.expectEqual(@as(?anyerror, error.CertificateInvalid), errors.client);
    try testing.expectEqual(@as(?anyerror, error.PeerFatalAlert), errors.server);
    try testing.expect(!client.bridge.handshake_complete);
    try testing.expect(!server.bridge.handshake_complete);
    try testing.expect(!server_backend.received_client_finished);
    try expectLatchedFailureConformance(client.stream(), error.CertificateInvalid);
}

test "driver-owned handshake latches a terminal failure and flushes its fatal alert to the peer" {
    const cp = testProvider();
    var duplex = Duplex{ .max_chunk = record_codec.max_ciphertext_record_len };
    var client_backend = ScriptedRecordBackend{ .role = .client, .bad_hello = true };
    var server_backend = ScriptedRecordBackend{ .role = .server };
    var client = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .client, cp, .tls_aes_128_gcm_sha256, duplex.clientCarrier(), client_backend.recordBackend());
    defer client.deinit();
    var server = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .server, cp, .tls_aes_128_gcm_sha256, duplex.serverCarrier(), server_backend.recordBackend());
    defer server.deinit();

    // Client sends its (rejected) hello.
    _ = try client.stream().drive();

    // The server rejects it, queues a fatal alert, flushes it, then latches the
    // stable terminal error -- the alert-send does not erase the failure.
    var server_error: ?anyerror = null;
    var rounds: usize = 0;
    while (rounds < 100) : (rounds += 1) {
        const r = server.stream().drive() catch |err| {
            server_error = err;
            break;
        };
        if (!r.made_progress) break;
    }
    try testing.expectEqual(@as(?anyerror, error.UnexpectedHandshakeMessage), server_error);
    try testing.expectEqual(Lifecycle.failed, server.lifecycle);
    try expectLatchedFailureConformance(server.stream(), error.UnexpectedHandshakeMessage);

    // The peer observes the fatal alert the server flushed and fails closed.
    var client_error: ?anyerror = null;
    rounds = 0;
    while (rounds < 100) : (rounds += 1) {
        const r = client.stream().drive() catch |err| {
            client_error = err;
            break;
        };
        if (!r.made_progress) break;
    }
    try testing.expectEqual(@as(?anyerror, error.PeerFatalAlert), client_error);
    try testing.expectEqual(Lifecycle.failed, client.lifecycle);
}

/// A scripted backend whose start installs handshake key material and queues a
/// flight, so a cancellation happening after `drive()` has sensitive state to
/// release. Counts its own teardown so tests can prove it runs exactly once.
const CountingRecordBackend = struct {
    deinit_count: usize = 0,
    started: bool = false,
    /// When true, `start` installs handshake traffic secrets before queuing the
    /// flight (cancellation after keys exist); when false it only queues an
    /// initial-epoch flight (cancellation before any keys, first flight
    /// undrained).
    install_keys: bool = true,

    fn recordBackend(self: *CountingRecordBackend) RecordHandshakeBackend {
        return .{ .ptr = self, .startFn = start, .receiveFn = receive, .deinitFn = deinit };
    }

    fn start(ptr: *anyopaque, role: tls_state.Role, _: void, sink: *RecordTransport.EventSink) RecordHandshakeError!void {
        const self: *CountingRecordBackend = @ptrCast(@alignCast(ptr));
        std.debug.assert(role == .client);
        self.started = true;
        if (self.install_keys) {
            try sink.emitSecret(.handshake, .write, &secret(0x11));
            try sink.emitSecret(.handshake, .read, &secret(0x22));
            try sink.emitHandshakeBytes(.handshake, "flight");
        } else {
            try sink.emitHandshakeBytes(.initial, "client hello");
        }
    }

    fn receive(_: *anyopaque, _: events.EncryptionEpoch, _: []const u8, _: *RecordTransport.EventSink) RecordHandshakeError!void {}

    fn deinit(ptr: *anyopaque) void {
        const self: *CountingRecordBackend = @ptrCast(@alignCast(ptr));
        self.deinit_count += 1;
    }
};

/// An owned carrier that blocks writes (so the queued flight never drains) and
/// counts how many times the stream closes it.
const CountingOwnedCarrier = struct {
    close_count: usize = 0,

    fn carrier(self: *CountingOwnedCarrier) Carrier {
        return .{ .ptr = self, .readFn = read, .writeFn = write, .closeFn = close, .owns_handle = true };
    }

    fn read(_: *anyopaque, _: []u8) Error!usize {
        return error.WouldBlock;
    }

    fn write(_: *anyopaque, _: []const u8) Error!usize {
        return error.WouldBlock;
    }

    fn close(ptr: *anyopaque) void {
        const self: *CountingOwnedCarrier = @ptrCast(@alignCast(ptr));
        self.close_count += 1;
    }
};

/// A deterministic carrier that accepts exactly one byte after each explicit
/// re-arm, then returns `WouldBlock` until the next `drive()`. This models an
/// edge-triggered event loop delivering repeated writable notifications while
/// forcing a protected alert to span many drive calls.
const OneBytePerDriveCarrier = struct {
    captured: ByteQueue(PureZigRecordStream.max_ciphertext_queue, error.CiphertextBufferFull) = .{},
    armed: bool = false,

    fn carrier(self: *OneBytePerDriveCarrier) Carrier {
        return .{ .ptr = self, .readFn = read, .writeFn = write };
    }

    fn rearm(self: *OneBytePerDriveCarrier) void {
        self.armed = true;
    }

    fn read(_: *anyopaque, _: []u8) Error!usize {
        return error.WouldBlock;
    }

    fn write(ptr: *anyopaque, bytes: []const u8) Error!usize {
        const self: *OneBytePerDriveCarrier = @ptrCast(@alignCast(ptr));
        if (!self.armed or bytes.len == 0) return error.WouldBlock;
        self.armed = false;
        self.captured.append(bytes[0..1]) catch return error.WouldBlock;
        return 1;
    }
};

test "driver-owned cancellation releases owned carrier, driver, and secrets exactly once" {
    const cp = testProvider();
    inline for (.{ true, false }) |install_keys| {
        var backend = CountingRecordBackend{ .install_keys = install_keys };
        var carrier = CountingOwnedCarrier{};
        var stream = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .client, cp, .tls_aes_128_gcm_sha256, carrier.carrier(), backend.recordBackend());

        // Start the driver: it installs sensitive state (keys and/or a queued
        // flight) that a blocked carrier keeps undrained.
        _ = try stream.stream().drive();
        try testing.expect(backend.started);
        try testing.expect(stream.queuedCiphertextLen() > 0);
        if (install_keys) try testing.expect(stream.bridge.hasWriteKeys(.handshake));
        const used_before = stream.handshake_driver.?.sink.used;
        try testing.expect(used_before > 0);

        // Cancel mid-handshake: the queued flight is dropped and the owned
        // carrier is closed exactly once.
        stream.stream().close();
        _ = try stream.stream().drive();
        try testing.expectEqual(Lifecycle.closed, stream.lifecycle);
        try testing.expectEqual(@as(usize, 0), stream.queuedCiphertextLen());
        try testing.expectEqual(@as(usize, 1), carrier.close_count);

        // Teardown runs the driver's deinit (and its backend's) exactly once,
        // wipes bridge key material, and does not re-close the carrier.
        stream.deinit();
        try testing.expectEqual(@as(usize, 1), carrier.close_count);
        try testing.expectEqual(@as(usize, 1), backend.deinit_count);
        try testing.expect(!stream.bridge.hasReadKeys(.handshake));
        try testing.expect(!stream.bridge.hasWriteKeys(.handshake));

        // The driver's borrowed event sink -- which had copied traffic-secret
        // bytes into its scratch -- was securely zeroed by teardown.
        try testing.expectEqual(@as(usize, 0), stream.handshake_driver.?.sink.used);
        for (stream.handshake_driver.?.sink.scratch[0..used_before]) |b| {
            try testing.expectEqual(@as(u8, 0), b);
        }

        // A second deinit is a no-op: the driver is not torn down twice.
        stream.deinit();
        try testing.expectEqual(@as(usize, 1), backend.deinit_count);
        try testing.expectEqual(@as(usize, 1), carrier.close_count);
    }
}

test "driver-owned handshake preserves a pending fatal alert across write backpressure" {
    const cp = testProvider();
    var duplex = Duplex{ .max_chunk = record_codec.max_ciphertext_record_len, .block_s2c = true };
    var client_backend = ScriptedRecordBackend{ .role = .client, .bad_hello = true };
    var server_backend = ScriptedRecordBackend{ .role = .server };
    var client = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .client, cp, .tls_aes_128_gcm_sha256, duplex.clientCarrier(), client_backend.recordBackend());
    defer client.deinit();
    var server = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .server, cp, .tls_aes_128_gcm_sha256, duplex.serverCarrier(), server_backend.recordBackend());
    defer server.deinit();

    // Client sends its rejected hello.
    _ = try client.stream().drive();

    // First server drive reads and rejects the hello, queuing a fatal alert.
    _ = try server.stream().drive();
    try testing.expect(server.pending_terminal != null);

    // The carrier write side is blocked. Within the bounded flush deadline the
    // failure stays pending: the alert is neither dropped nor latched, and
    // readiness asks to be driven when the carrier becomes writable -- no hidden
    // synchronous retry-and-discard.
    for (0..3) |_| {
        const result = try server.stream().drive();
        try testing.expect(!result.made_progress); // blocked write makes no progress
    }
    try testing.expect(server.pending_terminal != null);
    try testing.expect(server.queuedCiphertextLen() > 0);
    const blocked = server.readiness();
    try testing.expect(blocked.wants_write);
    try testing.expect(!blocked.wants_read);
    try testing.expect(!blocked.can_read_plaintext);

    // Unblock the carrier: the alert flushes and the preserved handshake error
    // latches (never replaced by a carrier error).
    duplex.block_s2c = false;
    var server_error: ?anyerror = null;
    for (0..8) |_| {
        _ = server.stream().drive() catch |err| {
            server_error = err;
            break;
        };
    }
    try testing.expectEqual(@as(?anyerror, error.UnexpectedHandshakeMessage), server_error);
    try testing.expectEqual(Lifecycle.failed, server.lifecycle);

    // The alert actually reached the peer, which fails closed on it.
    var client_error: ?anyerror = null;
    for (0..8) |_| {
        _ = client.stream().drive() catch |err| {
            client_error = err;
            break;
        };
    }
    try testing.expectEqual(@as(?anyerror, error.PeerFatalAlert), client_error);
}

test "terminal alert flush deadline resets on partial-write progress" {
    const cp = testProvider();
    const hs_secret = secret(0x5a);
    var carrier = OneBytePerDriveCarrier{};
    var sender = PureZigRecordStream.initWithCarrier(.client, cp, .tls_aes_128_gcm_sha256, carrier.carrier());
    defer sender.deinit();
    var peer = PureZigRecordStream.init(.server, cp, .tls_aes_128_gcm_sha256);
    defer peer.deinit();

    try sender.bridge.installTrafficSecret(.handshake, .write, &hs_secret);
    sender.write_epoch = .handshake;
    try peer.bridge.installTrafficSecret(.handshake, .read, &hs_secret);

    // Put a protected handshake record ahead of the synthesized alert so the
    // queue takes substantially more than the 16-attempt no-progress deadline
    // to drain at one byte per writable notification.
    var record_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const earlier = try sender.bridge.sealHandshake(.handshake, "queued-before-alert", &record_buf);
    try sender.outbound_ciphertext.append(earlier);
    sender.deferHandshakeFailure(error.CertificateInvalid, null);
    try testing.expectEqual(alerts.AlertDescription.bad_certificate, PureZigRecordStream.mappedFatalAlert(error.CertificateInvalid).?);
    try testing.expect(sender.queuedCiphertextLen() > PureZigRecordStream.max_terminal_flush_attempts);

    var drives: usize = 0;
    while (drives < PureZigRecordStream.max_ciphertext_queue) : (drives += 1) {
        carrier.rearm();
        const result = sender.stream().drive() catch |err| {
            try testing.expectEqual(error.CertificateInvalid, err);
            break;
        };
        try testing.expect(result.made_progress);
        try testing.expectEqual(@as(usize, 0), sender.terminal_flush_attempts);
        try testing.expect(sender.pending_terminal != null);
    }
    try testing.expect(drives > PureZigRecordStream.max_terminal_flush_attempts);
    try testing.expectEqual(Lifecycle.failed, sender.lifecycle);
    try expectLatchedFailureConformance(sender.stream(), error.CertificateInvalid);

    // The peer can consume the complete earlier handshake record and then
    // opens the following protected fatal alert rather than seeing truncation.
    const captured = carrier.captured.slice();
    const consumed = try peer.feedHandshakeCiphertext(.handshake, captured);
    var plaintext: [64]u8 = undefined;
    try testing.expectEqualStrings("queued-before-alert", plaintext[0..try peer.readHandshake(&plaintext)]);
    try testing.expectError(error.PeerFatalAlert, peer.feedHandshakeCiphertext(.handshake, captured[consumed..]));
}

test "driver-owned handshake latches on the flush deadline when a fatal alert can never be sent" {
    const cp = testProvider();
    var duplex = Duplex{ .max_chunk = record_codec.max_ciphertext_record_len, .block_s2c = true };
    var client_backend = ScriptedRecordBackend{ .role = .client, .bad_hello = true };
    var server_backend = ScriptedRecordBackend{ .role = .server };
    var client = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .client, cp, .tls_aes_128_gcm_sha256, duplex.clientCarrier(), client_backend.recordBackend());
    defer client.deinit();
    var server = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .server, cp, .tls_aes_128_gcm_sha256, duplex.serverCarrier(), server_backend.recordBackend());
    defer server.deinit();

    _ = try client.stream().drive();

    // The carrier never accepts the alert. The stream must not wedge forever:
    // after a bounded number of flush attempts it latches the preserved error
    // regardless, and the alert-send failure never erases that error.
    var server_error: ?anyerror = null;
    var attempts: usize = 0;
    while (attempts < PureZigRecordStream.max_terminal_flush_attempts + 4) : (attempts += 1) {
        _ = server.stream().drive() catch |err| {
            server_error = err;
            break;
        };
    }
    try testing.expectEqual(@as(?anyerror, error.UnexpectedHandshakeMessage), server_error);
    try testing.expectEqual(Lifecycle.failed, server.lifecycle);
    try expectLatchedFailureConformance(server.stream(), error.UnexpectedHandshakeMessage);
}

// ───────────────────────────────────────────────────────────────────────────

// #493-C encrypted-stream / scripted-carrier fuzz targets. See
// docs/CRYPTO_FUZZ_CONTRACT.md's "#493" section for the shared rules these
// follow (fresh provider per case, fixed buffers, explicit operation bounds,
// typed-error classification, sanitized diagnostics).
//
// Nothing below opens a socket, resolves a name, or performs any other network
// I/O: `ScriptedCarrier` is the only transport, it is backed entirely by fixed
// arrays, and the existing `testSocketPair` helpers are deliberately never
// called from a fuzz callback.
// ───────────────────────────────────────────────────────────────────────────

/// One step of a `ScriptedCarrier` read or write script.
const CarrierAction = union(enum) {
    /// Transfer at most this many bytes (further bounded by the caller's slice
    /// and by the fixture's own fixed capacity). A `.transfer` that has nothing
    /// to move reports `WouldBlock` rather than zero, because a zero-byte
    /// carrier *read* means EOF to `drive()`.
    transfer: usize,
    /// Temporary no-readiness in either direction.
    would_block,
    /// Zero-byte progress: EOF on the read side, a no-progress write on the
    /// write side (which must not make `drive()` spin).
    zero,
    end_of_stream,
    /// The one typed carrier error this fixture injects per direction.
    fail,
};

const scripted_script_len = 8;
const scripted_inbound_capacity = 4096;
const scripted_capture_capacity = 4096;

/// A deterministic, fixed-capacity, test-only `Carrier`. Inbound bytes come
/// from a preloaded queue; outbound bytes land in a capture buffer the test
/// drains itself. Read and write behaviour is driven by independent cyclic
/// action scripts, so partial I/O, would-block, zero progress, EOF, and a
/// typed failure are all reachable without any real descriptor.
///
/// Deliberately private to this file's tests: no fake-carrier API leaks into
/// production.
const ScriptedCarrier = struct {
    inbound: [scripted_inbound_capacity]u8 = undefined,
    inbound_len: usize = 0,
    inbound_head: usize = 0,
    captured: [scripted_capture_capacity]u8 = undefined,
    captured_len: usize = 0,

    read_script: [scripted_script_len]CarrierAction = [_]CarrierAction{.{ .transfer = scripted_inbound_capacity }} ** scripted_script_len,
    read_script_len: usize = 1,
    read_cursor: usize = 0,
    write_script: [scripted_script_len]CarrierAction = [_]CarrierAction{.{ .transfer = scripted_capture_capacity }} ** scripted_script_len,
    write_script_len: usize = 1,
    write_cursor: usize = 0,

    read_calls: usize = 0,
    write_calls: usize = 0,
    read_bytes: usize = 0,
    write_bytes: usize = 0,
    close_calls: usize = 0,
    owns_handle: bool = false,

    fn carrier(self: *ScriptedCarrier) Carrier {
        return .{
            .ptr = self,
            .readFn = scriptedRead,
            .writeFn = scriptedWrite,
            .closeFn = scriptedClose,
            .owns_handle = self.owns_handle,
        };
    }

    fn inboundPending(self: *const ScriptedCarrier) usize {
        return self.inbound_len - self.inbound_head;
    }

    fn inboundAvailable(self: *const ScriptedCarrier) usize {
        return scripted_inbound_capacity - self.inboundPending();
    }

    /// Append inbound bytes, compacting the already-consumed prefix first.
    /// Returns false when the fixed capacity cannot hold `bytes`.
    fn pushInbound(self: *ScriptedCarrier, bytes: []const u8) bool {
        if (bytes.len > self.inboundAvailable()) return false;
        if (bytes.len > scripted_inbound_capacity - self.inbound_len) {
            const pending = self.inboundPending();
            std.mem.copyForwards(u8, self.inbound[0..pending], self.inbound[self.inbound_head..self.inbound_len]);
            self.inbound_head = 0;
            self.inbound_len = pending;
        }
        @memcpy(self.inbound[self.inbound_len..][0..bytes.len], bytes);
        self.inbound_len += bytes.len;
        return true;
    }

    fn captureSlice(self: *const ScriptedCarrier) []const u8 {
        return self.captured[0..self.captured_len];
    }

    fn consumeCapture(self: *ScriptedCarrier, count: usize) void {
        std.debug.assert(count <= self.captured_len);
        const remaining = self.captured_len - count;
        std.mem.copyForwards(u8, self.captured[0..remaining], self.captured[count..self.captured_len]);
        self.captured_len = remaining;
    }

    fn nextAction(script: []const CarrierAction, cursor: *usize) CarrierAction {
        const action = script[cursor.* % script.len];
        cursor.* += 1;
        return action;
    }

    fn scriptedRead(ptr: *anyopaque, out: []u8) Error!usize {
        const self: *ScriptedCarrier = @ptrCast(@alignCast(ptr));
        self.read_calls += 1;
        switch (nextAction(self.read_script[0..self.read_script_len], &self.read_cursor)) {
            .would_block => return error.WouldBlock,
            .zero => return 0,
            .end_of_stream => return error.EndOfStream,
            .fail => return error.SocketReadFailed,
            .transfer => |cap| {
                const pending = self.inboundPending();
                if (pending == 0 or out.len == 0 or cap == 0) return error.WouldBlock;
                const n = @min(@min(cap, out.len), pending);
                @memcpy(out[0..n], self.inbound[self.inbound_head..][0..n]);
                self.inbound_head += n;
                self.read_bytes += n;
                return n;
            },
        }
    }

    fn scriptedWrite(ptr: *anyopaque, bytes: []const u8) Error!usize {
        const self: *ScriptedCarrier = @ptrCast(@alignCast(ptr));
        self.write_calls += 1;
        switch (nextAction(self.write_script[0..self.write_script_len], &self.write_cursor)) {
            .would_block => return error.WouldBlock,
            .zero => return 0,
            .end_of_stream => return error.EndOfStream,
            .fail => return error.SocketWriteFailed,
            .transfer => |cap| {
                const room = scripted_capture_capacity - self.captured_len;
                const n = @min(@min(cap, bytes.len), room);
                if (n == 0) return error.WouldBlock;
                @memcpy(self.captured[self.captured_len..][0..n], bytes[0..n]);
                self.captured_len += n;
                self.write_bytes += n;
                return n;
            },
        }
    }

    fn scriptedClose(ptr: *anyopaque) void {
        const self: *ScriptedCarrier = @ptrCast(@alignCast(ptr));
        self.close_calls += 1;
    }
};

/// Draw one bounded, cyclic carrier action script. `.fail` and `.end_of_stream`
/// occupy one slot each out of twelve so that ordinary partial-progress and
/// would-block interleavings dominate; the corpus pins the harsher scripts
/// explicitly.
fn scriptFromSmith(smith: *std.testing.Smith, out: *[scripted_script_len]CarrierAction, max_transfer: usize) usize {
    const len = 1 + smith.index(scripted_script_len);
    for (out[0..len]) |*action| {
        action.* = switch (smith.index(12)) {
            0, 1, 2 => .would_block,
            3 => .zero,
            4 => .end_of_stream,
            5 => .fail,
            6, 7 => .{ .transfer = 1 },
            8 => .{ .transfer = 2 + smith.index(30) },
            9 => .{ .transfer = 1 + smith.index(max_transfer) },
            else => .{ .transfer = max_transfer },
        };
    }
    return len;
}

const fuzz_stream_max_operations = 24;
const fuzz_stream_max_read_buf = 512;
const fuzz_stream_peer_chunk = 64;
/// Inbound-queue headroom required before the peer seals another record:
/// header + content + inner content type + the largest AEAD tag, rounded up.
const fuzz_stream_peer_record_reserve = record_codec.header_len + fuzz_stream_peer_chunk + 1 + 32;
/// Bounded drain/flush iteration budgets. Exceeding one is itself a failure:
/// it means the state machine kept claiming progress without terminating.
const fuzz_stream_sync_rounds = 96;
const fuzz_stream_flush_rounds = 96;

/// The two application byte streams are generated rather than buffered, so the
/// oracle only has to carry offsets: byte `i` of each direction has one fixed
/// value, and "no loss or duplication" becomes "the `n`th delivered byte equals
/// `f(n)`" plus a monotone delivered-at-most-accepted bound. That keeps a
/// maximum-fragment write (16 KiB) expressible without a 16 KiB oracle buffer.
fn subjectStreamByte(i: usize) u8 {
    return @truncate(i *% 31 +% 7);
}

fn peerStreamByte(i: usize) u8 {
    return @truncate(i *% 17 +% 129);
}

/// Independent plaintext/ciphertext accounting for one progression case.
const StreamOracle = struct {
    /// Plaintext bytes the subject accepted from its application.
    subject_sent: usize = 0,
    /// Plaintext bytes the peer has read back out, i.e. that actually survived
    /// sealing, the scripted carrier, and the peer's parser.
    peer_received: usize = 0,
    /// Plaintext bytes the peer sealed into the carrier's inbound queue.
    peer_sent: usize = 0,
    /// Plaintext bytes the subject delivered to its application.
    subject_received: usize = 0,
    /// False once the peer has seen the subject's `close_notify`: from then on
    /// it swallows further input by contract, so it can no longer witness the
    /// subject's byte stream. This is the *only* thing that retires the peer --
    /// a record the peer cannot open or parse means the subject emitted bytes
    /// the real record path rejects, which is precisely the corruption this
    /// target exists to catch, so those errors propagate and fail the case.
    peer_usable: bool = true,
    /// The subject's latched terminal error, once one exists.
    terminal: ?anyerror = null,
};

/// Read everything currently available from the peer, checking each delivered
/// byte against the subject's generated stream.
fn drainPeerPlaintext(peer: *PureZigRecordStream, oracle: *StreamOracle) !void {
    var buf: [fuzz_stream_max_read_buf]u8 = undefined;
    var rounds: usize = 0;
    while (rounds < fuzz_stream_sync_rounds) : (rounds += 1) {
        const n = peer.readPlaintext(&buf) catch |err| switch (err) {
            // Nothing buffered, or a peer that has already seen `close_notify`.
            error.WouldBlock, error.EndOfStream => return,
            // Anything else means the plaintext the subject produced could not
            // be delivered by the real record path.
            else => return err,
        };
        if (n == 0) return;
        for (buf[0..n], 0..) |byte, i| {
            try testing.expectEqual(subjectStreamByte(oracle.peer_received + i), byte);
        }
        oracle.peer_received += n;
        // Delivered can never run ahead of accepted: that would be duplication.
        try testing.expect(oracle.peer_received <= oracle.subject_sent);
    }
    return error.PeerDrainDidNotTerminate;
}

/// Move whatever the subject wrote to its carrier into the peer, then read the
/// peer's plaintext back out. This is the only place the captured ciphertext is
/// interpreted, so the capture buffer doubles as the "bytes in flight" queue.
fn syncCapture(carrier: *ScriptedCarrier, peer: *PureZigRecordStream, oracle: *StreamOracle) !void {
    if (!oracle.peer_usable) {
        carrier.captured_len = 0;
        return;
    }
    var rounds: usize = 0;
    while (carrier.captured_len > 0 and rounds < fuzz_stream_sync_rounds) : (rounds += 1) {
        // Only `WouldBlock` is an expected outcome here: it is the peer's own
        // buffer pressure, and the same bytes are retried next round. Every
        // other error means the subject emitted ciphertext the real record path
        // could not authenticate or frame, so it must fail the case rather than
        // quietly retire the oracle.
        const consumed = peer.feedCiphertext(carrier.captureSlice()) catch |err| switch (err) {
            error.WouldBlock => 0,
            else => return err,
        };
        if (consumed > 0) carrier.consumeCapture(consumed);
        try drainPeerPlaintext(peer, oracle);
        if (peer.peer_closed) {
            // The subject's `close_notify` landed. Everything ahead of it in
            // the capture was already delivered above, so the accounting is
            // complete; the peer now swallows input and can witness no more.
            oracle.peer_usable = false;
            carrier.captured_len = 0;
            return;
        }
        if (consumed == 0) break;
    }
    try drainPeerPlaintext(peer, oracle);
}

/// Seal one bounded plaintext chunk from the peer into the carrier's inbound
/// queue. Refuses rather than truncates when the fixed capacity is short, so
/// the inbound accounting can never silently lose a byte.
fn enqueuePeerRecord(
    peer: *PureZigRecordStream,
    carrier: *ScriptedCarrier,
    oracle: *StreamOracle,
    len: usize,
) !void {
    if (!oracle.peer_usable or len == 0) return;
    // Refuse rather than truncate: one sealed record for a
    // `fuzz_stream_peer_chunk` fragment is header + content + content-type +
    // tag, and the inbound accounting must never silently lose a byte.
    if (carrier.inboundAvailable() < fuzz_stream_peer_record_reserve) return;
    if (peer.queuedCiphertextLen() != 0) return;

    var chunk: [fuzz_stream_peer_chunk]u8 = undefined;
    for (chunk[0..len], 0..) |*byte, i| byte.* = peerStreamByte(oracle.peer_sent + i);
    // `WouldBlock` is the peer's own outbound backpressure and simply means
    // "not this round"; anything else is a real defect in the record path.
    const n = peer.writePlaintext(chunk[0..len]) catch |err| switch (err) {
        error.WouldBlock => return,
        else => return err,
    };

    var buf: [256]u8 = undefined;
    while (peer.queuedCiphertextLen() > 0) {
        const moved = try peer.drainCiphertext(&buf);
        try testing.expect(moved > 0);
        try testing.expect(carrier.pushInbound(buf[0..moved]));
    }
    oracle.peer_sent += n;
}

/// Per-operation invariants that must hold at every point of a progression
/// program, terminal or not.
fn checkStreamInvariants(subject: *PureZigRecordStream, carrier: *const ScriptedCarrier) !void {
    // An owned carrier handle is released at most once, ever.
    try testing.expect(carrier.close_calls <= 1);

    const snapshot = subject.bufferSnapshot();
    const limits = snapshot.limits.?;
    try testing.expect(snapshot.current.inbound_ciphertext <= limits.inbound_ciphertext.hard);
    try testing.expect(snapshot.current.inbound_plaintext <= limits.inbound_plaintext.hard);
    try testing.expect(snapshot.current.outbound_ciphertext <= limits.outbound_ciphertext.hard);
    try testing.expect(snapshot.current.handshake <= limits.handshake.hard);
    // ...and inside the fixed backing capacities, independently of the limits.
    try testing.expect(subject.inbound_carrier.len <= PureZigRecordStream.max_carrier_input_queue);
    try testing.expect(subject.inbound_plaintext.len <= PureZigRecordStream.max_plaintext_queue);
    try testing.expect(subject.outbound_ciphertext.len <= PureZigRecordStream.max_ciphertext_queue);
    try testing.expect(subject.inbound_handshake.len <= PureZigRecordStream.max_handshake_queue);
    try testing.expect(subject.initial_parser.len <= record_codec.max_ciphertext_record_len);
    try testing.expect(subject.ciphertext_parser.len <= record_codec.max_ciphertext_record_len);
    // The plaintext queue and its provenance shadow move together.
    try testing.expectEqual(subject.inbound_plaintext.len, subject.inbound_plaintext_provenance.len);
    try testing.expect(snapshot.peak_total >= snapshot.current.total());

    // Backpressure pauses and resumes strictly alternate from "not paused", so
    // the two counters differ by exactly the current flag. `clearOwnedQueues`
    // drops the flags wholesale on a terminal transition, so the invariant is
    // scoped to a stream that has not been torn down or latched.
    if (subject.failed == null and subject.lifecycle != .closed and subject.lifecycle != .failed) {
        const counters = snapshot.counters;
        try testing.expect(counters.inbound_read_pauses >= counters.inbound_read_resumes);
        try testing.expect(counters.plaintext_write_pauses >= counters.plaintext_write_resumes);
        try testing.expectEqual(
            @as(u64, if (snapshot.pause_state.inbound_read_paused) 1 else 0),
            counters.inbound_read_pauses - counters.inbound_read_resumes,
        );
        try testing.expectEqual(
            @as(u64, if (snapshot.pause_state.plaintext_write_paused) 1 else 0),
            counters.plaintext_write_pauses - counters.plaintext_write_resumes,
        );
    }
}

/// One `drive()`, with the per-call carrier work budgets asserted around it.
/// A successful carrier read or write always moves at least one byte, so
/// bounding calls by bytes-plus-a-constant is exactly the "no spin under
/// repeated zero-progress readiness" property.
fn driveChecked(
    subject: *PureZigRecordStream,
    carrier: *ScriptedCarrier,
    oracle: *StreamOracle,
) !?DriveResult {
    const read_calls_before = carrier.read_calls;
    const write_calls_before = carrier.write_calls;
    const read_bytes_before = carrier.read_bytes;
    const write_bytes_before = carrier.write_bytes;

    const outbound_before = subject.queuedCiphertextLen();
    const close_notify_before = subject.close_notify_queued;
    const lifecycle_before = subject.lifecycle;
    const queues_before = subject.bufferSnapshot().current;
    const carrier_eof_before = subject.carrier_eof;
    const peer_closed_before = subject.peer_closed;
    const deferred_before = subject.pending_terminal_read_error;

    const result = subject.stream().drive() catch |err| {
        oracle.terminal = err;
        return null;
    };

    // Exact outbound byte conservation across a (possibly partial) carrier
    // write: everything that left the queue is exactly what the carrier
    // accepted, so a partial write discards only the written prefix and keeps
    // the unwritten suffix intact. Skipped for the two drives that legitimately
    // change the queue by other means -- sealing `close_notify`, and the
    // terminal/close transition that clears every owned queue.
    if (close_notify_before == subject.close_notify_queued and lifecycle_before == subject.lifecycle) {
        try testing.expectEqual(outbound_before, subject.queuedCiphertextLen() + (carrier.write_bytes - write_bytes_before));
    }

    const read_bytes = carrier.read_bytes - read_bytes_before;
    const write_bytes = carrier.write_bytes - write_bytes_before;
    try testing.expect(read_bytes <= PureZigRecordStream.drive_read_budget + PureZigRecordStream.drive_read_chunk);
    try testing.expect(write_bytes <= PureZigRecordStream.drive_write_budget + record_codec.max_ciphertext_record_len);
    // At most one non-productive read call (the one that ends the read loop),
    // and at most three non-productive writes (each of `drive`'s two write
    // loops, plus slack for the terminal-alert flush path).
    try testing.expect(carrier.read_calls - read_calls_before <= read_bytes + 2);
    try testing.expect(carrier.write_calls - write_calls_before <= write_bytes + 3);
    // `drive` must report the readiness the stream actually has on return.
    try testing.expectEqual(subject.readiness(), result.readiness);

    // Progress must be *real*: a drive that claims progress moved at least one
    // carrier byte or changed observable stream state. Together with the fixed
    // queue capacities and the per-drive budgets above, that is what makes
    // repeated driving terminate instead of spinning on a would-block or
    // zero-write carrier.
    const state_changed = lifecycle_before != subject.lifecycle or
        close_notify_before != subject.close_notify_queued or
        carrier_eof_before != subject.carrier_eof or
        peer_closed_before != subject.peer_closed or
        !std.meta.eql(deferred_before, subject.pending_terminal_read_error) or
        !std.meta.eql(queues_before, subject.bufferSnapshot().current);
    if (result.made_progress) {
        try testing.expect(read_bytes + write_bytes > 0 or state_changed);
    } else {
        // ...and a drive that reports none moved no carrier byte, changed no
        // observable state, and left every owned queue exactly as it was. This
        // is the full "no spin under repeated zero-progress readiness"
        // property, not just one projection of it.
        try testing.expectEqual(@as(usize, 0), read_bytes);
        try testing.expectEqual(@as(usize, 0), write_bytes);
        try testing.expect(!state_changed);
        try testing.expect(std.meta.eql(queues_before, subject.bufferSnapshot().current));
    }
    return result;
}

/// Every owned buffer is empty *and* zeroed, both parsers are reset, and no key
/// material survives. Holds on all three teardown paths: `fail()`, `deinit()`,
/// and -- since they now share `finishClose()` -- a completed orderly close.
///
/// Negotiation metadata and deferred terminal state are deliberately excluded:
/// `fail()`/`deinit()` clear those too, but an orderly close keeps the
/// negotiated ALPN so a caller can still report the protocol it spoke. See
/// `expectTeardownMetadataCleared` for the stricter check.
fn expectStreamStateCleared(subject: *PureZigRecordStream) !void {
    try testing.expectEqual(@as(usize, 0), subject.inbound_carrier.len);
    try testing.expectEqual(@as(usize, 0), subject.inbound_plaintext.len);
    try testing.expectEqual(@as(usize, 0), subject.inbound_handshake.len);
    try testing.expectEqual(@as(usize, 0), subject.outbound_ciphertext.len);
    try testing.expectEqual(@as(usize, 0), subject.inbound_plaintext_provenance.len);
    try testing.expectEqual(@as(usize, 0), subject.initial_parser.len);
    try testing.expectEqual(@as(usize, 0), subject.ciphertext_parser.len);

    // No stale plaintext or ciphertext left behind in the backing storage.
    try testing.expect(allEqualUninstrumented(u8, &subject.inbound_carrier.buf, 0));
    try testing.expect(allEqualUninstrumented(u8, &subject.inbound_plaintext.buf, 0));
    try testing.expect(allEqualUninstrumented(u8, &subject.inbound_handshake.buf, 0));
    try testing.expect(allEqualUninstrumented(u8, &subject.outbound_ciphertext.buf, 0));
    try testing.expect(allEqualUninstrumented(u8, &subject.initial_parser.pending, 0));
    try testing.expect(allEqualUninstrumented(u8, &subject.ciphertext_parser.pending, 0));
    try testing.expect(allEqualUninstrumented(bool, &subject.inbound_plaintext_provenance.buf, false));

    // ...and no key material, at any epoch, in either direction.
    inline for (.{ events.EncryptionEpoch.zero_rtt, .handshake, .application }) |epoch| {
        try testing.expect(!subject.bridge.hasReadKeys(epoch));
        try testing.expect(!subject.bridge.hasWriteKeys(epoch));
    }
    try testing.expect(!subject.bridge.handshake_complete);
}

/// Zeroization assertions scan the complete fixed backing arrays (about 247 KiB
/// per call). Coverage instrumentation on every scalar comparison makes those
/// test-only scans dominate sustained fuzzing even though their internal loop
/// carries no useful input-dependent coverage signal.
fn allEqualUninstrumented(comptime T: type, slice: []const T, scalar: T) bool {
    @disableInstrumentation();
    return std.mem.allEqual(T, slice, scalar);
}

/// The extra state `fail()` and `deinit()` clear on top of
/// `expectStreamStateCleared`: captured negotiation metadata and any deferred
/// terminal condition.
fn expectTeardownMetadataCleared(subject: *PureZigRecordStream) !void {
    try expectStreamStateCleared(subject);
    try testing.expectEqual(@as(usize, 0), subject.alpn_len);
    try testing.expect(!subject.alpn_captured);
    try testing.expectEqual(@as(usize, 0), subject.expected_alpn_len);
    try testing.expect(!subject.require_alpn);
    try testing.expectEqual(events.CertificateState.not_checked, subject.certificate_state);
    try testing.expectEqual(@as(?Error, null), subject.pending_terminal);
    try testing.expectEqual(@as(?Error, null), subject.pending_terminal_read_error);
    try testing.expectEqual(@as(usize, 0), subject.terminal_flush_attempts);
}

/// A latched failure is stable: it survives repetition, is never replaced by a
/// cleanup or carrier error, and cannot revive the stream.
fn expectStableTerminal(subject: *PureZigRecordStream, carrier: *const ScriptedCarrier, expected: anyerror) !void {
    for (0..3) |_| {
        try expectLatchedFailureConformance(subject.stream(), expected);
        try checkStreamInvariants(subject, carrier);
    }
    try expectTeardownMetadataCleared(subject);
}

/// Classify a plaintext-I/O error. A latched stream records its terminal
/// error; an *un*-latched stream may only refuse I/O for one of the two
/// deferred terminal conditions -- a fatal alert still flushing
/// (`pending_terminal`) or a terminal read error waiting behind buffered
/// plaintext (`pending_terminal_read_error`) -- and must report that condition
/// unchanged rather than substituting another error.
fn classifyStreamError(subject: *PureZigRecordStream, oracle: *StreamOracle, err: anyerror) !void {
    if (subject.failed != null) {
        oracle.terminal = err;
        return;
    }
    const deferred = if (subject.pending_terminal) |pending|
        pending
    else if (subject.pending_terminal_read_error) |pending|
        pending
    else
        return error.UnlatchedStreamErrorWithoutDeferredCause;
    try testing.expectEqual(@as(anyerror, deferred), err);
}

/// One plaintext read from the subject, checked against the peer's generated
/// stream. A deferred terminal read error must be surfaced unchanged, and only
/// after the plaintext buffered ahead of it has been delivered.
fn subjectReadOnce(subject: *PureZigRecordStream, oracle: *StreamOracle, out: []u8) !void {
    const n = subject.stream().read(out) catch |err| switch (err) {
        // `StreamClosed` is the closed-lifecycle contract, not a latched
        // failure: `readPlaintext` reports a real failure ahead of it.
        error.WouldBlock, error.EndOfStream, error.StreamClosed => return,
        else => return classifyStreamError(subject, oracle, err),
    };
    for (out[0..n], 0..) |byte, i| {
        try testing.expectEqual(peerStreamByte(oracle.subject_received + i), byte);
    }
    oracle.subject_received += n;
    try testing.expect(oracle.subject_received <= oracle.peer_sent);
}

fn subjectWriteOnce(subject: *PureZigRecordStream, oracle: *StreamOracle, src: []u8) !void {
    for (src, 0..) |*byte, i| byte.* = subjectStreamByte(oracle.subject_sent + i);
    const n = subject.stream().write(src) catch |err| switch (err) {
        error.WouldBlock, error.StreamClosed => return,
        else => return classifyStreamError(subject, oracle, err),
    };
    try testing.expect(n <= src.len);
    oracle.subject_sent += n;
}

test "fuzz: TLS record: encrypted stream scripted carrier progression preserves bytes and terminal state" {
    try testing.fuzz({}, fuzzEncryptedStreamProgressionInput, .{
        .corpus = &.{
            "",
            &[_]u8{0},
            // Operation-selector programs covering the classes the generator
            // draws from: drive-only, read/write interleaving, close then
            // repeated drive, enqueue-then-drain, and teardown.
            &[_]u8{ 0, 0, 0, 0 },
            &[_]u8{ 4, 0, 1, 0, 1, 0 },
            &[_]u8{ 2, 0, 2, 0, 0, 0 },
            &[_]u8{ 2, 0, 3, 0, 0, 0, 0 },
            &[_]u8{ 4, 4, 0, 1, 1, 1, 0, 1 },
            &[_]u8{ 2, 5, 6, 0, 3, 5, 5 },
            &[_]u8{ 4, 0, 1, 7 },
            &[_]u8{ 2, 0, 7 },
            &([_]u8{0} ** 48),
            &([_]u8{0xff} ** 48),
            &([_]u8{ 0, 1, 2, 3, 4, 5, 6, 7 } ** 6),
            &([_]u8{ 2, 0, 4, 1 } ** 12),
        },
    });
}

fn fuzzEncryptedStreamProgressionInput(_: void, smith: *std.testing.Smith) !void {
    const pure_zig = crypto.pure_zig;
    // Fresh provider per case, per the #493 shared rules -- not this module's
    // process-wide `testProvider()` singleton.
    var entropy = pure_zig.DeterministicEntropy.init(0x493e);
    var provider_state = pure_zig.Provider.init(entropy.entropy());
    const cp = provider_state.cryptoProvider();

    const suite: algorithms.CipherSuite = switch (smith.index(3)) {
        0 => .tls_aes_128_gcm_sha256,
        1 => .tls_aes_256_gcm_sha384,
        else => .tls_chacha20_poly1305_sha256,
    };

    var carrier_state = ScriptedCarrier{ .owns_handle = smith.index(2) == 0 };
    carrier_state.read_script_len = scriptFromSmith(smith, &carrier_state.read_script, scripted_inbound_capacity);
    carrier_state.write_script_len = scriptFromSmith(smith, &carrier_state.write_script, scripted_capture_capacity);

    // The peer is a full record stream too: it seals every inbound record and
    // opens every outbound one, so the oracle is checked against the real
    // record path rather than against a hand-rolled encoder.
    var peer = PureZigRecordStream.init(.client, cp, suite);
    defer peer.deinit();
    var subject = PureZigRecordStream.initWithCarrier(.server, cp, suite, carrier_state.carrier());
    defer subject.deinit();
    try establishForSuite(&peer, &subject, suite);

    var oracle = StreamOracle{};
    var write_src: [record_codec.max_plaintext_fragment_len]u8 = undefined;
    var read_buf: [fuzz_stream_max_read_buf]u8 = undefined;

    // Every case carries real bytes in both directions before the fuzzer's
    // program starts: one mandatory inbound record and one mandatory
    // application write, plus a fuzzer-chosen number of extra inbound records.
    // Without that floor a program whose scripts never move a byte would reach
    // the accounting assertions with nothing to account for.
    for (0..1 + smith.index(3)) |_| {
        try enqueuePeerRecord(&peer, &carrier_state, &oracle, 1 + smith.index(fuzz_stream_peer_chunk));
    }
    try subjectWriteOnce(&subject, &oracle, write_src[0 .. 1 + smith.index(64)]);
    try testing.expect(oracle.peer_sent > 0);
    try testing.expect(oracle.subject_sent > 0);
    try checkStreamInvariants(&subject, &carrier_state);

    var torn_down = false;
    const operations = smith.index(fuzz_stream_max_operations + 1);
    for (0..operations) |_| {
        if (oracle.terminal != null) break;
        switch (smith.index(7)) {
            0 => _ = try driveChecked(&subject, &carrier_state, &oracle),
            1 => {
                const cap: usize = switch (smith.index(5)) {
                    0 => 0,
                    1 => 1,
                    2 => 2,
                    3 => 64,
                    else => fuzz_stream_max_read_buf,
                };
                try subjectReadOnce(&subject, &oracle, read_buf[0..cap]);
            },
            2 => {
                const len: usize = switch (smith.index(6)) {
                    0 => 1,
                    1 => 2,
                    2 => 7,
                    3 => 64,
                    4 => 1024,
                    // The maximum a single `writePlaintext` can accept, so
                    // outbound saturation is reachable inside the op budget.
                    else => record_codec.max_plaintext_fragment_len,
                };
                try subjectWriteOnce(&subject, &oracle, write_src[0..len]);
            },
            3 => subject.stream().close(),
            4 => try enqueuePeerRecord(&peer, &carrier_state, &oracle, 1 + smith.index(fuzz_stream_peer_chunk)),
            5 => {
                // Repeated driving with no intervening application or carrier
                // change. Each call is checked by `driveChecked`; a *stable*
                // script's settle-and-stay-settled behaviour is pinned by the
                // named companions instead, which do not have this target's
                // advancing script cursor confounding "nothing changed in
                // between".
                for (0..2 + smith.index(2)) |_| {
                    if (oracle.terminal != null) break;
                    _ = try driveChecked(&subject, &carrier_state, &oracle);
                }
            },
            else => {
                // Cancellation/teardown, reachable after any operation class.
                // Kept a minority outcome so most programs run to their full
                // operation budget rather than ending on the first draw.
                if (smith.index(4) == 0) {
                    subject.deinit();
                    torn_down = true;
                } else {
                    _ = try driveChecked(&subject, &carrier_state, &oracle);
                }
            },
        }
        if (torn_down) break;
        try syncCapture(&carrier_state, &peer, &oracle);
        try checkStreamInvariants(&subject, &carrier_state);
    }

    if (torn_down) {
        try expectTeardownMetadataCleared(&subject);
        try testing.expectEqual(Lifecycle.closed, subject.lifecycle);
        if (carrier_state.owns_handle) try testing.expectEqual(@as(usize, 1), carrier_state.close_calls);
        for (0..3) |_| {
            try expectClosedConformance(subject.stream());
            try checkStreamInvariants(&subject, &carrier_state);
        }
        // A second teardown is safe and does not double-release the handle.
        subject.deinit();
        try testing.expect(carrier_state.close_calls <= 1);
        return;
    }

    // Bounded flush: drive and drain until the stream settles. The round cap is
    // a runtime bound rather than the anti-spin property -- a one-byte-per-call
    // write script legitimately needs many rounds to drain a saturated queue.
    // The real guarantees are asserted per drive in `driveChecked`: bounded
    // carrier work, progress only when a byte or some observable state actually
    // moved, and no queue movement when no progress is reported.
    var flush_rounds: usize = 0;
    while (oracle.terminal == null and flush_rounds < fuzz_stream_flush_rounds) : (flush_rounds += 1) {
        const before_received = oracle.subject_received;
        const result = try driveChecked(&subject, &carrier_state, &oracle) orelse break;
        try syncCapture(&carrier_state, &peer, &oracle);
        try subjectReadOnce(&subject, &oracle, &read_buf);
        try checkStreamInvariants(&subject, &carrier_state);
        if (oracle.terminal != null) break;
        if (!result.made_progress and oracle.subject_received == before_received) break;
    }

    if (oracle.terminal) |err| {
        try expectStableTerminal(&subject, &carrier_state, err);
        if (carrier_state.owns_handle) try testing.expectEqual(@as(usize, 1), carrier_state.close_calls);
        return;
    }

    // Deterministic epilogue. The scripts have already done their fragmentation
    // work; lifting the obstruction lets everything still queued or in flight
    // drain, so the byte accounting below is actually reached instead of being
    // skipped for any case whose script happened never to let a byte through.
    // This is what makes the seed-corpus replay a real end-to-end check on
    // every record the subject emitted and every record it consumed.
    if (subject.lifecycle != .closed and !subject.carrier_eof) {
        // Stage one opens the write side only. Every drive here is a
        // *write-only* drive, so the carrier bytes it moves are the sole thing
        // that can justify `made_progress` -- which is what makes
        // `driveChecked`'s no-progress branch a real check rather than one a
        // concurrent read could satisfy on its behalf.
        carrier_state.read_script_len = 1;
        carrier_state.read_script[0] = .would_block;
        carrier_state.write_script_len = 1;
        carrier_state.write_script[0] = .{ .transfer = scripted_capture_capacity };
        var drain_rounds: usize = 0;
        while (oracle.terminal == null and drain_rounds < fuzz_stream_flush_rounds) : (drain_rounds += 1) {
            const result = try driveChecked(&subject, &carrier_state, &oracle) orelse break;
            try syncCapture(&carrier_state, &peer, &oracle);
            try checkStreamInvariants(&subject, &carrier_state);
            if (oracle.terminal != null or !result.made_progress) break;
        }
        try testing.expect(drain_rounds < fuzz_stream_flush_rounds);

        // Stage two opens the read side too and settles the whole stream.
        carrier_state.read_script[0] = .{ .transfer = scripted_inbound_capacity };
        var epilogue_rounds: usize = 0;
        while (oracle.terminal == null and epilogue_rounds < fuzz_stream_flush_rounds) : (epilogue_rounds += 1) {
            const before_received = oracle.subject_received;
            const result = try driveChecked(&subject, &carrier_state, &oracle) orelse break;
            try syncCapture(&carrier_state, &peer, &oracle);
            try subjectReadOnce(&subject, &oracle, &read_buf);
            try checkStreamInvariants(&subject, &carrier_state);
            if (oracle.terminal != null) break;
            if (!result.made_progress and oracle.subject_received == before_received) break;
        }
        try testing.expect(epilogue_rounds < fuzz_stream_flush_rounds);
    }

    if (oracle.terminal) |err| {
        try expectStableTerminal(&subject, &carrier_state, err);
        if (carrier_state.owns_handle) try testing.expectEqual(@as(usize, 1), carrier_state.close_calls);
        return;
    }

    // Outbound accounting: once nothing is queued or in flight, every plaintext
    // byte the subject accepted arrived at the peer exactly once.
    if ((oracle.peer_usable or peer.peer_closed) and
        subject.queuedCiphertextLen() == 0 and
        carrier_state.captured_len == 0)
    {
        try testing.expectEqual(oracle.subject_sent, oracle.peer_received);
    }
    // Inbound accounting: same, in the other direction, for a stream still open
    // (a completed close clears the owned queues by contract).
    if (subject.lifecycle == .open and
        carrier_state.inboundPending() == 0 and
        subject.inbound_carrier.len == 0 and
        subject.ciphertext_parser.len == 0 and
        subject.inbound_plaintext.len == 0)
    {
        try testing.expectEqual(oracle.peer_sent, oracle.subject_received);
    }

    if (subject.lifecycle == .closed) {
        for (0..3) |_| {
            try expectClosedConformance(subject.stream());
            try checkStreamInvariants(&subject, &carrier_state);
        }
        if (carrier_state.owns_handle) try testing.expectEqual(@as(usize, 1), carrier_state.close_calls);
    }
}

/// Root failures whose fatal alert `deferHandshakeFailure` queues and
/// `drive()` then flushes. Each one must survive the flush unchanged, however
/// the carrier behaves.
const fuzz_cleanup_root_errors = [_]Error{
    error.UnexpectedHandshakeMessage,
    error.CertificateInvalid,
    error.AlpnMismatch,
    error.IllegalParameter,
    error.MalformedHandshake,
    error.DecryptError,
    // No mapped alert: the failure must still latch unchanged.
    error.SecretExportFailed,
};

/// Enough drives for the slowest legal flush this target can script: a handful
/// of pre-queued handshake records draining at one byte per writable
/// notification, behind a script that only becomes writable one step in eight.
const fuzz_cleanup_max_drives = 4096;

test "fuzz: TLS record: encrypted stream cleanup preserves root errors across alerts and epoch transitions" {
    try testing.fuzz({}, fuzzEncryptedStreamCleanupInput, .{
        .corpus = &.{
            "",
            &[_]u8{0},
            // One entry per scenario family, plus a spread of script and
            // root-error selectors within each.
            &[_]u8{ 0, 0, 0, 0, 0, 0 },
            &[_]u8{ 0, 1, 1, 3, 2, 5 },
            &[_]u8{ 1, 0, 0, 2, 4 },
            &[_]u8{ 1, 1, 3, 0, 7 },
            &[_]u8{ 2, 0, 0, 0 },
            &[_]u8{ 2, 1, 5, 9 },
            &[_]u8{ 3, 0, 1, 2, 3 },
            &[_]u8{ 3, 1, 0, 0, 0, 0 },
            &([_]u8{0} ** 32),
            &([_]u8{0xff} ** 32),
            &([_]u8{ 0, 1, 2, 3 } ** 8),
        },
    });
}

fn fuzzEncryptedStreamCleanupInput(_: void, smith: *std.testing.Smith) !void {
    const pure_zig = crypto.pure_zig;
    var entropy = pure_zig.DeterministicEntropy.init(0x493f);
    var provider_state = pure_zig.Provider.init(entropy.entropy());
    const cp = provider_state.cryptoProvider();

    const suite: algorithms.CipherSuite = switch (smith.index(3)) {
        0 => .tls_aes_128_gcm_sha256,
        1 => .tls_aes_256_gcm_sha384,
        else => .tls_chacha20_poly1305_sha256,
    };

    // Every family runs in every case rather than one being selected per case.
    // A `smith.index(4)` selector here looked reasonable but left three of the
    // four families unreached by the deterministic seed-corpus replay -- every
    // checked-in entry resolved to the same branch -- so the properties they
    // own were only ever checked under a coverage-guided run. Each family
    // builds its own streams and carrier and draws its own Smith values, so
    // running them in sequence keeps every case deterministic.
    try cleanupDeferredAlertCase(smith, cp, suite);
    try cleanupAuthenticationFailureCase(smith, cp, suite);
    try cleanupEpochTransitionCase(smith, cp, suite);
    try cleanupTeardownCase(smith, cp, suite);
}

/// A terminal handshake failure whose fatal alert is flushed to a scripted
/// carrier that may progress partially, block, make no progress, or fail. The
/// preserved root error must latch unchanged in every case, within the bounded
/// flush deadline, leaving no secret-bearing state behind.
fn cleanupDeferredAlertCase(smith: *std.testing.Smith, cp: provider.CryptoProvider, suite: algorithms.CipherSuite) !void {
    var carrier_state = ScriptedCarrier{ .owns_handle = smith.index(2) == 0 };
    carrier_state.write_script_len = scriptFromSmith(smith, &carrier_state.write_script, scripted_capture_capacity);
    carrier_state.read_script_len = 1;
    carrier_state.read_script[0] = .would_block;

    var subject = PureZigRecordStream.initWithCarrier(.client, cp, suite, carrier_state.carrier());
    defer subject.deinit();

    // Half the cases queue the alert under real handshake write keys (a
    // protected alert record) behind zero or more earlier handshake records, so
    // the flush has to drain more than the deadline's worth of bytes; the rest
    // leave the write epoch at `.initial`, where the alert is a plaintext
    // record.
    if (smith.index(2) == 0) {
        const secret_len = algorithms.transcriptHash(suite).digestLength();
        const handshake_secret = wideSecret(0x5a);
        try subject.bridge.installTrafficSecret(.handshake, .write, handshake_secret[0..secret_len]);
        subject.write_epoch = .handshake;
        for (0..smith.index(4)) |_| {
            var record_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
            const record = try subject.bridge.sealHandshake(.handshake, "queued-before-alert", &record_buf);
            subject.outbound_ciphertext.append(record) catch break;
        }
    }

    const root = fuzz_cleanup_root_errors[smith.index(fuzz_cleanup_root_errors.len)];
    subject.deferHandshakeFailure(root, null);
    try testing.expectEqual(@as(?Error, root), subject.pending_terminal);
    const queued_before_flush = subject.queuedCiphertextLen();

    var oracle = StreamOracle{};
    var drives: usize = 0;
    while (oracle.terminal == null and drives < fuzz_cleanup_max_drives) : (drives += 1) {
        const result = try driveChecked(&subject, &carrier_state, &oracle) orelse break;
        try checkStreamInvariants(&subject, &carrier_state);
        // Until it latches, the stream advertises only the write it needs to
        // finish the flush -- no new reads and no plaintext I/O.
        if (subject.pending_terminal != null) {
            try testing.expect(!result.readiness.wants_read);
            try testing.expect(!result.readiness.can_read_plaintext);
            try testing.expect(!result.readiness.can_write_plaintext);
        }
    }

    // The root error latched, and a partial, blocked, zero-progress, or failing
    // alert write never replaced it.
    try testing.expectEqual(@as(?anyerror, root), oracle.terminal);
    try testing.expectEqual(Lifecycle.failed, subject.lifecycle);
    // Flush attempts stay bounded: no byte can leave the queue more than once,
    // and a carrier that never drains hits the deadline instead of wedging.
    try testing.expect(carrier_state.write_bytes <= queued_before_flush);
    try testing.expect(drives < fuzz_cleanup_max_drives);
    try expectStableTerminal(&subject, &carrier_state, root);
    if (carrier_state.owns_handle) try testing.expectEqual(@as(usize, 1), carrier_state.close_calls);
}

/// A record-layer authentication failure behind (optionally) already-delivered
/// plaintext: the failure must latch, must never yield the tampered record's
/// contents, and must clear every owned buffer.
fn cleanupAuthenticationFailureCase(smith: *std.testing.Smith, cp: provider.CryptoProvider, suite: algorithms.CipherSuite) !void {
    var carrier_state = ScriptedCarrier{ .owns_handle = smith.index(2) == 0 };
    carrier_state.read_script_len = scriptFromSmith(smith, &carrier_state.read_script, scripted_inbound_capacity);
    carrier_state.write_script_len = 1;
    carrier_state.write_script[0] = .{ .transfer = scripted_capture_capacity };
    // A scripted read failure or EOF would pre-empt the tampered record with a
    // different terminal error; this case is about the authentication path.
    for (carrier_state.read_script[0..carrier_state.read_script_len]) |*action| {
        switch (action.*) {
            .end_of_stream, .fail, .zero => action.* = .would_block,
            else => {},
        }
    }
    // ...and at least one step must move bytes, so the tampered record is
    // actually reachable rather than blocked forever.
    carrier_state.read_script[0] = .{ .transfer = scripted_inbound_capacity };

    var peer = PureZigRecordStream.init(.client, cp, suite);
    defer peer.deinit();
    var subject = PureZigRecordStream.initWithCarrier(.server, cp, suite, carrier_state.carrier());
    defer subject.deinit();
    try establishForSuite(&peer, &subject, suite);

    var oracle = StreamOracle{};
    var read_buf: [fuzz_stream_max_read_buf]u8 = undefined;

    // Stage one: genuine plaintext, driven all the way *through* to the
    // application before the tampered record is ever queued. Staging matters --
    // queuing the prelude and the tampered record together lets a single
    // `drive()` open both, and `fail()` clears `inbound_plaintext` before the
    // caller can read any of it, so the case would never exercise the scenario
    // it is named for: an authentication failure landing *behind*
    // already-delivered plaintext.
    for (0..1 + smith.index(2)) |_| {
        try enqueuePeerRecord(&peer, &carrier_state, &oracle, 1 + smith.index(fuzz_stream_peer_chunk));
    }
    try testing.expect(oracle.peer_sent > 0);

    var prelude_rounds: usize = 0;
    while (oracle.subject_received < oracle.peer_sent and prelude_rounds < 64) : (prelude_rounds += 1) {
        _ = try driveChecked(&subject, &carrier_state, &oracle) orelse break;
        try subjectReadOnce(&subject, &oracle, &read_buf);
        try checkStreamInvariants(&subject, &carrier_state);
    }
    try testing.expect(prelude_rounds < 64);
    try testing.expectEqual(@as(?anyerror, null), oracle.terminal);
    try testing.expectEqual(oracle.peer_sent, oracle.subject_received);
    try testing.expect(oracle.subject_received > 0);
    // ...and the read sequence really advanced on that genuine traffic, so the
    // failure below lands on a live, already-used read state.
    try testing.expect(subject.bridge.read_application.?.sequence > 0);

    // Stage two: the next record in sequence, with one byte of its payload
    // flipped. The AEAD
    // authenticates the header as associated data and the payload as
    // ciphertext-plus-tag, so a payload mutation is always an authentication
    // failure rather than a framing error.
    //
    // Its plaintext is the bitwise *complement* of what the generated stream
    // would carry next, and `oracle.peer_sent` is deliberately not advanced for
    // it: this record's content is never legitimate output, so if any byte of
    // it ever reached the application, `subjectReadOnce`'s per-byte check would
    // reject it rather than mistake it for the stream continuing.
    //
    // Every step of this construction is deterministic once the family is
    // selected: the peer is open with a drained outbound queue, one sealed
    // record is at most `header + chunk + type + tag` bytes, and the inbound
    // queue is empty again after stage one. Nothing here may quietly return
    // and let the case pass without testing the property it is named for.
    const content_len = 1 + smith.index(fuzz_stream_peer_chunk);
    var content: [fuzz_stream_peer_chunk]u8 = undefined;
    for (content[0..content_len], 0..) |*byte, i| byte.* = ~peerStreamByte(oracle.peer_sent + i);
    try testing.expectEqual(content_len, try peer.writePlaintext(content[0..content_len]));
    var record_buf: [256]u8 = undefined;
    const record_len = try peer.drainCiphertext(&record_buf);
    try testing.expectEqual(@as(usize, 0), peer.queuedCiphertextLen());
    try testing.expect(record_len > record_codec.header_len);
    const offset = record_codec.header_len + smith.index(record_len - record_codec.header_len);
    record_buf[offset] ^= @as(u8, 1) << @intCast(smith.index(8));
    try testing.expect(carrier_state.pushInbound(record_buf[0..record_len]));

    var drives: usize = 0;
    while (oracle.terminal == null and drives < 256) : (drives += 1) {
        const result = try driveChecked(&subject, &carrier_state, &oracle) orelse break;
        try subjectReadOnce(&subject, &oracle, &read_buf);
        try checkStreamInvariants(&subject, &carrier_state);
        if (oracle.terminal != null) break;
        if (!result.made_progress and carrier_state.inboundPending() == 0) break;
    }
    try testing.expect(drives < 256);

    // The tampered record always reaches the bridge -- the read script's first
    // step is forced to transfer and the inbound queue holds only this record --
    // so the outcome is unconditional.
    try testing.expectEqual(@as(?anyerror, error.AuthenticationFailed), oracle.terminal);
    // The genuine plaintext delivered in stage one stays exactly accounted for
    // across the failure: nothing was retroactively unmade, and not one byte of
    // the tampered record reached the application. `subjectReadOnce` checks
    // every delivered byte against the generated stream, and this record's
    // plaintext is the complement of it, so a leak could not pass as the stream
    // continuing.
    try testing.expectEqual(oracle.peer_sent, oracle.subject_received);
    try expectStableTerminal(&subject, &carrier_state, error.AuthenticationFailed);
    if (carrier_state.owns_handle) try testing.expectEqual(@as(usize, 1), carrier_state.close_calls);
}

/// A `.handshake` epoch discard landing on a not-yet-complete buffered record.
/// The transition must fail closed rather than let those bytes be reinterpreted
/// under application keys.
fn cleanupEpochTransitionCase(smith: *std.testing.Smith, cp: provider.CryptoProvider, suite: algorithms.CipherSuite) !void {
    var carrier_state = ScriptedCarrier{ .owns_handle = smith.index(2) == 0 };
    carrier_state.read_script_len = 1;
    carrier_state.read_script[0] = .would_block;
    carrier_state.write_script_len = 1;
    carrier_state.write_script[0] = .would_block;

    var subject = PureZigRecordStream.initWithCarrier(.server, cp, suite, carrier_state.carrier());
    defer subject.deinit();

    const secret_len = algorithms.transcriptHash(suite).digestLength();
    const handshake_read = wideSecret(0x51);
    const handshake_write = wideSecret(0x52);
    const application_read = wideSecret(0x53);
    const application_write = wideSecret(0x54);
    try subject.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .read, .data = handshake_read[0..secret_len] } });
    try subject.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .write, .data = handshake_write[0..secret_len] } });
    try subject.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .read, .data = application_read[0..secret_len] } });
    try subject.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .write, .data = application_write[0..secret_len] } });

    // A record header declaring more payload than is delivered. `feedOne`'s
    // exact-consumption contract means a nonzero parser length here can only be
    // a genuinely incomplete record, never a legitimate next-record suffix.
    const declared: usize = 1 + smith.index(64);
    // Strictly fewer payload bytes than declared, so the record can never
    // complete and be opened; the parser is left holding a genuine partial.
    const delivered = smith.index(declared);
    var wire: [record_codec.header_len + 64]u8 = undefined;
    wire[0] = @intFromEnum(record_codec.ContentType.application_data);
    wire[1] = 0x03;
    wire[2] = 0x03;
    wire[3] = @intCast(declared >> 8);
    wire[4] = @intCast(declared & 0xff);
    for (wire[record_codec.header_len..][0..delivered], 0..) |*byte, i| byte.* = @truncate(i *% 7 +% 3);
    // ...and how much of that prefix actually arrives, from none of it (which
    // leaves the parser empty, the legal-discard control case) through a split
    // header to the whole incomplete prefix.
    const feed_len = smith.index(record_codec.header_len + delivered + 1);
    _ = try subject.feedHandshakeCiphertext(.handshake, wire[0..feed_len]);

    const partial = subject.ciphertext_parser.len != 0;
    const result = subject.applyEvent(.{ .discard_epoch = .handshake });
    if (partial) {
        try testing.expectError(error.PartialRecordAtEpochTransition, result);
        // Latched, cleared, and stable: the buffered prefix cannot be resumed
        // or reinterpreted under application keys by any later call.
        try expectStableTerminal(&subject, &carrier_state, error.PartialRecordAtEpochTransition);
        try testing.expectError(error.PartialRecordAtEpochTransition, subject.applyEvent(.handshake_complete));
        try testing.expectError(error.PartialRecordAtEpochTransition, subject.feedCiphertext(wire[0..feed_len]));
        if (carrier_state.owns_handle) try testing.expectEqual(@as(usize, 1), carrier_state.close_calls);
    } else {
        try result;
        try testing.expectEqual(@as(?Error, null), subject.failed);
        try testing.expect(!subject.bridge.hasReadKeys(.handshake));
        try testing.expect(!subject.bridge.hasWriteKeys(.handshake));
        try checkStreamInvariants(&subject, &carrier_state);
    }
}

/// Teardown with every owned buffer, both parsers, and a pending terminal state
/// populated *at once*. Each of those states is dirtied deterministically and
/// asserted nonzero immediately before `deinit()`, so the zeroization checks
/// that follow cannot pass vacuously against storage that was never written.
fn cleanupTeardownCase(smith: *std.testing.Smith, cp: provider.CryptoProvider, suite: algorithms.CipherSuite) !void {
    var carrier_state = ScriptedCarrier{ .owns_handle = smith.index(2) == 0 };
    // Both directions blocked, so nothing this case queues can drain before
    // teardown observes it.
    carrier_state.read_script_len = 1;
    carrier_state.read_script[0] = .would_block;
    carrier_state.write_script_len = 1;
    carrier_state.write_script[0] = .would_block;

    var subject = PureZigRecordStream.initWithCarrier(.server, cp, suite, carrier_state.carrier());
    defer subject.deinit();

    const secret_len = algorithms.transcriptHash(suite).digestLength();
    const client_hs = wideSecret(0x61);
    const server_hs = wideSecret(0x62);
    try subject.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .read, .data = client_hs[0..secret_len] } });
    try subject.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .write, .data = server_hs[0..secret_len] } });
    subject.write_epoch = .handshake;

    // Outbound ciphertext: sealed handshake records the blocked carrier cannot
    // drain.
    for (0..1 + smith.index(3)) |_| {
        try subject.applyEvent(.{ .handshake_bytes = .{ .epoch = .handshake, .data = "server-handshake-flight" } });
    }

    // Both parsers dirty simultaneously: a partial plaintext record buffered at
    // the initial epoch and a partial protected record buffered at the
    // handshake epoch. `feedOne`'s exact-consumption contract means a nonzero
    // length in either can only be a genuinely incomplete record.
    const initial_partial = [_]u8{ @intFromEnum(record_codec.ContentType.handshake), 0x03, 0x03 };
    _ = try subject.feedHandshakeCiphertext(.initial, initial_partial[0 .. 1 + smith.index(initial_partial.len)]);
    const protected_partial = [_]u8{
        @intFromEnum(record_codec.ContentType.application_data),
        0x03,
        0x03,
        0x00,
        0x10,
        0x01,
        0x02,
        0x03,
    };
    _ = try subject.feedHandshakeCiphertext(
        .handshake,
        protected_partial[0 .. record_codec.header_len + 1 + smith.index(3)],
    );

    // Inbound plaintext with its provenance shadow, inbound handshake bytes,
    // and carrier input the read budget has not reached. These go through the
    // stream's own append accessors so the provenance shadow stays in step.
    // Normal lifecycle rules cannot leave every one of these nonzero at the
    // same instant; the property under test is that teardown zeroes *nonzero*
    // owned storage, so dirtying it directly is the point.
    var filler: [128]u8 = undefined;
    for (&filler, 0..) |*byte, i| byte.* = @truncate(i +% 1);
    // The provenance shadow has to be dirtied with `true`: `false` is its
    // *cleared* value, so an all-`false` shadow would leave the post-teardown
    // all-`false` assertion vacuous and a broken `PlaintextProvenanceQueue`
    // teardown invisible. A second span carries the other value so both are
    // represented.
    const early_len = 1 + smith.index(filler.len);
    try subject.appendInboundPlaintext(filler[0..early_len], true);
    if (early_len < filler.len) try subject.appendInboundPlaintext(filler[early_len..], false);
    try subject.appendInboundHandshake(&filler);
    try subject.appendInboundCarrier(&filler);

    // ...and a pending terminal alert the blocked carrier is still holding.
    subject.deferHandshakeFailure(error.CertificateInvalid, null);

    // Preconditions: every state whose zeroization is asserted below really is
    // nonzero right now.
    try testing.expect(subject.inbound_carrier.len > 0);
    try testing.expect(subject.inbound_plaintext.len > 0);
    try testing.expect(subject.inbound_plaintext_provenance.len > 0);
    // ...and genuinely nonzero, not merely non-empty: this is the exact
    // negation of the post-teardown check.
    try testing.expect(!std.mem.allEqual(
        bool,
        subject.inbound_plaintext_provenance.buf[0..subject.inbound_plaintext_provenance.len],
        false,
    ));
    try testing.expect(subject.inbound_handshake.len > 0);
    try testing.expect(subject.outbound_ciphertext.len > 0);
    try testing.expect(subject.initial_parser.len > 0);
    try testing.expect(subject.ciphertext_parser.len > 0);
    try testing.expect(subject.pending_terminal != null);
    try testing.expect(subject.bridge.hasReadKeys(.handshake));
    try testing.expect(subject.bridge.hasWriteKeys(.handshake));

    subject.deinit();

    try expectTeardownMetadataCleared(&subject);
    try testing.expectEqual(Lifecycle.closed, subject.lifecycle);
    if (carrier_state.owns_handle) try testing.expectEqual(@as(usize, 1), carrier_state.close_calls);
    for (0..3) |_| {
        try expectClosedConformance(subject.stream());
        try checkStreamInvariants(&subject, &carrier_state);
    }
    // Repeated teardown neither double-releases the handle nor resurrects state.
    subject.deinit();
    subject.deinit();
    try testing.expect(carrier_state.close_calls <= 1);
    try expectTeardownMetadataCleared(&subject);
}

// ── #493-C named deterministic companions ──────────────────────────────────
//
// The scripted corpus classes the issue requires that CI's seed-corpus replay
// cannot reliably reach, pinned as named tests next to the fuzz targets --
// following the standard #493-A set for `encodeInnerPlaintext` and #493-B for
// the epoch lifecycle. `-Dtls-record-test-filter` selects these by name too.

/// Bring up a scripted-carrier subject and a keyed peer for a companion case.
const CompanionPair = struct {
    peer: PureZigRecordStream,
    subject: PureZigRecordStream,

    fn init(cp: provider.CryptoProvider, carrier_state: *ScriptedCarrier) !CompanionPair {
        var pair = CompanionPair{
            .peer = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256),
            .subject = PureZigRecordStream.initWithCarrier(.server, cp, .tls_aes_128_gcm_sha256, carrier_state.carrier()),
        };
        try establish(&pair.peer, &pair.subject);
        return pair;
    }

    fn deinit(self: *CompanionPair) void {
        self.peer.deinit();
        self.subject.deinit();
    }
};

/// Drive, sync, and read until the stream settles or latches. Returns the
/// number of rounds it took; exceeding the bound is a failure.
fn runCompanionUntilSettled(
    subject: *PureZigRecordStream,
    peer: *PureZigRecordStream,
    carrier_state: *ScriptedCarrier,
    oracle: *StreamOracle,
    read_buf: []u8,
) !usize {
    var rounds: usize = 0;
    while (oracle.terminal == null and rounds < 8192) : (rounds += 1) {
        const result = try driveChecked(subject, carrier_state, oracle) orelse break;
        try syncCapture(carrier_state, peer, oracle);
        try subjectReadOnce(subject, oracle, read_buf);
        try checkStreamInvariants(subject, carrier_state);
        if (oracle.terminal != null) break;
        if (!result.made_progress and
            subject.inbound_plaintext.len == 0 and
            carrier_state.inboundPending() == 0 and
            carrier_state.captured_len == 0) break;
    }
    try testing.expect(rounds < 8192);
    return rounds;
}

test "encrypted stream scripted carrier delivers every byte across one-byte reads and writes" {
    const cp = testProvider();
    var carrier_state = ScriptedCarrier{};
    carrier_state.read_script_len = 1;
    carrier_state.read_script[0] = .{ .transfer = 1 };
    carrier_state.write_script_len = 1;
    carrier_state.write_script[0] = .{ .transfer = 1 };

    var pair = try CompanionPair.init(cp, &carrier_state);
    defer pair.deinit();

    var oracle = StreamOracle{};
    for (0..3) |_| try enqueuePeerRecord(&pair.peer, &carrier_state, &oracle, 40);
    var src: [97]u8 = undefined;
    try subjectWriteOnce(&pair.subject, &oracle, &src);
    try testing.expectEqual(@as(usize, 97), oracle.subject_sent);

    var read_buf: [1]u8 = undefined;
    _ = try runCompanionUntilSettled(&pair.subject, &pair.peer, &carrier_state, &oracle, &read_buf);

    try testing.expectEqual(@as(?anyerror, null), oracle.terminal);
    // Every byte, both directions, exactly once, through single-byte carrier
    // transfers in both directions.
    try testing.expectEqual(oracle.peer_sent, oracle.subject_received);
    try testing.expectEqual(oracle.subject_sent, oracle.peer_received);
    try testing.expectEqual(@as(usize, 120), oracle.subject_received);
}

test "encrypted stream settles without spinning under repeated would-block and zero-progress carriers" {
    const cp = testProvider();
    // A zero-byte carrier *read* is EOF by contract, so only the write side
    // varies between the two permanent no-progress conditions.
    inline for (.{ CarrierAction.would_block, CarrierAction.zero }) |write_action| {
        var carrier_state = ScriptedCarrier{};
        carrier_state.read_script_len = 1;
        carrier_state.read_script[0] = .would_block;
        carrier_state.write_script_len = 1;
        carrier_state.write_script[0] = write_action;

        var pair = try CompanionPair.init(cp, &carrier_state);
        defer pair.deinit();

        var oracle = StreamOracle{};
        var src: [64]u8 = undefined;
        try subjectWriteOnce(&pair.subject, &oracle, &src);
        const queued = pair.subject.queuedCiphertextLen();
        try testing.expect(queued > 0);

        var previous: ?Readiness = null;
        for (0..64) |_| {
            const calls_before = carrier_state.read_calls + carrier_state.write_calls;
            const result = (try driveChecked(&pair.subject, &carrier_state, &oracle)).?;
            // No progress is claimed, no byte moves, the queue is unchanged,
            // and readiness is stable across every repetition.
            try testing.expect(!result.made_progress);
            try testing.expectEqual(queued, pair.subject.queuedCiphertextLen());
            try testing.expectEqual(@as(usize, 0), carrier_state.write_bytes);
            try testing.expectEqual(@as(usize, 0), carrier_state.read_bytes);
            // ...and the work inside one `drive()` stays constant: the two
            // write loops and the read loop each give up after one call.
            try testing.expect(carrier_state.read_calls + carrier_state.write_calls - calls_before <= 4);
            if (previous) |prev| try testing.expectEqual(prev, result.readiness);
            previous = result.readiness;
        }
        try testing.expect(previous.?.wants_write);
        try testing.expectEqual(@as(?anyerror, null), oracle.terminal);
    }
}

test "encrypted stream carrier EOF at every record boundary preserves truncation and delivery order" {
    const cp = testProvider();
    // One complete record's worth of bytes, cut at each boundary the issue
    // names: before the record, inside the five-byte header, inside the
    // payload, one byte short, and exactly after a complete record.
    var template = ScriptedCarrier{};
    var template_pair = try CompanionPair.init(cp, &template);
    defer template_pair.deinit();
    var template_oracle = StreamOracle{};
    try enqueuePeerRecord(&template_pair.peer, &template, &template_oracle, 32);
    const record_len = template.inboundPending();
    try testing.expect(record_len > record_codec.header_len + 1);
    var record: [256]u8 = undefined;
    @memcpy(record[0..record_len], template.inbound[0..record_len]);

    const cuts = [_]usize{
        0,
        3,
        record_codec.header_len,
        record_codec.header_len + 1,
        record_len - 1,
        record_len,
    };
    for (cuts) |cut| {
        var carrier_state = ScriptedCarrier{};
        carrier_state.read_script_len = 2;
        carrier_state.read_script[0] = .{ .transfer = scripted_inbound_capacity };
        carrier_state.read_script[1] = .end_of_stream;
        carrier_state.write_script_len = 1;
        carrier_state.write_script[0] = .{ .transfer = scripted_capture_capacity };

        var pair = try CompanionPair.init(cp, &carrier_state);
        defer pair.deinit();
        // The same generated plaintext the template record carries, so
        // `subjectReadOnce`'s byte check applies to this pair too.
        var oracle = StreamOracle{ .peer_sent = 32 };
        try testing.expect(carrier_state.pushInbound(record[0..cut]));

        var read_buf: [64]u8 = undefined;
        var rounds: usize = 0;
        while (oracle.terminal == null and rounds < 64) : (rounds += 1) {
            // Deliberately no early exit on a no-progress round: the read
            // script only reaches its `end_of_stream` step on a later call, so
            // stopping at the first would-block would never see the EOF.
            _ = try driveChecked(&pair.subject, &carrier_state, &oracle) orelse break;
            try subjectReadOnce(&pair.subject, &oracle, &read_buf);
            try checkStreamInvariants(&pair.subject, &carrier_state);
        }
        try testing.expect(rounds < 64);

        // Truncation is terminal in every case: an unclean EOF is never a
        // clean close.
        try testing.expectEqual(@as(?anyerror, error.TruncatedStream), oracle.terminal);
        try expectStableTerminal(&pair.subject, &carrier_state, error.TruncatedStream);
        if (cut == record_len) {
            // A complete record ahead of the EOF is delivered first, and only
            // then is the preserved truncation surfaced.
            try testing.expectEqual(@as(usize, 32), oracle.subject_received);
        } else {
            // A partial record yields nothing: no unauthenticated prefix leaks.
            try testing.expectEqual(@as(usize, 0), oracle.subject_received);
        }
    }
}

test "encrypted stream partial carrier writes preserve the exact unwritten suffix" {
    const cp = testProvider();
    var carrier_state = ScriptedCarrier{};
    carrier_state.read_script_len = 1;
    carrier_state.read_script[0] = .would_block;
    // One byte accepted, then blocked: every drive leaves a partially written
    // record behind.
    carrier_state.write_script_len = 2;
    carrier_state.write_script[0] = .{ .transfer = 1 };
    carrier_state.write_script[1] = .would_block;

    var pair = try CompanionPair.init(cp, &carrier_state);
    defer pair.deinit();

    var oracle = StreamOracle{};
    var src: [200]u8 = undefined;
    try subjectWriteOnce(&pair.subject, &oracle, &src);

    var expected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const total = pair.subject.queuedCiphertextLen();
    @memcpy(expected[0..total], pair.subject.peekCiphertext());
    try testing.expect(total > 8);

    var rounds: usize = 0;
    while (carrier_state.write_bytes < total and rounds < 4 * total) : (rounds += 1) {
        _ = (try driveChecked(&pair.subject, &carrier_state, &oracle)).?;
        const moved = carrier_state.write_bytes;
        // The written prefix is exact and the retained suffix is byte-identical
        // to what was queued: a partial write discards only what the carrier
        // actually accepted.
        try testing.expectEqualSlices(u8, expected[0..moved], carrier_state.captureSlice());
        try testing.expectEqualSlices(u8, expected[moved..total], pair.subject.peekCiphertext());
    }
    try testing.expectEqual(total, carrier_state.write_bytes);
    // ...and the reassembled record still opens at the peer.
    try syncCapture(&carrier_state, &pair.peer, &oracle);
    try testing.expectEqual(oracle.subject_sent, oracle.peer_received);
}

test "encrypted stream output saturation pauses plaintext writes and resumes below the low watermark" {
    const cp = testProvider();
    var carrier_state = ScriptedCarrier{};
    carrier_state.read_script_len = 1;
    carrier_state.read_script[0] = .would_block;
    carrier_state.write_script_len = 1;
    carrier_state.write_script[0] = .would_block;

    var pair = try CompanionPair.init(cp, &carrier_state);
    defer pair.deinit();

    var oracle = StreamOracle{};
    var src: [record_codec.max_plaintext_fragment_len]u8 = undefined;
    var accepted: usize = 0;
    var attempts: usize = 0;
    while (attempts < 16) : (attempts += 1) {
        const before = oracle.subject_sent;
        try subjectWriteOnce(&pair.subject, &oracle, &src);
        if (oracle.subject_sent == before) break;
        accepted += 1;
    }
    try testing.expect(accepted > 0);
    try testing.expect(attempts < 16);

    const paused = pair.subject.bufferSnapshot();
    try testing.expect(paused.pause_state.plaintext_write_paused);
    // Exactly one pause for one threshold crossing, and no resume yet.
    try testing.expectEqual(@as(u64, 1), paused.counters.plaintext_write_pauses);
    try testing.expectEqual(@as(u64, 0), paused.counters.plaintext_write_resumes);
    try testing.expect(!pair.subject.readiness().can_write_plaintext);
    // A rejected retry consumes nothing.
    const queued_when_paused = pair.subject.queuedCiphertextLen();
    try testing.expectError(error.WouldBlock, pair.subject.stream().write(&src));
    try testing.expectEqual(queued_when_paused, pair.subject.queuedCiphertextLen());
    try testing.expectEqual(@as(u64, 1), pair.subject.bufferSnapshot().counters.plaintext_write_pauses);

    // Drain below the low watermark and the stream resumes exactly once.
    carrier_state.write_script[0] = .{ .transfer = scripted_capture_capacity };
    var rounds: usize = 0;
    while (pair.subject.bufferSnapshot().pause_state.plaintext_write_paused and rounds < 256) : (rounds += 1) {
        _ = (try driveChecked(&pair.subject, &carrier_state, &oracle)).?;
        try syncCapture(&carrier_state, &pair.peer, &oracle);
        try checkStreamInvariants(&pair.subject, &carrier_state);
    }
    try testing.expect(rounds < 256);
    const resumed = pair.subject.bufferSnapshot();
    try testing.expect(!resumed.pause_state.plaintext_write_paused);
    try testing.expectEqual(@as(u64, 1), resumed.counters.plaintext_write_pauses);
    try testing.expectEqual(@as(u64, 1), resumed.counters.plaintext_write_resumes);
    try testing.expect(pair.subject.readiness().can_write_plaintext);

    // Drain everything still queued or in flight, then check that no byte was
    // lost or duplicated across the whole pause/resume cycle.
    var drains: usize = 0;
    while (drains < 4096 and (pair.subject.queuedCiphertextLen() != 0 or carrier_state.captured_len != 0)) : (drains += 1) {
        _ = (try driveChecked(&pair.subject, &carrier_state, &oracle)).?;
        try syncCapture(&carrier_state, &pair.peer, &oracle);
        try checkStreamInvariants(&pair.subject, &carrier_state);
    }
    try testing.expect(drains < 4096);
    try testing.expectEqual(oracle.subject_sent, oracle.peer_received);
}

test "encrypted stream inbound plaintext saturation pauses carrier reads and resumes after draining" {
    const cp = testProvider();
    var carrier_state = ScriptedCarrier{};
    carrier_state.read_script_len = 1;
    carrier_state.read_script[0] = .{ .transfer = scripted_inbound_capacity };
    carrier_state.write_script_len = 1;
    carrier_state.write_script[0] = .{ .transfer = scripted_capture_capacity };

    var pair = try CompanionPair.init(cp, &carrier_state);
    defer pair.deinit();

    var oracle = StreamOracle{};
    var rounds: usize = 0;
    while (!pair.subject.bufferSnapshot().pause_state.inbound_read_paused and rounds < 512) : (rounds += 1) {
        while (carrier_state.inboundAvailable() > 4 * record_codec.header_len + 2 * fuzz_stream_peer_chunk) {
            const before = oracle.peer_sent;
            try enqueuePeerRecord(&pair.peer, &carrier_state, &oracle, fuzz_stream_peer_chunk);
            if (oracle.peer_sent == before) break;
        }
        _ = (try driveChecked(&pair.subject, &carrier_state, &oracle)).?;
        try checkStreamInvariants(&pair.subject, &carrier_state);
    }
    try testing.expect(rounds < 512);

    const paused = pair.subject.bufferSnapshot();
    try testing.expect(paused.pause_state.inbound_read_paused);
    try testing.expectEqual(@as(u64, 1), paused.counters.inbound_read_pauses);
    try testing.expectEqual(@as(u64, 0), paused.counters.inbound_read_resumes);
    try testing.expect(!pair.subject.readiness().wants_read);

    // Drain the plaintext below the low watermark: reads resume exactly once,
    // and every buffered byte is still the peer's, in order.
    var read_buf: [fuzz_stream_max_read_buf]u8 = undefined;
    var drains: usize = 0;
    while (pair.subject.bufferSnapshot().pause_state.inbound_read_paused and drains < 4096) : (drains += 1) {
        try subjectReadOnce(&pair.subject, &oracle, &read_buf);
        _ = (try driveChecked(&pair.subject, &carrier_state, &oracle)).?;
        try checkStreamInvariants(&pair.subject, &carrier_state);
    }
    try testing.expect(drains < 4096);
    const resumed = pair.subject.bufferSnapshot();
    try testing.expect(!resumed.pause_state.inbound_read_paused);
    try testing.expectEqual(@as(u64, 1), resumed.counters.inbound_read_pauses);
    try testing.expectEqual(@as(u64, 1), resumed.counters.inbound_read_resumes);
    try testing.expectEqual(@as(?anyerror, null), oracle.terminal);
}

test "encrypted stream orderly close releases the handshake driver and its secret scratch" {
    const cp = testProvider();

    // A completed session, closed cleanly. This is the `finishClose` path
    // `drive()` takes once `close_notify` has drained.
    {
        var duplex = Duplex{ .max_chunk = record_codec.max_ciphertext_record_len };
        var client_backend = ScriptedRecordBackend{ .role = .client };
        var server_backend = ScriptedRecordBackend{ .role = .server };
        var client = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .client, cp, .tls_aes_128_gcm_sha256, duplex.clientCarrier(), client_backend.recordBackend());
        defer client.deinit();
        var server = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .server, cp, .tls_aes_128_gcm_sha256, duplex.serverCarrier(), server_backend.recordBackend());
        defer server.deinit();

        try driveBothUntil(&client, &server, bothComplete);
        try testing.expect(client.bridge.hasWriteKeys(.application));
        // The driver's borrowed sink copied traffic-secret bytes into its
        // scratch during the handshake; that is the state teardown must wipe.
        const used_before = client.handshake_driver.?.sink.used;
        try testing.expect(used_before > 0);
        try testing.expect(!client.driver_torn_down);
        try testing.expectEqual(@as(usize, 0), client_backend.deinit_count);

        client.stream().close();
        var rounds: usize = 0;
        while (client.lifecycle != .closed and rounds < 64) : (rounds += 1) {
            _ = try client.stream().drive();
            _ = try server.stream().drive();
        }
        try testing.expect(rounds < 64);

        // The orderly close released the driver and its backend exactly once,
        // wiped the sink's used secret scratch, and dropped every bridge key --
        // without waiting for an outer `deinit()`.
        try testing.expect(client.driver_torn_down);
        try testing.expectEqual(@as(usize, 1), client_backend.deinit_count);
        try testing.expectEqual(@as(usize, 0), client.handshake_driver.?.sink.used);
        try testing.expect(std.mem.allEqual(u8, client.handshake_driver.?.sink.scratch[0..used_before], 0));
        try testing.expect(!client.bridge.hasReadKeys(.application));
        try testing.expect(!client.bridge.hasWriteKeys(.application));
        try expectClosedConformance(client.stream());

        // ...and the later `deinit()` does not release the backend a second
        // time (`Driver.deinit` is not idempotent).
        client.deinit();
        try testing.expectEqual(@as(usize, 1), client_backend.deinit_count);
    }

    // Cancellation before the handshake completes takes the other
    // `finishClose` path, through `queueCloseNotify`'s unkeyed branch.
    inline for (.{ true, false }) |install_keys| {
        var backend = CountingRecordBackend{ .install_keys = install_keys };
        var carrier = CountingOwnedCarrier{};
        var stream = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .client, cp, .tls_aes_128_gcm_sha256, carrier.carrier(), backend.recordBackend());
        defer stream.deinit();

        _ = try stream.stream().drive();
        const used_before = stream.handshake_driver.?.sink.used;
        try testing.expect(used_before > 0);

        stream.stream().close();
        _ = try stream.stream().drive();
        try testing.expectEqual(Lifecycle.closed, stream.lifecycle);
        try testing.expect(stream.driver_torn_down);
        try testing.expectEqual(@as(usize, 1), backend.deinit_count);
        try testing.expectEqual(@as(usize, 1), carrier.close_count);
        try testing.expectEqual(@as(usize, 0), stream.handshake_driver.?.sink.used);
        try testing.expect(std.mem.allEqual(u8, stream.handshake_driver.?.sink.scratch[0..used_before], 0));

        stream.deinit();
        try testing.expectEqual(@as(usize, 1), backend.deinit_count);
        try testing.expectEqual(@as(usize, 1), carrier.close_count);
    }
}

test "encrypted stream close is terminal and idempotent from every lifecycle state" {
    const cp = testProvider();

    // handshaking: no application keys, so close discards immediately.
    {
        var carrier_state = ScriptedCarrier{ .owns_handle = true };
        var subject = PureZigRecordStream.initWithCarrier(.server, cp, .tls_aes_128_gcm_sha256, carrier_state.carrier());
        defer subject.deinit();
        subject.stream().close();
        subject.stream().close();
        _ = try subject.stream().drive();
        try testing.expectEqual(Lifecycle.closed, subject.lifecycle);
        try testing.expectEqual(@as(usize, 1), carrier_state.close_calls);
        try expectClosedConformance(subject.stream());
        try expectStreamStateCleared(&subject);
    }

    // open: a real `close_notify` is sealed, flushed, and closes the carrier
    // exactly once; the peer sees a clean close rather than truncation.
    {
        var carrier_state = ScriptedCarrier{ .owns_handle = true };
        carrier_state.read_script_len = 1;
        carrier_state.read_script[0] = .would_block;
        carrier_state.write_script_len = 1;
        carrier_state.write_script[0] = .{ .transfer = scripted_capture_capacity };

        var pair = try CompanionPair.init(cp, &carrier_state);
        defer pair.deinit();
        var oracle = StreamOracle{};
        var src: [48]u8 = undefined;
        try subjectWriteOnce(&pair.subject, &oracle, &src);

        pair.subject.stream().close();
        // Closing, but not yet closed: `close_notify` waits behind the queued
        // application record.
        try testing.expectEqual(Lifecycle.closing, pair.subject.lifecycle);
        pair.subject.stream().close(); // idempotent
        try testing.expectEqual(Lifecycle.closing, pair.subject.lifecycle);

        var rounds: usize = 0;
        while (pair.subject.lifecycle != .closed and rounds < 64) : (rounds += 1) {
            _ = (try driveChecked(&pair.subject, &carrier_state, &oracle)).?;
            try syncCapture(&carrier_state, &pair.peer, &oracle);
        }
        try testing.expect(rounds < 64);
        try testing.expectEqual(@as(usize, 1), carrier_state.close_calls);
        try testing.expectEqual(oracle.subject_sent, oracle.peer_received);
        try testing.expect(pair.peer.peer_closed);
        try expectClosedConformance(pair.subject.stream());
        try expectStreamStateCleared(&pair.subject);
        // Closing again after the fact changes nothing.
        pair.subject.stream().close();
        try testing.expectEqual(Lifecycle.closed, pair.subject.lifecycle);
        try testing.expectEqual(@as(usize, 1), carrier_state.close_calls);
    }

    // failed: close after a latched failure neither revives the stream nor
    // releases the (already released) handle a second time.
    {
        var carrier_state = ScriptedCarrier{ .owns_handle = true };
        carrier_state.read_script_len = 1;
        carrier_state.read_script[0] = .fail;
        carrier_state.write_script_len = 1;
        carrier_state.write_script[0] = .would_block;

        var pair = try CompanionPair.init(cp, &carrier_state);
        defer pair.deinit();
        try testing.expectError(error.SocketReadFailed, pair.subject.stream().drive());
        try testing.expectEqual(@as(usize, 1), carrier_state.close_calls);
        pair.subject.stream().close();
        try testing.expectEqual(Lifecycle.failed, pair.subject.lifecycle);
        try expectLatchedFailureConformance(pair.subject.stream(), error.SocketReadFailed);
        try expectTeardownMetadataCleared(&pair.subject);
        try testing.expectEqual(@as(usize, 1), carrier_state.close_calls);
    }
}

// ===========================================================================
// #359: record sizing and padding on a driver-owned stream.
// ===========================================================================

test "#359 a driver-owned stream honors the peer's record_size_limit on every protected write" {
    const cp = testProvider();
    var duplex = Duplex{ .max_chunk = record_codec.max_ciphertext_record_len };
    // The server told the client it accepts at most 128-byte inner
    // plaintexts; the client told the server the protocol maximum.
    var client_backend = ScriptedRecordBackend{ .role = .client, .record_size_limits = .{ .peer = 128 } };
    var server_backend = ScriptedRecordBackend{ .role = .server, .record_size_limits = .{ .local = 128 } };
    var client = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .client, cp, .tls_aes_128_gcm_sha256, duplex.clientCarrier(), client_backend.recordBackend());
    defer client.deinit();
    try client.setExpectedAlpn("h1");
    var server = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .server, cp, .tls_aes_128_gcm_sha256, duplex.serverCarrier(), server_backend.recordBackend());
    defer server.deinit();

    try driveBothUntil(&client, &server, bothComplete);
    try testing.expectEqual(@as(?u16, 128), client.recordSizeLimits().peer);
    try testing.expectEqual(@as(usize, 127), client.bridge.outboundContentMax());

    // A single write is capped at 127 content bytes -- the peer's 128 minus
    // the content-type byte RFC 8449 counts -- and reports the short length
    // rather than failing.
    const payload = [_]u8{'q'} ** 400;
    var sent: usize = 0;
    var writes: usize = 0;
    while (sent < payload.len) {
        const n = try client.stream().write(payload[sent..]);
        try testing.expect(n <= 127);
        sent += n;
        writes += 1;
        _ = try client.stream().drive();
        _ = try server.stream().drive();
    }
    try testing.expectEqual(@as(usize, 4), writes);
    try testing.expect(client.recordSizeCounters().peer_limited_writes > 0);

    try driveBothUntil(&client, &server, struct {
        fn done(_: *PureZigRecordStream, s: *PureZigRecordStream) bool {
            return s.readiness().can_read_plaintext;
        }
    }.done);

    // The server accepted every record: none exceeded what it advertised.
    var received: [payload.len]u8 = undefined;
    var total: usize = 0;
    while (total < payload.len) {
        const n = server.stream().read(received[total..]) catch |err| switch (err) {
            error.WouldBlock => {
                _ = try client.stream().drive();
                _ = try server.stream().drive();
                continue;
            },
            else => return err,
        };
        total += n;
    }
    try testing.expectEqualSlices(u8, &payload, received[0..total]);
    try testing.expectEqual(@as(u64, 0), server.recordSizeCounters().oversize_records_rejected);
}

test "#359 a stream pads application records without ever exceeding the peer's limit" {
    const cp = testProvider();
    var duplex = Duplex{ .max_chunk = record_codec.max_ciphertext_record_len };
    var client_backend = ScriptedRecordBackend{ .role = .client, .record_size_limits = .{ .peer = 512 } };
    var server_backend = ScriptedRecordBackend{ .role = .server, .record_size_limits = .{ .local = 512 } };
    var client = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .client, cp, .tls_aes_128_gcm_sha256, duplex.clientCarrier(), client_backend.recordBackend());
    defer client.deinit();
    try client.setExpectedAlpn("h1");
    var server = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .server, cp, .tls_aes_128_gcm_sha256, duplex.serverCarrier(), server_backend.recordBackend());
    defer server.deinit();
    // Padding is local policy: it is set on the stream, never negotiated, and
    // the peer learns nothing about it beyond uniform record lengths.
    try client.setRecordPadding(.{ .block = 256 });

    try driveBothUntil(&client, &server, bothComplete);
    try testing.expectEqual(@as(usize, 4), try client.stream().write("tiny"));
    try driveBothUntil(&client, &server, struct {
        fn done(_: *PureZigRecordStream, s: *PureZigRecordStream) bool {
            return s.readiness().can_read_plaintext;
        }
    }.done);

    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("tiny", buf[0..try server.stream().read(&buf)]);
    // 4 content bytes + the type byte is 5; padded to the next 256 boundary.
    const counters = client.recordSizeCounters();
    try testing.expectEqual(@as(u64, 1), counters.padded_records);
    try testing.expectEqual(@as(u64, 251), counters.padding_bytes);
    // And the server, which advertised 512, accepted it: padding stayed
    // inside the negotiated bound.
    try testing.expectEqual(@as(u64, 0), server.recordSizeCounters().oversize_records_rejected);
}

test "#359 padding configuration outside the honorable range is rejected at the stream" {
    const cp = testProvider();
    var backend = ScriptedRecordBackend{ .role = .client };
    var stream_state = try PureZigRecordStream.initWithBackend(std.testing.allocator, .client, cp, .tls_aes_128_gcm_sha256, backend.recordBackend());
    defer stream_state.deinit();
    try testing.expectError(error.InvalidRecordSizeLimit, stream_state.setRecordPadding(.{ .block = 0 }));
    try testing.expectError(
        error.InvalidRecordSizeLimit,
        stream_state.setRecordPadding(.{ .block = record_size.PaddingPolicy.max_block + 1 }),
    );
    try testing.expectEqual(record_size.PaddingPolicy.none, stream_state.bridge.record_padding);
}

test "#359 an inbound record past our advertised limit fails the stream with record_overflow" {
    // The peer ignores what we advertised: our own bridge is configured to
    // accept only 128, while the sender still uses the protocol maximum.
    const cp = testProvider();
    var duplex = Duplex{ .max_chunk = record_codec.max_ciphertext_record_len };
    var client_backend = ScriptedRecordBackend{ .role = .client };
    var server_backend = ScriptedRecordBackend{ .role = .server };
    var client = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .client, cp, .tls_aes_128_gcm_sha256, duplex.clientCarrier(), client_backend.recordBackend());
    defer client.deinit();
    try client.setExpectedAlpn("h1");
    var server = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .server, cp, .tls_aes_128_gcm_sha256, duplex.serverCarrier(), server_backend.recordBackend());
    defer server.deinit();

    try driveBothUntil(&client, &server, bothComplete);
    // Tighten only the receiving side, after the handshake, so the sender
    // keeps writing full-size records into a peer that no longer accepts them.
    try server.bridge.setRecordSizeLimits(.{ .local = 128 });

    const payload = [_]u8{'w'} ** 1024;
    _ = try client.stream().write(&payload);
    _ = try client.stream().drive();
    try testing.expectError(error.RecordSizeLimitExceeded, server.stream().drive());
    try testing.expectEqual(@as(u64, 1), server.bridge.record_size_counters.oversize_records_rejected);
    try testing.expectEqual(
        alerts.AlertDescription.record_overflow,
        PureZigRecordStream.mappedFatalAlert(error.RecordSizeLimitExceeded).?,
    );
}

test "#359 a server that answers extension 28 and then oversizes its own flight gets record_overflow" {
    // The client-side enforcement gap, end to end. The client advertises 512
    // but cannot apply it to the server's first protected flight: until that
    // flight is parsed it does not know whether the server answered extension
    // 28 at all. Here the server does answer (modelled by the client backend
    // reporting the negotiated bound once it has processed the flight) *and*
    // sends a single 2000-byte handshake record. The record is opened against
    // the protocol maximum, then judged the moment the bound becomes known.
    const cp = testProvider();
    var duplex = Duplex{ .max_chunk = record_codec.max_ciphertext_record_len };
    const oversized_finished = "SF" ++ ("p" ** 2000);
    // The server is unconstrained, so it seals that flight as one record
    // rather than fragmenting it to the client's bound.
    var server_backend = ScriptedRecordBackend{ .role = .server, .server_finished = oversized_finished };
    var client_backend = ScriptedRecordBackend{
        .role = .client,
        .record_size_limits = .{},
        .record_size_limits_after_flight = .{ .local = 512, .peer = record_size.max_limit },
    };
    var client = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .client, cp, .tls_aes_128_gcm_sha256, duplex.clientCarrier(), client_backend.recordBackend());
    defer client.deinit();
    try client.setExpectedAlpn("h1");
    var server = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .server, cp, .tls_aes_128_gcm_sha256, duplex.serverCarrier(), server_backend.recordBackend());
    defer server.deinit();

    const errors = driveDriverPairUntilBothErrors(&client, &server);
    try testing.expectEqual(@as(?anyerror, error.RecordSizeLimitExceeded), errors.client);
    // The alert actually reached the peer rather than the stream tearing down
    // silently: RFC 8446 §6 requires `record_overflow` for a record above what
    // the receiver accepts.
    try testing.expectEqual(alerts.AlertDescription.record_overflow, server.peerAlert().?);
    try testing.expect(!client.bridge.handshake_complete);
    try testing.expectEqual(@as(u64, 1), client.bridge.record_size_counters.oversize_records_rejected);
}

test "#359 the same oversized flight is accepted when the server never answers extension 28" {
    // The other half of the same window: a server that does not implement
    // RFC 8449 is entitled to the protocol maximum, so the identical flight
    // must complete. Without the offer/negotiated split this would fail.
    const cp = testProvider();
    var duplex = Duplex{ .max_chunk = record_codec.max_ciphertext_record_len };
    const oversized_finished = "SF" ++ ("p" ** 2000);
    var server_backend = ScriptedRecordBackend{ .role = .server, .server_finished = oversized_finished };
    // No `record_size_limits_after_flight`: the peer never answered, so the
    // client keeps reporting the protocol maximum as its enforceable bound.
    var client_backend = ScriptedRecordBackend{ .role = .client, .record_size_limits = .{} };
    var client = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .client, cp, .tls_aes_128_gcm_sha256, duplex.clientCarrier(), client_backend.recordBackend());
    defer client.deinit();
    try client.setExpectedAlpn("h1");
    var server = try PureZigRecordStream.initWithCarrierAndBackend(std.testing.allocator, .server, cp, .tls_aes_128_gcm_sha256, duplex.serverCarrier(), server_backend.recordBackend());
    defer server.deinit();

    try driveBothUntil(&client, &server, bothComplete);
    try testing.expect(client.bridge.handshake_complete);
    try testing.expectEqual(@as(u64, 0), client.bridge.record_size_counters.oversize_records_rejected);
}
