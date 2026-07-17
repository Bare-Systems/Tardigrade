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
const messages = @import("messages.zig");
const record_codec = @import("record_codec.zig");
const record_epoch_bridge = @import("record_epoch_bridge.zig");
const tls_state = @import("state.zig");
const transport = @import("transport.zig");

const provider = crypto.provider;

/// Error set the record-mode handshake driver/backend contract carries. It is a
/// superset of every error the shared engine `Driver`, the `EventSink`, and the
/// `record_epoch_bridge` can surface, so a concrete TLS backend wired in from a
/// higher layer (#410) can report handshake failures without a lossy remap.
pub const RecordHandshakeError = record_epoch_bridge.Error || events.HandshakeError ||
    messages.ReadError || messages.WriteError || error{
    TransportBufferOverflow,
    /// A transport profile delivered handshake bytes in an epoch where the
    /// shared TLS engine cannot consume them.
    UnexpectedTransportEpoch,
    /// A transport profile that requires an extension (currently QUIC) did
    /// not receive it. Record mode never enables such an extension.
    MissingTransportExtension,
};

/// The canonical record-mode handshake transport contract (#408): protocol
/// events keyed on `events.EncryptionEpoch`, no transport-parameter payload
/// (that is a QUIC concern), reusing the shared `transport.Contract`/
/// `engine.Driver` rather than a parallel driver of its own.
pub const RecordTransport = transport.Contract(void, events.EncryptionEpoch, RecordHandshakeError);
/// The injected backend seam: a concrete TLS 1.3 engine (wired from a module
/// above `tls_core`, e.g. the pure-Zig engine wrapped for record mode) drives
/// the handshake through this vtable and reports keying/negotiation results
/// through the shared `EventSink`.
pub const RecordHandshakeBackend = RecordTransport.Backend;
/// The shared engine driver instantiated for record mode. `PureZigRecordStream`
/// owns one of these and progresses it inside `drive()`.
pub const RecordHandshakeDriver = engine.Driver(RecordTransport);

pub const Error = RecordHandshakeError || error{
    WouldBlock,
    EndOfStream,
    StreamClosed,
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
    outbound_ciphertext: ByteQueue(max_ciphertext_queue, error.CiphertextBufferFull) = .{},
    inbound_handshake: ByteQueue(max_handshake_queue, error.PlaintextBufferFull) = .{},
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

    pub fn initWithCarrier(role: tls_state.Role, crypto_provider: provider.CryptoProvider, cipher_suite: algorithms.CipherSuite, carrier: Carrier) PureZigRecordStream {
        std.debug.assert(!carrier.owns_handle or carrier.closeFn != null);
        var stream_state = init(role, crypto_provider, cipher_suite);
        stream_state.carrier = carrier;
        return stream_state;
    }

    /// Like `init`, but the stream owns a shared TLS handshake driver over the
    /// injected `backend`. `drive()` then starts and progresses the real
    /// handshake itself rather than relying on callers to hand-apply events.
    pub fn initWithBackend(
        role: tls_state.Role,
        crypto_provider: provider.CryptoProvider,
        cipher_suite: algorithms.CipherSuite,
        backend: RecordHandshakeBackend,
    ) PureZigRecordStream {
        var stream_state = init(role, crypto_provider, cipher_suite);
        stream_state.handshake_driver = RecordHandshakeDriver.init(role, backend);
        return stream_state;
    }

    /// `initWithBackend` plus a nonblocking carrier, the production shape: a
    /// real backend driving a real handshake over a real byte-stream carrier.
    pub fn initWithCarrierAndBackend(
        role: tls_state.Role,
        crypto_provider: provider.CryptoProvider,
        cipher_suite: algorithms.CipherSuite,
        carrier: Carrier,
        backend: RecordHandshakeBackend,
    ) PureZigRecordStream {
        std.debug.assert(!carrier.owns_handle or carrier.closeFn != null);
        var stream_state = initWithBackend(role, crypto_provider, cipher_suite, backend);
        stream_state.carrier = carrier;
        return stream_state;
    }

    /// The ALPN protocol negotiated by the handshake, or null if none was seen.
    pub fn negotiatedAlpn(self: *const PureZigRecordStream) ?[]const u8 {
        if (!self.alpn_captured) return null;
        return self.alpn_storage[0..self.alpn_len];
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

    /// The peer certificate validation outcome the backend reported.
    pub fn certificateState(self: *const PureZigRecordStream) events.CertificateState {
        return self.certificate_state;
    }

    pub fn deinit(self: *PureZigRecordStream) void {
        self.teardownDriver();
        self.bridge.deinit();
        self.inbound_carrier.clear();
        self.inbound_plaintext.clear();
        self.outbound_ciphertext.clear();
        self.inbound_handshake.clear();
        self.clearHandshakeMetadata();
        self.initial_parser.reset();
        self.ciphertext_parser.reset();
        self.closeCarrier();
        self.lifecycle = .closed;
        self.peer_closed = true;
        self.carrier_eof = false;
        self.close_notify_queued = false;
        self.pending_terminal_read_error = null;
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

    pub fn applyEvent(self: *PureZigRecordStream, event: events.Event) Error!void {
        if (self.failed) |err| return err;
        if (self.lifecycle == .closed or self.lifecycle == .failed or self.lifecycle == .closing) return error.StreamClosed;
        if (event == .handshake_bytes and self.outbound_ciphertext.available() < record_codec.max_ciphertext_record_len) return error.WouldBlock;
        var record_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
        if (self.bridge.applyEvent(event, &record_buf) catch |err| return self.fail(err)) |record| {
            self.outbound_ciphertext.append(record) catch |err| return self.fail(err);
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
        if (self.outbound_ciphertext.available() < handshake_output_reserve) return false;
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

    /// Apply one borrowed driver event batch. Every payload slice is consumed,
    /// copied, or serialized here, before any subsequent driver call resets the
    /// sink. A terminal backend error is deferred (with its fatal alert queued)
    /// rather than propagated, so `drive()` can flush the alert before latching.
    fn applyDriverOutcome(self: *PureZigRecordStream, outcome: RecordHandshakeDriver.Outcome) Error!void {
        var fatal_alert: ?alerts.AlertDescription = null;
        const sink = outcome.sink;
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
                    var record_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
                    const record = self.bridge.sealHandshake(hb.epoch, hb.data, &record_buf) catch |err| return self.fail(err);
                    self.outbound_ciphertext.append(record) catch |err| return self.fail(err);
                },
                .traffic_secret => |ts| {
                    self.bridge.installTrafficSecret(ts.epoch, ts.direction, ts.data) catch |err| return self.fail(err);
                    self.advanceEpochOnSecret(ts.epoch, ts.direction);
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

    /// Handshake secrets advance the explicit record epoch one step. Application
    /// secrets do NOT advance the epoch here: the peer may still be sending
    /// handshake-epoch records (its Finished) after this side installs its
    /// application read secret. The `.application` transition happens only at
    /// authenticated `handshake_complete`.
    fn advanceEpochOnSecret(self: *PureZigRecordStream, epoch: events.EncryptionEpoch, direction: events.SecretDirection) void {
        if (epoch != .handshake) return;
        switch (direction) {
            .read => self.read_epoch = .handshake,
            .write => self.write_epoch = .handshake,
        }
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
            => alerts.fromHandshakeError(@errorCast(err)),
            else => null,
        };
    }

    /// Best-effort: seal a fatal alert at the current write epoch into the
    /// outbound queue. Silently skips if keys or capacity are unavailable --
    /// a lost alert must never erase the underlying handshake failure.
    fn queueFatalAlert(self: *PureZigRecordStream, desc: alerts.AlertDescription) void {
        if (self.outbound_ciphertext.available() < record_codec.max_ciphertext_record_len) return;
        const payload = [_]u8{ 2, @intFromEnum(desc) }; // level = fatal(2)
        var alert_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
        const record = switch (self.write_epoch) {
            .initial => record_codec.encodePlaintextRecord(.alert, &payload, &alert_buf) catch return,
            .handshake, .application => self.bridge.sealProtected(self.write_epoch, .alert, &payload, &alert_buf) catch return,
            .zero_rtt => return,
        };
        self.outbound_ciphertext.append(record) catch return;
    }

    pub fn feedHandshakeCiphertext(self: *PureZigRecordStream, epoch: events.EncryptionEpoch, bytes: []const u8) Error!usize {
        if (self.failed) |err| return err;
        if (self.lifecycle == .closed or self.lifecycle == .failed) return error.StreamClosed;
        if (self.inbound_handshake.available() < record_codec.max_plaintext_fragment_len) return error.WouldBlock;
        var sink = record_codec.RecordSink(1, record_codec.max_ciphertext_fragment_len){};
        const parser = self.parserForEpoch(epoch);
        const consumed = feedUntilOneRecord(parser, bytes, &sink) catch |err| return self.fail(err);
        self.openHandshakeSink(epoch, &sink) catch |err| return self.fail(err);
        return consumed;
    }

    pub fn readHandshake(self: *PureZigRecordStream, out: []u8) Error!usize {
        if (self.failed) |err| return err;
        if (self.lifecycle == .closed or self.lifecycle == .failed) return error.StreamClosed;
        if (self.inbound_handshake.read(out)) |n| return n;
        try self.raisePendingTerminalError();
        return error.WouldBlock;
    }

    pub fn feedCiphertext(self: *PureZigRecordStream, bytes: []const u8) Error!usize {
        if (self.failed) |err| return err;
        if (self.lifecycle == .closed or self.lifecycle == .failed) return error.StreamClosed;
        if (self.peer_closed) return bytes.len;
        if (!self.canAcceptCarrierRead()) return error.WouldBlock;
        var sink = record_codec.RecordSink(1, record_codec.max_ciphertext_fragment_len){};
        const consumed = feedUntilOneRecord(&self.ciphertext_parser, bytes, &sink) catch |err| return self.fail(err);

        var plaintext_buf: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
        for (sink.items[0..sink.len]) |record| {
            const opened = self.bridge.openProtected(.application, record, &plaintext_buf) catch |err| return self.fail(err);
            switch (opened.inner.content_type) {
                .application_data => self.inbound_plaintext.append(opened.inner.content) catch |err| return self.fail(err),
                .handshake => self.inbound_handshake.append(opened.inner.content) catch |err| return self.fail(err),
                .alert => self.handleAlert(opened.inner.content) catch |err| return self.fail(err),
                .change_cipher_spec => return self.fail(error.UnsupportedRecordContent),
            }
        }
        return consumed;
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
        if (self.inbound_plaintext.read(out)) |n| return n;
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
        if (self.lifecycle != .open or !self.bridge.handshake_complete) return error.WouldBlock;
        if (self.outbound_ciphertext.available() < record_codec.max_ciphertext_record_len) return error.WouldBlock;

        const n = @min(bytes.len, record_codec.max_plaintext_fragment_len);
        var record_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
        const record = self.bridge.sealApplicationData(bytes[0..n], &record_buf) catch |err| return self.fail(err);
        self.outbound_ciphertext.append(record) catch |err| return self.fail(err);
        return n;
    }

    pub fn drainCiphertext(self: *PureZigRecordStream, out: []u8) Error!usize {
        if (self.failed) |err| return err;
        if (self.outbound_ciphertext.read(out)) |n| return n;
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
        if (self.lifecycle == .closing and self.carrier == null and self.close_notify_queued and self.outbound_ciphertext.len == 0) {
            self.lifecycle = .closed;
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
        return .{
            .wants_read = !self.carrier_eof and self.canAcceptCarrierRead(),
            .wants_write = self.outbound_ciphertext.len > 0 or (self.lifecycle == .closing and !self.close_notify_queued),
            .can_read_plaintext = self.inbound_plaintext.len > 0 or pending_terminal_read_ready,
            .can_write_plaintext = self.pending_terminal_read_error == null and self.lifecycle == .open and self.bridge.handshake_complete and self.outbound_ciphertext.available() >= record_codec.max_ciphertext_record_len,
            .peer_closed = self.peer_closed,
        };
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
                self.lifecycle = .closed;
                self.closeCarrier();
                made_progress = true;
                return .{ .made_progress = made_progress, .readiness = self.readiness() };
            }

            var record_budget_remaining: usize = drive_record_budget;
            if (try self.processCarrierInputBudget(&record_budget_remaining)) made_progress = true;

            var read_total: usize = 0;
            while (!self.carrier_eof and read_total < drive_read_budget and self.canAcceptCarrierRead() and self.inbound_carrier.available() > 0) {
                var buf: [drive_read_chunk]u8 = undefined;
                const read_cap = @min(buf.len, @min(self.inbound_carrier.available(), drive_read_budget - read_total));
                if (read_cap == 0) break;
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
                        self.inbound_carrier.append(buf[0..read_len]) catch |err| return self.fail(err);
                        read_total += read_len;
                        made_progress = true;
                        if (try self.processCarrierInputBudget(&record_budget_remaining)) made_progress = true;
                    }
                } else {
                    break;
                }
            }
            if (self.carrier_eof) {
                if (try self.handleCarrierEof(&record_budget_remaining)) made_progress = true;
            }
        } else if (self.lifecycle == .closing) {
            if (try self.queueCloseNotify()) made_progress = true;
            if (self.close_notify_queued and self.outbound_ciphertext.len == 0) {
                self.lifecycle = .closed;
                made_progress = true;
            }
        } else {
            if (try self.processCarrierInput(drive_record_budget)) made_progress = true;
        }

        if (self.lifecycle == .closing and self.carrier != null and self.close_notify_queued and self.outbound_ciphertext.len == 0) {
            self.lifecycle = .closed;
            self.closeCarrier();
            made_progress = true;
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
            const opened = try self.bridge.openProtected(epoch, record, &plaintext_buf);
            switch (opened.inner.content_type) {
                .handshake => try self.inbound_handshake.append(opened.inner.content),
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
        if (self.bridge.handshake_complete) return self.feedCiphertext(bytes);
        if (self.driverPresent()) {
            // A terminal handshake failure is pending its alert flush; stop
            // consuming carrier records until `drive()` latches it.
            if (self.pending_terminal != null) return error.WouldBlock;
            // Preflight so a full emitted event batch serializes atomically; if
            // the outbound queue is too full, wait for the carrier to drain.
            if (self.outbound_ciphertext.available() < handshake_output_reserve) return error.WouldBlock;
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
        const consumed = feedUntilOneRecord(parser, bytes, &sink) catch |err| return self.fail(err);
        var plaintext_buf: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
        for (sink.items[0..sink.len]) |record| {
            if (epoch == .initial and record.content_type == .alert) {
                try self.handleAlert(record.payload);
                continue;
            }
            const opened = self.bridge.openProtected(epoch, record, &plaintext_buf) catch |err| return self.fail(err);
            switch (opened.inner.content_type) {
                .handshake => try self.driveReceive(epoch, opened.inner.content),
                .alert => try self.handleAlert(opened.inner.content),
                .application_data,
                .change_cipher_spec,
                => return self.fail(error.UnexpectedRecordContent),
            }
            // A deferred terminal failure means the driver rejected this
            // message; stop opening further coalesced records under it.
            if (self.pending_terminal != null) break;
        }
        return consumed;
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
        return self.lifecycle != .closed and self.lifecycle != .failed and self.lifecycle != .closing and !self.peer_closed and
            self.inbound_carrier.available() > 0 and
            self.inbound_plaintext.available() >= record_codec.max_plaintext_fragment_len and
            self.inbound_handshake.available() >= record_codec.max_plaintext_fragment_len;
    }

    fn queueCloseNotify(self: *PureZigRecordStream) Error!bool {
        if (self.lifecycle != .closing or self.close_notify_queued) return false;
        if (!self.bridge.handshake_complete) {
            self.outbound_ciphertext.clear();
            self.lifecycle = .closed;
            self.closeCarrier();
            return true;
        }
        if (self.outbound_ciphertext.len > 0) return false;
        if (self.outbound_ciphertext.available() < record_codec.max_ciphertext_record_len) return false;
        var alert_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
        const close_notify = self.bridge.sealProtected(.application, .alert, &.{ 1, 0 }, &alert_buf) catch |err| return self.fail(err);
        self.outbound_ciphertext.append(close_notify) catch |err| return self.fail(err);
        self.close_notify_queued = true;
        return true;
    }

    fn processCarrierInputBudget(self: *PureZigRecordStream, record_budget_remaining: *usize) Error!bool {
        const initial_budget = record_budget_remaining.*;
        while (record_budget_remaining.* > 0 and self.inbound_carrier.len > 0 and self.canAcceptCarrierRead()) {
            const pending = self.inbound_carrier.slice();
            const consumed = self.feedCarrierCiphertext(pending) catch |err| switch (err) {
                error.WouldBlock => break,
                else => return err,
            };
            if (consumed == 0) break;
            try self.inbound_carrier.discard(consumed);
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
        self.inbound_carrier.clear();
        self.inbound_plaintext.clear();
        self.outbound_ciphertext.clear();
        self.inbound_handshake.clear();
        self.clearHandshakeMetadata();
        self.initial_parser.reset();
        self.ciphertext_parser.reset();
        self.pending_terminal_read_error = null;
        self.pending_terminal = null;
        self.terminal_flush_attempts = 0;
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
            self.discard(n) catch unreachable;
            return n;
        }

        fn slice(self: *const Self) []const u8 {
            return self.buf[0..self.len];
        }

        fn discard(self: *Self, count: usize) Error!void {
            if (count > self.len) return error.WouldBlock;
            std.mem.copyForwards(u8, self.buf[0 .. self.len - count], self.buf[count..self.len]);
            self.len -= count;
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
    try testing.expectError(error.WouldBlock, server.feedCiphertext(coalesced[consumed..total_len]));
    try testing.expectEqual(read_seq + 1, server.bridge.read_application.?.sequence);
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

    stream_state.inbound_handshake.len = 1;
    try testing.expect(!stream.readiness().wants_read);
    const blocked = try stream.drive();
    try testing.expect(!blocked.made_progress);
    try testing.expect(!blocked.readiness.wants_read);
    stream_state.inbound_handshake.len = 0;

    const drive = try stream.drive();
    try testing.expect(!drive.made_progress);
    try testing.expectEqual(before, drive.readiness);
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
    var native = PureZigRecordStream.init(.client, cp, .tls_aes_128_gcm_sha256);
    defer native.deinit();
    streams[0] = native.stream();
    try testing.expectEqual(BackendKind.pure_zig_record, streams[0].backend());
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

    const hs_c2s = secret(0x11);
    const hs_s2c = secret(0x22);
    const app_c2s = secret(0x33);
    const app_s2c = secret(0x44);

    fn recordBackend(self: *ScriptedRecordBackend) RecordHandshakeBackend {
        return .{ .ptr = self, .startFn = start, .receiveFn = receive };
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
                    try sink.emitHandshakeBytes(.handshake, "SF");
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
                } else if (epoch == .handshake and std.mem.eql(u8, bytes, "SF")) {
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
        var client = PureZigRecordStream.initWithCarrierAndBackend(.client, cp, .tls_aes_128_gcm_sha256, duplex.clientCarrier(), client_backend.recordBackend());
        defer client.deinit();
        try client.setExpectedAlpn("h1");
        var server = PureZigRecordStream.initWithCarrierAndBackend(.server, cp, .tls_aes_128_gcm_sha256, duplex.serverCarrier(), server_backend.recordBackend());
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
    var client = PureZigRecordStream.initWithCarrierAndBackend(.client, cp, .tls_aes_128_gcm_sha256, duplex.clientCarrier(), client_backend.recordBackend());
    defer client.deinit();
    try client.setExpectedAlpn("h1");
    var server = PureZigRecordStream.initWithCarrierAndBackend(.server, cp, .tls_aes_128_gcm_sha256, duplex.serverCarrier(), server_backend.recordBackend());
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
    var client = PureZigRecordStream.initWithCarrierAndBackend(.client, cp, .tls_aes_128_gcm_sha256, duplex.clientCarrier(), client_backend.recordBackend());
    defer client.deinit();
    try client.setExpectedAlpn("h1");
    var server = PureZigRecordStream.initWithCarrierAndBackend(.server, cp, .tls_aes_128_gcm_sha256, duplex.serverCarrier(), server_backend.recordBackend());
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
    var client = PureZigRecordStream.initWithCarrierAndBackend(.client, cp, .tls_aes_128_gcm_sha256, duplex.clientCarrier(), client_backend.recordBackend());
    defer client.deinit();
    try client.setExpectedAlpn("h1");
    var server = PureZigRecordStream.initWithCarrierAndBackend(.server, cp, .tls_aes_128_gcm_sha256, duplex.serverCarrier(), server_backend.recordBackend());
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
    var client = PureZigRecordStream.initWithCarrierAndBackend(.client, cp, .tls_aes_128_gcm_sha256, duplex.clientCarrier(), client_backend.recordBackend());
    defer client.deinit();
    var server = PureZigRecordStream.initWithCarrierAndBackend(.server, cp, .tls_aes_128_gcm_sha256, duplex.serverCarrier(), server_backend.recordBackend());
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
        var stream = PureZigRecordStream.initWithCarrierAndBackend(.client, cp, .tls_aes_128_gcm_sha256, carrier.carrier(), backend.recordBackend());

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
    var client = PureZigRecordStream.initWithCarrierAndBackend(.client, cp, .tls_aes_128_gcm_sha256, duplex.clientCarrier(), client_backend.recordBackend());
    defer client.deinit();
    var server = PureZigRecordStream.initWithCarrierAndBackend(.server, cp, .tls_aes_128_gcm_sha256, duplex.serverCarrier(), server_backend.recordBackend());
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
    var client = PureZigRecordStream.initWithCarrierAndBackend(.client, cp, .tls_aes_128_gcm_sha256, duplex.clientCarrier(), client_backend.recordBackend());
    defer client.deinit();
    var server = PureZigRecordStream.initWithCarrierAndBackend(.server, cp, .tls_aes_128_gcm_sha256, duplex.serverCarrier(), server_backend.recordBackend());
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
