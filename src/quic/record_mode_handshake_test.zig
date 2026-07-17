//! A real client/server TLS 1.3 handshake driven through the merged record
//! stack (#408 finding 6). #406's own integration test proves the generic
//! `transport.Contract`/`engine.Driver`/`record_epoch_bridge.Bridge` event
//! plumbing with a scripted backend that fabricates handshake strings; it
//! never exercises real cryptography. This file drives the same plumbing
//! with the production TLS 1.3 engine (`tls_backend.Tls13Backend`) instead,
//! so a genuine ClientHello/ServerHello/Certificate/Finished exchange is
//! sealed and opened as real TLS records, first-record keys are checked
//! independently (client- and server-derived secrets for the same direction
//! come from separate HKDF computations off separate ECDH shares, so their
//! equality is a real cross-check, not a tautology), and epoch discard plus
//! teardown are proven on both the success and failure paths.
//!
//! `Tls13Backend` is otherwise QUIC-shaped: it emits events through
//! `tls_handshake.EventSink`, typed on QUIC's `config.TransportParameters`
//! and `EncryptionLevel`. `omit_transport_parameters = true` (already a
//! first-class backend option, used elsewhere to test the QUIC driver's
//! `MissingTransportParameters` path) skips the one QUIC-specific extension
//! entirely, so a plain zero-valued `config.TransportParameters` never gets
//! read. `EncryptionLevel` and `tls_core.events.EncryptionEpoch` carry the
//! same four variants in the same order, so `mapEpoch` below is a plain
//! translation, not a lossy one.

const std = @import("std");
const crypto = @import("crypto");
const config = @import("config.zig");
const tls_adapter = @import("tls_adapter.zig");
const tls_handshake = @import("tls_handshake.zig");
const tls_backend = @import("tls_backend.zig");
const tls_core = @import("tls_core");

const record_codec = tls_core.record_codec;
const record_protection = tls_core.record_protection;
const record_epoch_bridge = tls_core.record_epoch_bridge;
const events = tls_core.events;
const Bridge = record_epoch_bridge.Bridge;

const Error = tls_handshake.HandshakeError || record_epoch_bridge.Error;

const dummy_params = config.TransportParameters{
    .max_idle_timeout_ms = 0,
    .active_connection_id_limit = 0,
    .max_udp_payload_size = 0,
    .initial_max_data = 0,
    .initial_max_stream_data_bidi_local = 0,
    .initial_max_stream_data_bidi_remote = 0,
    .initial_max_stream_data_uni = 0,
    .initial_max_streams_bidi = 0,
    .initial_max_streams_uni = 0,
    .disable_active_migration = false,
};

fn clientEntropy() tls_backend.Entropy {
    return .{ .hello_random = [_]u8{0xc1} ** 32, .key_share_seed = [_]u8{0x11} ** 32 };
}

fn serverEntropy() tls_backend.Entropy {
    return .{ .hello_random = [_]u8{0x51} ** 32, .key_share_seed = [_]u8{0x22} ** 32 };
}

fn fixtureIdentity() tls_backend.Identity {
    return tls_backend.Identity.initPkcs8(
        tls_backend.testdata.certificate_der,
        tls_backend.testdata.private_key_pkcs8_der,
    ) catch unreachable;
}

fn clientProvider() crypto.provider.CryptoProvider {
    const pure_zig = crypto.pure_zig;
    const State = struct {
        var entropy = pure_zig.DeterministicEntropy.init(0x408_c);
        var provider_state = pure_zig.Provider.init(entropy.entropy());
    };
    return State.provider_state.cryptoProvider();
}

fn serverProvider() crypto.provider.CryptoProvider {
    const pure_zig = crypto.pure_zig;
    const State = struct {
        var entropy = pure_zig.DeterministicEntropy.init(0x408_5);
        var provider_state = pure_zig.Provider.init(entropy.entropy());
    };
    return State.provider_state.cryptoProvider();
}

fn mapEpoch(level: tls_adapter.EncryptionLevel) events.EncryptionEpoch {
    return switch (level) {
        .initial => .initial,
        .zero_rtt => .zero_rtt,
        .handshake => .handshake,
        .application => .application,
    };
}

fn parseSingleRecord(mode: record_codec.RecordMode, bytes: []const u8) Error!record_codec.Record {
    if (bytes.len < record_codec.header_len) return error.TruncatedRecord;
    const header = try record_codec.parseHeader(bytes[0..record_codec.header_len], mode, .strict);
    const record_len = record_codec.header_len + header.payload_len;
    if (bytes.len != record_len) return error.TruncatedRecord;
    return .{
        .content_type = header.content_type,
        .legacy_version = header.legacy_version,
        .payload = bytes[record_codec.header_len..record_len],
    };
}

/// Confirms a Driver's own teardown guarantee (#408 finding 2): after
/// `deinit()`, the sink reports no used bytes, and every byte that was
/// copied into scratch before teardown (per `used_before`, captured prior
/// to calling `deinit()`) has been securely zeroed.
fn expectDriverSinkWiped(driver: *const tls_handshake.CoreDriver, used_before: usize) !void {
    try std.testing.expectEqual(@as(usize, 0), driver.sink.used);
    for (driver.sink.scratch[0..used_before]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

const KeySnapshot = struct {
    key: [crypto.provider.max_aead_key_len]u8 = undefined,
    key_len: usize = 0,
    iv: [crypto.provider.aead_nonce_len]u8 = undefined,

    fn capture(keys: *const record_protection.TrafficKeys) KeySnapshot {
        var snap = KeySnapshot{};
        const key_slice = keys.key.slice();
        snap.key_len = key_slice.len;
        @memcpy(snap.key[0..snap.key_len], key_slice);
        @memcpy(&snap.iv, keys.iv.slice());
        return snap;
    }

    fn eql(a: KeySnapshot, b: KeySnapshot) bool {
        return a.key_len == b.key_len and
            std.mem.eql(u8, a.key[0..a.key_len], b.key[0..b.key_len]) and
            std.mem.eql(u8, &a.iv, &b.iv);
    }
};

const Side = enum { client, server };

/// Everything independently observed while pumping the handshake, captured
/// at the moment each event is applied (traffic secrets are wiped from the
/// bridge itself once their epoch is discarded, so this is the only chance
/// to record them for the post-handshake cross-checks below).
const Observed = struct {
    handshake_write: [2]?KeySnapshot = .{ null, null },
    handshake_read: [2]?KeySnapshot = .{ null, null },
    application_write: [2]?KeySnapshot = .{ null, null },
    application_read: [2]?KeySnapshot = .{ null, null },
    handshake_write_seq_after_first_record: [2]?u64 = .{ null, null },
    alpn: [32]u8 = undefined,
    alpn_len: usize = 0,
    certificate_state: ?events.CertificateState = null,
    initial_discarded: [2]bool = .{ false, false },
    handshake_discarded: [2]bool = .{ false, false },

    fn captureSecret(self: *Observed, side: Side, epoch: events.EncryptionEpoch, direction: events.SecretDirection, keys: *const record_protection.TrafficKeys) void {
        const i = @intFromEnum(side);
        const slot: *?KeySnapshot = switch (epoch) {
            .handshake => switch (direction) {
                .write => &self.handshake_write[i],
                .read => &self.handshake_read[i],
            },
            .application => switch (direction) {
                .write => &self.application_write[i],
                .read => &self.application_read[i],
            },
            .initial, .zero_rtt => return,
        };
        slot.* = KeySnapshot.capture(keys);
    }

    fn noteAlpn(self: *Observed, protocol: []const u8) void {
        self.alpn_len = protocol.len;
        @memcpy(self.alpn[0..protocol.len], protocol);
    }

    fn noteHandshakeWriteSequence(self: *Observed, side: Side, sequence: u64) void {
        const i = @intFromEnum(side);
        if (self.handshake_write_seq_after_first_record[i] == null) {
            self.handshake_write_seq_after_first_record[i] = sequence;
        }
    }

    fn noteDiscard(self: *Observed, side: Side, epoch: events.EncryptionEpoch) void {
        const i = @intFromEnum(side);
        switch (epoch) {
            .initial => self.initial_discarded[i] = true,
            .handshake => self.handshake_discarded[i] = true,
            .application, .zero_rtt => {},
        }
    }
};

/// Mirrors `record_epoch_bridge.zig`'s scripted-backend test harness: drain
/// one driver's sink, sealing/opening each handshake-bytes event as a real
/// record and recursing into the peer for its response, applying every
/// other event to the sending side's bridge. The only difference is the
/// real `Tls13Backend` behind the drivers and the snapshot bookkeeping in
/// `Observed`.
fn pump(
    sender_driver: *tls_handshake.CoreDriver,
    sender_bridge: *Bridge,
    sender_side: Side,
    receiver_driver: *tls_handshake.CoreDriver,
    receiver_bridge: *Bridge,
    receiver_side: Side,
    sink: *tls_handshake.EventSink,
    observed: *Observed,
) Error!void {
    var opened: [record_codec.max_ciphertext_fragment_len]u8 = undefined;

    // Sealing must happen in the sink's own order (a handshake-bytes event
    // sealed with a key that a later event in the same sink discards is
    // only valid if it is sealed before that discard runs). Delivering to
    // the peer must not: the peer's response can cascade into a discard on
    // *this* bridge that is only valid once every one of this sink's own
    // remaining local events (typically installing this side's own
    // application secrets) has been applied. So seal in-line, in order, but
    // queue delivery/recursion for a second pass once the whole sink is
    // drained.
    const max_queued = 4;
    const QueuedMessage = struct {
        epoch: events.EncryptionEpoch,
        level: tls_adapter.EncryptionLevel,
        mode: record_codec.RecordMode,
        buf: [4096]u8 = undefined,
        len: usize,
    };
    var queued: [max_queued]QueuedMessage = undefined;
    var queued_len: usize = 0;

    for (sink.items[0..sink.len]) |event| {
        switch (event) {
            .handshake_bytes => |hb| {
                const epoch = mapEpoch(hb.epoch);
                std.debug.assert(queued_len < max_queued);
                const slot = &queued[queued_len];
                queued_len += 1;
                slot.* = .{ .epoch = epoch, .level = hb.epoch, .mode = if (hb.epoch == .initial) .plaintext else .ciphertext, .len = 0 };
                const bytes = (try sender_bridge.applyEvent(.{ .handshake_bytes = .{ .epoch = epoch, .data = hb.data } }, &slot.buf)).?;
                slot.len = bytes.len;
                if (epoch == .handshake) {
                    observed.noteHandshakeWriteSequence(sender_side, sender_bridge.write_handshake.?.sequence);
                }
            },
            .traffic_secret => |ts| {
                var scratch: [1]u8 = undefined;
                _ = try sender_bridge.applyEvent(.{ .traffic_secret = .{ .epoch = mapEpoch(ts.epoch), .direction = ts.direction, .data = ts.data } }, &scratch);
                const keys: *const record_protection.TrafficKeys = switch (mapEpoch(ts.epoch)) {
                    .handshake => switch (ts.direction) {
                        .write => &sender_bridge.write_handshake.?.keys,
                        .read => &sender_bridge.read_handshake.?.keys,
                    },
                    .application => switch (ts.direction) {
                        .write => &sender_bridge.write_application.?.keys,
                        .read => &sender_bridge.read_application.?.keys,
                    },
                    .initial, .zero_rtt => continue,
                };
                observed.captureSecret(sender_side, mapEpoch(ts.epoch), ts.direction, keys);
            },
            .discard_epoch => |epoch| {
                var scratch: [1]u8 = undefined;
                _ = try sender_bridge.applyEvent(.{ .discard_epoch = mapEpoch(epoch) }, &scratch);
                observed.noteDiscard(sender_side, mapEpoch(epoch));
            },
            .handshake_complete => {
                var scratch: [1]u8 = undefined;
                _ = try sender_bridge.applyEvent(.handshake_complete, &scratch);
                sender_driver.complete();
            },
            .peer_transport_parameters => {},
            .alpn => |protocol| observed.noteAlpn(protocol),
            .certificate => |state| observed.certificate_state = state,
            .fatal_alert => {},
        }
    }

    for (queued[0..queued_len]) |msg| {
        const record = try parseSingleRecord(msg.mode, msg.buf[0..msg.len]);
        const message = try receiver_bridge.openHandshake(msg.epoch, record, &opened);
        const next = try receiver_driver.receive(msg.level, message.inner.content);
        try pump(receiver_driver, receiver_bridge, receiver_side, sender_driver, sender_bridge, sender_side, next, observed);
    }
}

const Harness = struct {
    client_backend: tls_backend.Tls13Backend,
    server_backend: tls_backend.Tls13Backend,
    client_driver: tls_handshake.CoreDriver,
    server_driver: tls_handshake.CoreDriver,
    client_bridge: Bridge,
    server_bridge: Bridge,
    observed: Observed = .{},
    /// Guards deinit()'s driver cleanup: client_driver/server_driver start
    /// as `undefined` and only become valid once `run()` constructs them.
    drivers_ready: bool = false,
    /// Guards against calling deinit() more than once. The bridge/driver
    /// contracts document exactly one deinit() call per owner; tests that
    /// both `defer h.deinit()` and call it explicitly to inspect
    /// post-teardown state must still honor that, so a second call is a
    /// no-op rather than relying on today's incidental idempotency.
    deinitialized: bool = false,

    fn init() Harness {
        var client_backend = tls_backend.Tls13Backend.initClient(clientEntropy(), .{ .pinned_certificate = tls_backend.testdata.certificate_der });
        client_backend.omit_transport_parameters = true;
        var server_backend = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity());
        server_backend.omit_transport_parameters = true;

        return .{
            .client_backend = client_backend,
            .server_backend = server_backend,
            .client_driver = undefined,
            .server_driver = undefined,
            .client_bridge = Bridge.init(clientProvider(), .tls_aes_128_gcm_sha256),
            .server_bridge = Bridge.init(serverProvider(), .tls_aes_128_gcm_sha256),
        };
    }

    /// Wires the drivers after the backends have a stable address (the
    /// backend vtable in `.backend()` captures `&self`), then runs the
    /// handshake to completion through the record stack.
    fn run(self: *Harness) Error!void {
        self.client_driver = tls_handshake.CoreDriver.init(.client, self.client_backend.backend().transport);
        self.server_driver = tls_handshake.CoreDriver.init(.server, self.server_backend.backend().transport);
        self.drivers_ready = true;

        // The server backend only transitions out of its default `.start`
        // expectation once its own driver's `start` runs (it emits no
        // events of its own -- it just becomes ready to receive the
        // ClientHello), so both sides must be started before anything is
        // pumped.
        _ = try self.server_driver.start(dummy_params);
        const initial = try self.client_driver.start(dummy_params);
        try pump(&self.client_driver, &self.client_bridge, .client, &self.server_driver, &self.server_bridge, .server, initial, &self.observed);
    }

    fn deinit(self: *Harness) void {
        if (self.deinitialized) return;
        self.deinitialized = true;
        self.client_bridge.deinit();
        self.server_bridge.deinit();
        // The generic Driver's own teardown (#408 finding 2): it wipes
        // whatever traffic-secret bytes are still copied into its sink from
        // the final start/receive call. Every Driver owner must call this
        // exactly once, alongside (not instead of) the Bridge's own
        // secret wipe -- they own separate scratch buffers.
        if (self.drivers_ready) {
            self.client_driver.deinit();
            self.server_driver.deinit();
        }
    }
};

test "a real TLS 1.3 handshake completes end to end through the merged record stack" {
    var h = Harness.init();
    defer h.deinit();
    try h.run();

    try std.testing.expect(h.client_driver.isComplete());
    try std.testing.expect(h.server_driver.isComplete());

    // ALPN negotiated and the server's pinned certificate verified, both
    // carried as ordinary events through the same contract records use.
    try std.testing.expectEqualStrings("h3", h.observed.alpn[0..h.observed.alpn_len]);
    try std.testing.expectEqual(events.CertificateState.valid, h.observed.certificate_state.?);

    // Independent verification of the first protected handshake records:
    // client- and server-derived secrets for the same direction come from
    // separate HKDF computations off each side's own ECDH share and
    // transcript hash, so equality here proves the handshake, not just the
    // record layer, is correct on both ends.
    const client = 0;
    const server = 1;
    try std.testing.expect(h.observed.handshake_write[client].?.eql(h.observed.handshake_read[server].?));
    try std.testing.expect(h.observed.handshake_read[client].?.eql(h.observed.handshake_write[server].?));
    try std.testing.expect(h.observed.application_write[client].?.eql(h.observed.application_read[server].?));
    try std.testing.expect(h.observed.application_read[client].?.eql(h.observed.application_write[server].?));

    // Each side sent exactly one handshake-epoch flight (client Finished;
    // server's EncryptedExtensions+Certificate+CertificateVerify+Finished
    // coalesced into one CRYPTO write), so the first and only handshake
    // record from each side advances that side's write sequence to 1.
    try std.testing.expectEqual(@as(u64, 1), h.observed.handshake_write_seq_after_first_record[client].?);
    try std.testing.expectEqual(@as(u64, 1), h.observed.handshake_write_seq_after_first_record[server].?);

    // Epoch discard actually happened (finding 5): initial and handshake
    // keys are gone on both sides once the handshake completes.
    try std.testing.expect(h.observed.initial_discarded[client]);
    try std.testing.expect(h.observed.initial_discarded[server]);
    try std.testing.expect(h.observed.handshake_discarded[client]);
    try std.testing.expect(h.observed.handshake_discarded[server]);
    try std.testing.expect(!h.client_bridge.hasReadKeys(.handshake));
    try std.testing.expect(!h.client_bridge.hasWriteKeys(.handshake));
    try std.testing.expect(!h.server_bridge.hasReadKeys(.handshake));
    try std.testing.expect(!h.server_bridge.hasWriteKeys(.handshake));

    // The first real protected application record, independently sealed
    // and opened through the production record stack post-handshake.
    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    const request = try h.client_bridge.sealApplicationData("GET / HTTP/1.1\r\n\r\n", &protected);
    try std.testing.expectEqual(@as(u64, 1), h.client_bridge.write_application.?.sequence);
    const parsed_request = try parseSingleRecord(.ciphertext, request);
    const opened_request = try h.server_bridge.openApplicationData(parsed_request, &plaintext);
    try std.testing.expectEqualStrings("GET / HTTP/1.1\r\n\r\n", opened_request.inner.content);
    try std.testing.expectEqual(@as(u64, 1), h.server_bridge.read_application.?.sequence);

    const response = try h.server_bridge.sealApplicationData("HTTP/1.1 200 OK\r\n\r\n", &protected);
    try std.testing.expectEqual(@as(u64, 1), h.server_bridge.write_application.?.sequence);
    const parsed_response = try parseSingleRecord(.ciphertext, response);
    const opened_response = try h.client_bridge.openApplicationData(parsed_response, &plaintext);
    try std.testing.expectEqualStrings("HTTP/1.1 200 OK\r\n\r\n", opened_response.inner.content);
    try std.testing.expectEqual(@as(u64, 1), h.client_bridge.read_application.?.sequence);

    // Cleanup on success: deinit wipes every remaining key on both sides,
    // *and* the drivers' own event sinks. The client driver's last receive
    // (the server's flight) copied fresh application traffic secrets into
    // its sink, so its scratch is provably nonempty before teardown; the
    // server driver's last receive (the client's Finished) only carried
    // non-byte-bearing discard/complete events, so its scratch may already
    // be empty -- the post-teardown check still holds either way.
    const client_driver_used = h.client_driver.sink.used;
    const server_driver_used = h.server_driver.sink.used;
    try std.testing.expect(client_driver_used > 0);
    h.deinit();
    try std.testing.expect(!h.client_bridge.hasReadKeys(.application));
    try std.testing.expect(!h.client_bridge.hasWriteKeys(.application));
    try std.testing.expect(!h.server_bridge.hasReadKeys(.application));
    try std.testing.expect(!h.server_bridge.hasWriteKeys(.application));
    try expectDriverSinkWiped(&h.client_driver, client_driver_used);
    try expectDriverSinkWiped(&h.server_driver, server_driver_used);
}

test "a tampered application record fails closed and cleanup still wipes secrets" {
    var h = Harness.init();
    defer h.deinit();
    try h.run();
    try std.testing.expect(h.client_driver.isComplete());
    try std.testing.expect(h.server_driver.isComplete());

    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    const request = try h.client_bridge.sealApplicationData("tampered request", &protected);

    var tampered: [record_codec.max_ciphertext_record_len]u8 = undefined;
    @memcpy(tampered[0..request.len], request);
    tampered[request.len - 1] ^= 0x80;

    const parsed = try parseSingleRecord(.ciphertext, tampered[0..request.len]);
    try std.testing.expectError(error.AuthenticationFailed, h.server_bridge.openApplicationData(parsed, &plaintext));

    // Fail-closed does not mean fail-dirty: teardown after the failure still
    // wipes both sides' remaining live key material, including the drivers'
    // own event sinks.
    const client_driver_used = h.client_driver.sink.used;
    const server_driver_used = h.server_driver.sink.used;
    try std.testing.expect(client_driver_used > 0);
    h.deinit();
    try std.testing.expect(!h.client_bridge.hasReadKeys(.application));
    try std.testing.expect(!h.client_bridge.hasWriteKeys(.application));
    try std.testing.expect(!h.server_bridge.hasReadKeys(.application));
    try std.testing.expect(!h.server_bridge.hasWriteKeys(.application));
    try expectDriverSinkWiped(&h.client_driver, client_driver_used);
    try expectDriverSinkWiped(&h.server_driver, server_driver_used);
}

// ===========================================================================
// #410: PureZigRecordStream drives a real TLS 1.3 handshake over a nonblocking
// socket-pair carrier.
//
// The pieces above proved the record stack in-memory by hand-pumping the
// driver. Here the *stream* owns the driver end to end: `drive()` starts the
// handshake, does nonblocking carrier I/O, parses/protects records, applies
// every emitted event, installs and discards keys, completes, and shuts down --
// with no test-only `establish()`, fabricated secrets, or hand-applied events.
//
// The real engine (`tls_backend.Tls13Backend`) is QUIC-shaped, so a thin
// `RecordModeBackend` wrapper translates its QUIC-typed event batch into the
// record-mode contract `PureZigRecordStream` owns. This wrapper is the
// "smallest wrapper needed to instantiate the shared TLS backend in record
// mode" the issue calls for; production HTTP dispatch over it is #356.
// ===========================================================================

const builtin = @import("builtin");
const es = tls_core.encrypted_stream;

const suite: tls_core.algorithms.CipherSuite = .tls_aes_128_gcm_sha256;

/// Adapts the pure-Zig TLS 1.3 engine to the record-mode handshake backend the
/// stream owns: it runs the engine into a private QUIC-typed sink, then
/// translates each event into the record contract's epoch vocabulary, dropping
/// the QUIC-only transport parameters. The engine must have
/// `omit_transport_parameters = true`.
const RecordModeBackend = struct {
    engine: *tls_backend.Tls13Backend,
    scratch: tls_handshake.EventSink = .{},

    fn init(engine_ptr: *tls_backend.Tls13Backend) RecordModeBackend {
        return .{ .engine = engine_ptr };
    }

    fn backend(self: *RecordModeBackend) es.RecordHandshakeBackend {
        return .{ .ptr = self, .startFn = start, .receiveFn = receive, .deinitFn = deinit };
    }

    fn start(ptr: *anyopaque, role: tls_core.state.Role, _: void, sink: *es.RecordTransport.EventSink) es.RecordHandshakeError!void {
        const self: *RecordModeBackend = @ptrCast(@alignCast(ptr));
        self.scratch.reset();
        const result = self.engine.backend().transport.start(role, dummy_params, &self.scratch);
        try translate(&self.scratch, sink);
        result catch |err| return mapError(err);
        if (self.deferredPolicyError()) |err| return err;
    }

    fn receive(ptr: *anyopaque, epoch: events.EncryptionEpoch, bytes: []const u8, sink: *es.RecordTransport.EventSink) es.RecordHandshakeError!void {
        const self: *RecordModeBackend = @ptrCast(@alignCast(ptr));
        self.scratch.reset();
        const result = self.engine.backend().transport.receive(toLevel(epoch), bytes, &self.scratch);
        try translate(&self.scratch, sink);
        result catch |err| return mapError(err);
        if (self.deferredPolicyError()) |err| return err;
    }

    /// The concrete engine reports ALPN/certificate policy results as events and
    /// marks its own core failed while returning success -- it expects its
    /// driver to convert those into terminal errors (the QUIC driver does the
    /// same via `AlpnMismatch`/`CertificateInvalid`). Surface that here so the
    /// record handshake fails closed instead of stalling with the peer's
    /// `Finished` still buffered and no further record ever arriving.
    fn deferredPolicyError(self: *RecordModeBackend) ?es.RecordHandshakeError {
        if (self.engine.core.handshake_lifecycle != .failed) return null;
        for (self.scratch.items[0..self.scratch.len]) |event| {
            if (event == .certificate and event.certificate == .invalid) return error.CertificateInvalid;
        }
        for (self.scratch.items[0..self.scratch.len]) |event| {
            if (event == .alpn) return error.AlpnMismatch;
        }
        return error.UnexpectedHandshakeMessage;
    }

    /// Securely wipe the last batch's copied secrets from the private sink. The
    /// engine itself is owned (and deinitialized) by the harness, not here.
    fn deinit(ptr: *anyopaque) void {
        const self: *RecordModeBackend = @ptrCast(@alignCast(ptr));
        self.scratch.deinit();
    }

    fn translate(qsink: *const tls_handshake.EventSink, rsink: *es.RecordTransport.EventSink) es.RecordHandshakeError!void {
        for (qsink.items[0..qsink.len]) |event| {
            switch (event) {
                .handshake_bytes => |c| try rsink.emitHandshakeBytes(toEpoch(c.epoch), c.data),
                .traffic_secret => |s| try rsink.emitSecret(toEpoch(s.epoch), s.direction, s.data),
                .peer_transport_parameters => {}, // QUIC-only; record mode ignores it
                .alpn => |protocol| try rsink.emitAlpn(protocol),
                .certificate => |cert_state| try rsink.emitCertificate(cert_state),
                .discard_epoch => |level| try rsink.emitDiscardEpoch(toEpoch(level)),
                .handshake_complete => try rsink.emitHandshakeComplete(),
                .fatal_alert => |alert| try rsink.emitFatalAlert(alert),
            }
        }
    }

    /// Every engine error except the three QUIC-transport-only ones (which
    /// `omit_transport_parameters` + correct epoch mapping prevent here) is
    /// already a member of the record error set.
    fn mapError(err: tls_handshake.HandshakeError) es.RecordHandshakeError {
        switch (err) {
            error.UnexpectedCryptoLevel,
            error.MissingTransportParameters,
            error.InvalidTransportParameters,
            => return error.MalformedHandshake,
            else => {},
        }
        return @errorCast(err);
    }

    fn toEpoch(level: tls_adapter.EncryptionLevel) events.EncryptionEpoch {
        return switch (level) {
            .initial => .initial,
            .zero_rtt => .zero_rtt,
            .handshake => .handshake,
            .application => .application,
        };
    }

    fn toLevel(epoch: events.EncryptionEpoch) tls_adapter.EncryptionLevel {
        return switch (epoch) {
            .initial => .initial,
            .zero_rtt => .zero_rtt,
            .handshake => .handshake,
            .application => .application,
        };
    }
};

// ── Nonblocking socket-pair carrier ─────────────────────────────────────────

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

fn readFd(fd: std.posix.fd_t, out: []u8) es.Error!usize {
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

fn writeFd(fd: std.posix.fd_t, bytes: []const u8) es.Error!usize {
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

/// A nonblocking fd carrier with an optional per-call chunk cap (to force
/// fragmented reads and partial writes) and an optional one-shot byte flip on
/// the read path (to corrupt a message in flight).
const FdCarrier = struct {
    fd: std.posix.fd_t,
    max_chunk: usize = std.math.maxInt(usize),
    read_offset: usize = 0,
    corrupt_at: ?usize = null,

    fn carrier(self: *FdCarrier) es.Carrier {
        return .{ .ptr = self, .readFn = read, .writeFn = write };
    }

    fn read(ptr: *anyopaque, out: []u8) es.Error!usize {
        const self: *FdCarrier = @ptrCast(@alignCast(ptr));
        const cap = @min(out.len, self.max_chunk);
        if (cap == 0) return error.WouldBlock;
        const n = try readFd(self.fd, out[0..cap]);
        if (self.corrupt_at) |target| {
            if (target >= self.read_offset and target < self.read_offset + n) {
                out[target - self.read_offset] ^= 0xff;
                self.corrupt_at = null;
            }
        }
        self.read_offset += n;
        return n;
    }

    fn write(ptr: *anyopaque, bytes: []const u8) es.Error!usize {
        const self: *FdCarrier = @ptrCast(@alignCast(ptr));
        const cap = @min(bytes.len, self.max_chunk);
        if (cap == 0) return error.WouldBlock;
        return writeFd(self.fd, bytes[0..cap]);
    }
};

/// Owns the two engines, wrappers, carriers, and streams for one socket-pair
/// handshake. Heap-allocated so the self-referential carrier/backend vtables
/// keep stable pointers.
const SocketHarness = struct {
    fds: [2]std.posix.fd_t,
    fds_closed: [2]bool,
    client_engine: tls_backend.Tls13Backend,
    server_engine: tls_backend.Tls13Backend,
    client_wrapper: RecordModeBackend = undefined,
    server_wrapper: RecordModeBackend = undefined,
    client_carrier: FdCarrier,
    server_carrier: FdCarrier,
    client: es.PureZigRecordStream = undefined,
    server: es.PureZigRecordStream = undefined,

    const Options = struct {
        client_chunk: usize = std.math.maxInt(usize),
        server_chunk: usize = std.math.maxInt(usize),
        client_trust: tls_backend.Trust = .{ .pinned_certificate = tls_backend.testdata.certificate_der },
        client_alpn: []const u8 = "h3",
        server_alpn: []const u8 = "h3",
    };

    fn create(opts: Options) !*SocketHarness {
        const self = try std.testing.allocator.create(SocketHarness);
        errdefer std.testing.allocator.destroy(self);
        self.fds = try testSocketPair();
        self.fds_closed = .{ false, false };

        self.client_engine = tls_backend.Tls13Backend.initClient(clientEntropy(), opts.client_trust);
        self.client_engine.omit_transport_parameters = true;
        self.client_engine.alpn = opts.client_alpn;
        self.server_engine = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity());
        self.server_engine.omit_transport_parameters = true;
        self.server_engine.alpn = opts.server_alpn;

        self.client_wrapper = RecordModeBackend.init(&self.client_engine);
        self.server_wrapper = RecordModeBackend.init(&self.server_engine);
        self.client_carrier = .{ .fd = self.fds[0], .max_chunk = opts.client_chunk };
        self.server_carrier = .{ .fd = self.fds[1], .max_chunk = opts.server_chunk };

        self.client = es.PureZigRecordStream.initWithCarrierAndBackend(.client, clientProvider(), suite, self.client_carrier.carrier(), self.client_wrapper.backend());
        self.server = es.PureZigRecordStream.initWithCarrierAndBackend(.server, serverProvider(), suite, self.server_carrier.carrier(), self.server_wrapper.backend());
        return self;
    }

    /// Close one endpoint exactly once (idempotent), so a test can close an
    /// endpoint early to model peer EOF without `destroy` double-closing a
    /// potentially-recycled descriptor.
    fn closeEndpoint(self: *SocketHarness, index: usize) void {
        if (!self.fds_closed[index]) {
            closeFd(self.fds[index]);
            self.fds_closed[index] = true;
        }
    }

    fn destroy(self: *SocketHarness) void {
        self.client.deinit();
        self.server.deinit();
        self.client_engine.deinit();
        self.server_engine.deinit();
        self.closeEndpoint(0);
        self.closeEndpoint(1);
        std.testing.allocator.destroy(self);
    }

    /// Drive both streams until `done` holds, either fails, or progress stalls.
    fn driveUntil(self: *SocketHarness, done: *const fn (*SocketHarness) bool) !void {
        var rounds: usize = 0;
        while (rounds < 5000) : (rounds += 1) {
            const c = self.client.stream().drive() catch |err| return err;
            const s = self.server.stream().drive() catch |err| return err;
            if (done(self)) return;
            if (!c.made_progress and !s.made_progress) return error.Stalled;
        }
        return error.Stalled;
    }

    fn bothComplete(self: *SocketHarness) bool {
        return self.client.bridge.handshake_complete and self.server.bridge.handshake_complete;
    }
};

test "record stream completes a real TLS 1.3 handshake over a nonblocking socket pair" {
    // Fragmentation matrix: every practical carrier chunk size, from a
    // one-byte trickle (each socket read/write splits records at arbitrary
    // boundaries, including inside the initial record header) up to whole
    // records at once, plus asymmetric client/server chunking.
    const chunks = [_][2]usize{
        .{ 1, 1 },
        .{ 2, 3 },
        .{ 3, 2 },
        .{ 5, 5 },
        .{ 7, 64 },
        .{ 64, 7 },
        .{ record_codec.max_ciphertext_record_len, record_codec.max_ciphertext_record_len },
    };
    for (chunks) |chunk| {
        const h = try SocketHarness.create(.{ .client_chunk = chunk[0], .server_chunk = chunk[1] });
        defer h.destroy();

        try h.driveUntil(SocketHarness.bothComplete);
        try std.testing.expect(h.client.bridge.handshake_complete);
        try std.testing.expect(h.server.bridge.handshake_complete);

        // Both sides installed genuine derived 1-RTT secrets (client- and
        // server-derived, from separate ECDH shares) -- proven by the peer
        // being able to open what this side sealed, below.
        try std.testing.expect(h.client.bridge.hasWriteKeys(.application));
        try std.testing.expect(h.server.bridge.hasReadKeys(.application));
        // Handshake keys were discarded on both sides by completion.
        try std.testing.expect(!h.client.bridge.hasWriteKeys(.handshake));
        try std.testing.expect(!h.server.bridge.hasReadKeys(.handshake));
        // ALPN and certificate negotiation were captured through the same
        // event contract records use.
        try std.testing.expectEqualStrings("h3", h.client.negotiatedAlpn().?);
        try std.testing.expectEqual(events.CertificateState.valid, h.client.certificateState());

        // Application plaintext flows both ways after the real handshake.
        try std.testing.expectEqual(@as(usize, 16), try h.client.stream().write("client to server"));
        try h.driveUntil(struct {
            fn done(hh: *SocketHarness) bool {
                return hh.server.readiness().can_read_plaintext;
            }
        }.done);
        var buf: [64]u8 = undefined;
        try std.testing.expectEqualStrings("client to server", buf[0..try h.server.stream().read(&buf)]);

        try std.testing.expectEqual(@as(usize, 16), try h.server.stream().write("server to client"));
        try h.driveUntil(struct {
            fn done(hh: *SocketHarness) bool {
                return hh.client.readiness().can_read_plaintext;
            }
        }.done);
        try std.testing.expectEqualStrings("server to client", buf[0..try h.client.stream().read(&buf)]);

        // Orderly close_notify shutdown.
        h.client.stream().close();
        try h.driveUntil(struct {
            fn done(hh: *SocketHarness) bool {
                return hh.client.lifecycle == .closed and hh.server.readiness().peer_closed;
            }
        }.done);
        try std.testing.expectError(error.EndOfStream, h.server.stream().read(&buf));
    }
}

test "record stream handshake fails closed when a ClientHello is corrupted in flight" {
    const h = try SocketHarness.create(.{});
    defer h.destroy();
    // Flip a byte inside the ClientHello's 32-byte random (past the 5-byte
    // record header, 4-byte handshake header, and 2-byte legacy_version) as the
    // server reads it. The X25519 key_share is untouched, so both sides derive
    // the same ECDH secret but a *different* transcript hash -- exactly the
    // "bad Finished / authentication failure" case: the server seals its flight
    // under keys the client (correct-transcript) cannot open.
    h.server_carrier.corrupt_at = record_codec.header_len + 4 + 2 + 4;

    var client_error: ?anyerror = null;
    var server_error: ?anyerror = null;
    var rounds: usize = 0;
    while (rounds < 500) : (rounds += 1) {
        _ = h.client.stream().drive() catch |err| {
            client_error = err;
            break;
        };
        _ = h.server.stream().drive() catch |err| {
            server_error = err;
            break;
        };
        if (h.client.lifecycle == .failed or h.server.lifecycle == .failed) break;
    }
    // Neither side completes, and the tamper surfaces as a stable AEAD
    // authentication failure on whichever side first opens a record sealed
    // under the diverged transcript (the client, opening the server flight).
    try std.testing.expect(!h.client.bridge.handshake_complete);
    try std.testing.expect(!h.server.bridge.handshake_complete);
    try std.testing.expect(h.client.lifecycle == .failed or h.server.lifecycle == .failed);
    const failure: ?anyerror = if (client_error) |e| e else server_error;
    try std.testing.expect(failure != null);
    try std.testing.expect(failure.? == error.AuthenticationFailed);
}

test "record stream handshake treats carrier EOF before close_notify as truncation" {
    const h = try SocketHarness.create(.{});
    defer h.destroy();

    // Complete the handshake, then the server abruptly closes its socket
    // instead of sending close_notify. `closeEndpoint` makes the harness the
    // sole owner of each descriptor, so `destroy` never double-closes it.
    try h.driveUntil(SocketHarness.bothComplete);
    h.closeEndpoint(1);
    h.server.stream().close();

    var client_error: ?anyerror = null;
    var rounds: usize = 0;
    while (rounds < 500) : (rounds += 1) {
        _ = h.client.stream().drive() catch |err| {
            client_error = err;
            break;
        };
    }
    try std.testing.expectEqual(@as(?anyerror, error.TruncatedStream), client_error);
    try std.testing.expect(h.client.lifecycle == .failed);
}

/// Drive both streams until one returns a terminal error or progress stalls,
/// returning the first error observed (client checked before server each round).
fn driveUntilError(h: *SocketHarness) ?anyerror {
    var rounds: usize = 0;
    while (rounds < 500) : (rounds += 1) {
        const c = h.client.stream().drive() catch |err| return err;
        const s = h.server.stream().drive() catch |err| return err;
        if (h.client.lifecycle == .failed or h.server.lifecycle == .failed) {
            // Give the failing side one more drive to surface its latched error.
            _ = h.client.stream().drive() catch |err| return err;
            _ = h.server.stream().drive() catch |err| return err;
            return null;
        }
        if (!c.made_progress and !s.made_progress) return null;
    }
    return null;
}

test "record stream handshake fails closed with CertificateInvalid on a wrong pinned certificate" {
    // The client pins a certificate that does not byte-equal the one the server
    // presents. Proof-of-possession still checks out, so the engine emits
    // `.certificate(.invalid)`, marks its core failed, and returns success --
    // record mode must convert that into a terminal `CertificateInvalid` rather
    // than stalling with the server `Finished` still buffered.
    var wrong_pin: [tls_backend.testdata.certificate_der.len]u8 = undefined;
    @memcpy(&wrong_pin, tls_backend.testdata.certificate_der);
    wrong_pin[wrong_pin.len / 2] ^= 0xff;

    const h = try SocketHarness.create(.{ .client_trust = .{ .pinned_certificate = &wrong_pin } });
    defer h.destroy();

    const failure = driveUntilError(h);
    try std.testing.expect(!h.client.bridge.handshake_complete);
    try std.testing.expect(!h.server.bridge.handshake_complete);
    try std.testing.expect(h.client.lifecycle == .failed);
    try std.testing.expect(failure != null);
    try std.testing.expect(failure.? == error.CertificateInvalid);
    // A repeated drive returns the stable, latched terminal error, and the
    // fatal failure wiped the captured negotiation metadata.
    try std.testing.expectError(error.CertificateInvalid, h.client.stream().drive());
    try std.testing.expectEqual(events.CertificateState.not_checked, h.client.certificateState());
}

test "record stream handshake fails closed with AlpnMismatch when the server selects a different protocol" {
    // The client offers h3; the server supports only h2. The engine reports the
    // offered protocol, marks its core failed, and returns success, deferring
    // the AlpnMismatch decision to record mode.
    const h = try SocketHarness.create(.{ .server_alpn = "h2" });
    defer h.destroy();

    const failure = driveUntilError(h);
    try std.testing.expect(!h.client.bridge.handshake_complete);
    try std.testing.expect(!h.server.bridge.handshake_complete);
    try std.testing.expect(h.server.lifecycle == .failed);
    try std.testing.expect(failure != null);
    try std.testing.expect(failure.? == error.AlpnMismatch);
    try std.testing.expectError(error.AlpnMismatch, h.server.stream().drive());
}
