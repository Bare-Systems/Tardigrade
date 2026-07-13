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
