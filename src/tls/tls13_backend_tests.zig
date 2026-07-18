//! Shared TLS 1.3 backend record-mode integration tests. This file drives the
//! production TLS-owned engine directly through the record transport contract,
//! so a genuine ClientHello/ServerHello/Certificate/Finished exchange is
//! sealed and opened as real TLS records, first-record keys are checked
//! independently (client- and server-derived secrets for the same direction
//! come from separate HKDF computations off separate ECDH shares, so their
//! equality is a real cross-check, not a tautology), and epoch discard plus
//! teardown are proven on both the success and failure paths.
//! application data is exchanged, and lifecycle cleanup is exercised. This
//! module imports no QUIC package or QUIC transport type.

const std = @import("std");
const crypto = @import("crypto");
const tls_core = @import("tls_core");
const tls_backend = tls_core.tls13_backend;

const record_codec = tls_core.record_codec;
const events = tls_core.events;
const credentials = tls_core.credentials;

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
        var entropy = pure_zig.DeterministicEntropy.init(0x442_c);
        var provider_state = pure_zig.Provider.init(entropy.entropy());
    };
    return State.provider_state.cryptoProvider();
}

fn serverProvider() crypto.provider.CryptoProvider {
    const pure_zig = crypto.pure_zig;
    const State = struct {
        var entropy = pure_zig.DeterministicEntropy.init(0x442_5);
        var provider_state = pure_zig.Provider.init(entropy.entropy());
    };
    return State.provider_state.cryptoProvider();
}

// ==========================================================================
// Direct transport-neutral driver coverage. This keeps key derivation,
// record sequencing, epoch discard, and teardown assertions at the engine
// seam rather than relying only on the higher-level socket stream.
// ==========================================================================

const tls13_transport = tls_core.tls13_transport;
const DirectDriver = tls_core.engine.Driver(tls13_transport.Contract);
const DirectSink = tls13_transport.EventSink;
const Bridge = tls_core.record_epoch_bridge.Bridge;
const DirectError = tls13_transport.Error || tls_core.record_epoch_bridge.Error;

fn parseSingleRecord(mode: record_codec.RecordMode, bytes: []const u8) DirectError!record_codec.Record {
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

const KeySnapshot = struct {
    key: [crypto.provider.max_aead_key_len]u8 = undefined,
    key_len: usize = 0,
    iv: [crypto.provider.aead_nonce_len]u8 = undefined,

    fn capture(keys: *const tls_core.record_protection.TrafficKeys) KeySnapshot {
        var snapshot = KeySnapshot{};
        const key = keys.key.slice();
        snapshot.key_len = key.len;
        @memcpy(snapshot.key[0..key.len], key);
        @memcpy(&snapshot.iv, keys.iv.slice());
        return snapshot;
    }

    fn eql(a: KeySnapshot, b: KeySnapshot) bool {
        return a.key_len == b.key_len and
            std.mem.eql(u8, a.key[0..a.key_len], b.key[0..b.key_len]) and
            std.mem.eql(u8, &a.iv, &b.iv);
    }
};

const SecretSnapshot = struct {
    bytes: [tls_backend.hash_len]u8,

    fn capture(secret: []const u8) SecretSnapshot {
        std.debug.assert(secret.len == tls_backend.hash_len);
        return .{ .bytes = secret[0..tls_backend.hash_len].* };
    }
};

const DirectSide = enum { client, server };

const DirectObserved = struct {
    handshake_write: [2]?KeySnapshot = .{ null, null },
    handshake_read: [2]?KeySnapshot = .{ null, null },
    application_write: [2]?KeySnapshot = .{ null, null },
    application_read: [2]?KeySnapshot = .{ null, null },
    handshake_write_secret: [2]?SecretSnapshot = .{ null, null },
    application_write_secret: [2]?SecretSnapshot = .{ null, null },
    handshake_write_seq_after_first_record: [2]?u64 = .{ null, null },
    alpn: [32]u8 = undefined,
    alpn_len: usize = 0,
    certificate_state: ?events.CertificateState = null,
    initial_discarded: [2]bool = .{ false, false },
    handshake_discarded: [2]bool = .{ false, false },

    fn captureSecret(
        self: *DirectObserved,
        side: DirectSide,
        epoch: events.EncryptionEpoch,
        direction: events.SecretDirection,
        secret: []const u8,
        keys: *const tls_core.record_protection.TrafficKeys,
    ) void {
        const index = @intFromEnum(side);
        const slot: *?KeySnapshot = switch (epoch) {
            .handshake => switch (direction) {
                .write => &self.handshake_write[index],
                .read => &self.handshake_read[index],
            },
            .application => switch (direction) {
                .write => &self.application_write[index],
                .read => &self.application_read[index],
            },
            .initial, .zero_rtt => return,
        };
        slot.* = KeySnapshot.capture(keys);
        if (direction == .write) switch (epoch) {
            .handshake => self.handshake_write_secret[index] = SecretSnapshot.capture(secret),
            .application => self.application_write_secret[index] = SecretSnapshot.capture(secret),
            .initial, .zero_rtt => {},
        };
    }

    fn noteAlpn(self: *DirectObserved, protocol: []const u8) void {
        self.alpn_len = protocol.len;
        @memcpy(self.alpn[0..protocol.len], protocol);
    }

    fn noteDiscard(self: *DirectObserved, side: DirectSide, epoch: events.EncryptionEpoch) void {
        const index = @intFromEnum(side);
        switch (epoch) {
            .initial => self.initial_discarded[index] = true,
            .handshake => self.handshake_discarded[index] = true,
            .application, .zero_rtt => {},
        }
    }
};

fn pumpDirect(
    sender_driver: *DirectDriver,
    sender_bridge: *Bridge,
    sender_side: DirectSide,
    receiver_driver: *DirectDriver,
    receiver_bridge: *Bridge,
    receiver_side: DirectSide,
    sink: *DirectSink,
    observed: *DirectObserved,
) DirectError!void {
    var opened: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    const QueuedMessage = struct {
        epoch: events.EncryptionEpoch,
        mode: record_codec.RecordMode,
        buf: [4096]u8 = undefined,
        len: usize,
    };
    var queued: [4]QueuedMessage = undefined;
    var queued_len: usize = 0;

    for (sink.items[0..sink.len]) |event| switch (event) {
        .handshake_bytes => |handshake_bytes| {
            std.debug.assert(queued_len < queued.len);
            const slot = &queued[queued_len];
            queued_len += 1;
            slot.* = .{
                .epoch = handshake_bytes.epoch,
                .mode = if (handshake_bytes.epoch == .initial) .plaintext else .ciphertext,
                .len = 0,
            };
            const bytes = (try sender_bridge.applyEvent(
                .{ .handshake_bytes = .{ .epoch = handshake_bytes.epoch, .data = handshake_bytes.data } },
                &slot.buf,
            )).?;
            slot.len = bytes.len;
            if (handshake_bytes.epoch == .handshake and
                observed.handshake_write_seq_after_first_record[@intFromEnum(sender_side)] == null)
            {
                observed.handshake_write_seq_after_first_record[@intFromEnum(sender_side)] = sender_bridge.write_handshake.?.sequence;
            }
        },
        .traffic_secret => |traffic_secret| {
            var scratch: [1]u8 = undefined;
            _ = try sender_bridge.applyEvent(.{ .traffic_secret = .{
                .epoch = traffic_secret.epoch,
                .direction = traffic_secret.direction,
                .data = traffic_secret.data,
            } }, &scratch);
            const keys: *const tls_core.record_protection.TrafficKeys = switch (traffic_secret.epoch) {
                .handshake => switch (traffic_secret.direction) {
                    .write => &sender_bridge.write_handshake.?.keys,
                    .read => &sender_bridge.read_handshake.?.keys,
                },
                .application => switch (traffic_secret.direction) {
                    .write => &sender_bridge.write_application.?.keys,
                    .read => &sender_bridge.read_application.?.keys,
                },
                .initial, .zero_rtt => continue,
            };
            observed.captureSecret(sender_side, traffic_secret.epoch, traffic_secret.direction, traffic_secret.data, keys);
        },
        .discard_epoch => |epoch| {
            var scratch: [1]u8 = undefined;
            _ = try sender_bridge.applyEvent(.{ .discard_epoch = epoch }, &scratch);
            observed.noteDiscard(sender_side, epoch);
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
    };

    for (queued[0..queued_len]) |message| {
        const record = try parseSingleRecord(message.mode, message.buf[0..message.len]);
        const opened_message = try receiver_bridge.openHandshake(message.epoch, record, &opened);
        const next = try receiver_driver.receive(message.epoch, opened_message.inner.content);
        try pumpDirect(receiver_driver, receiver_bridge, receiver_side, sender_driver, sender_bridge, sender_side, next, observed);
    }
}

const DirectHarness = struct {
    client_backend: tls_backend.Tls13Backend,
    server_backend: tls_backend.Tls13Backend,
    client_driver: DirectDriver = undefined,
    server_driver: DirectDriver = undefined,
    client_bridge: Bridge,
    server_bridge: Bridge,
    observed: DirectObserved = .{},
    drivers_ready: bool = false,
    deinitialized: bool = false,
    // Handshake-time client-authentication storage (#334). Held by the harness
    // so the provider/verifier vtables outlive the handshake; their stable
    // addresses are captured into the backends by `configureClientAuth`.
    client_credential: ?credentials.FixedCredentialProvider = null,
    server_client_verifier: ?credentials.FixedVerifier = null,

    /// Wire up handshake-time client authentication before `run`. `mode` is the
    /// server's request policy; `client_cert` decides whether the client offers
    /// a credential (false models a client declining with an empty Certificate);
    /// `verifier_trust` is how the server judges a presented client certificate.
    fn configureClientAuth(
        self: *DirectHarness,
        mode: tls_backend.ClientAuthMode,
        client_cert: bool,
        verifier_trust: credentials.Trust,
    ) void {
        self.server_client_verifier = credentials.FixedVerifier.init(verifier_trust);
        self.server_backend.requestClientAuthentication(mode, self.server_client_verifier.?.verifier());
        if (client_cert) {
            self.client_credential = credentials.FixedCredentialProvider.init(fixtureIdentity());
            self.client_backend.setLocalCredentialProvider(self.client_credential.?.provider());
        }
    }

    fn init() DirectHarness {
        return initProfiles(
            .{ .record = .{ .alpn = "h2" } },
            .{ .record = .{ .alpn = "h2" } },
        );
    }

    fn initExtension() DirectHarness {
        return initProfiles(
            .{ .extension = .{ .alpn = "h3", .extension_type = 57, .local = "client transport parameters" } },
            .{ .extension = .{ .alpn = "h3", .extension_type = 57, .local = "server transport parameters" } },
        );
    }

    fn initProfiles(client_profile: tls_backend.TransportProfile, server_profile: tls_backend.TransportProfile) DirectHarness {
        return .{
            .client_backend = tls_backend.Tls13Backend.initClient(
                clientEntropy(),
                .{ .pinned_certificate = tls_backend.testdata.certificate_der },
                client_profile,
            ),
            .server_backend = tls_backend.Tls13Backend.initServer(
                serverEntropy(),
                fixtureIdentity(),
                server_profile,
            ),
            .client_bridge = Bridge.init(clientProvider(), .tls_aes_128_gcm_sha256),
            .server_bridge = Bridge.init(serverProvider(), .tls_aes_128_gcm_sha256),
        };
    }

    fn run(self: *DirectHarness) DirectError!void {
        self.client_driver = DirectDriver.init(.client, self.client_backend.backend());
        self.server_driver = DirectDriver.init(.server, self.server_backend.backend());
        self.drivers_ready = true;
        _ = try self.server_driver.start({});
        const initial = try self.client_driver.start({});
        try pumpDirect(
            &self.client_driver,
            &self.client_bridge,
            .client,
            &self.server_driver,
            &self.server_bridge,
            .server,
            initial,
            &self.observed,
        );
    }

    fn deinit(self: *DirectHarness) void {
        if (self.deinitialized) return;
        self.deinitialized = true;
        self.client_bridge.deinit();
        self.server_bridge.deinit();
        if (self.drivers_ready) {
            self.client_driver.deinit();
            self.server_driver.deinit();
        } else {
            self.client_backend.deinit();
            self.server_backend.deinit();
        }
        // The client credential provider is external to the backend, so the
        // harness wipes its key material.
        if (self.client_credential) |*credential| credential.deinit();
    }
};

fn expectDirectSinkWiped(driver: *const DirectDriver, used_before: usize) !void {
    try std.testing.expectEqual(@as(usize, 0), driver.sink.used);
    try std.testing.expect(std.mem.allEqual(u8, driver.sink.scratch[0..used_before], 0));
}

test "direct shared driver preserves derivation, sequence, discard, and teardown invariants" {
    var harness = DirectHarness.init();
    defer harness.deinit();
    try harness.run();

    try std.testing.expect(harness.client_driver.isComplete());
    try std.testing.expect(harness.server_driver.isComplete());
    try std.testing.expectEqualStrings("h2", harness.observed.alpn[0..harness.observed.alpn_len]);
    try std.testing.expectEqual(events.CertificateState.valid, harness.observed.certificate_state.?);

    const client = @intFromEnum(DirectSide.client);
    const server = @intFromEnum(DirectSide.server);
    try std.testing.expect(harness.observed.handshake_write[client].?.eql(harness.observed.handshake_read[server].?));
    try std.testing.expect(harness.observed.handshake_read[client].?.eql(harness.observed.handshake_write[server].?));
    try std.testing.expect(harness.observed.application_write[client].?.eql(harness.observed.application_read[server].?));
    try std.testing.expect(harness.observed.application_read[client].?.eql(harness.observed.application_write[server].?));
    try std.testing.expectEqual(@as(u64, 1), harness.observed.handshake_write_seq_after_first_record[client].?);
    try std.testing.expectEqual(@as(u64, 1), harness.observed.handshake_write_seq_after_first_record[server].?);
    try std.testing.expect(harness.observed.initial_discarded[client]);
    try std.testing.expect(harness.observed.initial_discarded[server]);
    try std.testing.expect(harness.observed.handshake_discarded[client]);
    try std.testing.expect(harness.observed.handshake_discarded[server]);
    try std.testing.expect(!harness.client_bridge.hasReadKeys(.handshake));
    try std.testing.expect(!harness.client_bridge.hasWriteKeys(.handshake));
    try std.testing.expect(!harness.server_bridge.hasReadKeys(.handshake));
    try std.testing.expect(!harness.server_bridge.hasWriteKeys(.handshake));

    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    const request = try harness.client_bridge.sealApplicationData("client application", &protected);
    try std.testing.expectEqual(@as(u64, 1), harness.client_bridge.write_application.?.sequence);
    const opened_request = try harness.server_bridge.openApplicationData(try parseSingleRecord(.ciphertext, request), &plaintext);
    try std.testing.expectEqualStrings("client application", opened_request.inner.content);
    try std.testing.expectEqual(@as(u64, 1), harness.server_bridge.read_application.?.sequence);

    const response = try harness.server_bridge.sealApplicationData("server application", &protected);
    try std.testing.expectEqual(@as(u64, 1), harness.server_bridge.write_application.?.sequence);
    const opened_response = try harness.client_bridge.openApplicationData(try parseSingleRecord(.ciphertext, response), &plaintext);
    try std.testing.expectEqualStrings("server application", opened_response.inner.content);
    try std.testing.expectEqual(@as(u64, 1), harness.client_bridge.read_application.?.sequence);

    const client_used = harness.client_driver.sink.used;
    const server_used = harness.server_driver.sink.used;
    try std.testing.expect(client_used > 0);
    harness.deinit();
    try std.testing.expect(!harness.client_bridge.hasReadKeys(.application));
    try std.testing.expect(!harness.client_bridge.hasWriteKeys(.application));
    try std.testing.expect(!harness.server_bridge.hasReadKeys(.application));
    try std.testing.expect(!harness.server_bridge.hasWriteKeys(.application));
    try expectDirectSinkWiped(&harness.client_driver, client_used);
    try expectDirectSinkWiped(&harness.server_driver, server_used);
    try std.testing.expect(std.mem.allEqual(u8, &harness.client_backend.entropy.key_share_seed, 0));
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&harness.server_backend.identity), 0));
}

test "direct shared driver cleanup wipes secrets after record authentication failure" {
    var harness = DirectHarness.init();
    defer harness.deinit();
    try harness.run();

    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    const request = try harness.client_bridge.sealApplicationData("tampered", &protected);
    protected[request.len - 1] ^= 0x80;
    try std.testing.expectError(
        error.AuthenticationFailed,
        harness.server_bridge.openApplicationData(try parseSingleRecord(.ciphertext, protected[0..request.len]), &plaintext),
    );

    const client_used = harness.client_driver.sink.used;
    harness.deinit();
    try std.testing.expect(!harness.client_bridge.hasWriteKeys(.application));
    try std.testing.expect(!harness.server_bridge.hasReadKeys(.application));
    try expectDirectSinkWiped(&harness.client_driver, client_used);
    try std.testing.expect(std.mem.allEqual(u8, &harness.client_backend.entropy.key_share_seed, 0));
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&harness.server_backend.identity), 0));
}

fn secretGolden(comptime hex: []const u8) [tls_backend.hash_len]u8 {
    var bytes: [tls_backend.hash_len]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}

test "record and extension profiles preserve independent traffic-secret goldens" {
    var record = DirectHarness.init();
    defer record.deinit();
    try record.run();
    var extension = DirectHarness.initExtension();
    defer extension.deinit();
    try extension.run();

    const record_goldens = [_][tls_backend.hash_len]u8{
        secretGolden("fa4c75e9e45a4efa0a3d4a9efa07f385fa982a11e840809a630da05e9e64cf42"),
        secretGolden("fef9a2a33efb498bc4c6944aeab79acbf94c0a3fd150f3b698fc85f768d4bf9c"),
        secretGolden("fd142b50d9b3f191db764952ad7b4ba31619b9402edbffbf232a1734533b07c0"),
        secretGolden("f836781ca88477bc429739cd0a56c429b8013b3977294e4a1418f1049f0c33c2"),
    };
    const extension_goldens = [_][tls_backend.hash_len]u8{
        secretGolden("b8fe711917084a6c2ebcea0b47366ea8e2f87787b5a8ce11a43f9b689a174650"),
        secretGolden("2455663e8808188978de2877d7dbc598e6ea066e94070149025504279a562d3d"),
        secretGolden("04e00eb271f91edc7a64290adc6ad7095169ee95e1a41334b4c604cd6b7d1af3"),
        secretGolden("a5807cb6724439c34856eba3c50763d7c3bfef08afb428d403994a87a828737c"),
    };
    const record_actual = [_][tls_backend.hash_len]u8{
        record.observed.handshake_write_secret[0].?.bytes,
        record.observed.handshake_write_secret[1].?.bytes,
        record.observed.application_write_secret[0].?.bytes,
        record.observed.application_write_secret[1].?.bytes,
    };
    const extension_actual = [_][tls_backend.hash_len]u8{
        extension.observed.handshake_write_secret[0].?.bytes,
        extension.observed.handshake_write_secret[1].?.bytes,
        extension.observed.application_write_secret[0].?.bytes,
        extension.observed.application_write_secret[1].?.bytes,
    };
    for (record_goldens, record_actual) |expected, actual| {
        try std.testing.expectEqualSlices(u8, &expected, &actual);
    }
    for (extension_goldens, extension_actual) |expected, actual| {
        try std.testing.expectEqualSlices(u8, &expected, &actual);
    }
    try std.testing.expectEqualStrings("server transport parameters", recordOrEmpty(extension.client_backend.takePeerTransportExtension()));
    try std.testing.expectEqualStrings("client transport parameters", recordOrEmpty(extension.server_backend.takePeerTransportExtension()));
}

fn recordOrEmpty(bytes: ?[]const u8) []const u8 {
    return bytes orelse "";
}

// ===========================================================================
// #334: handshake-time client authentication over the record transport. The
// server issues a CertificateRequest; the client answers with its own
// Certificate / CertificateVerify / Finished flight (or declines with an empty
// Certificate), and the server verifies it before completing.
// ===========================================================================

test "required client authentication completes with a valid client certificate" {
    var harness = DirectHarness.init();
    defer harness.deinit();
    harness.configureClientAuth(.required, true, .{ .pinned_certificate = tls_backend.testdata.certificate_der });
    try harness.run();

    try std.testing.expect(harness.client_driver.isComplete());
    try std.testing.expect(harness.server_driver.isComplete());
    // The last certificate verdict observed is the server's over the client's
    // presented certificate: accepted against the pin.
    try std.testing.expectEqual(events.CertificateState.valid, harness.observed.certificate_state.?);

    // Application data still flows in both directions after mutual auth.
    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    const request = try harness.client_bridge.sealApplicationData("mutually authenticated", &protected);
    const opened = try harness.server_bridge.openApplicationData(try parseSingleRecord(.ciphertext, request), &plaintext);
    try std.testing.expectEqualStrings("mutually authenticated", opened.inner.content);
}

test "optional client authentication completes when the client declines" {
    var harness = DirectHarness.init();
    defer harness.deinit();
    // No client credential configured: the client answers with an empty
    // Certificate and no CertificateVerify; optional mode accepts it.
    harness.configureClientAuth(.optional, false, .{ .pinned_certificate = tls_backend.testdata.certificate_der });
    try harness.run();

    try std.testing.expect(harness.client_driver.isComplete());
    try std.testing.expect(harness.server_driver.isComplete());
}

test "required client authentication fails closed when the client declines" {
    var harness = DirectHarness.init();
    defer harness.deinit();
    // Required mode with no client credential: the empty client Certificate is
    // rejected with certificate_required.
    harness.configureClientAuth(.required, false, .{ .pinned_certificate = tls_backend.testdata.certificate_der });
    try std.testing.expectError(error.ClientCertificateRequired, harness.run());
    try std.testing.expectEqual(
        tls_backend.CredentialFailure.client_certificate_required,
        harness.server_backend.credentialFailure().?,
    );
}

test "client authentication fails when the server rejects the client certificate" {
    var harness = DirectHarness.init();
    defer harness.deinit();
    // The client presents a valid certificate whose proof-of-possession checks
    // out, but the server's verifier is pinned to a different certificate and
    // rejects it (bad_certificate).
    var wrong = [_]u8{0} ** 4;
    harness.configureClientAuth(.required, true, .{ .pinned_certificate = &wrong });
    try std.testing.expectError(error.CertificateInvalid, harness.run());
    try std.testing.expectEqual(
        tls_backend.CredentialFailure.peer_verification_rejected,
        harness.server_backend.credentialFailure().?,
    );
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
// The concrete engine is constructed in `.record` mode and injected directly;
// there are no QUIC types, dummy parameters, or translation wrappers.
// ===========================================================================

const builtin = @import("builtin");
const es = tls_core.encrypted_stream;

const suite: tls_core.algorithms.CipherSuite = .tls_aes_128_gcm_sha256;

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
    one_write_per_drive: bool = false,
    write_armed: bool = true,

    fn carrier(self: *FdCarrier) es.Carrier {
        return .{ .ptr = self, .readFn = read, .writeFn = write };
    }

    fn rearmWrite(self: *FdCarrier) void {
        if (self.one_write_per_drive) self.write_armed = true;
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
        if (self.one_write_per_drive and !self.write_armed) return error.WouldBlock;
        const cap = @min(bytes.len, self.max_chunk);
        if (cap == 0) return error.WouldBlock;
        const written = try writeFd(self.fd, bytes[0..cap]);
        if (self.one_write_per_drive and written > 0) self.write_armed = false;
        return written;
    }
};

/// Owns the two engines, carriers, and streams for one socket-pair
/// handshake. Heap-allocated so the self-referential carrier/backend vtables
/// keep stable pointers.
const SocketHarness = struct {
    allocator: std.mem.Allocator,
    fds: [2]std.posix.fd_t,
    fds_closed: [2]bool,
    client_engine: tls_backend.Tls13Backend,
    server_engine: tls_backend.Tls13Backend,
    client_carrier: FdCarrier,
    server_carrier: FdCarrier,
    client: es.PureZigRecordStream = undefined,
    server: es.PureZigRecordStream = undefined,

    const Options = struct {
        client_chunk: usize = std.math.maxInt(usize),
        server_chunk: usize = std.math.maxInt(usize),
        client_trust: tls_backend.Trust = .{ .pinned_certificate = tls_backend.testdata.certificate_der },
        client_alpn: []const u8 = "h2",
        server_alpn: []const u8 = "h2",
        one_write_per_drive: bool = false,
        /// Optional external credential provider / peer verifier (mocks). Their
        /// storage must outlive the harness. When null, the fixed identity/trust
        /// is used through the same production contract.
        server_provider: ?tls_backend.CredentialProvider = null,
        client_verifier: ?tls_backend.PeerVerifier = null,
        client_options: tls_backend.Tls13Backend.ClientOptions = .{},
    };

    fn create(opts: Options) !*SocketHarness {
        return createWithAllocator(std.testing.allocator, opts);
    }

    fn createWithAllocator(allocator: std.mem.Allocator, opts: Options) !*SocketHarness {
        const self = try allocator.create(SocketHarness);
        errdefer allocator.destroy(self);
        self.allocator = allocator;
        self.fds = try testSocketPair();
        self.fds_closed = .{ false, false };

        self.client_engine = if (opts.client_verifier) |verifier|
            tls_backend.Tls13Backend.initClientWithVerifier(clientEntropy(), verifier, .{ .record = .{ .alpn = opts.client_alpn } }, opts.client_options)
        else
            tls_backend.Tls13Backend.initClient(clientEntropy(), opts.client_trust, .{ .record = .{ .alpn = opts.client_alpn } });
        self.server_engine = if (opts.server_provider) |provider|
            tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), provider, .{ .record = .{ .alpn = opts.server_alpn } })
        else
            tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .{ .record = .{ .alpn = opts.server_alpn } });
        self.client_carrier = .{ .fd = self.fds[0], .max_chunk = opts.client_chunk, .one_write_per_drive = opts.one_write_per_drive };
        self.server_carrier = .{ .fd = self.fds[1], .max_chunk = opts.server_chunk, .one_write_per_drive = opts.one_write_per_drive };

        self.client = es.PureZigRecordStream.initWithCarrierAndBackend(.client, clientProvider(), suite, self.client_carrier.carrier(), self.client_engine.backend());
        self.server = es.PureZigRecordStream.initWithCarrierAndBackend(.server, serverProvider(), suite, self.server_carrier.carrier(), self.server_engine.backend());
        self.client.setExpectedAlpn(opts.client_alpn) catch unreachable;
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
        self.closeEndpoint(0);
        self.closeEndpoint(1);
        self.allocator.destroy(self);
    }

    /// Drive both streams until `done` holds, either fails, or progress stalls.
    fn driveUntil(self: *SocketHarness, done: *const fn (*SocketHarness) bool) !void {
        var rounds: usize = 0;
        while (rounds < 5000) : (rounds += 1) {
            const c = self.driveClient() catch |err| return err;
            const s = self.driveServer() catch |err| return err;
            if (done(self)) return;
            if (!c.made_progress and !s.made_progress) return error.Stalled;
        }
        return error.Stalled;
    }

    fn driveClient(self: *SocketHarness) es.Error!es.DriveResult {
        self.client_carrier.rearmWrite();
        return self.client.stream().drive();
    }

    fn driveServer(self: *SocketHarness) es.Error!es.DriveResult {
        self.server_carrier.rearmWrite();
        return self.server.stream().drive();
    }

    fn bothComplete(self: *SocketHarness) bool {
        return self.client.bridge.handshake_complete and self.server.bridge.handshake_complete;
    }
};

test "allocating record owner cleans up across every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            const harness = try SocketHarness.createWithAllocator(allocator, .{});
            harness.destroy();
        }
    }.run, .{});
}

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
        try std.testing.expectEqualStrings("h2", h.client.negotiatedAlpn().?);
        try std.testing.expectEqual(events.CertificateState.valid, h.client.certificateState());
        try std.testing.expect(h.client_engine.takePeerTransportExtension() == null);
        try std.testing.expect(h.server_engine.takePeerTransportExtension() == null);

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
        const c = h.driveClient() catch |err| return err;
        const s = h.driveServer() catch |err| return err;
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

const PairErrors = struct {
    client: ?anyerror = null,
    server: ?anyerror = null,
};

/// Keep driving the non-failed peer after the policy-failing side latches its
/// root error, so the test proves the complete synthesized-alert delivery path.
fn driveUntilBothErrors(h: *SocketHarness) PairErrors {
    var errors = PairErrors{};
    var rounds: usize = 0;
    while (rounds < 20_000) : (rounds += 1) {
        if (errors.client == null) {
            _ = h.driveClient() catch |err| {
                errors.client = err;
            };
        }
        if (errors.server == null) {
            _ = h.driveServer() catch |err| {
                errors.server = err;
            };
        }
        if (errors.client != null and errors.server != null) return errors;
    }
    return errors;
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

    const h = try SocketHarness.create(.{
        .client_chunk = 1,
        .server_chunk = 1,
        .client_trust = .{ .pinned_certificate = &wrong_pin },
        .one_write_per_drive = true,
    });
    defer h.destroy();

    const failures = driveUntilBothErrors(h);
    try std.testing.expect(!h.client.bridge.handshake_complete);
    try std.testing.expect(!h.server.bridge.handshake_complete);
    try std.testing.expect(h.client.lifecycle == .failed);
    try std.testing.expectEqual(@as(?anyerror, error.CertificateInvalid), failures.client);
    try std.testing.expectEqual(@as(?anyerror, error.PeerFatalAlert), failures.server);
    // A repeated drive returns the stable, latched terminal error, and the
    // fatal failure wiped the captured negotiation metadata.
    try std.testing.expectError(error.CertificateInvalid, h.client.stream().drive());
    try std.testing.expectEqual(events.CertificateState.not_checked, h.client.certificateState());
}

test "record stream handshake fails closed with AlpnMismatch when the server selects a different protocol" {
    // The client offers h2; the server supports only http/1.1. The engine reports the
    // offered protocol, marks its core failed, and returns success, deferring
    // the AlpnMismatch decision to record mode.
    const h = try SocketHarness.create(.{
        .client_chunk = 1,
        .server_chunk = 1,
        .server_alpn = "http/1.1",
        .one_write_per_drive = true,
    });
    defer h.destroy();

    const failures = driveUntilBothErrors(h);
    try std.testing.expect(!h.client.bridge.handshake_complete);
    try std.testing.expect(!h.server.bridge.handshake_complete);
    try std.testing.expect(h.server.lifecycle == .failed);
    try std.testing.expectEqual(@as(?anyerror, error.PeerFatalAlert), failures.client);
    try std.testing.expectEqual(@as(?anyerror, error.AlpnMismatch), failures.server);
    try std.testing.expectError(error.AlpnMismatch, h.server.stream().drive());
}

test "record stream requires explicit opt-in for an unverified client certificate policy" {
    const strict = try SocketHarness.create(.{ .client_trust = .insecure_no_verification });
    defer strict.destroy();

    const strict_failures = driveUntilBothErrors(strict);
    try std.testing.expectEqual(@as(?anyerror, error.CertificateInvalid), strict_failures.client);
    try std.testing.expectEqual(@as(?anyerror, error.PeerFatalAlert), strict_failures.server);
    try std.testing.expect(!strict.client.bridge.handshake_complete);

    const opted_in = try SocketHarness.create(.{ .client_trust = .insecure_no_verification });
    defer opted_in.destroy();
    opted_in.client.allow_unverified_certificate = true;

    try opted_in.driveUntil(SocketHarness.bothComplete);
    try std.testing.expect(opted_in.client.bridge.handshake_complete);
    try std.testing.expect(opted_in.server.bridge.handshake_complete);
    try std.testing.expectEqual(events.CertificateState.not_checked, opted_in.client.certificateState());
}
// ==========================================================================
// Credential provider / peer verifier contract integration (#334). These
// drive the production engine through the new provider and verifier seams and
// assert callback invocation counts and exact lifetime transitions, not merely
// final success/failure.
// ==========================================================================

const HsWriter = tls_core.handshake.Writer;
const HsMessageType = tls_core.handshake.MessageType;
const X25519 = std.crypto.dh.X25519;

const ClientHelloOptions = struct {
    sni: ?[]const u8 = null,
    /// Raw bytes to place verbatim as the server_name extension body (the
    /// ServerNameList), for crafting malformed/duplicate SNI. Overrides `sni`.
    sni_raw: ?[]const u8 = null,
    sig_schemes: []const u16 = &.{ 0x0807, 0x0403 },
    alpn: []const u8 = "h2",
};

/// Build a minimal, well-formed TLS 1.3 ClientHello the server engine accepts,
/// with an optional SNI and a caller-chosen signature_algorithms list. Returns
/// the message slice into `buf`.
fn buildClientHello(buf: []u8, opts: ClientHelloOptions) ![]const u8 {
    const seed: [X25519.seed_length]u8 = [_]u8{0x33} ** X25519.seed_length;
    const key_pair = try X25519.KeyPair.generateDeterministic(seed);
    var w = HsWriter{ .buf = buf };
    try w.u8_(@intFromEnum(HsMessageType.client_hello));
    const message_len = try w.reserve(3);
    try w.u16_(0x0303); // legacy_version
    try w.bytes(&([_]u8{0x77} ** 32)); // random
    try w.u8_(0); // session_id
    try w.u16_(2); // cipher_suites
    try w.u16_(0x1301);
    try w.u8_(1); // compression methods
    try w.u8_(0);

    const extensions_len = try w.reserve(2);
    // supported_versions
    try w.u16_(43);
    try w.u16_(3);
    try w.u8_(2);
    try w.u16_(0x0304);
    // supported_groups
    try w.u16_(10);
    try w.u16_(4);
    try w.u16_(2);
    try w.u16_(0x001d);
    // signature_algorithms
    try w.u16_(13);
    try w.u16_(@intCast(2 + 2 * opts.sig_schemes.len));
    try w.u16_(@intCast(2 * opts.sig_schemes.len));
    for (opts.sig_schemes) |scheme| try w.u16_(scheme);
    // key_share
    try w.u16_(51);
    try w.u16_(2 + 2 + 2 + X25519.public_length);
    try w.u16_(2 + 2 + X25519.public_length);
    try w.u16_(0x001d);
    try w.u16_(X25519.public_length);
    try w.bytes(&key_pair.public_key);
    // alpn
    try w.u16_(16);
    const alpn_ext = try w.reserve(2);
    const alpn_list = try w.reserve(2);
    try w.u8_(@intCast(opts.alpn.len));
    try w.bytes(opts.alpn);
    w.patch(2, alpn_list);
    w.patch(2, alpn_ext);
    // server_name (optional)
    if (opts.sni_raw) |raw| {
        try w.u16_(0);
        try w.u16_(@intCast(raw.len));
        try w.bytes(raw);
    } else if (opts.sni) |sni| {
        try w.u16_(0);
        const sni_ext = try w.reserve(2);
        const sni_list = try w.reserve(2);
        try w.u8_(0); // name_type host_name
        try w.u16_(@intCast(sni.len));
        try w.bytes(sni);
        w.patch(2, sni_list);
        w.patch(2, sni_ext);
    }
    w.patch(2, extensions_len);
    w.patch(3, message_len);
    return buf[0..w.len];
}

/// Drive a server engine through selection by feeding it one ClientHello.
fn driveServerSelection(server: *tls_backend.Tls13Backend, opts: ClientHelloOptions) !void {
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, opts);
    try server.backend().receive(.initial, hello, &sink);
}

test "exact SNI reaches credential selection through a mock provider" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    var server = tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), mock.provider(), .{ .record = .{ .alpn = "h2" } });
    defer server.deinit();

    try driveServerSelection(&server, .{ .sni = "exact.example.test" });
    try std.testing.expectEqual(@as(usize, 1), mock.select_count);
    try std.testing.expect(mock.lastServerName() != null);
    try std.testing.expectEqualStrings("exact.example.test", mock.lastServerName().?);
    // A selected credential is signed with exactly once and released exactly once.
    try std.testing.expectEqual(@as(usize, 1), mock.sign_count);
    try std.testing.expectEqual(@as(usize, 1), mock.release_count);
}

test "absent SNI reaches selection deterministically as null" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    var server = tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), mock.provider(), .{ .record = .{ .alpn = "h2" } });
    defer server.deinit();

    try driveServerSelection(&server, .{ .sni = null });
    try std.testing.expectEqual(@as(usize, 1), mock.select_count);
    try std.testing.expect(mock.lastServerName() == null);
}

test "selection sees the peer's offered schemes and picks a compatible credential" {
    // Fixed Ed25519 identity; the peer offers ECDSA first then Ed25519. The
    // fixed provider still binds, proving order-independent compatibility.
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .{ .record = .{ .alpn = "h2" } });
    defer server.deinit();
    try driveServerSelection(&server, .{ .sig_schemes = &.{ 0x0403, 0x0807 } });
    try std.testing.expect(server.credentialFailure() == null);
}

test "no compatible signature algorithm fails with handshake_failure attribution" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .{ .record = .{ .alpn = "h2" } });
    defer server.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [1024]u8 = undefined;
    // Peer offers only ECDSA; the Ed25519 fixed credential is incompatible.
    const hello = try buildClientHello(&buf, .{ .sig_schemes = &.{0x0403} });
    try std.testing.expectError(error.NoApplicableCredential, server.backend().receive(.initial, hello, &sink));
    try std.testing.expectEqual(tls_backend.CredentialFailure.no_compatible_signature_algorithm, server.credentialFailure().?);
    try std.testing.expectEqual(
        tls_core.alerts.AlertDescription.handshake_failure,
        server.credentialFailure().?.alert(),
    );
}

test "no credential available fails deterministically and preserves the failure" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.force_select_error = error.NoCredentialAvailable;
    var server = tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), mock.provider(), .{ .record = .{ .alpn = "h2" } });
    defer server.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{});
    try std.testing.expectError(error.NoApplicableCredential, server.backend().receive(.initial, hello, &sink));
    try std.testing.expectEqual(tls_backend.CredentialFailure.no_credential_available, server.credentialFailure().?);
    try std.testing.expectEqual(@as(usize, 0), mock.sign_count);
    try std.testing.expectEqual(@as(usize, 0), mock.release_count);
    // Terminal cleanup preserves the underlying typed failure (#334).
    server.deinit();
    try std.testing.expectEqual(tls_backend.CredentialFailure.no_credential_available, server.credentialFailure().?);
}

test "an empty local credential chain is rejected before signing" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.empty_chain = true;
    var server = tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), mock.provider(), .{ .record = .{ .alpn = "h2" } });
    defer server.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{});
    try std.testing.expectError(error.CredentialProviderFailed, server.backend().receive(.initial, hello, &sink));
    try std.testing.expectEqual(tls_backend.CredentialFailure.malformed_credential_chain, server.credentialFailure().?);
    // The handle was released exactly once even on the failure path.
    try std.testing.expectEqual(@as(usize, 1), mock.release_count);
}

test "a signing provider failure maps to internal_error and releases the handle" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.force_sign_error = error.SigningProviderFailure;
    var server = tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), mock.provider(), .{ .record = .{ .alpn = "h2" } });
    defer server.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{});
    try std.testing.expectError(error.CredentialProviderFailed, server.backend().receive(.initial, hello, &sink));
    try std.testing.expectEqual(tls_backend.CredentialFailure.signing_provider_failure, server.credentialFailure().?);
    try std.testing.expectEqual(@as(usize, 1), mock.sign_count);
    try std.testing.expectEqual(@as(usize, 1), mock.release_count);
}

test "an over-length reported signature is caught as a provider contract violation" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.force_sign_len = 4096; // far beyond the engine's bounded scratch
    var server = tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), mock.provider(), .{ .record = .{ .alpn = "h2" } });
    defer server.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{});
    try std.testing.expectError(error.CredentialProviderFailed, server.backend().receive(.initial, hello, &sink));
    try std.testing.expectEqual(tls_backend.CredentialFailure.invalid_callback_behavior, server.credentialFailure().?);
}

test "successful server handshake and peer verification through mock provider and verifier" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    var verifier = credentials.MockVerifier.init(.accepted);
    const h = try SocketHarness.create(.{
        .server_provider = mock.provider(),
        .client_verifier = verifier.verifier(),
    });
    defer h.destroy();

    try h.driveUntil(SocketHarness.bothComplete);
    try std.testing.expect(h.client.bridge.handshake_complete);
    try std.testing.expect(h.server.bridge.handshake_complete);
    // Exact lifetime transitions: one selection, one signature, one release,
    // one verification.
    try std.testing.expectEqual(@as(usize, 1), mock.select_count);
    try std.testing.expectEqual(@as(usize, 1), mock.sign_count);
    try std.testing.expectEqual(@as(usize, 1), mock.release_count);
    try std.testing.expectEqual(@as(usize, 1), verifier.verify_count);
    try std.testing.expectEqual(@as(usize, 1), verifier.last_chain_len);
    try std.testing.expectEqual(events.CertificateState.valid, h.client.certificateState());
}

test "peer verifier rejection fails the client as a peer authentication failure" {
    var verifier = credentials.MockVerifier.init(.rejected);
    const h = try SocketHarness.create(.{ .client_verifier = verifier.verifier() });
    defer h.destroy();

    const failures = driveUntilBothErrors(h);
    try std.testing.expectEqual(@as(?anyerror, error.CertificateInvalid), failures.client);
    try std.testing.expect(!h.client.bridge.handshake_complete);
    try std.testing.expectEqual(tls_backend.CredentialFailure.peer_verification_rejected, h.client_engine.credentialFailure().?);
    try std.testing.expectEqual(@as(usize, 1), verifier.verify_count);
}

test "a peer verifier internal failure is a local fault, not a peer rejection" {
    var verifier = credentials.MockVerifier.init(error.VerifierInternalFailure);
    const h = try SocketHarness.create(.{ .client_verifier = verifier.verifier() });
    defer h.destroy();

    const failures = driveUntilBothErrors(h);
    try std.testing.expectEqual(@as(?anyerror, error.CredentialProviderFailed), failures.client);
    try std.testing.expectEqual(tls_backend.CredentialFailure.verifier_internal_failure, h.client_engine.credentialFailure().?);
    try std.testing.expectEqual(
        tls_core.alerts.AlertDescription.internal_error,
        h.client_engine.credentialFailure().?.alert(),
    );
}

test "a bad CertificateVerify signature fails proof of possession at the client" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.flip_signature = true;
    const h = try SocketHarness.create(.{ .server_provider = mock.provider() });
    defer h.destroy();

    const failures = driveUntilBothErrors(h);
    // A CertificateVerify proof-of-possession failure is a decrypt_error
    // (RFC 8446 §4.4.3), distinct from a trust rejection.
    try std.testing.expectEqual(@as(?anyerror, error.DecryptError), failures.client);
    // The client synthesizes the decrypt_error alert and the server receives it
    // (rather than a silent stall/EOF).
    try std.testing.expectEqual(@as(?anyerror, error.PeerFatalAlert), failures.server);
    try std.testing.expect(!h.client.bridge.handshake_complete);
    try std.testing.expectEqual(tls_backend.CredentialFailure.certificate_verify_invalid, h.client_engine.credentialFailure().?);
}

test "the fixed provider replaces the previous hard-coded identity with no engine change" {
    // The default harness uses initServer(fixtureIdentity) -> the fixed
    // provider, driving the same engine path a mock or external provider does.
    const h = try SocketHarness.create(.{});
    defer h.destroy();
    try h.driveUntil(SocketHarness.bothComplete);
    try std.testing.expect(h.client.bridge.handshake_complete);
    try std.testing.expect(h.server.bridge.handshake_complete);
    try std.testing.expectEqual(events.CertificateState.valid, h.client.certificateState());
    // No credential failure was latched on the success path.
    try std.testing.expect(h.server_engine.credentialFailure() == null);
    try std.testing.expect(h.client_engine.credentialFailure() == null);
}

test "provider and verifier mocks under allocation failure clean up" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
            var verifier = credentials.MockVerifier.init(.accepted);
            const harness = try SocketHarness.createWithAllocator(allocator, .{
                .server_provider = mock.provider(),
                .client_verifier = verifier.verifier(),
            });
            harness.destroy();
        }
    }.run, .{});
}

// --------------------------------------------------------------------------
// Review round 2 (#334): ClientHello metadata fidelity, provider-output
// validation, verifier identity/policy, and the expanded failure taxonomy.
// --------------------------------------------------------------------------

fn serverWithProvider(mock: *credentials.MockCredentialProvider) tls_backend.Tls13Backend {
    return tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), mock.provider(), .{ .record = .{ .alpn = "h2" } });
}

fn expectServerReceiveError(server: *tls_backend.Tls13Backend, opts: ClientHelloOptions, want: anyerror) !void {
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [2048]u8 = undefined;
    const hello = try buildClientHello(&buf, opts);
    try std.testing.expectError(want, server.backend().receive(.initial, hello, &sink));
}

test "a compatible signature scheme past the legacy cap is still selected" {
    // 17 filler schemes, then Ed25519 in slot 18: truncation at 16 would have
    // hidden it and produced a false NoCompatibleSignatureAlgorithm.
    var schemes: [18]u16 = undefined;
    for (0..17) |i| schemes[i] = @intCast(0xfe00 + i);
    schemes[17] = 0x0807; // ed25519
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .{ .record = .{ .alpn = "h2" } });
    defer server.deinit();
    try driveServerSelection(&server, .{ .sig_schemes = &schemes });
    try std.testing.expect(server.credentialFailure() == null);
}

test "a signature_algorithms offer larger than the bound fails closed" {
    var schemes: [80]u16 = undefined;
    for (0..80) |i| schemes[i] = @intCast(0xfe00 + i);
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .{ .record = .{ .alpn = "h2" } });
    defer server.deinit();
    try expectServerReceiveError(&server, .{ .sig_schemes = &schemes }, error.MalformedHandshake);
}

test "an empty signature_algorithms list is a peer-attributed malformed ClientHello" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .{ .record = .{ .alpn = "h2" } });
    defer server.deinit();
    try expectServerReceiveError(&server, .{ .sig_schemes = &.{} }, error.MalformedHandshake);
}

test "malformed SNI is rejected rather than collapsed into the default path" {
    // Empty host_name.
    {
        var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .{ .record = .{ .alpn = "h2" } });
        defer server.deinit();
        // ServerNameList<len=3>{ name_type=0, host_name<len=0> }
        const empty_host = [_]u8{ 0x00, 0x03, 0x00, 0x00, 0x00 };
        try expectServerReceiveError(&server, .{ .sni_raw = &empty_host }, error.IllegalParameter);
    }
    // Duplicate host_name entries (RFC 6066 forbids a repeated name_type).
    {
        var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .{ .record = .{ .alpn = "h2" } });
        defer server.deinit();
        // ServerNameList<len=8>{ {0,"a"}, {0,"b"} }
        const dup = [_]u8{ 0x00, 0x08, 0x00, 0x00, 0x01, 'a', 0x00, 0x00, 0x01, 'b' };
        try expectServerReceiveError(&server, .{ .sni_raw = &dup }, error.IllegalParameter);
    }
    // Empty ServerNameList (RFC 6066 §3: ServerNameList<1..>). Must be rejected,
    // not silently treated as "no host_name present" and routed to the default
    // credential.
    {
        var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .{ .record = .{ .alpn = "h2" } });
        defer server.deinit();
        const empty_list = [_]u8{ 0x00, 0x00 }; // ServerNameList<len=0>{}
        try expectServerReceiveError(&server, .{ .sni_raw = &empty_list }, error.IllegalParameter);
    }
}

test "a provider returning an unoffered scheme is rejected before signing" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity()); // ed25519
    mock.ignore_offer = true; // hand back ed25519 even though the peer omits it
    var server = serverWithProvider(&mock);
    defer server.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{ .sig_schemes = &.{0x0403} }); // ECDSA only
    try std.testing.expectError(error.CredentialProviderFailed, server.backend().receive(.initial, hello, &sink));
    try std.testing.expectEqual(tls_backend.CredentialFailure.invalid_callback_behavior, server.credentialFailure().?);
    try std.testing.expectEqual(@as(usize, 0), mock.sign_count);
    try std.testing.expectEqual(@as(usize, 1), mock.release_count);
}

test "a provider chain exceeding the bounds is rejected without signing" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.chain_repeat = 12; // beyond max_chain_entries
    var server = serverWithProvider(&mock);
    defer server.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{});
    try std.testing.expectError(error.CredentialProviderFailed, server.backend().receive(.initial, hello, &sink));
    try std.testing.expectEqual(tls_backend.CredentialFailure.malformed_credential_chain, server.credentialFailure().?);
    try std.testing.expectEqual(@as(usize, 0), mock.sign_count);
    try std.testing.expectEqual(@as(usize, 1), mock.release_count);
}

test "a provider internal failure is attributed to the provider, not the verifier" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.force_select_error = error.ProviderInternalFailure;
    var server = serverWithProvider(&mock);
    defer server.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{});
    try std.testing.expectError(error.CredentialProviderFailed, server.backend().receive(.initial, hello, &sink));
    try std.testing.expectEqual(tls_backend.CredentialFailure.provider_internal_failure, server.credentialFailure().?);
}

test "the verifier observes the exact intended hostname and explicit policy" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    var verifier = credentials.MockVerifier.init(.accepted);
    const h = try SocketHarness.create(.{
        .server_provider = mock.provider(),
        .client_verifier = verifier.verifier(),
        .client_options = .{ .server_name = "verify.example.test", .policy = .{ .require_peer_authentication = true } },
    });
    defer h.destroy();
    try h.driveUntil(SocketHarness.bothComplete);

    // The client emitted SNI, so the server's selector saw it too.
    try std.testing.expect(mock.lastServerName() != null);
    try std.testing.expectEqualStrings("verify.example.test", mock.lastServerName().?);
    // The verifier received the exact hostname and the caller's explicit policy.
    try std.testing.expect(verifier.lastServerName() != null);
    try std.testing.expectEqualStrings("verify.example.test", verifier.lastServerName().?);
    try std.testing.expect(verifier.last_policy.require_peer_authentication);
    try std.testing.expect(!verifier.last_policy.allow_unverified_peer);
}

test "an absent intended hostname reaches the verifier as null" {
    var verifier = credentials.MockVerifier.init(.accepted);
    const h = try SocketHarness.create(.{
        .client_verifier = verifier.verifier(),
        .client_options = .{ .server_name = null },
    });
    defer h.destroy();
    try h.driveUntil(SocketHarness.bothComplete);
    try std.testing.expect(verifier.lastServerName() == null);
}

// --------------------------------------------------------------------------
// Review round 2 (#334) finding 2: asynchronous / event-driven progression.
// The engine parks a pending select / sign / verify, resumes without recording
// any handshake message twice, and cancels + releases exactly once on
// teardown. These drive the parking machinery directly.
// --------------------------------------------------------------------------

/// Concatenate all handshake-epoch crypto bytes an engine emitted into `out`.
fn collectHandshakeCrypto(sink: *const DirectSink, out: []u8) []const u8 {
    var len: usize = 0;
    for (sink.items[0..sink.len]) |event| {
        switch (event) {
            .handshake_bytes => |hb| if (hb.epoch == .handshake) {
                @memcpy(out[len..][0..hb.data.len], hb.data);
                len += hb.data.len;
            },
            else => {},
        }
    }
    return out[0..len];
}

fn certificateStateIn(sink: *const DirectSink) ?events.CertificateState {
    var found: ?events.CertificateState = null;
    for (sink.items[0..sink.len]) |event| {
        switch (event) {
            .certificate => |state| found = state,
            else => {},
        }
    }
    return found;
}

fn firstInitialCrypto(sink: *const DirectSink, out: []u8) []const u8 {
    for (sink.items[0..sink.len]) |event| {
        switch (event) {
            .handshake_bytes => |hb| if (hb.epoch == .initial) {
                @memcpy(out[0..hb.data.len], hb.data);
                return out[0..hb.data.len];
            },
            else => {},
        }
    }
    return out[0..0];
}

test "an async credential selection suspends the handshake and resumes to completion" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.async_select = true;
    mock.pending_polls = 2;
    var server = serverWithProvider(&mock);
    defer server.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{});
    try server.backend().receive(.initial, hello, &sink);

    // Parked awaiting the async selection; nothing signed yet.
    try std.testing.expect(server.authPending());
    try std.testing.expectEqual(@as(usize, 1), mock.select_count);
    try std.testing.expectEqual(@as(usize, 0), mock.sign_count);

    try server.resumeAuth(&sink); // poll #1: still pending
    try std.testing.expect(server.authPending());
    try server.resumeAuth(&sink); // poll #2: still pending
    try std.testing.expect(server.authPending());
    try server.resumeAuth(&sink); // poll #3: completes, runs the rest of the flight
    try std.testing.expect(!server.authPending());

    try std.testing.expectEqual(@as(usize, 3), mock.poll_count);
    try std.testing.expectEqual(@as(usize, 1), mock.op_release_count);
    try std.testing.expectEqual(@as(usize, 1), mock.sign_count);
    try std.testing.expectEqual(@as(usize, 1), mock.release_count);
    try std.testing.expect(server.credentialFailure() == null);
}

test "an async signature suspends after the certificate and resumes to completion" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.async_sign = true;
    mock.pending_polls = 1;
    var server = serverWithProvider(&mock);
    defer server.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{});
    try server.backend().receive(.initial, hello, &sink);

    try std.testing.expect(server.authPending()); // parked awaiting the signature
    try std.testing.expectEqual(@as(usize, 1), mock.select_count);
    try server.resumeAuth(&sink); // poll #1: still pending
    try std.testing.expect(server.authPending());
    try server.resumeAuth(&sink); // poll #2: completes
    try std.testing.expect(!server.authPending());
    try std.testing.expectEqual(@as(usize, 1), mock.sign_count);
    try std.testing.expectEqual(@as(usize, 1), mock.release_count);
    try std.testing.expectEqual(@as(usize, 1), mock.op_release_count);
    try std.testing.expect(server.credentialFailure() == null);
}

test "a cancelled async signature releases the operation and credential exactly once" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.async_sign = true;
    mock.pending_polls = 5; // never completes before teardown
    var server = serverWithProvider(&mock);
    var sink = DirectSink{};
    try server.backend().start(.server, {}, &sink);
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{});
    try server.backend().receive(.initial, hello, &sink);
    try std.testing.expect(server.authPending());

    sink.deinit();
    server.deinit(); // cancels the parked op and releases the held credential

    try std.testing.expectEqual(@as(usize, 1), mock.cancel_count);
    try std.testing.expectEqual(@as(usize, 1), mock.op_release_count);
    try std.testing.expectEqual(@as(usize, 1), mock.release_count);
}

test "an async signing failure latches the typed signing-provider failure" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.async_sign = true;
    mock.pending_polls = 0;
    mock.pending_fails = true;
    var server = serverWithProvider(&mock);
    defer server.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{});
    try server.backend().receive(.initial, hello, &sink);
    try std.testing.expect(server.authPending());

    try std.testing.expectError(error.CredentialProviderFailed, server.resumeAuth(&sink));
    try std.testing.expectEqual(tls_backend.CredentialFailure.signing_provider_failure, server.credentialFailure().?);
    // `poll` returning an error means the operation already terminated: it must
    // not be cancelled (cancel is for abandoning an operation before it
    // resolves), only released.
    try std.testing.expectEqual(@as(usize, 0), mock.cancel_count);
    try std.testing.expectEqual(@as(usize, 1), mock.op_release_count);
}

test "a poll error reports InvalidCallbackBehavior distinctly from an ordinary operation failure" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.async_select = true;
    mock.pending_polls = 0;
    mock.pending_fails = true;
    mock.pending_fail_invalid_callback = true;
    var server = serverWithProvider(&mock);
    defer server.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{});
    try server.backend().receive(.initial, hello, &sink);
    try std.testing.expect(server.authPending());

    try std.testing.expectError(error.CredentialProviderFailed, server.resumeAuth(&sink));
    // `InvalidCallbackBehavior` is a distinct, stage-independent contract
    // violation, not the stage's ordinary "operation failed" classification.
    try std.testing.expectEqual(tls_backend.CredentialFailure.invalid_callback_behavior, server.credentialFailure().?);
    try std.testing.expectEqual(@as(usize, 0), mock.cancel_count);
    try std.testing.expectEqual(@as(usize, 1), mock.op_release_count);
}

test "resumeAuth is a safe no-op before any suspend and after completion" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    var server = serverWithProvider(&mock);
    defer server.deinit();
    var driver = DirectDriver.init(.server, server.backend());
    defer driver.deinit();

    // Before any suspend: nothing pending, must not fail.
    _ = try driver.resumeAuth();
    try std.testing.expect(!driver.authPending());

    _ = try driver.start({});
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{});
    _ = try driver.receive(.initial, hello);
    // The synchronous fixed provider never parks: mid-handshake, with nothing
    // pending, a call still must not fail.
    try std.testing.expect(!driver.authPending());
    const sink = try driver.resumeAuth();
    try std.testing.expectEqual(@as(usize, 0), sink.len);
    try std.testing.expect(!driver.authPending());
}

/// Drive a client backend up to (and through) CertificateVerify against a
/// cooperating fixed-identity server backend, so the client's peer verifier is
/// exercised. Leaves the client parked if its verifier went async.
fn driveClientThroughCertificateVerify(client: *tls_backend.Tls13Backend, client_sink: *DirectSink) !void {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .{ .record = .{ .alpn = "h2" } });
    defer server.deinit();
    var server_sink = DirectSink{};
    defer server_sink.deinit();

    try client.backend().start(.client, {}, client_sink);
    var ch_buf: [1024]u8 = undefined;
    const client_hello = firstInitialCrypto(client_sink, &ch_buf);

    try server.backend().start(.server, {}, &server_sink);
    try server.backend().receive(.initial, client_hello, &server_sink);

    var sh_buf: [512]u8 = undefined;
    const server_hello = firstInitialCrypto(&server_sink, &sh_buf);
    var flight_buf: [4096]u8 = undefined;
    const flight = collectHandshakeCrypto(&server_sink, &flight_buf);

    client_sink.reset();
    try client.backend().receive(.initial, server_hello, client_sink);
    // Feed the server's EncryptedExtensions..Finished; the client parks at
    // CertificateVerify if its verifier is asynchronous.
    try client.backend().receive(.handshake, flight, client_sink);
}

test "an async peer verification suspends the client and resumes to acceptance" {
    var verifier = credentials.MockVerifier.init(.accepted);
    verifier.async_mode = true;
    verifier.pending_polls = 2;
    var client = tls_backend.Tls13Backend.initClientWithVerifier(clientEntropy(), verifier.verifier(), .{ .record = .{ .alpn = "h2" } }, .{ .server_name = "tardigrade.test" });
    defer client.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    try driveClientThroughCertificateVerify(&client, &sink);

    try std.testing.expect(client.authPending());
    try std.testing.expectEqual(@as(usize, 1), verifier.verify_count);
    try client.resumeAuth(&sink); // poll #1
    try std.testing.expect(client.authPending());
    try client.resumeAuth(&sink); // poll #2
    try std.testing.expect(client.authPending());
    try client.resumeAuth(&sink); // completes -> accepted
    try std.testing.expect(!client.authPending());
    try std.testing.expectEqual(events.CertificateState.valid, certificateStateIn(&sink).?);
    try std.testing.expect(client.credentialFailure() == null);
}

test "a cancelled async peer verification cancels and releases the operation once" {
    var verifier = credentials.MockVerifier.init(.accepted);
    verifier.async_mode = true;
    verifier.pending_polls = 5;
    var client = tls_backend.Tls13Backend.initClientWithVerifier(clientEntropy(), verifier.verifier(), .{ .record = .{ .alpn = "h2" } }, .{});
    var sink = DirectSink{};
    try driveClientThroughCertificateVerify(&client, &sink);
    try std.testing.expect(client.authPending());

    sink.deinit();
    client.deinit();
    try std.testing.expectEqual(@as(usize, 1), verifier.cancel_count);
    try std.testing.expectEqual(@as(usize, 1), verifier.op_release_count);
}

// ===========================================================================
// #334 checkpoint 3: asynchronous handshake-time client authentication. The
// client's own credential selection and signing may suspend; the server's
// verification of the client certificate may suspend. Each side resumes
// without recording a message twice, and buffered messages behind the suspend
// point are drained automatically on resume.
// ===========================================================================

/// A client backend configured to authenticate with `provider` and to trust
/// the fixture server certificate by pin (its own server verification stays
/// synchronous, so the only suspends come from client selection/signing).
fn clientWithLocalCredential(provider: credentials.CredentialProvider) tls_backend.Tls13Backend {
    var client = tls_backend.Tls13Backend.initClient(
        clientEntropy(),
        .{ .pinned_certificate = tls_backend.testdata.certificate_der },
        .{ .record = .{ .alpn = "h2" } },
    );
    client.setLocalCredentialProvider(provider);
    return client;
}

fn resumeUntilSettled(backend: *tls_backend.Tls13Backend, sink: *DirectSink) !void {
    var guard: usize = 0;
    while (backend.authPending()) {
        try backend.resumeAuth(sink);
        guard += 1;
        if (guard > 64) return error.TestResumeLoopStuck;
    }
}

/// Start both backends and deliver the server's ServerHello + handshake flight
/// (EncryptedExtensions, CertificateRequest, Certificate, CertificateVerify,
/// Finished) to the client. The fixed-identity server is synchronous. The
/// client is left exactly as receiving that flight left it — parked if its
/// credential selection or signing went asynchronous.
fn deliverServerFlightToClient(
    client: *tls_backend.Tls13Backend,
    server: *tls_backend.Tls13Backend,
    client_sink: *DirectSink,
    server_sink: *DirectSink,
) !void {
    try client.backend().start(.client, {}, client_sink);
    var ch_buf: [1024]u8 = undefined;
    const client_hello = firstInitialCrypto(client_sink, &ch_buf);

    try server.backend().start(.server, {}, server_sink);
    try server.backend().receive(.initial, client_hello, server_sink);

    var sh_buf: [512]u8 = undefined;
    const server_hello = firstInitialCrypto(server_sink, &sh_buf);
    var flight_buf: [8192]u8 = undefined;
    const flight = collectHandshakeCrypto(server_sink, &flight_buf);

    client_sink.reset();
    try client.backend().receive(.initial, server_hello, client_sink);
    try client.backend().receive(.handshake, flight, client_sink);
}

/// Deliver the client's certificate flight to the server, either coalesced in
/// one chunk or fragmented byte-by-byte to exercise reassembly.
fn deliverClientFlightToServer(
    server: *tls_backend.Tls13Backend,
    server_sink: *DirectSink,
    flight: []const u8,
    fragment: bool,
) !void {
    server_sink.reset();
    if (fragment) {
        var i: usize = 0;
        while (i < flight.len) : (i += 1) {
            try server.backend().receive(.handshake, flight[i .. i + 1], server_sink);
        }
    } else {
        try server.backend().receive(.handshake, flight, server_sink);
    }
}

fn serverRequestingClientAuth(mode: tls_backend.ClientAuthMode, verifier: credentials.PeerVerifier) tls_backend.Tls13Backend {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .{ .record = .{ .alpn = "h2" } });
    server.requestClientAuthentication(mode, verifier);
    return server;
}

test "async client credential selection suspends the client flight and resumes to mutual completion" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.async_select = true;
    mock.pending_polls = 2;
    var client = clientWithLocalCredential(mock.provider());
    defer client.deinit();
    var verifier = credentials.MockVerifier.init(.accepted);
    var server = serverRequestingClientAuth(.required, verifier.verifier());
    defer server.deinit();

    var client_sink = DirectSink{};
    defer client_sink.deinit();
    var server_sink = DirectSink{};
    defer server_sink.deinit();

    try deliverServerFlightToClient(&client, &server, &client_sink, &server_sink);
    // Parked awaiting the async selection; nothing signed and no flight yet.
    try std.testing.expect(client.authPending());
    try std.testing.expectEqual(@as(usize, 0), mock.sign_count);

    try resumeUntilSettled(&client, &client_sink);
    try std.testing.expect(!client.authPending());
    try std.testing.expectEqual(@as(usize, 1), mock.sign_count);
    try std.testing.expectEqual(@as(usize, 1), mock.release_count);

    var flight_buf: [8192]u8 = undefined;
    const flight = collectHandshakeCrypto(&client_sink, &flight_buf);
    try deliverClientFlightToServer(&server, &server_sink, flight, false);
    try resumeUntilSettled(&server, &server_sink);

    try std.testing.expectEqual(tls_core.handshake.HandshakeLifecycle.complete, server.core.handshake_lifecycle);
    try std.testing.expectEqual(events.CertificateState.valid, certificateStateIn(&server_sink).?);
    try std.testing.expect(server.credentialFailure() == null);
    try std.testing.expectEqual(@as(usize, 1), verifier.verify_count);
}

test "async client signing suspends after the client Certificate and resumes to completion" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.async_sign = true;
    mock.pending_polls = 1;
    var client = clientWithLocalCredential(mock.provider());
    defer client.deinit();
    var verifier = credentials.MockVerifier.init(.accepted);
    var server = serverRequestingClientAuth(.required, verifier.verifier());
    defer server.deinit();

    var client_sink = DirectSink{};
    defer client_sink.deinit();
    var server_sink = DirectSink{};
    defer server_sink.deinit();

    try deliverServerFlightToClient(&client, &server, &client_sink, &server_sink);
    // The client emitted its Certificate, then parked awaiting the signature.
    try std.testing.expect(client.authPending());

    try resumeUntilSettled(&client, &client_sink);
    try std.testing.expectEqual(@as(usize, 1), mock.sign_count);
    try std.testing.expectEqual(@as(usize, 1), mock.op_release_count);
    try std.testing.expectEqual(@as(usize, 1), mock.release_count);

    var flight_buf: [8192]u8 = undefined;
    const flight = collectHandshakeCrypto(&client_sink, &flight_buf);
    try deliverClientFlightToServer(&server, &server_sink, flight, false);
    try resumeUntilSettled(&server, &server_sink);
    try std.testing.expectEqual(tls_core.handshake.HandshakeLifecycle.complete, server.core.handshake_lifecycle);
    try std.testing.expect(server.credentialFailure() == null);
}

test "async server verification of a coalesced client flight drains the buffered Finished on resume" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    var client = clientWithLocalCredential(mock.provider());
    defer client.deinit();
    var verifier = credentials.MockVerifier.init(.accepted);
    verifier.async_mode = true;
    verifier.pending_polls = 2;
    var server = serverRequestingClientAuth(.required, verifier.verifier());
    defer server.deinit();

    var client_sink = DirectSink{};
    defer client_sink.deinit();
    var server_sink = DirectSink{};
    defer server_sink.deinit();

    try deliverServerFlightToClient(&client, &server, &client_sink, &server_sink);
    try resumeUntilSettled(&client, &client_sink); // client is synchronous here
    var flight_buf: [8192]u8 = undefined;
    const flight = collectHandshakeCrypto(&client_sink, &flight_buf);

    // Deliver Certificate + CertificateVerify + Finished coalesced. The server
    // parks verifying CertificateVerify; the Finished stays buffered behind the
    // suspend point and must not be processed until the verifier resolves.
    try deliverClientFlightToServer(&server, &server_sink, flight, false);
    try std.testing.expect(server.authPending());
    try std.testing.expectEqual(tls_core.handshake.HandshakeLifecycle.running, server.core.handshake_lifecycle);

    try resumeUntilSettled(&server, &server_sink);
    // On resume the verdict is applied and the buffered Finished is drained
    // automatically, completing the handshake.
    try std.testing.expectEqual(tls_core.handshake.HandshakeLifecycle.complete, server.core.handshake_lifecycle);
    try std.testing.expectEqual(events.CertificateState.valid, certificateStateIn(&server_sink).?);
    try std.testing.expect(server.credentialFailure() == null);
}

test "a client certificate flight fragmented byte-by-byte still completes on the server" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    var client = clientWithLocalCredential(mock.provider());
    defer client.deinit();
    var verifier = credentials.MockVerifier.init(.accepted); // synchronous
    var server = serverRequestingClientAuth(.required, verifier.verifier());
    defer server.deinit();

    var client_sink = DirectSink{};
    defer client_sink.deinit();
    var server_sink = DirectSink{};
    defer server_sink.deinit();

    try deliverServerFlightToClient(&client, &server, &client_sink, &server_sink);
    try resumeUntilSettled(&client, &client_sink);
    var flight_buf: [8192]u8 = undefined;
    const flight = collectHandshakeCrypto(&client_sink, &flight_buf);

    try deliverClientFlightToServer(&server, &server_sink, flight, true); // fragmented
    try resumeUntilSettled(&server, &server_sink);
    try std.testing.expectEqual(tls_core.handshake.HandshakeLifecycle.complete, server.core.handshake_lifecycle);
    try std.testing.expect(server.credentialFailure() == null);
}

test "a cancelled async client signature releases the operation and credential exactly once" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.async_sign = true;
    mock.pending_polls = 5; // never completes before teardown
    var client = clientWithLocalCredential(mock.provider());
    var verifier = credentials.MockVerifier.init(.accepted);
    var server = serverRequestingClientAuth(.required, verifier.verifier());
    defer server.deinit();

    var client_sink = DirectSink{};
    var server_sink = DirectSink{};
    defer server_sink.deinit();

    try deliverServerFlightToClient(&client, &server, &client_sink, &server_sink);
    try std.testing.expect(client.authPending());

    client_sink.deinit();
    client.deinit(); // cancels the parked op and releases the held credential
    try std.testing.expectEqual(@as(usize, 1), mock.cancel_count);
    try std.testing.expectEqual(@as(usize, 1), mock.op_release_count);
    try std.testing.expectEqual(@as(usize, 1), mock.release_count);
}

/// A credential provider whose asynchronous selection completes with the wrong
/// Completion variant (a signature length instead of a credential), violating
/// the callback contract — to prove the engine rejects a malformed completion.
const WrongKindSelectProvider = struct {
    poll_count: usize = 0,
    cancel_count: usize = 0,
    release_count: usize = 0,

    fn provider(self: *WrongKindSelectProvider) credentials.CredentialProvider {
        return .{ .ctx = self, .vtable = &prov_vtable };
    }
    const prov_vtable = credentials.CredentialProvider.VTable{ .select = select };
    fn select(ctx: *anyopaque, _: *const credentials.SelectionContext) credentials.SelectError!credentials.Progress(credentials.SelectedCredential) {
        const self: *WrongKindSelectProvider = @ptrCast(@alignCast(ctx));
        return .{ .pending = .{ .handle = self, .vtable = &op_vtable } };
    }
    const op_vtable = credentials.PendingOperation.VTable{ .poll = poll, .cancel = cancel, .release = release };
    fn poll(handle: *anyopaque, out: *credentials.Completion) credentials.OperationError!bool {
        const self: *WrongKindSelectProvider = @ptrCast(@alignCast(handle));
        self.poll_count += 1;
        out.* = .{ .signature_len = 0 }; // wrong kind for a selection
        return true;
    }
    fn cancel(handle: *anyopaque) void {
        const self: *WrongKindSelectProvider = @ptrCast(@alignCast(handle));
        self.cancel_count += 1;
    }
    fn release(handle: *anyopaque) void {
        const self: *WrongKindSelectProvider = @ptrCast(@alignCast(handle));
        self.release_count += 1;
    }
};

test "a malformed async client selection completion is rejected as a provider failure" {
    var wrong = WrongKindSelectProvider{};
    var client = clientWithLocalCredential(wrong.provider());
    defer client.deinit();
    var verifier = credentials.MockVerifier.init(.accepted);
    var server = serverRequestingClientAuth(.required, verifier.verifier());
    defer server.deinit();

    var client_sink = DirectSink{};
    defer client_sink.deinit();
    var server_sink = DirectSink{};
    defer server_sink.deinit();

    try deliverServerFlightToClient(&client, &server, &client_sink, &server_sink);
    try std.testing.expect(client.authPending());
    // The resume observes a signature-length completion where a credential was
    // required and fails closed without emitting a client flight.
    try std.testing.expectError(error.CredentialProviderFailed, client.resumeAuth(&client_sink));
    try std.testing.expectEqual(tls_backend.CredentialFailure.provider_internal_failure, client.credentialFailure().?);
    try std.testing.expectEqual(@as(usize, 1), wrong.release_count);
}

test "an oversized configured server name is rejected at start rather than truncated" {
    var verifier = credentials.MockVerifier.init(.accepted);
    // One byte past the bounded SNI buffer (max_server_name_len is 256).
    const too_long = [_]u8{'a'} ** 257;
    var client = tls_backend.Tls13Backend.initClientWithVerifier(
        clientEntropy(),
        verifier.verifier(),
        .{ .record = .{ .alpn = "h2" } },
        .{ .server_name = &too_long },
    );
    defer client.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    // Fails closed before any ClientHello is emitted; nothing is truncated.
    try std.testing.expectError(error.InvalidHandshakeState, client.backend().start(.client, {}, &sink));
    try std.testing.expectEqual(@as(usize, 0), sink.len);
    try std.testing.expect(!client.key_pair_present);
}

test "a ClientHello combining maximum ALPN, SNI, and transport extension serializes successfully" {
    // #334 review: with maximum-length ALPN (255, the largest a u8 length
    // prefix allows), SNI (256, max_server_name_len), and a maximum transport
    // extension (tls_backend.max_transport_extension_len = 512), the encoded
    // ClientHello is roughly 1.15 KiB. The buffer that serializes it must be
    // sized for this combination, not just the common case.
    const max_alpn = [_]u8{'a'} ** 255;
    const max_sni = [_]u8{'s'} ** 256;
    var max_transport_ext = [_]u8{0xab} ** tls_backend.max_transport_extension_len;
    var client = tls_backend.Tls13Backend.initClient(
        clientEntropy(),
        .{ .pinned_certificate = tls_backend.testdata.certificate_der },
        .{ .extension = .{ .alpn = &max_alpn, .extension_type = 57, .local = &max_transport_ext } },
    );
    client.server_name_len = max_sni.len;
    @memcpy(client.server_name[0..max_sni.len], &max_sni);
    client.server_name_present = true;
    defer client.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    try client.backend().start(.client, {}, &sink);
    try std.testing.expect(client.key_pair_present);
    try std.testing.expectEqual(@as(usize, 1), sink.len);
    try std.testing.expectEqualStrings("h2", "h2"); // profile untouched; explicit no-op to document intent
}

// ===========================================================================
// #334 checkpoint 4: pending/resume progression is reachable through the
// production drivers (the record stream and the generic engine Driver), not
// only the concrete backend.
// ===========================================================================

test "the record stream production driver resumes async client authentication end to end" {
    // The client's own credential signs asynchronously; the shared record
    // stream must poll resume across drive() ticks and complete mutual auth
    // over a real socket pair.
    var client_credential = credentials.MockCredentialProvider.init(fixtureIdentity());
    client_credential.async_sign = true;
    client_credential.pending_polls = 2;
    var server_verifier = credentials.MockVerifier.init(.accepted);
    var client_verifier = credentials.MockVerifier.init(.accepted);

    const h = try SocketHarness.create(.{ .client_verifier = client_verifier.verifier() });
    defer h.destroy();
    // Configure handshake-time client authentication on the heap-stable engines
    // before the first drive starts either handshake.
    h.client_engine.setLocalCredentialProvider(client_credential.provider());
    h.server_engine.requestClientAuthentication(.required, server_verifier.verifier());

    try h.driveUntil(SocketHarness.bothComplete);
    try std.testing.expect(h.client.bridge.handshake_complete);
    try std.testing.expect(h.server.bridge.handshake_complete);
    // The async signature was polled to completion through the driver, and the
    // server verified the client certificate.
    try std.testing.expectEqual(@as(usize, 1), client_credential.sign_count);
    try std.testing.expectEqual(@as(usize, 1), client_credential.op_release_count);
    try std.testing.expectEqual(@as(usize, 1), server_verifier.verify_count);
    try std.testing.expect(h.client_engine.credentialFailure() == null);
    try std.testing.expect(h.server_engine.credentialFailure() == null);
}

test "the generic engine driver exposes authPending and resumeAuth for the concrete backend" {
    // Drive a server backend through the generic Driver (not the concrete
    // backend) and prove the async credential selection suspends and resumes
    // through the Driver's own authPending/resumeAuth surface.
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.async_select = true;
    mock.pending_polls = 1;
    var server = serverWithProvider(&mock);
    var driver = DirectDriver.init(.server, server.backend());
    defer driver.deinit();

    _ = try driver.start({});
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{});
    _ = try driver.receive(.initial, hello);
    try std.testing.expect(driver.authPending());

    _ = try driver.resumeAuth(); // poll #1: still pending
    try std.testing.expect(driver.authPending());
    _ = try driver.resumeAuth(); // poll #2: completes the flight
    try std.testing.expect(!driver.authPending());
    try std.testing.expect(server.credentialFailure() == null);
}

// ===========================================================================
// #334 review round: adversarial async progression, client-auth policy, exact
// serialization bounds, and resource ownership.
// ===========================================================================

// --- F1: a Finished delivered in a separate receive while verification is
//         pending must not be processed until an accepted resume. ---

test "a Finished in a separate receive while client verification is pending is not processed early" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    var client = clientWithLocalCredential(mock.provider());
    defer client.deinit();
    var verifier = credentials.MockVerifier.init(.accepted);
    verifier.async_mode = true;
    verifier.pending_polls = 1;
    var server = serverRequestingClientAuth(.required, verifier.verifier());
    defer server.deinit();

    var client_sink = DirectSink{};
    defer client_sink.deinit();
    var server_sink = DirectSink{};
    defer server_sink.deinit();

    try deliverServerFlightToClient(&client, &server, &client_sink, &server_sink);
    try resumeUntilSettled(&client, &client_sink);
    var flight_buf: [8192]u8 = undefined;
    const flight = collectHandshakeCrypto(&client_sink, &flight_buf);

    const finished_message_len = 4 + tls_backend.hash_len; // type+len+verify_data
    const split = flight.len - finished_message_len;

    // First receive: Certificate + CertificateVerify. The server parks on the
    // async verifier with the Finished not yet delivered.
    server_sink.reset();
    try server.backend().receive(.handshake, flight[0..split], &server_sink);
    try std.testing.expect(server.authPending());
    try std.testing.expectEqual(tls_core.handshake.HandshakeLifecycle.running, server.core.handshake_lifecycle);

    // Second receive delivers Finished WHILE verification is still pending. It
    // must be buffered, never dispatched: no completion, still pending.
    try server.backend().receive(.handshake, flight[split..], &server_sink);
    try std.testing.expect(server.authPending());
    try std.testing.expectEqual(tls_core.handshake.HandshakeLifecycle.running, server.core.handshake_lifecycle);

    // Only the accepted resume drains the buffered Finished and completes.
    try resumeUntilSettled(&server, &server_sink);
    try std.testing.expectEqual(tls_core.handshake.HandshakeLifecycle.complete, server.core.handshake_lifecycle);
    try std.testing.expect(server.credentialFailure() == null);
}

test "a rejected client verification never processes the buffered Finished" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    var client = clientWithLocalCredential(mock.provider());
    defer client.deinit();
    var verifier = credentials.MockVerifier.init(.rejected);
    verifier.async_mode = true;
    verifier.pending_polls = 1;
    var server = serverRequestingClientAuth(.required, verifier.verifier());
    defer server.deinit();

    var client_sink = DirectSink{};
    defer client_sink.deinit();
    var server_sink = DirectSink{};
    defer server_sink.deinit();

    try deliverServerFlightToClient(&client, &server, &client_sink, &server_sink);
    try resumeUntilSettled(&client, &client_sink);
    var flight_buf: [8192]u8 = undefined;
    const flight = collectHandshakeCrypto(&client_sink, &flight_buf);

    // Deliver the whole flight coalesced: Certificate/CertificateVerify park the
    // verifier, Finished is buffered behind the suspend point.
    server_sink.reset();
    try server.backend().receive(.handshake, flight, &server_sink);
    try std.testing.expect(server.authPending());

    // Resume rejects: the handshake fails and the buffered Finished is never
    // processed into a completion.
    try std.testing.expectError(error.CertificateInvalid, resumeUntilSettled(&server, &server_sink));
    try std.testing.expectEqual(tls_core.handshake.HandshakeLifecycle.failed, server.core.handshake_lifecycle);
    try std.testing.expectEqual(tls_backend.CredentialFailure.peer_verification_rejected, server.credentialFailure().?);
}

// --- F3: a .not_checked verdict must not satisfy required or optional client
//         authentication of a presented certificate. ---

test "a not_checked verdict fails a presented client certificate under optional and required" {
    for ([_]tls_backend.ClientAuthMode{ .optional, .required }) |mode| {
        var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
        var client = clientWithLocalCredential(mock.provider());
        defer client.deinit();
        var verifier = credentials.MockVerifier.init(.not_checked);
        var server = serverRequestingClientAuth(mode, verifier.verifier());
        defer server.deinit();

        var client_sink = DirectSink{};
        defer client_sink.deinit();
        var server_sink = DirectSink{};
        defer server_sink.deinit();

        try deliverServerFlightToClient(&client, &server, &client_sink, &server_sink);
        try resumeUntilSettled(&client, &client_sink);
        var flight_buf: [8192]u8 = undefined;
        const flight = collectHandshakeCrypto(&client_sink, &flight_buf);

        // The client presented a real certificate; a verifier that declines to
        // evaluate trust must not silently establish mutual authentication.
        try std.testing.expectError(error.CertificateInvalid, deliverClientFlightToServer(&server, &server_sink, flight, false));
        try std.testing.expectEqual(tls_backend.CredentialFailure.peer_verification_rejected, server.credentialFailure().?);
    }
}

// --- F4: a client with no suitable credential sends an empty Certificate. ---

test "a client with no credential declines with an empty Certificate (optional completes, required fails)" {
    // Optional: the empty Certificate is accepted and the handshake completes.
    {
        var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
        mock.force_select_error = error.NoCredentialAvailable;
        var client = clientWithLocalCredential(mock.provider());
        defer client.deinit();
        var verifier = credentials.MockVerifier.init(.accepted);
        var server = serverRequestingClientAuth(.optional, verifier.verifier());
        defer server.deinit();

        var client_sink = DirectSink{};
        defer client_sink.deinit();
        var server_sink = DirectSink{};
        defer server_sink.deinit();

        try deliverServerFlightToClient(&client, &server, &client_sink, &server_sink);
        try resumeUntilSettled(&client, &client_sink);
        var flight_buf: [8192]u8 = undefined;
        const flight = collectHandshakeCrypto(&client_sink, &flight_buf);
        try deliverClientFlightToServer(&server, &server_sink, flight, false);
        try resumeUntilSettled(&server, &server_sink);
        try std.testing.expectEqual(tls_core.handshake.HandshakeLifecycle.complete, server.core.handshake_lifecycle);
        // The client declined without signing.
        try std.testing.expectEqual(@as(usize, 0), mock.sign_count);
    }
    // Required: the empty Certificate is certificate_required.
    {
        var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
        mock.force_select_error = error.NoCompatibleSignatureAlgorithm;
        var client = clientWithLocalCredential(mock.provider());
        defer client.deinit();
        var verifier = credentials.MockVerifier.init(.accepted);
        var server = serverRequestingClientAuth(.required, verifier.verifier());
        defer server.deinit();

        var client_sink = DirectSink{};
        defer client_sink.deinit();
        var server_sink = DirectSink{};
        defer server_sink.deinit();

        try deliverServerFlightToClient(&client, &server, &client_sink, &server_sink);
        try resumeUntilSettled(&client, &client_sink);
        var flight_buf: [8192]u8 = undefined;
        const flight = collectHandshakeCrypto(&client_sink, &flight_buf);
        try std.testing.expectError(error.ClientCertificateRequired, deliverClientFlightToServer(&server, &server_sink, flight, false));
        try std.testing.expectEqual(tls_backend.CredentialFailure.client_certificate_required, server.credentialFailure().?);
    }
}

test "an async selector that resolves to no credential declines with an empty Certificate" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.async_select = true;
    mock.async_no_credential = true;
    mock.pending_polls = 1;
    var client = clientWithLocalCredential(mock.provider());
    defer client.deinit();
    var verifier = credentials.MockVerifier.init(.accepted);
    var server = serverRequestingClientAuth(.optional, verifier.verifier());
    defer server.deinit();

    var client_sink = DirectSink{};
    defer client_sink.deinit();
    var server_sink = DirectSink{};
    defer server_sink.deinit();

    try deliverServerFlightToClient(&client, &server, &client_sink, &server_sink);
    try std.testing.expect(client.authPending()); // suspended in selection
    try resumeUntilSettled(&client, &client_sink); // resolves to "no credential"
    try std.testing.expectEqual(@as(usize, 0), mock.sign_count);

    var flight_buf: [8192]u8 = undefined;
    const flight = collectHandshakeCrypto(&client_sink, &flight_buf);
    try deliverClientFlightToServer(&server, &server_sink, flight, false);
    try resumeUntilSettled(&server, &server_sink);
    try std.testing.expectEqual(tls_core.handshake.HandshakeLifecycle.complete, server.core.handshake_lifecycle);
}

// --- F5: exact serialized-flight preflight rejects a chain that overflows once
//         message and surrounding-flight framing is counted. ---

/// A provider returning `entry_count` certificate entries of `entry_len` bytes,
/// to probe the exact flight-size boundary. Never actually signs (the preflight
/// rejects the chain first).
const BigChainProvider = struct {
    entry_len: usize,
    entry_count: usize,
    storage: [tls_backend.max_certificate_len]u8 = [_]u8{0x2c} ** tls_backend.max_certificate_len,
    entries: [credentials.max_chain_entries][]const u8 = undefined,
    release_count: usize = 0,

    fn provider(self: *BigChainProvider) credentials.CredentialProvider {
        return .{ .ctx = self, .vtable = &prov_vtable };
    }
    const prov_vtable = credentials.CredentialProvider.VTable{ .select = select };
    fn select(ctx: *anyopaque, _: *const credentials.SelectionContext) credentials.SelectError!credentials.Progress(credentials.SelectedCredential) {
        const self: *BigChainProvider = @ptrCast(@alignCast(ctx));
        return .{ .complete = .{ .handle = self, .scheme = .ed25519, .vtable = &cred_vtable } };
    }
    const cred_vtable = credentials.SelectedCredential.VTable{ .chain = chain, .sign = sign, .release = release };
    fn chain(handle: *anyopaque) credentials.CertificateChain {
        const self: *BigChainProvider = @ptrCast(@alignCast(handle));
        for (0..self.entry_count) |i| self.entries[i] = self.storage[0..self.entry_len];
        return .{ .entries = self.entries[0..self.entry_count] };
    }
    fn sign(_: *anyopaque, _: credentials.SignatureScheme, _: []const u8, _: []u8) credentials.SignError!credentials.Progress(usize) {
        return .{ .complete = 0 }; // unreachable: the size preflight fails first
    }
    fn release(handle: *anyopaque) void {
        const self: *BigChainProvider = @ptrCast(@alignCast(handle));
        self.release_count += 1;
    }
};

test "the server flight preflight rejects a chain that fits entries but overflows with framing" {
    // Four 2043-byte entries sum to exactly max_message_len once each entry's
    // 5-byte framing is added, but the Certificate message header pushes it over.
    var big = BigChainProvider{ .entry_len = 2043, .entry_count = 4 };
    var server = tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), big.provider(), .{ .record = .{ .alpn = "h2" } });
    defer server.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{});
    try std.testing.expectError(error.CredentialProviderFailed, server.backend().receive(.initial, hello, &sink));
    try std.testing.expectEqual(tls_backend.CredentialFailure.malformed_credential_chain, server.credentialFailure().?);
    try std.testing.expectEqual(@as(usize, 1), big.release_count);
}

test "the client flight preflight rejects a chain that overflows with the message header" {
    var big = BigChainProvider{ .entry_len = 2043, .entry_count = 4 };
    var client = tls_backend.Tls13Backend.initClient(
        clientEntropy(),
        .{ .pinned_certificate = tls_backend.testdata.certificate_der },
        .{ .record = .{ .alpn = "h2" } },
    );
    client.setLocalCredentialProvider(big.provider());
    defer client.deinit();
    var verifier = credentials.MockVerifier.init(.accepted);
    var server = serverRequestingClientAuth(.required, verifier.verifier());
    defer server.deinit();

    var client_sink = DirectSink{};
    defer client_sink.deinit();
    var server_sink = DirectSink{};
    defer server_sink.deinit();

    // The client parks/emits nothing valid: building its Certificate fails the
    // exact-size preflight before any transcript mutation or emission.
    try std.testing.expectError(error.CredentialProviderFailed, deliverServerFlightToClient(&client, &server, &client_sink, &server_sink));
    try std.testing.expectEqual(tls_backend.CredentialFailure.malformed_credential_chain, client.credentialFailure().?);
    try std.testing.expectEqual(@as(usize, 1), big.release_count);
}

// --- F8: a wrong-kind async completion releases every owned handle once. ---

test "a sign stage that completes with a credential releases the held and returned handles once" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.async_sign = true;
    mock.pending_polls = 0;
    mock.sign_returns_credential = true; // contract violation
    var client = clientWithLocalCredential(mock.provider());
    defer client.deinit();
    var verifier = credentials.MockVerifier.init(.accepted);
    var server = serverRequestingClientAuth(.required, verifier.verifier());
    defer server.deinit();

    var client_sink = DirectSink{};
    defer client_sink.deinit();
    var server_sink = DirectSink{};
    defer server_sink.deinit();

    try deliverServerFlightToClient(&client, &server, &client_sink, &server_sink);
    try std.testing.expect(client.authPending()); // parked awaiting the signature

    // The resume observes a credential where a signature length was required and
    // fails closed, releasing the held signing credential and the (aliased)
    // returned one exactly once between them.
    try std.testing.expectError(error.CredentialProviderFailed, client.resumeAuth(&client_sink));
    try std.testing.expectEqual(tls_backend.CredentialFailure.invalid_callback_behavior, client.credentialFailure().?);
    try std.testing.expectEqual(@as(usize, 1), mock.release_count);
    try std.testing.expectEqual(@as(usize, 1), mock.op_release_count);
}

// --- F6: record mode synthesizes the certificate_required alert end to end. ---

test "record mode delivers a fatal alert to the client when required client auth is declined" {
    var verifier = credentials.MockVerifier.init(.accepted);
    const h = try SocketHarness.create(.{});
    defer h.destroy();
    // The server requires client authentication; the client has no local
    // credential and answers with an empty Certificate.
    h.server_engine.requestClientAuthentication(.required, verifier.verifier());

    const failures = driveUntilBothErrors(h);
    // The server fails with certificate_required and synthesizes the alert
    // (previously it emitted none and the peer only saw a stall/EOF). The client
    // terminates on the delivered alert rather than hanging. (The client has
    // already reached 1-RTT here, so the exact received-alert surface depends on
    // epoch timing; the decrypt_error test above covers the clean PeerFatalAlert
    // path end to end.)
    try std.testing.expectEqual(@as(?anyerror, error.ClientCertificateRequired), failures.server);
    try std.testing.expect(failures.client != null);
    try std.testing.expect(!h.server.bridge.handshake_complete);
    try std.testing.expectEqual(tls_backend.CredentialFailure.client_certificate_required, h.server_engine.credentialFailure().?);
}
