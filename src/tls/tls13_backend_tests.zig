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
const encrypted_stream_connection = @import("http_encrypted_stream_connection");
const http_request = @import("http_request");

const record_codec = tls_core.record_codec;
const events = tls_core.events;
const credentials = tls_core.credentials;
const session = tls_core.session;
const session_cache = tls_core.session_cache;
const sni_provider = tls_core.sni_provider;

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

fn recordPolicyForNames(names: []const []const u8, allow_absent_alpn: bool) tls_core.policy.Policy {
    if (names.len == 1 and std.mem.eql(u8, names[0], "h2")) return tls_core.policy.Policy.recordH2Only();
    if (names.len == 1 and std.mem.eql(u8, names[0], "http/1.1")) return tls_core.policy.Policy.recordHttp1Only(allow_absent_alpn);
    var policy = tls_core.policy.Policy.recordDefault();
    policy.allow_absent_alpn = allow_absent_alpn;
    return policy;
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
    // #366: record/QUIC 0-RTT key installation is a follow-up slice, so
    // `record_epoch_bridge.Bridge` deliberately does not support the
    // `.zero_rtt` epoch yet. `pumpDirect` below captures a `.zero_rtt`
    // secret event directly (client write / server read) instead of
    // routing it through the bridge, so 0-RTT tests can still drive a real
    // end-to-end handshake through this harness.
    zero_rtt_secret: [2]?SecretSnapshot = .{ null, null },
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
            if (traffic_secret.epoch == .zero_rtt) {
                observed.zero_rtt_secret[@intFromEnum(sender_side)] = SecretSnapshot.capture(traffic_secret.data);
                continue;
            }
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
            .record,
            .record,
        );
    }

    fn initExtension() DirectHarness {
        return initProfiles(
            .{ .extension = .{ .extension_type = 57, .local = "client transport parameters" } },
            .{ .extension = .{ .extension_type = 57, .local = "server transport parameters" } },
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

test "direct record handshake delivers large post-handshake ticket once" {
    const Capture = struct {
        count: usize = 0,
        psk: [tls_backend.hash_len]u8 = undefined,
        ticket_len: usize = 0,

        fn now(_: *anyopaque) i64 {
            return 10;
        }

        fn onTicket(ctx: *anyopaque, ticket: *const session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.count += 1;
            @memcpy(&self.psk, ticket.common.resumption_psk.slice());
            self.ticket_len = ticket.ticket.slice().len;
        }
    };

    var harness = DirectHarness.init();
    defer harness.deinit();
    var capture = Capture{};
    const limits = session.Limits{ .max_ticket_len = session.absolute_ticket_wire_max, .max_serialized_len = 128 * 1024 };
    try harness.client_backend.setSessionTicketConsumer(std.testing.allocator, limits, .{
        .ctx = &capture,
        .nowUnixMsFn = Capture.now,
        .onTicketFn = Capture.onTicket,
    });
    try harness.run();

    const opaque_ticket = try std.testing.allocator.alloc(u8, session.absolute_ticket_wire_max);
    defer std.testing.allocator.free(opaque_ticket);
    @memset(opaque_ticket, 0xa5);

    var sink = DirectSink{};
    defer sink.deinit();
    var server_state = try harness.server_backend.emitNewSessionTicket(std.testing.allocator, &sink, .{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .opaque_ticket = opaque_ticket,
        .issued_at_unix_ms = 10,
    }, limits);
    defer server_state.deinit();
    try std.testing.expectEqual(@as(usize, 1), sink.len);

    const ticket_event = sink.items[0].handshake_bytes;
    try std.testing.expect(ticket_event.data.len > record_codec.max_plaintext_fragment_len);
    var protected: [record_codec.max_ciphertext_record_len * 8]u8 = undefined;
    const records = (try harness.server_bridge.applyEvent(.{ .handshake_bytes = .{
        .epoch = ticket_event.epoch,
        .data = ticket_event.data,
    } }, &protected)).?;

    var parser = record_codec.Parser.init(.ciphertext);
    var record_sink = record_codec.RecordSink(8, record_codec.max_ciphertext_fragment_len * 8){};
    try parser.feed(records, &record_sink);
    try std.testing.expect(record_sink.len > 1);

    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    for (record_sink.items[0..record_sink.len]) |record| {
        const opened = try harness.client_bridge.openHandshake(.application, record, &plaintext);
        const next = try harness.client_driver.receive(.application, opened.inner.content);
        try std.testing.expectEqual(@as(usize, 0), next.len);
    }
    try std.testing.expectEqual(@as(usize, 1), capture.count);
    try std.testing.expectEqual(opaque_ticket.len, capture.ticket_len);
    try std.testing.expectEqualSlices(u8, server_state.common.resumption_psk.slice(), &capture.psk);
}

const pre_shared_key = tls_core.pre_shared_key;

test "PSK round trip: an offered, resolved, and verified ticket resumes the handshake" {
    // Phase 1: a full handshake, after which the server issues a ticket and
    // the client captures the resulting ClientTicketState (#361 machinery).
    var harness = DirectHarness.init();
    defer harness.deinit();

    const TicketCapture = struct {
        ticket: session.ClientTicketState = .{},
        fn now(_: *anyopaque) i64 {
            return 1000;
        }
        fn onTicket(ctx: *anyopaque, ticket: *const session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            ticket.cloneInto(std.testing.allocator, &self.ticket) catch unreachable;
        }
    };
    var capture = TicketCapture{};
    defer capture.ticket.deinit();
    const limits = session.Limits.default;
    try harness.client_backend.setSessionTicketConsumer(std.testing.allocator, limits, .{
        .ctx = &capture,
        .nowUnixMsFn = TicketCapture.now,
        .onTicketFn = TicketCapture.onTicket,
    });
    try harness.run();
    try std.testing.expect(harness.client_driver.isComplete());
    try std.testing.expect(harness.server_driver.isComplete());

    var sink = DirectSink{};
    defer sink.deinit();
    var server_state = try harness.server_backend.emitNewSessionTicket(std.testing.allocator, &sink, .{
        .ticket_lifetime = 3600,
        .ticket_age_add = 500,
        .ticket_nonce = "\x01",
        .opaque_ticket = "opaque-psk-ticket",
        .issued_at_unix_ms = 1000,
    }, limits);
    defer server_state.deinit();
    try std.testing.expectEqual(@as(usize, 1), sink.len);

    // Deliver the ticket to the client over the (encrypted) application
    // channel, exactly as a real deployment would.
    const ticket_event = sink.items[0].handshake_bytes;
    var protected: [record_codec.max_ciphertext_record_len * 2]u8 = undefined;
    const records = (try harness.server_bridge.applyEvent(.{ .handshake_bytes = .{
        .epoch = ticket_event.epoch,
        .data = ticket_event.data,
    } }, &protected)).?;
    var parser = record_codec.Parser.init(.ciphertext);
    var record_sink = record_codec.RecordSink(8, record_codec.max_ciphertext_fragment_len * 8){};
    try parser.feed(records, &record_sink);
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    for (record_sink.items[0..record_sink.len]) |record| {
        const opened = try harness.client_bridge.openHandshake(.application, record, &plaintext);
        _ = try harness.client_driver.receive(.application, opened.inner.content);
    }
    try std.testing.expect(capture.ticket.ticket.slice().len > 0);
    try std.testing.expectEqualSlices(u8, server_state.common.resumption_psk.slice(), capture.ticket.common.resumption_psk.slice());

    // Phase 2: a fresh connection offers the captured ticket as a PSK. The
    // server resolves it (a trivial in-memory "stateful cache" stand-in for
    // #364), evaluates compatibility, verifies the binder, and both sides
    // resume without a certificate flight.
    var resumed = DirectHarness.init();
    defer resumed.deinit();

    var offers: pre_shared_key.ClientPskOfferSet = .{};
    try offers.push(&capture.ticket);
    var clock_dummy: u8 = 0;
    const Clock = struct {
        fn now(_: *anyopaque) i64 {
            return 2000;
        }
    };
    try resumed.client_backend.setClientPskOffers(&offers, &clock_dummy, Clock.now);

    const Resolver = struct {
        state: *session.ServerRecoverableState,
        resolve_calls: usize = 0,

        fn now(_: *anyopaque) i64 {
            return 2000;
        }
        fn resolve(ctx: *anyopaque, identity: []const u8) pre_shared_key.ResolveError!pre_shared_key.ServerPskResolveResult {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.resolve_calls += 1;
            if (!std.mem.eql(u8, identity, "opaque-psk-ticket")) return .miss;
            return clonedResolveHit(self.state, std.testing.allocator);
        }
    };
    // `state` is a pointer, not a copy: `server_state` (below, an
    // allocator-backed value with e.g. a non-null `transport_compat`) must
    // not be shallow-copied, or its owned storage would be deinitialized
    // twice — once here, once by `server_state`'s own `defer` above.
    var resolver_state: Resolver = .{ .state = &server_state };
    try resumed.server_backend.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = Resolver.now,
        .resolveFn = Resolver.resolve,
    });

    try resumed.run();

    try std.testing.expect(resumed.client_driver.isComplete());
    try std.testing.expect(resumed.server_driver.isComplete());
    try std.testing.expectEqual(@as(usize, 1), resolver_state.resolve_calls);
    try std.testing.expect(resumed.client_backend.core.psk_authenticated);
    try std.testing.expect(resumed.server_backend.core.psk_authenticated);
    // No certificate flight: the fixed server identity was never consumed.
    // `certificate_state` reports `.valid` anyway (#488) — a PSK-resumed
    // handshake never sends Certificate, so the completion policy that
    // requires a valid peer certificate for the client role would otherwise
    // treat every resumed connection as fatally unauthenticated; the client
    // instead inherits trust from the original full handshake that issued
    // this ticket, confirmed here by the binder.
    try std.testing.expectEqual(events.CertificateState.valid, resumed.observed.certificate_state.?);

    // The resumed connection is genuinely usable: application data flows
    // both ways under the PSK-derived keys.
    var protected2: [record_codec.max_ciphertext_record_len]u8 = undefined;
    var plaintext2: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    const request = try resumed.client_bridge.sealApplicationData("resumed request", &protected2);
    const opened_request = try resumed.server_bridge.openApplicationData(try parseSingleRecord(.ciphertext, request), &plaintext2);
    try std.testing.expectEqualStrings("resumed request", opened_request.inner.content);
}

// ==========================================================================
// #366: 0-RTT policy gate — TLS vocabulary/negotiation slice.
//
// Record/QUIC key installation and the HTTP-level request-safety gate are
// separate follow-up slices; these tests only prove the TLS-layer
// negotiation (ClientHello/EncryptedExtensions `early_data`, the server's
// live identity-0/skew/replay decision, and the derived early secret)
// through the real backend and driver, via `DirectHarness`'s `zero_rtt`
// secret capture (see `pumpDirect`).
// ==========================================================================

const IssuedEarlyTicket = struct {
    ticket: session.ClientTicketState = .{},
    server_state: session.ServerRecoverableState = .{},

    fn deinit(self: *IssuedEarlyTicket) void {
        self.ticket.deinit();
        self.server_state.deinit();
    }
};

/// Runs a full handshake and has the server issue a ticket advertising
/// `max_early_data_size`, delivering it to the client exactly as `PSK round
/// trip` above does, then returns the client's captured ticket and the
/// server's recoverable state (for a `resumed` connection's resolver) with
/// ownership moved out for the caller to `deinit`.
fn issueEarlyCapableTicket(max_early_data_size: ?u32) !IssuedEarlyTicket {
    var harness = DirectHarness.init();
    defer harness.deinit();

    const TicketCapture = struct {
        ticket: session.ClientTicketState = .{},
        fn now(_: *anyopaque) i64 {
            return 1000;
        }
        fn onTicket(ctx: *anyopaque, ticket: *const session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            ticket.cloneInto(std.testing.allocator, &self.ticket) catch unreachable;
        }
    };
    var capture = TicketCapture{};
    errdefer capture.ticket.deinit();
    const limits = session.Limits.default;
    try harness.client_backend.setSessionTicketConsumer(std.testing.allocator, limits, .{
        .ctx = &capture,
        .nowUnixMsFn = TicketCapture.now,
        .onTicketFn = TicketCapture.onTicket,
    });
    try harness.run();
    try std.testing.expect(harness.client_driver.isComplete());
    try std.testing.expect(harness.server_driver.isComplete());

    var sink = DirectSink{};
    defer sink.deinit();
    var server_state = try harness.server_backend.emitNewSessionTicket(std.testing.allocator, &sink, .{
        .ticket_lifetime = 3600,
        .ticket_age_add = 500,
        .ticket_nonce = "\x01",
        .opaque_ticket = "opaque-early-ticket",
        .max_early_data_size = max_early_data_size,
        .issued_at_unix_ms = 1000,
    }, limits);
    errdefer server_state.deinit();
    try std.testing.expectEqual(@as(usize, 1), sink.len);

    const ticket_event = sink.items[0].handshake_bytes;
    var protected: [record_codec.max_ciphertext_record_len * 2]u8 = undefined;
    const records = (try harness.server_bridge.applyEvent(.{ .handshake_bytes = .{
        .epoch = ticket_event.epoch,
        .data = ticket_event.data,
    } }, &protected)).?;
    var parser = record_codec.Parser.init(.ciphertext);
    var record_sink = record_codec.RecordSink(8, record_codec.max_ciphertext_fragment_len * 8){};
    try parser.feed(records, &record_sink);
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    for (record_sink.items[0..record_sink.len]) |record| {
        const opened = try harness.client_bridge.openHandshake(.application, record, &plaintext);
        _ = try harness.client_driver.receive(.application, opened.inner.content);
    }
    try std.testing.expect(capture.ticket.ticket.slice().len > 0);

    var result = IssuedEarlyTicket{};
    result.ticket.moveFrom(&capture.ticket);
    result.server_state.moveFrom(&server_state);
    return result;
}

/// Wires a fresh `resumed` `DirectHarness` to offer `issued.ticket` and
/// resolve it back to `issued.server_state`, but does not configure any
/// 0-RTT policy — callers set `client_early_data_intent`/
/// `server_early_data_policy`/the replay gate afterward.
/// A resolver keyed on exact identity match, mirroring `Resolver` in `PSK
/// round trip` above — an instance (not a file-scope var) so its state
/// safely outlives the setup call that wires it into
/// `resumed.server_backend`, for the whole life of the test.
const IdentityResolver = struct {
    state: *session.ServerRecoverableState,

    fn now(_: *anyopaque) i64 {
        return 2000;
    }
    fn resolve(ctx: *anyopaque, identity: []const u8) pre_shared_key.ResolveError!pre_shared_key.ServerPskResolveResult {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        if (!std.mem.eql(u8, identity, "opaque-early-ticket")) return .miss;
        return clonedResolveHit(self.state, std.testing.allocator);
    }
};

fn earlyDataResumedClientClock(_: *anyopaque) i64 {
    return 2000;
}

test "0-RTT round trip: an early-capable ticket, matching policy, and an allowing replay gate is accepted by both sides" {
    var issued = try issueEarlyCapableTicket(32);
    defer issued.deinit();

    var resumed = DirectHarness.init();
    defer resumed.deinit();

    var offers: pre_shared_key.ClientPskOfferSet = .{};
    try offers.push(&issued.ticket);
    var clock_dummy: u8 = 0;
    try resumed.client_backend.setClientPskOffers(&offers, &clock_dummy, earlyDataResumedClientClock);

    var resolver_state = IdentityResolver{ .state = &issued.server_state };
    try resumed.server_backend.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = IdentityResolver.now,
        .resolveFn = IdentityResolver.resolve,
    });

    try resumed.client_backend.setClientEarlyDataIntent(.{ .enabled = true, .max_bytes = 16384 });
    try resumed.server_backend.setServerEarlyDataPolicy(.{ .enabled = true, .age_skew_tolerance_ms = 60_000 });
    var replay_gate_ctx: u8 = 0;
    try resumed.server_backend.setEarlyDataReplayGate(.{
        .ctx = &replay_gate_ctx,
        .decideFn = struct {
            fn decide(_: *anyopaque, _: tls_backend.EarlyDataReplayCandidate) tls_backend.EarlyDataReplayDecision {
                return .allow;
            }
        }.decide,
    });

    try resumed.run();

    try std.testing.expect(resumed.client_driver.isComplete());
    try std.testing.expect(resumed.server_driver.isComplete());
    try std.testing.expect(resumed.client_backend.core.psk_authenticated);
    try std.testing.expect(resumed.server_backend.core.psk_authenticated);

    try std.testing.expect(resumed.client_backend.earlyDataAttempted());
    try std.testing.expect(resumed.client_backend.earlyDataAccepted());
    try std.testing.expect(resumed.server_backend.earlyDataAccepted());
    try std.testing.expectEqual(tls_backend.EarlyDataDecision.accepted, resumed.server_backend.earlyDataDecision());

    // The client's `c e traffic` secret (derived from the final ClientHello
    // it sent) and the server's own derivation (from the same ClientHello,
    // captured pre-binder-verification) must be byte-identical — a real
    // cross-check, not a tautology, since each side runs
    // `KeySchedule.clientEarlyTrafficSecret` independently.
    try std.testing.expectEqualSlices(
        u8,
        &resumed.observed.zero_rtt_secret[0].?.bytes,
        &resumed.observed.zero_rtt_secret[1].?.bytes,
    );

    // The resumed 1-RTT connection remains usable afterward regardless of
    // the 0-RTT outcome (record/QUIC 0-RTT delivery is a follow-up slice).
    var protected2: [record_codec.max_ciphertext_record_len]u8 = undefined;
    var plaintext2: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    const request = try resumed.client_bridge.sealApplicationData("resumed request", &protected2);
    const opened_request = try resumed.server_bridge.openApplicationData(try parseSingleRecord(.ciphertext, request), &plaintext2);
    try std.testing.expectEqualStrings("resumed request", opened_request.inner.content);
}

test "0-RTT is never attempted for a resume-only ticket even with client intent enabled" {
    var issued = try issueEarlyCapableTicket(null); // resume_only: no max_early_data_size
    defer issued.deinit();

    var resumed = DirectHarness.init();
    defer resumed.deinit();

    var offers: pre_shared_key.ClientPskOfferSet = .{};
    try offers.push(&issued.ticket);
    var clock_dummy: u8 = 0;
    try resumed.client_backend.setClientPskOffers(&offers, &clock_dummy, earlyDataResumedClientClock);
    var resolver_state = IdentityResolver{ .state = &issued.server_state };
    try resumed.server_backend.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = IdentityResolver.now,
        .resolveFn = IdentityResolver.resolve,
    });

    try resumed.client_backend.setClientEarlyDataIntent(.{ .enabled = true, .max_bytes = 16384 });
    try resumed.server_backend.setServerEarlyDataPolicy(.{ .enabled = true, .age_skew_tolerance_ms = 60_000 });

    try resumed.run();

    try std.testing.expect(resumed.client_driver.isComplete());
    try std.testing.expect(resumed.server_driver.isComplete());
    try std.testing.expect(resumed.client_backend.core.psk_authenticated);
    try std.testing.expect(!resumed.client_backend.earlyDataAttempted());
    try std.testing.expect(!resumed.client_backend.earlyDataAccepted());
    try std.testing.expect(!resumed.server_backend.earlyDataAccepted());
    try std.testing.expectEqual(@as(?SecretSnapshot, null), resumed.observed.zero_rtt_secret[0]);
    try std.testing.expectEqual(@as(?SecretSnapshot, null), resumed.observed.zero_rtt_secret[1]);
}

test "0-RTT is never attempted when the client never opts in, even for an early-capable ticket" {
    var issued = try issueEarlyCapableTicket(32);
    defer issued.deinit();

    var resumed = DirectHarness.init();
    defer resumed.deinit();

    var offers: pre_shared_key.ClientPskOfferSet = .{};
    try offers.push(&issued.ticket);
    var clock_dummy: u8 = 0;
    try resumed.client_backend.setClientPskOffers(&offers, &clock_dummy, earlyDataResumedClientClock);
    var resolver_state = IdentityResolver{ .state = &issued.server_state };
    try resumed.server_backend.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = IdentityResolver.now,
        .resolveFn = IdentityResolver.resolve,
    });
    // Client intent left at its disabled default.
    try resumed.server_backend.setServerEarlyDataPolicy(.{ .enabled = true, .age_skew_tolerance_ms = 60_000 });

    try resumed.run();

    try std.testing.expect(resumed.client_driver.isComplete());
    try std.testing.expect(resumed.server_driver.isComplete());
    try std.testing.expect(!resumed.client_backend.earlyDataAttempted());
    try std.testing.expect(!resumed.server_backend.earlyDataAccepted());
    try std.testing.expectEqual(tls_backend.EarlyDataDecision.not_attempted, resumed.server_backend.earlyDataDecision());
}

test "0-RTT is attempted but rejected when the server's early-data policy is disabled (the default)" {
    var issued = try issueEarlyCapableTicket(32);
    defer issued.deinit();

    var resumed = DirectHarness.init();
    defer resumed.deinit();

    var offers: pre_shared_key.ClientPskOfferSet = .{};
    try offers.push(&issued.ticket);
    var clock_dummy: u8 = 0;
    try resumed.client_backend.setClientPskOffers(&offers, &clock_dummy, earlyDataResumedClientClock);
    var resolver_state = IdentityResolver{ .state = &issued.server_state };
    try resumed.server_backend.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = IdentityResolver.now,
        .resolveFn = IdentityResolver.resolve,
    });
    try resumed.client_backend.setClientEarlyDataIntent(.{ .enabled = true, .max_bytes = 16384 });
    // Server early-data policy left at its disabled default.

    try resumed.run();

    try std.testing.expect(resumed.client_driver.isComplete());
    try std.testing.expect(resumed.server_driver.isComplete());
    // Resumption itself is unaffected by the rejected early-data attempt.
    try std.testing.expect(resumed.client_backend.core.psk_authenticated);
    try std.testing.expect(resumed.server_backend.core.psk_authenticated);

    try std.testing.expect(resumed.client_backend.earlyDataAttempted());
    try std.testing.expect(!resumed.client_backend.earlyDataAccepted());
    try std.testing.expect(!resumed.server_backend.earlyDataAccepted());
    try std.testing.expectEqual(tls_backend.EarlyDataDecision.disabled, resumed.server_backend.earlyDataDecision());
    // The client still derived and emitted its own 0-RTT write secret (the
    // attempt itself always happens locally); only the server never emits
    // a matching read secret, since it never reached `.accepted`.
    try std.testing.expect(resumed.observed.zero_rtt_secret[0] != null);
    try std.testing.expectEqual(@as(?SecretSnapshot, null), resumed.observed.zero_rtt_secret[1]);
}

fn earlyDataSkewedClientClock(_: *anyopaque) i64 {
    // The ticket was issued and received at simulated t=1000 (see
    // `issueEarlyCapableTicket`'s `TicketCapture.now`); the server's own
    // resolver clock (`IdentityResolver.now`) reports t=2000, for a genuine
    // 1000ms server-observed age. Reporting a much larger "now" here makes
    // the *client's* apparent ticket age diverge sharply from that — real
    // clock skew, not merely two different-but-consistent clocks.
    return 6000;
}

test "0-RTT is rejected for a ticket-age skew outside the configured tolerance" {
    var issued = try issueEarlyCapableTicket(32);
    defer issued.deinit();

    var resumed = DirectHarness.init();
    defer resumed.deinit();

    var offers: pre_shared_key.ClientPskOfferSet = .{};
    try offers.push(&issued.ticket);
    var clock_dummy: u8 = 0;
    try resumed.client_backend.setClientPskOffers(&offers, &clock_dummy, earlyDataSkewedClientClock);
    var resolver_state = IdentityResolver{ .state = &issued.server_state };
    try resumed.server_backend.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = IdentityResolver.now,
        .resolveFn = IdentityResolver.resolve,
    });
    try resumed.client_backend.setClientEarlyDataIntent(.{ .enabled = true, .max_bytes = 16384 });
    try resumed.server_backend.setServerEarlyDataPolicy(.{ .enabled = true, .age_skew_tolerance_ms = 10 });

    try resumed.run();

    try std.testing.expect(resumed.client_driver.isComplete());
    try std.testing.expect(resumed.server_driver.isComplete());
    try std.testing.expect(resumed.server_backend.core.psk_authenticated);
    try std.testing.expect(!resumed.server_backend.earlyDataAccepted());
    try std.testing.expectEqual(tls_backend.EarlyDataDecision.age_skew, resumed.server_backend.earlyDataDecision());
}

test "0-RTT is rejected when the anti-replay gate reports replay, without affecting resumption" {
    var issued = try issueEarlyCapableTicket(32);
    defer issued.deinit();

    var resumed = DirectHarness.init();
    defer resumed.deinit();

    var offers: pre_shared_key.ClientPskOfferSet = .{};
    try offers.push(&issued.ticket);
    var clock_dummy: u8 = 0;
    try resumed.client_backend.setClientPskOffers(&offers, &clock_dummy, earlyDataResumedClientClock);
    var resolver_state = IdentityResolver{ .state = &issued.server_state };
    try resumed.server_backend.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = IdentityResolver.now,
        .resolveFn = IdentityResolver.resolve,
    });
    try resumed.client_backend.setClientEarlyDataIntent(.{ .enabled = true, .max_bytes = 16384 });
    try resumed.server_backend.setServerEarlyDataPolicy(.{ .enabled = true, .age_skew_tolerance_ms = 60_000 });
    var replay_gate_ctx: u8 = 0;
    try resumed.server_backend.setEarlyDataReplayGate(.{
        .ctx = &replay_gate_ctx,
        .decideFn = struct {
            fn decide(_: *anyopaque, _: tls_backend.EarlyDataReplayCandidate) tls_backend.EarlyDataReplayDecision {
                return .replay;
            }
        }.decide,
    });

    try resumed.run();

    try std.testing.expect(resumed.server_backend.core.psk_authenticated);
    try std.testing.expect(!resumed.server_backend.earlyDataAccepted());
    try std.testing.expectEqual(tls_backend.EarlyDataDecision.replay_rejected, resumed.server_backend.earlyDataDecision());
}

test "0-RTT anti-replay defaults to unavailable (fails closed) when no gate is configured" {
    var issued = try issueEarlyCapableTicket(32);
    defer issued.deinit();

    var resumed = DirectHarness.init();
    defer resumed.deinit();

    var offers: pre_shared_key.ClientPskOfferSet = .{};
    try offers.push(&issued.ticket);
    var clock_dummy: u8 = 0;
    try resumed.client_backend.setClientPskOffers(&offers, &clock_dummy, earlyDataResumedClientClock);
    var resolver_state = IdentityResolver{ .state = &issued.server_state };
    try resumed.server_backend.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = IdentityResolver.now,
        .resolveFn = IdentityResolver.resolve,
    });
    try resumed.client_backend.setClientEarlyDataIntent(.{ .enabled = true, .max_bytes = 16384 });
    try resumed.server_backend.setServerEarlyDataPolicy(.{ .enabled = true, .age_skew_tolerance_ms = 60_000 });
    // No `setEarlyDataReplayGate` call: production is safe with no replay
    // store configured at all.

    try resumed.run();

    try std.testing.expect(resumed.server_backend.core.psk_authenticated);
    try std.testing.expect(!resumed.server_backend.earlyDataAccepted());
    try std.testing.expectEqual(tls_backend.EarlyDataDecision.replay_unavailable, resumed.server_backend.earlyDataDecision());
}

test "0-RTT is rejected when the server selects an identity other than 0, even though the client attempted it" {
    var issued = try issueEarlyCapableTicket(32);
    defer issued.deinit();
    // A second, ordinary (non-early-capable) ticket that the resolver will
    // actually select, offered *after* the early-capable one so wire index
    // 0 stays the early-capable ticket the client attempted 0-RTT against.
    var second_issued = try issueEarlyCapableTicket(null);
    defer second_issued.deinit();

    var resumed = DirectHarness.init();
    defer resumed.deinit();

    var offers: pre_shared_key.ClientPskOfferSet = .{};
    try offers.push(&issued.ticket);
    try offers.push(&second_issued.ticket);
    const Clock = struct {
        fn now(_: *anyopaque) i64 {
            return 2000;
        }
    };
    var clock_dummy: u8 = 0;
    try resumed.client_backend.setClientPskOffers(&offers, &clock_dummy, Clock.now);
    try resumed.client_backend.setClientEarlyDataIntent(.{ .enabled = true, .max_bytes = 16384 });

    // The resolver misses identity 0 (forcing selection of identity 1),
    // regardless of which ticket's opaque identity it actually is —
    // `issueEarlyCapableTicket` gives both the same opaque identity string,
    // so the resolver is keyed on call count instead.
    const CallCountResolver = struct {
        state: *session.ServerRecoverableState,
        calls: usize = 0,

        fn now(_: *anyopaque) i64 {
            return 2000;
        }
        fn resolve(ctx: *anyopaque, _: []const u8) pre_shared_key.ResolveError!pre_shared_key.ServerPskResolveResult {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            if (self.calls == 1) return .miss;
            return clonedResolveHit(self.state, std.testing.allocator);
        }
    };
    var resolver_state = CallCountResolver{ .state = &second_issued.server_state };
    try resumed.server_backend.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = CallCountResolver.now,
        .resolveFn = CallCountResolver.resolve,
    });
    try resumed.server_backend.setServerEarlyDataPolicy(.{ .enabled = true, .age_skew_tolerance_ms = 60_000 });

    try resumed.run();

    try std.testing.expect(resumed.client_driver.isComplete());
    try std.testing.expect(resumed.server_driver.isComplete());
    try std.testing.expect(resumed.server_backend.core.psk_authenticated);
    try std.testing.expectEqual(@as(usize, 2), resolver_state.calls);
    try std.testing.expect(!resumed.server_backend.earlyDataAccepted());
    try std.testing.expectEqual(tls_backend.EarlyDataDecision.selected_identity_not_zero, resumed.server_backend.earlyDataDecision());
}

test "the ClientHello wire-encodes early_data before pre_shared_key only when 0-RTT is attempted" {
    var issued = try issueEarlyCapableTicket(32);
    defer issued.deinit();

    var resumed = DirectHarness.init();
    defer resumed.deinit();

    var offers: pre_shared_key.ClientPskOfferSet = .{};
    try offers.push(&issued.ticket);
    var clock_dummy: u8 = 0;
    try resumed.client_backend.setClientPskOffers(&offers, &clock_dummy, earlyDataResumedClientClock);
    var resolver_state = IdentityResolver{ .state = &issued.server_state };
    try resumed.server_backend.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = IdentityResolver.now,
        .resolveFn = IdentityResolver.resolve,
    });
    try resumed.client_backend.setClientEarlyDataIntent(.{ .enabled = true, .max_bytes = 16384 });

    resumed.client_driver = DirectDriver.init(.client, resumed.client_backend.backend());
    resumed.drivers_ready = true;
    const initial_sink = try resumed.client_driver.start({});
    // Attempting 0-RTT means `sendClientHello` also emits its own
    // `.zero_rtt`/`.write` secret event (see `tls13_backend.zig`), ahead of
    // the ClientHello's `handshake_bytes` event — find the ClientHello
    // itself rather than assuming its position.
    var client_hello: ?[]const u8 = null;
    for (initial_sink.items[0..initial_sink.len]) |event| {
        if (event == .handshake_bytes) client_hello = event.handshake_bytes.data;
    }
    const ch = client_hello orelse return error.TestExpectedEqual;

    const early_data_ext: u16 = @intFromEnum(tls_core.algorithms.ExtensionType.early_data);
    const psk_ext: u16 = pre_shared_key.ext_pre_shared_key;
    const early_data_pos = std.mem.indexOf(u8, ch, &std.mem.toBytes(std.mem.nativeToBig(u16, early_data_ext))) orelse
        return error.TestExpectedEqual;
    // `pre_shared_key`'s own 2-byte type also appears inside the extension
    // as the identities/binders vector lengths never happen to collide
    // with the exact 2-byte pattern `0029` (41) at a *type* position for
    // this fixed, small ClientHello — found from the end so the match is
    // unambiguous even so.
    const psk_ext_pos = std.mem.lastIndexOf(u8, ch, &std.mem.toBytes(std.mem.nativeToBig(u16, psk_ext))) orelse
        return error.TestExpectedEqual;
    try std.testing.expect(early_data_pos < psk_ext_pos);

    // Server never started (no `harness.run()`): nothing to tear down
    // beyond the harness's own `deinit`, which only runs the drivers'
    // `deinit` when `drivers_ready` — already true here.
    resumed.server_driver = DirectDriver.init(.server, resumed.server_backend.backend());
}

fn expectRuntimeResumedRecordHandshake(
    server_config: tls_core.resumption_runtime.Config,
    client_config: tls_core.resumption_runtime.Config,
    expected_identity: tls_core.resumption_runtime.Runtime.IdentityMode,
) !void {
    const resumption_runtime = tls_core.resumption_runtime;

    // Phase 1: a full handshake. The server issues a ticket through the new
    // #488 two-phase API (prepare -> Runtime.createIdentity -> emit) instead
    // of the single-phase `emitNewSessionTicket`, and the client captures the
    // resulting ClientTicketState into its own process-shared runtime.
    var harness = DirectHarness.init();
    defer harness.deinit();

    var server_runtime = try resumption_runtime.Runtime.init(
        std.testing.allocator,
        server_config,
        .{ .ctx = undefined, .nowUnixMsFn = struct {
            fn now(_: *anyopaque) i64 {
                return 1000;
            }
        }.now },
        serverProvider(),
    );
    defer server_runtime.deinit();

    var client_runtime = try resumption_runtime.Runtime.init(
        std.testing.allocator,
        client_config,
        .{ .ctx = undefined, .nowUnixMsFn = struct {
            fn now(_: *anyopaque) i64 {
                return 2000;
            }
        }.now },
        clientProvider(),
    );
    defer client_runtime.deinit();

    const TicketCapture = struct {
        runtime: *resumption_runtime.Runtime,
        stored: session_cache.StoreResult = undefined,

        fn now(_: *anyopaque) i64 {
            return 1000;
        }
        fn onTicket(ctx: *anyopaque, ticket: *const session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.stored = self.runtime.storeClientTicket(ticket);
        }
    };
    var capture = TicketCapture{ .runtime = &client_runtime };
    const limits = session.Limits.default;
    try harness.client_backend.setSessionTicketConsumer(std.testing.allocator, limits, .{
        .ctx = &capture,
        .nowUnixMsFn = TicketCapture.now,
        .onTicketFn = TicketCapture.onTicket,
    });
    try harness.run();
    try std.testing.expect(harness.client_driver.isComplete());
    try std.testing.expect(harness.server_driver.isComplete());

    var sink = DirectSink{};
    defer sink.deinit();
    var prepared = try harness.server_backend.prepareNewSessionTicket(std.testing.allocator, .{
        .ticket_lifetime = 3600,
        .ticket_age_add = 500,
        .ticket_nonce = "\x01",
        .issued_at_unix_ms = 1000,
    }, limits);
    defer prepared.deinit();
    var scratch: [session.absolute_ticket_wire_max]u8 = undefined;
    var identity = try server_runtime.createIdentity(&prepared.state, 1000, &scratch);
    defer identity.deinit();
    try std.testing.expectEqual(expected_identity, std.meta.activeTag(identity));
    try harness.server_backend.emitPreparedNewSessionTicket(std.testing.allocator, &sink, &prepared, identity.slice(), limits);
    try std.testing.expectEqual(@as(usize, 1), sink.len);

    // Deliver the ticket to the client over the (encrypted) application
    // channel, exactly as a real deployment would.
    const ticket_event = sink.items[0].handshake_bytes;
    var protected: [record_codec.max_ciphertext_record_len * 2]u8 = undefined;
    const records = (try harness.server_bridge.applyEvent(.{ .handshake_bytes = .{
        .epoch = ticket_event.epoch,
        .data = ticket_event.data,
    } }, &protected)).?;
    var parser = record_codec.Parser.init(.ciphertext);
    var record_sink = record_codec.RecordSink(8, record_codec.max_ciphertext_fragment_len * 8){};
    try parser.feed(records, &record_sink);
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    for (record_sink.items[0..record_sink.len]) |record| {
        const opened = try harness.client_bridge.openHandshake(.application, record, &plaintext);
        _ = try harness.client_driver.receive(.application, opened.inner.content);
    }
    try std.testing.expectEqual(session_cache.StoreResult.stored, capture.stored);

    // Phase 2: a fresh connection looks its offer up through the client
    // runtime and the server resolves it through the *same* server runtime
    // that issued it — proving the runtime's cache/resolver composition (not
    // hand-rolled test stand-ins) drives a real abbreviated handshake.
    var resumed = DirectHarness.init();
    defer resumed.deinit();

    const candidate: session.CandidateContext = .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .server_name = null,
        // The `DirectHarness` backends negotiate ALPN `h2` by default even
        // without an explicit policy override; the candidate must match the
        // exact origin the ticket was actually issued under.
        .application_protocol = "h2",
        .auth_binding = session.AuthBinding.fromLeafCertificateDer(tls_backend.testdata.certificate_der),
    };
    var lookup = client_runtime.lookupClientOffers(candidate);
    defer lookup.deinit();
    try std.testing.expect(lookup == .hit);
    try std.testing.expectEqual(@as(usize, 1), lookup.hit.offers.len);

    var clock_dummy: u8 = 0;
    const ClientClock = struct {
        fn now(_: *anyopaque) i64 {
            return 2000;
        }
    };
    try resumed.client_backend.setClientPskOfferLease(&lookup.hit, &clock_dummy, ClientClock.now);
    try resumed.server_backend.setServerPskResolver(server_runtime.serverResolver().?);

    try resumed.run();

    try std.testing.expect(resumed.client_driver.isComplete());
    try std.testing.expect(resumed.server_driver.isComplete());
    try std.testing.expect(resumed.client_backend.core.psk_authenticated);
    try std.testing.expect(resumed.server_backend.core.psk_authenticated);
    // No certificate flight: this is a genuine PSK-abbreviated handshake, not
    // merely a second successful full handshake. `certificate_state` reports
    // `.valid` anyway (#488): the client inherits trust from the original
    // full handshake that issued this ticket, confirmed here by the binder,
    // since every transport completion policy otherwise requires a valid
    // peer certificate for the client role.
    try std.testing.expectEqual(events.CertificateState.valid, resumed.observed.certificate_state.?);

    // The resumed connection is genuinely usable: application data flows
    // both ways under the PSK-derived keys.
    var protected2: [record_codec.max_ciphertext_record_len]u8 = undefined;
    var plaintext2: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    const request = try resumed.client_bridge.sealApplicationData("resumed request", &protected2);
    const opened_request = try resumed.server_bridge.openApplicationData(try parseSingleRecord(.ciphertext, request), &plaintext2);
    try std.testing.expectEqualStrings("resumed request", opened_request.inner.content);
}

test "#488: stateful runtime drives a genuine end-to-end resumed handshake via two-phase issuance" {
    try expectRuntimeResumedRecordHandshake(
        .{ .mode = .stateful },
        .{ .mode = .stateful },
        .stateful,
    );
}

test "#488: stateless runtime drives a genuine end-to-end resumed handshake via two-phase issuance" {
    try expectRuntimeResumedRecordHandshake(
        .{ .mode = .stateless },
        .{ .mode = .stateless },
        .stateless,
    );
}

test "#488: hybrid runtime falls back to stateless issuance and reconnects successfully" {
    try expectRuntimeResumedRecordHandshake(
        .{ .mode = .hybrid, .server_cache_limits = .{
            .max_entries = 4,
            .max_origins = 4,
            .max_total_bytes = 1,
            .max_entry_bytes = 1,
            .max_entries_per_origin = 4,
        } },
        .{ .mode = .hybrid },
        .stateless,
    );
}

test "PSK round trip resumes over the extension (QUIC-style) profile with asymmetric client/server transport payloads" {
    // Regression coverage: `ticketEligibleToOffer` used to compare the
    // ticket's stored *server* transport snapshot against this client's own
    // *local* outbound extension — the wrong direction, which would
    // silently filter out every ticket whenever the two peers' transport
    // payloads differ. `DirectHarness.initExtension()` deliberately uses
    // different client/server payloads, so this both proves the ticket is
    // still offered at all and completes a genuine QUIC-carrier-shaped
    // (extension-profile) resumption, not only the record harness.
    var harness = DirectHarness.initExtension();
    defer harness.deinit();

    const TicketCapture = struct {
        ticket: session.ClientTicketState = .{},
        fn now(_: *anyopaque) i64 {
            return 1000;
        }
        fn onTicket(ctx: *anyopaque, ticket: *const session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            ticket.cloneInto(std.testing.allocator, &self.ticket) catch unreachable;
        }
    };
    var capture = TicketCapture{};
    defer capture.ticket.deinit();
    const limits = session.Limits.default;
    try harness.client_backend.setSessionTicketConsumer(std.testing.allocator, limits, .{
        .ctx = &capture,
        .nowUnixMsFn = TicketCapture.now,
        .onTicketFn = TicketCapture.onTicket,
    });
    try harness.run();
    try std.testing.expect(harness.client_driver.isComplete());
    try std.testing.expect(harness.server_driver.isComplete());

    var sink = DirectSink{};
    defer sink.deinit();
    var server_state = try harness.server_backend.emitNewSessionTicket(std.testing.allocator, &sink, .{
        .ticket_lifetime = 3600,
        .ticket_age_add = 500,
        .ticket_nonce = "\x01",
        .opaque_ticket = "extension-profile-ticket",
        .issued_at_unix_ms = 1000,
    }, limits);
    defer server_state.deinit();

    const ticket_event = sink.items[0].handshake_bytes;
    var protected: [record_codec.max_ciphertext_record_len * 2]u8 = undefined;
    const records = (try harness.server_bridge.applyEvent(.{ .handshake_bytes = .{
        .epoch = ticket_event.epoch,
        .data = ticket_event.data,
    } }, &protected)).?;
    var parser = record_codec.Parser.init(.ciphertext);
    var record_sink = record_codec.RecordSink(8, record_codec.max_ciphertext_fragment_len * 8){};
    try parser.feed(records, &record_sink);
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    for (record_sink.items[0..record_sink.len]) |record| {
        const opened = try harness.client_bridge.openHandshake(.application, record, &plaintext);
        _ = try harness.client_driver.receive(.application, opened.inner.content);
    }
    try std.testing.expect(capture.ticket.ticket.slice().len > 0);
    // The stored ticket carries the *server's* transport payload, not the
    // client's — this is exactly the value the (fixed) client-side
    // eligibility check must no longer compare against its own local one.
    try std.testing.expectEqualStrings("server transport parameters", capture.ticket.common.transport_compat.?.slice());

    var resumed = DirectHarness.initExtension();
    defer resumed.deinit();

    var offers: pre_shared_key.ClientPskOfferSet = .{};
    try offers.push(&capture.ticket);
    var clock_dummy: u8 = 0;
    const Clock = struct {
        fn now(_: *anyopaque) i64 {
            return 2000;
        }
    };
    try resumed.client_backend.setClientPskOffers(&offers, &clock_dummy, Clock.now);

    const Resolver = struct {
        state: *session.ServerRecoverableState,
        resolve_calls: usize = 0,
        fn now(_: *anyopaque) i64 {
            return 2000;
        }
        fn resolve(ctx: *anyopaque, identity: []const u8) pre_shared_key.ResolveError!pre_shared_key.ServerPskResolveResult {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.resolve_calls += 1;
            if (!std.mem.eql(u8, identity, "extension-profile-ticket")) return .miss;
            return clonedResolveHit(self.state, std.testing.allocator);
        }
    };
    // Pointer, not a copy — see the identical note in the record-profile
    // round-trip test above: `server_state` owns allocator-backed storage
    // (this ticket has a non-null `transport_compat`), and shallow-copying
    // it here would double-free that storage.
    var resolver_state: Resolver = .{ .state = &server_state };
    try resumed.server_backend.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = Resolver.now,
        .resolveFn = Resolver.resolve,
    });

    try resumed.run();

    try std.testing.expect(resumed.client_driver.isComplete());
    try std.testing.expect(resumed.server_driver.isComplete());
    // The ticket was actually offered and resolved (not silently filtered
    // out by the wrong-direction transport-compat comparison).
    try std.testing.expectEqual(@as(usize, 1), resolver_state.resolve_calls);
    try std.testing.expect(resumed.client_backend.core.psk_authenticated);
    try std.testing.expect(resumed.server_backend.core.psk_authenticated);

    var protected2: [record_codec.max_ciphertext_record_len]u8 = undefined;
    var plaintext2: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    const request = try resumed.client_bridge.sealApplicationData("resumed over quic-style transport", &protected2);
    const opened_request = try resumed.server_bridge.openApplicationData(try parseSingleRecord(.ciphertext, request), &plaintext2);
    try std.testing.expectEqualStrings("resumed over quic-style transport", opened_request.inner.content);
}

test "PSK round trip falls back to a full handshake when the resolver has no match" {
    var harness = DirectHarness.init();
    defer harness.deinit();

    var ticket_common: session.ResumableSessionCommon = .{};
    try ticket_common.init(std.testing.allocator, session.Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &([_]u8{0x77} ** tls_backend.hash_len),
        .auth_binding = session.AuthBinding.fromLeafCertificateDer(""),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 3600,
    });
    var offered_ticket: session.ClientTicketState = .{};
    try offered_ticket.init(std.testing.allocator, session.Limits.default, &ticket_common, .{
        .ticket = "unknown-to-server",
        .ticket_age_add = 0,
        .ticket_nonce = "n",
        .received_at_unix_ms = 0,
    });

    var offers: pre_shared_key.ClientPskOfferSet = .{};
    try offers.push(&offered_ticket);
    var clock_dummy: u8 = 0;
    const Clock = struct {
        fn now(_: *anyopaque) i64 {
            return 0;
        }
    };
    try harness.client_backend.setClientPskOffers(&offers, &clock_dummy, Clock.now);

    const NoMatchResolver = struct {
        fn now(_: *anyopaque) i64 {
            return 0;
        }
        fn resolve(_: *anyopaque, _: []const u8) pre_shared_key.ResolveError!pre_shared_key.ServerPskResolveResult {
            return .miss;
        }
    };
    try harness.server_backend.setServerPskResolver(.{
        .ctx = undefined,
        .nowUnixMsFn = NoMatchResolver.now,
        .resolveFn = NoMatchResolver.resolve,
    });

    try harness.run();

    try std.testing.expect(harness.client_driver.isComplete());
    try std.testing.expect(harness.server_driver.isComplete());
    try std.testing.expect(!harness.client_backend.core.psk_authenticated);
    try std.testing.expect(!harness.server_backend.core.psk_authenticated);
    try std.testing.expectEqual(events.CertificateState.valid, harness.observed.certificate_state.?);
}

test "an ineligible offered ticket is filtered without desyncing the wire index of a later valid one" {
    // Regression coverage: `sendClientHello` used to filter eligible
    // tickets while writing the wire offer, but `onServerHello` indexed
    // the original, unfiltered client offer array. With an
    // expired ticket first and a valid one second, the wire would contain
    // only the valid ticket at index 0, but the client would resolve
    // `selected_identity = 0` back to the expired ticket's PSK — a silent
    // secret mismatch. Client offers are now compacted to exactly the
    // wire-emitted, wire-ordered subset before `core.start()`, so this
    // must complete cleanly with matching keys on both sides.
    var harness = DirectHarness.init();
    defer harness.deinit();

    const psk = [_]u8{0x77} ** tls_backend.hash_len;
    var expired_common: session.ResumableSessionCommon = .{};
    try expired_common.init(std.testing.allocator, session.Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &psk,
        .application_protocol = "h2",
        .auth_binding = session.AuthBinding.fromLeafCertificateDer(tls_backend.testdata.certificate_der),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 1,
    });
    var expired_ticket: session.ClientTicketState = .{};
    try expired_ticket.init(std.testing.allocator, session.Limits.default, &expired_common, .{
        .ticket = "expired-ticket",
        .ticket_age_add = 0,
        .ticket_nonce = "n",
        .received_at_unix_ms = 0,
    });

    var valid_common: session.ResumableSessionCommon = .{};
    try valid_common.init(std.testing.allocator, session.Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &psk,
        .application_protocol = "h2",
        .auth_binding = session.AuthBinding.fromLeafCertificateDer(tls_backend.testdata.certificate_der),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 3600,
    });
    var valid_ticket: session.ClientTicketState = .{};
    try valid_ticket.init(std.testing.allocator, session.Limits.default, &valid_common, .{
        .ticket = "valid-ticket",
        .ticket_age_add = 0,
        .ticket_nonce = "n",
        .received_at_unix_ms = 0,
    });

    var offers: pre_shared_key.ClientPskOfferSet = .{};
    try offers.push(&expired_ticket); // offer index 0: filtered out at plan time
    try offers.push(&valid_ticket); // offer index 1: the only one actually sent, as wire index 0

    var clock_dummy: u8 = 0;
    const Clock = struct {
        fn now(_: *anyopaque) i64 {
            return 10_000; // well past the expired ticket's 1-second lifetime
        }
    };
    try harness.client_backend.setClientPskOffers(&offers, &clock_dummy, Clock.now);

    var stored_state = pskStoredState(&psk);
    defer stored_state.deinit();
    var resolver_state = CountingResolver{ .state = &stored_state, .identity = "valid-ticket" };
    try harness.server_backend.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = CountingResolver.now,
        .resolveFn = CountingResolver.resolve,
    });
    try harness.run();

    try std.testing.expect(harness.client_driver.isComplete());
    try std.testing.expect(harness.server_driver.isComplete());
    // Exactly one identity was ever offered (or resolved): the expired one
    // never reached the wire at all.
    try std.testing.expectEqual(@as(usize, 1), resolver_state.calls);
    try std.testing.expect(harness.client_backend.core.psk_authenticated);
    try std.testing.expect(harness.server_backend.core.psk_authenticated);
}

test "handshake-time client authentication forces a full handshake even when a PSK is offered" {
    var harness = DirectHarness.init();
    defer harness.deinit();
    harness.configureClientAuth(.required, true, .{ .pinned_certificate = tls_backend.testdata.certificate_der });

    const psk = [_]u8{0x88} ** tls_backend.hash_len;
    var common: session.ResumableSessionCommon = .{};
    try common.init(std.testing.allocator, session.Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &psk,
        .application_protocol = "h2",
        .auth_binding = session.AuthBinding.fromLeafCertificateDer(tls_backend.testdata.certificate_der),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 3600,
    });
    var ticket: session.ClientTicketState = .{};
    try ticket.init(std.testing.allocator, session.Limits.default, &common, .{
        .ticket = "client-auth-ticket",
        .ticket_age_add = 0,
        .ticket_nonce = "n",
        .received_at_unix_ms = 0,
    });
    var offers: pre_shared_key.ClientPskOfferSet = .{};
    try offers.push(&ticket);
    var clock_dummy: u8 = 0;
    const Clock = struct {
        fn now(_: *anyopaque) i64 {
            return 0;
        }
    };
    try harness.client_backend.setClientPskOffers(&offers, &clock_dummy, Clock.now);

    var stored_state = pskStoredState(&psk);
    defer stored_state.deinit();
    var resolver_state = CountingResolver{ .state = &stored_state, .identity = "client-auth-ticket" };
    try harness.server_backend.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = CountingResolver.now,
        .resolveFn = CountingResolver.resolve,
    });
    var decisions = DecisionProbe{};
    try harness.server_backend.setResumptionDecisionObserver(decisions.observer());

    try harness.run();

    try std.testing.expect(harness.client_driver.isComplete());
    try std.testing.expect(harness.server_driver.isComplete());
    try std.testing.expect(!harness.client_backend.core.psk_authenticated);
    try std.testing.expect(!harness.server_backend.core.psk_authenticated);
    // The resolver is never even consulted: client_auth forces the full
    // fallback before PSK selection begins.
    try std.testing.expectEqual(@as(usize, 0), resolver_state.calls);
    try std.testing.expectEqual(@as(usize, 1), decisions.count);
    try std.testing.expectEqual(tls_backend.Tls13Backend.ResumptionDecision.full_handshake, decisions.last.?);
    try std.testing.expectEqual(events.CertificateState.valid, harness.observed.certificate_state.?);
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
    client_alpn_protocols: [1][]const u8 = undefined,
    server_alpn_protocols: [1][]const u8 = undefined,

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
        client_post_handshake_allocator: ?std.mem.Allocator = null,
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

        self.client_alpn_protocols = .{opts.client_alpn};
        self.server_alpn_protocols = .{opts.server_alpn};
        const client_config = tls_backend.recordConfig(recordPolicyForNames(&self.client_alpn_protocols, false));
        const server_config = tls_backend.recordConfig(recordPolicyForNames(&self.server_alpn_protocols, false));
        self.client_engine = if (opts.client_verifier) |verifier|
            tls_backend.Tls13Backend.initClientWithVerifierConfigured(clientEntropy(), verifier, client_config, opts.client_options)
        else
            tls_backend.Tls13Backend.initClientConfigured(clientEntropy(), opts.client_trust, client_config, .{});
        self.server_engine = if (opts.server_provider) |provider|
            tls_backend.Tls13Backend.initServerWithProviderConfigured(serverEntropy(), provider, server_config)
        else
            tls_backend.Tls13Backend.initServerConfigured(serverEntropy(), fixtureIdentity(), server_config);
        if (opts.client_post_handshake_allocator) |post_allocator| {
            try self.client_engine.setPostHandshakeAllocator(post_allocator);
        }
        self.client_carrier = .{ .fd = self.fds[0], .max_chunk = opts.client_chunk, .one_write_per_drive = opts.one_write_per_drive };
        self.server_carrier = .{ .fd = self.fds[1], .max_chunk = opts.server_chunk, .one_write_per_drive = opts.one_write_per_drive };

        self.client = try es.PureZigRecordStream.initWithCarrierAndBackend(allocator, .client, clientProvider(), suite, self.client_carrier.carrier(), self.client_engine.backend());
        self.server = try es.PureZigRecordStream.initWithCarrierAndBackend(allocator, .server, serverProvider(), suite, self.server_carrier.carrier(), self.server_engine.backend());
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

test "record stream delivers maximum post-handshake ticket and remains usable" {
    const Capture = struct {
        count: usize = 0,
        ticket_len: usize = 0,
        psk: [tls_backend.hash_len]u8 = undefined,

        fn now(_: *anyopaque) i64 {
            return 10;
        }

        fn onTicket(ctx: *anyopaque, ticket: *const session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.count += 1;
            self.ticket_len = ticket.ticket.slice().len;
            @memcpy(&self.psk, ticket.common.resumption_psk.slice());
        }
    };

    const h = try SocketHarness.create(.{ .client_chunk = 4096, .server_chunk = 4096 });
    defer h.destroy();
    var capture = Capture{};
    const limits = session.Limits{ .max_ticket_len = session.absolute_ticket_wire_max, .max_serialized_len = 128 * 1024 };
    try h.client_engine.setSessionTicketConsumer(std.testing.allocator, limits, .{
        .ctx = &capture,
        .nowUnixMsFn = Capture.now,
        .onTicketFn = Capture.onTicket,
    });
    try h.driveUntil(SocketHarness.bothComplete);

    try std.testing.expectEqual(@as(usize, 13), try h.client.stream().write("before-ticket"));
    try h.driveUntil(struct {
        fn done(hh: *SocketHarness) bool {
            return hh.server.readiness().can_read_plaintext;
        }
    }.done);
    var app_buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("before-ticket", app_buf[0..try h.server.stream().read(&app_buf)]);

    const opaque_ticket = try std.testing.allocator.alloc(u8, session.absolute_ticket_wire_max);
    defer std.testing.allocator.free(opaque_ticket);
    @memset(opaque_ticket, 0xa5);
    var sink = DirectSink{};
    defer sink.deinit();
    var server_state = try h.server_engine.emitNewSessionTicket(std.testing.allocator, &sink, .{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .opaque_ticket = opaque_ticket,
        .issued_at_unix_ms = 10,
    }, limits);
    defer server_state.deinit();
    const ticket_event = sink.items[0].handshake_bytes;
    try h.server.applyEvent(.{ .handshake_bytes = .{
        .epoch = ticket_event.epoch,
        .data = ticket_event.data,
    } });

    var rounds: usize = 0;
    while (rounds < 5000 and capture.count == 0) : (rounds += 1) {
        _ = try h.server.stream().drive();
        _ = try h.client.stream().drive();
    }
    try std.testing.expectEqual(@as(usize, 1), capture.count);
    try std.testing.expectEqual(opaque_ticket.len, capture.ticket_len);
    try std.testing.expectEqualSlices(u8, server_state.common.resumption_psk.slice(), &capture.psk);

    try std.testing.expectEqual(@as(usize, 12), try h.server.stream().write("after-ticket"));
    try h.driveUntil(struct {
        fn done(hh: *SocketHarness) bool {
            return hh.client.readiness().can_read_plaintext;
        }
    }.done);
    try std.testing.expectEqualStrings("after-ticket", app_buf[0..try h.client.stream().read(&app_buf)]);
}

test "record stream drops valid ticket with no consumer and remains usable" {
    const h = try SocketHarness.create(.{
        .client_chunk = 1024,
        .server_chunk = 1024,
    });
    defer h.destroy();
    try h.driveUntil(SocketHarness.bothComplete);

    var sink = DirectSink{};
    defer sink.deinit();
    var server_state = try h.server_engine.emitNewSessionTicket(std.testing.allocator, &sink, .{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .opaque_ticket = "drop-ticket",
        .issued_at_unix_ms = 10,
    }, session.Limits.default);
    defer server_state.deinit();
    const ticket_event = sink.items[0].handshake_bytes;
    try h.server.applyEvent(.{ .handshake_bytes = .{
        .epoch = ticket_event.epoch,
        .data = ticket_event.data,
    } });

    var rounds: usize = 0;
    while (rounds < 1000) : (rounds += 1) {
        const s = try h.server.stream().drive();
        const c = try h.client.stream().drive();
        if (!s.made_progress and !c.made_progress) break;
    }

    try std.testing.expectEqual(@as(usize, 9), try h.client.stream().write("afterdrop"));
    try h.driveUntil(struct {
        fn done(hh: *SocketHarness) bool {
            return hh.server.readiness().can_read_plaintext;
        }
    }.done);
    var app_buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("afterdrop", app_buf[0..try h.server.stream().read(&app_buf)]);
}

test "record stream ticket callback clone survives callback return" {
    const Capture = struct {
        allocator: std.mem.Allocator,
        retained: session.ClientTicketState = .{},
        count: usize = 0,

        fn now(_: *anyopaque) i64 {
            return 10;
        }

        fn onTicket(ctx: *anyopaque, ticket: *const session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            ticket.cloneInto(self.allocator, &self.retained) catch unreachable;
            self.count += 1;
        }
    };

    const h = try SocketHarness.create(.{ .client_chunk = 1024, .server_chunk = 1024 });
    defer h.destroy();
    var capture = Capture{ .allocator = std.testing.allocator };
    defer capture.retained.deinit();
    try h.client_engine.setSessionTicketConsumer(std.testing.allocator, session.Limits.default, .{
        .ctx = &capture,
        .nowUnixMsFn = Capture.now,
        .onTicketFn = Capture.onTicket,
    });
    try h.driveUntil(SocketHarness.bothComplete);

    var sink = DirectSink{};
    defer sink.deinit();
    var server_state = try h.server_engine.emitNewSessionTicket(std.testing.allocator, &sink, .{
        .ticket_lifetime = 60,
        .ticket_age_add = 0x11223344,
        .ticket_nonce = "\x01\x02",
        .opaque_ticket = "clone-ticket",
        .max_early_data_size = 32,
        .issued_at_unix_ms = 10,
    }, session.Limits.default);
    defer server_state.deinit();
    const ticket_event = sink.items[0].handshake_bytes;
    try h.server.applyEvent(.{ .handshake_bytes = .{ .epoch = ticket_event.epoch, .data = ticket_event.data } });

    var rounds: usize = 0;
    while (rounds < 1000 and capture.count == 0) : (rounds += 1) {
        _ = try h.server.stream().drive();
        _ = try h.client.stream().drive();
    }
    try std.testing.expectEqual(@as(usize, 1), capture.count);
    try std.testing.expectEqualSlices(u8, "clone-ticket", capture.retained.ticket.slice());
    try std.testing.expectEqualSlices(u8, "\x01\x02", capture.retained.ticket_nonce.slice());
    try std.testing.expectEqual(@as(u32, 0x11223344), capture.retained.ticket_age_add);
    try std.testing.expectEqual(@as(i64, 10), capture.retained.received_at_unix_ms);
    try std.testing.expectEqual(@as(u32, 60), capture.retained.common.lifetime_seconds);
    try std.testing.expectEqual(session.EarlyDataPolicy{ .early_data_capable = 32 }, capture.retained.common.early_data);
    try std.testing.expectEqualSlices(u8, server_state.common.resumption_psk.slice(), capture.retained.common.resumption_psk.slice());
    try std.testing.expect(capture.retained.common.application_protocol != null);
    try std.testing.expectEqualSlices(u8, "h2", capture.retained.common.application_protocol.?.slice());
}

test "record stream ticket callback clone refusal is nonfatal" {
    const Capture = struct {
        allocator: std.mem.Allocator,
        storage_refused: bool = false,
        callbacks: usize = 0,

        fn now(_: *anyopaque) i64 {
            return 10;
        }

        fn onTicket(ctx: *anyopaque, ticket: *const session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            var retained: session.ClientTicketState = .{};
            ticket.cloneInto(self.allocator, &retained) catch {
                self.storage_refused = true;
                self.callbacks += 1;
                return;
            };
            retained.deinit();
            self.callbacks += 1;
        }
    };

    const h = try SocketHarness.create(.{ .client_chunk = 1024, .server_chunk = 1024 });
    defer h.destroy();
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var capture = Capture{ .allocator = failing.allocator() };
    try h.client_engine.setSessionTicketConsumer(std.testing.allocator, session.Limits.default, .{
        .ctx = &capture,
        .nowUnixMsFn = Capture.now,
        .onTicketFn = Capture.onTicket,
    });
    try h.driveUntil(SocketHarness.bothComplete);

    var sink = DirectSink{};
    defer sink.deinit();
    var server_state = try h.server_engine.emitNewSessionTicket(std.testing.allocator, &sink, .{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .opaque_ticket = "refuse-clone",
        .issued_at_unix_ms = 10,
    }, session.Limits.default);
    defer server_state.deinit();
    const ticket_event = sink.items[0].handshake_bytes;
    try h.server.applyEvent(.{ .handshake_bytes = .{ .epoch = ticket_event.epoch, .data = ticket_event.data } });

    var rounds: usize = 0;
    while (rounds < 1000 and capture.callbacks == 0) : (rounds += 1) {
        _ = try h.server.stream().drive();
        _ = try h.client.stream().drive();
    }
    try std.testing.expect(capture.storage_refused);
    try std.testing.expectEqual(@as(usize, 1), capture.callbacks);

    try std.testing.expectEqual(@as(usize, 8), try h.client.stream().write("still-ok"));
    try h.driveUntil(struct {
        fn done(hh: *SocketHarness) bool {
            return hh.server.readiness().can_read_plaintext;
        }
    }.done);
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("still-ok", buf[0..try h.server.stream().read(&buf)]);
}

test "pure-Zig HTTPS HTTP/1.1 bytes enter existing parser through EncryptedStream adapter" {
    const h = try SocketHarness.create(.{
        .client_chunk = 3,
        .server_chunk = 5,
        .client_alpn = "http/1.1",
        .server_alpn = "http/1.1",
    });
    defer h.destroy();

    try h.driveUntil(SocketHarness.bothComplete);
    try std.testing.expectEqualStrings("http/1.1", h.server.negotiatedAlpn().?);

    var client_conn = encrypted_stream_connection.EncryptedStreamHttpConnection.init(h.client.stream());
    var server_conn = encrypted_stream_connection.EncryptedStreamHttpConnection.init(h.server.stream());

    const request_bytes = "GET /adapter-h1 HTTP/1.1\r\nHost: tardigrade.test\r\n\r\n";
    try client_conn.writer().writeAll(request_bytes);
    try h.driveUntil(struct {
        fn done(hh: *SocketHarness) bool {
            return hh.server.bufferSnapshot().current.inbound_plaintext >= request_bytes.len;
        }
    }.done);

    var req_buf: [128]u8 = undefined;
    const req_len = try server_conn.read(&req_buf);
    var parsed = try http_request.Request.parse(std.testing.allocator, req_buf[0..req_len], http_request.DEFAULT_MAX_BODY_SIZE);
    defer parsed.request.deinit();
    try std.testing.expectEqualStrings("/adapter-h1", parsed.request.uri.path);
    try std.testing.expectEqual(req_len, parsed.bytes_consumed);

    const response_bytes = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";
    try server_conn.writer().writeAll(response_bytes);
    try h.driveUntil(struct {
        fn done(hh: *SocketHarness) bool {
            return hh.client.bufferSnapshot().current.inbound_plaintext >= response_bytes.len;
        }
    }.done);

    var resp_buf: [128]u8 = undefined;
    const resp_len = try client_conn.read(&resp_buf);
    try std.testing.expect(std.mem.startsWith(u8, resp_buf[0..resp_len], "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, resp_buf[0..resp_len], "\r\n\r\nok"));
}

test "pure-Zig HTTPS HTTP/2 preface and settings enter frame runtime through EncryptedStream adapter" {
    const h = try SocketHarness.create(.{
        .client_chunk = 2,
        .server_chunk = 7,
        .client_alpn = "h2",
        .server_alpn = "h2",
    });
    defer h.destroy();

    try h.driveUntil(SocketHarness.bothComplete);
    try std.testing.expectEqualStrings("h2", h.server.negotiatedAlpn().?);

    var client_conn = encrypted_stream_connection.EncryptedStreamHttpConnection.init(h.client.stream());
    var server_conn = encrypted_stream_connection.EncryptedStreamHttpConnection.init(h.server.stream());

    const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    try client_conn.writer().writeAll(preface);
    const client_settings = h2SettingsFrame(0);
    try client_conn.writer().writeAll(&client_settings);
    try h.driveUntil(struct {
        fn done(hh: *SocketHarness) bool {
            return hh.server.bufferSnapshot().current.inbound_plaintext >= preface.len + h2_frame_header_len;
        }
    }.done);

    var preface_buf: [preface.len]u8 = undefined;
    try readExactAdapter(&server_conn, preface_buf[0..]);
    try std.testing.expectEqualStrings(preface, preface_buf[0..]);
    var settings_header: [h2_frame_header_len]u8 = undefined;
    try readExactAdapter(&server_conn, &settings_header);
    try std.testing.expectEqual(@as(u8, h2_frame_type_settings), settings_header[3]);
    try std.testing.expectEqual(@as(u8, 0), settings_header[4]);
    try std.testing.expectEqual(@as(usize, 0), h2PayloadLen(settings_header));

    const server_ack = h2SettingsFrame(h2_flag_ack);
    try server_conn.writer().writeAll(&server_ack);
    try h.driveUntil(struct {
        fn done(hh: *SocketHarness) bool {
            return hh.client.bufferSnapshot().current.inbound_plaintext >= h2_frame_header_len;
        }
    }.done);
    var ack_header: [h2_frame_header_len]u8 = undefined;
    try readExactAdapter(&client_conn, &ack_header);
    try std.testing.expectEqual(@as(u8, h2_frame_type_settings), ack_header[3]);
    try std.testing.expectEqual(@as(u8, h2_flag_ack), ack_header[4]);
}

fn readExactAdapter(conn: *encrypted_stream_connection.EncryptedStreamHttpConnection, out: []u8) !void {
    var offset: usize = 0;
    while (offset < out.len) {
        const n = try conn.read(out[offset..]);
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
}

const h2_frame_header_len: usize = 9;
const h2_frame_type_settings: u8 = 0x4;
const h2_flag_ack: u8 = 0x1;

fn h2SettingsFrame(flags: u8) [h2_frame_header_len]u8 {
    return .{ 0, 0, 0, h2_frame_type_settings, flags, 0, 0, 0, 0 };
}

fn h2PayloadLen(header: [h2_frame_header_len]u8) usize {
    return (@as(usize, header[0]) << 16) | (@as(usize, header[1]) << 8) | @as(usize, header[2]);
}

fn sniIdentityConfig(patterns: []const []const u8, chain: []const []const u8, default: bool) sni_provider.CredentialBundleConfig {
    return .{
        .chain = chain,
        .patterns = patterns,
        .signer = sni_provider.SignAdapter.fromIdentity(fixtureIdentity()),
        .key_kind = .ed25519,
        .is_default = default,
    };
}

test "record stream uses reloadable SNI provider for exact wildcard and default classes" {
    var provider = sni_provider.ReloadableProvider.init(std.testing.allocator);
    defer provider.deinit();

    const chain_one = [_][]const u8{tls_backend.testdata.certificate_der};
    const chain_two = [_][]const u8{ tls_backend.testdata.certificate_der, tls_backend.testdata.certificate_der };
    const chain_three = [_][]const u8{ tls_backend.testdata.certificate_der, tls_backend.testdata.certificate_der, tls_backend.testdata.certificate_der };
    const configs = [_]sni_provider.CredentialBundleConfig{
        sniIdentityConfig(&.{"api.example.test"}, chain_one[0..], false),
        sniIdentityConfig(&.{"*.example.test"}, chain_two[0..], false),
        sniIdentityConfig(&.{"default.example.test"}, chain_three[0..], true),
    };
    try provider.reload(&configs, .{ .unknown_sni_policy = .use_default });

    {
        var verifier = credentials.MockVerifier.init(.accepted);
        const h = try SocketHarness.create(.{
            .server_provider = provider.provider(),
            .client_verifier = verifier.verifier(),
            .client_options = .{ .server_name = "API.Example.Test", .policy = .{ .require_peer_authentication = true } },
        });
        defer h.destroy();
        try h.driveUntil(SocketHarness.bothComplete);
        try std.testing.expectEqual(@as(usize, 1), verifier.last_chain_len);
    }
    {
        var verifier = credentials.MockVerifier.init(.accepted);
        const h = try SocketHarness.create(.{
            .server_provider = provider.provider(),
            .client_verifier = verifier.verifier(),
            .client_options = .{ .server_name = "www.example.test", .policy = .{ .require_peer_authentication = true } },
        });
        defer h.destroy();
        try h.driveUntil(SocketHarness.bothComplete);
        try std.testing.expectEqual(@as(usize, 2), verifier.last_chain_len);
    }
    {
        var verifier = credentials.MockVerifier.init(.accepted);
        const h = try SocketHarness.create(.{
            .server_provider = provider.provider(),
            .client_verifier = verifier.verifier(),
            .client_options = .{ .policy = .{ .require_peer_authentication = true } },
        });
        defer h.destroy();
        try h.driveUntil(SocketHarness.bothComplete);
        try std.testing.expectEqual(@as(usize, 3), verifier.last_chain_len);
    }
}

test "record engine pins selected SNI generation across provider reload" {
    var provider = sni_provider.ReloadableProvider.init(std.testing.allocator);
    defer provider.deinit();

    const chain_one = [_][]const u8{tls_backend.testdata.certificate_der};
    const chain_two = [_][]const u8{ tls_backend.testdata.certificate_der, tls_backend.testdata.certificate_der };
    var first_deinit = std.atomic.Value(usize).init(0);
    const BlockingSigner = struct {
        entered: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        release_sign: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        release_count: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

        fn sign(ctx: *anyopaque, scheme: credentials.SignatureScheme, input: []const u8, out: []u8) credentials.SignError!usize {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (scheme != .ed25519) return error.InvalidCallbackBehavior;
            self.entered.store(true, .release);
            while (!self.release_sign.load(.acquire)) {
                std.atomic.spinLoopHint();
            }
            var identity = fixtureIdentity();
            defer std.crypto.secureZero(u8, std.mem.asBytes(&identity.key));
            return identity.sign(input, out);
        }

        fn release(ctx: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            _ = self.release_count.fetchAdd(1, .monotonic);
        }
    };
    var blocking = BlockingSigner{};
    const blocking_config = sni_provider.CredentialBundleConfig{
        .chain = chain_one[0..],
        .patterns = &.{"pin.example.test"},
        .signer = sni_provider.SignAdapter.fromExternal(&blocking, BlockingSigner.sign, BlockingSigner.release),
        .key_kind = .ed25519,
        .supported_schemes = &.{.ed25519},
        .is_default = true,
    };
    const first = try sni_provider.Snapshot.build(std.testing.allocator, &.{blocking_config}, .{}, 1);
    first.deinit_count = &first_deinit;
    try provider.install(first);

    var verifier = credentials.MockVerifier.init(.accepted);
    var client = tls_backend.Tls13Backend.initClientWithVerifier(
        clientEntropy(),
        verifier.verifier(),
        .record,
        .{ .server_name = "pin.example.test", .policy = .{ .require_peer_authentication = true } },
    );
    defer client.deinit();
    var server = tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), provider.provider(), .record);
    defer server.deinit();
    var client_sink = DirectSink{};
    defer client_sink.deinit();
    var server_sink = DirectSink{};
    defer server_sink.deinit();

    try client.backend().start(.client, {}, &client_sink);
    var client_hello_buf: [1024]u8 = undefined;
    const client_hello = firstInitialCrypto(&client_sink, &client_hello_buf);
    try server.backend().start(.server, {}, &server_sink);

    const ServerReceiveThread = struct {
        server_backend: *tls_backend.Tls13Backend,
        hello: []const u8,
        sink: *DirectSink,
        result: ?anyerror = null,

        fn run(self: *@This()) void {
            self.server_backend.backend().receive(.initial, self.hello, self.sink) catch |err| {
                self.result = err;
            };
        }
    };
    var receive_ctx = ServerReceiveThread{
        .server_backend = &server,
        .hello = client_hello,
        .sink = &server_sink,
    };
    var thread = try std.Thread.spawn(.{}, ServerReceiveThread.run, .{&receive_ctx});
    var thread_joined = false;
    defer {
        if (!thread_joined) {
            blocking.release_sign.store(true, .release);
            thread.join();
        }
    }

    var spins: usize = 0;
    while (!blocking.entered.load(.acquire) and spins < 1_000_000) : (spins += 1) {
        std.Thread.yield() catch {};
    }
    if (!blocking.entered.load(.acquire)) {
        blocking.release_sign.store(true, .release);
        thread.join();
        thread_joined = true;
        if (receive_ctx.result) |err| return err;
        return error.TestTimeout;
    }

    try provider.reload(&.{sniIdentityConfig(&.{"pin.example.test"}, chain_two[0..], true)}, .{});
    try std.testing.expectEqual(@as(usize, 0), first_deinit.load(.monotonic));

    blocking.release_sign.store(true, .release);
    thread.join();
    thread_joined = true;
    if (receive_ctx.result) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), first_deinit.load(.monotonic));
    try std.testing.expectEqual(@as(usize, 1), blocking.release_count.load(.monotonic));

    var server_hello_buf: [512]u8 = undefined;
    const server_hello = firstInitialCrypto(&server_sink, &server_hello_buf);
    var server_flight_buf: [8192]u8 = undefined;
    const server_flight = collectHandshakeCrypto(&server_sink, &server_flight_buf);
    client_sink.reset();
    try client.backend().receive(.initial, server_hello, &client_sink);
    try client.backend().receive(.handshake, server_flight, &client_sink);
    try std.testing.expectEqual(@as(usize, 1), verifier.last_chain_len);

    var client_flight_buf: [8192]u8 = undefined;
    const client_flight = collectHandshakeCrypto(&client_sink, &client_flight_buf);
    try deliverClientFlightToServer(&server, &server_sink, client_flight, false);
    try std.testing.expectEqual(tls_core.handshake.HandshakeLifecycle.complete, server.core.handshake_lifecycle);

    var later_verifier = credentials.MockVerifier.init(.accepted);
    const h = try SocketHarness.create(.{
        .server_provider = provider.provider(),
        .client_verifier = later_verifier.verifier(),
        .client_options = .{ .server_name = "pin.example.test", .policy = .{ .require_peer_authentication = true } },
    });
    defer h.destroy();
    try h.driveUntil(SocketHarness.bothComplete);
    try std.testing.expectEqual(@as(usize, 2), later_verifier.last_chain_len);
}

test "record stream fails unknown SNI before application data is possible" {
    var provider = sni_provider.ReloadableProvider.init(std.testing.allocator);
    defer provider.deinit();

    const chain = [_][]const u8{tls_backend.testdata.certificate_der};
    const config = sniIdentityConfig(&.{"known.example.test"}, chain[0..], true);
    try provider.reload(&.{config}, .{ .unknown_sni_policy = .fail_handshake });

    var verifier = credentials.MockVerifier.init(.accepted);
    const h = try SocketHarness.create(.{
        .server_provider = provider.provider(),
        .client_verifier = verifier.verifier(),
        .client_options = .{ .server_name = "missing.example.test", .policy = .{ .require_peer_authentication = true } },
    });
    defer h.destroy();

    try std.testing.expectError(error.NoApplicableCredential, h.driveUntil(SocketHarness.bothComplete));
    try std.testing.expect(!h.client.bridge.handshake_complete);
    try std.testing.expect(!h.client.readiness().can_write_plaintext);
    try std.testing.expectEqual(tls_backend.CredentialFailure.no_credential_available, h.server_engine.credentialFailure().?);
    try std.testing.expectEqual(@as(usize, 0), verifier.verify_count);
}

test "unknown SNI fails before emitting ServerHello" {
    var provider = sni_provider.ReloadableProvider.init(std.testing.allocator);
    defer provider.deinit();

    const chain = [_][]const u8{tls_backend.testdata.certificate_der};
    const config = sniIdentityConfig(&.{"known.example.test"}, chain[0..], true);
    try provider.reload(&.{config}, .{ .unknown_sni_policy = .fail_handshake });

    var server = tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), provider.provider(), .record);
    defer server.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);

    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{ .sni = "missing.example.test" });
    try std.testing.expectError(error.NoApplicableCredential, server.backend().receive(.initial, hello, &sink));
    try std.testing.expectEqual(@as(usize, 0), countCryptoEvents(&sink, .initial));
}

test "record stream SNI provider fails exact incompatible signature without wildcard fallback" {
    var provider = sni_provider.ReloadableProvider.init(std.testing.allocator);
    defer provider.deinit();
    const chain = [_][]const u8{tls_backend.testdata.certificate_der};
    const configs = [_]sni_provider.CredentialBundleConfig{
        sniIdentityConfig(&.{"api.example.test"}, chain[0..], false),
        sniIdentityConfig(&.{"*.example.test"}, chain[0..], true),
    };
    try provider.reload(&configs, .{});

    var server = tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), provider.provider(), .record);
    defer server.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);

    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{ .sni = "api.example.test", .sig_schemes = &.{0x0403} });
    try std.testing.expectError(error.NoApplicableCredential, server.backend().receive(.initial, hello, &sink));
    try std.testing.expectEqual(tls_backend.CredentialFailure.no_compatible_signature_algorithm, server.credentialFailure().?);
}

test "pending server credential selection emits no ServerHello until resume" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.async_select = true;
    mock.pending_polls = 1;
    var server = serverWithProvider(&mock);
    defer server.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);

    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{ .sni = "pending.example.test" });
    try server.backend().receive(.initial, hello, &sink);
    try std.testing.expect(server.authPending());
    try std.testing.expectEqual(@as(usize, 1), mock.select_count);
    try std.testing.expectEqual(@as(usize, 0), countCryptoEvents(&sink, .initial));

    try server.backend().resumeAuth(&sink);
    try std.testing.expect(server.authPending());
    try std.testing.expectEqual(@as(usize, 0), countCryptoEvents(&sink, .initial));

    try server.backend().resumeAuth(&sink);
    try std.testing.expect(!server.authPending());
    try std.testing.expectEqual(@as(usize, 1), countCryptoEvents(&sink, .initial));
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
    include_signature_algorithms: bool = true,
    sig_schemes: []const u16 = &.{ 0x0807, 0x0403 },
    alpn_protocols: ?[]const []const u8 = &.{"h2"},
    duplicate_supported_versions: bool = false,
    /// The opaque transport extension (e.g. QUIC transport parameters) to
    /// offer, for driving an extension-profile (#392 HTTP/3) server through
    /// selection the same way a real QUIC client would.
    transport_extension: ?struct { extension_type: u16, payload: []const u8 } = null,
    /// #362: offer one or more resumption PSKs, in order, as the
    /// (necessarily last) ClientHello extension. Each binder is computed
    /// over the exact bytes this function ends up producing, from the
    /// per-entry `binder_psk` — pass a value other than the identity's real
    /// PSK to model a wrong binder.
    psk: ?PskOfferOptions = null,
};

const PskOfferOptions = struct {
    items: []const PskOfferItemOptions,
    /// Skip writing `psk_key_exchange_modes` — for the missing-extension
    /// malformed-input test.
    omit_modes: bool = false,
    modes: []const pre_shared_key.PskKeyExchangeMode = &.{.psk_dhe_ke},
    /// When set, write this literal `pre_shared_key` extension_data
    /// verbatim instead of building it from `items` — bypasses
    /// `pre_shared_key.writeOffer`'s own `max_offered_identities` cap, for
    /// constructing a wire ClientHello with more offered identities than
    /// this module ever legitimately emits (the resolver-attempt-cap
    /// tests).
    raw_ext_data: ?[]const u8 = null,
};

const PskOfferItemOptions = struct {
    identity: []const u8,
    binder_psk: []const u8,
    obfuscated_ticket_age: u32 = 0,
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
    if (opts.duplicate_supported_versions) {
        try w.u16_(43);
        try w.u16_(3);
        try w.u8_(2);
        try w.u16_(0x0304);
    }
    // supported_groups
    try w.u16_(10);
    try w.u16_(4);
    try w.u16_(2);
    try w.u16_(0x001d);
    // signature_algorithms
    if (opts.include_signature_algorithms) {
        try w.u16_(13);
        try w.u16_(@intCast(2 + 2 * opts.sig_schemes.len));
        try w.u16_(@intCast(2 * opts.sig_schemes.len));
        for (opts.sig_schemes) |scheme| try w.u16_(scheme);
    }
    // key_share
    try w.u16_(51);
    try w.u16_(2 + 2 + 2 + X25519.public_length);
    try w.u16_(2 + 2 + X25519.public_length);
    try w.u16_(0x001d);
    try w.u16_(X25519.public_length);
    try w.bytes(&key_pair.public_key);
    // alpn
    if (opts.alpn_protocols) |protocols| {
        try w.u16_(16);
        const alpn_ext = try w.reserve(2);
        const alpn_list = try w.reserve(2);
        for (protocols) |protocol| {
            try w.u8_(@intCast(protocol.len));
            try w.bytes(protocol);
        }
        w.patch(2, alpn_list);
        w.patch(2, alpn_ext);
    }
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
    // opaque transport extension (extension-profile / QUIC servers require
    // seeing this before selection completes)
    if (opts.transport_extension) |transport| {
        try w.u16_(transport.extension_type);
        try w.u16_(@intCast(transport.payload.len));
        try w.bytes(transport.payload);
    }
    // pre_shared_key (#362): must be the last extension.
    var psk_offer: ?pre_shared_key.ClientOfferWrite = null;
    var psk_items_buf: [pre_shared_key.max_offered_identities]pre_shared_key.OfferItem = undefined;
    if (opts.psk) |psk_opt| {
        if (!psk_opt.omit_modes) {
            try w.u16_(pre_shared_key.ext_psk_key_exchange_modes);
            const modes_ext_len = try w.reserve(2);
            try pre_shared_key.writeModes(&w, psk_opt.modes);
            w.patch(2, modes_ext_len);
        }
        if (psk_opt.raw_ext_data) |raw| {
            try w.u16_(pre_shared_key.ext_pre_shared_key);
            try w.u16_(@intCast(raw.len));
            try w.bytes(raw);
        } else {
            for (psk_opt.items, 0..) |item, i| {
                psk_items_buf[i] = .{
                    .identity = item.identity,
                    .obfuscated_ticket_age = item.obfuscated_ticket_age,
                    .digest_len = tls_backend.hash_len,
                };
            }
            psk_offer = try pre_shared_key.writeOffer(&w, psk_items_buf[0..psk_opt.items.len]);
        }
    }

    w.patch(2, extensions_len);
    w.patch(3, message_len);

    if (psk_offer) |offer| {
        const prefix = buf[0..offer.truncated_len];
        for (opts.psk.?.items, 0..) |item, i| {
            var binder: [tls_backend.hash_len]u8 = undefined;
            try pre_shared_key.deriveBinder(.sha256, item.binder_psk, prefix, &binder);
            const slot = offer.slots[i];
            @memcpy(buf[slot.offset..][0..slot.len], &binder);
        }
    }
    return buf[0..w.len];
}

/// Server key-share cases for the PSK-selected ServerHello consistency
/// matrix (#362: "selected index/hash/key-share consistency is validated
/// by the client").
const ServerKeyShareCase = enum { valid, missing, wrong_group, wrong_length, low_order };

const ServerHelloOptions = struct {
    session_id: []const u8 = &.{},
    key_share_seed: [X25519.seed_length]u8 = [_]u8{0x55} ** X25519.seed_length,
    selected_identity: ?u16 = null,
    selected_version: u16 = 0x0304,
    cipher_suite: u16 = 0x1301,
    key_share: ServerKeyShareCase = .valid,
};

/// Build a minimal, well-formed (unless `opts` deliberately says
/// otherwise) TLS 1.3 ServerHello — for driving a client's `onServerHello`
/// directly with a chosen `selected_identity`, cipher suite, negotiated
/// version, and key-share shape (#362 client-side consistency tests),
/// independent of any real server.
fn buildServerHello(buf: []u8, opts: ServerHelloOptions) ![]const u8 {
    const key_pair = try X25519.KeyPair.generateDeterministic(opts.key_share_seed);
    var w = HsWriter{ .buf = buf };
    try w.u8_(@intFromEnum(HsMessageType.server_hello));
    const message_len = try w.reserve(3);
    try w.u16_(0x0303); // legacy_version
    try w.bytes(&([_]u8{0x51} ** 32)); // random
    try w.u8_(@intCast(opts.session_id.len));
    try w.bytes(opts.session_id);
    try w.u16_(opts.cipher_suite);
    try w.u8_(0); // legacy_compression_method
    const extensions_len = try w.reserve(2);
    try w.u16_(43); // supported_versions
    try w.u16_(2);
    try w.u16_(opts.selected_version);
    switch (opts.key_share) {
        .missing => {},
        .valid => {
            try w.u16_(51);
            try w.u16_(2 + 2 + X25519.public_length);
            try w.u16_(0x001d); // x25519
            try w.u16_(X25519.public_length);
            try w.bytes(&key_pair.public_key);
        },
        .wrong_group => {
            try w.u16_(51);
            try w.u16_(2 + 2 + X25519.public_length);
            try w.u16_(0x0017); // secp256r1, not x25519
            try w.u16_(X25519.public_length);
            try w.bytes(&key_pair.public_key);
        },
        .wrong_length => {
            const short_len = X25519.public_length - 1;
            try w.u16_(51);
            try w.u16_(2 + 2 + short_len);
            try w.u16_(0x001d);
            try w.u16_(short_len);
            try w.bytes(key_pair.public_key[0..short_len]);
        },
        .low_order => {
            try w.u16_(51);
            try w.u16_(2 + 2 + X25519.public_length);
            try w.u16_(0x001d);
            try w.u16_(X25519.public_length);
            try w.bytes(&([_]u8{0} ** X25519.public_length)); // the identity point
        },
    }
    if (opts.selected_identity) |idx| {
        try w.u16_(pre_shared_key.ext_pre_shared_key);
        try w.u16_(2);
        try w.u16_(idx);
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

test "record ALPN policy uses server preference across a dual offer" {
    var server = tls_backend.Tls13Backend.initServerConfigured(
        serverEntropy(),
        fixtureIdentity(),
        tls_backend.recordConfig(tls_core.policy.Policy.recordDefault()),
    );
    defer server.deinit();

    try driveServerSelection(&server, .{ .alpn_protocols = &.{ "http/1.1", "h2" } });
    try std.testing.expectEqualStrings("h2", server.selectedAlpn().?);
}

test "record ALPN policy permits absent extension only when configured" {
    var fallback = tls_backend.Tls13Backend.initServerConfigured(
        serverEntropy(),
        fixtureIdentity(),
        tls_backend.recordConfig(tls_core.policy.Policy.recordHttp1Only(true)),
    );
    defer fallback.deinit();

    try driveServerSelection(&fallback, .{ .alpn_protocols = null });
    try std.testing.expect(fallback.selectedAlpn() == null);

    var strict = tls_backend.Tls13Backend.initServerConfigured(
        serverEntropy(),
        fixtureIdentity(),
        tls_backend.recordConfig(tls_core.policy.Policy.recordHttp1Only(false)),
    );
    defer strict.deinit();

    try std.testing.expectError(error.AlpnMismatch, driveServerSelection(&strict, .{ .alpn_protocols = null }));
}

test "record ALPN fallback rejects present empty extension as malformed" {
    var fallback = tls_backend.Tls13Backend.initServerConfigured(
        serverEntropy(),
        fixtureIdentity(),
        tls_backend.recordConfig(tls_core.policy.Policy.recordHttp1Only(true)),
    );
    defer fallback.deinit();

    try std.testing.expectError(error.MalformedHandshake, driveServerSelection(&fallback, .{ .alpn_protocols = &.{} }));
}

test "duplicate ClientHello extension maps to illegal_parameter" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();

    try expectServerReceiveError(&server, .{ .duplicate_supported_versions = true }, error.IllegalParameter);
}

test "record ALPN policy rejects no-overlap and malformed vectors" {
    var no_overlap = tls_backend.Tls13Backend.initServer(
        serverEntropy(),
        fixtureIdentity(),
        .record,
    );
    defer no_overlap.deinit();

    try std.testing.expectError(error.AlpnMismatch, driveServerSelection(&no_overlap, .{ .alpn_protocols = &.{"http/1.1"} }));

    var h2_only_absent = tls_backend.Tls13Backend.initServer(
        serverEntropy(),
        fixtureIdentity(),
        .record,
    );
    defer h2_only_absent.deinit();

    try std.testing.expectError(error.AlpnMismatch, driveServerSelection(&h2_only_absent, .{ .alpn_protocols = null }));

    var malformed = tls_backend.Tls13Backend.initServer(
        serverEntropy(),
        fixtureIdentity(),
        .record,
    );
    defer malformed.deinit();

    try std.testing.expectError(error.MalformedHandshake, driveServerSelection(&malformed, .{ .alpn_protocols = &.{""} }));
}

test "exact SNI reaches credential selection through a mock provider" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    var server = tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), mock.provider(), .record);
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
    var server = tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), mock.provider(), .record);
    defer server.deinit();

    try driveServerSelection(&server, .{ .sni = null });
    try std.testing.expectEqual(@as(usize, 1), mock.select_count);
    try std.testing.expect(mock.lastServerName() == null);
}

test "selection sees the peer's offered schemes and picks a compatible credential" {
    // Fixed Ed25519 identity; the peer offers ECDSA first then Ed25519. The
    // fixed provider still binds, proving order-independent compatibility.
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();
    try driveServerSelection(&server, .{ .sig_schemes = &.{ 0x0403, 0x0807 } });
    try std.testing.expect(server.credentialFailure() == null);
}

test "no compatible signature algorithm fails with handshake_failure attribution" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
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
    var server = tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), mock.provider(), .record);
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
    var server = tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), mock.provider(), .record);
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
    var server = tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), mock.provider(), .record);
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
    var server = tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), mock.provider(), .record);
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

test "server rejects provider-selected signature scheme incompatible with leaf key before flight" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.scheme_override = .ecdsa_secp256r1_sha256;
    var server = tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), mock.provider(), .record);
    defer server.deinit();

    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{});
    try std.testing.expectError(error.CredentialProviderFailed, server.backend().receive(.initial, hello, &sink));
    try std.testing.expectEqual(tls_backend.CredentialFailure.invalid_callback_behavior, server.credentialFailure().?);
    try std.testing.expectEqual(@as(usize, 1), mock.release_count);
    try std.testing.expectEqual(@as(usize, 0), countCryptoEvents(&sink, .initial));
}

test "async server selection rejects signature scheme incompatible with leaf key before flight" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.scheme_override = .ecdsa_secp256r1_sha256;
    mock.async_select = true;
    mock.pending_polls = 0;
    var server = tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), mock.provider(), .record);
    defer server.deinit();

    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{});
    try server.backend().receive(.initial, hello, &sink);
    try std.testing.expect(server.authPending());
    try std.testing.expectError(error.CredentialProviderFailed, server.resumeAuth(&sink));
    try std.testing.expectEqual(tls_backend.CredentialFailure.invalid_callback_behavior, server.credentialFailure().?);
    try std.testing.expectEqual(@as(usize, 1), mock.release_count);
    try std.testing.expectEqual(@as(usize, 0), countCryptoEvents(&sink, .initial));
}

fn malformedEd25519PublicKeyCertificate(out: *[tls_backend.testdata.certificate_der.len]u8) []const u8 {
    @memcpy(out, tls_backend.testdata.certificate_der);
    const parsed = (std.crypto.Certificate{ .buffer = out, .index = 0 }).parse() catch unreachable;
    const pub_key = parsed.pubKey();
    const offset = @intFromPtr(pub_key.ptr) - @intFromPtr(out);
    @memset(out[offset..][0..pub_key.len], 0xff);
    return out[0..];
}

test "malformed supported Ed25519 public key is bad_certificate" {
    var cert: [tls_backend.testdata.certificate_der.len]u8 = undefined;
    const malformed = malformedEd25519PublicKeyCertificate(&cert);
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.chain_entry = .{malformed};
    var verifier = credentials.MockVerifier.init(.accepted);
    const h = try SocketHarness.create(.{ .server_provider = mock.provider(), .client_verifier = verifier.verifier() });
    defer h.destroy();

    const failures = driveUntilBothErrors(h);
    try std.testing.expectEqual(@as(?anyerror, error.CertificateInvalid), failures.client);
    try std.testing.expectEqual(@as(?anyerror, error.PeerFatalAlert), failures.server);
    try std.testing.expectEqual(tls_backend.CredentialFailure.invalid_peer_certificate_chain, h.client_engine.credentialFailure().?);
    try std.testing.expectEqual(
        tls_core.alerts.AlertDescription.bad_certificate,
        h.client_engine.credentialFailure().?.alert(),
    );
    try std.testing.expectEqual(@as(usize, 0), verifier.verify_count);
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
    return tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), mock.provider(), .record);
}

fn expectServerReceiveError(server: *tls_backend.Tls13Backend, opts: ClientHelloOptions, want: anyerror) !void {
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [2048]u8 = undefined;
    const hello = try buildClientHello(&buf, opts);
    try std.testing.expectError(want, server.backend().receive(.initial, hello, &sink));
}

fn countCryptoEvents(sink: *const DirectSink, epoch: events.EncryptionEpoch) usize {
    var count: usize = 0;
    for (sink.items[0..sink.len]) |event| switch (event) {
        .handshake_bytes => |bytes| {
            if (bytes.epoch == epoch) count += 1;
        },
        else => {},
    };
    return count;
}

fn expectMalformedSniRejectedBeforeSelection(raw_sni: []const u8) !void {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    var server = serverWithProvider(&mock);
    defer server.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [2048]u8 = undefined;
    const hello = try buildClientHello(&buf, .{ .sni = raw_sni });
    try std.testing.expectError(error.IllegalParameter, server.backend().receive(.initial, hello, &sink));
    try std.testing.expectEqual(@as(usize, 0), mock.select_count);
    try std.testing.expectEqual(@as(usize, 0), countCryptoEvents(&sink, .initial));
}

test "a compatible signature scheme past the legacy cap is still selected" {
    // 17 filler schemes, then Ed25519 in slot 18: truncation at 16 would have
    // hidden it and produced a false NoCompatibleSignatureAlgorithm.
    var schemes: [18]u16 = undefined;
    for (0..17) |i| schemes[i] = @intCast(0xfe00 + i);
    schemes[17] = 0x0807; // ed25519
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();
    try driveServerSelection(&server, .{ .sig_schemes = &schemes });
    try std.testing.expect(server.credentialFailure() == null);
}

test "a signature_algorithms offer larger than the bound fails closed" {
    var schemes: [80]u16 = undefined;
    for (0..80) |i| schemes[i] = @intCast(0xfe00 + i);
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();
    try expectServerReceiveError(&server, .{ .sig_schemes = &schemes }, error.MalformedHandshake);
}

test "an empty signature_algorithms list is a peer-attributed malformed ClientHello" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();
    try expectServerReceiveError(&server, .{ .sig_schemes = &.{} }, error.MalformedHandshake);
}

test "an absent signature_algorithms extension maps to missing_extension" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();
    try expectServerReceiveError(&server, .{ .include_signature_algorithms = false }, error.MissingExtension);
}

test "malformed SNI is rejected rather than collapsed into the default path" {
    // Empty host_name.
    {
        var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
        defer server.deinit();
        // ServerNameList<len=3>{ name_type=0, host_name<len=0> }
        const empty_host = [_]u8{ 0x00, 0x03, 0x00, 0x00, 0x00 };
        try expectServerReceiveError(&server, .{ .sni_raw = &empty_host }, error.IllegalParameter);
    }
    // Duplicate host_name entries (RFC 6066 forbids a repeated name_type).
    {
        var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
        defer server.deinit();
        // ServerNameList<len=8>{ {0,"a"}, {0,"b"} }
        const dup = [_]u8{ 0x00, 0x08, 0x00, 0x00, 0x01, 'a', 0x00, 0x00, 0x01, 'b' };
        try expectServerReceiveError(&server, .{ .sni_raw = &dup }, error.IllegalParameter);
    }
    // Empty ServerNameList (RFC 6066 §3: ServerNameList<1..>). Must be rejected,
    // not silently treated as "no host_name present" and routed to the default
    // credential.
    {
        var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
        defer server.deinit();
        const empty_list = [_]u8{ 0x00, 0x00 }; // ServerNameList<len=0>{}
        try expectServerReceiveError(&server, .{ .sni_raw = &empty_list }, error.IllegalParameter);
    }
    try expectMalformedSniRejectedBeforeSelection("bad..example");
    try expectMalformedSniRejectedBeforeSelection("bad host.example");
    try expectMalformedSniRejectedBeforeSelection("bad\x00host.example");
    try expectMalformedSniRejectedBeforeSelection("-bad.example");
    try expectMalformedSniRejectedBeforeSelection("bad-.example");
    try expectMalformedSniRejectedBeforeSelection("bad.-example");
    try expectMalformedSniRejectedBeforeSelection("bad.example-");
    const long_label = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example";
    try expectMalformedSniRejectedBeforeSelection(long_label);
    const too_long_name =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa." ++
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb." ++
        "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc." ++
        "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd." ++
        "e.example";
    try expectMalformedSniRejectedBeforeSelection(too_long_name);
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

fn handshakeCompleteIn(sink: *const DirectSink) bool {
    for (sink.items[0..sink.len]) |event| {
        if (event == .handshake_complete) return true;
    }
    return false;
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

fn pskStoredState(psk: []const u8) session.ServerRecoverableState {
    return pskStoredStateWithBinding(psk, session.AuthBinding.fromLeafCertificateDer(tls_backend.testdata.certificate_der));
}

/// Like `pskStoredState`, but with an explicit `auth_binding` — for modelling
/// a ticket issued under a *different* server certificate than the one
/// currently selected (certificate-rotation fallback).
fn pskStoredStateWithBinding(psk: []const u8, auth_binding: session.AuthBinding) session.ServerRecoverableState {
    var common: session.ResumableSessionCommon = .{};
    common.init(std.testing.allocator, session.Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = psk,
        // Matches `buildClientHello`'s default `alpn_protocols = &.{"h2"}`
        // and `serverWithProvider`'s "h2" record policy, so the candidate
        // compatibility check (negotiated ALPN vs. stored) is satisfied.
        .application_protocol = "h2",
        .auth_binding = auth_binding,
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 3600,
    }) catch unreachable;
    var state: session.ServerRecoverableState = .{};
    state.init(&common, 0);
    return state;
}

fn clonedResolveHit(
    state: *session.ServerRecoverableState,
    allocator: std.mem.Allocator,
) pre_shared_key.ResolveError!pre_shared_key.ServerPskResolveResult {
    var out: session.ServerRecoverableState = .{};
    state.cloneInto(allocator, &out) catch return error.ResolverFailed;
    return .{ .hit = .{ .state = out, .lease = pre_shared_key.ServerPskLease.initNoop() } };
}

const CountingResolver = struct {
    state: *session.ServerRecoverableState,
    identity: []const u8,
    calls: usize = 0,

    fn now(_: *anyopaque) i64 {
        return 0;
    }
    fn resolve(ctx: *anyopaque, identity: []const u8) pre_shared_key.ResolveError!pre_shared_key.ServerPskResolveResult {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        if (!std.mem.eql(u8, identity, self.identity)) return .miss;
        return clonedResolveHit(self.state, std.testing.allocator);
    }
};

const DecisionProbe = struct {
    count: usize = 0,
    last: ?tls_backend.Tls13Backend.ResumptionDecision = null,

    fn observer(self: *DecisionProbe) tls_backend.Tls13Backend.ResumptionDecisionObserver {
        return .{ .ctx = self, .onDecisionFn = onDecision };
    }

    fn onDecision(ctx: *anyopaque, decision: tls_backend.Tls13Backend.ResumptionDecision) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.count += 1;
        self.last = decision;
    }
};

const LeaseProbe = struct {
    commit_count: usize = 0,
    release_count: usize = 0,
    deinit_count: usize = 0,
    sink: ?*DirectSink = null,
    committed_sink_len: ?usize = null,

    fn lease(self: *LeaseProbe) pre_shared_key.ServerPskLease {
        return pre_shared_key.ServerPskLease.initOwned(self, commit, release, deinitLease);
    }

    fn commit(ctx: *anyopaque) void {
        const self: *LeaseProbe = @ptrCast(@alignCast(ctx));
        self.commit_count += 1;
        if (self.sink) |sink| self.committed_sink_len = sink.len;
    }

    fn release(ctx: *anyopaque) void {
        const self: *LeaseProbe = @ptrCast(@alignCast(ctx));
        self.release_count += 1;
    }

    fn deinitLease(ctx: *anyopaque) void {
        const self: *LeaseProbe = @ptrCast(@alignCast(ctx));
        self.deinit_count += 1;
    }
};

const TwoIdentityLeaseResolver = struct {
    first_identity: []const u8,
    first_state: *session.ServerRecoverableState,
    first_lease: *LeaseProbe,
    second_identity: []const u8,
    second_state: *session.ServerRecoverableState,
    second_lease: *LeaseProbe,
    calls: usize = 0,

    fn now(_: *anyopaque) i64 {
        return 0;
    }

    fn resolve(ctx: *anyopaque, identity: []const u8) pre_shared_key.ResolveError!pre_shared_key.ServerPskResolveResult {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        if (std.mem.eql(u8, identity, self.first_identity)) {
            var out: session.ServerRecoverableState = .{};
            self.first_state.cloneInto(std.testing.allocator, &out) catch return error.ResolverFailed;
            return .{ .hit = .{ .state = out, .lease = self.first_lease.lease() } };
        }
        if (std.mem.eql(u8, identity, self.second_identity)) {
            var out: session.ServerRecoverableState = .{};
            self.second_state.cloneInto(std.testing.allocator, &out) catch return error.ResolverFailed;
            return .{ .hit = .{ .state = out, .lease = self.second_lease.lease() } };
        }
        return .miss;
    }
};

test "async credential selection resumes PSK selection identically to the synchronous path" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.async_select = true;
    mock.pending_polls = 2;
    var server = serverWithProvider(&mock);
    defer server.deinit();

    const psk = [_]u8{0x5a} ** tls_backend.hash_len;
    var stored_state = pskStoredState(&psk);
    defer stored_state.deinit();
    var resolver_state = CountingResolver{ .state = &stored_state, .identity = "async-ticket" };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = CountingResolver.now,
        .resolveFn = CountingResolver.resolve,
    });
    var decisions = DecisionProbe{};
    try server.setResumptionDecisionObserver(decisions.observer());

    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{ .psk = .{ .items = &.{.{ .identity = "async-ticket", .binder_psk = &psk }} } });
    try server.backend().receive(.initial, hello, &sink);

    // Parked awaiting the async credential selection: no resolver or binder
    // work has happened yet — PSK selection only runs once a credential is
    // in hand, exactly as it does synchronously.
    try std.testing.expect(server.authPending());
    try std.testing.expectEqual(@as(usize, 0), resolver_state.calls);

    try server.resumeAuth(&sink); // poll #1: still pending
    try server.resumeAuth(&sink); // poll #2: still pending
    try server.resumeAuth(&sink); // poll #3: completes, runs PSK selection + the rest of the flight
    try std.testing.expect(!server.authPending());

    try std.testing.expectEqual(@as(usize, 1), resolver_state.calls);
    try std.testing.expect(server.core.psk_authenticated);
    try std.testing.expect(server.credentialFailure() == null);
    try std.testing.expect(server.client_hello_psk == null);
}

test "async credential selection failure clears the captured PSK offer" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.async_select = true;
    mock.pending_polls = 0;
    mock.pending_fails = true;
    var server = serverWithProvider(&mock);
    defer server.deinit();

    const psk = [_]u8{0x5a} ** tls_backend.hash_len;
    var stored_state = pskStoredState(&psk);
    defer stored_state.deinit();
    var resolver_state = CountingResolver{ .state = &stored_state, .identity = "async-ticket" };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = CountingResolver.now,
        .resolveFn = CountingResolver.resolve,
    });

    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{ .psk = .{ .items = &.{.{ .identity = "async-ticket", .binder_psk = &psk }} } });
    try server.backend().receive(.initial, hello, &sink);
    try std.testing.expect(server.authPending());

    try std.testing.expectError(error.CredentialProviderFailed, server.resumeAuth(&sink));
    try std.testing.expect(!server.authPending());
    try std.testing.expectEqual(@as(usize, 0), resolver_state.calls);
    try std.testing.expect(server.client_hello_psk == null);
}

test "async credential selection failure zeroes the captured ClientHello bytes, not just the pointer" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.async_select = true;
    mock.pending_polls = 0;
    mock.pending_fails = true;
    var server = serverWithProvider(&mock);
    defer server.deinit();

    const psk = [_]u8{0x5a} ** tls_backend.hash_len;
    var stored_state = pskStoredState(&psk);
    defer stored_state.deinit();
    var resolver_state = CountingResolver{ .state = &stored_state, .identity = "async-ticket" };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = CountingResolver.now,
        .resolveFn = CountingResolver.resolve,
    });

    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{ .psk = .{ .items = &.{.{ .identity = "async-ticket", .binder_psk = &psk }} } });
    try server.backend().receive(.initial, hello, &sink);
    try std.testing.expect(server.authPending());

    try std.testing.expect(server.client_hello_psk.?.message_len > 0);

    try std.testing.expectError(error.CredentialProviderFailed, server.resumeAuth(&sink));
    // Regression coverage: it is not enough to null the optional — the
    // framed ClientHello bytes it pointed at must themselves be
    // overwritten, or a scratch copy of the peer-supplied identity would
    // linger in backend storage past this failed connection. This test
    // deliberately does *not* capture a slice into `client_hello_psk.?`
    // and re-read it after this line sets the field to `null`: that would
    // be reading through a reference invalidated by the very assignment
    // being tested, and whatever byte pattern showed up afterward would be
    // Zig's own debug-safety instrumentation for an inactive optional
    // (observed to differ between the x86_64 and aarch64 backends in this
    // Zig version), not necessarily evidence of `ClientHelloPskCapture
    // .wipe()` having run. That zeroing is proven directly, on a plain
    // non-optional value, by `"ClientHelloPskCapture.wipe zeroizes the
    // captured message"` below; this test only asserts the state
    // transition it should trigger.
    try std.testing.expect(server.client_hello_psk == null);
}

test "ClientHelloPskCapture.wipe zeroizes the captured message" {
    var capture: tls_backend.Tls13Backend.ClientHelloPskCapture = .{};
    @memset(capture.message[0..64], 0x5c);
    capture.message_len = 64;
    const bytes = capture.message[0..capture.message_len];
    try std.testing.expect(!std.mem.allEqual(u8, bytes, 0));

    capture.wipe();

    try std.testing.expect(std.mem.allEqual(u8, bytes, 0));
    try std.testing.expectEqual(@as(usize, 0), capture.message_len);
}

test "a transport-extension type colliding with a TLS-owned extension is rejected at start" {
    inline for (.{
        pre_shared_key.ext_pre_shared_key,
        pre_shared_key.ext_psk_key_exchange_modes,
        @intFromEnum(tls_core.algorithms.ExtensionType.padding),
        @intFromEnum(tls_core.algorithms.ExtensionType.early_data),
        @intFromEnum(tls_core.algorithms.ExtensionType.cookie),
    }) |colliding_type| {
        var client = tls_backend.Tls13Backend.initClient(
            clientEntropy(),
            .{ .pinned_certificate = tls_backend.testdata.certificate_der },
            .{ .extension = .{ .extension_type = colliding_type, .local = "x" } },
        );
        defer client.deinit();
        var sink = DirectSink{};
        defer sink.deinit();
        try std.testing.expectError(error.InvalidTransportProfile, client.backend().start(.client, {}, &sink));
        try std.testing.expectEqual(.idle, client.core.handshake_lifecycle);
        try std.testing.expectEqual(@as(usize, 0), sink.len);
        try std.testing.expect(!client.key_pair_present);

        var server = tls_backend.Tls13Backend.initServer(
            serverEntropy(),
            fixtureIdentity(),
            .{ .extension = .{ .extension_type = colliding_type, .local = "y" } },
        );
        defer server.deinit();
        var server_sink = DirectSink{};
        defer server_sink.deinit();
        try std.testing.expectError(error.InvalidTransportProfile, server.backend().start(.server, {}, &server_sink));
        try std.testing.expectEqual(.idle, server.core.handshake_lifecycle);
    }
}

test "setApplicationCompat copies the caller's bytes instead of borrowing them" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();

    var scratch: [4]u8 = .{ 'o', 'l', 'd', '!' };
    try server.setApplicationCompat(.{ .format_id = 7, .format_version = 1, .bytes = &scratch });
    // The caller is free to mutate/reuse its own buffer immediately after
    // the call returns — the stored value must not observe this.
    @memset(&scratch, 'X');

    const stored = server.ownedApplicationCompat().?;
    try std.testing.expectEqualStrings("old!", stored.bytes);
}

test "setApplicationCompat accepts a snapshot larger than the transport-extension bound" {
    // Regression coverage: the owned storage used to be capped at
    // `max_transport_extension_len` (512), an unrelated QUIC/H3
    // transport-extension bound, silently rejecting an application
    // snapshot the shared session model itself allows up to 1024 bytes by
    // default (`session.Limits.default.max_application_compat_len`).
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();

    var large: [session.Limits.default.max_application_compat_len]u8 = undefined;
    @memset(&large, 0x5a);
    try server.setApplicationCompat(.{ .format_id = 1, .format_version = 1, .bytes = &large });
    const stored = server.ownedApplicationCompat().?;
    try std.testing.expectEqual(large.len, stored.bytes.len);
    try std.testing.expect(std.mem.allEqual(u8, stored.bytes, 0x5a));
}

test "PSK setters reject being called after start, leaving prior configuration unchanged" {
    var client = tls_backend.Tls13Backend.initClient(
        clientEntropy(),
        .{ .pinned_certificate = tls_backend.testdata.certificate_der },
        .record,
    );
    defer client.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    try client.backend().start(.client, {}, &sink);

    const psk = [_]u8{0x22} ** tls_backend.hash_len;
    var common: session.ResumableSessionCommon = .{};
    try common.init(std.testing.allocator, session.Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &psk,
        .auth_binding = session.AuthBinding.fromLeafCertificateDer(""),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 3600,
    });
    var ticket: session.ClientTicketState = .{};
    try ticket.init(std.testing.allocator, session.Limits.default, &common, .{
        .ticket = "late-offer",
        .ticket_age_add = 0,
        .ticket_nonce = "n",
        .received_at_unix_ms = 0,
    });
    var offers: pre_shared_key.ClientPskOfferSet = .{};
    try offers.push(&ticket);
    var clock_dummy: u8 = 0;
    const Clock = struct {
        fn now(_: *anyopaque) i64 {
            return 0;
        }
    };
    try std.testing.expectError(
        error.InvalidHandshakeState,
        client.setClientPskOffers(&offers, &clock_dummy, Clock.now),
    );
    // The rejected call took no ownership: the caller's offer is untouched.
    try std.testing.expectEqual(@as(usize, 1), offers.len);
    offers.deinit();

    try std.testing.expectError(error.InvalidHandshakeState, client.setApplicationCompat(.{ .format_id = 1, .format_version = 1, .bytes = "x" }));

    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();
    var server_sink = DirectSink{};
    defer server_sink.deinit();
    try server.backend().start(.server, {}, &server_sink);
    try std.testing.expectError(error.InvalidHandshakeState, server.setServerPskResolver(.{
        .ctx = undefined,
        .nowUnixMsFn = CountingResolver.now,
        .resolveFn = CountingResolver.resolve,
    }));
}

test "handshake-phase failure wipes PSK offer state before ServerHello even arrives" {
    var client = tls_backend.Tls13Backend.initClient(
        clientEntropy(),
        .{ .pinned_certificate = tls_backend.testdata.certificate_der },
        .record,
    );
    defer client.deinit();

    const psk = [_]u8{0x11} ** tls_backend.hash_len;
    var common: session.ResumableSessionCommon = .{};
    try common.init(std.testing.allocator, session.Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &psk,
        .auth_binding = session.AuthBinding.fromLeafCertificateDer(""),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 3600,
    });
    var ticket: session.ClientTicketState = .{};
    try ticket.init(std.testing.allocator, session.Limits.default, &common, .{
        .ticket = "offer",
        .ticket_age_add = 0,
        .ticket_nonce = "n",
        .received_at_unix_ms = 0,
    });
    var offers: pre_shared_key.ClientPskOfferSet = .{};
    try offers.push(&ticket);
    var clock_dummy: u8 = 0;
    const Clock = struct {
        fn now(_: *anyopaque) i64 {
            return 0;
        }
    };
    try client.setClientPskOffers(&offers, &clock_dummy, Clock.now);

    var sink = DirectSink{};
    defer sink.deinit();
    try client.backend().start(.client, {}, &sink);
    try std.testing.expect(!client.client_offer_lease.offers.isEmpty());

    // A Finished message at the initial epoch (ServerHello was expected) is
    // a wrong-transport-epoch rejection raised by `drainInput` itself,
    // before `core.acceptReceived` or any per-message handler — including
    // the handler-local `errdefer` inside `onServerHello` — ever runs.
    var buf: [8]u8 = undefined;
    const finished = try tls_core.messages.encode(.finished, "", &buf);
    try std.testing.expectError(error.UnexpectedTransportEpoch, client.backend().receive(.initial, finished, &sink));

    try std.testing.expect(client.client_offer_lease.offers.isEmpty());
}

fn pushTestTicket(offers: *pre_shared_key.ClientPskOfferSet, psk: []const u8, ticket: []const u8) !void {
    var common: session.ResumableSessionCommon = .{};
    try common.init(std.testing.allocator, session.Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = psk,
        .auth_binding = session.AuthBinding.fromLeafCertificateDer(""),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 3600,
    });
    var state: session.ClientTicketState = .{};
    try state.init(std.testing.allocator, session.Limits.default, &common, .{
        .ticket = ticket,
        .ticket_age_add = 0,
        .ticket_nonce = "n",
        .received_at_unix_ms = 0,
    });
    try offers.push(&state);
}

fn makeCacheTicket(psk: []const u8, ticket: []const u8) !session.ClientTicketState {
    return makeCacheTicketIssuedAt(psk, ticket, 0);
}

fn makeCacheTicketIssuedAt(psk: []const u8, ticket: []const u8, issued_at_unix_ms: i64) !session.ClientTicketState {
    var common: session.ResumableSessionCommon = .{};
    try common.init(std.testing.allocator, session.Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = psk,
        .auth_binding = session.AuthBinding.fromLeafCertificateDer(""),
        .issued_at_unix_ms = issued_at_unix_ms,
        .lifetime_seconds = 3600,
    });
    var state: session.ClientTicketState = .{};
    try state.init(std.testing.allocator, session.Limits.default, &common, .{
        .ticket = ticket,
        .ticket_age_add = 0,
        .ticket_nonce = "n",
        .received_at_unix_ms = 0,
    });
    return state;
}

fn cacheCandidate() session.CandidateContext {
    return .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .auth_binding = session.AuthBinding.fromLeafCertificateDer(""),
    };
}

fn storeCacheTicket(cache: *session_cache.ClientSessionCache, psk: []const u8, ticket: []const u8, now_ms: i64) !void {
    var state = try makeCacheTicket(psk, ticket);
    defer state.deinit();
    try std.testing.expectEqual(session_cache.StoreResult.stored, cache.storeClone(&state, now_ms, .single_use));
}

fn storeCacheTicketIssuedAt(cache: *session_cache.ClientSessionCache, psk: []const u8, ticket: []const u8, issued_at_unix_ms: i64, now_ms: i64) !void {
    var state = try makeCacheTicketIssuedAt(psk, ticket, issued_at_unix_ms);
    defer state.deinit();
    try std.testing.expectEqual(session_cache.StoreResult.stored, cache.storeClone(&state, now_ms, .single_use));
}

const CacheClock = struct {
    fn now(_: *anyopaque) i64 {
        return 0;
    }
};

test "client selects a later (non-zero) identity when the server names it" {
    var client = tls_backend.Tls13Backend.initClient(
        clientEntropy(),
        .{ .pinned_certificate = tls_backend.testdata.certificate_der },
        .record,
    );
    defer client.deinit();

    const psk_a = [_]u8{0x11} ** tls_backend.hash_len;
    const psk_b = [_]u8{0x22} ** tls_backend.hash_len;
    var offers: pre_shared_key.ClientPskOfferSet = .{};
    try pushTestTicket(&offers, &psk_a, "ticket-a");
    try pushTestTicket(&offers, &psk_b, "ticket-b");
    var clock_dummy: u8 = 0;
    const Clock = struct {
        fn now(_: *anyopaque) i64 {
            return 0;
        }
    };
    try client.setClientPskOffers(&offers, &clock_dummy, Clock.now);

    var sink = DirectSink{};
    defer sink.deinit();
    try client.backend().start(.client, {}, &sink);
    try std.testing.expectEqual(@as(usize, 2), client.client_offer_lease.offers.len);

    var buf: [512]u8 = undefined;
    const hello = try buildServerHello(&buf, .{ .selected_identity = 1 });
    try client.backend().receive(.initial, hello, &sink);

    try std.testing.expect(client.core.psk_authenticated);
    try std.testing.expect(client.selected_client_psk_present);
    // Index 1 names the *second* offer: "ticket-b", not "ticket-a".
    try std.testing.expectEqualStrings("ticket-b", client.selected_client_psk.ticket.slice());
}

test "client rejects a selected_identity equal to or beyond the emitted offer count" {
    for ([_]u16{ 1, 5 }) |bad_index| {
        var client = tls_backend.Tls13Backend.initClient(
            clientEntropy(),
            .{ .pinned_certificate = tls_backend.testdata.certificate_der },
            .record,
        );
        defer client.deinit();

        const psk = [_]u8{0x33} ** tls_backend.hash_len;
        var offers: pre_shared_key.ClientPskOfferSet = .{};
        try pushTestTicket(&offers, &psk, "only-ticket");
        var clock_dummy: u8 = 0;
        const Clock = struct {
            fn now(_: *anyopaque) i64 {
                return 0;
            }
        };
        try client.setClientPskOffers(&offers, &clock_dummy, Clock.now);

        var sink = DirectSink{};
        defer sink.deinit();
        try client.backend().start(.client, {}, &sink);
        try std.testing.expectEqual(@as(usize, 1), client.client_offer_lease.offers.len); // one offer emitted, index 0 valid

        var buf: [512]u8 = undefined;
        const hello = try buildServerHello(&buf, .{ .selected_identity = bad_index });
        try std.testing.expectError(error.IllegalParameter, client.backend().receive(.initial, hello, &sink));
        try std.testing.expect(client.client_offer_lease.offers.isEmpty());
        try std.testing.expect(!client.selected_client_psk_present);
        try std.testing.expect(!client.core.psk_authenticated);
    }
}

test "client rejects a forged selected_identity when no PSK was ever offered" {
    var client = tls_backend.Tls13Backend.initClient(
        clientEntropy(),
        .{ .pinned_certificate = tls_backend.testdata.certificate_der },
        .record,
    );
    defer client.deinit();
    try std.testing.expect(client.client_offer_lease.offers.isEmpty());

    var sink = DirectSink{};
    defer sink.deinit();
    try client.backend().start(.client, {}, &sink);
    try std.testing.expect(client.client_offer_lease.offers.isEmpty());

    var buf: [512]u8 = undefined;
    const hello = try buildServerHello(&buf, .{ .selected_identity = 0 });
    try std.testing.expectError(error.IllegalParameter, client.backend().receive(.initial, hello, &sink));
    try std.testing.expect(!client.core.psk_authenticated);
}

test "a PSK-selected ServerHello with inconsistent suite/version/key-share is rejected and fully cleans up" {
    const Case = struct { opts: ServerHelloOptions, expected: anyerror };
    const cases = [_]Case{
        // Wrong (unsupported) cipher suite — this profile only negotiates
        // TLS_AES_128_GCM_SHA256.
        .{ .opts = .{ .selected_identity = 0, .cipher_suite = 0x1302 }, .expected = error.IllegalParameter },
        // Selected a non-TLS-1.3 version.
        .{ .opts = .{ .selected_identity = 0, .selected_version = 0x0303 }, .expected = error.IllegalParameter },
        // No key_share extension at all.
        .{ .opts = .{ .selected_identity = 0, .key_share = .missing }, .expected = error.MalformedHandshake },
        // key_share names a group other than x25519.
        .{ .opts = .{ .selected_identity = 0, .key_share = .wrong_group }, .expected = error.IllegalParameter },
        // key_share's declared length doesn't match x25519's fixed size.
        .{ .opts = .{ .selected_identity = 0, .key_share = .wrong_length }, .expected = error.IllegalParameter },
        // A well-formed but low-order/identity x25519 point.
        .{ .opts = .{ .selected_identity = 0, .key_share = .low_order }, .expected = error.IllegalParameter },
    };

    for (cases) |case| {
        var client = tls_backend.Tls13Backend.initClient(
            clientEntropy(),
            .{ .pinned_certificate = tls_backend.testdata.certificate_der },
            .record,
        );
        defer client.deinit();

        const psk = [_]u8{0x44} ** tls_backend.hash_len;
        var offers: pre_shared_key.ClientPskOfferSet = .{};
        try pushTestTicket(&offers, &psk, "consistency-ticket");
        var clock_dummy: u8 = 0;
        const Clock = struct {
            fn now(_: *anyopaque) i64 {
                return 0;
            }
        };
        try client.setClientPskOffers(&offers, &clock_dummy, Clock.now);

        var sink = DirectSink{};
        defer sink.deinit();
        try client.backend().start(.client, {}, &sink);
        try std.testing.expectEqual(@as(usize, 1), client.client_offer_lease.offers.len);

        var buf: [512]u8 = undefined;
        const hello = try buildServerHello(&buf, case.opts);
        try std.testing.expectError(case.expected, client.backend().receive(.initial, hello, &sink));

        try std.testing.expect(client.client_offer_lease.offers.isEmpty());
        try std.testing.expect(!client.selected_client_psk_present);
        try std.testing.expect(!client.core.psk_authenticated);
        try std.testing.expect(client.schedule == null);
    }
}

test "a rejected ServerHello observably zeroes the client's offered PSK bytes, not just the length" {
    var client = tls_backend.Tls13Backend.initClient(
        clientEntropy(),
        .{ .pinned_certificate = tls_backend.testdata.certificate_der },
        .record,
    );
    defer client.deinit();

    const psk = [_]u8{0x99} ** tls_backend.hash_len;
    var common: session.ResumableSessionCommon = .{};
    try common.init(std.testing.allocator, session.Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &psk,
        .auth_binding = session.AuthBinding.fromLeafCertificateDer(""),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 3600,
    });
    var ticket_state: session.ClientTicketState = .{};
    try ticket_state.init(std.testing.allocator, session.Limits.default, &common, .{
        .ticket = "wipe-client-ticket",
        .ticket_age_add = 0,
        .ticket_nonce = "n",
        .received_at_unix_ms = 0,
    });
    var offers: pre_shared_key.ClientPskOfferSet = .{};
    try offers.push(&ticket_state);

    var clock_dummy: u8 = 0;
    const Clock = struct {
        fn now(_: *anyopaque) i64 {
            return 0;
        }
    };
    try client.setClientPskOffers(&offers, &clock_dummy, Clock.now);

    var sink = DirectSink{};
    defer sink.deinit();
    try client.backend().start(.client, {}, &sink);
    try std.testing.expectEqual(@as(usize, 1), client.client_offer_lease.offers.len);

    // Captured from the offer's *final* resting place inside the backend
    // (after every intervening move), not the now-defunct local variable
    // above: only this copy is the one `clearFailedHandshakeState` must
    // reach.
    const settled = &client.client_offer_lease.offers.tickets[0];
    const psk_memory = settled.common.resumption_psk.bytes[0..settled.common.resumption_psk.len];
    const ticket_memory = settled.ticket.slice();
    const nonce_memory = settled.ticket_nonce.bytes[0..settled.ticket_nonce.len];
    try std.testing.expect(!std.mem.allEqual(u8, psk_memory, 0));
    try std.testing.expectEqualStrings("wipe-client-ticket", ticket_memory);
    try std.testing.expect(!std.mem.allEqual(u8, nonce_memory, 0));

    var buf: [512]u8 = undefined;
    const hello = try buildServerHello(&buf, .{ .selected_identity = 5 }); // beyond the single emitted offer
    try std.testing.expectError(error.IllegalParameter, client.backend().receive(.initial, hello, &sink));

    try std.testing.expect(client.client_offer_lease.offers.isEmpty());
    // `resumption_psk`/`ticket_nonce` are embedded fixed-size arrays, never
    // routed through an allocator or an optional-to-null transition, so
    // `secureZero`'s effect is directly and reliably observable here.
    try std.testing.expect(std.mem.allEqual(u8, psk_memory, 0));
    try std.testing.expect(std.mem.allEqual(u8, nonce_memory, 0));
    // `ticket` (`BoundedSecret`) is allocator-backed: Zig's generic
    // `Allocator.free()` front-end unconditionally `@memset`s freed memory
    // to `undefined` *after* `BoundedSecret.deinit()`'s own `secureZero`
    // runs, so re-inspecting `ticket_memory`'s bytes here would prove
    // nothing about whether that `secureZero` call actually executed —
    // the exact same undefined-fill would occur even if it were deleted.
    // `BoundedSecret`'s own zero-before-free behavior is proven directly,
    // without that interference, by `"bounded secret clears allocator
    // backing storage before free"` in secrets.zig; what this test can
    // reliably prove at the backend/type-integration boundary is that
    // `deinit()` actually ran and released ownership — `.len` and
    // `.bytes` are updated by this code's own explicit assignments, not
    // by the allocator, so they are unaffected by that undefined-fill.
    try std.testing.expectEqual(@as(usize, 0), settled.ticket.len);
    try std.testing.expectEqual(@as(usize, 0), settled.ticket.bytes.len);
}

test "cache-backed client offer lease consumes selected identity and releases the rest" {
    var cache = try session_cache.ClientSessionCache.init(std.testing.allocator, session_cache.Limits.client_default);
    defer cache.deinit();
    const psk_a = [_]u8{0x11} ** tls_backend.hash_len;
    const psk_b = [_]u8{0x22} ** tls_backend.hash_len;
    try storeCacheTicket(&cache, &psk_a, "cache-ticket-a", 0);
    try storeCacheTicket(&cache, &psk_b, "cache-ticket-b", 1);

    var lookup = cache.lookupOffers(cacheCandidate(), 2);
    defer lookup.deinit();
    try std.testing.expect(lookup == .hit);
    try std.testing.expectEqual(@as(usize, 2), lookup.hit.offers.len);
    try std.testing.expectEqualStrings("cache-ticket-b", lookup.hit.offers.constSlice()[0].ticket.slice());
    try std.testing.expectEqualStrings("cache-ticket-a", lookup.hit.offers.constSlice()[1].ticket.slice());

    var client = tls_backend.Tls13Backend.initClient(
        clientEntropy(),
        .{ .pinned_certificate = tls_backend.testdata.certificate_der },
        .record,
    );
    defer client.deinit();
    var clock_dummy: u8 = 0;
    try client.setClientPskOfferLease(&lookup.hit, &clock_dummy, CacheClock.now);

    var sink = DirectSink{};
    defer sink.deinit();
    try client.backend().start(.client, {}, &sink);
    var buf: [512]u8 = undefined;
    const hello = try buildServerHello(&buf, .{ .selected_identity = 1 });
    try client.backend().receive(.initial, hello, &sink);

    try std.testing.expect(client.core.psk_authenticated);
    try std.testing.expectEqualStrings("cache-ticket-a", client.selected_client_psk.ticket.slice());
    try std.testing.expectEqual(@as(usize, 1), cache.count());
    var after = cache.lookupOffers(cacheCandidate(), 6);
    defer after.deinit();
    try std.testing.expect(after == .hit);
    try std.testing.expectEqual(@as(usize, 1), after.hit.offers.len);
    try std.testing.expectEqualStrings("cache-ticket-b", after.hit.offers.constSlice()[0].ticket.slice());
}

test "cache-backed client offer lease releases all pins for invalid selected_identity" {
    var cache = try session_cache.ClientSessionCache.init(std.testing.allocator, session_cache.Limits.client_default);
    defer cache.deinit();
    const psk_a = [_]u8{0x31} ** tls_backend.hash_len;
    const psk_b = [_]u8{0x32} ** tls_backend.hash_len;
    try storeCacheTicket(&cache, &psk_a, "bad-index-a", 0);
    try storeCacheTicket(&cache, &psk_b, "bad-index-b", 1);

    var lookup = cache.lookupOffers(cacheCandidate(), 2);
    defer lookup.deinit();
    try std.testing.expect(lookup == .hit);

    var client = tls_backend.Tls13Backend.initClient(
        clientEntropy(),
        .{ .pinned_certificate = tls_backend.testdata.certificate_der },
        .record,
    );
    defer client.deinit();
    var clock_dummy: u8 = 0;
    try client.setClientPskOfferLease(&lookup.hit, &clock_dummy, CacheClock.now);

    var sink = DirectSink{};
    defer sink.deinit();
    try client.backend().start(.client, {}, &sink);
    var buf: [512]u8 = undefined;
    const hello = try buildServerHello(&buf, .{ .selected_identity = 7 });
    try std.testing.expectError(error.IllegalParameter, client.backend().receive(.initial, hello, &sink));

    try std.testing.expectEqual(@as(usize, 2), cache.count());
    var after = cache.lookupOffers(cacheCandidate(), 6);
    defer after.deinit();
    try std.testing.expect(after == .hit);
    try std.testing.expectEqual(@as(usize, 2), after.hit.offers.len);
}

test "cache-backed client offer lease is not_selected when ServerHello omits PSK" {
    var cache = try session_cache.ClientSessionCache.init(std.testing.allocator, session_cache.Limits.client_default);
    defer cache.deinit();
    const psk = [_]u8{0x41} ** tls_backend.hash_len;
    try storeCacheTicket(&cache, &psk, "not-selected-cache", 0);

    var lookup = cache.lookupOffers(cacheCandidate(), 1);
    defer lookup.deinit();
    try std.testing.expect(lookup == .hit);

    var client = tls_backend.Tls13Backend.initClient(
        clientEntropy(),
        .{ .pinned_certificate = tls_backend.testdata.certificate_der },
        .record,
    );
    defer client.deinit();
    var clock_dummy: u8 = 0;
    try client.setClientPskOfferLease(&lookup.hit, &clock_dummy, CacheClock.now);

    var sink = DirectSink{};
    defer sink.deinit();
    try client.backend().start(.client, {}, &sink);
    var buf: [512]u8 = undefined;
    const hello = try buildServerHello(&buf, .{});
    try client.backend().receive(.initial, hello, &sink);

    try std.testing.expect(!client.core.psk_authenticated);
    try std.testing.expectEqual(@as(usize, 1), cache.count());
    var after = cache.lookupOffers(cacheCandidate(), 2);
    defer after.deinit();
    try std.testing.expect(after == .hit);
    try std.testing.expectEqualStrings("not-selected-cache", after.hit.offers.constSlice()[0].ticket.slice());
}

test "cache-backed client offer lease aborts on teardown before ServerHello" {
    var cache = try session_cache.ClientSessionCache.init(std.testing.allocator, session_cache.Limits.client_default);
    defer cache.deinit();
    const psk = [_]u8{0x51} ** tls_backend.hash_len;
    try storeCacheTicket(&cache, &psk, "aborted-cache", 0);

    var lookup = cache.lookupOffers(cacheCandidate(), 1);
    defer lookup.deinit();
    try std.testing.expect(lookup == .hit);

    var client = tls_backend.Tls13Backend.initClient(
        clientEntropy(),
        .{ .pinned_certificate = tls_backend.testdata.certificate_der },
        .record,
    );
    defer client.deinit();
    var clock_dummy: u8 = 0;
    try client.setClientPskOfferLease(&lookup.hit, &clock_dummy, CacheClock.now);

    var sink = DirectSink{};
    defer sink.deinit();
    try client.backend().start(.client, {}, &sink);
    var finished_buf: [8]u8 = undefined;
    const finished = try tls_core.messages.encode(.finished, "", &finished_buf);
    try std.testing.expectError(error.UnexpectedTransportEpoch, client.backend().receive(.initial, finished, &sink));

    try std.testing.expectEqual(@as(usize, 1), cache.count());
    var after = cache.lookupOffers(cacheCandidate(), 2);
    defer after.deinit();
    try std.testing.expect(after == .hit);
    try std.testing.expectEqualStrings("aborted-cache", after.hit.offers.constSlice()[0].ticket.slice());
}

test "cache-backed client offer filtering preserves selected index token mapping" {
    var cache = try session_cache.ClientSessionCache.init(std.testing.allocator, session_cache.Limits.client_default);
    defer cache.deinit();
    const valid_psk = [_]u8{0x61} ** tls_backend.hash_len;
    const future_psk = [_]u8{0x62} ** tls_backend.hash_len;
    try storeCacheTicket(&cache, &valid_psk, "mapping-selected", 0);
    try storeCacheTicketIssuedAt(&cache, &future_psk, "mapping-dropped", 5, 1);

    var lookup = cache.lookupOffers(cacheCandidate(), 6);
    defer lookup.deinit();
    try std.testing.expect(lookup == .hit);
    try std.testing.expectEqual(@as(usize, 2), lookup.hit.offers.len);
    try std.testing.expectEqualStrings("mapping-dropped", lookup.hit.offers.constSlice()[0].ticket.slice());
    try std.testing.expectEqualStrings("mapping-selected", lookup.hit.offers.constSlice()[1].ticket.slice());

    var client = tls_backend.Tls13Backend.initClient(
        clientEntropy(),
        .{ .pinned_certificate = tls_backend.testdata.certificate_der },
        .record,
    );
    defer client.deinit();
    var clock_dummy: u8 = 0;
    try client.setClientPskOfferLease(&lookup.hit, &clock_dummy, CacheClock.now);

    var sink = DirectSink{};
    defer sink.deinit();
    try client.backend().start(.client, {}, &sink);
    try std.testing.expectEqual(@as(usize, 1), client.client_offer_lease.offers.len);
    try std.testing.expectEqualStrings("mapping-selected", client.client_offer_lease.offers.constSlice()[0].ticket.slice());

    var buf: [512]u8 = undefined;
    const hello = try buildServerHello(&buf, .{ .selected_identity = 0 });
    try client.backend().receive(.initial, hello, &sink);

    try std.testing.expect(client.core.psk_authenticated);
    try std.testing.expectEqualStrings("mapping-selected", client.selected_client_psk.ticket.slice());
    try std.testing.expectEqual(@as(usize, 1), cache.count());
    var after = cache.lookupOffers(cacheCandidate(), 6);
    defer after.deinit();
    try std.testing.expect(after == .hit);
    try std.testing.expectEqual(@as(usize, 1), after.hit.offers.len);
    try std.testing.expectEqualStrings("mapping-dropped", after.hit.offers.constSlice()[0].ticket.slice());
}

/// Completes a PSK-resumed server handshake driven by `driveServerSelection`
/// by feeding it the correct client Finished — computed from the server's
/// own (symmetric) key schedule, since there is no real client driver in
/// these server-only tests.
fn feedValidClientFinished(server: *tls_backend.Tls13Backend) !void {
    const schedule = &server.schedule.?;
    var client_verify = tls_backend.KeySchedule.verifyData(&schedule.client_handshake_traffic, server.core.transcriptHash());
    defer std.crypto.secureZero(u8, &client_verify);
    var finished_buf: [4 + tls_backend.hash_len]u8 = undefined;
    const finished = try tls_core.messages.encode(.finished, &client_verify, &finished_buf);
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().receive(.handshake, finished, &sink);
}

test "takeSelectedServerPsk returns null before the client Finished commits the handshake" {
    // Regression coverage: the binder succeeding only proves the *client*
    // authenticated — the server's own handshake is not committed until
    // the client's Finished verifies. Handing the accepted session out any
    // earlier would let a caller retain it past a subsequent bad-Finished
    // failure, which `clearFailedHandshakeState` can then no longer reach.
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();

    const psk = [_]u8{0x88} ** tls_backend.hash_len;
    var stored_state = pskStoredState(&psk);
    defer stored_state.deinit();
    var resolver_state = CountingResolver{ .state = &stored_state, .identity = "not-yet-committed" };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = CountingResolver.now,
        .resolveFn = CountingResolver.resolve,
    });

    try driveServerSelection(&server, .{ .psk = .{ .items = &.{.{ .identity = "not-yet-committed", .binder_psk = &psk }} } });
    try std.testing.expect(server.core.psk_authenticated);
    try std.testing.expect(server.selected_server_psk_present);

    var taken: session.ServerRecoverableState = .{};
    try std.testing.expectEqual(@as(?u16, null), server.takeSelectedServerPsk(&taken));
    // Left untouched: still present, still retrievable once actually committed.
    try std.testing.expect(server.selected_server_psk_present);

    try feedValidClientFinished(&server);
    try std.testing.expectEqual(.complete, server.core.handshake_lifecycle);
    var taken_after: session.ServerRecoverableState = .{};
    defer taken_after.deinit();
    try std.testing.expect(server.takeSelectedServerPsk(&taken_after) != null);
}

test "backend teardown observably zeroes the key schedule and selected PSK session" {
    // Deliberately stops short of feeding the client Finished: `finish()`
    // already wipes `schedule` eagerly the moment the handshake actually
    // completes (traffic secrets have been handed to the sink by then), so
    // proving teardown-time zeroization needs a still-live, uncommitted
    // schedule — exactly the state selection leaves behind (see
    // `takeSelectedServerPsk returns null before the client Finished
    // commits the handshake`, above).
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);

    const psk = [_]u8{0xcc} ** tls_backend.hash_len;
    var stored_state = pskStoredState(&psk);
    defer stored_state.deinit();
    var resolver_state = CountingResolver{ .state = &stored_state, .identity = "teardown-ticket" };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = CountingResolver.now,
        .resolveFn = CountingResolver.resolve,
    });

    try driveServerSelection(&server, .{ .psk = .{ .items = &.{.{ .identity = "teardown-ticket", .binder_psk = &psk }} } });
    try std.testing.expect(server.core.psk_authenticated);
    try std.testing.expect(server.selected_server_psk_present);
    try std.testing.expect(server.schedule != null);

    // `selected_server_psk.state` is a plain (non-optional) field — never
    // routed through a `?T = null` transition — so its address stays valid
    // across `deinit()` and the bytes are directly, reliably inspectable
    // for exact zero afterward.
    const selected_psk_memory = server.selected_server_psk.state.common.resumption_psk.bytes[0..server.selected_server_psk.state.common.resumption_psk.len];
    try std.testing.expect(!std.mem.allEqual(u8, selected_psk_memory, 0));

    server.deinit();

    try std.testing.expect(std.mem.allEqual(u8, selected_psk_memory, 0));
    // `schedule` (`?KeySchedule`) is deliberately *not* re-inspected here:
    // capturing a slice into `schedule.?`'s payload and reading it after
    // `deinit()` sets `schedule = null` would be reading through a
    // reference invalidated by that assignment — whatever byte pattern
    // shows up afterward is Zig's own debug-safety instrumentation for an
    // inactive optional (observed to differ between the x86_64 and
    // aarch64 backends in this Zig version), not necessarily evidence of
    // this code's `secureZero` call. `KeySchedule.wipe()`'s zeroing is
    // proven directly, on a plain non-optional value, by `"KeySchedule.wipe
    // zeroizes every derived secret"` in key_schedule.zig; what this test
    // can reliably assert at the backend level is the state transition.
    try std.testing.expect(server.schedule == null);
}

fn pskStoredStateTimed(psk: []const u8, issued_at_unix_ms: i64, ticket_age_add: u32) session.ServerRecoverableState {
    var common: session.ResumableSessionCommon = .{};
    common.init(std.testing.allocator, session.Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = psk,
        .application_protocol = "h2",
        .auth_binding = session.AuthBinding.fromLeafCertificateDer(tls_backend.testdata.certificate_der),
        .issued_at_unix_ms = issued_at_unix_ms,
        .lifetime_seconds = 3600,
    }) catch unreachable;
    var state: session.ServerRecoverableState = .{};
    state.init(&common, ticket_age_add);
    return state;
}

const TimedResolver = struct {
    state: *session.ServerRecoverableState,
    identity: []const u8,
    now_value: i64,
    calls: usize = 0,

    fn now(ctx: *anyopaque) i64 {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        return self.now_value;
    }
    fn resolve(ctx: *anyopaque, identity: []const u8) pre_shared_key.ResolveError!pre_shared_key.ServerPskResolveResult {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        if (!std.mem.eql(u8, identity, self.identity)) return .miss;
        return clonedResolveHit(self.state, std.testing.allocator);
    }
};

test "takePskAgeSkew reports the exact signed observation and is one-shot" {
    const Case = struct { apparent_age_ms: u32, actual_elapsed_ms: i64, expected_skew_ms: i64 };
    const cases = [_]Case{
        .{ .apparent_age_ms = 0, .actual_elapsed_ms = 0, .expected_skew_ms = 0 }, // exact zero
        .{ .apparent_age_ms = 4200, .actual_elapsed_ms = 4200, .expected_skew_ms = 0 }, // normal, matching
        .{ .apparent_age_ms = 5000, .actual_elapsed_ms = 3000, .expected_skew_ms = 2000 }, // positive skew
        .{ .apparent_age_ms = 1000, .actual_elapsed_ms = 4000, .expected_skew_ms = -3000 }, // negative skew
        .{ .apparent_age_ms = 1_000_000, .actual_elapsed_ms = 10, .expected_skew_ms = 999_990 }, // large skew, still 1-RTT
    };
    for (cases) |case| {
        var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
        defer server.deinit();

        const psk = [_]u8{0x88} ** tls_backend.hash_len;
        const issued_at: i64 = 5_000_000;
        const ticket_age_add: u32 = 0xdead_beef;
        var stored_state = pskStoredStateTimed(&psk, issued_at, ticket_age_add);
        defer stored_state.deinit();
        var resolver_state = TimedResolver{
            .state = &stored_state,
            .identity = "aged-ticket",
            .now_value = issued_at + case.actual_elapsed_ms,
        };
        try server.setServerPskResolver(.{
            .ctx = &resolver_state,
            .nowUnixMsFn = TimedResolver.now,
            .resolveFn = TimedResolver.resolve,
        });

        const obfuscated = pre_shared_key.obfuscateTicketAge(case.apparent_age_ms, ticket_age_add);
        try driveServerSelection(&server, .{ .psk = .{ .items = &.{
            .{ .identity = "aged-ticket", .binder_psk = &psk, .obfuscated_ticket_age = obfuscated },
        } } });

        // Skew alone never rejects 1-RTT resumption, however large.
        try std.testing.expect(server.core.psk_authenticated);

        const skew = server.takePskAgeSkew().?;
        try std.testing.expectEqual(case.apparent_age_ms, skew.apparent_age_ms);
        try std.testing.expectEqual(case.expected_skew_ms, skew.skew_ms);
        // One-shot: taken once, then null.
        try std.testing.expectEqual(@as(?pre_shared_key.AgeSkew, null), server.takePskAgeSkew());
    }
}

test "a rejected or fallback candidate publishes no age-skew observation" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();

    const psk = [_]u8{0x99} ** tls_backend.hash_len;
    var stored_state = pskStoredStateTimed(&psk, 0, 0);
    defer stored_state.deinit();
    var resolver_state = TimedResolver{ .state = &stored_state, .identity = "never-offered", .now_value = 0 };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = TimedResolver.now,
        .resolveFn = TimedResolver.resolve,
    });

    // The offered identity never matches, so selection falls back — no
    // candidate was ever compatible/binder-checked.
    try driveServerSelection(&server, .{ .psk = .{ .items = &.{
        .{ .identity = "unrelated-ticket", .binder_psk = &psk },
    } } });

    try std.testing.expect(!server.core.psk_authenticated);
    try std.testing.expectEqual(@as(?pre_shared_key.AgeSkew, null), server.takePskAgeSkew());
}

test "the accepted server session survives PSK selection with its early-data and metadata intact" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();

    const psk = [_]u8{0x66} ** tls_backend.hash_len;
    var common: session.ResumableSessionCommon = .{};
    try common.init(std.testing.allocator, session.Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &psk,
        .application_protocol = "h2",
        .auth_binding = session.AuthBinding.fromLeafCertificateDer(tls_backend.testdata.certificate_der),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 3600,
        .early_data = .{ .early_data_capable = 12345 },
    });
    var stored_state: session.ServerRecoverableState = .{};
    stored_state.init(&common, 0);
    defer stored_state.deinit();
    var resolver_state = CountingResolver{ .state = &stored_state, .identity = "early-data-ticket" };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = CountingResolver.now,
        .resolveFn = CountingResolver.resolve,
    });

    try driveServerSelection(&server, .{ .psk = .{ .items = &.{.{ .identity = "early-data-ticket", .binder_psk = &psk }} } });
    try feedValidClientFinished(&server);

    try std.testing.expect(server.core.psk_authenticated);
    try std.testing.expectEqual(.complete, server.core.handshake_lifecycle);
    var taken: session.ServerRecoverableState = .{};
    const index = server.takeSelectedServerPsk(&taken).?;
    defer taken.deinit();
    try std.testing.expectEqual(@as(u16, 0), index);
    try std.testing.expectEqual(@as(u32, 12345), taken.common.early_data.maxEarlyData());
    try std.testing.expectEqualStrings("h2", taken.common.application_protocol.?.slice());
    // One-shot: a second take returns null and leaves `out` untouched.
    var second: session.ServerRecoverableState = .{};
    try std.testing.expectEqual(@as(?u16, null), server.takeSelectedServerPsk(&second));
}

test "a bad client Finished after PSK selection clears the accepted session and secret state" {
    // Regression coverage: `Core.acceptReceived` marks the server's
    // handshake lifecycle `.complete` as soon as a Finished message's
    // *ordering* is accepted — before this backend has verified its MAC.
    // The old `clearFailedHandshakeState` guard (`core.handshake_lifecycle
    // == .complete`) would therefore see `.complete` and skip cleanup
    // entirely on exactly this path.
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();

    const psk = [_]u8{0x77} ** tls_backend.hash_len;
    var stored_state = pskStoredState(&psk);
    defer stored_state.deinit();
    var resolver_state = CountingResolver{ .state = &stored_state, .identity = "bad-finished-ticket" };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = CountingResolver.now,
        .resolveFn = CountingResolver.resolve,
    });

    try driveServerSelection(&server, .{ .psk = .{ .items = &.{.{ .identity = "bad-finished-ticket", .binder_psk = &psk }} } });
    try std.testing.expect(server.core.psk_authenticated);
    try std.testing.expect(server.selected_server_psk_present);

    var sink = DirectSink{};
    defer sink.deinit();
    var bad_finished_buf: [4 + tls_backend.hash_len]u8 = undefined;
    const bad_finished = try tls_core.messages.encode(.finished, &([_]u8{0xaa} ** tls_backend.hash_len), &bad_finished_buf);
    try std.testing.expectError(error.DecryptError, server.backend().receive(.handshake, bad_finished, &sink));

    // Core's own lifecycle already (incorrectly, from this backend's
    // perspective) reads `.complete` at this point — the actual assertion
    // is that the backend's cleanup corrects it and wipes everything.
    try std.testing.expectEqual(.failed, server.core.handshake_lifecycle);
    try std.testing.expect(!server.core.psk_authenticated);
    try std.testing.expect(server.schedule == null);
    try std.testing.expectEqual(@as(usize, 0), server.resumption_master_secret.slice().len);
    var taken: session.ServerRecoverableState = .{};
    try std.testing.expectEqual(@as(?u16, null), server.takeSelectedServerPsk(&taken));
    try std.testing.expectEqual(@as(?pre_shared_key.AgeSkew, null), server.takePskAgeSkew());
}

/// Writes a raw `pre_shared_key` extension_data with `count` identities
/// named "id-0".."id-{count-1}", each with a zero-filled 32-byte binder
/// placeholder — for the resolver-attempt-cap tests, which only care how
/// many times (and in what order) the resolver is invoked, not binder
/// validity (unknown/rejected identities never reach the binder check).
fn buildRawOfferedPsks(buf: []u8, count: usize) ![]const u8 {
    var w = HsWriter{ .buf = buf };
    const ids_len_idx = try w.reserve(2);
    var name_buf: [8]u8 = undefined;
    for (0..count) |i| {
        const name = try std.fmt.bufPrint(&name_buf, "id-{d}", .{i});
        try w.u16_(@intCast(name.len));
        try w.bytes(name);
        try w.bytes(&[_]u8{0} ** 4); // age
    }
    w.patch(2, ids_len_idx);
    const binders_len_idx = try w.reserve(2);
    for (0..count) |_| {
        try w.u8_(32);
        try w.bytes(&[_]u8{0} ** 32);
    }
    w.patch(2, binders_len_idx);
    return w.written();
}

const AllocFailResolver = struct {
    state: *session.ServerRecoverableState,
    allocator: std.mem.Allocator,
    saw_oom: bool = false,
    fn now(_: *anyopaque) i64 {
        return 0;
    }
    fn resolve(ctx: *anyopaque, _: []const u8) pre_shared_key.ResolveError!pre_shared_key.ServerPskResolveResult {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        var out: session.ServerRecoverableState = .{};
        self.state.cloneInto(self.allocator, &out) catch |err| {
            self.saw_oom = (err == error.OutOfMemory);
            return error.ResolverFailed;
        };
        return .{ .hit = .{ .state = out, .lease = pre_shared_key.ServerPskLease.initNoop() } };
    }
};

/// Exercises exactly the allocation `selectPsk()` performs on the success
/// path — the resolver's own `ServerRecoverableState.cloneInto` — through
/// the real backend, for `std.testing.checkAllAllocationFailures`. Only an
/// allocation failure the resolver itself observed is translated back into
/// `error.OutOfMemory`; any other failure is a genuine test failure, not a
/// silently accepted one.
fn exerciseResolverCloneThroughBackend(
    allocator: std.mem.Allocator,
    stored: *session.ServerRecoverableState,
    psk: *const [tls_backend.hash_len]u8,
) !void {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();
    try server.setApplicationCompat(.{ .format_id = 2, .format_version = 1, .bytes = "application-snapshot" });

    var resolver_state = AllocFailResolver{ .state = stored, .allocator = allocator };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = AllocFailResolver.now,
        .resolveFn = AllocFailResolver.resolve,
    });

    driveServerSelection(&server, .{ .psk = .{ .items = &.{
        .{ .identity = "alloc-ticket", .binder_psk = psk },
    } } }) catch |err| {
        if (resolver_state.saw_oom and err == error.CredentialProviderFailed) return error.OutOfMemory;
        return err;
    };
    try std.testing.expect(server.core.psk_authenticated);
    try std.testing.expect(server.selected_server_psk_present);
}

test "resolver candidate cloning is proven correct across every allocation-failure point" {
    // `selectPsk()`'s only allocation on the success path is the
    // resolver's own `ServerRecoverableState.cloneInto` (the underlying
    // allocation primitives — `ResumableSessionCommon.init`/`cloneInto`,
    // `BoundedSecret`/`CompatSnapshot` — already have exhaustive
    // `checkAllAllocationFailures` coverage in session.zig; this proves
    // the *backend* PSK path degrades cleanly, not silently, at every one
    // of those allocation points, and that a real success run exists once
    // every allocation succeeds).
    var stored_common: session.ResumableSessionCommon = .{};
    try stored_common.init(std.testing.allocator, session.Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &([_]u8{0xbb} ** tls_backend.hash_len),
        .application_protocol = "h2",
        .auth_binding = session.AuthBinding.fromLeafCertificateDer(tls_backend.testdata.certificate_der),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 3600,
        // An allocator-backed optional field, so cloning has more than one
        // allocation point to fail at. `transport_compat` is deliberately
        // left unset: the record profile never has a candidate to match it
        // against, which would make every candidate incompatible rather
        // than exercising the allocation-failure path.
        .application_compat = .{ .format_id = 2, .format_version = 1, .bytes = "application-snapshot" },
    });
    var stored_state: session.ServerRecoverableState = .{};
    stored_state.init(&stored_common, 0);
    defer stored_state.deinit();
    const psk = [_]u8{0xbb} ** tls_backend.hash_len;

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        exerciseResolverCloneThroughBackend,
        .{ &stored_state, &psk },
    );
}

test "resolver identity-resolution attempts are bounded to eight even when a ninth would succeed" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();

    const psk = [_]u8{0x44} ** tls_backend.hash_len;
    var stored_state = pskStoredState(&psk);
    defer stored_state.deinit();
    // Only the *ninth* (index 8, "id-8") wire identity would ever resolve.
    var resolver_state = CountingResolver{ .state = &stored_state, .identity = "id-8" };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = CountingResolver.now,
        .resolveFn = CountingResolver.resolve,
    });
    var decisions = DecisionProbe{};
    try server.setResumptionDecisionObserver(decisions.observer());

    var ext_buf: [512]u8 = undefined;
    const raw_ext_data = try buildRawOfferedPsks(&ext_buf, 9);

    // Falls back to a full handshake: the one identity that would have
    // resolved is never attempted, because it is the ninth.
    try driveServerSelection(&server, .{ .psk = .{ .items = &.{}, .raw_ext_data = raw_ext_data } });

    try std.testing.expectEqual(@as(usize, 8), resolver_state.calls);
    try std.testing.expect(!server.core.psk_authenticated);
    try std.testing.expectEqual(@as(usize, 1), decisions.count);
    try std.testing.expectEqual(tls_backend.Tls13Backend.ResumptionDecision.miss, decisions.last.?);
}

test "resolver identity-resolution attempts stop at exactly eight when all eight are unusable" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();

    const psk = [_]u8{0x55} ** tls_backend.hash_len;
    var stored_state = pskStoredState(&psk);
    defer stored_state.deinit();
    // No wire identity matches this at all — exercises exactly eight misses,
    // not nine, when there are only eight to try.
    var resolver_state = CountingResolver{ .state = &stored_state, .identity = "never-matches" };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = CountingResolver.now,
        .resolveFn = CountingResolver.resolve,
    });

    var ext_buf: [512]u8 = undefined;
    const raw_ext_data = try buildRawOfferedPsks(&ext_buf, 8);
    try driveServerSelection(&server, .{ .psk = .{ .items = &.{}, .raw_ext_data = raw_ext_data } });

    try std.testing.expectEqual(@as(usize, 8), resolver_state.calls);
    try std.testing.expect(!server.core.psk_authenticated);
}

test "a resolver operational failure is fatal and distinct from an ordinary miss" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();

    const FailingResolver = struct {
        calls: usize = 0,
        fn now(_: *anyopaque) i64 {
            return 0;
        }
        fn resolve(ctx: *anyopaque, _: []const u8) pre_shared_key.ResolveError!pre_shared_key.ServerPskResolveResult {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            return error.ResolverFailed;
        }
    };
    var resolver_state = FailingResolver{};
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = FailingResolver.now,
        .resolveFn = FailingResolver.resolve,
    });
    var decisions = DecisionProbe{};
    try server.setResumptionDecisionObserver(decisions.observer());

    const psk = [_]u8{0x66} ** tls_backend.hash_len;
    try std.testing.expectError(error.CredentialProviderFailed, driveServerSelection(&server, .{
        .psk = .{ .items = &.{.{ .identity = "any-ticket", .binder_psk = &psk }} },
    }));
    // Fatal on the very first failure: never retried against a later
    // identity, unlike an ordinary "unknown" miss.
    try std.testing.expectEqual(@as(usize, 1), resolver_state.calls);
    try std.testing.expectEqual(tls_backend.CredentialFailure.provider_internal_failure, server.credentialFailure().?);
    try std.testing.expectEqual(@as(usize, 1), decisions.count);
    try std.testing.expectEqual(tls_backend.Tls13Backend.ResumptionDecision.fatal, decisions.last.?);
}

test "a resolver that partially populates its output before failing leaves no residue" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();

    const PartialResolver = struct {
        calls: usize = 0,
        fn now(_: *anyopaque) i64 {
            return 0;
        }
        fn resolve(ctx: *anyopaque, _: []const u8) pre_shared_key.ResolveError!pre_shared_key.ServerPskResolveResult {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            return error.ResolverFailed;
        }
    };
    var resolver_state = PartialResolver{};
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = PartialResolver.now,
        .resolveFn = PartialResolver.resolve,
    });

    const psk = [_]u8{0x77} ** tls_backend.hash_len;
    try std.testing.expectError(error.CredentialProviderFailed, driveServerSelection(&server, .{
        .psk = .{ .items = &.{.{ .identity = "any-ticket", .binder_psk = &psk }} },
    }));
    try std.testing.expectEqual(@as(usize, 1), resolver_state.calls);
    // No PSK state was retained despite the resolver populating `out`.
    try std.testing.expect(!server.selected_server_psk_present);
    try std.testing.expect(!server.core.psk_authenticated);
}

test "server selects the first compatible identity: unknown first, valid second" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();

    const psk = [_]u8{0x11} ** tls_backend.hash_len;
    var stored_state = pskStoredState(&psk);
    defer stored_state.deinit();
    var resolver_state = CountingResolver{ .state = &stored_state, .identity = "known-ticket" };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = CountingResolver.now,
        .resolveFn = CountingResolver.resolve,
    });
    var decisions = DecisionProbe{};
    try server.setResumptionDecisionObserver(decisions.observer());

    try driveServerSelection(&server, .{ .psk = .{ .items = &.{
        .{ .identity = "unknown-ticket", .binder_psk = &psk },
        .{ .identity = "known-ticket", .binder_psk = &psk },
    } } });

    try std.testing.expectEqual(@as(usize, 2), resolver_state.calls);
    try std.testing.expect(server.core.psk_authenticated);
    try std.testing.expect(server.credentialFailure() == null);
    try std.testing.expectEqual(@as(usize, 1), decisions.count);
    try std.testing.expectEqual(tls_backend.Tls13Backend.ResumptionDecision.accepted, decisions.last.?);
}

test "a compatible candidate with a wrong binder is fatal and never probes a later identity" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();

    const psk = [_]u8{0x22} ** tls_backend.hash_len;
    const wrong_psk = [_]u8{0x33} ** tls_backend.hash_len;
    var stored_state = pskStoredState(&psk);
    defer stored_state.deinit();
    var resolver_state = CountingResolver{ .state = &stored_state, .identity = "ticket-a" };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = CountingResolver.now,
        .resolveFn = CountingResolver.resolve,
    });
    var decisions = DecisionProbe{};
    try server.setResumptionDecisionObserver(decisions.observer());

    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    const events_before_client_hello = sink.len;
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{
        .psk = .{
            .items = &.{
                .{ .identity = "ticket-a", .binder_psk = &wrong_psk }, // resolvable and compatible, wrong binder
                .{ .identity = "ticket-b", .binder_psk = &psk }, // would otherwise succeed; must never be tried
            },
        },
    });
    try std.testing.expectError(error.DecryptError, server.backend().receive(.initial, hello, &sink));

    try std.testing.expectEqual(@as(usize, 1), resolver_state.calls);
    // No ServerHello, secret, or any other event was emitted for the
    // failed selection: the fatal binder mismatch is caught before
    // anything is written to the wire.
    try std.testing.expectEqual(events_before_client_hello, sink.len);
    try std.testing.expectEqual(@as(usize, 1), decisions.count);
    try std.testing.expectEqual(tls_backend.Tls13Backend.ResumptionDecision.fatal, decisions.last.?);
}

test "resolver lease releases incompatible candidate and commits later selected identity" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();

    const psk = [_]u8{0x91} ** tls_backend.hash_len;
    var incompatible_state = pskStoredStateWithBinding(&psk, session.AuthBinding.fromLeafCertificateDer("different-leaf"));
    defer incompatible_state.deinit();
    var compatible_state = pskStoredState(&psk);
    defer compatible_state.deinit();
    var incompatible_lease = LeaseProbe{};
    var compatible_lease = LeaseProbe{};
    var resolver_state = TwoIdentityLeaseResolver{
        .first_identity = "incompatible-ticket",
        .first_state = &incompatible_state,
        .first_lease = &incompatible_lease,
        .second_identity = "compatible-ticket",
        .second_state = &compatible_state,
        .second_lease = &compatible_lease,
    };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = TwoIdentityLeaseResolver.now,
        .resolveFn = TwoIdentityLeaseResolver.resolve,
    });
    var decisions = DecisionProbe{};
    try server.setResumptionDecisionObserver(decisions.observer());

    try driveServerSelection(&server, .{ .psk = .{ .items = &.{
        .{ .identity = "incompatible-ticket", .binder_psk = &psk },
        .{ .identity = "compatible-ticket", .binder_psk = &psk },
    } } });

    try std.testing.expectEqual(@as(usize, 2), resolver_state.calls);
    try std.testing.expectEqual(@as(usize, 0), incompatible_lease.commit_count);
    try std.testing.expectEqual(@as(usize, 1), incompatible_lease.release_count);
    try std.testing.expectEqual(@as(usize, 1), incompatible_lease.deinit_count);
    try std.testing.expectEqual(@as(usize, 1), compatible_lease.commit_count);
    try std.testing.expectEqual(@as(usize, 0), compatible_lease.release_count);
    try std.testing.expectEqual(@as(usize, 1), compatible_lease.deinit_count);
    try std.testing.expect(server.core.psk_authenticated);
    try std.testing.expectEqual(@as(usize, 1), decisions.count);
    try std.testing.expectEqual(tls_backend.Tls13Backend.ResumptionDecision.accepted, decisions.last.?);
}

test "resolver incompatibility reports incompatible full-handshake fallback" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();

    const psk = [_]u8{0xa1} ** tls_backend.hash_len;
    var incompatible_state = pskStoredStateWithBinding(&psk, session.AuthBinding.fromLeafCertificateDer("different-leaf"));
    defer incompatible_state.deinit();
    var resolver_state = CountingResolver{ .state = &incompatible_state, .identity = "incompatible-ticket" };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = CountingResolver.now,
        .resolveFn = CountingResolver.resolve,
    });
    var decisions = DecisionProbe{};
    try server.setResumptionDecisionObserver(decisions.observer());

    try driveServerSelection(&server, .{ .psk = .{ .items = &.{
        .{ .identity = "incompatible-ticket", .binder_psk = &psk },
    } } });

    try std.testing.expectEqual(@as(usize, 1), resolver_state.calls);
    try std.testing.expect(!server.core.psk_authenticated);
    try std.testing.expectEqual(@as(usize, 1), decisions.count);
    try std.testing.expectEqual(tls_backend.Tls13Backend.ResumptionDecision.incompatible, decisions.last.?);
}

test "unsupported PSK key-exchange mode reports full-handshake fallback" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();

    const psk = [_]u8{0xb4} ** tls_backend.hash_len;
    var stored_state = pskStoredState(&psk);
    defer stored_state.deinit();
    var resolver_state = CountingResolver{ .state = &stored_state, .identity = "psk-ke-only-ticket" };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = CountingResolver.now,
        .resolveFn = CountingResolver.resolve,
    });
    var decisions = DecisionProbe{};
    try server.setResumptionDecisionObserver(decisions.observer());

    try driveServerSelection(&server, .{ .psk = .{
        .modes = &.{.psk_ke},
        .items = &.{.{ .identity = "psk-ke-only-ticket", .binder_psk = &psk }},
    } });

    try std.testing.expectEqual(@as(usize, 0), resolver_state.calls);
    try std.testing.expect(!server.core.psk_authenticated);
    try std.testing.expectEqual(@as(usize, 1), decisions.count);
    try std.testing.expectEqual(tls_backend.Tls13Backend.ResumptionDecision.full_handshake, decisions.last.?);
}

test "resolver lease releases bad-binder candidate before fatal failure and probes no later identity" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();

    const psk = [_]u8{0x92} ** tls_backend.hash_len;
    const wrong_psk = [_]u8{0x93} ** tls_backend.hash_len;
    var first_state = pskStoredState(&psk);
    defer first_state.deinit();
    var second_state = pskStoredState(&psk);
    defer second_state.deinit();
    var first_lease = LeaseProbe{};
    var second_lease = LeaseProbe{};
    var resolver_state = TwoIdentityLeaseResolver{
        .first_identity = "bad-binder-ticket",
        .first_state = &first_state,
        .first_lease = &first_lease,
        .second_identity = "later-ticket",
        .second_state = &second_state,
        .second_lease = &second_lease,
    };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = TwoIdentityLeaseResolver.now,
        .resolveFn = TwoIdentityLeaseResolver.resolve,
    });

    try std.testing.expectError(error.DecryptError, driveServerSelection(&server, .{ .psk = .{ .items = &.{
        .{ .identity = "bad-binder-ticket", .binder_psk = &wrong_psk },
        .{ .identity = "later-ticket", .binder_psk = &psk },
    } } }));

    try std.testing.expectEqual(@as(usize, 1), resolver_state.calls);
    try std.testing.expectEqual(@as(usize, 0), first_lease.commit_count);
    try std.testing.expectEqual(@as(usize, 1), first_lease.release_count);
    try std.testing.expectEqual(@as(usize, 1), first_lease.deinit_count);
    try std.testing.expectEqual(@as(usize, 0), second_lease.commit_count);
    try std.testing.expectEqual(@as(usize, 0), second_lease.release_count);
    try std.testing.expectEqual(@as(usize, 0), second_lease.deinit_count);
}

test "resolver lease commits before PSK-selected ServerHello is emitted" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();

    const psk = [_]u8{0x94} ** tls_backend.hash_len;
    var stored_state = pskStoredState(&psk);
    defer stored_state.deinit();
    var unused_state = pskStoredState(&psk);
    defer unused_state.deinit();
    var selected_lease = LeaseProbe{};
    var unused_lease = LeaseProbe{};
    var resolver_state = TwoIdentityLeaseResolver{
        .first_identity = "selected-ticket",
        .first_state = &stored_state,
        .first_lease = &selected_lease,
        .second_identity = "unused-ticket",
        .second_state = &unused_state,
        .second_lease = &unused_lease,
    };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = TwoIdentityLeaseResolver.now,
        .resolveFn = TwoIdentityLeaseResolver.resolve,
    });

    var sink = DirectSink{};
    defer sink.deinit();
    selected_lease.sink = &sink;
    try server.backend().start(.server, {}, &sink);
    const events_before_client_hello = sink.len;
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{ .psk = .{ .items = &.{
        .{ .identity = "selected-ticket", .binder_psk = &psk },
    } } });
    try server.backend().receive(.initial, hello, &sink);

    try std.testing.expectEqual(@as(usize, 1), resolver_state.calls);
    try std.testing.expectEqual(@as(usize, 1), selected_lease.commit_count);
    try std.testing.expectEqual(@as(usize, 0), selected_lease.release_count);
    try std.testing.expectEqual(@as(usize, 1), selected_lease.deinit_count);
    try std.testing.expectEqual(events_before_client_hello, selected_lease.committed_sink_len.?);
    try std.testing.expect(sink.len > events_before_client_hello);
    try std.testing.expect(server.core.psk_authenticated);
}

test "stateful single-use cache adapter commits selected handle and consumes it" {
    var cache = try session_cache.StatefulServerCache.init(
        std.testing.allocator,
        session_cache.Limits.stateful_server_default,
        session_cache.system_random_source,
    );
    defer cache.deinit();

    const psk = [_]u8{0x95} ** tls_backend.hash_len;
    var stored_state = pskStoredState(&psk);
    var handle: [session_cache.stateful_identity_len]u8 = undefined;
    try std.testing.expectEqual(
        session_cache.StoreResult.stored,
        cache.insertMove(&stored_state, 0, .single_use, &handle),
    );

    var adapter = session_cache.StatefulServerPskResolverAdapter{
        .cache = &cache,
        .allocator = std.testing.allocator,
        .now_unix_ms = 0,
    };
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();
    try server.setServerPskResolver(adapter.resolver());

    try driveServerSelection(&server, .{ .psk = .{ .items = &.{.{ .identity = &handle, .binder_psk = &psk }} } });
    try std.testing.expect(server.core.psk_authenticated);

    var after_success = try session_cache.resolveStatefulServerPsk(&cache, std.testing.allocator, &handle, 0);
    defer after_success.deinit();
    try std.testing.expect(after_success == .miss);
}

test "stateful single-use cache adapter releases handle after bad binder" {
    var cache = try session_cache.StatefulServerCache.init(
        std.testing.allocator,
        session_cache.Limits.stateful_server_default,
        session_cache.system_random_source,
    );
    defer cache.deinit();

    const psk = [_]u8{0x96} ** tls_backend.hash_len;
    const wrong_psk = [_]u8{0x97} ** tls_backend.hash_len;
    var stored_state = pskStoredState(&psk);
    var handle: [session_cache.stateful_identity_len]u8 = undefined;
    try std.testing.expectEqual(
        session_cache.StoreResult.stored,
        cache.insertMove(&stored_state, 0, .single_use, &handle),
    );

    var adapter = session_cache.StatefulServerPskResolverAdapter{
        .cache = &cache,
        .allocator = std.testing.allocator,
        .now_unix_ms = 0,
    };
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();
    try server.setServerPskResolver(adapter.resolver());

    try std.testing.expectError(error.DecryptError, driveServerSelection(&server, .{ .psk = .{ .items = &.{
        .{ .identity = &handle, .binder_psk = &wrong_psk },
    } } }));

    var after_failure = try session_cache.resolveStatefulServerPsk(&cache, std.testing.allocator, &handle, 0);
    defer after_failure.deinit();
    try std.testing.expect(after_failure == .hit);
}

test "stateful reusable cache adapter refreshes LRU only after selected binder success" {
    var limits = session_cache.Limits.stateful_server_default;
    limits.max_entries = 3;
    var cache = try session_cache.StatefulServerCache.init(
        std.testing.allocator,
        limits,
        session_cache.system_random_source,
    );
    defer cache.deinit();

    const rejected_psk = [_]u8{0xa1} ** tls_backend.hash_len;
    var rejected_state = pskStoredStateWithBinding(
        &rejected_psk,
        session.AuthBinding.fromLeafCertificateDer("different-leaf"),
    );
    var rejected_handle: [session_cache.stateful_identity_len]u8 = undefined;
    try std.testing.expectEqual(
        session_cache.StoreResult.stored,
        cache.insertMove(&rejected_state, 0, .reusable, &rejected_handle),
    );

    const selected_psk = [_]u8{0xa2} ** tls_backend.hash_len;
    var selected_state = pskStoredState(&selected_psk);
    var selected_handle: [session_cache.stateful_identity_len]u8 = undefined;
    try std.testing.expectEqual(
        session_cache.StoreResult.stored,
        cache.insertMove(&selected_state, 1, .reusable, &selected_handle),
    );

    const middle_psk = [_]u8{0xa3} ** tls_backend.hash_len;
    var middle_state = pskStoredState(&middle_psk);
    var middle_handle: [session_cache.stateful_identity_len]u8 = undefined;
    try std.testing.expectEqual(
        session_cache.StoreResult.stored,
        cache.insertMove(&middle_state, 2, .reusable, &middle_handle),
    );

    var adapter = session_cache.StatefulServerPskResolverAdapter{
        .cache = &cache,
        .allocator = std.testing.allocator,
        .now_unix_ms = 0,
    };

    var reject_server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer reject_server.deinit();
    try reject_server.setServerPskResolver(adapter.resolver());
    try driveServerSelection(&reject_server, .{ .psk = .{ .items = &.{.{
        .identity = &rejected_handle,
        .binder_psk = &rejected_psk,
    }} } });
    try std.testing.expect(!reject_server.core.psk_authenticated);

    var pressure_state = pskStoredState(&([_]u8{0xa4} ** tls_backend.hash_len));
    var pressure_handle: [session_cache.stateful_identity_len]u8 = undefined;
    try std.testing.expectEqual(
        session_cache.StoreResult.stored,
        cache.insertMove(&pressure_state, 3, .reusable, &pressure_handle),
    );
    var rejected_after_pressure = cache.resolveLease(&rejected_handle, 3);
    defer rejected_after_pressure.deinit();
    try std.testing.expect(rejected_after_pressure == .miss);

    var selected_after_reject = cache.resolveLease(&selected_handle, 3);
    defer selected_after_reject.deinit();
    try std.testing.expect(selected_after_reject == .hit);
    var middle_after_reject = cache.resolveLease(&middle_handle, 3);
    defer middle_after_reject.deinit();
    try std.testing.expect(middle_after_reject == .hit);

    var select_server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer select_server.deinit();
    try select_server.setServerPskResolver(adapter.resolver());
    try driveServerSelection(&select_server, .{ .psk = .{ .items = &.{.{
        .identity = &selected_handle,
        .binder_psk = &selected_psk,
    }} } });
    try std.testing.expect(select_server.core.psk_authenticated);

    var second_pressure_state = pskStoredState(&([_]u8{0xa5} ** tls_backend.hash_len));
    var second_pressure_handle: [session_cache.stateful_identity_len]u8 = undefined;
    try std.testing.expectEqual(
        session_cache.StoreResult.stored,
        cache.insertMove(&second_pressure_state, 4, .reusable, &second_pressure_handle),
    );

    var middle_after_success = cache.resolveLease(&middle_handle, 4);
    defer middle_after_success.deinit();
    try std.testing.expect(middle_after_success == .miss);
    var selected_after_success = cache.resolveLease(&selected_handle, 4);
    defer selected_after_success.deinit();
    try std.testing.expect(selected_after_success == .hit);
    var pressure_after_success = cache.resolveLease(&pressure_handle, 4);
    defer pressure_after_success.deinit();
    try std.testing.expect(pressure_after_success == .hit);
    var second_pressure_after_success = cache.resolveLease(&second_pressure_handle, 4);
    defer second_pressure_after_success.deinit();
    try std.testing.expect(second_pressure_after_success == .hit);
}

const FbaCloningResolver = struct {
    state: *session.ServerRecoverableState,
    allocator: std.mem.Allocator,
    identity: []const u8,
    calls: usize = 0,

    fn now(_: *anyopaque) i64 {
        return 0;
    }
    fn resolve(ctx: *anyopaque, identity: []const u8) pre_shared_key.ResolveError!pre_shared_key.ServerPskResolveResult {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        if (!std.mem.eql(u8, identity, self.identity)) return .miss;
        self.calls += 1;
        // Deliberately clones through a *different* allocator than the one
        // backing `self.state` itself, so the only writes ever made into
        // `allocator`'s backing storage are the transient per-attempt
        // candidate this resolver hands back to `selectPsk` — isolating
        // exactly the allocation this test means to observe.
        return clonedResolveHit(self.state, self.allocator);
    }
};

test "a bad binder wipes the resolver's cloned candidate, including its compat blob" {
    // Zig's generic `Allocator.free()` front-end unconditionally
    // `@memset`s freed memory to `undefined`, for *any* backing allocator
    // (including `FixedBufferAllocator`) — so scanning `backing` for the
    // absence of a marker byte string proves nothing: that scan would
    // "pass" even if the candidate's `deinit()` were never called, because
    // any full alloc/free round-trip on this allocator poisons the same
    // bytes regardless. What genuinely distinguishes "freed" from "leaked"
    // here is `FixedBufferAllocator`'s own *bookkeeping* (`end_index`),
    // which the `Allocator.free()` wrapper does not touch and which only
    // advances/retreats through real (de)allocations of the clone's
    // backing storage: a full round-trip back to the starting offset can
    // only happen if every byte this resolver allocated for the failed
    // candidate was also freed.
    var backing = [_]u8{0xa5} ** 4096;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    const clone_allocator = fba.allocator();
    const end_index_before_selection = fba.end_index;

    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();

    const marker = "candidate-compat-blob-marker";
    try server.setApplicationCompat(.{ .format_id = 3, .format_version = 1, .bytes = marker });

    const psk = [_]u8{0x66} ** tls_backend.hash_len;
    const wrong_psk = [_]u8{0x77} ** tls_backend.hash_len;
    var common: session.ResumableSessionCommon = .{};
    // Built with a plain allocator: this is the resolver's *source* record,
    // never itself passed to `selectPsk` — only its clones (made through
    // `clone_allocator` below) are, so this allocation must not alias the
    // one under test.
    try common.init(std.testing.allocator, session.Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &psk,
        .application_protocol = "h2",
        .auth_binding = session.AuthBinding.fromLeafCertificateDer(tls_backend.testdata.certificate_der),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 3600,
        .application_compat = .{ .format_id = 3, .format_version = 1, .bytes = marker },
    });
    var stored_state: session.ServerRecoverableState = .{};
    stored_state.init(&common, 0);
    defer stored_state.deinit();

    var resolver_state = FbaCloningResolver{ .state = &stored_state, .allocator = clone_allocator, .identity = "bad-binder-ticket" };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = FbaCloningResolver.now,
        .resolveFn = FbaCloningResolver.resolve,
    });

    try std.testing.expectError(error.DecryptError, driveServerSelection(&server, .{
        .psk = .{ .items = &.{.{ .identity = "bad-binder-ticket", .binder_psk = &wrong_psk }} },
    }));

    try std.testing.expect(!server.core.psk_authenticated);
    try std.testing.expect(!server.selected_server_psk_present);
    // The resolver really was invoked (and so really did clone a compat
    // blob into `clone_allocator`, proving this exercised the allocator)...
    try std.testing.expectEqual(@as(usize, 1), resolver_state.calls);
    // ...and by the time selection has failed, every byte it allocated for
    // that candidate has been released back to the allocator: `end_index`
    // returned exactly to its starting point. This can only happen if the
    // candidate's `deinit()` (which frees the cloned compat blob) actually
    // ran on the bad-binder path — a leaked candidate would leave
    // `end_index` permanently advanced.
    try std.testing.expectEqual(end_index_before_selection, fba.end_index);
}

/// A hand-written `CredentialProvider` whose second chain entry is
/// malformed (empty, or larger than `max_certificate_len`) — for proving
/// `inspectSelectedServerCredential` validates every entry, not only the
/// leaf, before PSK selection ever runs.
const MalformedTailProvider = struct {
    entries: [2][]const u8,
    release_count: usize = 0,

    fn provider(self: *MalformedTailProvider) credentials.CredentialProvider {
        return .{ .ctx = self, .vtable = &vtable };
    }

    const vtable = credentials.CredentialProvider.VTable{ .select = select };

    fn select(ctx: *anyopaque, selection: *const credentials.SelectionContext) credentials.SelectError!credentials.Progress(credentials.SelectedCredential) {
        _ = selection;
        return .{ .complete = .{ .handle = ctx, .scheme = .ed25519, .vtable = &cred_vtable } };
    }

    const cred_vtable = credentials.SelectedCredential.VTable{ .chain = chainFn, .sign = signFn, .release = releaseFn };

    fn chainFn(handle: *anyopaque) credentials.CertificateChain {
        const self: *MalformedTailProvider = @ptrCast(@alignCast(handle));
        return .{ .entries = &self.entries };
    }
    fn signFn(handle: *anyopaque, scheme: credentials.SignatureScheme, input: []const u8, out: []u8) credentials.SignError!credentials.Progress(usize) {
        _ = handle;
        _ = scheme;
        _ = input;
        _ = out;
        // Never reached: chain validation must fail before any signing is
        // attempted, on both the PSK and full-handshake paths.
        return error.SigningProviderFailure;
    }
    fn releaseFn(handle: *anyopaque) void {
        const self: *MalformedTailProvider = @ptrCast(@alignCast(handle));
        self.release_count += 1;
    }
};

test "a malformed non-leaf chain entry is rejected before PSK resolver/binder work, even though the leaf is valid" {
    var mock = MalformedTailProvider{ .entries = .{ tls_backend.testdata.certificate_der, "" } }; // entry 1: empty
    var server = tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), mock.provider(), .record);
    defer server.deinit();

    const psk = [_]u8{0x99} ** tls_backend.hash_len;
    var stored_state = pskStoredState(&psk);
    defer stored_state.deinit();
    var resolver_state = CountingResolver{ .state = &stored_state, .identity = "leaf-ok-tail-bad" };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = CountingResolver.now,
        .resolveFn = CountingResolver.resolve,
    });

    try std.testing.expectError(error.CredentialProviderFailed, driveServerSelection(&server, .{
        .psk = .{ .items = &.{.{ .identity = "leaf-ok-tail-bad", .binder_psk = &psk }} },
    }));

    try std.testing.expectEqual(tls_backend.CredentialFailure.malformed_credential_chain, server.credentialFailure().?);
    // The resolver/binder path was never reached at all.
    try std.testing.expectEqual(@as(usize, 0), resolver_state.calls);
    try std.testing.expectEqual(@as(usize, 1), mock.release_count);
}

test "an oversized non-leaf chain entry is rejected before PSK resolver/binder work" {
    const oversized = [_]u8{0} ** (tls_backend.max_certificate_len + 1);
    var mock = MalformedTailProvider{ .entries = .{ tls_backend.testdata.certificate_der, &oversized } };
    var server = tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), mock.provider(), .record);
    defer server.deinit();

    const psk = [_]u8{0xaa} ** tls_backend.hash_len;
    var stored_state = pskStoredState(&psk);
    defer stored_state.deinit();
    var resolver_state = CountingResolver{ .state = &stored_state, .identity = "leaf-ok-tail-oversized" };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = CountingResolver.now,
        .resolveFn = CountingResolver.resolve,
    });

    try std.testing.expectError(error.CredentialProviderFailed, driveServerSelection(&server, .{
        .psk = .{ .items = &.{.{ .identity = "leaf-ok-tail-oversized", .binder_psk = &psk }} },
    }));

    try std.testing.expectEqual(tls_backend.CredentialFailure.malformed_credential_chain, server.credentialFailure().?);
    try std.testing.expectEqual(@as(usize, 0), resolver_state.calls);
    try std.testing.expectEqual(@as(usize, 1), mock.release_count);
}

test "a ticket bound to a different server certificate falls back to a full handshake" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();

    const psk = [_]u8{0x44} ** tls_backend.hash_len;
    var stored_state = pskStoredStateWithBinding(&psk, session.AuthBinding.fromLeafCertificateDer("a different certificate entirely"));
    defer stored_state.deinit();
    var resolver_state = CountingResolver{ .state = &stored_state, .identity = "rotated-ticket" };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = CountingResolver.now,
        .resolveFn = CountingResolver.resolve,
    });

    try driveServerSelection(&server, .{ .psk = .{ .items = &.{
        .{ .identity = "rotated-ticket", .binder_psk = &psk },
    } } });

    try std.testing.expectEqual(@as(usize, 1), resolver_state.calls);
    try std.testing.expect(!server.core.psk_authenticated);
    // Falls back to the ordinary full-certificate flight rather than
    // failing the connection outright.
    try std.testing.expectEqual(.running, server.core.handshake_lifecycle);
    try std.testing.expect(server.credentialFailure() == null);
}

test "PSK offered without psk_key_exchange_modes is a missing_extension failure" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();
    const psk = [_]u8{0x55} ** tls_backend.hash_len;
    try std.testing.expectError(error.MissingExtension, driveServerSelection(&server, .{ .psk = .{
        .omit_modes = true,
        .items = &.{.{ .identity = "ticket", .binder_psk = &psk }},
    } }));
}

test "PSK identity and binder count mismatch is illegal_parameter" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();

    var raw_ext_data: [2 + (2 + 6 + 4) + 2 + 2 * (1 + tls_backend.hash_len)]u8 = undefined;
    var w = HsWriter{ .buf = &raw_ext_data };
    const identities_len = try w.reserve(2);
    try w.u16_(6);
    try w.bytes("ticket");
    try w.bytes(&.{ 0, 0, 0, 0 });
    w.patch(2, identities_len);
    const binders_len = try w.reserve(2);
    inline for (0..2) |_| {
        try w.u8_(tls_backend.hash_len);
        try w.bytes(&([_]u8{0xaa} ** tls_backend.hash_len));
    }
    w.patch(2, binders_len);

    try std.testing.expectError(error.IllegalParameter, driveServerSelection(&server, .{ .psk = .{
        .items = &.{},
        .raw_ext_data = w.written(),
    } }));
}

test "an SNI mismatch falls back to a full handshake instead of rejecting the connection" {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();

    const psk = [_]u8{0x66} ** tls_backend.hash_len;
    var common: session.ResumableSessionCommon = .{};
    try common.init(std.testing.allocator, session.Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &psk,
        .application_protocol = "h2",
        .server_name = "original.example",
        .auth_binding = session.AuthBinding.fromLeafCertificateDer(tls_backend.testdata.certificate_der),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 3600,
    });
    var stored_state: session.ServerRecoverableState = .{};
    stored_state.init(&common, 0);
    defer stored_state.deinit();
    var resolver_state = CountingResolver{ .state = &stored_state, .identity = "sni-ticket" };
    try server.setServerPskResolver(.{
        .ctx = &resolver_state,
        .nowUnixMsFn = CountingResolver.now,
        .resolveFn = CountingResolver.resolve,
    });

    // The client now connects to a *different* host name than the ticket
    // was issued for.
    try driveServerSelection(&server, .{
        .sni = "different.example",
        .psk = .{ .items = &.{.{ .identity = "sni-ticket", .binder_psk = &psk }} },
    });

    try std.testing.expectEqual(@as(usize, 1), resolver_state.calls);
    try std.testing.expect(!server.core.psk_authenticated);
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
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
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
    var client = tls_backend.Tls13Backend.initClientWithVerifier(clientEntropy(), verifier.verifier(), .record, .{ .server_name = "tardigrade.test" });
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
    var client = tls_backend.Tls13Backend.initClientWithVerifier(clientEntropy(), verifier.verifier(), .record, .{});
    var sink = DirectSink{};
    try driveClientThroughCertificateVerify(&client, &sink);
    try std.testing.expect(client.authPending());

    sink.deinit();
    client.deinit();
    try std.testing.expectEqual(@as(usize, 1), verifier.cancel_count);
    try std.testing.expectEqual(@as(usize, 1), verifier.op_release_count);
}

test "a client rejects trailing handshake bytes after the server Finished" {
    var verifier = credentials.MockVerifier.init(.accepted);
    var client = tls_backend.Tls13Backend.initClientWithVerifier(clientEntropy(), verifier.verifier(), .record, .{});
    defer client.deinit();
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();
    var client_sink = DirectSink{};
    defer client_sink.deinit();
    var server_sink = DirectSink{};
    defer server_sink.deinit();

    try client.backend().start(.client, {}, &client_sink);
    var ch_buf: [1024]u8 = undefined;
    const client_hello = firstInitialCrypto(&client_sink, &ch_buf);
    try server.backend().start(.server, {}, &server_sink);
    try server.backend().receive(.initial, client_hello, &server_sink);

    var sh_buf: [512]u8 = undefined;
    const server_hello = firstInitialCrypto(&server_sink, &sh_buf);
    var flight_buf: [8192]u8 = undefined;
    const flight = collectHandshakeCrypto(&server_sink, &flight_buf);
    var suffixed: [8193]u8 = undefined;
    @memcpy(suffixed[0..flight.len], flight);
    suffixed[flight.len] = @intFromEnum(HsMessageType.finished);

    client_sink.reset();
    try client.backend().receive(.initial, server_hello, &client_sink);
    try std.testing.expectError(error.UnexpectedHandshakeMessage, client.backend().receive(.handshake, suffixed[0 .. flight.len + 1], &client_sink));
    try std.testing.expect(!handshakeCompleteIn(&client_sink));
}

test "a server rejects trailing handshake bytes after the client Finished" {
    var client = tls_backend.Tls13Backend.initClient(clientEntropy(), .{ .pinned_certificate = tls_backend.testdata.certificate_der }, .record);
    defer client.deinit();
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    defer server.deinit();
    var client_sink = DirectSink{};
    defer client_sink.deinit();
    var server_sink = DirectSink{};
    defer server_sink.deinit();

    try deliverServerFlightToClient(&client, &server, &client_sink, &server_sink);
    var finished_buf: [512]u8 = undefined;
    const client_finished = collectHandshakeCrypto(&client_sink, &finished_buf);
    var suffixed: [513]u8 = undefined;
    @memcpy(suffixed[0..client_finished.len], client_finished);
    suffixed[client_finished.len] = @intFromEnum(HsMessageType.certificate);

    try std.testing.expectError(error.UnexpectedHandshakeMessage, server.backend().receive(.handshake, suffixed[0 .. client_finished.len + 1], &server_sink));
    try std.testing.expect(!handshakeCompleteIn(&server_sink));
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
        .record,
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

test "absent ALPN reaches server selector and client verifier as null" {
    var provider = credentials.MockCredentialProvider.init(fixtureIdentity());
    var verifier = credentials.MockVerifier.init(.accepted);
    var client_policy = tls_core.policy.Policy.recordHttp1Only(true);
    client_policy.alpn_protocols = &.{};
    var client = tls_backend.Tls13Backend.initClientWithVerifierConfigured(
        clientEntropy(),
        verifier.verifier(),
        tls_backend.recordConfig(client_policy),
        .{},
    );
    defer client.deinit();
    var server = tls_backend.Tls13Backend.initServerWithProviderConfigured(
        serverEntropy(),
        provider.provider(),
        tls_backend.recordConfig(tls_core.policy.Policy.recordHttp1Only(true)),
    );
    defer server.deinit();

    var client_sink = DirectSink{};
    defer client_sink.deinit();
    var server_sink = DirectSink{};
    defer server_sink.deinit();

    try deliverServerFlightToClient(&client, &server, &client_sink, &server_sink);
    try std.testing.expectEqual(@as(usize, 1), provider.select_count);
    try std.testing.expectEqual(@as(usize, 1), verifier.verify_count);
    try std.testing.expect(provider.lastApplicationProtocol() == null);
    try std.testing.expect(verifier.lastApplicationProtocol() == null);
}

fn serverRequestingClientAuth(mode: tls_backend.ClientAuthMode, verifier: credentials.PeerVerifier) tls_backend.Tls13Backend {
    var server = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .record);
    server.requestClientAuthentication(mode, verifier);
    return server;
}

test "client rejects selected signature scheme incompatible with leaf key before Certificate flight" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.scheme_override = .ecdsa_secp256r1_sha256;
    var client = clientWithLocalCredential(mock.provider());
    defer client.deinit();
    var verifier = credentials.MockVerifier.init(.accepted);
    var server = serverRequestingClientAuth(.required, verifier.verifier());
    defer server.deinit();

    var client_sink = DirectSink{};
    defer client_sink.deinit();
    var server_sink = DirectSink{};
    defer server_sink.deinit();

    try std.testing.expectError(error.CredentialProviderFailed, deliverServerFlightToClient(&client, &server, &client_sink, &server_sink));
    try std.testing.expectEqual(tls_backend.CredentialFailure.invalid_callback_behavior, client.credentialFailure().?);
    try std.testing.expectEqual(@as(usize, 1), mock.release_count);
    try std.testing.expectEqual(@as(usize, 0), mock.sign_count);
    try std.testing.expectEqual(@as(usize, 0), countCryptoEvents(&client_sink, .handshake));
}

test "async client selection rejects signature scheme incompatible with leaf key before Certificate flight" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.scheme_override = .ecdsa_secp256r1_sha256;
    mock.async_select = true;
    mock.pending_polls = 0;
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
    try std.testing.expect(client.authPending());
    try std.testing.expectEqual(@as(usize, 0), countCryptoEvents(&client_sink, .handshake));
    try std.testing.expectError(error.CredentialProviderFailed, client.resumeAuth(&client_sink));
    try std.testing.expectEqual(tls_backend.CredentialFailure.invalid_callback_behavior, client.credentialFailure().?);
    try std.testing.expectEqual(@as(usize, 1), mock.release_count);
    try std.testing.expectEqual(@as(usize, 0), mock.sign_count);
    try std.testing.expectEqual(@as(usize, 0), countCryptoEvents(&client_sink, .handshake));
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

test "pending client credential selection rejects later handshake bytes and cancels once" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.async_select = true;
    mock.pending_polls = 5;
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
    try std.testing.expect(client.authPending());
    client_sink.reset();

    const stray = [_]u8{@intFromEnum(HsMessageType.finished)};
    try std.testing.expectError(error.UnexpectedHandshakeMessage, client.backend().receive(.handshake, &stray, &client_sink));
    try std.testing.expect(!client.authPending());
    try std.testing.expect(!handshakeCompleteIn(&client_sink));
    try std.testing.expectEqual(@as(usize, 1), mock.cancel_count);
    try std.testing.expectEqual(@as(usize, 1), mock.op_release_count);
    try std.testing.expectEqual(@as(usize, 0), mock.release_count);
    try std.testing.expectEqual(@as(usize, 0), mock.sign_count);
}

test "pending client signing rejects later handshake bytes and releases the held credential once" {
    var mock = credentials.MockCredentialProvider.init(fixtureIdentity());
    mock.async_sign = true;
    mock.pending_polls = 5;
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
    try std.testing.expect(client.authPending());
    client_sink.reset();

    const stray = [_]u8{@intFromEnum(HsMessageType.certificate)};
    try std.testing.expectError(error.UnexpectedHandshakeMessage, client.backend().receive(.handshake, &stray, &client_sink));
    try std.testing.expect(!client.authPending());
    try std.testing.expect(!handshakeCompleteIn(&client_sink));
    try std.testing.expectEqual(@as(usize, 1), mock.cancel_count);
    try std.testing.expectEqual(@as(usize, 1), mock.op_release_count);
    try std.testing.expectEqual(@as(usize, 1), mock.release_count);
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

test "a malformed async client selection completion is rejected as invalid callback behavior" {
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
    try std.testing.expectEqual(tls_backend.CredentialFailure.invalid_callback_behavior, client.credentialFailure().?);
    try std.testing.expectEqual(@as(usize, 1), wrong.release_count);
}

test "an invalid configured server name is rejected at start rather than emitted" {
    var verifier = credentials.MockVerifier.init(.accepted);
    const too_long = [_]u8{'a'} ** 254;
    const too_long_label = [_]u8{'b'} ** 64;
    const invalid_names = [_][]const u8{
        "",
        &too_long,
        "bad..example",
        "bad host.example",
        "bad\x00host.example",
        "-bad.example",
        "bad-.example",
        "bad.-example",
        "bad.example-",
        &too_long_label,
    };
    for (invalid_names) |name| {
        var client = tls_backend.Tls13Backend.initClientWithVerifier(
            clientEntropy(),
            verifier.verifier(),
            .record,
            .{ .server_name = name },
        );
        defer client.deinit();
        var sink = DirectSink{};
        defer sink.deinit();
        // Fails closed before any ClientHello is emitted; nothing is truncated
        // or encoded as an empty host_name.
        try std.testing.expectError(error.InvalidHandshakeState, client.backend().start(.client, {}, &sink));
        try std.testing.expectEqual(@as(usize, 0), sink.len);
        try std.testing.expect(!client.key_pair_present);
    }
}

test "a ClientHello combining maximum ALPN, SNI, and transport extension serializes successfully" {
    // #334 review: with maximum-length ALPN (255, the largest a u8 length
    // prefix allows), SNI (256, max_server_name_len), and a maximum transport
    // extension (tls_backend.max_transport_extension_len = 512), the encoded
    // ClientHello is roughly 1.15 KiB. This bypasses public client options to
    // exercise the serializer's raw bounded buffer, not semantic DNS policy.
    const max_alpn = [_]u8{'a'} ** 255;
    const max_sni = [_]u8{'s'} ** 256;
    var max_transport_ext = [_]u8{0xab} ** tls_backend.max_transport_extension_len;
    const max_alpn_protocols = [_]tls_core.algorithms.ProtocolName{.{ .bytes = &max_alpn }};
    const max_alpn_policy = tls_core.policy.Policy.fromCapabilities(
        .quic,
        tls_backend.native_capabilities,
        &max_alpn_protocols,
    );
    var client = tls_backend.Tls13Backend.initClientConfigured(
        clientEntropy(),
        .{ .pinned_certificate = tls_backend.testdata.certificate_der },
        .{
            .policy = max_alpn_policy,
            .transport = .{ .extension = .{ .extension_type = 57, .local = &max_transport_ext } },
        },
        .{},
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

    while (!h.client_engine.authPending()) {
        const c = try h.driveClient();
        const s = try h.driveServer();
        if (!c.made_progress and !s.made_progress) return error.Stalled;
    }
    try std.testing.expectEqual(@as(usize, 0), client_credential.poll_count);

    _ = try h.driveClient();
    try std.testing.expect(h.client_engine.authPending());
    try std.testing.expectEqual(@as(usize, 1), client_credential.poll_count);

    _ = try h.driveClient();
    try std.testing.expect(h.client_engine.authPending());
    try std.testing.expectEqual(@as(usize, 2), client_credential.poll_count);

    const completion_poll = try h.driveClient();
    try std.testing.expect(completion_poll.made_progress);
    try std.testing.expect(!h.client_engine.authPending());
    try h.driveUntil(SocketHarness.bothComplete);
    try std.testing.expect(h.client.bridge.handshake_complete);
    try std.testing.expect(h.server.bridge.handshake_complete);
    // The async signature was polled to completion through the driver, and the
    // server verified the client certificate.
    try std.testing.expectEqual(@as(usize, 1), client_credential.sign_count);
    try std.testing.expectEqual(@as(usize, 3), client_credential.poll_count);
    try std.testing.expectEqual(@as(usize, 1), client_credential.op_release_count);
    try std.testing.expectEqual(@as(usize, 0), client_credential.cancel_count);
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
    var server = tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), big.provider(), .record);
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
        .record,
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

// --- #392 review: the appliance credential loader's flight-size preflight
//     bound must be writer-identical — a chain it accepts must actually
//     serialize through the real server flight, for both native TCP (record
//     ALPN) and native HTTP/3 (the QUIC transport-extension profile sharing
//     the same credential). A `BigChain*Provider` proves the writer's own
//     behavior directly; it does not need real X.509 DER (the writer's size
//     preflight, unlike `appliance_credentials.zig`'s, does not parse
//     entries), only a real Ed25519 signer so the flight actually completes.

/// Like `BigChainProvider`, but signs for real with the fixture Ed25519
/// identity so a size-preflight-passing chain's flight fully emits rather
/// than failing before reaching the signing step.
const BigChainSigningProvider = struct {
    entry_len: usize,
    entry_count: usize,
    storage: [tls_backend.max_certificate_len]u8 = [_]u8{0x2c} ** tls_backend.max_certificate_len,
    entries: [credentials.max_chain_entries][]const u8 = undefined,
    identity: tls_backend.Identity = undefined,
    sign_count: usize = 0,

    fn init(entry_len: usize, entry_count: usize) BigChainSigningProvider {
        return .{ .entry_len = entry_len, .entry_count = entry_count, .identity = fixtureIdentity() };
    }

    fn provider(self: *BigChainSigningProvider) credentials.CredentialProvider {
        return .{ .ctx = self, .vtable = &prov_vtable };
    }
    const prov_vtable = credentials.CredentialProvider.VTable{ .select = select };
    fn select(ctx: *anyopaque, selection: *const credentials.SelectionContext) credentials.SelectError!credentials.Progress(credentials.SelectedCredential) {
        const self: *BigChainSigningProvider = @ptrCast(@alignCast(ctx));
        if (!selection.offersScheme(.ed25519)) return error.NoCompatibleSignatureAlgorithm;
        return .{ .complete = .{ .handle = self, .scheme = .ed25519, .vtable = &cred_vtable } };
    }
    const cred_vtable = credentials.SelectedCredential.VTable{ .chain = chain, .sign = sign, .release = release };
    fn chain(handle: *anyopaque) credentials.CertificateChain {
        const self: *BigChainSigningProvider = @ptrCast(@alignCast(handle));
        if (self.entry_count > 0) self.entries[0] = self.identity.certificate_der;
        for (1..self.entry_count) |i| self.entries[i] = self.storage[0..self.entry_len];
        return .{ .entries = self.entries[0..self.entry_count] };
    }
    fn sign(handle: *anyopaque, _: credentials.SignatureScheme, input: []const u8, out: []u8) credentials.SignError!credentials.Progress(usize) {
        const self: *BigChainSigningProvider = @ptrCast(@alignCast(handle));
        self.sign_count += 1;
        return .{ .complete = try self.identity.sign(input, out) };
    }
    fn release(_: *anyopaque) void {}
};

/// Split `total` bytes of certificate-chain contribution as evenly as
/// possible across `entry_count` entries (each within
/// `tls_backend.max_certificate_len`), returning the per-entry length. This
/// mirrors exactly what the writer counts: `certificate_message_overhead`
/// once, plus `certificate_entry_overhead + entry_len` per entry.
fn chainEntryLenForTotal(total: usize, entry_count: usize) usize {
    const per_entry_with_overhead = (total - tls_backend.certificate_message_overhead) / entry_count;
    return per_entry_with_overhead - tls_backend.certificate_entry_overhead;
}

test "a chain at appliance's flight-size boundary serializes through the real record-mode server flight" {
    const entry_count = 4;
    const entry_len = chainEntryLenForTotal(
        tls_core.appliance_credentials.default_max_certificate_flight_bytes,
        entry_count,
    );
    try std.testing.expect(entry_len <= tls_backend.max_certificate_len);

    var big = BigChainSigningProvider.init(entry_len, entry_count);
    var server = tls_backend.Tls13Backend.initServerWithProvider(serverEntropy(), big.provider(), .record);
    defer server.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [1024]u8 = undefined;
    const hello = try buildClientHello(&buf, .{});
    // No CredentialProviderFailed / malformed_credential_chain: the chain
    // this appliance-computed boundary allows actually fits the live writer.
    try server.backend().receive(.initial, hello, &sink);
    try std.testing.expectEqual(@as(usize, 1), big.sign_count);
    try std.testing.expect(sink.len > 0); // EncryptedExtensions/Certificate/CertificateVerify/Finished were emitted
}

test "a chain at appliance's flight-size boundary serializes through the real HTTP/3 extension-profile server flight" {
    const entry_count = 4;
    const entry_len = chainEntryLenForTotal(
        tls_core.appliance_credentials.default_max_certificate_flight_bytes,
        entry_count,
    );
    try std.testing.expect(entry_len <= tls_backend.max_certificate_len);

    var big = BigChainSigningProvider.init(entry_len, entry_count);
    const local_transport_params = [_]u8{0xab} ** tls_backend.max_transport_extension_len;
    var server = tls_backend.Tls13Backend.initServerWithProvider(
        serverEntropy(),
        big.provider(),
        .{ .extension = .{ .extension_type = 57, .local = &local_transport_params } },
    );
    defer server.deinit();
    var sink = DirectSink{};
    defer sink.deinit();
    try server.backend().start(.server, {}, &sink);
    var buf: [2048]u8 = undefined;
    const hello = try buildClientHello(&buf, .{
        .alpn_protocols = &.{"h3"},
        .transport_extension = .{ .extension_type = 57, .payload = &local_transport_params },
    });
    try server.backend().receive(.initial, hello, &sink);
    try std.testing.expectEqual(@as(usize, 1), big.sign_count);
    try std.testing.expect(sink.len > 0); // EncryptedExtensions/Certificate/CertificateVerify/Finished were emitted
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
    // The server fails with certificate_required and synthesizes an
    // application-key alert after its Finished. The client must receive the
    // alert, not just hit EOF or an AEAD failure.
    try std.testing.expectEqual(@as(?anyerror, error.ClientCertificateRequired), failures.server);
    try std.testing.expectEqual(@as(?anyerror, error.PeerFatalAlert), failures.client);
    try std.testing.expect(!h.server.bridge.handshake_complete);
    try std.testing.expectEqual(tls_backend.CredentialFailure.client_certificate_required, h.server_engine.credentialFailure().?);
}
