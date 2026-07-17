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

        self.client_engine = tls_backend.Tls13Backend.initClient(clientEntropy(), opts.client_trust, .{ .record = .{ .alpn = opts.client_alpn } });
        self.server_engine = tls_backend.Tls13Backend.initServer(serverEntropy(), fixtureIdentity(), .{ .record = .{ .alpn = opts.server_alpn } });
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
