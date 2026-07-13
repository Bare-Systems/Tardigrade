//! TLS record epoch bridge.
//!
//! The shared TLS engine emits protocol events: handshake bytes, traffic
//! secrets, epoch discard, and completion. This module is the record-mode glue
//! between those events and `record_protection`: it owns independent read/write
//! traffic states for handshake and application epochs, keeps the initial
//! ClientHello/ServerHello plaintext path explicit, and rejects out-of-order key
//! transitions deterministically.

const std = @import("std");
const crypto = @import("crypto");
const algorithms = @import("algorithms.zig");
const engine = @import("engine.zig");
const events = @import("events.zig");
const record_codec = @import("record_codec.zig");
const record_protection = @import("record_protection.zig");
const tls_state = @import("state.zig");
const transport = @import("transport.zig");

const provider = crypto.provider;

pub const Error = record_codec.Error || record_protection.Error || error{
    UnsupportedRecordEpoch,
    DuplicateTrafficSecret,
    MissingReadKeys,
    MissingWriteKeys,
    MissingApplicationKeys,
    HandshakeNotComplete,
    InvalidEpochTransition,
    UnexpectedRecordContent,
};

pub const OpenedRecord = struct {
    epoch: events.EncryptionEpoch,
    inner: record_codec.InnerPlaintext,
};

const DirectionPhase = enum {
    initial,
    handshake,
    application,
    complete,
};

pub const Bridge = struct {
    crypto_provider: provider.CryptoProvider,
    cipher_suite: algorithms.CipherSuite,
    read_handshake: ?record_protection.ReadState = null,
    write_handshake: ?record_protection.WriteState = null,
    read_application: ?record_protection.ReadState = null,
    write_application: ?record_protection.WriteState = null,
    read_phase: DirectionPhase = .initial,
    write_phase: DirectionPhase = .initial,
    read_handshake_discarded: bool = false,
    write_handshake_discarded: bool = false,
    read_application_discarded: bool = false,
    write_application_discarded: bool = false,
    handshake_complete: bool = false,

    pub fn init(crypto_provider: provider.CryptoProvider, cipher_suite: algorithms.CipherSuite) Bridge {
        return .{ .crypto_provider = crypto_provider, .cipher_suite = cipher_suite };
    }

    pub fn deinit(self: *Bridge) void {
        self.discardEpoch(.handshake);
        self.discardEpoch(.application);
        self.handshake_complete = false;
    }

    pub fn applyEvent(self: *Bridge, event: events.Event, out: []u8) Error!?[]const u8 {
        switch (event) {
            .handshake_bytes => |bytes| return try self.sealHandshake(bytes.epoch, bytes.data, out),
            .traffic_secret => |traffic_secret| try self.installTrafficSecret(traffic_secret.epoch, traffic_secret.direction, traffic_secret.data),
            .discard_epoch => |epoch| self.discardEpoch(epoch),
            .handshake_complete => try self.markHandshakeComplete(),
            .alpn,
            .certificate,
            => {},
        }
        return null;
    }

    pub fn installTrafficSecret(
        self: *Bridge,
        epoch: events.EncryptionEpoch,
        direction: events.SecretDirection,
        traffic_secret: []const u8,
    ) Error!void {
        switch (epoch) {
            .handshake => switch (direction) {
                .read => {
                    if (self.read_phase != .initial or self.read_handshake_discarded) return error.InvalidEpochTransition;
                    try self.installRead(&self.read_handshake, traffic_secret);
                    self.read_phase = .handshake;
                },
                .write => {
                    if (self.write_phase != .initial or self.write_handshake_discarded) return error.InvalidEpochTransition;
                    try self.installWrite(&self.write_handshake, traffic_secret);
                    self.write_phase = .handshake;
                },
            },
            .application => switch (direction) {
                .read => {
                    if (self.read_phase != .handshake or self.read_handshake_discarded or self.read_application_discarded) return error.InvalidEpochTransition;
                    try self.installRead(&self.read_application, traffic_secret);
                    self.read_phase = .application;
                },
                .write => {
                    if (self.write_phase != .handshake or self.write_handshake_discarded or self.write_application_discarded) return error.InvalidEpochTransition;
                    try self.installWrite(&self.write_application, traffic_secret);
                    self.write_phase = .application;
                },
            },
            .initial,
            .zero_rtt,
            => return error.UnsupportedRecordEpoch,
        }
    }

    pub fn discardEpoch(self: *Bridge, epoch: events.EncryptionEpoch) void {
        switch (epoch) {
            .handshake => {
                clearRead(&self.read_handshake);
                clearWrite(&self.write_handshake);
                self.read_handshake_discarded = true;
                self.write_handshake_discarded = true;
            },
            .application => {
                clearRead(&self.read_application);
                clearWrite(&self.write_application);
                self.read_application_discarded = true;
                self.write_application_discarded = true;
                self.read_phase = .initial;
                self.write_phase = .initial;
                self.handshake_complete = false;
            },
            .initial,
            .zero_rtt,
            => {},
        }
    }

    pub fn markHandshakeComplete(self: *Bridge) Error!void {
        if (self.handshake_complete) return error.InvalidEpochTransition;
        if (self.read_phase != .application or self.write_phase != .application) return error.InvalidEpochTransition;
        if (self.read_application == null or self.write_application == null) return error.MissingApplicationKeys;
        self.handshake_complete = true;
        self.read_phase = .complete;
        self.write_phase = .complete;
    }

    pub fn sealHandshake(self: *Bridge, epoch: events.EncryptionEpoch, bytes: []const u8, out: []u8) Error![]const u8 {
        return self.sealProtected(epoch, .handshake, bytes, out);
    }

    pub fn sealProtected(
        self: *Bridge,
        epoch: events.EncryptionEpoch,
        content_type: record_codec.ContentType,
        bytes: []const u8,
        out: []u8,
    ) Error![]const u8 {
        return switch (epoch) {
            .initial => if (content_type == .handshake)
                record_codec.encodePlaintextRecord(.handshake, bytes, out)
            else
                error.UnsupportedRecordEpoch,
            .handshake => blk: {
                const write = self.writeHandshake() orelse return error.MissingWriteKeys;
                break :blk try write.seal(content_type, bytes, 0, out);
            },
            .application => blk: {
                if (!self.handshake_complete) return error.HandshakeNotComplete;
                const write = self.writeApplication() orelse return error.MissingWriteKeys;
                break :blk try write.seal(content_type, bytes, 0, out);
            },
            .zero_rtt => error.UnsupportedRecordEpoch,
        };
    }

    pub fn sealApplicationData(self: *Bridge, bytes: []const u8, out: []u8) Error![]const u8 {
        return self.sealProtected(.application, .application_data, bytes, out);
    }

    pub fn openHandshake(
        self: *Bridge,
        epoch: events.EncryptionEpoch,
        record: record_codec.Record,
        out: []u8,
    ) Error!OpenedRecord {
        const opened = try self.openProtected(epoch, record, out);
        if (opened.inner.content_type != .handshake) return error.UnexpectedRecordContent;
        return opened;
    }

    pub fn openProtected(
        self: *Bridge,
        epoch: events.EncryptionEpoch,
        record: record_codec.Record,
        out: []u8,
    ) Error!OpenedRecord {
        const inner = switch (epoch) {
            .initial => blk: {
                if (record.content_type != .handshake) return error.UnexpectedRecordContent;
                break :blk record_codec.InnerPlaintext{
                    .content_type = record.content_type,
                    .content = record.payload,
                    .padding_len = 0,
                };
            },
            .handshake => blk: {
                const read = self.readHandshake() orelse return error.MissingReadKeys;
                break :blk try read.open(record, out);
            },
            .application => blk: {
                if (!self.handshake_complete) return error.HandshakeNotComplete;
                const read = self.readApplication() orelse return error.MissingReadKeys;
                break :blk try read.open(record, out);
            },
            .zero_rtt => return error.UnsupportedRecordEpoch,
        };
        return .{ .epoch = epoch, .inner = inner };
    }

    pub fn openApplicationData(self: *Bridge, record: record_codec.Record, out: []u8) Error!OpenedRecord {
        const opened = try self.openProtected(.application, record, out);
        if (opened.inner.content_type != .application_data) return error.UnexpectedRecordContent;
        return opened;
    }

    pub fn hasReadKeys(self: *const Bridge, epoch: events.EncryptionEpoch) bool {
        return switch (epoch) {
            .handshake => self.read_handshake != null,
            .application => self.read_application != null,
            .initial,
            .zero_rtt,
            => false,
        };
    }

    pub fn hasWriteKeys(self: *const Bridge, epoch: events.EncryptionEpoch) bool {
        return switch (epoch) {
            .handshake => self.write_handshake != null,
            .application => self.write_application != null,
            .initial,
            .zero_rtt,
            => false,
        };
    }

    fn installRead(self: *Bridge, slot: *?record_protection.ReadState, traffic_secret: []const u8) Error!void {
        if (slot.* != null) return error.DuplicateTrafficSecret;
        slot.* = record_protection.ReadState.init(
            self.crypto_provider,
            try record_protection.TrafficKeys.derive(self.crypto_provider, self.cipher_suite, traffic_secret),
        );
    }

    fn installWrite(self: *Bridge, slot: *?record_protection.WriteState, traffic_secret: []const u8) Error!void {
        if (slot.* != null) return error.DuplicateTrafficSecret;
        slot.* = record_protection.WriteState.init(
            self.crypto_provider,
            try record_protection.TrafficKeys.derive(self.crypto_provider, self.cipher_suite, traffic_secret),
        );
    }

    fn readHandshake(self: *Bridge) ?*record_protection.ReadState {
        if (self.read_handshake) |*state| return state;
        return null;
    }

    fn writeHandshake(self: *Bridge) ?*record_protection.WriteState {
        if (self.write_handshake) |*state| return state;
        return null;
    }

    fn readApplication(self: *Bridge) ?*record_protection.ReadState {
        if (self.read_application) |*state| return state;
        return null;
    }

    fn writeApplication(self: *Bridge) ?*record_protection.WriteState {
        if (self.write_application) |*state| return state;
        return null;
    }
};

fn clearRead(slot: *?record_protection.ReadState) void {
    if (slot.*) |*state| state.deinit();
    slot.* = null;
}

fn clearWrite(slot: *?record_protection.WriteState) void {
    if (slot.*) |*state| state.deinit();
    slot.* = null;
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

fn testProvider() provider.CryptoProvider {
    const pure_zig = crypto.pure_zig;
    const State = struct {
        var entropy = pure_zig.DeterministicEntropy.init(0x352);
        var provider_state = pure_zig.Provider.init(entropy.entropy());
    };
    return State.provider_state.cryptoProvider();
}

fn secret(comptime fill: u8) [32]u8 {
    return [_]u8{fill} ** 32;
}

fn expectAes128TrafficKeys(traffic_secret: [32]u8, keys: record_protection.TrafficKeys) !void {
    const std_crypto = std.crypto;
    const HkdfSha256 = std_crypto.kdf.hkdf.HkdfSha256;
    const expected_key = std_crypto.tls.hkdfExpandLabel(HkdfSha256, traffic_secret, "key", "", 16);
    const expected_iv = std_crypto.tls.hkdfExpandLabel(HkdfSha256, traffic_secret, "iv", "", provider.aead_nonce_len);
    try testing.expectEqualSlices(u8, &expected_key, keys.key.slice());
    try testing.expectEqualSlices(u8, &expected_iv, keys.iv.slice());
}

const testing = std.testing;

test "record epoch bridge drives event loopback across plaintext, handshake, application, and post-handshake records" {
    const cp = testProvider();
    var client = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();

    const client_hs = secret(0x11);
    const server_hs = secret(0x22);
    const client_app = secret(0x33);
    const server_app = secret(0x44);

    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;

    const client_hello = (try client.applyEvent(.{ .handshake_bytes = .{ .epoch = .initial, .data = "client hello" } }, &protected)).?;
    const client_hello_record = try parseSingleRecord(.plaintext, client_hello);
    const opened_client_hello = try server.openHandshake(.initial, client_hello_record, &plaintext);
    try testing.expectEqual(events.EncryptionEpoch.initial, opened_client_hello.epoch);
    try testing.expectEqualStrings("client hello", opened_client_hello.inner.content);

    try testing.expectEqual(@as(?[]const u8, null), try client.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .write, .data = &client_hs } }, &protected));
    try testing.expectEqual(@as(?[]const u8, null), try client.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .read, .data = &server_hs } }, &protected));
    try testing.expectEqual(@as(?[]const u8, null), try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .read, .data = &client_hs } }, &protected));
    try testing.expectEqual(@as(?[]const u8, null), try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .write, .data = &server_hs } }, &protected));
    try expectAes128TrafficKeys(client_hs, client.write_handshake.?.keys);
    try testing.expectEqual(@as(u64, 0), client.write_handshake.?.sequence);

    const encrypted_finished = (try client.applyEvent(.{ .handshake_bytes = .{ .epoch = .handshake, .data = "client finished" } }, &protected)).?;
    const encrypted_finished_record = try parseSingleRecord(.ciphertext, encrypted_finished);
    const opened_finished = try server.openHandshake(.handshake, encrypted_finished_record, &plaintext);
    try testing.expectEqualStrings("client finished", opened_finished.inner.content);
    try testing.expectEqual(@as(u64, 1), client.write_handshake.?.sequence);
    try testing.expectEqual(@as(u64, 1), server.read_handshake.?.sequence);

    try testing.expectEqual(@as(?[]const u8, null), try client.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .write, .data = &client_app } }, &protected));
    try testing.expectEqual(@as(?[]const u8, null), try client.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .read, .data = &server_app } }, &protected));
    try testing.expectEqual(@as(?[]const u8, null), try server.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .read, .data = &client_app } }, &protected));
    try testing.expectEqual(@as(?[]const u8, null), try server.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .write, .data = &server_app } }, &protected));
    try testing.expectEqual(@as(?[]const u8, null), try client.applyEvent(.handshake_complete, &protected));
    try testing.expectEqual(@as(?[]const u8, null), try server.applyEvent(.handshake_complete, &protected));

    const application_record = try client.sealApplicationData("GET / HTTP/3", &protected);
    const parsed_application = try parseSingleRecord(.ciphertext, application_record);
    const opened_application = try server.openApplicationData(parsed_application, &plaintext);
    try testing.expectEqual(events.EncryptionEpoch.application, opened_application.epoch);
    try testing.expectEqualStrings("GET / HTTP/3", opened_application.inner.content);
    try testing.expectEqual(@as(u64, 1), client.write_application.?.sequence);
    try testing.expectEqual(@as(u64, 1), server.read_application.?.sequence);

    const post_handshake = (try server.applyEvent(.{ .handshake_bytes = .{ .epoch = .application, .data = "new session ticket" } }, &protected)).?;
    const parsed_post_handshake = try parseSingleRecord(.ciphertext, post_handshake);
    const opened_post_handshake = try client.openHandshake(.application, parsed_post_handshake, &plaintext);
    try testing.expectEqualStrings("new session ticket", opened_post_handshake.inner.content);
    try testing.expectEqual(@as(u64, 1), server.write_application.?.sequence);
    try testing.expectEqual(@as(u64, 1), client.read_application.?.sequence);
}

test "record epoch bridge rejects early, duplicate, missing, and unsupported transitions" {
    const cp = testProvider();
    var bridge = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer bridge.deinit();

    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const hs = secret(0x51);
    const app = secret(0x52);

    try testing.expectError(error.MissingWriteKeys, bridge.sealHandshake(.handshake, "finished", &protected));
    try testing.expectError(error.HandshakeNotComplete, bridge.sealApplicationData("data", &protected));
    try testing.expectError(error.UnsupportedRecordEpoch, bridge.installTrafficSecret(.initial, .write, &hs));
    try testing.expectError(error.InvalidEpochTransition, bridge.installTrafficSecret(.application, .write, &app));

    try bridge.installTrafficSecret(.handshake, .write, &hs);
    try testing.expectError(error.InvalidEpochTransition, bridge.installTrafficSecret(.handshake, .write, &hs));
    try testing.expectError(error.InvalidEpochTransition, bridge.markHandshakeComplete());

    try bridge.installTrafficSecret(.application, .write, &app);
    try testing.expectError(error.InvalidEpochTransition, bridge.markHandshakeComplete());
}

test "record epoch bridge discards prior epoch keys and fails closed after discard" {
    const cp = testProvider();
    var bridge = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer bridge.deinit();

    const hs_read = secret(0x61);
    const hs_write = secret(0x62);
    try bridge.installTrafficSecret(.handshake, .read, &hs_read);
    try bridge.installTrafficSecret(.handshake, .write, &hs_write);
    try testing.expect(bridge.hasReadKeys(.handshake));
    try testing.expect(bridge.hasWriteKeys(.handshake));

    bridge.discardEpoch(.handshake);
    try testing.expect(!bridge.hasReadKeys(.handshake));
    try testing.expect(!bridge.hasWriteKeys(.handshake));

    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    try testing.expectError(error.MissingWriteKeys, bridge.sealHandshake(.handshake, "late finished", &protected));
    try testing.expectError(error.InvalidEpochTransition, bridge.installTrafficSecret(.handshake, .write, &hs_write));
    try testing.expectError(error.InvalidEpochTransition, bridge.installTrafficSecret(.application, .write, &hs_write));
}

test "record epoch bridge rejects wrong content at otherwise valid epochs" {
    const cp = testProvider();
    var client = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();

    const client_app = secret(0x71);
    const server_app = secret(0x72);
    const client_hs = secret(0x73);
    const server_hs = secret(0x74);
    try client.installTrafficSecret(.handshake, .write, &client_hs);
    try client.installTrafficSecret(.handshake, .read, &server_hs);
    try server.installTrafficSecret(.handshake, .read, &client_hs);
    try server.installTrafficSecret(.handshake, .write, &server_hs);
    try client.installTrafficSecret(.application, .write, &client_app);
    try client.installTrafficSecret(.application, .read, &server_app);
    try server.installTrafficSecret(.application, .read, &client_app);
    try server.installTrafficSecret(.application, .write, &server_app);
    try client.markHandshakeComplete();
    try server.markHandshakeComplete();

    var protected: [record_codec.max_ciphertext_record_len]u8 = undefined;
    var plaintext: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
    const record = try client.sealApplicationData("not handshake", &protected);
    const parsed = try parseSingleRecord(.ciphertext, record);
    try testing.expectError(error.UnexpectedRecordContent, server.openHandshake(.application, parsed, &plaintext));
}

test "record epoch bridge shuttles protocol-neutral driver events through records" {
    const DriverError = Error || error{ InvalidHandshakeState, TransportBufferOverflow };
    const T = transport.Contract(void, events.EncryptionEpoch, DriverError);
    const D = engine.Driver(T);

    const ScriptedBackend = struct {
        const Self = @This();

        role: tls_state.Role,
        client_hs: [32]u8 = secret(0x81),
        server_hs: [32]u8 = secret(0x82),
        client_app: [32]u8 = secret(0x83),
        server_app: [32]u8 = secret(0x84),

        fn backend(self: *Self) T.Backend {
            return .{ .ptr = self, .startFn = start, .receiveFn = receive };
        }

        fn start(ptr: *anyopaque, role: tls_state.Role, _: void, sink: *T.EventSink) DriverError!void {
            const self: *Self = @ptrCast(@alignCast(ptr));
            if (self.role != role) return error.InvalidEpochTransition;
            if (role == .client) try sink.emitHandshakeBytes(.initial, "client hello");
        }

        fn receive(ptr: *anyopaque, epoch: events.EncryptionEpoch, bytes: []const u8, sink: *T.EventSink) DriverError!void {
            const self: *Self = @ptrCast(@alignCast(ptr));
            switch (self.role) {
                .server => {
                    if (epoch == .initial and std.mem.eql(u8, bytes, "client hello")) {
                        try sink.emitHandshakeBytes(.initial, "server hello");
                        try sink.emitSecret(.handshake, .read, &self.client_hs);
                        try sink.emitSecret(.handshake, .write, &self.server_hs);
                        try sink.emitHandshakeBytes(.handshake, "server finished");
                    } else if (epoch == .handshake and std.mem.eql(u8, bytes, "client finished")) {
                        try sink.emitSecret(.application, .read, &self.client_app);
                        try sink.emitSecret(.application, .write, &self.server_app);
                        try sink.emitHandshakeComplete();
                        try sink.emitHandshakeBytes(.application, "new session ticket");
                    } else {
                        return error.UnexpectedRecordContent;
                    }
                },
                .client => {
                    if (epoch == .initial and std.mem.eql(u8, bytes, "server hello")) {
                        try sink.emitSecret(.handshake, .write, &self.client_hs);
                        try sink.emitSecret(.handshake, .read, &self.server_hs);
                    } else if (epoch == .handshake and std.mem.eql(u8, bytes, "server finished")) {
                        try sink.emitSecret(.application, .write, &self.client_app);
                        try sink.emitSecret(.application, .read, &self.server_app);
                        try sink.emitHandshakeComplete();
                        try sink.emitHandshakeBytes(.handshake, "client finished");
                    } else if (epoch == .application and std.mem.eql(u8, bytes, "new session ticket")) {
                        try sink.emitAlpn("h3");
                    } else {
                        return error.UnexpectedRecordContent;
                    }
                },
            }
        }
    };

    const Harness = struct {
        fn pump(
            sender_driver: *D,
            sender_bridge: *Bridge,
            receiver_driver: *D,
            receiver_bridge: *Bridge,
            sink: *T.EventSink,
        ) DriverError!void {
            var sealed: [record_codec.max_ciphertext_record_len]u8 = undefined;
            var opened: [record_codec.max_ciphertext_fragment_len]u8 = undefined;

            for (sink.items[0..sink.len]) |event| {
                switch (event) {
                    .handshake_bytes => |handshake| {
                        const bytes = (try sender_bridge.applyEvent(.{ .handshake_bytes = .{ .epoch = handshake.epoch, .data = handshake.data } }, &sealed)).?;
                        const mode: record_codec.RecordMode = if (handshake.epoch == .initial) .plaintext else .ciphertext;
                        const record = try parseSingleRecord(mode, bytes);
                        const message = try receiver_bridge.openHandshake(handshake.epoch, record, &opened);
                        const next = try receiver_driver.receive(message.epoch, message.inner.content);
                        try pump(receiver_driver, receiver_bridge, sender_driver, sender_bridge, next);
                    },
                    .traffic_secret => |traffic_secret| {
                        _ = try sender_bridge.applyEvent(.{ .traffic_secret = .{
                            .epoch = traffic_secret.epoch,
                            .direction = traffic_secret.direction,
                            .data = traffic_secret.data,
                        } }, &sealed);
                    },
                    .discard_epoch => |epoch| {
                        _ = try sender_bridge.applyEvent(.{ .discard_epoch = epoch }, &sealed);
                    },
                    .handshake_complete => {
                        _ = try sender_bridge.applyEvent(.handshake_complete, &sealed);
                        sender_driver.complete();
                    },
                    .peer_transport_parameters,
                    .alpn,
                    .certificate,
                    // Whether/when to synthesize one is transport policy
                    // (#354); this harness only proves the contract can carry
                    // it, not that record mode acts on it yet.
                    .fatal_alert,
                    => {},
                }
            }
        }
    };

    const cp = testProvider();
    var client_backend = ScriptedBackend{ .role = .client };
    var server_backend = ScriptedBackend{ .role = .server };
    var client_driver = D.init(.client, client_backend.backend());
    var server_driver = D.init(.server, server_backend.backend());
    var client_bridge = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer client_bridge.deinit();
    var server_bridge = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer server_bridge.deinit();

    const initial = try client_driver.start({});
    try Harness.pump(&client_driver, &client_bridge, &server_driver, &server_bridge, initial);

    try testing.expect(client_driver.isComplete());
    try testing.expect(server_driver.isComplete());
    try testing.expectEqual(@as(u64, 1), client_bridge.write_handshake.?.sequence);
    try testing.expectEqual(@as(u64, 1), server_bridge.read_handshake.?.sequence);
    try testing.expectEqual(@as(u64, 1), server_bridge.write_application.?.sequence);
    try testing.expectEqual(@as(u64, 1), client_bridge.read_application.?.sequence);
}
