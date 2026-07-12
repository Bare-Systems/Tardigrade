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
const events = @import("events.zig");
const record_codec = @import("record_codec.zig");
const record_protection = @import("record_protection.zig");

const provider = crypto.provider;

pub const Error = record_codec.Error || record_protection.Error || error{
    UnsupportedRecordEpoch,
    DuplicateTrafficSecret,
    MissingReadKeys,
    MissingWriteKeys,
    MissingApplicationKeys,
    HandshakeNotComplete,
    UnexpectedRecordContent,
};

pub const OpenedRecord = struct {
    epoch: events.EncryptionEpoch,
    inner: record_codec.InnerPlaintext,
};

pub const Bridge = struct {
    crypto_provider: provider.CryptoProvider,
    cipher_suite: algorithms.CipherSuite,
    read_handshake: ?record_protection.ReadState = null,
    write_handshake: ?record_protection.WriteState = null,
    read_application: ?record_protection.ReadState = null,
    write_application: ?record_protection.WriteState = null,
    handshake_complete: bool = false,

    pub fn init(crypto_provider: provider.CryptoProvider, cipher_suite: algorithms.CipherSuite) Bridge {
        return .{ .crypto_provider = crypto_provider, .cipher_suite = cipher_suite };
    }

    pub fn deinit(self: *Bridge) void {
        self.discardEpoch(.handshake);
        self.discardEpoch(.application);
        self.handshake_complete = false;
    }

    pub fn applyEvent(self: *Bridge, event: events.Event) Error!void {
        switch (event) {
            .traffic_secret => |traffic_secret| try self.installTrafficSecret(traffic_secret.epoch, traffic_secret.direction, traffic_secret.data),
            .discard_epoch => |epoch| self.discardEpoch(epoch),
            .handshake_complete => try self.markHandshakeComplete(),
            .handshake_bytes,
            .alpn,
            .certificate,
            => {},
        }
    }

    pub fn installTrafficSecret(
        self: *Bridge,
        epoch: events.EncryptionEpoch,
        direction: events.SecretDirection,
        traffic_secret: []const u8,
    ) Error!void {
        switch (epoch) {
            .handshake => switch (direction) {
                .read => try self.installRead(&self.read_handshake, traffic_secret),
                .write => try self.installWrite(&self.write_handshake, traffic_secret),
            },
            .application => switch (direction) {
                .read => try self.installRead(&self.read_application, traffic_secret),
                .write => try self.installWrite(&self.write_application, traffic_secret),
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
            },
            .application => {
                clearRead(&self.read_application);
                clearWrite(&self.write_application);
                self.handshake_complete = false;
            },
            .initial,
            .zero_rtt,
            => {},
        }
    }

    pub fn markHandshakeComplete(self: *Bridge) Error!void {
        if (self.read_application == null or self.write_application == null) return error.MissingApplicationKeys;
        self.handshake_complete = true;
    }

    pub fn sealHandshake(self: *Bridge, epoch: events.EncryptionEpoch, bytes: []const u8, out: []u8) Error![]const u8 {
        return switch (epoch) {
            .initial => record_codec.encodePlaintextRecord(.handshake, bytes, out),
            .handshake => blk: {
                const write = self.writeHandshake() orelse return error.MissingWriteKeys;
                break :blk try write.seal(.handshake, bytes, 0, out);
            },
            .application => blk: {
                if (!self.handshake_complete) return error.HandshakeNotComplete;
                const write = self.writeApplication() orelse return error.MissingWriteKeys;
                break :blk try write.seal(.handshake, bytes, 0, out);
            },
            .zero_rtt => error.UnsupportedRecordEpoch,
        };
    }

    pub fn sealApplicationData(self: *Bridge, bytes: []const u8, out: []u8) Error![]const u8 {
        if (!self.handshake_complete) return error.HandshakeNotComplete;
        const write = self.writeApplication() orelse return error.MissingWriteKeys;
        return write.seal(.application_data, bytes, 0, out);
    }

    pub fn openHandshake(
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
        if (inner.content_type != .handshake) return error.UnexpectedRecordContent;
        return .{ .epoch = epoch, .inner = inner };
    }

    pub fn openApplicationData(self: *Bridge, record: record_codec.Record, out: []u8) Error!OpenedRecord {
        if (!self.handshake_complete) return error.HandshakeNotComplete;
        const read = self.readApplication() orelse return error.MissingReadKeys;
        const inner = try read.open(record, out);
        if (inner.content_type != .application_data) return error.UnexpectedRecordContent;
        return .{ .epoch = .application, .inner = inner };
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
    const header = try record_codec.parseHeader(bytes[0..record_codec.header_len], mode);
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

const testing = std.testing;

test "record epoch bridge drives plaintext handshake, encrypted handshake, application data, and post-handshake routing" {
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

    const client_hello = try client.sealHandshake(.initial, "client hello", &protected);
    const client_hello_record = try parseSingleRecord(.plaintext, client_hello);
    const opened_client_hello = try server.openHandshake(.initial, client_hello_record, &plaintext);
    try testing.expectEqual(events.EncryptionEpoch.initial, opened_client_hello.epoch);
    try testing.expectEqualStrings("client hello", opened_client_hello.inner.content);

    try client.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .write, .data = &client_hs } });
    try client.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .read, .data = &server_hs } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .read, .data = &client_hs } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .write, .data = &server_hs } });

    const encrypted_finished = try client.sealHandshake(.handshake, "client finished", &protected);
    const encrypted_finished_record = try parseSingleRecord(.ciphertext, encrypted_finished);
    const opened_finished = try server.openHandshake(.handshake, encrypted_finished_record, &plaintext);
    try testing.expectEqualStrings("client finished", opened_finished.inner.content);
    try testing.expectEqual(@as(u64, 1), client.write_handshake.?.sequence);
    try testing.expectEqual(@as(u64, 1), server.read_handshake.?.sequence);

    try client.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .write, .data = &client_app } });
    try client.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .read, .data = &server_app } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .read, .data = &client_app } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .write, .data = &server_app } });
    try client.applyEvent(.handshake_complete);
    try server.applyEvent(.handshake_complete);

    const application_record = try client.sealApplicationData("GET / HTTP/3", &protected);
    const parsed_application = try parseSingleRecord(.ciphertext, application_record);
    const opened_application = try server.openApplicationData(parsed_application, &plaintext);
    try testing.expectEqual(events.EncryptionEpoch.application, opened_application.epoch);
    try testing.expectEqualStrings("GET / HTTP/3", opened_application.inner.content);
    try testing.expectEqual(@as(u64, 1), client.write_application.?.sequence);
    try testing.expectEqual(@as(u64, 1), server.read_application.?.sequence);

    const post_handshake = try server.sealHandshake(.application, "new session ticket", &protected);
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

    try bridge.installTrafficSecret(.handshake, .write, &hs);
    try testing.expectError(error.DuplicateTrafficSecret, bridge.installTrafficSecret(.handshake, .write, &hs));
    try testing.expectError(error.MissingApplicationKeys, bridge.markHandshakeComplete());

    try bridge.installTrafficSecret(.application, .write, &app);
    try testing.expectError(error.MissingApplicationKeys, bridge.markHandshakeComplete());
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
}

test "record epoch bridge rejects wrong content at otherwise valid epochs" {
    const cp = testProvider();
    var client = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = Bridge.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();

    const client_app = secret(0x71);
    const server_app = secret(0x72);
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
