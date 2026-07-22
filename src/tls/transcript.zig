//! TLS 1.3 transcript hash helper.
//!
//! The transcript is transport-neutral: callers update it with exact handshake
//! message bytes as emitted by `messages.HandshakeMessage.raw`.

const std = @import("std");
const key_schedule = @import("key_schedule.zig");
const messages = @import("messages.zig");

pub const Hash = key_schedule.TranscriptHash;
pub const digest_len = key_schedule.hash_len;

pub const Transcript = struct {
    hash: Hash = Hash.init(.{}),

    pub fn update(self: *Transcript, bytes: []const u8) void {
        self.hash.update(bytes);
    }

    pub fn peek(self: *const Transcript) [digest_len]u8 {
        var copy = self.hash;
        var out: [digest_len]u8 = undefined;
        copy.final(&out);
        return out;
    }

    pub fn peekWith(self: *const Transcript, bytes: []const u8) [digest_len]u8 {
        var copy = self.hash;
        copy.update(bytes);
        var out: [digest_len]u8 = undefined;
        copy.final(&out);
        return out;
    }

    pub fn rebindClientHello(self: *Transcript) void {
        self.replace(self.peek());
    }

    pub fn replace(self: *Transcript, digest: [digest_len]u8) void {
        var synthetic: [4 + digest_len]u8 = undefined;
        synthetic[0] = @intFromEnum(messages.MessageType.message_hash);
        std.mem.writeInt(u24, synthetic[1..4], digest_len, .big);
        @memcpy(synthetic[4..], &digest);

        self.hash = Hash.init(.{});
        self.hash.update(&synthetic);
    }
};

const testing = std.testing;

test "transcript hash matches direct SHA-256 and supports HRR-style replacement" {
    var transcript = Transcript{};
    transcript.update("client hello");

    var expected: [digest_len]u8 = undefined;
    Hash.hash("client hello", &expected, .{});
    try testing.expectEqualSlices(u8, &expected, &transcript.peek());

    transcript.replace(expected);
    var rebound_expected: [digest_len]u8 = undefined;
    const synthetic = [_]u8{ 254, 0, 0, digest_len } ++ expected;
    Hash.hash(&synthetic, &rebound_expected, .{});
    try testing.expectEqualSlices(u8, &rebound_expected, &transcript.peek());
}

test "peekWith does not mutate transcript state" {
    var transcript = Transcript{};
    transcript.update("client hello");
    const before = transcript.peek();

    var expected = Hash.init(.{});
    expected.update("client hello");
    expected.update("hello retry request");
    var expected_digest: [digest_len]u8 = undefined;
    expected.final(&expected_digest);

    try testing.expectEqualSlices(u8, &expected_digest, &transcript.peekWith("hello retry request"));
    try testing.expectEqualSlices(u8, &before, &transcript.peek());
}

test "rebindClientHello produces deterministic HRR transcript fixture" {
    const client_hello_1 = [_]u8{ 1, 0, 0, 3, 0x01, 0x02, 0x03 };
    const hello_retry_request = [_]u8{ 2, 0, 0, 2, 0x04, 0x05 };
    const client_hello_2 = [_]u8{ 1, 0, 0, 4, 0x06, 0x07, 0x08, 0x09 };

    var transcript = Transcript{};
    transcript.update(&client_hello_1);
    transcript.rebindClientHello();
    transcript.update(&hello_retry_request);
    transcript.update(&client_hello_2);

    var independent_ch1_hash: [digest_len]u8 = undefined;
    Hash.hash(&client_hello_1, &independent_ch1_hash, .{});

    var synthetic: [4 + digest_len]u8 = undefined;
    synthetic[0] = @intFromEnum(messages.MessageType.message_hash);
    std.mem.writeInt(u24, synthetic[1..4], digest_len, .big);
    @memcpy(synthetic[4..], &independent_ch1_hash);

    var direct = Hash.init(.{});
    direct.update(&synthetic);
    direct.update(&hello_retry_request);
    direct.update(&client_hello_2);
    var expected: [digest_len]u8 = undefined;
    direct.final(&expected);

    try testing.expectEqualSlices(u8, &expected, &transcript.peek());
}
