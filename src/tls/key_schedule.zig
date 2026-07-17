//! Protocol-neutral TLS 1.3 SHA-256 key schedule.
//!
//! This module intentionally depends only on `std.crypto`: it has no QUIC,
//! HTTP, socket, or record-layer types. QUIC and future TCP-record integrations
//! both derive handshake/application traffic secrets through this shared core.

const std = @import("std");

const crypto = std.crypto;
const tls = crypto.tls;
const Sha256 = crypto.hash.sha2.Sha256;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
const X25519 = crypto.dh.X25519;

pub const TranscriptHash = Sha256;
pub const hash_len = Sha256.digest_length;
pub const shared_secret_len = X25519.shared_length;

const empty_transcript_hash: [hash_len]u8 = blk: {
    @setEvalBranchQuota(100_000);
    var out: [hash_len]u8 = undefined;
    Sha256.hash("", &out, .{});
    break :blk out;
};

const derived_early_secret: [hash_len]u8 = blk: {
    @setEvalBranchQuota(100_000);
    const zeros = [_]u8{0} ** hash_len;
    const early_secret = HkdfSha256.extract("", &zeros);
    break :blk tls.hkdfExpandLabel(HkdfSha256, early_secret, "derived", &empty_transcript_hash, hash_len);
};

pub const KeySchedule = struct {
    handshake_secret: [hash_len]u8,
    master_secret: [hash_len]u8,
    client_handshake_traffic: [hash_len]u8,
    server_handshake_traffic: [hash_len]u8,

    pub fn init(shared: [shared_secret_len]u8, hello_transcript_hash: [hash_len]u8) KeySchedule {
        const zeros = [_]u8{0} ** hash_len;
        const handshake_secret = HkdfSha256.extract(&derived_early_secret, &shared);
        const derived_handshake = tls.hkdfExpandLabel(HkdfSha256, handshake_secret, "derived", &empty_transcript_hash, hash_len);
        const master_secret = HkdfSha256.extract(&derived_handshake, &zeros);
        return .{
            .handshake_secret = handshake_secret,
            .master_secret = master_secret,
            .client_handshake_traffic = tls.hkdfExpandLabel(HkdfSha256, handshake_secret, "c hs traffic", &hello_transcript_hash, hash_len),
            .server_handshake_traffic = tls.hkdfExpandLabel(HkdfSha256, handshake_secret, "s hs traffic", &hello_transcript_hash, hash_len),
        };
    }

    pub const ApplicationSecrets = struct { client: [hash_len]u8, server: [hash_len]u8 };

    pub fn applicationSecrets(self: *const KeySchedule, finished_transcript_hash: [hash_len]u8) ApplicationSecrets {
        return .{
            .client = tls.hkdfExpandLabel(HkdfSha256, self.master_secret, "c ap traffic", &finished_transcript_hash, hash_len),
            .server = tls.hkdfExpandLabel(HkdfSha256, self.master_secret, "s ap traffic", &finished_transcript_hash, hash_len),
        };
    }

    pub fn finishedKey(traffic_secret: [hash_len]u8) [hash_len]u8 {
        return tls.hkdfExpandLabel(HkdfSha256, traffic_secret, "finished", "", hash_len);
    }

    pub fn verifyData(traffic_secret: [hash_len]u8, transcript_hash: [hash_len]u8) [hash_len]u8 {
        var mac: [HmacSha256.mac_length]u8 = undefined;
        HmacSha256.create(&mac, &transcript_hash, &finishedKey(traffic_secret));
        return mac;
    }

    pub fn wipe(self: *KeySchedule) void {
        crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

test "record-mode users can instantiate the protocol-neutral key schedule" {
    const shared = [_]u8{0x42} ** shared_secret_len;
    const transcript = [_]u8{0x24} ** hash_len;
    var schedule = KeySchedule.init(shared, transcript);
    defer schedule.wipe();
    const app = schedule.applicationSecrets(transcript);
    try std.testing.expect(!std.mem.eql(u8, &app.client, &app.server));
}

test "shared TLS 1.3 key schedule matches the RFC 8448 simple 1-RTT trace" {
    const shared = hexBytes("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    const hello_hash = hexBytes("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    const schedule = KeySchedule.init(shared, hello_hash);

    try std.testing.expectEqualSlices(u8, &hexBytes("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"), &schedule.handshake_secret);
    try std.testing.expectEqualSlices(u8, &hexBytes("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"), &schedule.client_handshake_traffic);
    try std.testing.expectEqualSlices(u8, &hexBytes("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"), &schedule.server_handshake_traffic);
    try std.testing.expectEqualSlices(u8, &hexBytes("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"), &schedule.master_secret);

    const finished_hash = hexBytes("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
    const app = schedule.applicationSecrets(finished_hash);
    try std.testing.expectEqualSlices(u8, &hexBytes("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"), &app.client);
    try std.testing.expectEqualSlices(u8, &hexBytes("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"), &app.server);
    try std.testing.expectEqualSlices(u8, &hexBytes("008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8"), &KeySchedule.finishedKey(schedule.server_handshake_traffic));
}

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var bytes: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}
