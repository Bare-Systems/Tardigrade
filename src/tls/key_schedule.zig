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
