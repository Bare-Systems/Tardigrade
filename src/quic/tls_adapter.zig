//! QUIC TLS 1.3 adapter (#249, RFC 9001): the boundary between the QUIC
//! connection and the TLS handshake. Carries CRYPTO frame data in/out of the
//! TLS state machine, installs read/write secrets per encryption level, and
//! provides packet-protection and header-protection keys to `packet.zig`.
//!
//! This is the one seam that may temporarily wrap an external TLS 1.3
//! implementation behind a no-leak interface (see the #242 design); no TLS
//! library type escapes this module. Initial-secret derivation and key updates
//! also live here.
//!
//! Status: the adapter contract, CRYPTO reassembly, AEAD packet protection and
//! header protection for every encryption level (Initial, 0-RTT, Handshake,
//! 1-RTT), packet-number reconstruction wiring, key updates, authenticated
//! transport parameters, ALPN/certificate reporting, and deprotection metrics
//! are all in place. Initial packet protection stays fixed to the RFC 9001
//! AES-128-GCM/SHA-256 profile; non-Initial packet protection follows the TLS
//! 1.3 cipher suite negotiated by `tls_handshake.zig` + `tls_backend.zig`
//! (#296/#566).
//!
//! Crypto ownership (#490): `QuicTlsAdapter` owns a `crypto.provider.CryptoProvider`
//! (`provider`), injected — never selected here — through `init`/`setProvider`,
//! both of which reject a provider missing the fixed profile's required
//! capabilities. This module never names a concrete backend (no
//! `crypto.pure_zig` import); choosing the pure-Zig provider is the native
//! HTTP/QUIC composition root's job (see `src/http/http3_runtime.zig`). The
//! adapter's own key derivation/update methods plus every send/receive call
//! site in `src/quic/connection.zig` and `src/http/http3_runtime.zig` call the
//! `*WithProvider` entry points on `PacketProtectionKeys`. The non-provider
//! functions and methods below remain only as differential test-vector
//! fixtures compared against the provider path; they are not the live path.

const std = @import("std");
const config = @import("config.zig");
const crypto_secrets = @import("crypto_secrets");
const crypto_pkg = @import("crypto");
const packet = @import("packet.zig");
const tls_core = @import("tls_core");
const test_quic_crypto = @import("test_quic_crypto");

const crypto = std.crypto;
const tls = std.crypto.tls;
const crypto_provider = crypto_pkg.provider;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const Aes128 = crypto.core.aes.Aes128;
const tls_algorithms = tls_core.algorithms;

pub const max_crypto_buffer = tls_core.tls13_transport.max_emitted_new_session_ticket_message_len;
pub const max_crypto_ranges = 32;
pub const max_handshake_record = 16 * 1024;
pub const max_secret_len = 64;
pub const min_initial_dcid_len = 8;
pub const max_connection_id_len = 20;
pub const initial_salt_v1 = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};
/// Length of the fixed SHA-256/AES-128 packet-protection profile. Initial
/// always uses this RFC 9001 profile; non-Initial levels use the negotiated
/// profile's `traffic_secret_len`.
pub const traffic_secret_len = HkdfSha256.prk_length;
pub const max_traffic_secret_len = crypto_provider.max_digest_len;
pub const aead_key_len = Aes128Gcm.key_length;
pub const aead_iv_len = Aes128Gcm.nonce_length;
pub const header_protection_key_len = Aes128Gcm.key_length;
pub const max_header_protection_key_len = crypto_provider.max_aead_key_len;
pub const packet_protection_tag_len = Aes128Gcm.tag_length;
/// Ciphertext sample size for header protection (RFC 9001 §5.4.1: one AES block).
pub const header_protection_sample_len = 16;
/// Largest QUIC packet-number encoding (RFC 9000 §17.1: 1..4 bytes).
pub const max_packet_number_length = 4;
pub const max_packet_number: u64 = (@as(u64, 1) << 62) - 1;

pub const EncryptionLevel = enum(u2) {
    initial,
    zero_rtt,
    handshake,
    application,

    pub fn index(self: EncryptionLevel) usize {
        return @intFromEnum(self);
    }

    pub fn packetNumberSpace(self: EncryptionLevel) PacketNumberSpace {
        return switch (self) {
            .initial => .initial,
            .handshake => .handshake,
            .zero_rtt, .application => .application,
        };
    }
};

fn cryptoStreamIndex(level: EncryptionLevel) error{InvalidCryptoLevel}!usize {
    return switch (level) {
        .initial, .handshake, .application => level.index(),
        .zero_rtt => error.InvalidCryptoLevel,
    };
}

pub const PacketNumberSpace = enum {
    initial,
    handshake,
    application,
};

pub const Direction = tls_core.events.SecretDirection;

pub const Perspective = enum {
    client,
    server,
};

pub const CertificateState = tls_core.events.CertificateState;

pub const KeyPhase = enum {
    current,
    next,
};

const TrafficSecret = crypto_secrets.FixedSecret(max_traffic_secret_len);
const PacketKeySecret = crypto_secrets.FixedSecret(crypto_provider.max_aead_key_len);
const PacketIvSecret = crypto_secrets.FixedSecret(crypto_provider.aead_nonce_len);
const HeaderProtectionSecret = crypto_secrets.FixedSecret(max_header_protection_key_len);

pub const PacketProtectionProfile = struct {
    hash: crypto_provider.Hash,
    aead: crypto_provider.Aead,
    header_protection: crypto_provider.QuicHeaderProtection,
    traffic_secret_len: usize,
    key_len: usize,
    iv_len: usize,
    tag_len: usize,
    hp_key_len: usize,

    pub fn forInitial() PacketProtectionProfile {
        return .{
            .hash = .sha256,
            .aead = .aes_128_gcm,
            .header_protection = .aes_128,
            .traffic_secret_len = traffic_secret_len,
            .key_len = aead_key_len,
            .iv_len = aead_iv_len,
            .tag_len = packet_protection_tag_len,
            .hp_key_len = header_protection_key_len,
        };
    }

    pub fn forCipherSuite(cipher_suite: tls_algorithms.CipherSuite) PacketProtectionProfile {
        return switch (cipher_suite) {
            .tls_aes_128_gcm_sha256 => .{
                .hash = .sha256,
                .aead = .aes_128_gcm,
                .header_protection = .aes_128,
                .traffic_secret_len = crypto_provider.Hash.sha256.digestLength(),
                .key_len = crypto_provider.Aead.aes_128_gcm.keyLength(),
                .iv_len = crypto_provider.aead_nonce_len,
                .tag_len = crypto_provider.aead_tag_len,
                .hp_key_len = crypto_provider.QuicHeaderProtection.aes_128.keyLength(),
            },
            .tls_aes_256_gcm_sha384 => .{
                .hash = .sha384,
                .aead = .aes_256_gcm,
                .header_protection = .aes_256,
                .traffic_secret_len = crypto_provider.Hash.sha384.digestLength(),
                .key_len = crypto_provider.Aead.aes_256_gcm.keyLength(),
                .iv_len = crypto_provider.aead_nonce_len,
                .tag_len = crypto_provider.aead_tag_len,
                .hp_key_len = crypto_provider.QuicHeaderProtection.aes_256.keyLength(),
            },
            .tls_chacha20_poly1305_sha256 => .{
                .hash = .sha256,
                .aead = .chacha20_poly1305,
                .header_protection = .chacha20,
                .traffic_secret_len = crypto_provider.Hash.sha256.digestLength(),
                .key_len = crypto_provider.Aead.chacha20_poly1305.keyLength(),
                .iv_len = crypto_provider.aead_nonce_len,
                .tag_len = crypto_provider.aead_tag_len,
                .hp_key_len = crypto_provider.QuicHeaderProtection.chacha20.keyLength(),
            },
        };
    }

    pub fn validateProvider(self: PacketProtectionProfile, provider: crypto_provider.CryptoProvider) error{ProviderUnsupported}!void {
        const caps = provider.capabilities();
        if (!caps.supportsHash(self.hash) or
            !caps.supportsAead(self.aead) or
            !caps.supportsQuicHeaderProtection(self.header_protection))
        {
            return error.ProviderUnsupported;
        }
    }
};

pub const Secret = struct {
    level: EncryptionLevel,
    direction: Direction,
    phase: KeyPhase = .current,
    material: crypto_secrets.FixedSecret(max_secret_len) = .{},

    pub fn init(level: EncryptionLevel, direction: Direction, bytes: []const u8) error{SecretTooLarge}!Secret {
        var secret = Secret{ .level = level, .direction = direction };
        secret.material.replace(bytes) catch return error.SecretTooLarge;
        return secret;
    }

    pub fn slice(self: *const Secret) []const u8 {
        return self.material.slice();
    }
};

pub const SecretStore = struct {
    read: [4]?Secret = .{ null, null, null, null },
    write: [4]?Secret = .{ null, null, null, null },

    pub fn install(self: *SecretStore, secret: Secret) void {
        switch (secret.direction) {
            .read => installSlot(&self.read[secret.level.index()], secret),
            .write => installSlot(&self.write[secret.level.index()], secret),
        }
    }

    pub fn get(self: *const SecretStore, level: EncryptionLevel, direction: Direction) ?*const Secret {
        return switch (direction) {
            .read => if (self.read[level.index()]) |*secret| secret else null,
            .write => if (self.write[level.index()]) |*secret| secret else null,
        };
    }

    pub fn discard(self: *SecretStore, level: EncryptionLevel) void {
        if (self.read[level.index()]) |*secret| wipe(secret);
        if (self.write[level.index()]) |*secret| wipe(secret);
        self.read[level.index()] = null;
        self.write[level.index()] = null;
    }

    pub fn deinit(self: *SecretStore) void {
        inline for (0..4) |index| {
            if (self.read[index]) |*secret| wipe(secret);
            if (self.write[index]) |*secret| wipe(secret);
            self.read[index] = null;
            self.write[index] = null;
        }
    }

    fn installSlot(slot: *?Secret, secret: Secret) void {
        if (slot.*) |*old_secret| wipe(old_secret);
        slot.* = secret;
    }

    fn wipe(secret: *Secret) void {
        secret.material.deinit();
    }
};

/// AEAD packet-protection material for one encryption level and direction
/// (RFC 9001 §5.1). Initial keys use the fixed AES-128-GCM/SHA-256 profile;
/// Handshake, 0-RTT, and 1-RTT keys use the negotiated TLS 1.3 suite profile.
pub const PacketProtectionKeys = struct {
    profile: PacketProtectionProfile = PacketProtectionProfile.forInitial(),
    secret: TrafficSecret = .{},
    key: PacketKeySecret = .{},
    iv: PacketIvSecret = .{},
    hp: HeaderProtectionSecret = .{},

    pub fn deinit(self: *PacketProtectionKeys) void {
        self.secret.deinit();
        self.key.deinit();
        self.iv.deinit();
        self.hp.deinit();
    }

    pub fn nonce(self: *const PacketProtectionKeys, packet_number: u64) [aead_iv_len]u8 {
        std.debug.assert(packet_number <= max_packet_number);

        std.debug.assert(self.iv.slice().len == aead_iv_len);
        var out: [aead_iv_len]u8 = undefined;
        @memcpy(&out, self.iv.slice());
        var packet_number_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &packet_number_bytes, packet_number, .big);
        for (packet_number_bytes, 0..) |byte, index| {
            out[aead_iv_len - packet_number_bytes.len + index] ^= byte;
        }
        return out;
    }

    pub fn sealPayload(
        self: *const PacketProtectionKeys,
        packet_number: u64,
        header: []const u8,
        plaintext: []const u8,
        out: []u8,
    ) error{ InvalidPacketNumber, OutputTooSmall }![]u8 {
        std.debug.assert(self.profile.aead == .aes_128_gcm);
        try validatePacketNumber(packet_number);
        if (plaintext.len > std.math.maxInt(usize) - self.profile.tag_len) return error.OutputTooSmall;
        const required_len = plaintext.len + self.profile.tag_len;
        if (out.len < required_len) return error.OutputTooSmall;

        var tag: [packet_protection_tag_len]u8 = undefined;
        Aes128Gcm.encrypt(
            out[0..plaintext.len],
            &tag,
            plaintext,
            header,
            self.nonce(packet_number),
            self.key.slice()[0..aead_key_len].*,
        );
        @memcpy(out[plaintext.len..][0..self.profile.tag_len], tag[0..self.profile.tag_len]);
        return out[0..required_len];
    }

    pub fn sealPayloadWithProvider(
        self: *const PacketProtectionKeys,
        provider: crypto_provider.CryptoProvider,
        packet_number: u64,
        header: []const u8,
        plaintext: []const u8,
        out: []u8,
    ) error{ InvalidPacketNumber, OutputTooSmall, ProviderUnsupported }![]u8 {
        try validatePacketNumber(packet_number);
        if (plaintext.len > std.math.maxInt(usize) - self.profile.tag_len) return error.OutputTooSmall;
        const required_len = plaintext.len + self.profile.tag_len;
        if (out.len < required_len) return error.OutputTooSmall;

        var tag: [crypto_provider.aead_tag_len]u8 = undefined;
        defer crypto_provider.secureZero(&tag);
        var packet_nonce = self.nonce(packet_number);
        defer crypto_provider.secureZero(&packet_nonce);
        provider.aeadSeal(self.profile.aead, self.key.slice(), &packet_nonce, header, plaintext, out[0..plaintext.len], tag[0..self.profile.tag_len]) catch |err| switch (err) {
            error.UnsupportedCapability => return error.ProviderUnsupported,
            error.InvalidInput => return error.OutputTooSmall,
        };
        @memcpy(out[plaintext.len..][0..self.profile.tag_len], tag[0..self.profile.tag_len]);
        return out[0..required_len];
    }

    pub fn openPayload(
        self: *const PacketProtectionKeys,
        packet_number: u64,
        header: []const u8,
        protected_payload: []const u8,
        out: []u8,
    ) error{ InvalidPacketNumber, ProtectedPayloadTooShort, OutputTooSmall, AuthenticationFailed }![]u8 {
        std.debug.assert(self.profile.aead == .aes_128_gcm);
        try validatePacketNumber(packet_number);
        if (protected_payload.len < self.profile.tag_len) return error.ProtectedPayloadTooShort;
        const ciphertext_len = protected_payload.len - self.profile.tag_len;
        if (out.len < ciphertext_len) return error.OutputTooSmall;

        var tag: [packet_protection_tag_len]u8 = undefined;
        @memcpy(tag[0..self.profile.tag_len], protected_payload[ciphertext_len..][0..self.profile.tag_len]);
        Aes128Gcm.decrypt(
            out[0..ciphertext_len],
            protected_payload[0..ciphertext_len],
            tag,
            header,
            self.nonce(packet_number),
            self.key.slice()[0..aead_key_len].*,
        ) catch return error.AuthenticationFailed;
        return out[0..ciphertext_len];
    }

    pub fn openPayloadWithProvider(
        self: *const PacketProtectionKeys,
        provider: crypto_provider.CryptoProvider,
        packet_number: u64,
        header: []const u8,
        protected_payload: []const u8,
        out: []u8,
    ) error{ InvalidPacketNumber, ProtectedPayloadTooShort, OutputTooSmall, AuthenticationFailed, ProviderUnsupported }![]u8 {
        try validatePacketNumber(packet_number);
        if (protected_payload.len < self.profile.tag_len) return error.ProtectedPayloadTooShort;
        const ciphertext_len = protected_payload.len - self.profile.tag_len;
        if (out.len < ciphertext_len) return error.OutputTooSmall;

        var packet_nonce = self.nonce(packet_number);
        defer crypto_provider.secureZero(&packet_nonce);
        provider.aeadOpen(
            self.profile.aead,
            self.key.slice(),
            &packet_nonce,
            header,
            protected_payload[0..ciphertext_len],
            protected_payload[ciphertext_len..][0..self.profile.tag_len],
            out[0..ciphertext_len],
        ) catch |err| switch (err) {
            error.UnsupportedCapability => return error.ProviderUnsupported,
            error.InvalidInput => return error.OutputTooSmall,
            error.AuthenticationFailed => return error.AuthenticationFailed,
        };
        return out[0..ciphertext_len];
    }

    pub fn headerProtectionMask(self: *const PacketProtectionKeys, sample: [header_protection_sample_len]u8) [5]u8 {
        std.debug.assert(self.profile.header_protection == .aes_128);
        const aes = Aes128.initEnc(self.hp.slice()[0..header_protection_key_len].*);
        var block: [header_protection_sample_len]u8 = undefined;
        aes.encrypt(&block, &sample);
        return block[0..5].*;
    }

    pub fn headerProtectionMaskWithProvider(
        self: *const PacketProtectionKeys,
        provider: crypto_provider.CryptoProvider,
        sample: [header_protection_sample_len]u8,
    ) error{ProviderUnsupported}![5]u8 {
        var mask: [5]u8 = undefined;
        provider.quicHeaderProtectionMask(self.profile.header_protection, self.hp.slice(), &sample, &mask) catch |err| switch (err) {
            error.UnsupportedCapability => return error.ProviderUnsupported,
            error.InvalidInput => return error.ProviderUnsupported,
        };
        return mask;
    }

    /// Apply QUIC header protection in place (RFC 9001 §5.4.1). `first_byte` is
    /// the packet's first byte and `packet_number_field` the 1..4 encoded
    /// packet-number bytes already written into the header; both are masked with
    /// the value derived from `sample`. The long/short header form is read from
    /// the (unprotected) high bit of `first_byte`.
    pub fn applyHeaderProtection(
        self: *const PacketProtectionKeys,
        first_byte: *u8,
        packet_number_field: []u8,
        sample: [header_protection_sample_len]u8,
    ) void {
        std.debug.assert(packet_number_field.len >= 1 and packet_number_field.len <= max_packet_number_length);
        const mask = self.headerProtectionMask(sample);
        first_byte.* ^= mask[0] & firstByteMask(first_byte.*);
        for (packet_number_field, 0..) |*byte, index| byte.* ^= mask[1 + index];
    }

    pub fn applyHeaderProtectionWithProvider(
        self: *const PacketProtectionKeys,
        provider: crypto_provider.CryptoProvider,
        first_byte: *u8,
        packet_number_field: []u8,
        sample: [header_protection_sample_len]u8,
    ) error{ProviderUnsupported}!void {
        std.debug.assert(packet_number_field.len >= 1 and packet_number_field.len <= max_packet_number_length);
        const mask = try self.headerProtectionMaskWithProvider(provider, sample);
        first_byte.* ^= mask[0] & firstByteMask(first_byte.*);
        for (packet_number_field, 0..) |*byte, index| byte.* ^= mask[1 + index];
    }

    /// Result of removing header protection: the recovered packet-number length
    /// (1..4) and the truncated packet number as sent on the wire. Feed
    /// `truncated_packet_number` to `packet.decodePacketNumber` with the largest
    /// processed packet number to reconstruct the full value.
    pub const RemovedHeaderProtection = struct {
        packet_number_length: usize,
        truncated_packet_number: u64,
    };

    /// Remove QUIC header protection in place (RFC 9001 §5.4.1). `sampled_pn`
    /// must hold the four bytes at the packet-number offset (the maximum-length
    /// field, always present because the header-protection sample follows it);
    /// only the recovered packet-number length is unmasked. The packet-number
    /// length is not known until the first byte is unmasked, so it is returned.
    pub fn removeHeaderProtection(
        self: *const PacketProtectionKeys,
        first_byte: *u8,
        sampled_pn: *[max_packet_number_length]u8,
        sample: [header_protection_sample_len]u8,
    ) RemovedHeaderProtection {
        const mask = self.headerProtectionMask(sample);
        first_byte.* ^= mask[0] & firstByteMask(first_byte.*);
        const packet_number_length: usize = @as(usize, first_byte.* & 0x03) + 1;
        var truncated: u64 = 0;
        var index: usize = 0;
        while (index < packet_number_length) : (index += 1) {
            sampled_pn[index] ^= mask[1 + index];
            truncated = (truncated << 8) | sampled_pn[index];
        }
        return .{ .packet_number_length = packet_number_length, .truncated_packet_number = truncated };
    }

    pub fn removeHeaderProtectionWithProvider(
        self: *const PacketProtectionKeys,
        provider: crypto_provider.CryptoProvider,
        first_byte: *u8,
        sampled_pn: *[max_packet_number_length]u8,
        sample: [header_protection_sample_len]u8,
    ) error{ProviderUnsupported}!RemovedHeaderProtection {
        const mask = try self.headerProtectionMaskWithProvider(provider, sample);
        first_byte.* ^= mask[0] & firstByteMask(first_byte.*);
        const packet_number_length: usize = @as(usize, first_byte.* & 0x03) + 1;
        var truncated: u64 = 0;
        var index: usize = 0;
        while (index < packet_number_length) : (index += 1) {
            sampled_pn[index] ^= mask[1 + index];
            truncated = (truncated << 8) | sampled_pn[index];
        }
        return .{ .packet_number_length = packet_number_length, .truncated_packet_number = truncated };
    }
};

/// Header-protection first-byte mask: 4 low bits for long headers (high bit
/// set), 5 low bits for short headers (RFC 9001 §5.4.1).
fn firstByteMask(first_byte: u8) u8 {
    return if (first_byte & 0x80 != 0) 0x0f else 0x1f;
}

fn validatePacketNumber(packet_number: u64) error{InvalidPacketNumber}!void {
    if (packet_number > max_packet_number) return error.InvalidPacketNumber;
}

pub const InitialSecrets = struct {
    initial_secret: [traffic_secret_len]u8,
    client: PacketProtectionKeys,
    server: PacketProtectionKeys,

    pub fn deinit(self: *InitialSecrets) void {
        crypto_provider.secureZero(&self.initial_secret);
        self.client.deinit();
        self.server.deinit();
    }
};

pub fn deriveInitialSecretsV1(client_initial_dcid: []const u8) error{InvalidConnectionId}!InitialSecrets {
    if (client_initial_dcid.len < min_initial_dcid_len or client_initial_dcid.len > max_connection_id_len) {
        return error.InvalidConnectionId;
    }

    var initial_secret = HkdfSha256.extract(&initial_salt_v1, client_initial_dcid);
    defer crypto_provider.secureZero(&initial_secret);
    var client_secret = tls.hkdfExpandLabel(HkdfSha256, initial_secret, "client in", "", traffic_secret_len);
    defer crypto_provider.secureZero(&client_secret);
    var server_secret = tls.hkdfExpandLabel(HkdfSha256, initial_secret, "server in", "", traffic_secret_len);
    defer crypto_provider.secureZero(&server_secret);
    return InitialSecrets{
        .initial_secret = initial_secret,
        .client = deriveAes128GcmKeys(client_secret),
        .server = deriveAes128GcmKeys(server_secret),
    };
}

pub fn deriveInitialSecretsV1WithProvider(provider: crypto_provider.CryptoProvider, client_initial_dcid: []const u8) error{ InvalidConnectionId, ProviderUnsupported }!InitialSecrets {
    if (client_initial_dcid.len < min_initial_dcid_len or client_initial_dcid.len > max_connection_id_len) {
        return error.InvalidConnectionId;
    }

    var initial_secret: [traffic_secret_len]u8 = undefined;
    defer crypto_provider.secureZero(&initial_secret);
    provider.hkdfExtract(.sha256, &initial_salt_v1, client_initial_dcid, &initial_secret) catch return error.ProviderUnsupported;
    var client_secret: [traffic_secret_len]u8 = undefined;
    defer crypto_provider.secureZero(&client_secret);
    var server_secret: [traffic_secret_len]u8 = undefined;
    defer crypto_provider.secureZero(&server_secret);
    provider.hkdfExpandLabel(.sha256, &initial_secret, "client in", "", &client_secret) catch return error.ProviderUnsupported;
    provider.hkdfExpandLabel(.sha256, &initial_secret, "server in", "", &server_secret) catch return error.ProviderUnsupported;

    var out = InitialSecrets{
        .initial_secret = initial_secret,
        .client = .{},
        .server = .{},
    };
    errdefer out.deinit();
    out.client = try deriveAes128GcmKeysWithProvider(provider, &client_secret);
    out.server = try deriveAes128GcmKeysWithProvider(provider, &server_secret);
    return out;
}

/// Derive AEAD packet-protection keys for the fixed AES-128-GCM/SHA-256
/// profile, per RFC 9001 §5.1. This legacy helper remains for Initial keys and
/// differential vectors; live non-Initial paths call
/// `derivePacketProtectionKeysWithProvider` with the negotiated profile.
pub fn deriveAes128GcmKeys(secret: [traffic_secret_len]u8) PacketProtectionKeys {
    var keys = PacketProtectionKeys{ .profile = PacketProtectionProfile.forInitial() };
    keys.secret.replace(&secret) catch unreachable;
    var key = tls.hkdfExpandLabel(HkdfSha256, secret, "quic key", "", aead_key_len);
    defer crypto_provider.secureZero(&key);
    var iv = tls.hkdfExpandLabel(HkdfSha256, secret, "quic iv", "", aead_iv_len);
    defer crypto_provider.secureZero(&iv);
    var hp = tls.hkdfExpandLabel(HkdfSha256, secret, "quic hp", "", header_protection_key_len);
    defer crypto_provider.secureZero(&hp);
    keys.key.replace(&key) catch unreachable;
    keys.iv.replace(&iv) catch unreachable;
    keys.hp.replace(&hp) catch unreachable;
    return keys;
}

pub fn deriveAes128GcmKeysWithProvider(provider: crypto_provider.CryptoProvider, secret: []const u8) error{ProviderUnsupported}!PacketProtectionKeys {
    return derivePacketProtectionKeysWithProvider(provider, PacketProtectionProfile.forInitial(), secret) catch return error.ProviderUnsupported;
}

pub fn derivePacketProtectionKeysWithProvider(provider: crypto_provider.CryptoProvider, profile: PacketProtectionProfile, secret: []const u8) error{ InvalidTrafficSecretLength, ProviderUnsupported }!PacketProtectionKeys {
    if (secret.len != profile.traffic_secret_len) return error.InvalidTrafficSecretLength;
    try profile.validateProvider(provider);

    var key: [crypto_provider.max_aead_key_len]u8 = undefined;
    defer crypto_provider.secureZero(&key);
    var iv: [crypto_provider.aead_nonce_len]u8 = undefined;
    defer crypto_provider.secureZero(&iv);
    var hp: [crypto_provider.max_aead_key_len]u8 = undefined;
    defer crypto_provider.secureZero(&hp);

    provider.hkdfExpandLabel(profile.hash, secret, "quic key", "", key[0..profile.key_len]) catch return error.ProviderUnsupported;
    provider.hkdfExpandLabel(profile.hash, secret, "quic iv", "", iv[0..profile.iv_len]) catch return error.ProviderUnsupported;
    provider.hkdfExpandLabel(profile.hash, secret, "quic hp", "", hp[0..profile.hp_key_len]) catch return error.ProviderUnsupported;

    var keys = PacketProtectionKeys{ .profile = profile };
    errdefer keys.deinit();
    keys.secret.replace(secret) catch unreachable;
    keys.key.replace(key[0..profile.key_len]) catch unreachable;
    keys.iv.replace(iv[0..profile.iv_len]) catch unreachable;
    keys.hp.replace(hp[0..profile.hp_key_len]) catch unreachable;
    return keys;
}

/// Derive the next-generation application traffic secret for a key update
/// (RFC 9001 §6.1): `secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku")`.
/// Applies to the 1-RTT read and write secrets only.
pub fn deriveNextGenerationSecret(secret: [traffic_secret_len]u8) [traffic_secret_len]u8 {
    return tls.hkdfExpandLabel(HkdfSha256, secret, "quic ku", "", traffic_secret_len);
}

pub fn deriveNextGenerationSecretWithProvider(provider: crypto_provider.CryptoProvider, secret: [traffic_secret_len]u8) error{ProviderUnsupported}![traffic_secret_len]u8 {
    var out: [traffic_secret_len]u8 = undefined;
    provider.hkdfExpandLabel(.sha256, &secret, "quic ku", "", &out) catch return error.ProviderUnsupported;
    return out;
}

pub fn deriveNextGenerationSecretForProfileWithProvider(provider: crypto_provider.CryptoProvider, profile: PacketProtectionProfile, secret: []const u8, out: []u8) error{ InvalidTrafficSecretLength, ProviderUnsupported }!void {
    if (secret.len != profile.traffic_secret_len or out.len != profile.traffic_secret_len) return error.InvalidTrafficSecretLength;
    if (!provider.capabilities().supportsHash(profile.hash)) return error.ProviderUnsupported;
    provider.hkdfExpandLabel(profile.hash, secret, "quic ku", "", out) catch return error.ProviderUnsupported;
}

pub const ByteRange = struct {
    start: u64,
    end: u64,
};

pub const CryptoStream = struct {
    buffer: [max_crypto_buffer]u8 = undefined,
    ranges: [max_crypto_ranges]ByteRange = undefined,
    range_count: usize = 0,
    base_offset: u64 = 0,
    consumed_offset: u64 = 0,

    pub fn insert(self: *CryptoStream, offset: u64, data: []const u8) error{ CryptoBufferTooLarge, TooManyCryptoRanges }!void {
        if (data.len == 0) return;
        var start = offset;
        var bytes = data;
        const original_end = std.math.add(u64, start, @as(u64, @intCast(bytes.len))) catch return error.CryptoBufferTooLarge;
        if (original_end <= self.consumed_offset) return;
        if (start < self.consumed_offset) {
            const skip: usize = @intCast(self.consumed_offset - start);
            start = self.consumed_offset;
            bytes = bytes[skip..];
        }
        const end = std.math.add(u64, start, @as(u64, @intCast(bytes.len))) catch return error.CryptoBufferTooLarge;
        const window_base = self.consumed_offset;
        if (start < window_base) return error.CryptoBufferTooLarge;
        const checked_relative_start = start - window_base;
        if (checked_relative_start >= max_crypto_buffer) return error.CryptoBufferTooLarge;
        const checked_relative_end = end - window_base;
        if (checked_relative_end > max_crypto_buffer) return error.CryptoBufferTooLarge;

        // Re-anchoring the physical buffer to `consumed_offset` is only
        // needed when the tail genuinely has no room left for this insert
        // at the current anchor -- calling it unconditionally made every
        // insert that followed any prior discard pay a full memmove of
        // everything currently buffered (up to max_crypto_buffer, ~64KB),
        // regardless of how little was actually consumed (#675 campaign
        // finding, same pattern as ByteQueue's discard).
        if (end - self.base_offset > max_crypto_buffer) self.compactConsumed();
        if (start < self.base_offset) return error.CryptoBufferTooLarge;
        const relative_start = start - self.base_offset;
        if (relative_start >= max_crypto_buffer) return error.CryptoBufferTooLarge;
        const relative_end = end - self.base_offset;
        if (relative_end > max_crypto_buffer) return error.CryptoBufferTooLarge;

        try self.addRangeMerged(.{ .start = start, .end = end });
        @memcpy(self.buffer[@intCast(relative_start)..@intCast(relative_end)], bytes);
    }

    pub fn contiguous(self: *const CryptoStream) []const u8 {
        const end = self.contiguousEnd();
        if (end <= self.consumed_offset) return &.{};
        return self.buffer[@intCast(self.consumed_offset - self.base_offset)..@intCast(end - self.base_offset)];
    }

    pub fn discardContiguous(self: *CryptoStream, len: usize) void {
        const available = self.contiguous().len;
        const n = @min(len, available);
        if (n == 0) return;
        const start: usize = @intCast(self.consumed_offset - self.base_offset);
        crypto_secrets.secureZero(self.buffer[start..][0..n]);
        self.consumed_offset += n;
        self.dropConsumedRanges();
    }

    fn compactConsumed(self: *CryptoStream) void {
        if (self.consumed_offset == self.base_offset) return;
        const keep_start = self.consumed_offset;
        const keep_end = self.bufferedEnd();
        const old_end: usize = @intCast(keep_end - self.base_offset);
        if (keep_end > keep_start) {
            const old_start: usize = @intCast(keep_start - self.base_offset);
            const keep_len: usize = @intCast(keep_end - keep_start);
            std.mem.copyForwards(u8, self.buffer[0..keep_len], self.buffer[old_start..][0..keep_len]);
            crypto_secrets.secureZero(self.buffer[keep_len..old_end]);
        } else {
            crypto_secrets.secureZero(self.buffer[0..old_end]);
        }
        self.base_offset = self.consumed_offset;
    }

    fn bufferedEnd(self: *const CryptoStream) u64 {
        var end = self.consumed_offset;
        for (self.ranges[0..self.range_count]) |range| {
            end = @max(end, range.end);
        }
        return end;
    }

    fn addRangeMerged(self: *CryptoStream, new_range: ByteRange) error{TooManyCryptoRanges}!void {
        var merged: [max_crypto_ranges]ByteRange = undefined;
        var merged_count: usize = 0;
        var pending = new_range;
        var inserted = false;

        var index: usize = 0;
        while (index < self.range_count) : (index += 1) {
            const current = self.ranges[index];
            if (current.end < pending.start) {
                try appendRange(&merged, &merged_count, current);
            } else if (pending.end < current.start) {
                if (!inserted) {
                    try appendRange(&merged, &merged_count, pending);
                    inserted = true;
                }
                try appendRange(&merged, &merged_count, current);
            } else {
                pending.start = @min(pending.start, current.start);
                pending.end = @max(pending.end, current.end);
            }
        }
        if (!inserted) try appendRange(&merged, &merged_count, pending);

        @memcpy(self.ranges[0..merged_count], merged[0..merged_count]);
        self.range_count = merged_count;
    }

    fn appendRange(ranges_out: *[max_crypto_ranges]ByteRange, count: *usize, range: ByteRange) error{TooManyCryptoRanges}!void {
        if (count.* == max_crypto_ranges) return error.TooManyCryptoRanges;
        ranges_out[count.*] = range;
        count.* += 1;
    }

    fn contiguousEnd(self: *const CryptoStream) u64 {
        var end = self.consumed_offset;
        var index: usize = 0;
        while (index < self.range_count) : (index += 1) {
            const range = self.ranges[index];
            if (range.end <= end) continue;
            if (range.start > end) break;
            end = range.end;
        }
        return end;
    }

    fn dropConsumedRanges(self: *CryptoStream) void {
        var out: usize = 0;
        var index: usize = 0;
        while (index < self.range_count) : (index += 1) {
            var range = self.ranges[index];
            if (range.end <= self.consumed_offset) continue;
            if (range.start < self.consumed_offset) range.start = self.consumed_offset;
            self.ranges[out] = range;
            out += 1;
        }
        self.range_count = out;
    }
};

pub const CryptoReassembler = struct {
    streams: [4]CryptoStream = .{ .{}, .{}, .{}, .{} },

    pub fn insert(self: *CryptoReassembler, level: EncryptionLevel, offset: u64, data: []const u8) error{ CryptoBufferTooLarge, TooManyCryptoRanges, InvalidCryptoLevel }!void {
        const index = try cryptoStreamIndex(level);
        try self.streams[index].insert(offset, data);
    }

    pub fn contiguous(self: *const CryptoReassembler, level: EncryptionLevel) error{InvalidCryptoLevel}![]const u8 {
        const index = try cryptoStreamIndex(level);
        return self.streams[index].contiguous();
    }

    pub fn discardContiguous(self: *CryptoReassembler, level: EncryptionLevel, len: usize) error{InvalidCryptoLevel}!void {
        const index = try cryptoStreamIndex(level);
        self.streams[index].discardContiguous(len);
    }

    pub fn deinit(self: *CryptoReassembler) void {
        // No `self.* = .{}` afterwards: every default in `CryptoStream` is
        // either zero (`range_count`, `base_offset`, `consumed_offset`) or
        // `undefined` (`buffer`, `ranges`), so the wipe above already leaves
        // exactly the default state. Re-assigning `.{}` only bought a second
        // full-width memset of the same 265 KB -- and on x86_64 that second
        // one is a plain (non-volatile) `@memset`, so it lowered to
        // `compiler_rt.memset`'s byte loop no matter what `secureZero` does
        // (#675). `crypto reassembler deinit leaves the default state`
        // pins the equivalence.
        crypto_secrets.secureZero(std.mem.asBytes(self));
    }
};

pub const HandshakeInput = struct {
    level: EncryptionLevel,
    bytes: []const u8,
};

pub const HandshakeOutput = struct {
    level: EncryptionLevel,
    offset: u64,
    bytes: []const u8,
};

pub const CryptoOutput = struct {
    buffer: [max_crypto_buffer]u8 = undefined,
    start: usize = 0,
    end: usize = 0,
    next_offset: u64 = 0,

    pub fn append(self: *CryptoOutput, bytes: []const u8) error{CryptoBufferTooLarge}!void {
        if (bytes.len == 0) return;
        // Overflow-safe: never form `self.end + bytes.len` at a packet boundary.
        if (bytes.len > max_crypto_buffer - self.end) {
            self.compact();
            if (bytes.len > max_crypto_buffer - self.end) return error.CryptoBufferTooLarge;
        }
        @memcpy(self.buffer[self.end .. self.end + bytes.len], bytes);
        self.end += bytes.len;
    }

    pub fn pending(self: *const CryptoOutput) usize {
        return self.end - self.start;
    }

    pub fn peek(self: *CryptoOutput, max_bytes: usize) ?struct { offset: u64, bytes: []const u8 } {
        const available = self.pending();
        if (available == 0) return null;
        const len = @min(available, max_bytes);
        const offset = self.next_offset;
        const bytes = self.buffer[self.start .. self.start + len];
        return .{ .offset = offset, .bytes = bytes };
    }

    pub fn discardTaken(self: *CryptoOutput, len: usize) void {
        const n = @min(len, self.pending());
        if (n == 0) return;
        crypto_secrets.secureZero(self.buffer[self.start..][0..n]);
        self.start += n;
        self.next_offset += n;
        if (self.start == self.end) {
            self.start = 0;
            self.end = 0;
        }
    }

    fn compact(self: *CryptoOutput) void {
        if (self.start == 0) return;
        const available = self.pending();
        if (available > 0) std.mem.copyForwards(u8, self.buffer[0..available], self.buffer[self.start..self.end]);
        crypto_secrets.secureZero(self.buffer[available..self.end]);
        self.start = 0;
        self.end = available;
    }

    pub fn deinit(self: *CryptoOutput) void {
        // Same reasoning as `CryptoReassembler.deinit`: `start`, `end` and
        // `next_offset` all default to zero and `buffer` is `undefined`, so
        // the wipe already produces the default state and `self.* = .{}`
        // would only pay for a second full-width memset (#675).
        crypto_secrets.secureZero(std.mem.asBytes(self));
    }
};

/// Packet-protection counters exposed for observability (#255) and to satisfy
/// the requirement that deprotection failures are reported deterministically.
pub const Metrics = struct {
    packets_protected: u64 = 0,
    packets_deprotected: u64 = 0,
    deprotection_failures: u64 = 0,
};

pub const QuicTlsAdapter = struct {
    local_transport_parameters: ?config.TransportParameters = null,
    peer_transport_parameters: ?config.TransportParameters = null,
    peer_transport_parameters_authenticated: bool = false,
    reassembler: CryptoReassembler = .{},
    outbound: [4]CryptoOutput = .{ .{}, .{}, .{}, .{} },
    secrets: SecretStore = .{},
    alpn_h3: bool = false,
    certificate_state: CertificateState = .not_checked,
    /// 0-RTT is disabled unless explicitly enabled via config (RFC 9001 §4.6).
    zero_rtt_enabled: bool = false,
    /// 1-RTT key phase bits (RFC 9001 §6). Write and read advance independently:
    /// write flips when this endpoint initiates a key update, read flips when a
    /// peer key update is observed and authenticated.
    application_write_key_phase: u1 = 0,
    application_read_key_phase: u1 = 0,
    metrics: Metrics = .{},
    negotiated_cipher_suite: ?tls_algorithms.CipherSuite = null,
    negotiated_profile: ?PacketProtectionProfile = null,
    zero_rtt_cipher_suite: ?tls_algorithms.CipherSuite = null,
    zero_rtt_profile: ?PacketProtectionProfile = null,
    application_hp: [2]?HeaderProtectionSecret = .{ null, null },
    /// Provider-owned crypto for HKDF, AEAD, and QUIC header-protection
    /// operations (#490). No default: `src/quic/` must not choose a concrete
    /// backend (that decision belongs to the native HTTP/QUIC composition
    /// root), so every adapter is constructed with an explicit, capability-
    /// checked provider via `init` or `setProvider`.
    provider: crypto_provider.CryptoProvider,

    /// Capabilities every QUIC packet-protection profile requires of any
    /// injected provider.
    fn validateProvider(provider: crypto_provider.CryptoProvider) error{ProviderUnsupported}!void {
        try PacketProtectionProfile.forInitial().validateProvider(provider);
        inline for (.{
            tls_algorithms.CipherSuite.tls_aes_128_gcm_sha256,
            tls_algorithms.CipherSuite.tls_aes_256_gcm_sha384,
            tls_algorithms.CipherSuite.tls_chacha20_poly1305_sha256,
        }) |suite| try PacketProtectionProfile.forCipherSuite(suite).validateProvider(provider);
    }

    pub fn init(provider: crypto_provider.CryptoProvider) error{ProviderUnsupported}!QuicTlsAdapter {
        try validateProvider(provider);
        return .{ .provider = provider };
    }

    pub fn setProvider(self: *QuicTlsAdapter, provider: crypto_provider.CryptoProvider) error{ProviderUnsupported}!void {
        try validateProvider(provider);
        self.provider = provider;
    }

    pub fn deinit(self: *QuicTlsAdapter) void {
        self.secrets.deinit();
        self.discardApplicationHeaderProtection();
        self.reassembler.deinit();
        for (&self.outbound) |*out| out.deinit();
        const provider = self.provider;
        crypto_secrets.secureZero(std.mem.asBytes(self));
        self.* = .{ .provider = provider };
    }

    pub fn setLocalTransportParameters(self: *QuicTlsAdapter, params: config.TransportParameters) void {
        self.local_transport_parameters = params;
    }

    /// Record the peer's transport parameters as received in the handshake.
    /// They are not trusted until `authenticatePeerTransportParameters` marks
    /// the handshake authenticated, so `peerTransportParameters` returns null
    /// until then.
    pub fn setPeerTransportParameters(self: *QuicTlsAdapter, params: config.TransportParameters) void {
        self.peer_transport_parameters = params;
        self.peer_transport_parameters_authenticated = false;
    }

    pub fn authenticatePeerTransportParameters(self: *QuicTlsAdapter) void {
        self.peer_transport_parameters_authenticated = true;
    }

    /// The peer's transport parameters, but only once they have been
    /// authenticated through the handshake. Returns null while unauthenticated,
    /// so callers cannot act on unverified parameters.
    pub fn peerTransportParameters(self: *const QuicTlsAdapter) ?config.TransportParameters {
        if (!self.peer_transport_parameters_authenticated) return null;
        return self.peer_transport_parameters;
    }

    /// Whether peer transport parameters have been received at all, regardless
    /// of authentication. The handshake driver uses this to fail deterministically
    /// when a peer completes the handshake without ever sending them.
    pub fn peerTransportParametersReceived(self: *const QuicTlsAdapter) bool {
        return self.peer_transport_parameters != null;
    }

    /// Enable or disable 0-RTT. Off by default; callers wire this from
    /// `config` after making the replay-safety product decision (out of scope
    /// for #249).
    pub fn setZeroRttEnabled(self: *QuicTlsAdapter, enabled: bool) void {
        self.zero_rtt_enabled = enabled;
    }

    pub fn receiveCrypto(self: *QuicTlsAdapter, level: EncryptionLevel, offset: u64, data: []const u8) error{ CryptoBufferTooLarge, TooManyCryptoRanges, InvalidCryptoLevel }!void {
        try self.reassembler.insert(level, offset, data);
    }

    pub fn nextHandshakeInput(self: *QuicTlsAdapter, level: EncryptionLevel) error{InvalidCryptoLevel}!?HandshakeInput {
        const bytes = try self.reassembler.contiguous(level);
        if (bytes.len == 0) return null;
        return .{ .level = level, .bytes = bytes };
    }

    pub fn discardHandshakeInput(self: *QuicTlsAdapter, level: EncryptionLevel, len: usize) error{InvalidCryptoLevel}!void {
        try self.reassembler.discardContiguous(level, len);
    }

    pub fn queueHandshakeOutput(self: *QuicTlsAdapter, level: EncryptionLevel, bytes: []const u8) error{ CryptoBufferTooLarge, InvalidCryptoLevel }!void {
        const index = try cryptoStreamIndex(level);
        try self.outbound[index].append(bytes);
    }

    pub fn nextHandshakeOutput(self: *QuicTlsAdapter, level: EncryptionLevel, max_bytes: usize) error{InvalidCryptoLevel}!?HandshakeOutput {
        const index = try cryptoStreamIndex(level);
        if (max_bytes == 0) return null;
        const output = self.outbound[index].peek(max_bytes) orelse return null;
        return .{ .level = level, .offset = output.offset, .bytes = output.bytes };
    }

    pub fn discardHandshakeOutput(self: *QuicTlsAdapter, level: EncryptionLevel, len: usize) error{InvalidCryptoLevel}!void {
        const index = try cryptoStreamIndex(level);
        self.outbound[index].discardTaken(len);
    }

    pub fn installSecret(self: *QuicTlsAdapter, installed_secret: Secret) void {
        self.captureApplicationHeaderProtection(installed_secret) catch {};
        self.secrets.install(installed_secret);
    }

    pub fn installNegotiatedParameters(self: *QuicTlsAdapter, params: tls_core.events.NegotiatedParameters) error{ InvalidCipherSuite, ProviderUnsupported }!void {
        const selected = try self.packetProtectionProfileFromParameters(params);
        self.negotiated_cipher_suite = selected.suite;
        self.negotiated_profile = selected.profile;
    }

    pub fn installEarlyDataParameters(self: *QuicTlsAdapter, params: tls_core.events.NegotiatedParameters) error{ InvalidCipherSuite, ProviderUnsupported }!void {
        const selected = try self.packetProtectionProfileFromParameters(params);
        self.zero_rtt_cipher_suite = selected.suite;
        self.zero_rtt_profile = selected.profile;
    }

    fn packetProtectionProfileFromParameters(self: *const QuicTlsAdapter, params: tls_core.events.NegotiatedParameters) error{ InvalidCipherSuite, ProviderUnsupported }!struct { suite: tls_algorithms.CipherSuite, profile: PacketProtectionProfile } {
        const suite = tls_algorithms.fromInt(tls_algorithms.CipherSuite, params.cipher_suite) orelse return error.InvalidCipherSuite;
        const profile = PacketProtectionProfile.forCipherSuite(suite);
        if (profile.hash != switch (params.transcript_hash) {
            .sha256 => crypto_provider.Hash.sha256,
            .sha384 => crypto_provider.Hash.sha384,
        }) return error.InvalidCipherSuite;
        try profile.validateProvider(self.provider);
        return .{ .suite = suite, .profile = profile };
    }

    pub fn negotiatedCipherSuite(self: *const QuicTlsAdapter) ?tls_algorithms.CipherSuite {
        return self.negotiated_cipher_suite;
    }

    pub fn zeroRttCipherSuite(self: *const QuicTlsAdapter) ?tls_algorithms.CipherSuite {
        return self.zero_rtt_cipher_suite;
    }

    pub fn secret(self: *const QuicTlsAdapter, level: EncryptionLevel, direction: Direction) ?*const Secret {
        return self.secrets.get(level, direction);
    }

    pub fn installInitialSecrets(self: *QuicTlsAdapter, perspective: Perspective, client_initial_dcid: []const u8) error{ InvalidConnectionId, SecretTooLarge, ProviderUnsupported }!InitialSecrets {
        var secrets = try deriveInitialSecretsV1WithProvider(self.provider, client_initial_dcid);
        errdefer secrets.deinit();
        switch (perspective) {
            .client => {
                self.installSecret(try Secret.init(.initial, .write, secrets.client.secret.slice()));
                self.installSecret(try Secret.init(.initial, .read, secrets.server.secret.slice()));
            },
            .server => {
                self.installSecret(try Secret.init(.initial, .read, secrets.client.secret.slice()));
                self.installSecret(try Secret.init(.initial, .write, secrets.server.secret.slice()));
            },
        }
        return secrets;
    }

    /// Derive AEAD packet-protection keys for `level` in `direction` from the
    /// installed traffic secret. Works for Initial, Handshake, and 1-RTT
    /// (`.application`) once the corresponding secret has been installed —
    /// Initial via `installInitialSecrets`, later levels via `installSecret`
    /// with the TLS-exported traffic secret. Returns null when 0-RTT is
    /// requested but disabled, when no secret is installed, or when its length
    /// does not match the SHA-256 suite. `error.ProviderUnsupported` is
    /// distinct from "no keys": `init`/`setProvider` already reject a provider
    /// missing the required capabilities, so it should not occur once the
    /// adapter is constructed — callers must not fold it into the "no secret
    /// installed" case (that would misreport a configuration bug as an
    /// ordinary missing-key condition, or a receive-path drop as if it were
    /// peer authentication failure).
    pub fn protectionKeys(self: *const QuicTlsAdapter, level: EncryptionLevel, direction: Direction) error{ProviderUnsupported}!?PacketProtectionKeys {
        if (level == .zero_rtt and !self.zero_rtt_enabled) return null;
        const installed_secret = self.secret(level, direction) orelse return null;
        const secret_bytes = installed_secret.slice();
        const profile = self.profileForLevel(level) orelse return null;
        if (secret_bytes.len != profile.traffic_secret_len) return null;
        var keys = derivePacketProtectionKeysWithProvider(self.provider, profile, secret_bytes) catch |err| switch (err) {
            error.InvalidTrafficSecretLength => return null,
            error.ProviderUnsupported => return error.ProviderUnsupported,
        };
        errdefer keys.deinit();
        try self.applyFixedHeaderProtection(level, direction, &keys);
        return keys;
    }

    pub fn hasProtectionKeys(self: *const QuicTlsAdapter, level: EncryptionLevel, direction: Direction) error{ProviderUnsupported}!bool {
        var keys = (try self.protectionKeys(level, direction)) orelse return false;
        defer keys.deinit();
        return true;
    }

    /// Seal `plaintext` for `level`/`direction` into `out`, tracking a protected
    /// packet count. Returns error.KeysUnavailable when no usable secret is
    /// installed for the level.
    pub fn sealPacketPayload(
        self: *QuicTlsAdapter,
        level: EncryptionLevel,
        direction: Direction,
        packet_number: u64,
        header: []const u8,
        plaintext: []const u8,
        out: []u8,
    ) error{ KeysUnavailable, InvalidPacketNumber, OutputTooSmall, ProviderUnsupported }![]u8 {
        var keys = (try self.protectionKeys(level, direction)) orelse return error.KeysUnavailable;
        defer keys.deinit();
        const sealed = try keys.sealPayloadWithProvider(self.provider, packet_number, header, plaintext, out);
        self.metrics.packets_protected += 1;
        return sealed;
    }

    /// Remove packet protection for `level`/`direction`, incrementing the
    /// deprotection counters. Authentication failures are counted separately so
    /// the connection layer can act on repeated forgery deterministically.
    pub fn openPacketPayload(
        self: *QuicTlsAdapter,
        level: EncryptionLevel,
        direction: Direction,
        packet_number: u64,
        header: []const u8,
        protected_payload: []const u8,
        out: []u8,
    ) error{ KeysUnavailable, InvalidPacketNumber, ProtectedPayloadTooShort, OutputTooSmall, AuthenticationFailed, ProviderUnsupported }![]u8 {
        var keys = (try self.protectionKeys(level, direction)) orelse return error.KeysUnavailable;
        defer keys.deinit();
        const plaintext = keys.openPayloadWithProvider(self.provider, packet_number, header, protected_payload, out) catch |err| {
            if (err == error.AuthenticationFailed) self.metrics.deprotection_failures += 1;
            return err;
        };
        self.metrics.packets_deprotected += 1;
        return plaintext;
    }

    /// Key phase bit this endpoint sets on outgoing 1-RTT packets (RFC 9001 §6).
    pub fn applicationWriteKeyPhase(self: *const QuicTlsAdapter) u1 {
        return self.application_write_key_phase;
    }

    /// Key phase bit this endpoint currently decrypts incoming 1-RTT packets
    /// with (RFC 9001 §6). Read and write phases advance independently.
    pub fn applicationReadKeyPhase(self: *const QuicTlsAdapter) u1 {
        return self.application_read_key_phase;
    }

    /// Initiate a local key update: roll the 1-RTT *write* secret to the next
    /// generation and flip the outgoing key phase bit (RFC 9001 §6.1). Read keys
    /// are untouched — the peer's key phase rolls only when its updated packets
    /// are observed. Requires the application write secret to be installed.
    pub fn updateApplicationWriteKeys(self: *QuicTlsAdapter) error{ ApplicationSecretsMissing, ProviderUnsupported }!void {
        const profile = self.profileForLevel(.application) orelse return error.ApplicationSecretsMissing;
        const write_secret = self.applicationTrafficSecret(.write) orelse return error.ApplicationSecretsMissing;
        var next_write: [max_traffic_secret_len]u8 = undefined;
        defer crypto_provider.secureZero(&next_write);
        deriveNextGenerationSecretForProfileWithProvider(self.provider, profile, write_secret, next_write[0..profile.traffic_secret_len]) catch |err| switch (err) {
            error.InvalidTrafficSecretLength => return error.ApplicationSecretsMissing,
            error.ProviderUnsupported => return error.ProviderUnsupported,
        };
        self.installSecret(Secret.init(.application, .write, next_write[0..profile.traffic_secret_len]) catch unreachable);
        self.application_write_key_phase ^= 1;
    }

    /// Next-generation 1-RTT *read* keys for trial-decrypting a peer packet that
    /// carries the opposite key phase bit (RFC 9001 §6.3), without committing to
    /// them. Returns null when no application read secret is installed. Commit
    /// with `commitApplicationReadKeyUpdate` only after such a packet
    /// authenticates. See `protectionKeys` for why `ProviderUnsupported` is
    /// kept distinct from "no keys".
    pub fn nextApplicationReadKeys(self: *const QuicTlsAdapter) error{ProviderUnsupported}!?PacketProtectionKeys {
        const profile = self.profileForLevel(.application) orelse return null;
        const read_secret = self.applicationTrafficSecret(.read) orelse return null;
        var next_read: [max_traffic_secret_len]u8 = undefined;
        defer crypto_provider.secureZero(&next_read);
        deriveNextGenerationSecretForProfileWithProvider(self.provider, profile, read_secret, next_read[0..profile.traffic_secret_len]) catch |err| switch (err) {
            error.InvalidTrafficSecretLength => return null,
            error.ProviderUnsupported => return error.ProviderUnsupported,
        };
        var keys = derivePacketProtectionKeysWithProvider(self.provider, profile, next_read[0..profile.traffic_secret_len]) catch |err| switch (err) {
            error.InvalidTrafficSecretLength => return null,
            error.ProviderUnsupported => return error.ProviderUnsupported,
        };
        errdefer keys.deinit();
        try self.applyFixedHeaderProtection(.application, .read, &keys);
        return keys;
    }

    /// Commit the next-generation 1-RTT *read* secret after a peer key update
    /// has been authenticated, flipping the incoming key phase bit (RFC 9001
    /// §6.3). Write keys and the outgoing phase are untouched.
    pub fn commitApplicationReadKeyUpdate(self: *QuicTlsAdapter) error{ ApplicationSecretsMissing, ProviderUnsupported }!void {
        const profile = self.profileForLevel(.application) orelse return error.ApplicationSecretsMissing;
        const read_secret = self.applicationTrafficSecret(.read) orelse return error.ApplicationSecretsMissing;
        var next_read: [max_traffic_secret_len]u8 = undefined;
        defer crypto_provider.secureZero(&next_read);
        deriveNextGenerationSecretForProfileWithProvider(self.provider, profile, read_secret, next_read[0..profile.traffic_secret_len]) catch |err| switch (err) {
            error.InvalidTrafficSecretLength => return error.ApplicationSecretsMissing,
            error.ProviderUnsupported => return error.ProviderUnsupported,
        };
        self.installSecret(Secret.init(.application, .read, next_read[0..profile.traffic_secret_len]) catch unreachable);
        self.application_read_key_phase ^= 1;
    }

    fn applicationTrafficSecret(self: *const QuicTlsAdapter, direction: Direction) ?[]const u8 {
        const installed_secret = self.secret(.application, direction) orelse return null;
        const secret_bytes = installed_secret.slice();
        const profile = self.profileForLevel(.application) orelse return null;
        if (secret_bytes.len != profile.traffic_secret_len) return null;
        return secret_bytes;
    }

    fn captureApplicationHeaderProtection(self: *QuicTlsAdapter, installed_secret: Secret) error{ProviderUnsupported}!void {
        if (installed_secret.level != .application) return;
        const slot = &self.application_hp[@intFromEnum(installed_secret.direction)];
        if (slot.* != null) return;
        const profile = self.profileForLevel(.application) orelse return;
        const secret_bytes = installed_secret.slice();
        if (secret_bytes.len != profile.traffic_secret_len) return;
        var keys = derivePacketProtectionKeysWithProvider(self.provider, profile, secret_bytes) catch |err| switch (err) {
            error.InvalidTrafficSecretLength => return,
            error.ProviderUnsupported => return error.ProviderUnsupported,
        };
        defer keys.deinit();
        slot.* = .{};
        slot.*.?.replace(keys.hp.slice()) catch unreachable;
    }

    fn applyFixedHeaderProtection(self: *const QuicTlsAdapter, level: EncryptionLevel, direction: Direction, keys: *PacketProtectionKeys) error{ProviderUnsupported}!void {
        if (level != .application) return;
        if (self.application_hp[@intFromEnum(direction)]) |*hp| {
            keys.hp.replace(hp.slice()) catch unreachable;
        }
    }

    fn discardApplicationHeaderProtection(self: *QuicTlsAdapter) void {
        for (&self.application_hp) |*slot| {
            if (slot.*) |*hp| hp.deinit();
            slot.* = null;
        }
    }

    fn profileForLevel(self: *const QuicTlsAdapter, level: EncryptionLevel) ?PacketProtectionProfile {
        return switch (level) {
            .initial => PacketProtectionProfile.forInitial(),
            .zero_rtt => self.zero_rtt_profile,
            .handshake, .application => self.negotiated_profile,
        };
    }

    pub fn discardSecrets(self: *QuicTlsAdapter, level: EncryptionLevel) void {
        self.secrets.discard(level);
        if (level == .application) self.discardApplicationHeaderProtection();
    }

    pub fn markAlpn(self: *QuicTlsAdapter, protocol: []const u8) void {
        self.alpn_h3 = std.mem.eql(u8, protocol, "h3");
    }

    /// Whether ALPN negotiated `h3` for the future HTTP/3 layer.
    pub fn negotiatedH3(self: *const QuicTlsAdapter) bool {
        return self.alpn_h3;
    }

    /// Report the peer certificate validation outcome from the TLS backend.
    pub fn setCertificateState(self: *QuicTlsAdapter, state: CertificateState) void {
        self.certificate_state = state;
    }

    pub fn certificateState(self: *const QuicTlsAdapter) CertificateState {
        return self.certificate_state;
    }
};

const testing = std.testing;

fn expectHex(comptime hex: []const u8, actual: []const u8) !void {
    var expected: [hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, hex);
    try testing.expectEqualSlices(u8, &expected, actual);
}

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var bytes: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}

fn transcriptHashEvent(hash: crypto_provider.Hash) tls_core.events.TranscriptHash {
    return switch (hash) {
        .sha256 => .sha256,
        .sha384 => .sha384,
    };
}

fn testSecret(seed: u8) [max_traffic_secret_len]u8 {
    var out: [max_traffic_secret_len]u8 = undefined;
    for (&out, 0..) |*byte, i| byte.* = seed +% @as(u8, @truncate(i * 13));
    return out;
}

test "encryption levels map to QUIC packet number spaces" {
    try testing.expectEqual(PacketNumberSpace.initial, EncryptionLevel.initial.packetNumberSpace());
    try testing.expectEqual(PacketNumberSpace.handshake, EncryptionLevel.handshake.packetNumberSpace());
    try testing.expectEqual(PacketNumberSpace.application, EncryptionLevel.zero_rtt.packetNumberSpace());
    try testing.expectEqual(PacketNumberSpace.application, EncryptionLevel.application.packetNumberSpace());
}

test "QUIC v1 Initial secrets match RFC 9001 sample vector" {
    var dcid: [8]u8 = undefined;
    _ = try std.fmt.hexToBytes(&dcid, "8394c8f03e515708");

    var secrets = try deriveInitialSecretsV1(&dcid);
    defer secrets.deinit();
    try expectHex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44", &secrets.initial_secret);
    try expectHex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea", secrets.client.secret.slice());
    try expectHex("1f369613dd76d5467730efcbe3b1a22d", secrets.client.key.slice());
    try expectHex("fa044b2f42a3fd3b46fb255c", secrets.client.iv.slice());
    try expectHex("9f50449e04a0e810283a1e9933adedd2", secrets.client.hp.slice());
    try expectHex("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b", secrets.server.secret.slice());
    try expectHex("cf3a5331653c364c88f0f379b6067e37", secrets.server.key.slice());
    try expectHex("0ac1493ca1905853b0bba03e", secrets.server.iv.slice());
    try expectHex("c206b8d9b9f0f37644430b490eeaa314", secrets.server.hp.slice());
}

test "Initial packet protection derives nonce and header protection mask" {
    var dcid: [8]u8 = undefined;
    _ = try std.fmt.hexToBytes(&dcid, "8394c8f03e515708");
    var secrets = try deriveInitialSecretsV1(&dcid);
    defer secrets.deinit();

    try expectHex("fa044b2f42a3fd3b46fb255e", &secrets.client.nonce(2));

    var sample: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sample, "d1b1c98dd7689fb8ec11d242b123dc9b");
    try expectHex("437b9aec36", &secrets.client.headerProtectionMask(sample));
}

test "Initial packet protection seals RFC 9001 client Initial payload sample" {
    var dcid: [8]u8 = undefined;
    _ = try std.fmt.hexToBytes(&dcid, "8394c8f03e515708");
    var secrets = try deriveInitialSecretsV1(&dcid);
    defer secrets.deinit();

    var header: [22]u8 = undefined;
    _ = try std.fmt.hexToBytes(&header, "c300000001088394c8f03e5157080000449e00000002");
    const crypto_frame = hexBytes(
        "060040f1010000ed0303ebf8fa56f129" ++
            "39b9584a3896472ec40bb863cfd3e868" ++
            "04fe3a47f06a2b69484c000004130113" ++
            "02010000c000000010000e00000b6578" ++
            "616d706c652e636f6dff01000100000a" ++
            "00080006001d00170018001000070005" ++
            "04616c706e0005000501000000000033" ++
            "00260024001d00209370b2c9caa47fba" ++
            "baf4559fedba753de171fa71f50f1ce1" ++
            "5d43e994ec74d748002b000302030400" ++
            "0d0010000e0403050306030203080408" ++
            "050806002d00020101001c0002400100" ++
            "3900320408ffffffffffffffff050480" ++
            "00ffff07048000ffff08011001048000" ++
            "75300901100f088394c8f03e51570806" ++
            "048000ffff",
    );
    var plaintext = [_]u8{0} ** 1162;
    @memcpy(plaintext[0..crypto_frame.len], &crypto_frame);

    var protected_payload: [1178]u8 = undefined;
    const sealed = try secrets.client.sealPayload(2, &header, &plaintext, &protected_payload);
    try testing.expectEqual(@as(usize, plaintext.len + packet_protection_tag_len), sealed.len);
    const expected_protected_payload = hexBytes(
        "d1b1c98dd7689fb8ec11d242b123dc9b" ++
            "d8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399" ++
            "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c" ++
            "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212" ++
            "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5" ++
            "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208" ++
            "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec" ++
            "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3" ++
            "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db" ++
            "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c" ++
            "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8" ++
            "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556" ++
            "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74" ++
            "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a" ++
            "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00" ++
            "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632" ++
            "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964" ++
            "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd" ++
            "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff" ++
            "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198" ++
            "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd" ++
            "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73" ++
            "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f" ++
            "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e" ++
            "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade" ++
            "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047" ++
            "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2" ++
            "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4" ++
            "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0" ++
            "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e" ++
            "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0" ++
            "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400" ++
            "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab" ++
            "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9" ++
            "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4" ++
            "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064" ++
            "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241" ++
            "e221af44860018ab0856972e194cd934",
    );
    try testing.expectEqualSlices(u8, &expected_protected_payload, sealed);

    var opened: [1162]u8 = undefined;
    const unsealed = try secrets.client.openPayload(2, &header, sealed, &opened);
    try testing.expectEqualSlices(u8, &plaintext, unsealed);
}

test "Initial packet protection rejects invalid inputs" {
    var dcid: [8]u8 = undefined;
    _ = try std.fmt.hexToBytes(&dcid, "8394c8f03e515708");
    var secrets = try deriveInitialSecretsV1(&dcid);
    defer secrets.deinit();
    const header = "test header";
    const plaintext = "ping";

    var too_small_seal: [plaintext.len + packet_protection_tag_len - 1]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, secrets.client.sealPayload(0, header, plaintext, &too_small_seal));

    var protected_payload: [plaintext.len + packet_protection_tag_len]u8 = undefined;
    const sealed = try secrets.client.sealPayload(0, header, plaintext, &protected_payload);

    try testing.expectError(error.InvalidPacketNumber, secrets.client.sealPayload(max_packet_number + 1, header, plaintext, &protected_payload));

    var too_small_open: [plaintext.len - 1]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, secrets.client.openPayload(0, header, sealed, &too_small_open));
    try testing.expectError(error.ProtectedPayloadTooShort, secrets.client.openPayload(0, header, sealed[0 .. packet_protection_tag_len - 1], &too_small_open));

    var opened: [plaintext.len]u8 = undefined;
    try testing.expectError(error.InvalidPacketNumber, secrets.client.openPayload(max_packet_number + 1, header, sealed, &opened));
    try testing.expectError(error.AuthenticationFailed, secrets.server.openPayload(0, header, sealed, &opened));

    var tampered = protected_payload;
    tampered[0] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, secrets.client.openPayload(0, header, &tampered, &opened));
}

test "Initial secrets reject invalid destination connection IDs" {
    try testing.expectError(error.InvalidConnectionId, deriveInitialSecretsV1(""));
    const too_short = [_]u8{0xaa} ** (min_initial_dcid_len - 1);
    try testing.expectError(error.InvalidConnectionId, deriveInitialSecretsV1(&too_short));

    const min_len = [_]u8{0xbb} ** min_initial_dcid_len;
    var min_secrets = try deriveInitialSecretsV1(&min_len);
    min_secrets.deinit();

    const too_long = [_]u8{0xaa} ** (max_connection_id_len + 1);
    try testing.expectError(error.InvalidConnectionId, deriveInitialSecretsV1(&too_long));
}

test "provider Initial derivation cleans partial client keys when server derivation fails" {
    const FaultProvider = struct {
        base: crypto_provider.CryptoProvider,
        quic_key_expands: usize = 0,

        fn provider(self: *@This()) crypto_provider.CryptoProvider {
            return .{
                .context = self,
                .vtable = &vtable,
                .entropy = self.base.entropy,
            };
        }

        fn from(ctx: *anyopaque) *@This() {
            return @ptrCast(@alignCast(ctx));
        }

        fn capabilities(ctx: *anyopaque) crypto_provider.Capabilities {
            const self = from(ctx);
            return self.base.capabilities();
        }

        fn hkdfExtract(ctx: *anyopaque, hash: crypto_provider.Hash, salt: []const u8, ikm: []const u8, out: []u8) crypto_provider.HkdfError!void {
            const self = from(ctx);
            return self.base.hkdfExtract(hash, salt, ikm, out);
        }

        fn hkdfExpandLabel(ctx: *anyopaque, hash: crypto_provider.Hash, secret: []const u8, label: []const u8, hash_context: []const u8, out: []u8) crypto_provider.HkdfError!void {
            const self = from(ctx);
            if (std.mem.eql(u8, label, "quic key")) {
                self.quic_key_expands += 1;
                if (self.quic_key_expands == 2) return error.UnsupportedCapability;
            }
            return self.base.hkdfExpandLabel(hash, secret, label, hash_context, out);
        }

        fn aeadSeal(ctx: *anyopaque, aead: crypto_provider.Aead, key: []const u8, nonce: []const u8, associated_data: []const u8, plaintext: []const u8, ciphertext: []u8, tag: []u8) crypto_provider.SealError!void {
            const self = from(ctx);
            return self.base.aeadSeal(aead, key, nonce, associated_data, plaintext, ciphertext, tag);
        }

        fn aeadOpen(ctx: *anyopaque, aead: crypto_provider.Aead, key: []const u8, nonce: []const u8, associated_data: []const u8, ciphertext: []const u8, tag: []const u8, plaintext: []u8) crypto_provider.OpenError!void {
            const self = from(ctx);
            return self.base.aeadOpen(aead, key, nonce, associated_data, ciphertext, tag, plaintext);
        }

        fn quicHeaderProtectionMask(ctx: *anyopaque, hp: crypto_provider.QuicHeaderProtection, key: []const u8, sample: []const u8, mask: []u8) crypto_provider.QuicHeaderProtectionError!void {
            const self = from(ctx);
            return self.base.quicHeaderProtectionMask(hp, key, sample, mask);
        }

        fn generateKeyShare(ctx: *anyopaque, group: crypto_provider.Group, public_out: []u8, private_out: []u8) crypto_provider.KeyShareError!void {
            const self = from(ctx);
            return self.base.generateKeyShare(group, public_out, private_out);
        }

        fn deriveSharedSecret(ctx: *anyopaque, group: crypto_provider.Group, private_scalar: []const u8, peer_public: []const u8, out: []u8) crypto_provider.DeriveError!void {
            const self = from(ctx);
            return self.base.deriveSharedSecret(group, private_scalar, peer_public, out);
        }

        fn verify(ctx: *anyopaque, scheme: crypto_provider.SignatureScheme, public_key: []const u8, message: []const u8, signature: []const u8) crypto_provider.VerifyError!void {
            const self = from(ctx);
            return self.base.verify(scheme, public_key, message, signature);
        }

        const vtable = crypto_provider.CryptoProvider.VTable{
            .capabilities = capabilities,
            .hkdfExtract = hkdfExtract,
            .hkdfExpandLabel = hkdfExpandLabel,
            .aeadSeal = aeadSeal,
            .aeadOpen = aeadOpen,
            .quicHeaderProtectionMask = quicHeaderProtectionMask,
            .generateKeyShare = generateKeyShare,
            .deriveSharedSecret = deriveSharedSecret,
            .verify = verify,
        };
    };

    var fault = FaultProvider{ .base = test_quic_crypto.testDefaultProvider() };
    const dcid = [_]u8{0x83} ** min_initial_dcid_len;
    try testing.expectError(error.ProviderUnsupported, deriveInitialSecretsV1WithProvider(fault.provider(), &dcid));
    try testing.expectEqual(@as(usize, 2), fault.quic_key_expands);
}

test "adapter installs Initial secrets by endpoint perspective" {
    var dcid: [8]u8 = undefined;
    _ = try std.fmt.hexToBytes(&dcid, "8394c8f03e515708");

    var client = QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
    var client_secrets = try client.installInitialSecrets(.client, &dcid);
    defer client_secrets.deinit();
    try testing.expectEqualSlices(u8, client_secrets.client.secret.slice(), client.secret(.initial, .write).?.slice());
    try testing.expectEqualSlices(u8, client_secrets.server.secret.slice(), client.secret(.initial, .read).?.slice());
    var client_write_keys = (try client.protectionKeys(.initial, .write)).?;
    defer client_write_keys.deinit();
    try testing.expectEqualSlices(u8, client_secrets.client.key.slice(), client_write_keys.key.slice());

    var server = QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
    var server_secrets = try server.installInitialSecrets(.server, &dcid);
    defer server_secrets.deinit();
    try testing.expectEqualSlices(u8, server_secrets.client.secret.slice(), server.secret(.initial, .read).?.slice());
    try testing.expectEqualSlices(u8, server_secrets.server.secret.slice(), server.secret(.initial, .write).?.slice());
    var server_write_keys = (server.protectionKeys(.initial, .write) catch unreachable).?;
    defer server_write_keys.deinit();
    try testing.expectEqualSlices(u8, server_secrets.server.hp.slice(), server_write_keys.hp.slice());
}

test "adapter derives Handshake and 1-RTT protection keys from installed traffic secrets" {
    var adapter = QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
    try adapter.installNegotiatedParameters(.{ .cipher_suite = @intFromEnum(tls_algorithms.CipherSuite.tls_aes_128_gcm_sha256), .transcript_hash = .sha256 });

    // No secret installed yet: every non-Initial level reports no keys.
    try testing.expectEqual(@as(?PacketProtectionKeys, null), adapter.protectionKeys(.handshake, .write));
    try testing.expectEqual(@as(?PacketProtectionKeys, null), adapter.protectionKeys(.application, .read));

    var hs_secret: [traffic_secret_len]u8 = undefined;
    for (&hs_secret, 0..) |*byte, i| byte.* = @intCast((i * 7 + 3) & 0xff);
    var app_secret: [traffic_secret_len]u8 = undefined;
    for (&app_secret, 0..) |*byte, i| byte.* = @intCast((i * 5 + 1) & 0xff);

    adapter.installSecret(try Secret.init(.handshake, .write, &hs_secret));
    adapter.installSecret(try Secret.init(.application, .read, &app_secret));

    // The adapter path matches the standalone derivation for the same suite.
    var hs_keys = (try adapter.protectionKeys(.handshake, .write)).?;
    defer hs_keys.deinit();
    var expected_hs = deriveAes128GcmKeys(hs_secret);
    defer expected_hs.deinit();
    try testing.expectEqualSlices(u8, expected_hs.key.slice(), hs_keys.key.slice());
    try testing.expectEqualSlices(u8, expected_hs.iv.slice(), hs_keys.iv.slice());
    try testing.expectEqualSlices(u8, expected_hs.hp.slice(), hs_keys.hp.slice());

    var app_keys = (adapter.protectionKeys(.application, .read) catch unreachable).?;
    defer app_keys.deinit();
    var expected_app = deriveAes128GcmKeys(app_secret);
    defer expected_app.deinit();
    try testing.expectEqualSlices(u8, expected_app.key.slice(), app_keys.key.slice());

    // Direction is honored: the untouched direction stays empty.
    try testing.expectEqual(@as(?PacketProtectionKeys, null), adapter.protectionKeys(.handshake, .read));
    try testing.expectEqual(@as(?PacketProtectionKeys, null), adapter.protectionKeys(.application, .write));
}

test "negotiated QUIC packet protection follows all supported TLS suites" {
    inline for (.{
        tls_algorithms.CipherSuite.tls_aes_128_gcm_sha256,
        tls_algorithms.CipherSuite.tls_aes_256_gcm_sha384,
        tls_algorithms.CipherSuite.tls_chacha20_poly1305_sha256,
    }) |suite| {
        const profile = PacketProtectionProfile.forCipherSuite(suite);
        var adapter = QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
        try adapter.installNegotiatedParameters(.{
            .cipher_suite = @intFromEnum(suite),
            .transcript_hash = transcriptHashEvent(profile.hash),
        });
        try testing.expectEqual(suite, adapter.negotiatedCipherSuite().?);

        var secret = testSecret(@intCast(@intFromEnum(suite) & 0xff));
        defer crypto_provider.secureZero(&secret);
        adapter.installSecret(try Secret.init(.handshake, .write, secret[0..profile.traffic_secret_len]));
        adapter.installSecret(try Secret.init(.handshake, .read, secret[0..profile.traffic_secret_len]));
        adapter.installSecret(try Secret.init(.application, .write, secret[0..profile.traffic_secret_len]));
        adapter.installSecret(try Secret.init(.application, .read, secret[0..profile.traffic_secret_len]));

        var hs_keys = (try adapter.protectionKeys(.handshake, .write)).?;
        defer hs_keys.deinit();
        try testing.expectEqual(profile.aead, hs_keys.profile.aead);
        try testing.expectEqual(profile.header_protection, hs_keys.profile.header_protection);
        try testing.expectEqual(profile.key_len, hs_keys.key.slice().len);
        try testing.expectEqual(profile.iv_len, hs_keys.iv.slice().len);
        try testing.expectEqual(profile.hp_key_len, hs_keys.hp.slice().len);
        try testing.expectEqual(profile.traffic_secret_len, hs_keys.secret.slice().len);

        const header = "\x50\x00\x00\x00\x09";
        const plaintext = "negotiated QUIC packet payload";
        var sealed: [128]u8 = undefined;
        const protected = try adapter.sealPacketPayload(.handshake, .write, 9, header, plaintext, &sealed);
        try testing.expectEqual(plaintext.len + profile.tag_len, protected.len);

        var opened: [128]u8 = undefined;
        const recovered = try adapter.openPacketPayload(.handshake, .read, 9, header, protected, &opened);
        try testing.expectEqualSlices(u8, plaintext, recovered);

        var first_byte: u8 = 0x42;
        var pn_field = [_]u8{ 0xaa, 0xbb };
        const sample = [_]u8{0x5c} ** header_protection_sample_len;
        try hs_keys.applyHeaderProtectionWithProvider(adapter.provider, &first_byte, &pn_field, sample);
        var sampled_pn = [_]u8{ pn_field[0], pn_field[1], 0, 0 };
        const removed = try hs_keys.removeHeaderProtectionWithProvider(adapter.provider, &first_byte, &sampled_pn, sample);
        try testing.expectEqual(@as(u8, 0x42), first_byte);
        try testing.expectEqual(@as(usize, 3), removed.packet_number_length);
        try testing.expectEqual(@as(u8, 0xaa), sampled_pn[0]);
        try testing.expectEqual(@as(u8, 0xbb), sampled_pn[1]);

        var write_before = (try adapter.protectionKeys(.application, .write)).?;
        defer write_before.deinit();
        try adapter.updateApplicationWriteKeys();
        var write_after = (try adapter.protectionKeys(.application, .write)).?;
        defer write_after.deinit();
        try testing.expectEqual(profile.key_len, write_after.key.slice().len);
        try testing.expect(!std.mem.eql(u8, write_before.key.slice(), write_after.key.slice()));

        var trial_read = (try adapter.nextApplicationReadKeys()).?;
        defer trial_read.deinit();
        try testing.expectEqual(profile.key_len, trial_read.key.slice().len);
        try adapter.commitApplicationReadKeyUpdate();
        var read_after = (try adapter.protectionKeys(.application, .read)).?;
        defer read_after.deinit();
        try testing.expectEqualSlices(u8, trial_read.key.slice(), read_after.key.slice());
    }
}

test "0-RTT packet protection uses resumed suite before negotiated parameters" {
    inline for (.{
        tls_algorithms.CipherSuite.tls_aes_128_gcm_sha256,
        tls_algorithms.CipherSuite.tls_aes_256_gcm_sha384,
        tls_algorithms.CipherSuite.tls_chacha20_poly1305_sha256,
    }) |suite| {
        const profile = PacketProtectionProfile.forCipherSuite(suite);
        var client = QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
        var server = QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
        const params: tls_core.events.NegotiatedParameters = .{
            .cipher_suite = @intFromEnum(suite),
            .transcript_hash = transcriptHashEvent(profile.hash),
        };
        try client.installEarlyDataParameters(params);
        try server.installEarlyDataParameters(params);
        client.setZeroRttEnabled(true);
        server.setZeroRttEnabled(true);
        try testing.expectEqual(@as(?tls_algorithms.CipherSuite, null), client.negotiatedCipherSuite());
        try testing.expectEqual(suite, client.zeroRttCipherSuite().?);

        var secret = testSecret(@intCast((@intFromEnum(suite) >> 8) & 0xff));
        defer crypto_provider.secureZero(&secret);
        client.installSecret(try Secret.init(.zero_rtt, .write, secret[0..profile.traffic_secret_len]));
        server.installSecret(try Secret.init(.zero_rtt, .read, secret[0..profile.traffic_secret_len]));

        var client_keys = (try client.protectionKeys(.zero_rtt, .write)).?;
        defer client_keys.deinit();
        try testing.expectEqual(profile.aead, client_keys.profile.aead);
        try testing.expectEqual(profile.header_protection, client_keys.profile.header_protection);
        try testing.expectEqual(@as(?PacketProtectionKeys, null), client.protectionKeys(.handshake, .write));

        const header = "\xd0\x00\x00\x00\x01\x00";
        const plaintext = "real zero-rtt payload before server hello";
        var sealed: [128]u8 = undefined;
        const protected = try client.sealPacketPayload(.zero_rtt, .write, 1, header, plaintext, &sealed);
        var opened: [128]u8 = undefined;
        const recovered = try server.openPacketPayload(.zero_rtt, .read, 1, header, protected, &opened);
        try testing.expectEqualSlices(u8, plaintext, recovered);
    }
}

test "application key updates keep header protection key fixed for all suites" {
    inline for (.{
        tls_algorithms.CipherSuite.tls_aes_128_gcm_sha256,
        tls_algorithms.CipherSuite.tls_aes_256_gcm_sha384,
        tls_algorithms.CipherSuite.tls_chacha20_poly1305_sha256,
    }) |suite| {
        const profile = PacketProtectionProfile.forCipherSuite(suite);
        var client = QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
        var server = QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
        const params: tls_core.events.NegotiatedParameters = .{
            .cipher_suite = @intFromEnum(suite),
            .transcript_hash = transcriptHashEvent(profile.hash),
        };
        try client.installNegotiatedParameters(params);
        try server.installNegotiatedParameters(params);

        var secret = testSecret(@intCast((@intFromEnum(suite) + 0x31) & 0xff));
        defer crypto_provider.secureZero(&secret);
        client.installSecret(try Secret.init(.application, .write, secret[0..profile.traffic_secret_len]));
        server.installSecret(try Secret.init(.application, .read, secret[0..profile.traffic_secret_len]));

        var client_before = (try client.protectionKeys(.application, .write)).?;
        defer client_before.deinit();
        var server_before = (try server.protectionKeys(.application, .read)).?;
        defer server_before.deinit();

        try client.updateApplicationWriteKeys();
        var client_after = (try client.protectionKeys(.application, .write)).?;
        defer client_after.deinit();
        var server_trial = (try server.nextApplicationReadKeys()).?;
        defer server_trial.deinit();

        try testing.expectEqualSlices(u8, client_before.hp.slice(), client_after.hp.slice());
        try testing.expectEqualSlices(u8, server_before.hp.slice(), server_trial.hp.slice());
        try testing.expect(!std.mem.eql(u8, client_before.key.slice(), client_after.key.slice()));
        try testing.expect(!std.mem.eql(u8, client_before.iv.slice(), client_after.iv.slice()));

        var packet_bytes: [128]u8 = undefined;
        const pn_offset: usize = 1;
        const pn_len: usize = 2;
        packet_bytes[0] = 0x40 | 0x04 | 0x01; // short header, key phase 1, two-byte PN
        packet_bytes[1] = 0x00;
        packet_bytes[2] = 0x07;
        const header = packet_bytes[0..3];
        const plaintext = "new phase packet long enough for hp sample";
        const ciphertext = try client_after.sealPayloadWithProvider(client.provider, 7, header, plaintext, packet_bytes[3..]);
        const sample = packet_bytes[pn_offset + 4 ..][0..header_protection_sample_len].*;
        try client_after.applyHeaderProtectionWithProvider(client.provider, &packet_bytes[0], packet_bytes[pn_offset..][0..pn_len], sample);

        var sampled_pn: [max_packet_number_length]u8 = packet_bytes[pn_offset..][0..max_packet_number_length].*;
        const removed = try server_before.removeHeaderProtectionWithProvider(server.provider, &packet_bytes[0], &sampled_pn, sample);
        try testing.expectEqual(@as(usize, pn_len), removed.packet_number_length);
        @memcpy(packet_bytes[pn_offset..][0..pn_len], sampled_pn[0..pn_len]);
        const recovered_header = packet_bytes[0 .. pn_offset + pn_len];
        var opened: [128]u8 = undefined;
        const recovered = try server_trial.openPayloadWithProvider(server.provider, removed.truncated_packet_number, recovered_header, ciphertext, &opened);
        try testing.expectEqualSlices(u8, plaintext, recovered);
    }
}

test "packet protection round-trips at Handshake and 1-RTT levels" {
    var adapter = QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
    try adapter.installNegotiatedParameters(.{ .cipher_suite = @intFromEnum(tls_algorithms.CipherSuite.tls_aes_128_gcm_sha256), .transcript_hash = .sha256 });
    const secret = hexBytes("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    adapter.installSecret(try Secret.init(.handshake, .write, &secret));
    adapter.installSecret(try Secret.init(.application, .write, &secret));

    const header = "\xe0\x00\x00\x00\x01";
    const plaintext = "handshake and 1-rtt payloads use the same AEAD path";

    for ([_]EncryptionLevel{ .handshake, .application }) |level| {
        var keys = (try adapter.protectionKeys(level, .write)).?;
        defer keys.deinit();

        var sealed: [128]u8 = undefined;
        const protected = try keys.sealPayload(7, header, plaintext, &sealed);
        try testing.expectEqual(plaintext.len + packet_protection_tag_len, protected.len);

        var opened: [128]u8 = undefined;
        const recovered = try keys.openPayload(7, header, protected, &opened);
        try testing.expectEqualSlices(u8, plaintext, recovered);

        // A different packet number changes the nonce and fails authentication.
        try testing.expectError(error.AuthenticationFailed, keys.openPayload(8, header, protected, &opened));
    }
}

test "protection keys reject a traffic secret of the wrong length" {
    var adapter = QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
    const short_secret = [_]u8{0xab} ** (traffic_secret_len - 1);
    adapter.installSecret(try Secret.init(.application, .write, &short_secret));
    try testing.expectEqual(@as(?PacketProtectionKeys, null), adapter.protectionKeys(.application, .write));
}

test "header protection matches the RFC 9001 client Initial sample" {
    var dcid: [8]u8 = undefined;
    _ = try std.fmt.hexToBytes(&dcid, "8394c8f03e515708");
    var secrets = try deriveInitialSecretsV1(&dcid);
    defer secrets.deinit();
    const sample = hexBytes("d1b1c98dd7689fb8ec11d242b123dc9b");

    // Apply: unprotected long header 0xc3 + 4-byte packet number 2 protect to
    // the wire bytes shown in RFC 9001 Appendix A.2.
    var first_byte: u8 = 0xc3;
    var pn_field = [_]u8{ 0x00, 0x00, 0x00, 0x02 };
    secrets.client.applyHeaderProtection(&first_byte, &pn_field, sample);
    try testing.expectEqual(@as(u8, 0xc0), first_byte);
    try expectHex("7b9aec34", &pn_field);

    // Remove: reverse the transformation and recover the packet-number length
    // from the unmasked first byte.
    var protected_first: u8 = 0xc0;
    var sampled_pn = [_]u8{ 0x7b, 0x9a, 0xec, 0x34 };
    const removed = secrets.client.removeHeaderProtection(&protected_first, &sampled_pn, sample);
    try testing.expectEqual(@as(u8, 0xc3), protected_first);
    try testing.expectEqual(@as(usize, 4), removed.packet_number_length);
    try testing.expectEqual(@as(u64, 2), removed.truncated_packet_number);

    // Packet-number reconstruction is wired through the packet layer.
    const pn_bits: u6 = @intCast(removed.packet_number_length * 8);
    try testing.expectEqual(@as(u64, 2), packet.decodePacketNumber(1, removed.truncated_packet_number, pn_bits));
}

test "header protection round-trips for short headers" {
    const secret = hexBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    var keys = deriveAes128GcmKeys(secret);
    defer keys.deinit();
    const sample = hexBytes("101112131415161718191a1b1c1d1e1f");

    // Short header (high bit clear), 1-byte packet number, key phase bit set.
    var first_byte: u8 = 0x50;
    var pn_field = [_]u8{0x9c};
    keys.applyHeaderProtection(&first_byte, &pn_field, sample);

    var sampled_pn = [_]u8{ pn_field[0], 0x00, 0x00, 0x00 };
    const removed = keys.removeHeaderProtection(&first_byte, &sampled_pn, sample);
    try testing.expectEqual(@as(u8, 0x50), first_byte);
    try testing.expectEqual(@as(usize, 1), removed.packet_number_length);
    try testing.expectEqual(@as(u64, 0x9c), removed.truncated_packet_number);
}

test "key update derives chained next-generation secrets" {
    const s0 = hexBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const s1 = deriveNextGenerationSecret(s0);
    const s2 = deriveNextGenerationSecret(s1);
    try testing.expect(!std.mem.eql(u8, &s0, &s1));
    try testing.expect(!std.mem.eql(u8, &s1, &s2));
    // Deterministic for a given input secret.
    try testing.expectEqualSlices(u8, &s1, &deriveNextGenerationSecret(s0));
}

test "local key update rolls only write keys and outgoing phase" {
    var adapter = QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
    try testing.expectError(error.ApplicationSecretsMissing, adapter.updateApplicationWriteKeys());
    try adapter.installNegotiatedParameters(.{ .cipher_suite = @intFromEnum(tls_algorithms.CipherSuite.tls_aes_128_gcm_sha256), .transcript_hash = .sha256 });

    const read_secret = hexBytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    const write_secret = hexBytes("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");
    adapter.installSecret(try Secret.init(.application, .read, &read_secret));
    adapter.installSecret(try Secret.init(.application, .write, &write_secret));

    try testing.expectEqual(@as(u1, 0), adapter.applicationWriteKeyPhase());
    try testing.expectEqual(@as(u1, 0), adapter.applicationReadKeyPhase());
    var read_before = (try adapter.protectionKeys(.application, .read)).?;
    defer read_before.deinit();

    try adapter.updateApplicationWriteKeys();

    // Only the write side advanced: outgoing phase flipped, read side untouched.
    try testing.expectEqual(@as(u1, 1), adapter.applicationWriteKeyPhase());
    try testing.expectEqual(@as(u1, 0), adapter.applicationReadKeyPhase());
    var expected_write = deriveAes128GcmKeys(deriveNextGenerationSecret(write_secret));
    defer expected_write.deinit();
    var actual_write = (adapter.protectionKeys(.application, .write) catch unreachable).?;
    defer actual_write.deinit();
    try testing.expectEqualSlices(u8, expected_write.key.slice(), actual_write.key.slice());
    // Read keys still decrypt the peer's current (old) key phase.
    var read_after_write_update = (adapter.protectionKeys(.application, .read) catch unreachable).?;
    defer read_after_write_update.deinit();
    try testing.expectEqualSlices(u8, read_before.key.slice(), read_after_write_update.key.slice());
}

test "peer key update advances only read keys and incoming phase" {
    var adapter = QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
    try adapter.installNegotiatedParameters(.{ .cipher_suite = @intFromEnum(tls_algorithms.CipherSuite.tls_aes_128_gcm_sha256), .transcript_hash = .sha256 });
    const read_secret = hexBytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    const write_secret = hexBytes("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");
    adapter.installSecret(try Secret.init(.application, .read, &read_secret));
    adapter.installSecret(try Secret.init(.application, .write, &write_secret));

    var write_before = (try adapter.protectionKeys(.application, .write)).?;
    defer write_before.deinit();

    // Trial-decrypt keys for the next peer phase are derived without committing.
    var next_read = (adapter.nextApplicationReadKeys() catch unreachable).?;
    defer next_read.deinit();
    var expected_next_read = deriveAes128GcmKeys(deriveNextGenerationSecret(read_secret));
    defer expected_next_read.deinit();
    try testing.expectEqualSlices(u8, expected_next_read.key.slice(), next_read.key.slice());
    // Not yet committed: current read keys and phases are unchanged.
    try testing.expectEqual(@as(u1, 0), adapter.applicationReadKeyPhase());
    var expected_current_read = deriveAes128GcmKeys(read_secret);
    defer expected_current_read.deinit();
    var current_read = (adapter.protectionKeys(.application, .read) catch unreachable).?;
    defer current_read.deinit();
    try testing.expectEqualSlices(u8, expected_current_read.key.slice(), current_read.key.slice());

    // After the peer packet authenticates, commit the read key update.
    try adapter.commitApplicationReadKeyUpdate();
    try testing.expectEqual(@as(u1, 1), adapter.applicationReadKeyPhase());
    try testing.expectEqual(@as(u1, 0), adapter.applicationWriteKeyPhase());
    var committed_read = (adapter.protectionKeys(.application, .read) catch unreachable).?;
    defer committed_read.deinit();
    try testing.expectEqualSlices(u8, expected_next_read.key.slice(), committed_read.key.slice());
    // Write keys and outgoing phase were not disturbed.
    var write_after_read_update = (adapter.protectionKeys(.application, .write) catch unreachable).?;
    defer write_after_read_update.deinit();
    try testing.expectEqualSlices(u8, write_before.key.slice(), write_after_read_update.key.slice());

    // Read updates chain from the now-current read secret.
    var expected_second = deriveAes128GcmKeys(deriveNextGenerationSecret(deriveNextGenerationSecret(read_secret)));
    defer expected_second.deinit();
    var second_trial = (adapter.nextApplicationReadKeys() catch unreachable).?;
    defer second_trial.deinit();
    try testing.expectEqualSlices(u8, expected_second.key.slice(), second_trial.key.slice());
}

test "key update helpers require the corresponding application secret" {
    var adapter = QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
    try testing.expectError(error.ApplicationSecretsMissing, adapter.updateApplicationWriteKeys());
    try testing.expectError(error.ApplicationSecretsMissing, adapter.commitApplicationReadKeyUpdate());
    try testing.expectEqual(@as(?PacketProtectionKeys, null), adapter.nextApplicationReadKeys() catch unreachable);
}

test "adapter guards 0-RTT keys behind explicit config" {
    var adapter = QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
    try adapter.installEarlyDataParameters(.{ .cipher_suite = @intFromEnum(tls_algorithms.CipherSuite.tls_aes_128_gcm_sha256), .transcript_hash = .sha256 });
    const secret = hexBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    adapter.installSecret(try Secret.init(.zero_rtt, .write, &secret));

    // Disabled by default: no 0-RTT keys even though a secret is installed.
    try testing.expectEqual(@as(?PacketProtectionKeys, null), adapter.protectionKeys(.zero_rtt, .write));

    adapter.setZeroRttEnabled(true);
    try testing.expect(try adapter.hasProtectionKeys(.zero_rtt, .write));
}

test "peer transport parameters require handshake authentication" {
    var adapter = QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
    try testing.expectEqual(@as(?config.TransportParameters, null), adapter.peerTransportParameters());

    const params = try (config.Config{}).transportParameters();
    adapter.setPeerTransportParameters(params);
    // Still withheld until the handshake authenticates them.
    try testing.expectEqual(@as(?config.TransportParameters, null), adapter.peerTransportParameters());

    adapter.authenticatePeerTransportParameters();
    const authenticated = adapter.peerTransportParameters() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(params.max_idle_timeout_ms, authenticated.max_idle_timeout_ms);
}

test "adapter reports ALPN and certificate validation state" {
    var adapter = QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
    try testing.expect(!adapter.negotiatedH3());
    adapter.markAlpn("h3");
    try testing.expect(adapter.negotiatedH3());
    adapter.markAlpn("h2");
    try testing.expect(!adapter.negotiatedH3());

    try testing.expectEqual(CertificateState.not_checked, adapter.certificateState());
    adapter.setCertificateState(.valid);
    try testing.expectEqual(CertificateState.valid, adapter.certificateState());
}

test "adapter packet protection tracks metrics and counts deprotection failures" {
    var adapter = QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
    try adapter.installNegotiatedParameters(.{ .cipher_suite = @intFromEnum(tls_algorithms.CipherSuite.tls_aes_128_gcm_sha256), .transcript_hash = .sha256 });
    var out: [64]u8 = undefined;

    // No keys installed yet: deprotection is unavailable, not a failure.
    try testing.expectError(error.KeysUnavailable, adapter.openPacketPayload(.application, .read, 0, "hdr", "0123456789abcdef", &out));
    try testing.expectEqual(@as(u64, 0), adapter.metrics.deprotection_failures);

    const secret = hexBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    adapter.installSecret(try Secret.init(.application, .write, &secret));
    adapter.installSecret(try Secret.init(.application, .read, &secret));

    const header = "\x50\x00\x00\x00\x03";
    const plaintext = "one-rtt payload through the adapter seam";
    var sealed: [128]u8 = undefined;
    const protected = try adapter.sealPacketPayload(.application, .write, 3, header, plaintext, &sealed);
    try testing.expectEqual(@as(u64, 1), adapter.metrics.packets_protected);

    var opened: [128]u8 = undefined;
    const recovered = try adapter.openPacketPayload(.application, .read, 3, header, protected, &opened);
    try testing.expectEqualSlices(u8, plaintext, recovered);
    try testing.expectEqual(@as(u64, 1), adapter.metrics.packets_deprotected);

    // A forged packet is rejected and counted deterministically.
    var tampered: [128]u8 = undefined;
    @memcpy(tampered[0..protected.len], protected);
    tampered[0] ^= 0xff;
    try testing.expectError(error.AuthenticationFailed, adapter.openPacketPayload(.application, .read, 3, header, tampered[0..protected.len], &opened));
    try testing.expectEqual(@as(u64, 1), adapter.metrics.deprotection_failures);
}

test "CRYPTO reassembly emits only contiguous bytes by encryption level" {
    var reassembler = CryptoReassembler{};

    try reassembler.insert(.initial, 6, "world");
    try testing.expectEqual(@as(usize, 0), (try reassembler.contiguous(.initial)).len);

    try reassembler.insert(.handshake, 0, "other");
    try testing.expectEqualStrings("other", try reassembler.contiguous(.handshake));
    try reassembler.discardContiguous(.handshake, "other".len);

    try reassembler.insert(.initial, 0, "hello ");
    try testing.expectEqualStrings("hello world", try reassembler.contiguous(.initial));
    try reassembler.discardContiguous(.initial, "hello world".len);
    try testing.expectEqual(@as(usize, 0), (try reassembler.contiguous(.initial)).len);
}

test "CRYPTO reassembly merges duplicate and overlapping fragments" {
    var stream = CryptoStream{};
    try stream.insert(0, "abcde");
    try stream.insert(2, "cdef");
    try stream.insert(6, "g");

    try testing.expectEqual(@as(usize, 1), stream.range_count);
    try testing.expectEqualStrings("abcdefg", stream.contiguous());
    stream.discardContiguous("abcdefg".len);
}

test "CRYPTO reassembly preserves a gap after consumed bytes" {
    var stream = CryptoStream{};
    try stream.insert(0, "abc");
    try stream.insert(6, "ghi");
    try testing.expectEqualStrings("abc", stream.contiguous());
    stream.discardContiguous("abc".len);
    try testing.expectEqual(@as(u64, 3), stream.consumed_offset);
    try testing.expectEqual(@as(usize, 1), stream.range_count);
    try testing.expectEqual(@as(usize, 0), stream.contiguous().len);

    try stream.insert(3, "def");
    try testing.expectEqualStrings("defghi", stream.contiguous());
    stream.discardContiguous("defghi".len);
}

test "CRYPTO insert merges a full range set without partial failure" {
    var stream = CryptoStream{};
    stream.range_count = max_crypto_ranges;
    stream.ranges[0] = .{ .start = 0, .end = 2 };
    stream.ranges[1] = .{ .start = 4, .end = 6 };
    var index: usize = 2;
    while (index < max_crypto_ranges) : (index += 1) {
        const start: u64 = 10 + @as(u64, @intCast(index)) * 2;
        stream.ranges[index] = .{ .start = start, .end = start + 1 };
    }

    try stream.insert(2, "cd");
    try testing.expectEqual(@as(usize, max_crypto_ranges - 1), stream.range_count);
    try testing.expectEqual(ByteRange{ .start = 0, .end = 6 }, stream.ranges[0]);
    try testing.expectEqualStrings("cd", stream.buffer[2..4]);
}

test "CRYPTO insert does not mutate bytes when range insertion fails" {
    var stream = CryptoStream{};
    stream.range_count = max_crypto_ranges;
    var index: usize = 0;
    while (index < max_crypto_ranges) : (index += 1) {
        const start: u64 = 10 + @as(u64, @intCast(index)) * 2;
        stream.ranges[index] = .{ .start = start, .end = start + 1 };
    }
    stream.buffer[1] = 'x';

    try testing.expectError(error.TooManyCryptoRanges, stream.insert(1, "y"));
    try testing.expectEqual(@as(u8, 'x'), stream.buffer[1]);
    try testing.expectEqual(@as(usize, max_crypto_ranges), stream.range_count);
}

test "CRYPTO insert ignores and trims consumed retransmits" {
    var stream = CryptoStream{};
    try stream.insert(0, "hello");
    try testing.expectEqualStrings("hello", stream.contiguous());
    stream.discardContiguous("hello".len);
    try testing.expectEqual(@as(u64, 5), stream.consumed_offset);

    try stream.insert(0, "hello");
    try testing.expectEqual(@as(usize, 0), stream.range_count);
    try testing.expectEqual(@as(usize, 0), stream.contiguous().len);

    try stream.insert(3, "lo world");
    try testing.expectEqualStrings(" world", stream.contiguous());
    stream.discardContiguous(" world".len);
}

test "CRYPTO reassembly rejects offset overflow without partial mutation" {
    var stream = CryptoStream{};
    try stream.insert(0, "abc");

    const before_range_count = stream.range_count;
    const before_consumed = stream.consumed_offset;
    const before_base = stream.base_offset;
    try testing.expectError(error.CryptoBufferTooLarge, stream.insert(std.math.maxInt(u64) - 1, "abcd"));
    try testing.expectEqual(before_range_count, stream.range_count);
    try testing.expectEqual(before_consumed, stream.consumed_offset);
    try testing.expectEqual(before_base, stream.base_offset);
    try testing.expectEqualStrings("abc", stream.contiguous());
}

test "CRYPTO reassembly enforces exact sliding capacity boundary" {
    var stream = CryptoStream{};
    try stream.insert(max_crypto_buffer - 1, "x");
    try testing.expectError(error.CryptoBufferTooLarge, stream.insert(max_crypto_buffer, "x"));

    var prefix = CryptoStream{};
    try prefix.insert(0, "abc");
    prefix.discardContiguous(3);
    try prefix.insert(3 + max_crypto_buffer - 1, "x");
    try testing.expectError(error.CryptoBufferTooLarge, prefix.insert(3 + max_crypto_buffer, "x"));
}

test "fuzz: CRYPTO reassembly command sequences preserve bounded invariants" {
    try testing.fuzz({}, fuzzCryptoReassemblyCommands, .{ .corpus = &.{
        "",
        "\x00\x00\x05hello\x08\x00\x05hello\x01\x05\x05world",
        "\x01\x06\x05world\x00\x00\x06hello \x07\x00\x0b",
        "\x02\x00\x03abc\x02\x02\x04cdef\x02\x06\x01g\x07\x00\x07",
        "\x00\x00\x00\x00\x00\x01x\x00\xff\x04oops",
        "\x03\x00\x04test\x03\x00\x04test\x07\x00\x04\x09",
    } });
}

fn fuzzCryptoReassemblyCommands(_: void, smith: *testing.Smith) !void {
    var input: [192]u8 = undefined;
    const len = smith.slice(&input);
    try runCryptoReassemblyCommands(input[0..len]);
}

fn runCryptoReassemblyCommands(input: []const u8) !void {
    var reassembler = CryptoReassembler{};
    defer reassembler.deinit();

    var pos: usize = 0;
    while (pos < input.len) {
        const op = input[pos];
        pos += 1;
        const level = fuzzCryptoLevel(op);
        const level_index = try cryptoStreamIndex(level);

        switch (op % 10) {
            0...6 => {
                const offset = if (pos < input.len) input[pos] else 0;
                pos +|= @as(usize, @intFromBool(pos < input.len));
                const want = if (pos < input.len) @as(usize, input[pos] & 0x0f) else 0;
                pos +|= @as(usize, @intFromBool(pos < input.len));
                const take = @min(want, input.len - pos);
                const result = reassembler.insert(level, offset, input[pos..][0..take]);
                pos += take;
                if (result) |_| {
                    try expectCryptoStreamInvariants(&reassembler.streams[level_index]);
                } else |err| {
                    try testing.expect(err == error.CryptoBufferTooLarge or err == error.TooManyCryptoRanges);
                }
            },
            7 => {
                const available = (try reassembler.contiguous(level)).len;
                const discard_len = if (pos < input.len) @min(@as(usize, input[pos]), available) else available;
                pos +|= @as(usize, @intFromBool(pos < input.len));
                try reassembler.discardContiguous(level, discard_len);
            },
            8 => {
                const boundary_offset = std.math.add(u64, reassembler.streams[level_index].base_offset, max_crypto_buffer - 1) catch std.math.maxInt(u64);
                const beyond_offset = std.math.add(u64, reassembler.streams[level_index].base_offset, max_crypto_buffer) catch std.math.maxInt(u64);
                _ = reassembler.insert(level, boundary_offset, "x") catch {};
                _ = reassembler.insert(level, beyond_offset, "x") catch {};
            },
            else => {
                reassembler.deinit();
            },
        }

        const contiguous_after = (try reassembler.contiguous(level)).len;
        try testing.expect(contiguous_after <= max_crypto_buffer);
    }
}

fn fuzzCryptoLevel(op: u8) EncryptionLevel {
    return switch ((op >> 4) % 3) {
        0 => .initial,
        1 => .handshake,
        else => .application,
    };
}

fn expectCryptoStreamInvariants(stream: *const CryptoStream) !void {
    try testing.expect(stream.range_count <= max_crypto_ranges);
    var previous_end = stream.consumed_offset;
    var buffered: u64 = 0;
    for (stream.ranges[0..stream.range_count]) |range| {
        try testing.expect(range.start < range.end);
        try testing.expect(range.start >= stream.consumed_offset);
        try testing.expect(range.start >= previous_end);
        try testing.expect(range.end - stream.base_offset <= max_crypto_buffer);
        buffered += range.end - range.start;
        previous_end = range.end;
    }
    try testing.expect(buffered <= max_crypto_buffer);
    try testing.expect(stream.contiguous().len <= max_crypto_buffer);
}

test "adapter tracks transport parameters ALPN secrets and handshake input" {
    var adapter = QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
    const params = try (config.Config{}).transportParameters();
    adapter.setLocalTransportParameters(params);
    try testing.expect(adapter.local_transport_parameters != null);

    adapter.markAlpn("h3");
    try testing.expect(adapter.alpn_h3);

    const read_secret = try Secret.init(.handshake, .read, "read-secret");
    adapter.installSecret(read_secret);
    const stored_read_secret = adapter.secret(.handshake, .read).?;
    try testing.expectEqualStrings("read-secret", stored_read_secret.slice());
    adapter.discardSecrets(.handshake);
    try testing.expect(adapter.secret(.handshake, .read) == null);

    try adapter.receiveCrypto(.initial, 4, "lo");
    try adapter.receiveCrypto(.initial, 0, "hel");
    const first_input = (try adapter.nextHandshakeInput(.initial)).?;
    try testing.expectEqual(EncryptionLevel.initial, first_input.level);
    try testing.expectEqualStrings("hel", first_input.bytes);
    try adapter.discardHandshakeInput(.initial, first_input.bytes.len);
    try adapter.receiveCrypto(.initial, 3, "l");
    const input = (try adapter.nextHandshakeInput(.initial)).?;
    try testing.expectEqual(EncryptionLevel.initial, input.level);
    try testing.expectEqualStrings("llo", input.bytes);
    try adapter.discardHandshakeInput(.initial, input.bytes.len);
}

test "secret store returns pointers and wipes discarded secret bytes" {
    var store = SecretStore{};
    store.install(try Secret.init(.application, .write, "app-secret"));
    const stored = store.get(.application, .write).?;
    try testing.expectEqualStrings("app-secret", stored.slice());

    var standalone = try Secret.init(.application, .write, "wipe-me");
    SecretStore.wipe(&standalone);
    try testing.expectEqual(@as(usize, 0), standalone.material.len);
    for (standalone.material.bytes) |byte| try testing.expectEqual(@as(u8, 0), byte);

    store.discard(.application);
    try testing.expect(store.get(.application, .write) == null);
}

test "adapter queues outbound TLS handshake bytes as CRYPTO stream data" {
    var adapter = QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };

    try adapter.queueHandshakeOutput(.initial, "client");
    try adapter.queueHandshakeOutput(.initial, " hello");
    try adapter.queueHandshakeOutput(.handshake, "server");

    const first = (try adapter.nextHandshakeOutput(.initial, 6)).?;
    try testing.expectEqual(EncryptionLevel.initial, first.level);
    try testing.expectEqual(@as(u64, 0), first.offset);
    try testing.expectEqualStrings("client", first.bytes);
    try adapter.discardHandshakeOutput(.initial, first.bytes.len);

    const second = (try adapter.nextHandshakeOutput(.initial, 32)).?;
    try testing.expectEqual(@as(u64, 6), second.offset);
    try testing.expectEqualStrings(" hello", second.bytes);
    try adapter.discardHandshakeOutput(.initial, second.bytes.len);
    try testing.expect((try adapter.nextHandshakeOutput(.initial, 1)) == null);

    const handshake = (try adapter.nextHandshakeOutput(.handshake, 32)).?;
    try testing.expectEqual(EncryptionLevel.handshake, handshake.level);
    try testing.expectEqual(@as(u64, 0), handshake.offset);
    try testing.expectEqualStrings("server", handshake.bytes);
    try adapter.discardHandshakeOutput(.handshake, handshake.bytes.len);
}

test "crypto reassembler deinit leaves the default state" {
    // `CryptoReassembler.deinit` relies on `secureZero` alone producing the
    // same observable state as `.{}` -- dropping the redundant second
    // full-width memset is only sound while that holds (#675). If a future
    // field gains a non-zero default, this fails instead of silently
    // leaving a deinitialized reassembler in a non-default state.
    var reassembler = CryptoReassembler{};
    try reassembler.insert(.initial, 0, "secret-crypto-bytes");
    try reassembler.insert(.handshake, 4, "more-secret-bytes");
    try reassembler.discardContiguous(.initial, 3);
    reassembler.deinit();

    const fresh = CryptoReassembler{};
    for (&reassembler.streams, &fresh.streams) |*live, *expected| {
        try testing.expectEqual(expected.range_count, live.range_count);
        try testing.expectEqual(expected.base_offset, live.base_offset);
        try testing.expectEqual(expected.consumed_offset, live.consumed_offset);
        for (live.buffer) |byte| try testing.expectEqual(@as(u8, 0), byte);
    }
}

test "crypto output deinit leaves the default state" {
    var out = CryptoOutput{};
    try out.append("secret-output-bytes");
    out.discardTaken(4);
    out.deinit();

    const fresh = CryptoOutput{};
    try testing.expectEqual(fresh.start, out.start);
    try testing.expectEqual(fresh.end, out.end);
    try testing.expectEqual(fresh.next_offset, out.next_offset);
    for (out.buffer) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "adapter wipes consumed CRYPTO input and drained output bytes" {
    var adapter = QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
    const input_pattern = "ticket-input-pattern";
    try adapter.receiveCrypto(.application, 0, input_pattern);
    const input = (try adapter.nextHandshakeInput(.application)).?;
    try testing.expectEqualStrings(input_pattern, input.bytes);
    try adapter.discardHandshakeInput(.application, input.bytes.len);
    try testing.expect(std.mem.indexOf(u8, &adapter.reassembler.streams[EncryptionLevel.application.index()].buffer, input_pattern) == null);

    const output_pattern = "ticket-output-pattern";
    try adapter.queueHandshakeOutput(.application, output_pattern);
    const output = (try adapter.nextHandshakeOutput(.application, output_pattern.len)).?;
    try testing.expectEqualStrings(output_pattern, output.bytes);
    try adapter.discardHandshakeOutput(.application, output.bytes.len);
    try testing.expect(std.mem.indexOf(u8, &adapter.outbound[EncryptionLevel.application.index()].buffer, output_pattern) == null);
}

test "CRYPTO input storage is bounded by outstanding data, not lifetime offset" {
    var stream = CryptoStream{};
    const first = [_]u8{0x11} ** (40 * 1024);
    const second = [_]u8{0x22} ** (40 * 1024);

    try stream.insert(0, &first);
    try testing.expectEqualSlices(u8, &first, stream.contiguous());
    stream.discardContiguous(first.len);
    try stream.insert(first.len, &second);
    try testing.expectEqualSlices(u8, &second, stream.contiguous());
    stream.discardContiguous(second.len);
    try testing.expect(stream.consumed_offset > 64 * 1024);
}

test "0-RTT secrets are allowed but CRYPTO streams reject zero_rtt level" {
    var adapter = QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
    adapter.installSecret(try Secret.init(.zero_rtt, .read, "early-data-secret"));
    try testing.expectEqualStrings("early-data-secret", adapter.secret(.zero_rtt, .read).?.slice());

    try testing.expectError(error.InvalidCryptoLevel, adapter.receiveCrypto(.zero_rtt, 0, "bad"));
    try testing.expectError(error.InvalidCryptoLevel, adapter.queueHandshakeOutput(.zero_rtt, "bad"));
    try testing.expectError(error.InvalidCryptoLevel, adapter.nextHandshakeInput(.zero_rtt));
    try testing.expectError(error.InvalidCryptoLevel, adapter.nextHandshakeOutput(.zero_rtt, 1));
}

test {
    std.testing.refAllDecls(@This());
}
