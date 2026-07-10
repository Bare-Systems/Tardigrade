//! Protocol-neutral events emitted by the TLS 1.3 core.

pub const EncryptionEpoch = enum { initial, handshake, application };
pub const SecretDirection = enum { read, write };
pub const CertificateState = enum { not_checked, valid, invalid };

pub const Event = union(enum) {
    handshake_bytes: struct { epoch: EncryptionEpoch, data: []const u8 },
    traffic_secret: struct { epoch: EncryptionEpoch, direction: SecretDirection, data: []const u8 },
    alpn: []const u8,
    certificate: CertificateState,
    discard_epoch: EncryptionEpoch,
    handshake_complete,
};
