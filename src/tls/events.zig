//! Protocol-neutral TLS 1.3 event and failure vocabulary.
//!
//! The concrete transport integrations own their framing. QUIC maps these
//! concepts to CRYPTO streams and packet-protection keys; future TCP record
//! mode maps the same concepts to TLS records and encrypted byte streams.

pub const EncryptionEpoch = enum {
    initial,
    zero_rtt,
    handshake,
    application,
};

pub const SecretDirection = enum { read, write };
pub const CertificateState = enum { not_checked, valid, invalid };

/// Typed, deterministic TLS handshake failures. Transport layers translate
/// these into their own close/error surfaces without losing the TLS reason.
pub const HandshakeError = error{
    /// The peer's TLS handshake bytes were malformed or arrived in an illegal
    /// order.
    MalformedHandshake,
    /// ALPN did not negotiate an acceptable application protocol.
    AlpnMismatch,
    /// The peer certificate was rejected by local policy or failed proof of key
    /// possession.
    CertificateInvalid,
    /// A traffic secret could not be exported or installed.
    SecretExportFailed,
};

pub const Event = union(enum) {
    handshake_bytes: struct { epoch: EncryptionEpoch, data: []const u8 },
    traffic_secret: struct { epoch: EncryptionEpoch, direction: SecretDirection, data: []const u8 },
    alpn: []const u8,
    certificate: CertificateState,
    discard_epoch: EncryptionEpoch,
    handshake_complete,
};

test "event vocabulary covers QUIC and record-mode TLS lifecycles" {
    const std = @import("std");

    const secret_event = Event{
        .traffic_secret = .{
            .epoch = .handshake,
            .direction = .write,
            .data = "secret",
        },
    };
    try std.testing.expectEqual(EncryptionEpoch.handshake, secret_event.traffic_secret.epoch);
    try std.testing.expectEqual(SecretDirection.write, secret_event.traffic_secret.direction);

    const cert_event = Event{ .certificate = .valid };
    try std.testing.expectEqual(CertificateState.valid, cert_event.certificate);
}

test "shared handshake errors include transport-required failure cases" {
    const std = @import("std");

    const err: HandshakeError = error.MalformedHandshake;
    try std.testing.expectEqual(error.MalformedHandshake, err);
}
