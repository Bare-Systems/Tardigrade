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
    /// The peer's TLS handshake bytes could not be parsed: bad lengths, invalid
    /// encoding, unknown message or field values, or otherwise malformed wire
    /// data. Maps to the `decode_error` alert (RFC 8446 §6).
    MalformedHandshake,
    /// A syntactically valid handshake message arrived in the wrong state or at
    /// the wrong epoch — a legal message the peer sent out of order (for
    /// example a ServerHello where a Certificate was expected, or any handshake
    /// message once the handshake is finished). Distinct from
    /// `MalformedHandshake`: the bytes decode fine, the ordering does not. Maps
    /// to the `unexpected_message` alert (RFC 8446 §6).
    UnexpectedHandshakeMessage,
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

test "shared handshake errors include TLS-level failure cases" {
    const std = @import("std");

    const err: HandshakeError = error.MalformedHandshake;
    try std.testing.expectEqual(error.MalformedHandshake, err);
}

test "malformed bytes and out-of-order messages are distinct failure cases" {
    const std = @import("std");

    // Parse/decode failures and legal-but-misordered messages must be separate
    // errors so transports can map them to `decode_error` versus
    // `unexpected_message` respectively.
    const malformed: HandshakeError = error.MalformedHandshake;
    const unexpected: HandshakeError = error.UnexpectedHandshakeMessage;
    try std.testing.expect(malformed != unexpected);
}
