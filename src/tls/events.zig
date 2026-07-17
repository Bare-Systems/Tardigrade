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

pub const SecretLifecycleError = error{
    SecretAlreadyDiscarded,
    SecretNotInstalled,
};

/// Typed, deterministic TLS handshake failures. Transport layers translate
/// these into their own close/error surfaces without losing the TLS reason.
pub const HandshakeError = error{
    /// The peer's TLS handshake bytes could not be decoded: a length was wrong
    /// or out of range, the message was truncated, or a field could not be
    /// parsed at all. This is a *syntax/framing* failure — the wire data itself
    /// is wrong. Semantically-valid-but-incorrect field values are
    /// `IllegalParameter`, not this. Maps to the `decode_error` alert
    /// (RFC 8446 §6).
    MalformedHandshake,
    /// A handshake field decoded cleanly but carries a value that is incorrect
    /// or inconsistent with other fields: a bad `legacy_version`, an
    /// unsupported cipher suite or named group, a non-null compression method,
    /// a key share that is the wrong length for its group or a low-order/
    /// identity point, or a repeated extension type (RFC 8446 §4.2). The bytes
    /// conform to the formal syntax but are otherwise wrong. Maps to the
    /// `illegal_parameter` alert (RFC 8446 §6).
    IllegalParameter,
    /// A syntactically valid handshake message arrived in the wrong state or
    /// for the wrong role — a legal message the peer sent out of order (for
    /// example a ServerHello where a Certificate was expected, a ClientHello a
    /// client should never receive, or any handshake message once the handshake
    /// is finished). Distinct from `MalformedHandshake`: the bytes decode fine,
    /// the ordering does not. Wrong-*epoch* CRYPTO delivery is a QUIC-local
    /// concern (`UnexpectedCryptoLevel`), not this. Maps to the
    /// `unexpected_message` alert (RFC 8446 §6).
    UnexpectedHandshakeMessage,
    /// ALPN did not negotiate an acceptable application protocol.
    AlpnMismatch,
    /// The peer certificate was rejected by local policy or failed proof of key
    /// possession.
    CertificateInvalid,
    /// A traffic secret could not be exported or installed.
    SecretExportFailed,
    /// A local caller attempted an invalid handshake lifecycle transition.
    InvalidHandshakeState,
    /// This side cannot authenticate itself for the negotiated parameters: no
    /// local credential is available, or none is compatible with the peer's
    /// offered signature algorithms. A *local* configuration/selection failure,
    /// distinct from a peer-certificate rejection (`CertificateInvalid`). Maps
    /// to the `handshake_failure` alert (RFC 8446 §4.4.2.2).
    NoApplicableCredential,
    /// A local credential provider, signer, or peer verifier failed
    /// deterministically (malformed local chain, signing fault, output
    /// overflow, verifier internal error, or an invalid callback contract).
    /// Our own fault, never the peer's — maps to the `internal_error` alert.
    CredentialProviderFailed,
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

test "syntax, semantic, and ordering failures are distinct cases" {
    const std = @import("std");

    // Decode failures, semantically-invalid field values, and legal-but-
    // misordered messages must be separate errors so transports can map them to
    // `decode_error`, `illegal_parameter`, and `unexpected_message`
    // respectively.
    const malformed: HandshakeError = error.MalformedHandshake;
    const illegal: HandshakeError = error.IllegalParameter;
    const unexpected: HandshakeError = error.UnexpectedHandshakeMessage;
    try std.testing.expect(malformed != illegal);
    try std.testing.expect(malformed != unexpected);
    try std.testing.expect(illegal != unexpected);
}
