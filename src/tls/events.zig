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
    /// A required TLS extension was absent. Distinct from a present extension
    /// whose vector is empty or malformed, which remains a decode or parameter
    /// failure. Maps to `missing_extension` (RFC 8446 §6).
    MissingExtension,
    /// The peer returned an extension for which the local endpoint did not send
    /// the corresponding request, except where the protocol explicitly permits
    /// an unsolicited extension such as `cookie` in HelloRetryRequest. Maps to
    /// `unsupported_extension` (RFC 8446 §6).
    UnsupportedExtension,
    /// ALPN did not negotiate an acceptable application protocol.
    AlpnMismatch,
    /// The peer presented a certificate or public key type this implementation
    /// cannot use for the selected authentication operation. Maps to
    /// `unsupported_certificate`.
    UnsupportedCertificate,
    /// The peer certificate was rejected by local policy or failed proof of key
    /// possession.
    CertificateInvalid,
    /// A traffic secret could not be exported or installed.
    SecretExportFailed,
    /// A local caller attempted an invalid handshake lifecycle transition.
    InvalidHandshakeState,
    /// A ticket identity exceeded the caller-configured resumable-session
    /// model bound even though it may still fit the absolute RFC wire range.
    TicketTooLarge,
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
    /// The server required handshake-time client authentication but the client
    /// presented no certificate (an empty Certificate). Peer-attributed and
    /// distinct from a rejected/invalid chain: the client simply declined when
    /// a certificate was mandatory. Maps to the `certificate_required` alert
    /// (RFC 8446 §4.4.2.4).
    ClientCertificateRequired,
    /// A peer's CertificateVerify signature did not validate against its
    /// presented leaf (proof-of-possession failure). RFC 8446 §4.4.3 mandates
    /// terminating with the `decrypt_error` alert, distinct from a trust
    /// rejection (`CertificateInvalid`/bad_certificate).
    DecryptError,
    /// There is no overlap between what the peer offered and what local policy
    /// enables along some negotiated dimension — cipher suite, named group, or
    /// signature scheme. Every field the peer sent was individually
    /// well-formed and legal, so this is *not* `IllegalParameter`: the two
    /// sides simply have nothing in common.
    ///
    /// RFC 8446 §4.1.1 is explicit that this case terminates with
    /// `handshake_failure` (or `insufficient_security`), and #338's external
    /// conformance matrix asserts that against real peers. Folding it into
    /// `IllegalParameter` sent `illegal_parameter` instead, which told a peer
    /// its ClientHello was malformed when it was perfectly valid.
    NoMutualParameters,
    /// The peer's `supported_versions` was present and well-formed but offered
    /// no version this endpoint supports. RFC 8446 §4.2.1 requires aborting
    /// with the `protocol_version` alert specifically, so a peer can tell a
    /// version-negotiation failure from a malformed hello. Distinct from a
    /// ClientHello with no `supported_versions` at all, which is
    /// `MissingExtension`.
    UnsupportedProtocolVersion,
};

/// The transcript/HKDF hash a negotiated cipher suite selects
/// (`algorithms.transcriptHash`), re-exported here so a record or QUIC
/// consumer can size/interpret traffic secrets without importing
/// `algorithms.zig` or guessing from secret length alone (#564: two of the
/// three negotiable suites share a hash, so length is not an implicit
/// signal either way).
pub const TranscriptHash = enum { sha256, sha384 };

/// Cipher-suite metadata (#564/#566). For the `negotiated_parameters` event,
/// this is emitted exactly once per connection — for a full or a resumed
/// handshake alike — before any `traffic_secret` event for the `handshake`
/// epoch. For the `early_data_parameters` event, this names the resumed
/// ticket/session suite that 0-RTT uses and must be emitted before any
/// `.zero_rtt` `traffic_secret`. `cipher_suite` is the wire code point
/// (`algorithms.CipherSuite`'s backing `u16`); consumers that need the enum
/// value convert it with `algorithms.fromInt`. Transports must not infer the
/// suite from secret length or any other side channel.
pub const NegotiatedParameters = struct {
    cipher_suite: u16,
    transcript_hash: TranscriptHash,
};

pub const Event = union(enum) {
    handshake_bytes: struct { epoch: EncryptionEpoch, data: []const u8 },
    negotiated_parameters: NegotiatedParameters,
    early_data_parameters: NegotiatedParameters,
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

test "negotiated_parameters event carries the wire cipher suite and its transcript hash" {
    const std = @import("std");

    const event = Event{ .negotiated_parameters = .{ .cipher_suite = 0x1302, .transcript_hash = .sha384 } };
    try std.testing.expectEqual(@as(u16, 0x1302), event.negotiated_parameters.cipher_suite);
    try std.testing.expectEqual(TranscriptHash.sha384, event.negotiated_parameters.transcript_hash);
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
    const ticket_too_large: HandshakeError = error.TicketTooLarge;
    try std.testing.expect(malformed != illegal);
    try std.testing.expect(malformed != unexpected);
    try std.testing.expect(illegal != unexpected);
    try std.testing.expect(ticket_too_large != malformed);
}
