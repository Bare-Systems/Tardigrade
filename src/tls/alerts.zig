//! RFC 8446 §6 fatal alert descriptions and the mapping from tls_core's
//! protocol-neutral handshake failures to the alert a peer must be sent.
//!
//! Only the subset of `AlertDescription` values reachable from current
//! `tls_core` failures is populated here; transports add codes as new
//! failure cases are introduced in tls_core.

const events = @import("events.zig");

/// TLS 1.3 alert descriptions, values per RFC 8446 §6.
pub const AlertDescription = enum(u8) {
    close_notify = 0,
    unexpected_message = 10,
    bad_certificate = 42,
    unsupported_certificate = 43,
    illegal_parameter = 47,
    decode_error = 50,
    decrypt_error = 51,
    missing_extension = 109,
    unsupported_extension = 110,
    certificate_required = 116,
    internal_error = 80,
};

/// Maps a `tls_core.events.HandshakeError` to the fatal alert a peer must be
/// sent, or `null` if the error is not a TLS protocol violation. ALPN
/// mismatch is a local negotiation policy failure, not a TLS-level protocol
/// error, so it is intentionally left unmapped here; transports that need an
/// alert-like code for it (e.g. QUIC's `no_application_protocol`) define
/// their own translation.
pub fn fromHandshakeError(err: events.HandshakeError) ?AlertDescription {
    return switch (err) {
        error.MalformedHandshake => .decode_error,
        error.CertificateInvalid => .bad_certificate,
        error.SecretExportFailed => .internal_error,
        error.AlpnMismatch => null,
    };
}

const testing = @import("std").testing;

test "malformed handshake bytes map to decode_error" {
    try testing.expectEqual(AlertDescription.decode_error, fromHandshakeError(error.MalformedHandshake));
}

test "invalid peer certificate maps to bad_certificate" {
    try testing.expectEqual(AlertDescription.bad_certificate, fromHandshakeError(error.CertificateInvalid));
}

test "secret export failure maps to internal_error" {
    try testing.expectEqual(AlertDescription.internal_error, fromHandshakeError(error.SecretExportFailed));
}

test "ALPN mismatch is not a TLS protocol alert" {
    try testing.expectEqual(@as(?AlertDescription, null), fromHandshakeError(error.AlpnMismatch));
}

test "alert description values match RFC 8446 section 6" {
    try testing.expectEqual(@as(u8, 0), @intFromEnum(AlertDescription.close_notify));
    try testing.expectEqual(@as(u8, 10), @intFromEnum(AlertDescription.unexpected_message));
    try testing.expectEqual(@as(u8, 42), @intFromEnum(AlertDescription.bad_certificate));
    try testing.expectEqual(@as(u8, 43), @intFromEnum(AlertDescription.unsupported_certificate));
    try testing.expectEqual(@as(u8, 47), @intFromEnum(AlertDescription.illegal_parameter));
    try testing.expectEqual(@as(u8, 50), @intFromEnum(AlertDescription.decode_error));
    try testing.expectEqual(@as(u8, 51), @intFromEnum(AlertDescription.decrypt_error));
    try testing.expectEqual(@as(u8, 109), @intFromEnum(AlertDescription.missing_extension));
    try testing.expectEqual(@as(u8, 110), @intFromEnum(AlertDescription.unsupported_extension));
    try testing.expectEqual(@as(u8, 116), @intFromEnum(AlertDescription.certificate_required));
    try testing.expectEqual(@as(u8, 80), @intFromEnum(AlertDescription.internal_error));
}
