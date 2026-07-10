//! TLS key-log support for local QUIC decryption (#255).
//!
//! ## What this is
//!
//! Wireshark/qvis can only decrypt a captured QUIC flow if it is handed the
//! TLS traffic secrets. The de-facto interchange format is NSS's
//! `SSLKEYLOGFILE` — one line per secret:
//!
//!     <LABEL> <client_random_hex> <secret_hex>
//!
//! This module maps a `(perspective, direction, level)` triple from the TLS
//! adapter onto the correct NSS label and formats that line. It does **not**
//! open files or read `SSLKEYLOGFILE` itself: like `qlog.Sink`, secrets are
//! handed to an injected `Sink` and the composition root decides where they go.
//!
//! ## Why this is sensitive / debug-only
//!
//! A key log is exactly the material needed to decrypt the connection. Emitting
//! it defeats the confidentiality QUIC provides, so:
//!
//!   * it is gated behind `config.Observability.keylog_enabled`, which is
//!     `false` by default;
//!   * the adapter otherwise **wipes** these secrets (`SecretStore.wipe`), so a
//!     key log is the *only* place they escape — treat the destination as
//!     equivalent to the plaintext;
//!   * Initial secrets are intentionally never logged: they are derivable from
//!     the client DCID on the wire and add no debugging value while widening the
//!     surface.
//!
//! Operator guidance lives in `docs/QUIC_QLOG.md`.

const std = @import("std");
const tls = @import("tls_adapter.zig");

/// NSS key-log labels QUIC/TLS 1.3 uses (RFC 9001 keys are TLS 1.3 secrets).
pub const Label = enum {
    client_early_traffic_secret,
    client_handshake_traffic_secret,
    server_handshake_traffic_secret,
    client_traffic_secret_0,
    server_traffic_secret_0,

    pub fn text(self: Label) []const u8 {
        return switch (self) {
            .client_early_traffic_secret => "CLIENT_EARLY_TRAFFIC_SECRET",
            .client_handshake_traffic_secret => "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            .server_handshake_traffic_secret => "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            .client_traffic_secret_0 => "CLIENT_TRAFFIC_SECRET_0",
            .server_traffic_secret_0 => "SERVER_TRAFFIC_SECRET_0",
        };
    }
};

/// The classic `client_random` from the ClientHello ties every line in a key
/// log to its connection. QUIC has no TLS record layer, but the TLS 1.3
/// ClientHello still carries a 32-byte random that Wireshark keys on.
pub const client_random_len = 32;

/// Resolve which NSS label a freshly installed secret should be logged under,
/// or null when it should not be logged at all (Initial keys, and the
/// server-side "early" slot which does not exist).
///
/// `direction` is relative to this endpoint: `.write` is the secret this
/// endpoint encrypts with, `.read` the peer's. NSS labels are phrased from the
/// client/server point of view, so we fold `perspective` and `direction`
/// together to decide whose secret it is.
pub fn labelFor(
    perspective: tls.Perspective,
    direction: tls.Direction,
    level: tls.EncryptionLevel,
) ?Label {
    const is_client_secret = switch (direction) {
        .write => perspective == .client,
        .read => perspective == .server,
    };
    return switch (level) {
        .initial => null,
        .zero_rtt => if (is_client_secret) .client_early_traffic_secret else null,
        .handshake => if (is_client_secret) .client_handshake_traffic_secret else .server_handshake_traffic_secret,
        .application => if (is_client_secret) .client_traffic_secret_0 else .server_traffic_secret_0,
    };
}

/// One key-log entry: everything an NSS line needs, borrowing (not copying) the
/// secret bytes. The `Sink` is expected to format-and-write synchronously.
pub const Entry = struct {
    label: Label,
    client_random: []const u8,
    secret: []const u8,
};

/// Injected write seam, mirroring `qlog.Sink`. Default `.{}` is a no-op, so
/// key logging is off unless a composition root wires a destination.
pub const Sink = struct {
    context: ?*anyopaque = null,
    emit_fn: ?*const fn (?*anyopaque, Entry) void = null,

    pub fn emit(self: Sink, entry: Entry) void {
        if (self.emit_fn) |f| f(self.context, entry);
    }
};

/// Format one NSS `SSLKEYLOGFILE` line (including the trailing newline) into
/// `out`. Returns the written slice, or:
///   * `error.InvalidClientRandom` unless `client_random` is exactly
///     `client_random_len` bytes — Wireshark keys every line on the 32-byte
///     ClientHello random, so a wrong-length value produces a line no tool can
///     match. Rejecting it loudly beats emitting silent garbage.
///   * `error.EmptySecret` if `secret` is empty (a keyless line is useless).
///     Secret length is otherwise unconstrained, to admit future cipher suites.
///   * `error.NoSpaceLeft` if `out` is too small — a 256-byte buffer covers a
///     32-byte random and a 48-byte secret.
pub fn writeLine(entry: Entry, out: []u8) error{ InvalidClientRandom, EmptySecret, NoSpaceLeft }![]const u8 {
    if (entry.client_random.len != client_random_len) return error.InvalidClientRandom;
    if (entry.secret.len == 0) return error.EmptySecret;
    const label = entry.label.text();
    const needed = label.len + 1 + entry.client_random.len * 2 + 1 + entry.secret.len * 2 + 1;
    if (out.len < needed) return error.NoSpaceLeft;

    var i: usize = 0;
    @memcpy(out[i .. i + label.len], label);
    i += label.len;
    out[i] = ' ';
    i += 1;
    i += writeHex(entry.client_random, out[i..]);
    out[i] = ' ';
    i += 1;
    i += writeHex(entry.secret, out[i..]);
    out[i] = '\n';
    i += 1;
    return out[0..i];
}

fn writeHex(bytes: []const u8, out: []u8) usize {
    const hex = "0123456789abcdef";
    for (bytes, 0..) |b, idx| {
        out[idx * 2] = hex[b >> 4];
        out[idx * 2 + 1] = hex[b & 0x0f];
    }
    return bytes.len * 2;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "initial secrets are never logged" {
    try testing.expectEqual(@as(?Label, null), labelFor(.client, .write, .initial));
    try testing.expectEqual(@as(?Label, null), labelFor(.server, .read, .initial));
}

test "label folds perspective and direction into client/server secrets" {
    // Client endpoint: its write secret is the client's, its read secret the server's.
    try testing.expectEqual(Label.client_handshake_traffic_secret, labelFor(.client, .write, .handshake).?);
    try testing.expectEqual(Label.server_handshake_traffic_secret, labelFor(.client, .read, .handshake).?);
    // Server endpoint: mirror image.
    try testing.expectEqual(Label.server_traffic_secret_0, labelFor(.server, .write, .application).?);
    try testing.expectEqual(Label.client_traffic_secret_0, labelFor(.server, .read, .application).?);
    // 0-RTT only exists for the client's early data.
    try testing.expectEqual(Label.client_early_traffic_secret, labelFor(.client, .write, .zero_rtt).?);
    try testing.expectEqual(@as(?Label, null), labelFor(.server, .write, .zero_rtt));
}

test "writeLine emits a well-formed NSS key-log line" {
    const random = [_]u8{0xab} ** client_random_len;
    const secret = [_]u8{ 0x00, 0x0f, 0xff };
    var buf: [256]u8 = undefined;
    const line = try writeLine(.{ .label = .client_traffic_secret_0, .client_random = &random, .secret = &secret }, &buf);
    try testing.expect(std.mem.startsWith(u8, line, "CLIENT_TRAFFIC_SECRET_0 "));
    try testing.expect(std.mem.endsWith(u8, line, " 000fff\n"));
    // 32-byte random renders as 64 hex chars of 'ab'.
    try testing.expect(std.mem.indexOf(u8, line, "ababab") != null);
}

test "writeLine reports NoSpaceLeft instead of overflowing" {
    var buf: [8]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, writeLine(.{
        .label = .client_traffic_secret_0,
        .client_random = &[_]u8{0} ** client_random_len,
        .secret = &[_]u8{0} ** 48,
    }, &buf));
}

test "writeLine rejects a wrong-length client random" {
    var buf: [256]u8 = undefined;
    // One byte short of the required 32.
    try testing.expectError(error.InvalidClientRandom, writeLine(.{
        .label = .client_traffic_secret_0,
        .client_random = &[_]u8{0} ** (client_random_len - 1),
        .secret = &[_]u8{0x11},
    }, &buf));
}

test "writeLine rejects an empty secret" {
    var buf: [256]u8 = undefined;
    try testing.expectError(error.EmptySecret, writeLine(.{
        .label = .client_traffic_secret_0,
        .client_random = &[_]u8{0} ** client_random_len,
        .secret = &[_]u8{},
    }, &buf));
}

test "default sink is a no-op" {
    const sink = Sink{};
    sink.emit(.{ .label = .client_traffic_secret_0, .client_random = &[_]u8{}, .secret = &[_]u8{} });
}
