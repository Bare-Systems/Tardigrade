//! Bounded, header-safe description of a *verified* downstream client
//! certificate (#763).
//!
//! `ClientIdentity.fromVerifiedDer` must only be called on the DER the
//! handshake engine surfaced through `Tls13Backend.verifiedPeerCertificate`:
//! a leaf whose chain the native PKI validator accepted against the configured
//! client trust anchors *and* whose CertificateVerify proved possession of the
//! key. Nothing here makes a trust decision; it only renders already-trusted
//! fields into fixed-size ASCII storage so they can be asserted to upstreams
//! without allocation, log injection, or header injection.
//!
//! Every text field is printable ASCII (RFC 2253 style escaping for names;
//! anything outside `0x20..0x7e` becomes `\XX`), so each value is a valid HTTP
//! field value by construction. A field that would not fit its bound is
//! *omitted* rather than truncated: a truncated subject could name a different
//! principal than the one that was verified. The SHA-256 fingerprint of the
//! leaf DER is always present and is the stable, unforgeable identity key.

const std = @import("std");
const pki = @import("pki");

const Sha256 = std.crypto.hash.sha2.Sha256;
const wk = pki.oid.well_known;

pub const max_dn_len = 512;
pub const max_san_len = 255;
pub const fingerprint_hex_len = Sha256.digest_length * 2;
/// RFC 5280 caps serial numbers at 20 octets.
pub const max_serial_hex_len = 40;

pub const ClientIdentity = struct {
    fingerprint_buf: [fingerprint_hex_len]u8 = undefined,
    subject_buf: [max_dn_len]u8 = undefined,
    subject_len: usize = 0,
    issuer_buf: [max_dn_len]u8 = undefined,
    issuer_len: usize = 0,
    serial_buf: [max_serial_hex_len]u8 = undefined,
    serial_len: usize = 0,
    san_dns_buf: [max_san_len]u8 = undefined,
    san_dns_len: usize = 0,
    san_email_buf: [max_san_len]u8 = undefined,
    san_email_len: usize = 0,
    san_uri_buf: [max_san_len]u8 = undefined,
    san_uri_len: usize = 0,

    pub const Error = error{ MalformedCertificate, OutOfMemory };

    /// Lowercase hex SHA-256 of the certificate DER.
    pub fn fingerprintSha256(self: *const ClientIdentity) []const u8 {
        return &self.fingerprint_buf;
    }
    /// RFC 2253-style subject DN, or empty when absent or over `max_dn_len`.
    pub fn subject(self: *const ClientIdentity) []const u8 {
        return self.subject_buf[0..self.subject_len];
    }
    pub fn issuer(self: *const ClientIdentity) []const u8 {
        return self.issuer_buf[0..self.issuer_len];
    }
    pub fn serialHex(self: *const ClientIdentity) []const u8 {
        return self.serial_buf[0..self.serial_len];
    }
    /// First dNSName / rfc822Name / URI SAN entry, escaped; empty when none.
    pub fn sanDns(self: *const ClientIdentity) []const u8 {
        return self.san_dns_buf[0..self.san_dns_len];
    }
    pub fn sanEmail(self: *const ClientIdentity) []const u8 {
        return self.san_email_buf[0..self.san_email_len];
    }
    pub fn sanUri(self: *const ClientIdentity) []const u8 {
        return self.san_uri_buf[0..self.san_uri_len];
    }

    pub fn fromVerifiedDer(allocator: std.mem.Allocator, der: []const u8) Error!ClientIdentity {
        var arena_state = std.heap.ArenaAllocator.init(allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const cert = pki.x509.Certificate.parse(arena, der, .{}) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.MalformedCertificate,
        };

        var self: ClientIdentity = .{};
        var digest: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(der, &digest, .{});
        _ = std.fmt.bufPrint(&self.fingerprint_buf, "{x}", .{&digest}) catch unreachable;

        self.subject_len = renderName(&cert.subject, &self.subject_buf) orelse 0;
        self.issuer_len = renderName(&cert.issuer, &self.issuer_buf) orelse 0;

        // A serial longer than RFC 5280's 20 octets is omitted, not truncated.
        const serial = cert.serial_number.content;
        if (serial.len <= max_serial_hex_len / 2) {
            const printed = std.fmt.bufPrint(&self.serial_buf, "{x}", .{serial}) catch "";
            self.serial_len = printed.len;
        }

        if (cert.subjectAltName()) |names| {
            for (names) |name| switch (name) {
                .dns_name => |v| if (self.san_dns_len == 0) {
                    self.san_dns_len = escapeInto(&self.san_dns_buf, v, .value) orelse 0;
                },
                .rfc822_name => |v| if (self.san_email_len == 0) {
                    self.san_email_len = escapeInto(&self.san_email_buf, v, .value) orelse 0;
                },
                .uniform_resource_identifier => |v| if (self.san_uri_len == 0) {
                    self.san_uri_len = escapeInto(&self.san_uri_buf, v, .value) orelse 0;
                },
                else => {},
            };
        }
        return self;
    }
};

const EscapeMode = enum {
    /// RFC 2253 attribute value: also escapes the DN metacharacters.
    dn_value,
    /// Free-form SAN text: only forces printable ASCII and escapes `\`.
    value,
};

/// Escape `src` into `out`, returning the written length, or null when it does
/// not fit (the caller omits the field rather than truncating it).
fn escapeInto(out: []u8, src: []const u8, mode: EscapeMode) ?usize {
    var n: usize = 0;
    for (src, 0..) |byte, i| {
        const printable = byte >= 0x20 and byte <= 0x7e;
        const special = switch (mode) {
            .dn_value => byte == ',' or byte == '+' or byte == '"' or byte == '\\' or
                byte == '<' or byte == '>' or byte == ';' or byte == '=' or
                (i == 0 and (byte == '#' or byte == ' ')) or
                (i == src.len - 1 and byte == ' '),
            .value => byte == '\\',
        };
        if (!printable) {
            if (n + 3 > out.len) return null;
            out[n] = '\\';
            _ = std.fmt.bufPrint(out[n + 1 ..][0..2], "{x:0>2}", .{byte}) catch unreachable;
            n += 3;
        } else if (special) {
            if (n + 2 > out.len) return null;
            out[n] = '\\';
            out[n + 1] = byte;
            n += 2;
        } else {
            if (n + 1 > out.len) return null;
            out[n] = byte;
            n += 1;
        }
    }
    return n;
}

fn attributeLabel(components: []const u32) ?[]const u8 {
    const table = .{
        .{ &wk.common_name, "CN" },
        .{ &wk.organization, "O" },
        .{ &wk.organizational_unit, "OU" },
        .{ &wk.country, "C" },
        .{ &wk.state_or_province, "ST" },
        .{ &wk.locality, "L" },
        .{ &wk.serial_number_attr, "serialNumber" },
        .{ &wk.domain_component, "DC" },
        .{ &wk.email_address, "emailAddress" },
    };
    inline for (table) |entry| {
        if (std.mem.eql(u32, components, entry[0])) return entry[1];
    }
    return null;
}

/// Render a Name as an RFC 2253-style string (most specific RDN first). Returns
/// null when it does not fit.
fn renderName(name: *const pki.x509.Name, out: *[max_dn_len]u8) ?usize {
    var n: usize = 0;
    var i = name.rdns.len;
    while (i > 0) {
        i -= 1;
        if (n > 0) {
            if (n + 1 > out.len) return null;
            out[n] = ',';
            n += 1;
        }
        for (name.rdns[i].attributes, 0..) |attr, j| {
            if (j > 0) {
                if (n + 1 > out.len) return null;
                out[n] = '+';
                n += 1;
            }
            const components = attr.type.components();
            if (attributeLabel(components)) |label| {
                if (n + label.len > out.len) return null;
                @memcpy(out[n..][0..label.len], label);
                n += label.len;
            } else {
                for (components, 0..) |c, k| {
                    const printed = std.fmt.bufPrint(out[n..], "{s}{d}", .{ if (k == 0) "" else ".", c }) catch return null;
                    n += printed.len;
                }
            }
            if (n + 1 > out.len) return null;
            out[n] = '=';
            n += 1;
            n += escapeInto(out[n..], attr.value, .dn_value) orelse return null;
        }
    }
    return n;
}

const testing = std.testing;

test "escapeInto forces printable ASCII and escapes DN metacharacters" {
    var buf: [64]u8 = undefined;
    const n = escapeInto(&buf, "a,b\r\nX-Evil: 1\x00", .dn_value).?;
    try testing.expectEqualStrings("a\\,b\\0d\\0aX-Evil: 1\\00", buf[0..n]);
    for (buf[0..n]) |c| try testing.expect(c >= 0x20 and c <= 0x7e);
}

test "escapeInto omits rather than truncates" {
    var buf: [4]u8 = undefined;
    try testing.expect(escapeInto(&buf, "abcdef", .value) == null);
    try testing.expectEqual(@as(usize, 4), escapeInto(&buf, "abcd", .value).?);
}

test "fromVerifiedDer renders subject, issuer, serial and fingerprint" {
    const der = @embedFile("testdata/rsa3072-cert.der");
    const id = try ClientIdentity.fromVerifiedDer(testing.allocator, der);
    try testing.expectEqual(@as(usize, fingerprint_hex_len), id.fingerprintSha256().len);
    try testing.expect(id.subject().len > 0);
    try testing.expect(id.issuer().len > 0);
    try testing.expect(id.serialHex().len > 0);
    for (id.subject()) |c| try testing.expect(c >= 0x20 and c <= 0x7e);
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(der, &digest, .{});
    var expect: [fingerprint_hex_len]u8 = undefined;
    _ = try std.fmt.bufPrint(&expect, "{x}", .{&digest});
    try testing.expectEqualStrings(&expect, id.fingerprintSha256());
}

test "fromVerifiedDer rejects malformed DER" {
    try testing.expectError(error.MalformedCertificate, ClientIdentity.fromVerifiedDer(testing.allocator, "not a certificate"));
}
