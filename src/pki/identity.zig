//! SAN-only service identity verification (#342, RFC 9525 profile).
//!
//! Matches DNS and IP reference identities against `subjectAltName` entries
//! of a parsed certificate (#341). Common Name fallback is disabled: the
//! subject field is never consulted, so CN-only certificates always fail.
//!
//! ## Input contract (A-labels)
//!
//! DNS references must already be ASCII — internationalized names must be
//! converted to A-labels (IDNA/punycode) by the caller before verification.
//! This module never applies Unicode transformations; non-ASCII input is
//! rejected with `error.NonAsciiDnsReference` rather than silently mangled.
//!
//! ## Normalization
//!
//! ASCII case is ignored on both sides. Exactly one trailing dot is
//! stripped from the reference and from each presented DNS-ID; anything
//! beyond that (empty labels, a second dot) is malformed.
//!
//! ## Wildcards
//!
//! A wildcard is honored only when it is the complete left-most label of
//! the presented identifier (`*.example.com`), it never matches more or
//! fewer than exactly one label, and at least two literal labels must
//! follow it, so public-suffix-style identifiers (`*.com`) never match.
//! Partial-label (`f*o.example.com`) and interior (`a.*.example.com`)
//! wildcards match nothing. References may never contain `*`.
//!
//! ## Scope
//!
//! Identity matching is a pure function over one parsed certificate; it is
//! independent of chain construction (#324-E) and signature validation.
//! Mismatch results carry only the caller's reference identity and a
//! mismatch class — no certificate contents.

const std = @import("std");
const x509 = @import("x509.zig");

const net = std.Io.net;

pub const Error = error{
    EmptyReference,
    ReferenceTooLong,
    /// The reference violates the A-label input contract; convert
    /// internationalized names with IDNA before calling.
    NonAsciiDnsReference,
    /// Bad label syntax, an embedded `*`, an empty label, or an all-digit
    /// final label (an IP-address-shaped name that failed IP parsing).
    MalformedDnsReference,
};

/// RFC 1035 bounds for the presented/reference forms we compare.
const max_dns_name_len = 253;
const max_dns_label_len = 63;

pub const IpAddress = union(enum) {
    v4: [4]u8,
    v6: [16]u8,

    pub fn bytes(self: *const IpAddress) []const u8 {
        return switch (self.*) {
            .v4 => |*b| b,
            .v6 => |*b| b,
        };
    }
};

/// A reference identity: what the caller intends to connect to.
pub const Reference = union(enum) {
    /// ASCII DNS name, already validated and stripped of one trailing dot.
    dns_name: []const u8,
    ip_address: IpAddress,
};

pub const MismatchClass = enum {
    /// The certificate has no subjectAltName extension. Common Name
    /// fallback is disabled, so there is nothing to match against.
    no_subject_alt_name,
    /// The SAN holds no identifiers of the reference's type (e.g. an IP
    /// reference against a DNS-only SAN).
    no_entries_of_reference_type,
    /// Identifiers of the right type exist, but none matched.
    no_matching_entry,
};

pub const Mismatch = struct {
    /// The caller's reference identity, echoed back for reporting.
    reference: Reference,
    class: MismatchClass,
};

pub const Verdict = union(enum) {
    match,
    mismatch: Mismatch,

    pub fn isMatch(self: *const Verdict) bool {
        return self.* == .match;
    }
};

/// Build a DNS reference identity. Validates the A-label contract and LDH
/// label syntax, strips one trailing dot, and rejects embedded wildcards.
pub fn dnsReference(host: []const u8) Error!Reference {
    const name = try validateDnsReference(host);
    return .{ .dns_name = name };
}

/// Parse an IPv4/IPv6 literal (brackets accepted) into a reference
/// identity, or null when the input is not an IP literal.
pub fn ipReference(literal: []const u8) ?Reference {
    var text = literal;
    if (text.len >= 2 and text[0] == '[' and text[text.len - 1] == ']') {
        text = text[1 .. text.len - 1];
    }
    if (net.Ip4Address.parse(text, 0)) |v4| {
        return .{ .ip_address = .{ .v4 = v4.bytes } };
    } else |_| {}
    if (net.Ip6Address.parse(text, 0)) |v6| {
        return .{ .ip_address = .{ .v6 = v6.bytes } };
    } else |_| {}
    return null;
}

/// Classify a caller-supplied host string: IP literal first, DNS otherwise.
pub fn reference(host: []const u8) Error!Reference {
    if (ipReference(host)) |ref| return ref;
    return dnsReference(host);
}

/// Verify a reference identity against the certificate's subjectAltName.
pub fn verify(certificate: *const x509.Certificate, ref: Reference) Verdict {
    const san = certificate.subjectAltName() orelse return .{ .mismatch = .{
        .reference = ref,
        .class = .no_subject_alt_name,
    } };

    var entries_of_type: usize = 0;
    switch (ref) {
        .dns_name => |name| {
            for (san) |entry| {
                switch (entry) {
                    .dns_name => |presented| {
                        entries_of_type += 1;
                        if (presentedDnsIdMatches(presented, name)) return .match;
                    },
                    else => {},
                }
            }
        },
        .ip_address => |*address| {
            for (san) |entry| {
                switch (entry) {
                    .ip_address => |presented| {
                        entries_of_type += 1;
                        if (std.mem.eql(u8, presented, address.bytes())) return .match;
                    },
                    else => {},
                }
            }
        },
    }

    return .{ .mismatch = .{
        .reference = ref,
        .class = if (entries_of_type == 0) .no_entries_of_reference_type else .no_matching_entry,
    } };
}

/// Parse `host` as a reference identity and verify it. Errors describe the
/// reference, never the certificate.
pub fn verifyHost(certificate: *const x509.Certificate, host: []const u8) Error!Verdict {
    const ref = try reference(host);
    return verify(certificate, ref);
}

/// Whether one presented DNS-ID matches a validated DNS reference name.
/// `presented` comes from an untrusted SAN entry: identifiers with invalid
/// label syntax or non-conforming wildcards match nothing (the certificate
/// may still match through another entry). Exposed for TLS-layer reuse;
/// `reference_name` must come from `dnsReference`.
pub fn presentedDnsIdMatches(presented: []const u8, reference_name: []const u8) bool {
    const name = trimOneTrailingDot(presented);
    if (name.len == 0 or name.len > max_dns_name_len) return false;

    var presented_labels = std.mem.splitScalar(u8, name, '.');
    const first_label = presented_labels.next() orelse return false;

    if (std.mem.eql(u8, first_label, "*")) {
        // Wildcard: complete left-most label only, exactly one label deep,
        // with at least two literal labels after it.
        var literal_labels: usize = 0;
        while (presented_labels.next()) |label| {
            if (!isValidDnsLabel(label)) return false;
            literal_labels += 1;
        }
        if (literal_labels < 2) return false;

        var reference_labels = std.mem.splitScalar(u8, reference_name, '.');
        // The wildcard consumes exactly the first reference label.
        _ = reference_labels.next() orelse return false;

        presented_labels.reset();
        _ = presented_labels.next();
        while (presented_labels.next()) |presented_label| {
            const reference_label = reference_labels.next() orelse return false;
            if (!std.ascii.eqlIgnoreCase(presented_label, reference_label)) return false;
        }
        return reference_labels.next() == null;
    }

    // Exact match: every presented label must be valid LDH syntax; a
    // wildcard anywhere else in the identifier disqualifies it entirely.
    presented_labels.reset();
    while (presented_labels.next()) |label| {
        if (!isValidDnsLabel(label)) return false;
    }
    return std.ascii.eqlIgnoreCase(name, reference_name);
}

fn validateDnsReference(host: []const u8) Error![]const u8 {
    const name = trimOneTrailingDot(host);
    if (name.len == 0) return error.EmptyReference;
    if (name.len > max_dns_name_len) return error.ReferenceTooLong;

    for (name) |c| {
        if (c > 0x7f) return error.NonAsciiDnsReference;
    }

    var labels = std.mem.splitScalar(u8, name, '.');
    var last_label: []const u8 = "";
    while (labels.next()) |label| {
        if (!isValidDnsLabel(label)) return error.MalformedDnsReference;
        last_label = label;
    }

    // An all-digit final label is an IPv4-shaped name that failed strict IP
    // parsing (e.g. octal forms, out-of-range octets); matching it against
    // DNS-IDs would invite address confusion.
    var all_digits = true;
    for (last_label) |c| {
        if (c < '0' or c > '9') {
            all_digits = false;
            break;
        }
    }
    if (all_digits) return error.MalformedDnsReference;

    return name;
}

fn trimOneTrailingDot(name: []const u8) []const u8 {
    if (name.len > 0 and name[name.len - 1] == '.') return name[0 .. name.len - 1];
    return name;
}

fn isValidDnsLabel(label: []const u8) bool {
    if (label.len == 0 or label.len > max_dns_label_len) return false;
    if (label[0] == '-' or label[label.len - 1] == '-') return false;
    for (label) |c| {
        const valid = (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or c == '-';
        if (!valid) return false;
    }
    return true;
}

const testing = std.testing;

test {
    testing.refAllDecls(@This());
}
