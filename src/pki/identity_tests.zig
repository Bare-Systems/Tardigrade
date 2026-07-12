//! SAN-only identity matching tests (#342).
//!
//! Uses the OpenSSL fixtures from #341 (`ecdsa_leaf.crt` presents DNS,
//! wildcard, IPv4, IPv6, email, and URI SAN entries; `v1_leaf.crt` is a
//! CN-only certificate) plus synthetic certificates carrying hostile
//! presented identifiers.

const std = @import("std");
const der = @import("der.zig");
const oid = @import("oid.zig");
const pem = @import("pem.zig");
const x509 = @import("x509.zig");
const identity = @import("identity.zig");

const testing = std.testing;

const ecdsa_leaf_pem = @embedFile("testdata/ecdsa_leaf.crt");
const v1_leaf_pem = @embedFile("testdata/v1_leaf.crt");
const ed25519_pem = @embedFile("testdata/ed25519.crt");

const Fixture = struct {
    loaded: pem.Certificate,
    cert: x509.Certificate,

    fn init(allocator: std.mem.Allocator, pem_text: []const u8) !Fixture {
        var loaded = try pem.loadCertificatePem(allocator, pem_text, .{});
        errdefer loaded.deinit(allocator);
        const cert = try x509.Certificate.parse(allocator, loaded.der, .{});
        return .{ .loaded = loaded, .cert = cert };
    }

    fn deinit(self: *Fixture, allocator: std.mem.Allocator) void {
        self.cert.deinit(allocator);
        self.loaded.deinit(allocator);
    }
};

fn expectMatch(cert: *const x509.Certificate, host: []const u8) !void {
    const verdict = try identity.verifyHost(cert, host);
    try testing.expect(verdict.isMatch());
}

fn expectMismatch(cert: *const x509.Certificate, host: []const u8, class: identity.MismatchClass) !void {
    const verdict = try identity.verifyHost(cert, host);
    try testing.expect(!verdict.isMatch());
    try testing.expectEqual(class, verdict.mismatch.class);
}

test "exact DNS, wildcard, case, and trailing-dot references match the leaf fixture" {
    const allocator = testing.allocator;
    var fixture = try Fixture.init(allocator, ecdsa_leaf_pem);
    defer fixture.deinit(allocator);
    const cert = &fixture.cert;

    // SAN: leaf.example.com, *.leaf.example.com, 127.0.0.1, ::1,
    // email:admin@example.com, URI:https://leaf.example.com/app
    try expectMatch(cert, "leaf.example.com");
    try expectMatch(cert, "LEAF.EXAMPLE.COM");
    try expectMatch(cert, "Leaf.Example.Com.");
    try expectMatch(cert, "www.leaf.example.com");
    try expectMatch(cert, "WWW.leaf.EXAMPLE.com.");

    // Wildcards match exactly one label.
    try expectMismatch(cert, "a.b.leaf.example.com", .no_matching_entry);
    // Wildcard base itself is not covered by the wildcard.
    try expectMatch(cert, "leaf.example.com");
    try expectMismatch(cert, "example.com", .no_matching_entry);
    try expectMismatch(cert, "leaf.example.org", .no_matching_entry);
    try expectMismatch(cert, "eaf.example.com", .no_matching_entry);

    // email/URI SAN entries never satisfy DNS references.
    try expectMismatch(cert, "admin.example.com", .no_matching_entry);
}

test "IPv4 and IPv6 references match only IP SAN entries" {
    const allocator = testing.allocator;
    var fixture = try Fixture.init(allocator, ecdsa_leaf_pem);
    defer fixture.deinit(allocator);
    const cert = &fixture.cert;

    try expectMatch(cert, "127.0.0.1");
    try expectMatch(cert, "::1");
    try expectMatch(cert, "[::1]");
    try expectMatch(cert, "0:0:0:0:0:0:0:1");

    try expectMismatch(cert, "127.0.0.2", .no_matching_entry);
    try expectMismatch(cert, "::2", .no_matching_entry);
    // A v4 address never matches the v6 SAN entry byte-wise or vice versa.
    try expectMismatch(cert, "::ffff:127.0.0.1", .no_matching_entry);

    // An IP reference is never compared against DNS-ID entries, even when
    // a hostile certificate presents an IP-shaped DNS name.
    var arena_inst = std.heap.ArenaAllocator.init(allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();
    const bytes = try certWithSanEntries(arena, &.{
        try tlv(arena, 0x82, &.{"10.0.0.1"}),
    });
    var hostile = try x509.Certificate.parse(allocator, bytes, .{});
    defer hostile.deinit(allocator);
    try expectMismatch(&hostile, "10.0.0.1", .no_entries_of_reference_type);
}

test "CN-only certificates fail identity verification" {
    const allocator = testing.allocator;
    var fixture = try Fixture.init(allocator, v1_leaf_pem);
    defer fixture.deinit(allocator);

    // Subject CN is exactly leaf.example.com; it must not be consulted.
    try testing.expectEqualStrings("leaf.example.com", fixture.cert.subject.commonName().?);
    try expectMismatch(&fixture.cert, "leaf.example.com", .no_subject_alt_name);
    try expectMismatch(&fixture.cert, "127.0.0.1", .no_subject_alt_name);
}

test "reference type must be present among SAN entries" {
    const allocator = testing.allocator;
    var fixture = try Fixture.init(allocator, ed25519_pem);
    defer fixture.deinit(allocator);

    // SAN carries only DNS:ed25519.example.com.
    try expectMatch(&fixture.cert, "ed25519.example.com");
    try expectMismatch(&fixture.cert, "127.0.0.1", .no_entries_of_reference_type);
    try expectMismatch(&fixture.cert, "2001:db8::1", .no_entries_of_reference_type);
}

test "mismatch results echo the reference identity and class only" {
    const allocator = testing.allocator;
    var fixture = try Fixture.init(allocator, ecdsa_leaf_pem);
    defer fixture.deinit(allocator);

    const verdict = try identity.verifyHost(&fixture.cert, "other.example.org");
    try testing.expectEqualStrings("other.example.org", verdict.mismatch.reference.dns_name);
    try testing.expectEqual(identity.MismatchClass.no_matching_entry, verdict.mismatch.class);

    const ip_verdict = try identity.verifyHost(&fixture.cert, "192.0.2.7");
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 7 }, ip_verdict.mismatch.reference.ip_address.bytes());
}

test "reference parsing enforces the A-label contract and LDH syntax" {
    // IP literals classify as IP references.
    try testing.expect(identity.ipReference("127.0.0.1") != null);
    try testing.expect(identity.ipReference("[2001:db8::1]") != null);
    try testing.expect(identity.ipReference("leaf.example.com") == null);

    // Brackets are IPv6-only host syntax: bracketed IPv4 is neither an IP
    // literal nor a valid DNS reference.
    try testing.expect(identity.ipReference("[127.0.0.1]") == null);
    try testing.expect(identity.ipReference("[]") == null);
    try testing.expect(identity.ipReference("[leaf.example.com]") == null);
    try testing.expectError(error.MalformedDnsReference, identity.reference("[127.0.0.1]"));

    // Valid DNS references normalize the trailing dot.
    const ref = try identity.reference("Leaf.Example.COM.");
    try testing.expectEqualStrings("Leaf.Example.COM", ref.dns_name);

    try testing.expectError(error.EmptyReference, identity.reference(""));
    try testing.expectError(error.EmptyReference, identity.reference("."));
    try testing.expectError(error.NonAsciiDnsReference, identity.reference("bücher.example"));
    try testing.expectError(error.MalformedDnsReference, identity.reference("*.example.com"));
    try testing.expectError(error.MalformedDnsReference, identity.reference("example..com"));
    try testing.expectError(error.MalformedDnsReference, identity.reference("example.com.."));
    try testing.expectError(error.MalformedDnsReference, identity.reference("-a.example.com"));
    try testing.expectError(error.MalformedDnsReference, identity.reference("a-.example.com"));
    try testing.expectError(error.MalformedDnsReference, identity.reference("a_b.example.com"));
    // IPv4-shaped names that failed strict IP parsing stay rejected.
    try testing.expectError(error.MalformedDnsReference, identity.reference("300.300.300.300"));
    try testing.expectError(error.MalformedDnsReference, identity.reference("0177.0.0.1"));
    try testing.expectError(error.MalformedDnsReference, identity.reference("127.0.0.1."));

    const long_label = "a" ** 64 ++ ".example.com";
    try testing.expectError(error.MalformedDnsReference, identity.reference(long_label));
    const long_name = ("abcd." ** 51) ++ "example";
    try testing.expectError(error.ReferenceTooLong, identity.reference(long_name));
}

test "presented DNS-ID matching is conservative about wildcards" {
    const cases = [_]struct {
        presented: []const u8,
        reference: []const u8,
        matches: bool,
    }{
        .{ .presented = "leaf.example.com", .reference = "leaf.example.com", .matches = true },
        .{ .presented = "LEAF.example.COM", .reference = "leaf.EXAMPLE.com", .matches = true },
        .{ .presented = "leaf.example.com.", .reference = "leaf.example.com", .matches = true },
        .{ .presented = "*.example.com", .reference = "www.example.com", .matches = true },
        .{ .presented = "*.EXAMPLE.com", .reference = "WWW.example.COM", .matches = true },
        .{ .presented = "*.example.com.", .reference = "www.example.com", .matches = true },

        // The wildcard label never matches zero or multiple labels.
        .{ .presented = "*.example.com", .reference = "example.com", .matches = false },
        .{ .presented = "*.example.com", .reference = "a.b.example.com", .matches = false },
        // Partial-label wildcards match nothing.
        .{ .presented = "f*o.example.com", .reference = "foo.example.com", .matches = false },
        .{ .presented = "foo*.example.com", .reference = "foobar.example.com", .matches = false },
        .{ .presented = "*foo.example.com", .reference = "barfoo.example.com", .matches = false },
        // Interior and multiple wildcards match nothing.
        .{ .presented = "a.*.example.com", .reference = "a.b.example.com", .matches = false },
        .{ .presented = "*.*.example.com", .reference = "a.b.example.com", .matches = false },
        // Public-suffix-style wildcards match nothing.
        .{ .presented = "*.com", .reference = "example.com", .matches = false },
        .{ .presented = "*.", .reference = "example", .matches = false },
        .{ .presented = "*", .reference = "example", .matches = false },
        // Malformed presented identifiers match nothing.
        .{ .presented = "", .reference = "example.com", .matches = false },
        .{ .presented = "ex ample.com", .reference = "example.com", .matches = false },
        .{ .presented = "example..com", .reference = "example.com", .matches = false },
        .{ .presented = "example.com..", .reference = "example.com", .matches = false },
        .{ .presented = "-a.example.com", .reference = "a.example.com", .matches = false },
    };
    for (cases) |case| {
        const ref = try identity.dnsReference(case.reference);
        try testing.expectEqual(case.matches, identity.presentedDnsIdMatches(case.presented, ref.dns_name));
    }
}

test "presentedDnsIdMatches re-validates raw reference input" {
    // A malformed reference with an empty leading label must not be
    // swallowed by the wildcard.
    try testing.expect(!identity.presentedDnsIdMatches("*.example.com", ".example.com"));
    try testing.expect(!identity.presentedDnsIdMatches("*.example.com", "..example.com"));
    try testing.expect(!identity.presentedDnsIdMatches("example.com", ""));
    try testing.expect(!identity.presentedDnsIdMatches("*.example.com", "*.example.com"));
    try testing.expect(!identity.presentedDnsIdMatches("bücher.example", "bücher.example"));

    // Raw (not pre-normalized) references still work: one trailing dot is
    // normalized during re-validation.
    try testing.expect(identity.presentedDnsIdMatches("leaf.example.com", "leaf.example.com."));
    try testing.expect(identity.presentedDnsIdMatches("*.example.com", "www.example.com."));
}

test "hostile presented identifiers in real SANs never match" {
    const allocator = testing.allocator;
    var arena_inst = std.heap.ArenaAllocator.init(allocator);
    defer arena_inst.deinit();
    const arena = arena_inst.allocator();

    const bytes = try certWithSanEntries(arena, &.{
        try tlv(arena, 0x82, &.{"*.com"}),
        try tlv(arena, 0x82, &.{"f*o.example.com"}),
        try tlv(arena, 0x82, &.{"*.*.example.com"}),
        try tlv(arena, 0x82, &.{"a.*.example.com"}),
    });
    var cert = try x509.Certificate.parse(allocator, bytes, .{});
    defer cert.deinit(allocator);

    try expectMismatch(&cert, "example.com", .no_matching_entry);
    try expectMismatch(&cert, "foo.example.com", .no_matching_entry);
    try expectMismatch(&cert, "a.b.example.com", .no_matching_entry);
    try expectMismatch(&cert, "anything.com", .no_matching_entry);
}

// Minimal certificate builder: SAN-bearing v3 certificate with an Ed25519
// algorithm shell (identity matching never touches keys or signatures).

fn tlv(arena: std.mem.Allocator, tag: u8, parts: []const []const u8) ![]u8 {
    var total: usize = 0;
    for (parts) |part| total += part.len;
    var len_buf: [9]u8 = undefined;
    const len_len = try der.encodeLength(total, &len_buf);
    var out = try arena.alloc(u8, 1 + len_len + total);
    out[0] = tag;
    @memcpy(out[1 .. 1 + len_len], len_buf[0..len_len]);
    var offset = 1 + len_len;
    for (parts) |part| {
        @memcpy(out[offset .. offset + part.len], part);
        offset += part.len;
    }
    return out;
}

fn oidTlv(arena: std.mem.Allocator, components: []const u32) ![]u8 {
    var buf: [64]u8 = undefined;
    const n = try oid.encodeComponents(components, &buf);
    return tlv(arena, 0x06, &.{buf[0..n]});
}

fn certWithSanEntries(arena: std.mem.Allocator, entries: []const []const u8) ![]u8 {
    const algorithm = try tlv(arena, 0x30, &.{try oidTlv(arena, &.{ 1, 3, 101, 112 })});
    const atv = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &oid.well_known.common_name),
        try tlv(arena, 0x0c, &.{"Synthetic"}),
    });
    const name = try tlv(arena, 0x30, &.{try tlv(arena, 0x31, &.{atv})});
    const validity = try tlv(arena, 0x30, &.{
        try tlv(arena, 0x17, &.{"260101000000Z"}),
        try tlv(arena, 0x17, &.{"270101000000Z"}),
    });
    const key = [_]u8{0x00} ++ [_]u8{0xaa} ** 32;
    const spki = try tlv(arena, 0x30, &.{ algorithm, try tlv(arena, 0x03, &.{&key}) });
    const san_ext = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &oid.well_known.subject_alt_name),
        try tlv(arena, 0x04, &.{try tlv(arena, 0x30, entries)}),
    });
    const extensions = try tlv(arena, 0xa3, &.{try tlv(arena, 0x30, &.{san_ext})});
    const tbs = try tlv(arena, 0x30, &.{
        try tlv(arena, 0xa0, &.{try tlv(arena, 0x02, &.{&[_]u8{0x02}})}),
        try tlv(arena, 0x02, &.{&[_]u8{0x01}}),
        algorithm,
        name,
        validity,
        name,
        spki,
        extensions,
    });
    const sig = [_]u8{0x00} ++ [_]u8{0xbb} ** 64;
    return tlv(arena, 0x30, &.{ tbs, algorithm, try tlv(arena, 0x03, &.{&sig}) });
}
