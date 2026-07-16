//! Candidate-path construction regression and adversarial tests (#344).
//!
//! Fixtures are synthetic certificates built with the same minimal DER
//! builder used by the #341 tests: name chaining and AKI/SKI hints are what
//! the path builder consumes, so unsigned Ed25519 placeholders are
//! sufficient — no fixture signature verifies, by design, because
//! construction must not depend on signatures.

const std = @import("std");
const der = @import("der.zig");
const oid = @import("oid.zig");
const x509 = @import("x509.zig");
const path_builder = @import("path_builder.zig");

const testing = std.testing;

// --- Synthetic certificate builder ------------------------------------------

/// Concatenate `parts` into one TLV with a single-byte tag.
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

const ed25519_components = [_]u32{ 1, 3, 101, 112 };

fn algorithmEd25519(arena: std.mem.Allocator) ![]u8 {
    return tlv(arena, 0x30, &.{try oidTlv(arena, &ed25519_components)});
}

fn nameWithCn(arena: std.mem.Allocator, cn: []const u8, value_tag: u8) ![]u8 {
    const atv = try tlv(arena, 0x30, &.{
        try oidTlv(arena, &oid.well_known.common_name),
        try tlv(arena, value_tag, &.{cn}),
    });
    return tlv(arena, 0x30, &.{try tlv(arena, 0x31, &.{atv})});
}

fn utcValidity(arena: std.mem.Allocator) ![]u8 {
    return tlv(arena, 0x30, &.{
        try tlv(arena, 0x17, &.{"260101000000Z"}),
        try tlv(arena, 0x17, &.{"270101000000Z"}),
    });
}

fn spkiEd25519(arena: std.mem.Allocator) ![]u8 {
    const key = [_]u8{0x00} ++ [_]u8{0xaa} ** 32;
    return tlv(arena, 0x30, &.{
        try algorithmEd25519(arena),
        try tlv(arena, 0x03, &.{&key}),
    });
}

fn signatureBits(arena: std.mem.Allocator) ![]u8 {
    const sig = [_]u8{0x00} ++ [_]u8{0xbb} ** 64;
    return tlv(arena, 0x03, &.{&sig});
}

fn extensionTlv(arena: std.mem.Allocator, ext_oid: []const u32, value: []const u8) ![]u8 {
    return tlv(arena, 0x30, &.{
        try oidTlv(arena, ext_oid),
        try tlv(arena, 0x04, &.{value}),
    });
}

const Spec = struct {
    subject_cn: []const u8,
    issuer_cn: []const u8,
    /// Serial content byte — vary it to make otherwise-identical
    /// certificates byte-distinct.
    serial: u8 = 1,
    /// SubjectKeyIdentifier content when present.
    ski: ?[]const u8 = null,
    /// AuthorityKeyIdentifier keyIdentifier content when present.
    aki: ?[]const u8 = null,
    /// DER string tags for the CN values (UTF8String by default;
    /// 0x13 = PrintableString).
    subject_cn_tag: u8 = 0x0c,
    issuer_cn_tag: u8 = 0x0c,
};

/// Build one certificate's DER: v1 when no key identifiers are requested,
/// v3 with SKI/AKI extensions otherwise.
fn buildDer(arena: std.mem.Allocator, spec: Spec) ![]u8 {
    var extensions: std.ArrayList([]const u8) = .empty;
    defer extensions.deinit(arena);
    if (spec.ski) |ski| {
        const value = try tlv(arena, 0x04, &.{ski});
        try extensions.append(arena, try extensionTlv(arena, &oid.well_known.subject_key_identifier, value));
    }
    if (spec.aki) |aki| {
        const value = try tlv(arena, 0x30, &.{try tlv(arena, 0x80, &.{aki})});
        try extensions.append(arena, try extensionTlv(arena, &oid.well_known.authority_key_identifier, value));
    }

    var parts: std.ArrayList([]const u8) = .empty;
    defer parts.deinit(arena);
    if (extensions.items.len > 0) {
        // version [0] EXPLICIT INTEGER v3.
        try parts.append(arena, try tlv(arena, 0xa0, &.{try tlv(arena, 0x02, &.{&[_]u8{0x02}})}));
    }
    try parts.append(arena, try tlv(arena, 0x02, &.{&[_]u8{spec.serial}}));
    try parts.append(arena, try algorithmEd25519(arena));
    try parts.append(arena, try nameWithCn(arena, spec.issuer_cn, spec.issuer_cn_tag));
    try parts.append(arena, try utcValidity(arena));
    try parts.append(arena, try nameWithCn(arena, spec.subject_cn, spec.subject_cn_tag));
    try parts.append(arena, try spkiEd25519(arena));
    if (extensions.items.len > 0) {
        try parts.append(arena, try tlv(arena, 0xa3, &.{try tlv(arena, 0x30, extensions.items)}));
    }
    const tbs = try tlv(arena, 0x30, parts.items);
    return tlv(arena, 0x30, &.{ tbs, try algorithmEd25519(arena), try signatureBits(arena) });
}

/// A batch of parsed fixture certificates. `certs` order matches the `add`
/// call order; DER bytes live in the arena, parsed views in `allocator`.
const Fixtures = struct {
    allocator: std.mem.Allocator,
    arena_inst: std.heap.ArenaAllocator,
    certs: std.ArrayList(x509.Certificate),

    fn init(allocator: std.mem.Allocator) Fixtures {
        return .{
            .allocator = allocator,
            .arena_inst = std.heap.ArenaAllocator.init(allocator),
            .certs = .empty,
        };
    }

    fn deinit(self: *Fixtures) void {
        for (self.certs.items) |*cert| cert.deinit(self.allocator);
        self.certs.deinit(self.allocator);
        self.arena_inst.deinit();
        self.* = undefined;
    }

    fn add(self: *Fixtures, spec: Spec) !void {
        const bytes = try buildDer(self.arena_inst.allocator(), spec);
        const cert = try x509.Certificate.parse(self.allocator, bytes, .{});
        errdefer {
            var owned = cert;
            owned.deinit(self.allocator);
        }
        try self.certs.append(self.allocator, cert);
    }

    /// Re-add certificate `index` byte-identically (a true duplicate).
    fn addDuplicateOf(self: *Fixtures, index: usize) !void {
        const cert = try x509.Certificate.parse(self.allocator, self.certs.items[index].raw, .{});
        errdefer {
            var owned = cert;
            owned.deinit(self.allocator);
        }
        try self.certs.append(self.allocator, cert);
    }
};

fn expectPathCns(path: path_builder.Path, expected: []const []const u8) !void {
    try testing.expectEqual(expected.len, path.elements.len);
    for (path.elements, expected) |element, cn| {
        try testing.expectEqualStrings(cn, element.certificate.subject.commonName().?);
    }
}

// --- Straight chains ---------------------------------------------------------

test "straight chain builds exactly one path in order" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject_cn = "leaf", .issuer_cn = "Mid CA" });
    try fx.add(.{ .subject_cn = "Mid CA", .issuer_cn = "Root CA" });
    try fx.add(.{ .subject_cn = "Root CA", .issuer_cn = "Root CA" });

    const certs = fx.certs.items;
    var result = try path_builder.build(testing.allocator, &certs[0], certs[1..2], certs[2..3], .{});
    defer result.deinit(testing.allocator);

    try testing.expect(!result.truncated);
    try testing.expectEqual(@as(usize, 1), result.paths.len);
    try expectPathCns(result.paths[0], &.{ "leaf", "Mid CA", "Root CA" });

    const path = result.paths[0];
    try testing.expectEqual(path_builder.Source.leaf, path.leaf().source);
    try testing.expectEqual(path_builder.Source.intermediate, path.elements[1].source);
    try testing.expectEqual(path_builder.Source.anchor, path.anchor().source);
    try testing.expectEqual(@as(usize, 0), path.elements[1].input_index);
    try testing.expectEqual(@as(usize, 0), path.anchor().input_index);
    // Elements borrow the caller's certificates.
    try testing.expectEqual(&certs[0], path.leaf().certificate);
    try testing.expectEqual(&certs[2], path.anchor().certificate);
}

test "leaf issued directly by an anchor builds a two-element path" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject_cn = "leaf", .issuer_cn = "Root CA" });
    try fx.add(.{ .subject_cn = "Root CA", .issuer_cn = "Root CA" });

    const certs = fx.certs.items;
    var result = try path_builder.build(testing.allocator, &certs[0], &.{}, certs[1..2], .{});
    defer result.deinit(testing.allocator);

    try testing.expect(!result.truncated);
    try testing.expectEqual(@as(usize, 1), result.paths.len);
    try expectPathCns(result.paths[0], &.{ "leaf", "Root CA" });
}

test "issuer matching uses RFC 5280 name chaining, not encoding equality" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    // The leaf's issuer is a UTF8String with case and white-space noise;
    // the anchor's subject is a canonical PrintableString. RFC 5280 §7.1
    // chaining must still connect them even though the Name encodings
    // differ byte-for-byte.
    try fx.add(.{ .subject_cn = "leaf", .issuer_cn = "  EXAMPLE   ca " });
    try fx.add(.{
        .subject_cn = "Example CA",
        .issuer_cn = "Example CA",
        .subject_cn_tag = 0x13,
        .issuer_cn_tag = 0x13,
    });

    const certs = fx.certs.items;
    try testing.expect(!certs[0].issuer.eqlEncoding(&certs[1].subject));
    try testing.expect(certs[0].issuer.eqlForChaining(&certs[1].subject));

    var result = try path_builder.build(testing.allocator, &certs[0], &.{}, certs[1..2], .{});
    defer result.deinit(testing.allocator);

    try testing.expect(!result.truncated);
    try testing.expectEqual(@as(usize, 1), result.paths.len);
    try expectPathCns(result.paths[0], &.{ "leaf", "Example CA" });
    try testing.expectEqual(path_builder.Source.anchor, result.paths[0].anchor().source);
}

// --- Cross-signed roots ------------------------------------------------------

test "cross-signed root enumerates the anchor path before the cross path" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    // Chain: leaf <- Mid <- "Root A", where Root A is both a configured
    // anchor and cross-signed by Root B via a peer-supplied cross-cert.
    try fx.add(.{ .subject_cn = "leaf", .issuer_cn = "Mid CA" });
    try fx.add(.{ .subject_cn = "Mid CA", .issuer_cn = "Root A", .aki = "kA" });
    try fx.add(.{ .subject_cn = "Root A", .issuer_cn = "Root B", .serial = 2, .ski = "kA", .aki = "kB" });
    try fx.add(.{ .subject_cn = "Root A", .issuer_cn = "Root A", .serial = 3, .ski = "kA" });
    try fx.add(.{ .subject_cn = "Root B", .issuer_cn = "Root B", .ski = "kB" });

    const certs = fx.certs.items;
    const intermediates = certs[1..3]; // Mid, cross-signed Root A
    const anchors = certs[3..5]; // self-signed Root A, Root B
    var result = try path_builder.build(testing.allocator, &certs[0], intermediates, anchors, .{});
    defer result.deinit(testing.allocator);

    try testing.expect(!result.truncated);
    try testing.expectEqual(@as(usize, 2), result.paths.len);
    // Both candidates for Mid's issuer agree on the key identifier, so the
    // anchor-terminated path is enumerated before the cross-certificate one.
    try expectPathCns(result.paths[0], &.{ "leaf", "Mid CA", "Root A" });
    try testing.expectEqual(path_builder.Source.anchor, result.paths[0].anchor().source);
    try expectPathCns(result.paths[1], &.{ "leaf", "Mid CA", "Root A", "Root B" });
    try testing.expectEqual(path_builder.Source.intermediate, result.paths[1].elements[2].source);
}

// --- Ambiguous issuers -------------------------------------------------------

test "key identifier agreement outranks source and input order" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    // Two intermediates share the subject "CA X" but carry different keys;
    // the leaf's AKI names the second one's key. An anchor with the same
    // subject and a mismatching key also exists.
    try fx.add(.{ .subject_cn = "leaf", .issuer_cn = "CA X", .aki = "k2" });
    try fx.add(.{ .subject_cn = "CA X", .issuer_cn = "Root CA", .serial = 2, .ski = "k1" });
    try fx.add(.{ .subject_cn = "CA X", .issuer_cn = "Root CA", .serial = 3, .ski = "k2" });
    try fx.add(.{ .subject_cn = "CA X", .issuer_cn = "CA X", .serial = 4, .ski = "k9" });
    try fx.add(.{ .subject_cn = "Root CA", .issuer_cn = "Root CA" });

    const certs = fx.certs.items;
    var result = try path_builder.build(testing.allocator, &certs[0], certs[1..3], certs[3..5], .{});
    defer result.deinit(testing.allocator);

    try testing.expect(!result.truncated);
    try testing.expectEqual(@as(usize, 3), result.paths.len);
    // The key-id match ("k2") is tried first despite its higher input index
    // and despite an anchor competing: agreement outranks source. The two
    // mismatches ("k9" anchor, "k1" intermediate) tie on rank, so the anchor
    // goes first among them.
    try testing.expectEqual(@as(usize, 1), result.paths[0].elements[1].input_index); // k2 intermediate
    try expectPathCns(result.paths[0], &.{ "leaf", "CA X", "Root CA" });
    try expectPathCns(result.paths[1], &.{ "leaf", "CA X" });
    try testing.expectEqual(path_builder.Source.anchor, result.paths[1].anchor().source);
    try testing.expectEqual(@as(usize, 0), result.paths[2].elements[1].input_index); // k1 intermediate
    try expectPathCns(result.paths[2], &.{ "leaf", "CA X", "Root CA" });
}

test "identical inputs always enumerate identical results" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject_cn = "leaf", .issuer_cn = "CA X" });
    try fx.add(.{ .subject_cn = "CA X", .issuer_cn = "Root CA", .serial = 2 });
    try fx.add(.{ .subject_cn = "CA X", .issuer_cn = "Root CA", .serial = 3 });
    try fx.add(.{ .subject_cn = "Root CA", .issuer_cn = "Root CA" });

    const certs = fx.certs.items;
    var first = try path_builder.build(testing.allocator, &certs[0], certs[1..3], certs[3..4], .{});
    defer first.deinit(testing.allocator);
    var second = try path_builder.build(testing.allocator, &certs[0], certs[1..3], certs[3..4], .{});
    defer second.deinit(testing.allocator);

    try testing.expectEqual(first.paths.len, second.paths.len);
    for (first.paths, second.paths) |a, b| {
        try testing.expectEqual(a.elements.len, b.elements.len);
        for (a.elements, b.elements) |ea, eb| {
            try testing.expectEqual(ea.certificate, eb.certificate);
            try testing.expectEqual(ea.source, eb.source);
            try testing.expectEqual(ea.input_index, eb.input_index);
        }
    }
    // With no key-identifier evidence, ties break by ascending input index.
    try testing.expectEqual(@as(usize, 0), first.paths[0].elements[1].input_index);
    try testing.expectEqual(@as(usize, 1), first.paths[1].elements[1].input_index);
}

// --- Duplicates --------------------------------------------------------------

test "duplicate certificates collapse to one candidate" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject_cn = "leaf", .issuer_cn = "Mid CA" });
    try fx.add(.{ .subject_cn = "Mid CA", .issuer_cn = "Root CA" });
    try fx.addDuplicateOf(1);
    try fx.addDuplicateOf(1);
    try fx.add(.{ .subject_cn = "Root CA", .issuer_cn = "Root CA" });

    const certs = fx.certs.items;
    var result = try path_builder.build(testing.allocator, &certs[0], certs[1..4], certs[4..5], .{});
    defer result.deinit(testing.allocator);

    try testing.expect(!result.truncated);
    try testing.expectEqual(@as(usize, 1), result.paths.len);
    try expectPathCns(result.paths[0], &.{ "leaf", "Mid CA", "Root CA" });
    // The surviving candidate is the first occurrence.
    try testing.expectEqual(@as(usize, 0), result.paths[0].elements[1].input_index);
}

test "peer-supplied copy of the anchor does not lengthen the path" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    // Peer sends [leaf, Mid, Root] with Root also configured as an anchor:
    // the classic redundant-root chain. The root must terminate the path
    // once, not appear as intermediate and anchor.
    try fx.add(.{ .subject_cn = "leaf", .issuer_cn = "Mid CA" });
    try fx.add(.{ .subject_cn = "Mid CA", .issuer_cn = "Root CA" });
    try fx.add(.{ .subject_cn = "Root CA", .issuer_cn = "Root CA" });
    try fx.addDuplicateOf(2);

    const certs = fx.certs.items;
    var result = try path_builder.build(testing.allocator, &certs[0], certs[1..3], certs[3..4], .{});
    defer result.deinit(testing.allocator);

    try testing.expect(!result.truncated);
    try testing.expectEqual(@as(usize, 1), result.paths.len);
    try expectPathCns(result.paths[0], &.{ "leaf", "Mid CA", "Root CA" });
    try testing.expectEqual(path_builder.Source.anchor, result.paths[0].anchor().source);
}

// --- Cycles ------------------------------------------------------------------

test "issuer cycles terminate with no path" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    // A <-> B name cycle with no anchor reachable.
    try fx.add(.{ .subject_cn = "leaf", .issuer_cn = "CA A" });
    try fx.add(.{ .subject_cn = "CA A", .issuer_cn = "CA B", .serial = 2 });
    try fx.add(.{ .subject_cn = "CA B", .issuer_cn = "CA A", .serial = 3 });
    try fx.add(.{ .subject_cn = "Unrelated Root", .issuer_cn = "Unrelated Root" });

    const certs = fx.certs.items;
    try testing.expectError(
        error.NoCandidatePath,
        path_builder.build(testing.allocator, &certs[0], certs[1..3], certs[3..4], .{}),
    );
}

test "self-signed intermediate does not loop onto itself" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject_cn = "leaf", .issuer_cn = "Self CA" });
    try fx.add(.{ .subject_cn = "Self CA", .issuer_cn = "Self CA", .serial = 2 });
    try fx.add(.{ .subject_cn = "Unrelated Root", .issuer_cn = "Unrelated Root" });

    const certs = fx.certs.items;
    try testing.expectError(
        error.NoCandidatePath,
        path_builder.build(testing.allocator, &certs[0], certs[1..2], certs[2..3], .{}),
    );
}

// --- Incomplete chains and error taxonomy ------------------------------------

test "missing intermediate is a deterministic no-path" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject_cn = "leaf", .issuer_cn = "Missing CA" });
    try fx.add(.{ .subject_cn = "Root CA", .issuer_cn = "Root CA" });

    const certs = fx.certs.items;
    try testing.expectError(
        error.NoCandidatePath,
        path_builder.build(testing.allocator, &certs[0], &.{}, certs[1..2], .{}),
    );
}

test "empty trust store and oversized pools fail typed before searching" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject_cn = "leaf", .issuer_cn = "Root CA" });
    try fx.add(.{ .subject_cn = "Root CA", .issuer_cn = "Root CA" });

    const certs = fx.certs.items;
    try testing.expectError(
        error.NoTrustAnchors,
        path_builder.build(testing.allocator, &certs[0], &.{}, &.{}, .{}),
    );

    var tight: path_builder.Limits = .{};
    tight.max_anchors = 0;
    try testing.expectError(
        error.CountLimitExceeded,
        path_builder.build(testing.allocator, &certs[0], &.{}, certs[1..2], tight),
    );
    tight = .{};
    tight.max_intermediates = 0;
    try testing.expectError(
        error.CountLimitExceeded,
        path_builder.build(testing.allocator, &certs[0], certs[0..1], certs[1..2], tight),
    );
}

// --- Anchors are anchors ------------------------------------------------------

test "paths terminate at the first anchor and never traverse beyond it" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    // Mid CA is itself trusted. Even though Root CA is also an anchor and
    // Mid's issuer, the path stops at Mid; anchors are terminal.
    try fx.add(.{ .subject_cn = "leaf", .issuer_cn = "Mid CA" });
    try fx.add(.{ .subject_cn = "Mid CA", .issuer_cn = "Root CA" });
    try fx.add(.{ .subject_cn = "Root CA", .issuer_cn = "Root CA" });

    const certs = fx.certs.items;
    var result = try path_builder.build(testing.allocator, &certs[0], &.{}, certs[1..3], .{});
    defer result.deinit(testing.allocator);

    try testing.expect(!result.truncated);
    try testing.expectEqual(@as(usize, 1), result.paths.len);
    try expectPathCns(result.paths[0], &.{ "leaf", "Mid CA" });
    try testing.expectEqual(path_builder.Source.anchor, result.paths[0].anchor().source);
}

// --- Search limits -----------------------------------------------------------

test "depth limit truncates deep chains" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject_cn = "leaf", .issuer_cn = "CA 1" });
    try fx.add(.{ .subject_cn = "CA 1", .issuer_cn = "CA 2" });
    try fx.add(.{ .subject_cn = "CA 2", .issuer_cn = "CA 3" });
    try fx.add(.{ .subject_cn = "CA 3", .issuer_cn = "Root CA" });
    try fx.add(.{ .subject_cn = "Root CA", .issuer_cn = "Root CA" });

    const certs = fx.certs.items;
    var limits: path_builder.Limits = .{};
    limits.max_path_len = 4; // leaf + 3 more; the real path needs 5.
    try testing.expectError(
        error.SearchLimitExceeded,
        path_builder.build(testing.allocator, &certs[0], certs[1..4], certs[4..5], limits),
    );

    // One more element of room and the same inputs succeed.
    limits.max_path_len = 5;
    var result = try path_builder.build(testing.allocator, &certs[0], certs[1..4], certs[4..5], limits);
    defer result.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), result.paths.len);
    try expectPathCns(result.paths[0], &.{ "leaf", "CA 1", "CA 2", "CA 3", "Root CA" });
}

test "visit budget bounds adversarial fanout without losing found paths" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    // A two-layer explosion: many distinct "CA X" certificates, each of
    // which sees many distinct "CA Y" issuer candidates.
    try fx.add(.{ .subject_cn = "leaf", .issuer_cn = "CA X" });
    var serial: u8 = 2;
    var count: usize = 0;
    while (count < 8) : (count += 1) {
        try fx.add(.{ .subject_cn = "CA X", .issuer_cn = "CA Y", .serial = serial });
        serial += 1;
    }
    count = 0;
    while (count < 8) : (count += 1) {
        try fx.add(.{ .subject_cn = "CA Y", .issuer_cn = "Nowhere", .serial = serial });
        serial += 1;
    }
    try fx.add(.{ .subject_cn = "Unrelated Root", .issuer_cn = "Unrelated Root" });

    const certs = fx.certs.items;
    const intermediates = certs[1..17];
    const anchors = certs[17..18];

    // Exhaustive search proves there is no path...
    try testing.expectError(
        error.NoCandidatePath,
        path_builder.build(testing.allocator, &certs[0], intermediates, anchors, .{}),
    );

    // ...but a tight budget stops before proving it, and says so.
    var limits: path_builder.Limits = .{};
    limits.max_candidate_visits = 4;
    try testing.expectError(
        error.SearchLimitExceeded,
        path_builder.build(testing.allocator, &certs[0], intermediates, anchors, limits),
    );
}

test "tight budget cannot starve the best-ranked candidate" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    // Several mismatching same-subject anchors compete with one AKI/SKI-
    // matching intermediate. The visit budget is charged per candidate the
    // traversal attempts — after ranking and fanout — so scanning the
    // mismatching anchors while building the candidate list must not spend
    // the budget needed to walk the documented best-ranked path.
    try fx.add(.{ .subject_cn = "leaf", .issuer_cn = "CA X", .aki = "good" });
    try fx.add(.{ .subject_cn = "CA X", .issuer_cn = "Root CA", .serial = 2, .ski = "good" });
    try fx.add(.{ .subject_cn = "CA X", .issuer_cn = "CA X", .serial = 3, .ski = "bad1" });
    try fx.add(.{ .subject_cn = "CA X", .issuer_cn = "CA X", .serial = 4, .ski = "bad2" });
    try fx.add(.{ .subject_cn = "CA X", .issuer_cn = "CA X", .serial = 5, .ski = "bad3" });
    try fx.add(.{ .subject_cn = "Root CA", .issuer_cn = "Root CA" });

    const certs = fx.certs.items;
    var limits: path_builder.Limits = .{};
    limits.max_fanout = 1;
    limits.max_candidate_visits = 2; // exactly the two edges of the best path
    var result = try path_builder.build(testing.allocator, &certs[0], certs[1..2], certs[2..6], limits);
    defer result.deinit(testing.allocator);

    try testing.expect(result.truncated); // fanout dropped the anchors
    try testing.expectEqual(@as(usize, 1), result.paths.len);
    try expectPathCns(result.paths[0], &.{ "leaf", "CA X", "Root CA" });
    try testing.expectEqual(path_builder.Source.intermediate, result.paths[0].elements[1].source);
}

test "fanout-discarded candidates do not consume the traversal budget" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    // A wide first node: five same-subject decoys are collected and then
    // discarded by max_fanout. Only attempted candidates may be charged, so
    // a budget covering exactly the retained path must still succeed.
    try fx.add(.{ .subject_cn = "leaf", .issuer_cn = "CA X" });
    try fx.add(.{ .subject_cn = "CA X", .issuer_cn = "Root CA", .serial = 2 });
    try fx.add(.{ .subject_cn = "CA X", .issuer_cn = "Nowhere", .serial = 3 });
    try fx.add(.{ .subject_cn = "CA X", .issuer_cn = "Nowhere", .serial = 4 });
    try fx.add(.{ .subject_cn = "CA X", .issuer_cn = "Nowhere", .serial = 5 });
    try fx.add(.{ .subject_cn = "CA X", .issuer_cn = "Nowhere", .serial = 6 });
    try fx.add(.{ .subject_cn = "CA X", .issuer_cn = "Nowhere", .serial = 7 });
    try fx.add(.{ .subject_cn = "Root CA", .issuer_cn = "Root CA" });

    const certs = fx.certs.items;
    var limits: path_builder.Limits = .{};
    limits.max_fanout = 1;
    limits.max_candidate_visits = 2;
    var result = try path_builder.build(testing.allocator, &certs[0], certs[1..7], certs[7..8], limits);
    defer result.deinit(testing.allocator);

    try testing.expect(result.truncated); // fanout dropped the decoys
    try testing.expectEqual(@as(usize, 1), result.paths.len);
    try expectPathCns(result.paths[0], &.{ "leaf", "CA X", "Root CA" });
    try testing.expectEqual(@as(usize, 0), result.paths[0].elements[1].input_index);
}

test "fanout and path caps truncate enumeration deterministically" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject_cn = "leaf", .issuer_cn = "CA X" });
    try fx.add(.{ .subject_cn = "CA X", .issuer_cn = "Root CA", .serial = 2 });
    try fx.add(.{ .subject_cn = "CA X", .issuer_cn = "Root CA", .serial = 3 });
    try fx.add(.{ .subject_cn = "CA X", .issuer_cn = "Root CA", .serial = 4 });
    try fx.add(.{ .subject_cn = "Root CA", .issuer_cn = "Root CA" });

    const certs = fx.certs.items;

    // max_paths cuts enumeration after the first (best-ranked) path.
    var limits: path_builder.Limits = .{};
    limits.max_paths = 1;
    var capped = try path_builder.build(testing.allocator, &certs[0], certs[1..4], certs[4..5], limits);
    defer capped.deinit(testing.allocator);
    try testing.expect(capped.truncated);
    try testing.expectEqual(@as(usize, 1), capped.paths.len);
    try testing.expectEqual(@as(usize, 0), capped.paths[0].elements[1].input_index);

    // max_fanout keeps only the best-ranked candidates per node.
    limits = .{};
    limits.max_fanout = 2;
    var fanned = try path_builder.build(testing.allocator, &certs[0], certs[1..4], certs[4..5], limits);
    defer fanned.deinit(testing.allocator);
    try testing.expect(fanned.truncated);
    try testing.expectEqual(@as(usize, 2), fanned.paths.len);
    try testing.expectEqual(@as(usize, 0), fanned.paths[0].elements[1].input_index);
    try testing.expectEqual(@as(usize, 1), fanned.paths[1].elements[1].input_index);

    // Unbounded enough limits enumerate all three, untruncated.
    var full = try path_builder.build(testing.allocator, &certs[0], certs[1..4], certs[4..5], .{});
    defer full.deinit(testing.allocator);
    try testing.expect(!full.truncated);
    try testing.expectEqual(@as(usize, 3), full.paths.len);
}

// --- Allocation-failure safety -----------------------------------------------

test "builder is leak-free across allocation failure points" {
    var fx = Fixtures.init(testing.allocator);
    defer fx.deinit();
    try fx.add(.{ .subject_cn = "leaf", .issuer_cn = "Mid CA", .aki = "k1" });
    try fx.add(.{ .subject_cn = "Mid CA", .issuer_cn = "Root A", .serial = 2, .ski = "k1" });
    try fx.add(.{ .subject_cn = "Root A", .issuer_cn = "Root B", .serial = 3 });
    try fx.add(.{ .subject_cn = "Root A", .issuer_cn = "Root A", .serial = 4 });
    try fx.add(.{ .subject_cn = "Root B", .issuer_cn = "Root B" });

    const certs = fx.certs.items;
    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn run(
            inner_allocator: std.mem.Allocator,
            leaf: *const x509.Certificate,
            intermediates: []const x509.Certificate,
            anchors: []const x509.Certificate,
        ) !void {
            var result = try path_builder.build(inner_allocator, leaf, intermediates, anchors, .{});
            result.deinit(inner_allocator);
        }
    }.run, .{ &certs[0], certs[1..3], certs[3..5] });
}
