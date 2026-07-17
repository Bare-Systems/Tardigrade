//! Reduced regression corpus promoted from PKI differential mismatch
//! artifacts (#348).
//!
//! Each entry is one minimized hostile input plus its deterministic expected
//! outcome. The build embeds this registry into the PKI unit-test module, so
//! every seed automatically joins the DER and X.509 fuzz corpora and gets a
//! decision regression test — see `src/pki/x509_tests.zig` and
//! `src/pki/der_tests.zig`. Seeds whose interesting behavior is not a parse
//! error record the full in-process pipeline class instead, and the
//! differential module replays that exact class in the source case's chain
//! context.
//!
//! Promotion workflow: a differential mismatch artifact marked `promotable`
//! ships `<case-id>.reduced.der` next to its JSON. Copy the reduced bytes
//! into this directory, add an entry recording the observed outcome,
//! placement, and provenance, and extend the reproduction tests in
//! `tests/pki_differential.zig` with the seed's source context. Reduction is
//! deterministic, so a promoted seed must regenerate byte-for-byte from its
//! documented source and prove 1-minimality.

/// Where the seed sits in its source case's chain.
pub const Placement = union(enum) {
    leaf,
    intermediate: usize,
    root: usize,
};

/// Deterministic expected outcome of the promoted seed.
pub const Expected = union(enum) {
    /// `pki.x509.Certificate.parse` under default limits fails with this
    /// error name.
    parse_error: []const u8,
    /// The seed parses; the full in-process pipeline — path building,
    /// RFC 5280 validation, identity matching — yields exactly this
    /// `status|diagnostic` class in the source case's chain context.
    tardigrade_class: []const u8,
};

pub const Entry = struct {
    /// Kebab-case seed name matching `<name>.der` in this directory.
    name: []const u8,
    seed: []const u8,
    /// Differential-manifest case id the seed was promoted from.
    source_case: []const u8,
    placement: Placement,
    provenance: []const u8,
    license: []const u8,
    expected: Expected,
};

/// Derives the embedded seed from the entry name, so an entry can never
/// point at a differently named seed file.
fn entry(comptime name: []const u8, comptime fields: struct {
    source_case: []const u8,
    placement: Placement,
    provenance: []const u8,
    license: []const u8,
    expected: Expected,
}) Entry {
    return .{
        .name = name,
        .seed = @embedFile(name ++ ".der"),
        .source_case = fields.source_case,
        .placement = fields.placement,
        .provenance = fields.provenance,
        .license = fields.license,
        .expected = fields.expected,
    };
}

pub const entries = [_]Entry{
    entry("duplicate-critical-extension", .{
        .source_case = "duplicate-critical-extension",
        .placement = .leaf,
        .provenance = "DER payload of tests/vectors/pki/duplicate-extension-leaf.crt, " ++
            "minimized by tests/pki_reduce.zig under the DuplicateExtension parse " ++
            "oracle; the reducer's completed single-byte sweep proves the seed is " ++
            "the 1-minimal reproduction of the rejection.",
        .license = "Apache-2.0",
        .expected = .{ .parse_error = "DuplicateExtension" },
    }),
    entry("corrupt-certificate-signature", .{
        .source_case = "corrupt-certificate-signature",
        .placement = .leaf,
        .provenance = "DER payload of tests/vectors/pki/signature-corrupt-leaf.crt, " ++
            "minimized by tests/pki_reduce.zig under the full-pipeline class oracle " ++
            "(reject|signature_invalid at the leaf); the certificate parses, so the " ++
            "regression replays the recorded class through path building and " ++
            "validation rather than asserting a parse error.",
        .license = "Apache-2.0",
        .expected = .{ .tardigrade_class = "reject|signature_invalid certificate_index=0" },
    }),
};
