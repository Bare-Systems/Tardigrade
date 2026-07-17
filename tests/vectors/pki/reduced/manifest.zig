//! Reduced regression corpus promoted from PKI differential mismatch
//! artifacts (#348).
//!
//! Each entry is one minimized hostile input plus its deterministic expected
//! outcome. The build embeds this registry into the PKI unit-test module, so
//! every seed automatically joins the DER and X.509 fuzz corpora and gets a
//! decision regression test — see `src/pki/x509_tests.zig` and
//! `src/pki/der_tests.zig`.
//!
//! Promotion workflow: a differential mismatch writes
//! `<case-id>.reduced.der` next to its JSON artifact. Copy the reduced bytes
//! into this directory, add an entry here recording the observed parse
//! outcome and provenance, and keep the byte-for-byte reproduction test in
//! `tests/pki_differential.zig` green (the reduction is deterministic, so a
//! promoted seed must match a fresh reduction of its documented source).

pub const Entry = struct {
    /// Kebab-case seed name matching `<name>.der` in this directory.
    name: []const u8,
    seed: []const u8,
    /// Differential-manifest case id the seed was promoted from.
    source_case: []const u8,
    provenance: []const u8,
    license: []const u8,
    /// Expected `pki.x509.Certificate.parse` outcome under default limits:
    /// the error name, or null when the seed parses successfully.
    expected_parse_error: ?[]const u8,
};

pub const entries = [_]Entry{
    .{
        .name = "duplicate-critical-extension",
        .seed = @embedFile("duplicate-critical-extension.der"),
        .source_case = "duplicate-critical-extension",
        .provenance = "DER payload of tests/vectors/pki/duplicate-extension-leaf.crt, " ++
            "minimized by tests/pki_reduce.zig under the DuplicateExtension parse " ++
            "oracle; the reducer proves no single deletion preserves the class, so " ++
            "the seed is the 1-minimal reproduction of the rejection.",
        .license = "Apache-2.0",
        .expected_parse_error = "DuplicateExtension",
    },
};
