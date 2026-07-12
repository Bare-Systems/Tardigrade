//! Pure-Zig PEM and certificate-chain loader (#340).
//!
//! Loads X.509 certificates and ordered certificate chains from PEM or DER
//! buffers/files without constructing OpenSSL objects.
//!
//! ## PEM policy (RFC 7468 strict profile)
//!
//! - Only `CERTIFICATE` blocks yield certificates. Other well-formed blocks
//!   (`PRIVATE KEY`, `X509 CRL`, ...) are skipped so combined cert+key files
//!   load, but their boundaries must still pair up correctly.
//! - Text outside encapsulation boundaries is ignored (OpenSSL-style
//!   `subject=`/`issuer=` annotations between blocks are common).
//! - Boundary lines must start at column zero and carry nothing after the
//!   trailing dashes. A line starting with `-----` that is not a well-formed
//!   boundary is rejected rather than silently treated as text.
//! - Base64 is strict: standard alphabet only, mandatory canonical padding,
//!   zero trailing bits, no whitespace inside lines, no data after padding.
//! - LF and CRLF line endings are accepted (mixed freely); bare CR is not a
//!   line terminator.
//!
//! ## DER policy
//!
//! Every decoded certificate must be exactly one definite-length SEQUENCE
//! with no trailing bytes, validated by `der.Reader`. Full TBSCertificate
//! parsing is #341; this module preserves the exact DER bytes and input
//! order for it.
//!
//! ## Ownership
//!
//! Returned `Certificate` and `CertificateChain` values own copies of the
//! DER bytes. Callers free them with `deinit`, passing the same allocator
//! used to load. Input buffers are borrowed for the call only.

const std = @import("std");
const der = @import("der.zig");

/// Configurable loader resource bounds.
pub const Limits = struct {
    /// Maximum PEM/DER input size accepted by buffer APIs and file helpers.
    max_input_len: usize = 8 * 1024 * 1024,
    /// Maximum DER size of a single certificate.
    max_certificate_len: usize = 1024 * 1024,
    /// Maximum number of certificates in one chain or bundle.
    max_certificates: usize = 256,
    /// Structural bounds applied when validating each certificate's DER.
    der: der.Limits = .{},
};

pub const default_limits: Limits = .{};

pub const Error = error{
    /// Input (or file) exceeds `Limits.max_input_len`.
    InputTooLarge,
    /// A decoded certificate exceeds `Limits.max_certificate_len`.
    CertificateTooLarge,
    /// More than `Limits.max_certificates` certificates in the input.
    TooManyCertificates,
    /// No `CERTIFICATE` block (or empty DER input) — empty chains are invalid.
    NoCertificates,
    /// A line starting with `-----` is not a well-formed encapsulation
    /// boundary, an END appeared without a BEGIN, a BEGIN appeared inside an
    /// open block, or a label contains invalid characters.
    MalformedPemBoundary,
    /// An END boundary's label does not match the open BEGIN's label.
    MismatchedPemLabel,
    /// Input ended inside an encapsulated block.
    UnterminatedPemBlock,
    /// Invalid base64 character, non-canonical or missing padding, nonzero
    /// trailing bits, data after padding, or a blank/whitespace line inside
    /// an encapsulated block.
    InvalidPemBase64,
    /// A `CERTIFICATE` block decoded to zero bytes.
    EmptyPemBlock,
    /// Decoded bytes are not exactly one definite-length DER SEQUENCE.
    MalformedCertificateDer,
    OutOfMemory,
};

/// One certificate as exact DER bytes, owned by the loader's caller.
pub const Certificate = struct {
    der: []const u8,

    pub fn deinit(self: *Certificate, allocator: std.mem.Allocator) void {
        allocator.free(self.der);
        self.* = undefined;
    }
};

/// An ordered, non-empty certificate list preserving input order
/// (leaf first when the input follows TLS chain convention).
pub const CertificateChain = struct {
    certificates: []Certificate,

    pub fn deinit(self: *CertificateChain, allocator: std.mem.Allocator) void {
        for (self.certificates) |cert| allocator.free(cert.der);
        allocator.free(self.certificates);
        self.* = undefined;
    }
};

const begin_prefix = "-----BEGIN ";
const end_prefix = "-----END ";
const boundary_suffix = "-----";
const certificate_label = "CERTIFICATE";

/// Load every `CERTIFICATE` block from a PEM buffer, in input order.
pub fn loadChainPem(allocator: std.mem.Allocator, pem_text: []const u8, limits: Limits) Error!CertificateChain {
    if (pem_text.len > limits.max_input_len) return error.InputTooLarge;

    var certificates: std.ArrayList(Certificate) = .empty;
    defer {
        for (certificates.items) |cert| allocator.free(cert.der);
        certificates.deinit(allocator);
    }

    var base64_buf: std.ArrayList(u8) = .empty;
    defer base64_buf.deinit(allocator);

    const max_base64_len = base64EncodedLen(limits.max_certificate_len);

    const State = union(enum) {
        outside,
        in_certificate,
        in_skipped: []const u8,
    };
    var state: State = .outside;

    var lines = std.mem.splitScalar(u8, pem_text, '\n');
    while (lines.next()) |raw_line| {
        // Strip exactly one CR from a CRLF terminator. Any further CR stays
        // in the line and fails validation; bare CR is not a terminator.
        const line = if (raw_line.len > 0 and raw_line[raw_line.len - 1] == '\r')
            raw_line[0 .. raw_line.len - 1]
        else
            raw_line;
        // A trailing newline at EOF yields one final empty segment; that is
        // end-of-input, not a blank line inside a block.
        if (line.len == 0 and lines.peek() == null) break;
        switch (state) {
            .outside => {
                if (std.mem.startsWith(u8, line, "-----")) {
                    const boundary = try parseBoundary(line);
                    if (boundary.kind == .end) return error.MalformedPemBoundary;
                    if (std.mem.eql(u8, boundary.label, certificate_label)) {
                        base64_buf.clearRetainingCapacity();
                        state = .in_certificate;
                    } else {
                        state = .{ .in_skipped = boundary.label };
                    }
                }
                // Anything else outside a block is surrounding text; ignore.
            },
            .in_certificate => {
                if (std.mem.startsWith(u8, line, "-----")) {
                    const boundary = try parseBoundary(line);
                    if (boundary.kind == .begin) return error.MalformedPemBoundary;
                    if (!std.mem.eql(u8, boundary.label, certificate_label)) return error.MismatchedPemLabel;
                    if (certificates.items.len >= limits.max_certificates) return error.TooManyCertificates;
                    const der_bytes = try decodeCertificateBase64(allocator, base64_buf.items, limits);
                    errdefer allocator.free(der_bytes);
                    try certificates.append(allocator, .{ .der = der_bytes });
                    state = .outside;
                } else {
                    try validateBase64Line(line);
                    // items.len <= max_base64_len is an invariant, so the
                    // subtraction cannot underflow and the check cannot wrap.
                    if (line.len > max_base64_len - base64_buf.items.len) return error.CertificateTooLarge;
                    try base64_buf.appendSlice(allocator, line);
                }
            },
            .in_skipped => |label| {
                if (std.mem.startsWith(u8, line, "-----")) {
                    const boundary = try parseBoundary(line);
                    if (boundary.kind == .begin) return error.MalformedPemBoundary;
                    if (!std.mem.eql(u8, boundary.label, label)) return error.MismatchedPemLabel;
                    state = .outside;
                } else {
                    try validateBase64Line(line);
                }
            },
        }
    }
    if (state != .outside) return error.UnterminatedPemBlock;
    if (certificates.items.len == 0) return error.NoCertificates;

    const owned = try certificates.toOwnedSlice(allocator);
    return .{ .certificates = owned };
}

/// Load exactly one certificate from a PEM buffer. Rejects inputs carrying
/// more than one `CERTIFICATE` block.
pub fn loadCertificatePem(allocator: std.mem.Allocator, pem_text: []const u8, limits: Limits) Error!Certificate {
    var chain = try loadChainPem(allocator, pem_text, limits);
    if (chain.certificates.len != 1) {
        chain.deinit(allocator);
        return error.TooManyCertificates;
    }
    const cert = chain.certificates[0];
    allocator.free(chain.certificates);
    return cert;
}

/// Load a single certificate from raw DER bytes.
pub fn loadCertificateDer(allocator: std.mem.Allocator, der_bytes: []const u8, limits: Limits) Error!Certificate {
    if (der_bytes.len > limits.max_input_len) return error.InputTooLarge;
    if (der_bytes.len == 0) return error.NoCertificates;
    try validateCertificateDer(der_bytes, limits);
    const copy = try allocator.dupe(u8, der_bytes);
    return .{ .der = copy };
}

pub const FileError = Error || std.Io.File.OpenError || std.Io.File.Reader.Error;

/// Thin file helper over `loadChainPem`. Reads at most
/// `limits.max_input_len` bytes.
pub fn loadChainPemFile(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, sub_path: []const u8, limits: Limits) FileError!CertificateChain {
    const text = readFileBounded(allocator, io, dir, sub_path, limits.max_input_len) catch |err| switch (err) {
        error.StreamTooLong => return error.InputTooLarge,
        else => |other| return other,
    };
    defer allocator.free(text);
    return loadChainPem(allocator, text, limits);
}

/// Thin file helper over `loadCertificateDer`.
pub fn loadCertificateDerFile(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, sub_path: []const u8, limits: Limits) FileError!Certificate {
    const bytes = readFileBounded(allocator, io, dir, sub_path, limits.max_input_len) catch |err| switch (err) {
        error.StreamTooLong => return error.InputTooLarge,
        else => |other| return other,
    };
    defer allocator.free(bytes);
    return loadCertificateDer(allocator, bytes, limits);
}

fn readFileBounded(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, sub_path: []const u8, limit: usize) ![]u8 {
    return dir.readFileAlloc(io, sub_path, allocator, .limited(limit));
}

const BoundaryKind = enum { begin, end };

const Boundary = struct {
    kind: BoundaryKind,
    label: []const u8,
};

/// Parse a line already known to start with `-----` as an encapsulation
/// boundary. Labels follow RFC 7468: printable ASCII words separated by
/// single spaces or hyphens, no leading/trailing separator.
fn parseBoundary(line: []const u8) Error!Boundary {
    var kind: BoundaryKind = undefined;
    var rest: []const u8 = undefined;
    if (std.mem.startsWith(u8, line, begin_prefix)) {
        kind = .begin;
        rest = line[begin_prefix.len..];
    } else if (std.mem.startsWith(u8, line, end_prefix)) {
        kind = .end;
        rest = line[end_prefix.len..];
    } else {
        return error.MalformedPemBoundary;
    }
    if (!std.mem.endsWith(u8, rest, boundary_suffix)) return error.MalformedPemBoundary;
    const label = rest[0 .. rest.len - boundary_suffix.len];
    try validateLabel(label);
    return .{ .kind = kind, .label = label };
}

fn validateLabel(label: []const u8) Error!void {
    if (label.len == 0) return error.MalformedPemBoundary;
    var prev_separator = true; // Disallow a leading separator.
    for (label) |c| {
        if (c == ' ' or c == '-') {
            if (prev_separator) return error.MalformedPemBoundary;
            prev_separator = true;
        } else if (c >= 0x21 and c <= 0x7e) {
            prev_separator = false;
        } else {
            return error.MalformedPemBoundary;
        }
    }
    if (prev_separator) return error.MalformedPemBoundary;
}

/// Reject anything but base64 alphabet and padding before accumulation so
/// interior whitespace, blank lines, and control bytes fail loudly instead
/// of decoding by accident.
fn validateBase64Line(line: []const u8) Error!void {
    if (line.len == 0) return error.InvalidPemBase64;
    for (line) |c| {
        const valid = (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or c == '+' or c == '/' or c == '=';
        if (!valid) return error.InvalidPemBase64;
    }
}

fn decodeCertificateBase64(allocator: std.mem.Allocator, base64: []const u8, limits: Limits) Error![]u8 {
    if (base64.len == 0) return error.EmptyPemBlock;
    const decoder = std.base64.standard.Decoder;
    const decoded_len = decoder.calcSizeForSlice(base64) catch return error.InvalidPemBase64;
    if (decoded_len > limits.max_certificate_len) return error.CertificateTooLarge;
    const decoded = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(decoded);
    decoder.decode(decoded, base64) catch return error.InvalidPemBase64;
    if (decoded.len == 0) return error.EmptyPemBlock;
    try validateCertificateDer(decoded, limits);
    return decoded;
}

/// Certificate DER must be exactly one definite-length SEQUENCE spanning the
/// whole buffer. Interior structure is #341's job.
fn validateCertificateDer(bytes: []const u8, limits: Limits) Error!void {
    if (bytes.len > limits.max_certificate_len) return error.CertificateTooLarge;
    var reader = der.Reader.init(bytes, limits.der);
    const elem = reader.readElement() catch return error.MalformedCertificateDer;
    const sequence_tag = der.Tag.universal(@intFromEnum(der.UniversalTag.sequence), true);
    if (!elem.tag.eql(sequence_tag)) return error.MalformedCertificateDer;
    reader.expectEnd() catch return error.MalformedCertificateDer;
}

/// Base64 length (with padding) for `len` raw bytes. `Limits` is
/// caller-controlled, so this must not overflow for extreme values;
/// saturating at maxInt just means the accumulation bound defers to
/// `max_input_len`.
fn base64EncodedLen(len: usize) usize {
    const groups = len / 3 + @intFromBool(len % 3 != 0);
    return groups *| 4;
}

/// Fuzz and regression entrypoint (#327-G): parse arbitrary bytes as a PEM
/// bundle under strict limits without I/O, panics, or unbounded allocation.
pub fn fuzzLoadChainPem(allocator: std.mem.Allocator, input: []const u8) void {
    const limits: Limits = .{
        .max_input_len = 1024 * 1024,
        .max_certificate_len = 64 * 1024,
        .max_certificates = 16,
        .der = .{
            .max_depth = 8,
            .max_element_len = 64 * 1024,
            .max_elements = 64,
        },
    };
    var chain = loadChainPem(allocator, input, limits) catch return;
    chain.deinit(allocator);
}

const testing = std.testing;

test {
    testing.refAllDecls(@This());
}
