//! Native Web-PKI peer verification for the TLS client role (#634).
//!
//! Adapts the pure-Zig PKI chain builder/validator (`src/pki/`) to the
//! engine's `credentials.PeerVerifier` contract, for a TLS client that must
//! authenticate a server certificate chain against a trust-anchor set —
//! today the native upstream HTTPS client (`http/upstream_tls.zig`),
//! and any future native TLS client role — rather than a fixed pin or
//! insecure passthrough (both already covered by `credentials.FixedVerifier`
//! via `Trust.insecure_no_verification` / `.pinned_certificate`).
//!
//! No cryptographic primitive or ASN.1 decoder is implemented here: this file
//! only wires the existing chain builder (`pki.path_builder`), validator
//! (`pki.path_validator`, which itself calls `pki.identity.verifyHost` for
//! RFC 9525 hostname/SAN matching), and trust-anchor store (`pki.trust_store`)
//! together behind the engine's verifier seam. Verification is entirely
//! synchronous — no network or filesystem access happens during a handshake —
//! so `verifyPeer` always completes with `.complete`, never `.pending`.

const std = @import("std");
const crypto = @import("crypto");
const pki = @import("pki");
const zig_compat = @import("zig_compat");
const credentials = @import("credentials.zig");

pub const Error = pki.trust_store.FileError || error{NoSystemTrustAnchors};

/// Ordered, well-known CA bundle file locations consulted when no explicit
/// upstream CA bundle path is configured — the native-profile analogue of
/// OpenSSL's compiled-in default verify path
/// (`SSL_CTX_set_default_verify_paths`, see `upstream_tls.zig`). This is
/// plain filesystem access via the pure-Zig PEM/X.509 loader, not a foreign
/// TLS/crypto library — see the #634 comment clarifying that "pure Zig"
/// bounds external *protocol/crypto* implementations, not ordinary OS/kernel
/// facilities. The first candidate that exists and loads is used.
const system_ca_bundle_candidates = [_][]const u8{
    "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Arch
    "/etc/pki/tls/certs/ca-bundle.crt", // Fedora/RHEL/CentOS
    "/etc/ssl/cert.pem", // Alpine, macOS/Homebrew OpenSSL layout, *BSD
    "/etc/ssl/ca-bundle.pem", // openSUSE
    "/etc/pki/tls/cacert.pem", // older RHEL
    "/etc/certs/ca-certificates.crt", // Solaris/illumos
};

/// An owned trust-anchor snapshot ready for repeated `WebPkiVerifier` use.
/// Caller-owned; free with `deinit` once no in-flight verifier needs it.
pub const TrustAnchors = struct {
    snapshot: pki.trust_store.Snapshot,

    pub fn deinit(self: *TrustAnchors, allocator: std.mem.Allocator) void {
        self.snapshot.deinit(allocator);
        self.* = undefined;
    }

    pub fn anchors(self: *const TrustAnchors) []const pki.x509.Certificate {
        return self.snapshot.anchors();
    }
};

/// Load trust anchors from an explicit PEM CA bundle path, or — when empty —
/// the first well-known system CA bundle location that exists and parses.
/// Mirrors the OpenSSL upstream adapter's choice between
/// `SSL_CTX_load_verify_locations` and `SSL_CTX_set_default_verify_paths`
/// (`upstream_tls.zig`'s `UpstreamTlsConn.connect`), without linking
/// OpenSSL: both paths go through the same pure-Zig PEM/X.509 loader.
/// Deterministic failure (`error.NoSystemTrustAnchors`) when neither an
/// explicit bundle nor any well-known system location is usable — this never
/// silently falls back to an empty, always-failing trust store.
pub fn loadTrustAnchors(
    allocator: std.mem.Allocator,
    ca_bundle_path: []const u8,
) Error!TrustAnchors {
    const io = zig_compat.io();
    const dir = std.Io.Dir.cwd();
    if (ca_bundle_path.len > 0) {
        const snapshot = try pki.trust_store.Snapshot.loadFiles(allocator, io, dir, &.{.{ .pem = ca_bundle_path }}, .{});
        return .{ .snapshot = snapshot };
    }
    for (system_ca_bundle_candidates) |candidate| {
        const snapshot = pki.trust_store.Snapshot.loadFiles(allocator, io, dir, &.{.{ .pem = candidate }}, .{}) catch |err| {
            if (err == error.OutOfMemory) return err;
            continue;
        };
        return .{ .snapshot = snapshot };
    }
    return error.NoSystemTrustAnchors;
}

/// A `credentials.PeerVerifier` backed by RFC 5280 path validation against a
/// borrowed trust-anchor set. The anchors, and the `WebPkiVerifier` itself,
/// must outlive every handshake that uses `verifier()`.
pub const WebPkiVerifier = struct {
    allocator: std.mem.Allocator,
    trust_anchors: []const pki.x509.Certificate,
    crypto_provider: crypto.provider.CryptoProvider,
    /// Which TLS certificate purpose the peer chain is validated for. A
    /// `.client` verifier (downstream mTLS, #763) requires `id-kp-clientAuth`
    /// rather than `id-kp-serverAuth` and applies no hostname policy.
    purpose: Purpose = .server,
    /// Longest certification path accepted *including* the trust anchor: the
    /// internal bound shared by path building and validation.
    maximum_path_length: usize = default_maximum_path_length,

    pub const Purpose = enum { server, client };
    pub const default_maximum_path_length: usize = 8;

    pub fn init(
        allocator: std.mem.Allocator,
        trust_anchors: []const pki.x509.Certificate,
        crypto_provider: crypto.provider.CryptoProvider,
    ) WebPkiVerifier {
        return .{ .allocator = allocator, .trust_anchors = trust_anchors, .crypto_provider = crypto_provider };
    }

    /// A verifier for downstream client certificates (#763). `verify_depth`
    /// is the public `TARDIGRADE_TLS_CLIENT_VERIFY_DEPTH`: the number of
    /// non-anchor certificates (leaf plus intermediates) allowed, so depth 1
    /// accepts leaf -> anchor. The internal bound counts the anchor too.
    pub fn initClientAuth(
        allocator: std.mem.Allocator,
        trust_anchors: []const pki.x509.Certificate,
        crypto_provider: crypto.provider.CryptoProvider,
        verify_depth: usize,
    ) WebPkiVerifier {
        var self = init(allocator, trust_anchors, crypto_provider);
        self.purpose = .client;
        self.maximum_path_length = verify_depth +| 1;
        return self;
    }

    pub fn verifier(self: *WebPkiVerifier) credentials.PeerVerifier {
        return .{ .ctx = self, .vtable = &vtable };
    }

    const vtable = credentials.PeerVerifier.VTable{ .verify = verifyImpl };

    fn verifyImpl(
        ctx: *anyopaque,
        context: *const credentials.VerificationContext,
    ) credentials.VerifyError!credentials.Progress(credentials.Verdict) {
        const self: *WebPkiVerifier = @ptrCast(@alignCast(ctx));
        return .{ .complete = self.verify(context) };
    }

    /// Parse the presented DER chain, build candidate certification paths to
    /// `trust_anchors`, and validate the first one that satisfies RFC 5280 —
    /// including, when `context.server_name` is set, RFC 9525 hostname/SAN
    /// matching against the leaf (`pki.path_validator` calls
    /// `pki.identity.verifyHost` internally). All scratch state (parsed
    /// certificate views, candidate paths, validation output) lives in a
    /// per-call arena freed before returning — nothing here outlives the
    /// verdict.
    fn verify(self: *WebPkiVerifier, context: *const credentials.VerificationContext) credentials.Verdict {
        if (context.chain.count() == 0) return .rejected;

        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        var parsed: [credentials.max_chain_entries]pki.x509.Certificate = undefined;
        var parsed_len: usize = 0;
        for (context.chain.entries) |der| {
            if (parsed_len >= parsed.len) break;
            parsed[parsed_len] = pki.x509.Certificate.parse(arena, der, .{}) catch return .rejected;
            parsed_len += 1;
        }
        if (parsed_len == 0) return .rejected;

        const leaf = &parsed[0];
        const intermediates = parsed[1..parsed_len];

        const candidates = pki.path_builder.build(arena, leaf, intermediates, self.trust_anchors, .{ .max_path_len = self.maximum_path_length }) catch return .rejected;

        const now_unix_s = zig_compat.unixTimestamp();
        const result = pki.path_validator.validateCandidates(arena, candidates, .{
            .validation_time = now_unix_s,
            // The SNI a client sent names *our* server, not the client
            // certificate's identity: never a hostname policy for `.client`.
            .expected_dns_name = if (self.purpose == .server) context.server_name else null,
            .require_server_auth_eku = self.purpose == .server,
            .require_client_auth_eku = self.purpose == .client,
            .maximum_path_length = self.maximum_path_length,
            .trust_anchors = self.trust_anchors,
        }, self.crypto_provider);
        return switch (result) {
            .accepted => .accepted,
            .rejected => .rejected,
        };
    }
};

const testing = std.testing;

test {
    testing.refAllDecls(@This());
}

// ---------------------------------------------------------------------------
// #763: client-certificate handshake input. The chain a downstream client
// presents is attacker-controlled bytes that reach the verifier before any
// trust is established, so the verifier must be *total* over it (never panic,
// leak, or exceed its bounds) and must never grant trust to anything but the
// exact certificates the configured CA issued for client auth.
// ---------------------------------------------------------------------------

const client_fixture_dir = "tests/fixtures/tls/h3mtls/";

const ClientFixtureKind = enum { valid, expired, not_yet_valid, wrong_eku, wrong_ca };

fn clientFixtureFile(kind: ClientFixtureKind) []const u8 {
    return switch (kind) {
        .valid => client_fixture_dir ++ "client.der",
        .expired => client_fixture_dir ++ "client_expired.der",
        .not_yet_valid => client_fixture_dir ++ "client_not_yet_valid.der",
        .wrong_eku => client_fixture_dir ++ "client_wrong_eku.der",
        .wrong_ca => client_fixture_dir ++ "client_wrong_ca.der",
    };
}

fn verifyClientChain(
    allocator: std.mem.Allocator,
    anchors: *const TrustAnchors,
    entries: []const []const u8,
    depth: usize,
) !credentials.Verdict {
    var entropy = @import("production_crypto.zig").OsEntropy{};
    var provider_state = @import("production_crypto.zig").Provider.init(entropy.entropy());
    var verifier = WebPkiVerifier.initClientAuth(allocator, anchors.anchors(), provider_state.cryptoProvider(), depth);
    const context = credentials.VerificationContext{
        .role = .server,
        .server_name = "unrelated.example",
        .chain = .{ .entries = entries },
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = null,
        .auth_policy = .{ .require_peer_authentication = true },
    };
    const progress = verifier.verifier().verifyPeer(&context) catch return .rejected;
    return switch (progress) {
        .complete => |verdict| verdict,
        .pending => error.UnexpectedPending,
    };
}

test "fuzz: TLS protocol: client certificate chains are verified totally and mutations never gain trust (#763)" {
    try testing.fuzz({}, fuzzClientCertificateChain, .{
        .corpus = &.{
            "",
            // valid leaf accepted
            "\x00\x00",
            // each wrong-profile fixture rejected: expired, not-yet-valid, wrong EKU, wrong CA
            "\x00\x01",
            "\x00\x02",
            "\x00\x03",
            "\x00\x04",
            // single-bit flips at the head, middle and tail of the signed DER
            "\x01\x00\x00\x00\x00",
            "\x01\x00\x00\x40\x03",
            "\x01\x00\x00\xff\x07",
            // truncations, including to a bare header and to nothing
            "\x02\x00\x00\x00\x00",
            "\x02\x00\x00\x00\x04",
            "\x02\x00\x00\x7f\xff",
            // trailing garbage
            "\x03\x00\x00\x00\x00\x01",
            "\x03\x00\x00\x00\x00\x04\xde\xad\xbe\xef",
            // empty chain, empty leaf entry, pure noise, valid leaf with junk extras
            "\x04",
            "\x05",
            "\x06\x00\x30\x82\xff\xff",
            "\x07\x00\x00\x00\x03\x01\x02\x03",
            // over-long chains of the valid leaf
            "\x08\x00\x00\x0f",
            "\x08\x00\x00\xff",
        },
    });
}

fn fuzzClientCertificateChain(_: void, smith: *testing.Smith) !void {
    const allocator = testing.allocator;
    var anchors = loadTrustAnchors(allocator, client_fixture_dir ++ "ca.crt") catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer anchors.deinit(allocator);

    const kind: ClientFixtureKind = @enumFromInt(smith.index(@typeInfo(ClientFixtureKind).@"enum".fields.len));
    const leaf = try zig_compat.cwd().readFileAlloc(allocator, clientFixtureFile(kind), 64 * 1024);
    defer allocator.free(leaf);
    const depth: usize = 1 + smith.index(4);

    const op = smith.index(9);
    var scratch: [4096]u8 = undefined;
    var mutated: []u8 = &.{};
    defer if (mutated.len != 0) allocator.free(mutated);

    var entries_storage: [20][]const u8 = undefined;
    var entries: []const []const u8 = entries_storage[0..0];
    // Whether this input is, by construction, exactly a certificate the CA
    // issued for client auth (so acceptance is the only legal verdict) or a
    // negative that must never be accepted.
    var must_accept = false;
    var must_reject = false;

    switch (op) {
        0 => {
            entries_storage[0] = leaf;
            entries = entries_storage[0..1];
            must_accept = kind == .valid;
            must_reject = kind != .valid;
        },
        1 => { // single-bit flip anywhere in the signed encoding
            mutated = try allocator.dupe(u8, leaf);
            const index = smith.index(mutated.len);
            mutated[index] ^= @as(u8, 1) << @intCast(smith.index(8));
            entries_storage[0] = mutated;
            entries = entries_storage[0..1];
            must_reject = true;
        },
        2 => { // truncation
            const keep = smith.index(leaf.len);
            entries_storage[0] = leaf[0..keep];
            entries = entries_storage[0..1];
            must_reject = true;
        },
        3 => { // trailing bytes after the certificate
            const extra_len = 1 + smith.slice(scratch[0 .. scratch.len - 1]);
            if (extra_len == 0) return;
            mutated = try allocator.alloc(u8, leaf.len + extra_len);
            @memcpy(mutated[0..leaf.len], leaf);
            @memcpy(mutated[leaf.len..], scratch[0..extra_len]);
            entries_storage[0] = mutated;
            entries = entries_storage[0..1];
            must_reject = true;
        },
        4 => {}, // empty chain
        5 => { // empty leaf entry
            entries_storage[0] = "";
            entries = entries_storage[0..1];
            must_reject = true;
        },
        6 => { // arbitrary bytes as the leaf
            const len = smith.slice(&scratch);
            entries_storage[0] = scratch[0..len];
            entries = entries_storage[0..1];
            must_reject = true;
        },
        7 => { // valid leaf followed by arbitrary junk entries: leaf decides
            entries_storage[0] = leaf;
            const extras = smith.index(3);
            var i: usize = 0;
            var cursor: usize = 0;
            while (i < extras) : (i += 1) {
                const len = smith.slice(scratch[cursor..@min(scratch.len, cursor + 64)]);
                entries_storage[1 + i] = scratch[cursor..][0..len];
                cursor += len;
            }
            entries = entries_storage[0 .. 1 + extras];
            must_reject = kind != .valid;
        },
        else => { // over-long chain: bounded work, no panic
            const count = 1 + smith.index(entries_storage.len);
            for (entries_storage[0..count]) |*entry| entry.* = leaf;
            entries = entries_storage[0..count];
        },
    }

    const verdict = try verifyClientChain(allocator, &anchors, entries, depth);
    if (must_accept) try testing.expectEqual(credentials.Verdict.accepted, verdict);
    if (must_reject) try testing.expectEqual(credentials.Verdict.rejected, verdict);
}

test "client auth: every single-bit corruption and every truncation of a valid client certificate is rejected (#763)" {
    const allocator = testing.allocator;
    var anchors = try loadTrustAnchors(allocator, client_fixture_dir ++ "ca.crt");
    defer anchors.deinit(allocator);
    const leaf = try zig_compat.cwd().readFileAlloc(allocator, clientFixtureFile(.valid), 64 * 1024);
    defer allocator.free(leaf);

    var entries = [_][]const u8{leaf};
    try testing.expectEqual(credentials.Verdict.accepted, try verifyClientChain(allocator, &anchors, &entries, 3));

    const copy = try allocator.dupe(u8, leaf);
    defer allocator.free(copy);
    for (0..leaf.len) |byte_index| {
        for (0..8) |bit| {
            copy[byte_index] ^= @as(u8, 1) << @intCast(bit);
            entries[0] = copy;
            try testing.expectEqual(credentials.Verdict.rejected, try verifyClientChain(allocator, &anchors, &entries, 3));
            copy[byte_index] ^= @as(u8, 1) << @intCast(bit);
        }
    }
    for (0..leaf.len) |keep| {
        entries[0] = leaf[0..keep];
        try testing.expectEqual(credentials.Verdict.rejected, try verifyClientChain(allocator, &anchors, &entries, 3));
    }
}
