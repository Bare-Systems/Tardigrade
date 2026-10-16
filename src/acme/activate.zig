//! Pre-activation verification and durable identity-generation storage for a
//! single managed host group (#879, A4 of epic #759, design
//! `docs/ACME_AUTOMATIC_HTTPS.md` §§6.4, 7, 9.2).
//!
//! This module answers one question — is an issued leaf/chain *safe to
//! activate*, and if so, persist it as a new durable generation — and does
//! nothing else. It never publishes to `sni_provider.ReloadableProvider`
//! (that is #880/#884's job) and never talks to a CA (that is #883's job).
//! It composes exactly the machinery the design doc calls authoritative:
//! `pki.pem`/`pki.x509` for parsing, `pki.verify`/`pki.identity` for chain
//! and hostname verification, `crypto.pure_zig` for the sign/verify
//! key-binding probe, and `acme.state` for the atomic, symlink/ownership
//! hardened file procedure extended here with a validated nested
//! `groups/<id>/generations/<gen-id>/` layout (one new level of directory,
//! same invariants, at each step).
//!
//! ## On-disk layout (relative to the ACME `StateDir`)
//!
//! ```text
//! groups/<group-id>/
//!   current                  "<current>\n<previous-or-empty>\n", durable commit record
//!   generations/
//!     <seq>-<nonce-hex>/
//!       leaf.key             PKCS#8 PEM, 0600
//!       chain.pem            leaf-first PEM chain as issued
//!       meta.json            hostnames + validity + creation time
//! ```
//!
//! A generation directory is complete (and therefore trustworthy) only once
//! `current` names it; `verifyAndPersist` never rewrites `current` until
//! every file in the new generation is written and fsynced. Pruning (keep
//! the newest two) and orphan removal only ever touch generations that are
//! *not* the one just committed or recovered, so a bad new generation
//! always has a fallback.

const std = @import("std");
const crypto = @import("crypto");
const pki = @import("pki");
const tls_core = @import("tls_core");
const zig_compat = @import("zig_compat");
const account_mod = @import("account.zig");
const state_mod = @import("state.zig");
const json_limits = @import("json_limits.zig");

const secrets = crypto.secrets;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// The leaf private key container. Identical P-256/PKCS#8 shape to the ACME
/// account key (#832) — "leaf" vs. "account" is a role, not a different key
/// encoding — so activation reuses `account.AccountKey` rather than growing
/// a second PKCS#8 codec.
pub const LeafKey = account_mod.AccountKey;

/// §9.1/§7.1 pattern budget: at most 16 names per managed group.
pub const max_hostnames_per_group = 16;
pub const max_chain_entries = tls_core.credentials.max_chain_entries;
/// Same bound as `appliance_credentials.default_max_certificate_flight_bytes`
/// (design §6.4 item 1): one managed-group certificate must fit the same TLS
/// Certificate-message flight any provisioned identity does.
pub const max_certificate_flight_bytes = tls_core.appliance_credentials.default_max_certificate_flight_bytes;

pub const default_not_before_skew_seconds: i64 = 5 * 60;
pub const default_min_remaining_seconds: i64 = 24 * 60 * 60;
pub const default_max_validity_seconds: i64 = 400 * 24 * 60 * 60;

const groups_dir_name = "groups";
const generations_dir_name = "generations";
const generation_file_leaf_key = "leaf.key";
const generation_file_chain = "chain.pem";
const generation_file_meta = "meta.json";
const current_name = "current";
const current_tmp_name = "current.tmp";
const max_generation_id_len = 40;
const max_current_len = 2 * max_generation_id_len + 2;
/// Must fit `buildMetaJson`'s worst case: `max_hostnames_per_group` names at
/// the DNS 253-byte maximum, plus JSON quoting and the fixed fields. 8 KiB
/// leaves generous headroom over the ~4.25 KiB that bound actually produces.
const max_meta_len = 8192;
const meta_version: u32 = 1;

pub const VerifyError = error{
    EmptyChain,
    TooManyCertificates,
    CertificateTooLarge,
    ChainTooLarge,
    MalformedChain,
    UnhandledCriticalExtension,
    DuplicateCertificateEntry,
    UnsupportedLeafKeyAlgorithm,
    InvalidLeafCertificate,
    IntermediateNotCa,
    CertificateKeyUsageViolation,
    CertificateExtendedKeyUsageViolation,
    SanMismatch,
    NotYetValid,
    Expired,
    ValidityTooLong,
    InvalidCertificateChainOrder,
    CertificateSignatureInvalid,
    KeyCertificateMismatch,
    LeafKeyReusesAccountKey,
};

/// `state_mod.Error` (the file-system/security invariants) plus the
/// certificate-specific verification outcomes above.
pub const Error = state_mod.Error || VerifyError;

pub const VerifyOptions = struct {
    /// The exact requested SAN set for this group (no missing, no extra).
    hostnames: []const []const u8,
    /// Caller-supplied clock reading (unix seconds); never ambient, so tests
    /// control it exactly.
    now: i64,
    /// When set, a leaf SPKI equal to this (uncompressed SEC1) key is
    /// rejected: the account key must never double as a leaf key.
    account_public_key_sec1: ?[]const u8 = null,
    not_before_skew_seconds: i64 = default_not_before_skew_seconds,
    min_remaining_seconds: i64 = default_min_remaining_seconds,
    max_validity_seconds: i64 = default_max_validity_seconds,
};

pub const ChainSummary = struct {
    not_before: i64,
    not_after: i64,
};

var verify_entropy_state: tls_core.production_crypto.OsEntropy = .{};

/// Verify an issued leaf/chain against design §6.4: structural bounds,
/// leaf/private-key binding (constant-time compare, then a sign/verify
/// probe), exact SAN-set equality, validity window, and chain signature
/// coherence (no trust-anchor decision — that is deliberately out of scope,
/// same as `appliance_credentials`). Never touches disk.
pub fn verifyChain(
    allocator: std.mem.Allocator,
    leaf_key: *const LeafKey,
    chain_pem: []const u8,
    options: VerifyOptions,
) Error!ChainSummary {
    if (options.hostnames.len == 0 or options.hostnames.len > max_hostnames_per_group) return error.SanMismatch;

    var chain = pki.pem.loadChainPem(allocator, chain_pem, .{
        .max_input_len = 2 * max_certificate_flight_bytes,
        .max_certificate_len = tls_core.tls13_backend.max_certificate_len,
        .max_certificates = max_chain_entries,
    }) catch |err| return mapPemError(err);
    defer chain.deinit(allocator);

    const count = chain.certificates.len;
    if (count == 0) return error.EmptyChain;
    if (count > max_chain_entries) return error.TooManyCertificates;

    var flight: usize = tls_core.tls13_backend.certificate_message_overhead;
    for (chain.certificates) |cert| {
        if (cert.der.len == 0) return error.MalformedChain;
        if (cert.der.len > tls_core.tls13_backend.max_certificate_len) return error.CertificateTooLarge;
        flight = std.math.add(usize, flight, cert.der.len + tls_core.tls13_backend.certificate_entry_overhead) catch
            return error.ChainTooLarge;
        if (flight > max_certificate_flight_bytes) return error.ChainTooLarge;
    }

    var parsed: [max_chain_entries]pki.x509.Certificate = undefined;
    var parsed_count: usize = 0;
    defer for (parsed[0..parsed_count]) |*cert| cert.deinit(allocator);

    for (chain.certificates) |cert| {
        parsed[parsed_count] = pki.x509.Certificate.parse(allocator, cert.der, .{}) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.MalformedChain,
        };
        parsed_count += 1;
        if (parsed[parsed_count - 1].hasUnhandledCriticalExtension()) return error.UnhandledCriticalExtension;
    }

    for (0..count) |i| {
        for (i + 1..count) |j| {
            if (std.mem.eql(u8, chain.certificates[i].der, chain.certificates[j].der)) return error.DuplicateCertificateEntry;
        }
    }

    const leaf = &parsed[0];
    if (leaf.subject_public_key_info.key_type != .ecdsa_p256) return error.UnsupportedLeafKeyAlgorithm;
    const leaf_spki = leaf.subject_public_key_info.subject_public_key;
    if (leaf_spki.unused_bits != 0) return error.MalformedChain;

    const derived = leaf_key.key.publicKeySec1();
    if (!secrets.constantTimeEqual(&derived, leaf_spki.data)) return error.KeyCertificateMismatch;
    try proofOfPossession(leaf_key, leaf_spki.data);

    if (options.account_public_key_sec1) |account_key| {
        if (secrets.constantTimeEqual(account_key, leaf_spki.data)) return error.LeafKeyReusesAccountKey;
    }

    if (leaf.basicConstraints()) |bc| {
        if (bc.is_ca) return error.InvalidLeafCertificate;
    }
    if (leaf.keyUsage()) |ku| {
        if (!ku.digital_signature) return error.CertificateKeyUsageViolation;
    }
    if (leaf.extendedKeyUsage()) |eku| {
        if (!eku.allowsServerAuth()) return error.CertificateExtendedKeyUsageViolation;
    }

    try verifySanExact(leaf, options.hostnames);
    try verifyValidityWindow(leaf.validity, options);

    for (parsed[1..count]) |*intermediate| {
        const bc = intermediate.basicConstraints() orelse return error.IntermediateNotCa;
        if (!bc.is_ca) return error.IntermediateNotCa;
        if (intermediate.keyUsage()) |ku| {
            if (!ku.key_cert_sign) return error.CertificateKeyUsageViolation;
        }
    }

    if (count > 1) {
        var verify_provider_state = crypto.pure_zig.Provider.init(verify_entropy_state.entropy());
        const crypto_provider = verify_provider_state.cryptoProvider();
        for (0..count - 1) |i| {
            const child = &parsed[i];
            const issuer = &parsed[i + 1];
            if (!child.issuer.eqlForChaining(&issuer.subject)) return error.InvalidCertificateChainOrder;
            pki.verify.verifyCertificateSignature(crypto_provider, child, &issuer.subject_public_key_info) catch
                return error.CertificateSignatureInvalid;
        }
    }

    return .{
        .not_before = pki.path_validator.unixSeconds(leaf.validity.not_before),
        .not_after = pki.path_validator.unixSeconds(leaf.validity.not_after),
    };
}

fn mapPemError(err: pki.pem.Error) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.InputTooLarge => error.ChainTooLarge,
        error.CertificateTooLarge => error.CertificateTooLarge,
        error.TooManyCertificates => error.TooManyCertificates,
        error.NoCertificates => error.EmptyChain,
        error.MalformedPemBoundary,
        error.MismatchedPemLabel,
        error.UnterminatedPemBlock,
        error.InvalidPemBase64,
        error.EmptyPemBlock,
        error.MalformedCertificateDer,
        => error.MalformedChain,
    };
}

/// Fixed sign-and-verify probe, same defense-in-depth as
/// `appliance_credentials.proofOfPossession`: the constant-time compare
/// above proves the *bytes* match; this proves the private key can actually
/// produce a signature the leaf's own public key accepts.
fn proofOfPossession(leaf_key: *const LeafKey, leaf_public_sec1: []const u8) Error!void {
    const probe = "Tardigrade ACME activation preflight v1";
    var noise: [EcdsaP256Sha256.noise_length]u8 = undefined;
    defer secrets.secureZero(&noise);
    zig_compat.randomBytes(&noise);
    const signature = leaf_key.key.key_pair.sign(probe, noise) catch return error.KeyCertificateMismatch;
    var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const der_sig = signature.toDer(&der_buf);

    var verify_provider_state = crypto.pure_zig.Provider.init(verify_entropy_state.entropy());
    const crypto_provider = verify_provider_state.cryptoProvider();
    crypto_provider.verify(.ecdsa_secp256r1_sha256, leaf_public_sec1, probe, der_sig) catch return error.KeyCertificateMismatch;
}

/// SAN must equal the requested set exactly. `verifyHost` deliberately
/// supports wildcards, so it is an eligibility check only; it cannot prove
/// that two sets are equal. We first validate the requested DNS set and
/// establish a one-to-one exact (case-insensitive, one trailing-dot
/// canonicalized) mapping, then retain `verifyHost` as defense in depth.
fn verifySanExact(leaf: *const pki.x509.Certificate, hostnames: []const []const u8) Error!void {
    const san = leaf.subjectAltName() orelse return error.SanMismatch;
    var matched: [max_hostnames_per_group]bool = [_]bool{false} ** max_hostnames_per_group;
    for (hostnames, 0..) |host, i| {
        const ref = pki.identity.dnsReference(host) catch return error.SanMismatch;
        const canonical = switch (ref) {
            .dns_name => |name| name,
            else => return error.SanMismatch,
        };
        for (hostnames[0..i]) |prior| {
            const prior_ref = pki.identity.dnsReference(prior) catch return error.SanMismatch;
            const prior_name = switch (prior_ref) {
                .dns_name => |name| name,
                else => return error.SanMismatch,
            };
            if (std.ascii.eqlIgnoreCase(canonical, prior_name)) return error.SanMismatch;
        }
    }
    for (san) |name| {
        const presented = switch (name) {
            .dns_name => |dns| dns,
            else => return error.SanMismatch,
        };
        // A wildcard is never an HTTP-01 managed identity, even if it would
        // happen to cover a requested concrete name.
        if (std.mem.indexOfScalar(u8, presented, '*') != null) return error.SanMismatch;
        var found: ?usize = null;
        for (hostnames, 0..) |host, i| {
            const ref = pki.identity.dnsReference(host) catch return error.SanMismatch;
            const canonical = switch (ref) {
                .dns_name => |value| value,
                else => return error.SanMismatch,
            };
            if (pki.identity.presentedDnsIdMatches(presented, canonical) and std.ascii.eqlIgnoreCase(trimOneTrailingDot(presented), canonical)) {
                if (found != null or matched[i]) return error.SanMismatch;
                found = i;
            }
        }
        const index = found orelse return error.SanMismatch;
        matched[index] = true;
    }
    for (hostnames, 0..) |host, i| {
        if (!matched[i]) return error.SanMismatch;
        const verdict = pki.identity.verifyHost(leaf, host) catch return error.SanMismatch;
        if (!verdict.isMatch()) return error.SanMismatch;
    }
}

fn trimOneTrailingDot(name: []const u8) []const u8 {
    return if (name.len > 0 and name[name.len - 1] == '.') name[0 .. name.len - 1] else name;
}

fn verifyValidityWindow(validity: pki.x509.Validity, options: VerifyOptions) Error!void {
    const not_before = pki.path_validator.unixSeconds(validity.not_before);
    const not_after = pki.path_validator.unixSeconds(validity.not_after);
    if (not_after <= not_before) return error.ValidityTooLong;
    if (not_before > options.now + options.not_before_skew_seconds) return error.NotYetValid;
    if (not_after <= options.now + options.min_remaining_seconds) return error.Expired;
    if (not_after - not_before > options.max_validity_seconds) return error.ValidityTooLong;
}

// ---------------------------------------------------------------------------
// Durable generation storage (design §9.2)
// ---------------------------------------------------------------------------

const GenerationMetaJson = struct {
    version: u32,
    hostnames: [][]const u8,
    not_before: i64,
    not_after: i64,
    created_at: i64,
};

const meta_limits = json_limits.Limits{
    .max_bytes = max_meta_len,
    .max_depth = 3,
    .max_string = 320,
    .max_keys = 8,
    .max_array = max_hostnames_per_group,
};

const GenerationId = struct {
    buf: [max_generation_id_len]u8,
    len: usize,

    fn slice(self: *const GenerationId) []const u8 {
        return self.buf[0..self.len];
    }
};

/// The atomic `current` record is the sole authority for committed state.
/// Its optional second line records the previous committed generation, which
/// lets restart recovery distinguish a known fallback from a complete but
/// uncommitted orphan directory.
const CommitPointer = struct {
    current: GenerationId,
    previous: ?GenerationId = null,
};

pub const LoadedMeta = struct {
    parsed: std.json.Parsed(GenerationMetaJson),

    pub fn hostnames(self: *const LoadedMeta) []const []const u8 {
        return self.parsed.value.hostnames;
    }
    pub fn notBefore(self: *const LoadedMeta) i64 {
        return self.parsed.value.not_before;
    }
    pub fn notAfter(self: *const LoadedMeta) i64 {
        return self.parsed.value.not_after;
    }
    pub fn deinit(self: *LoadedMeta) void {
        self.parsed.deinit();
    }
};

/// A successfully persisted or recovered generation. The leaf key and chain
/// are returned (not published anywhere) for the A4 publication ticket
/// (#880/#884) to compose into `sni_provider.ReloadableProvider`.
pub const LoadedGeneration = struct {
    leaf_key: LeafKey,
    chain_pem: []u8,
    meta: LoadedMeta,
    generation_id_buf: [max_generation_id_len]u8,
    generation_id_len: usize,

    pub fn generationId(self: *const LoadedGeneration) []const u8 {
        return self.generation_id_buf[0..self.generation_id_len];
    }

    pub fn deinit(self: *LoadedGeneration, allocator: std.mem.Allocator) void {
        self.leaf_key.deinit();
        allocator.free(self.chain_pem);
        self.meta.deinit();
        self.* = undefined;
    }
};

pub const PersistResult = struct {
    generation_id_buf: [max_generation_id_len]u8,
    generation_id_len: usize,
    summary: ChainSummary,

    pub fn generationId(self: *const PersistResult) []const u8 {
        return self.generation_id_buf[0..self.generation_id_len];
    }
};

/// Verify (§6.4) and durably persist `leaf_key`/`chain_pem` as a new
/// generation of `group_id`, publishing nothing. On any verification or
/// I/O failure the group's `current` pointer and every prior generation are
/// untouched, with one unavoidable exception: if the final post-rename
/// `fsync` of the commit record itself fails, the rename is already visible
/// (§9.2's own ambiguity) and `current` may have already moved even though
/// this call reports an error. A caller that sees that specific failure
/// must re-check committed state (e.g. via `loadCommitted`) rather than
/// assume the previous generation is still current. On success `current` is
/// rewritten only after every generation file is written and fsynced (§9.2
/// steps 1-3), and generations beyond the new one and the one it replaced
/// are pruned.
pub fn verifyAndPersist(
    allocator: std.mem.Allocator,
    state: *state_mod.StateDir,
    group_id: []const u8,
    leaf_key: *const LeafKey,
    chain_pem: []const u8,
    options: VerifyOptions,
) Error!PersistResult {
    if (!state_mod.validName(group_id)) return error.InvalidPath;
    const summary = try verifyChain(allocator, leaf_key, chain_pem, options);

    const leaf_pem = leaf_key.toPkcs8Pem(allocator) catch return error.OutOfMemory;
    defer secrets.secureZeroAndFree(allocator, leaf_pem);
    const meta_json = try buildMetaJson(allocator, options.hostnames, summary, options.now);
    defer allocator.free(meta_json);

    var groups = try state.openOrCreateSubdir(groups_dir_name);
    defer groups.close();
    var group = try groups.openOrCreateSubdir(group_id);
    defer group.close();
    var generations = try group.openOrCreateSubdir(generations_dir_name);
    defer generations.close();

    const old_pointer = try readCurrentPointer(allocator, &group);
    const seq = try nextSequence(old_pointer);
    var nonce: [8]u8 = undefined;
    zig_compat.randomBytes(&nonce);
    var name_buf: [max_generation_id_len]u8 = undefined;
    const gen_name = formatGenerationName(&name_buf, seq, nonce);

    {
        var gen_dir = try generations.openOrCreateSubdir(gen_name);
        defer gen_dir.close();
        try gen_dir.writeFileAtomic(generation_file_leaf_key, leaf_pem, 0o600);
        try gen_dir.writeFileAtomicLimit(generation_file_chain, chain_pem, 0o600, 2 * max_certificate_flight_bytes);
        try gen_dir.writeFileAtomicLimit(generation_file_meta, meta_json, 0o600, max_meta_len);
        try gen_dir.fsync();
    }
    try generations.fsync();

    var previous: ?GenerationId = null;
    if (old_pointer) |pointer| previous = pointer.current;
    try rewriteCurrent(&group, gen_name, previous);

    var keep: [2][]const u8 = .{ gen_name, gen_name };
    var keep_count: usize = 1;
    if (previous) |old_current| {
        keep[1] = old_current.slice();
        keep_count = 2;
    }
    pruneGenerations(&generations, keep[0..keep_count]);

    var result = PersistResult{ .generation_id_buf = undefined, .generation_id_len = gen_name.len, .summary = summary };
    @memcpy(result.generation_id_buf[0..gen_name.len], gen_name);
    return result;
}

/// Load the committed generation of `group_id`, re-verifying it against
/// `hostnames`/`now` exactly as `verifyAndPersist` did (design §9.2
/// "startup strictly validates"). A generation that fails verification is
/// renamed `*.corrupt-<ts>` (never deleted) and the next-newest generation
/// is tried; if none validate the group is treated as having no
/// certificate (`null`), never as a hard error. Hard environment/security
/// failures (ownership, symlink, lock, memory) still propagate.
pub fn loadCommitted(
    allocator: std.mem.Allocator,
    state: *state_mod.StateDir,
    group_id: []const u8,
    hostnames: []const []const u8,
    now: i64,
) Error!?LoadedGeneration {
    if (!state_mod.validName(group_id)) return error.InvalidPath;
    var groups = state.openSubdirStrict(groups_dir_name) catch |err| return softNotFoundToNull(err);
    defer groups.close();
    var group = groups.openSubdirStrict(group_id) catch |err| return softNotFoundToNull(err);
    defer group.close();
    var generations = group.openSubdirStrict(generations_dir_name) catch |err| return softNotFoundToNull(err);
    defer generations.close();

    const pointer = (try readCurrentPointer(allocator, &group)) orelse return null;

    if (tryLoadGeneration(allocator, &generations, pointer.current.slice(), hostnames, now)) |value| {
        var loaded = value;
        errdefer loaded.deinit(allocator);
        // The fallback is retained only if it is still independently valid.
        var retained_previous: ?GenerationId = null;
        if (pointer.previous) |previous| {
            if (tryLoadGeneration(allocator, &generations, previous.slice(), hostnames, now)) |candidate| {
                var discard = candidate;
                discard.deinit(allocator);
                retained_previous = previous;
            } else |err| {
                if (isHardError(err)) return err;
                markCorrupt(&generations, previous.slice());
            }
        }
        if (!sameGeneration(retained_previous, pointer.previous))
            try rewriteCurrent(&group, pointer.current.slice(), retained_previous);
        var keep = [_][]const u8{ pointer.current.slice(), pointer.current.slice() };
        var keep_count: usize = 1;
        if (retained_previous) |previous| {
            keep[1] = previous.slice();
            keep_count = 2;
        }
        pruneGenerations(&generations, keep[0..keep_count]);
        return loaded;
    } else |err| {
        if (isHardError(err)) return err;
        markCorrupt(&generations, pointer.current.slice());
    }

    // Only the generation explicitly recorded as the prior commit may be a
    // fallback. Never scan complete-looking directories: a crash before the
    // final pointer rename must remain uncommitted.
    const previous = pointer.previous orelse return null;
    if (tryLoadGeneration(allocator, &generations, previous.slice(), hostnames, now)) |value| {
        var loaded = value;
        errdefer loaded.deinit(allocator);
        try rewriteCurrent(&group, previous.slice(), null);
        pruneGenerations(&generations, &.{previous.slice()});
        return loaded;
    } else |err| {
        if (isHardError(err)) return err;
        markCorrupt(&generations, previous.slice());
        return null;
    }
}

fn sameGeneration(a: ?GenerationId, b: ?GenerationId) bool {
    if (a == null or b == null) return a == null and b == null;
    return std.mem.eql(u8, a.?.slice(), b.?.slice());
}

fn softNotFoundToNull(err: Error) Error!?LoadedGeneration {
    return if (err == error.NotFound) null else err;
}

fn isHardError(err: Error) bool {
    return switch (err) {
        error.OutOfMemory,
        error.UnsafeFileType,
        error.InsecurePermissions,
        error.WrongOwner,
        error.Locked,
        error.IoFailure,
        error.InjectedFault,
        error.InvalidPath,
        => true,
        else => false,
    };
}

fn tryLoadGeneration(
    allocator: std.mem.Allocator,
    generations: *state_mod.SubDir,
    name: []const u8,
    hostnames: []const []const u8,
    now: i64,
) Error!LoadedGeneration {
    var gen_dir = try generations.openSubdirStrict(name);
    defer gen_dir.close();

    const leaf_pem = try gen_dir.readFileAlloc(allocator, generation_file_leaf_key, account_mod.max_pem_len, true);
    defer secrets.secureZeroAndFree(allocator, leaf_pem);
    var leaf_key = account_mod.AccountKey.fromPkcs8Pem(leaf_pem) catch return error.CorruptState;
    errdefer leaf_key.deinit();

    // Both files are written `0600` (verifyAndPersist); accepting a looser
    // mode or a different owner here would let a tampered-with generation
    // directory feed unverified identity/expiry data back into the caller.
    const chain_pem = try gen_dir.readFileAlloc(allocator, generation_file_chain, 2 * max_certificate_flight_bytes, true);
    errdefer allocator.free(chain_pem);

    const meta_bytes = try gen_dir.readFileAlloc(allocator, generation_file_meta, max_meta_len, true);
    defer allocator.free(meta_bytes);
    var meta_parsed = json_limits.parseBounded(GenerationMetaJson, allocator, meta_bytes, meta_limits) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.CorruptState,
    };
    errdefer meta_parsed.deinit();
    if (meta_parsed.value.version != meta_version) return error.CorruptState;

    const summary = try verifyChain(allocator, &leaf_key, chain_pem, .{ .hostnames = hostnames, .now = now });
    if (!sameHostnameSet(meta_parsed.value.hostnames, hostnames) or
        meta_parsed.value.not_before != summary.not_before or
        meta_parsed.value.not_after != summary.not_after) return error.CorruptState;

    var loaded = LoadedGeneration{
        .leaf_key = leaf_key,
        .chain_pem = chain_pem,
        .meta = .{ .parsed = meta_parsed },
        .generation_id_buf = undefined,
        .generation_id_len = name.len,
    };
    @memcpy(loaded.generation_id_buf[0..name.len], name);
    return loaded;
}

fn sameHostnameSet(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len or a.len > max_hostnames_per_group) return false;
    for (a, 0..) |name, i| {
        const ref = pki.identity.dnsReference(name) catch return false;
        const canonical = switch (ref) {
            .dns_name => |value| value,
            else => return false,
        };
        for (a[0..i]) |prior| {
            const prior_ref = pki.identity.dnsReference(prior) catch return false;
            const prior_name = switch (prior_ref) {
                .dns_name => |value| value,
                else => return false,
            };
            if (std.ascii.eqlIgnoreCase(canonical, prior_name)) return false;
        }
        var found = false;
        for (b) |other| {
            const other_ref = pki.identity.dnsReference(other) catch return false;
            const other_name = switch (other_ref) {
                .dns_name => |value| value,
                else => return false,
            };
            if (std.ascii.eqlIgnoreCase(canonical, other_name)) {
                if (found) return false;
                found = true;
            }
        }
        if (!found) return false;
    }
    return true;
}

fn readCurrentPointer(allocator: std.mem.Allocator, group: *state_mod.SubDir) Error!?CommitPointer {
    const bytes = group.readFileAllocExactMode(allocator, current_name, max_current_len, 0o600) catch |err| switch (err) {
        error.NotFound => return null,
        else => return err,
    };
    defer allocator.free(bytes);
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    const current = lines.next() orelse return error.CorruptState;
    const previous_line = lines.next() orelse return error.CorruptState;
    const terminator = lines.next() orelse return error.CorruptState;
    if (terminator.len != 0 or lines.next() != null or current.len == 0 or parseGenerationName(current) == null) return error.CorruptState;
    var out = CommitPointer{ .current = generationIdFromSlice(current), .previous = null };
    if (previous_line.len > 0) {
        if (parseGenerationName(previous_line) == null or std.mem.eql(u8, current, previous_line)) return error.CorruptState;
        out.previous = generationIdFromSlice(previous_line);
    }
    return out;
}

fn generationIdFromSlice(name: []const u8) GenerationId {
    var out = GenerationId{ .buf = undefined, .len = name.len };
    @memcpy(out.buf[0..name.len], name);
    return out;
}

/// `current_name` is used as the test-only fault label for the two steps
/// that `writeFileAtomic`'s own fault points cannot reach: the commit
/// rename itself (distinct from the rename of `current_tmp_name`'s own
/// write, which already completed) and the fsync that follows it.
fn rewriteCurrent(group: *state_mod.SubDir, name: []const u8, previous: ?GenerationId) Error!void {
    if (parseGenerationName(name) == null) return error.CorruptState;
    var buf: [max_current_len]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, "{s}\n{s}\n", .{ name, if (previous) |value| value.slice() else "" }) catch return error.CorruptState;
    try group.writeFileAtomic(current_tmp_name, line, 0o600);
    try group.injectTestFault(current_name, .rename);
    try group.renameWithin(current_tmp_name, current_name);
    try group.injectTestFault(current_name, .fsync_dir);
    try group.fsync();
}

fn markCorrupt(generations: *state_mod.SubDir, name: []const u8) void {
    var buf: [max_generation_id_len + 32]u8 = undefined;
    const corrupt_name = std.fmt.bufPrint(&buf, "{s}.corrupt-{d}", .{ name, zig_compat.unixTimestamp() }) catch return;
    generations.renameWithin(name, corrupt_name) catch {};
}

/// Delete every strictly-named generation directory except `keep`. Entries
/// that are not shaped like a generation id (already-`.corrupt-`-renamed,
/// or a stray name) are left untouched. `keep` (the caller's explicit
/// current/previous ids), never directory enumeration, is the authority for
/// what survives. Each pass scans the *entire* directory via `listMatching`
/// to collect up to 64 eligible candidates — retained `*.corrupt-*`
/// archives or the live generations never consume a slot, so no number of
/// ineligible entries ahead of a real orphan (in whatever order the
/// filesystem happens to iterate) can ever stall deletion — then deletes
/// that batch and rescans; repeated calls (every persist/load) eventually
/// reclaim every eligible orphan. A batch that removes nothing (every
/// candidate is a stuck regular file, symlink, mode-insecure directory, or
/// a non-empty directory) stops the scan rather than resubmitting the same
/// undeletable names forever.
fn pruneGenerations(generations: *state_mod.SubDir, keep: []const []const u8) void {
    while (true) {
        var names: [64][64]u8 = undefined;
        var lens: [64]usize = undefined;
        const count = generations.listMatching(&names, &lens, keep, isPruneCandidate) catch return;
        if (count == 0) return;
        var removed: usize = 0;
        for (0..count) |i| {
            const name = names[i][0..lens[i]];
            var doomed = generations.openSubdirStrict(name) catch continue;
            doomed.removeFile(generation_file_leaf_key);
            doomed.removeFile(generation_file_chain);
            doomed.removeFile(generation_file_meta);
            doomed.close();
            generations.removeEmpty(name) catch continue;
            removed += 1;
        }
        // A batch that deletes nothing means every eligible candidate is
        // currently undeletable (a regular file, symlink, mode-insecure
        // directory, or a directory with an unexpected extra file). Without
        // this check, `listMatching` would keep returning the same stuck
        // names forever and the caller would hang holding the state lock.
        if (removed == 0) return;
    }
}

fn isPruneCandidate(keep: []const []const u8, name: []const u8) bool {
    if (parseGenerationName(name) == null) return false;
    for (keep) |k| {
        if (std.mem.eql(u8, k, name)) return false;
    }
    return true;
}

fn nextSequence(pointer: ?CommitPointer) Error!u64 {
    const current = pointer orelse return 1;
    const seq = parseGenerationName(current.current.slice()).?;
    return std.math.add(u64, seq, 1) catch error.CorruptState;
}

/// `^[0-9]{1,20}-[0-9a-f]{16}$`, no leading zero unless the sequence is
/// exactly `0` (which a real sequence, starting at 1, never produces).
fn parseGenerationName(name: []const u8) ?u64 {
    if (name.len == 0 or name.len > max_generation_id_len) return null;
    const dash = std.mem.indexOfScalar(u8, name, '-') orelse return null;
    if (dash == 0) return null;
    const digits = name[0..dash];
    const hex = name[dash + 1 ..];
    if (hex.len != 16) return null;
    for (hex) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        if (!ok) return null;
    }
    if (digits.len > 1 and digits[0] == '0') return null;
    for (digits) |c| {
        if (c < '0' or c > '9') return null;
    }
    return std.fmt.parseUnsigned(u64, digits, 10) catch null;
}

fn formatGenerationName(buf: *[max_generation_id_len]u8, seq: u64, nonce: [8]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d}-{x}", .{ seq, nonce }) catch unreachable;
}

fn buildMetaJson(allocator: std.mem.Allocator, hostnames: []const []const u8, summary: ChainSummary, created_at: i64) Error![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{{\"version\":{d},\"hostnames\":{f},\"not_before\":{d},\"not_after\":{d},\"created_at\":{d}}}\n",
        .{ meta_version, std.json.fmt(hostnames, .{}), summary.not_before, summary.not_after, created_at },
    ) catch error.OutOfMemory;
}

// ---------------------------------------------------------------------------

test {
    std.testing.refAllDecls(@This());
}
