//! Reloadable in-memory SNI credential provider (#347).
//!
//! This module implements the production multi-certificate selector behind the
//! provider-neutral credential seam from `credentials.zig`. A published
//! `Snapshot` is immutable; reload builds a complete replacement off-path and
//! publishes it atomically. Selected handles retain their snapshot until
//! release, so in-flight handshakes never observe mixed generations.

const std = @import("std");
const std_crypto = std.crypto;
const crypto_provider = @import("crypto").provider;
const credentials = @import("credentials.zig");

pub const max_bundles = 64;
pub const max_patterns_per_bundle = 16;
pub const max_host_pattern_len = 253;

pub const AbsentSniPolicy = enum {
    use_default,
    fail_handshake,
};

pub const UnknownSniPolicy = enum {
    use_default,
    fail_handshake,
};

pub const SnapshotOptions = struct {
    absent_sni_policy: AbsentSniPolicy = .use_default,
    unknown_sni_policy: UnknownSniPolicy = .fail_handshake,
};

pub const KeyKind = enum {
    ed25519,
    ecdsa_p256,
};

pub const HostPattern = union(enum) {
    exact: []const u8,
    wildcard_suffix: []const u8,

    pub fn text(self: HostPattern) []const u8 {
        return switch (self) {
            .exact => |value| value,
            .wildcard_suffix => |value| value,
        };
    }
};

pub const BuildError = error{
    EmptyCredentialSet,
    EmptyChain,
    TooManyChainEntries,
    InvalidChain,
    InvalidLeafKey,
    KeySignerMismatch,
    UnsupportedKeyType,
    EmptyHostPattern,
    InvalidHostPattern,
    InvalidWildcardPattern,
    DuplicateHostPattern,
    DuplicateDefaultBundle,
    NoUsableDefaultBundle,
    NoSupportedSignatureScheme,
    InvalidOwnershipContract,
    OutOfMemory,
};

pub const SignAdapter = union(enum) {
    identity: credentials.Identity,
    external: ExternalSigner,
    signing_key: SigningKeyAdapter,

    pub const ExternalSigner = struct {
        context: *anyopaque,
        sign: *const fn (context: *anyopaque, scheme: credentials.SignatureScheme, input: []const u8, out: []u8) credentials.SignError!usize,
        release: *const fn (context: *anyopaque) void,
    };

    pub const SigningKeyAdapter = struct {
        key: crypto_provider.SigningKey,
        entropy: crypto_provider.Entropy,
        release_context: ?*anyopaque = null,
        release: ?*const fn (context: *anyopaque) void = null,
    };

    pub fn fromIdentity(identity: credentials.Identity) SignAdapter {
        return .{ .identity = identity };
    }

    pub fn fromExternal(
        context: *anyopaque,
        sign_fn: *const fn (*anyopaque, credentials.SignatureScheme, []const u8, []u8) credentials.SignError!usize,
        release_fn: *const fn (*anyopaque) void,
    ) SignAdapter {
        return .{ .external = .{ .context = context, .sign = sign_fn, .release = release_fn } };
    }

    pub fn fromSigningKey(
        key: crypto_provider.SigningKey,
        entropy: crypto_provider.Entropy,
        release_context: ?*anyopaque,
        release_fn: ?*const fn (*anyopaque) void,
    ) SignAdapter {
        return .{ .signing_key = .{ .key = key, .entropy = entropy, .release_context = release_context, .release = release_fn } };
    }

    fn sign(self: *SignAdapter, scheme: credentials.SignatureScheme, input: []const u8, out: []u8) credentials.SignError!usize {
        return switch (self.*) {
            .identity => |*identity| blk: {
                if (identity.signatureScheme() != scheme) return error.InvalidCallbackBehavior;
                break :blk try identity.sign(input, out);
            },
            .external => |external| try external.sign(external.context, scheme, input, out),
            .signing_key => |adapter| blk: {
                const provider_scheme = tlsToProviderScheme(scheme) orelse return error.InvalidCallbackBehavior;
                if (adapter.key.scheme() != provider_scheme) return error.InvalidCallbackBehavior;
                const written = adapter.key.sign(input, adapter.entropy, out) catch |err| switch (err) {
                    error.InvalidInput => return error.SignatureOutputOverflow,
                    error.UnsupportedCapability,
                    error.EntropyFailure,
                    error.ProviderFailure,
                    => return error.SigningProviderFailure,
                };
                break :blk written;
            },
        };
    }

    fn release(self: *SignAdapter) void {
        switch (self.*) {
            .identity => |*identity| std_crypto.secureZero(u8, std.mem.asBytes(&identity.key)),
            .external => |external| external.release(external.context),
            .signing_key => |adapter| if (adapter.release) |release_fn| {
                release_fn(adapter.release_context.?);
            },
        }
    }
};

pub const CredentialBundleConfig = struct {
    chain: []const []const u8,
    patterns: []const []const u8,
    signer: SignAdapter,
    key_kind: KeyKind,
    supported_schemes: []const credentials.SignatureScheme = &.{},
    is_default: bool = false,
};

const CredentialBundle = struct {
    chain: []const []const u8,
    patterns: []const HostPattern,
    signer: SignAdapter,
    key_kind: KeyKind,
    supported_schemes: []const credentials.SignatureScheme,
    install_order: usize,
    is_default: bool,

    fn deinit(self: *CredentialBundle, allocator: std.mem.Allocator) void {
        for (self.chain) |entry| allocator.free(entry);
        allocator.free(self.chain);
        for (self.patterns) |pattern| {
            switch (pattern) {
                .exact => |value| allocator.free(value),
                .wildcard_suffix => |value| allocator.free(value),
            }
        }
        allocator.free(self.patterns);
        allocator.free(self.supported_schemes);
        self.signer.release();
        self.* = undefined;
    }

    fn matchesPattern(self: *const CredentialBundle, class: MatchClass) bool {
        return switch (class) {
            .exact => |name| for (self.patterns) |pattern| {
                if (pattern == .exact and std.mem.eql(u8, pattern.exact, name)) break true;
            } else false,
            .wildcard => |suffix| for (self.patterns) |pattern| {
                if (pattern == .wildcard_suffix and std.mem.eql(u8, pattern.wildcard_suffix, suffix)) break true;
            } else false,
            .default => self.is_default,
        };
    }

    fn supportsScheme(self: *const CredentialBundle, scheme: credentials.SignatureScheme) bool {
        if (!schemeLegalForKeyKind(self.key_kind, scheme)) return false;
        for (self.supported_schemes) |candidate| {
            if (candidate == scheme) return true;
        }
        return false;
    }
};

pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    options: SnapshotOptions,
    generation: u64,
    bundles: []CredentialBundle,
    ref_count: std.atomic.Value(usize) = std.atomic.Value(usize).init(1),
    deinit_count: *usize = &noop_deinit_count,

    var noop_deinit_count: usize = 0;

    pub fn build(
        allocator: std.mem.Allocator,
        configs: []const CredentialBundleConfig,
        options: SnapshotOptions,
        generation: u64,
    ) BuildError!*Snapshot {
        if (configs.len == 0) return error.EmptyCredentialSet;
        if (configs.len > max_bundles) return error.EmptyCredentialSet;

        var snapshot = allocator.create(Snapshot) catch return error.OutOfMemory;
        snapshot.* = .{
            .allocator = allocator,
            .options = options,
            .generation = generation,
            .bundles = &.{},
        };
        errdefer {
            snapshot.deinit();
            allocator.destroy(snapshot);
        }

        var bundles = allocator.alloc(CredentialBundle, configs.len) catch return error.OutOfMemory;
        var initialized: usize = 0;
        errdefer {
            for (bundles[0..initialized]) |*bundle| bundle.deinit(allocator);
            allocator.free(bundles);
        }

        var default_count: usize = 0;
        for (configs, 0..) |config, index| {
            bundles[index] = try buildBundle(allocator, config, index);
            initialized += 1;
            if (bundles[index].is_default) default_count += 1;
        }
        if (default_count > 1) return error.DuplicateDefaultBundle;
        if (default_count == 0 and (options.absent_sni_policy == .use_default or options.unknown_sni_policy == .use_default))
            return error.NoUsableDefaultBundle;

        snapshot.bundles = bundles;
        return snapshot;
    }

    pub fn retain(self: *Snapshot) void {
        _ = self.ref_count.fetchAdd(1, .acq_rel);
    }

    pub fn release(self: *Snapshot) void {
        const previous = self.ref_count.fetchSub(1, .acq_rel);
        std.debug.assert(previous > 0);
        if (previous == 1) {
            const allocator = self.allocator;
            self.deinit();
            allocator.destroy(self);
        }
    }

    fn deinit(self: *Snapshot) void {
        self.deinit_count.* += 1;
        for (self.bundles) |*bundle| bundle.deinit(self.allocator);
        self.allocator.free(self.bundles);
        self.bundles = &.{};
    }

    fn select(self: *Snapshot, selection: *const credentials.SelectionContext) credentials.SelectError!credentials.SelectedCredential {
        const class = self.resolveClass(selection.server_name) orelse return error.NoCredentialAvailable;
        for (self.bundles, 0..) |*bundle, index| {
            if (!bundle.matchesPattern(class)) continue;
            const scheme = chooseCompatibleScheme(bundle, selection.peer_signature_schemes) orelse continue;
            const handle = self.allocator.create(SelectedHandle) catch return error.OutOfMemory;
            handle.* = .{
                .snapshot = self,
                .bundle_index = index,
                .chosen_scheme = scheme,
            };
            return .{ .handle = handle, .scheme = scheme, .vtable = &SelectedHandle.vtable };
        }
        return error.NoCompatibleSignatureAlgorithm;
    }

    fn resolveClass(self: *const Snapshot, server_name: ?[]const u8) ?MatchClass {
        const raw_name = server_name orelse {
            return switch (self.options.absent_sni_policy) {
                .use_default => .default,
                .fail_handshake => null,
            };
        };
        if (raw_name.len == 0 or raw_name.len > max_host_pattern_len) return null;
        var name_buf: [max_host_pattern_len]u8 = undefined;
        const name = lowerHostInto(raw_name, &name_buf) catch return null;

        for (self.bundles) |bundle| {
            for (bundle.patterns) |pattern| {
                if (pattern == .exact and std.mem.eql(u8, pattern.exact, name))
                    return .{ .exact = pattern.exact };
            }
        }

        var best: ?[]const u8 = null;
        for (self.bundles) |bundle| {
            for (bundle.patterns) |pattern| {
                if (pattern != .wildcard_suffix) continue;
                const suffix = pattern.wildcard_suffix;
                if (!wildcardMatchesSuffix(name, suffix)) continue;
                if (best == null or suffix.len > best.?.len) best = suffix;
            }
        }
        if (best) |suffix| return .{ .wildcard = suffix };

        return switch (self.options.unknown_sni_policy) {
            .use_default => .default,
            .fail_handshake => null,
        };
    }
};

const MatchClass = union(enum) {
    exact: []const u8,
    wildcard: []const u8,
    default,
};

pub const ReloadableProvider = struct {
    allocator: std.mem.Allocator,
    mutex: SpinMutex = .{},
    current: ?*Snapshot = null,
    next_generation: u64 = 1,

    pub fn init(allocator: std.mem.Allocator) ReloadableProvider {
        return .{ .allocator = allocator };
    }

    pub fn provider(self: *ReloadableProvider) credentials.CredentialProvider {
        return .{ .ctx = self, .vtable = &provider_vtable };
    }

    pub fn deinit(self: *ReloadableProvider) void {
        self.mutex.lock();
        const retired = self.current;
        self.current = null;
        self.mutex.unlock();
        if (retired) |snapshot| snapshot.release();
    }

    pub fn buildSnapshot(self: *ReloadableProvider, configs: []const CredentialBundleConfig, options: SnapshotOptions) BuildError!*Snapshot {
        self.mutex.lock();
        const generation = self.next_generation;
        self.next_generation += 1;
        self.mutex.unlock();
        return Snapshot.build(self.allocator, configs, options, generation);
    }

    pub fn reload(self: *ReloadableProvider, configs: []const CredentialBundleConfig, options: SnapshotOptions) BuildError!void {
        const replacement = try self.buildSnapshot(configs, options);
        self.install(replacement);
    }

    pub fn install(self: *ReloadableProvider, replacement: *Snapshot) void {
        self.mutex.lock();
        const retired = self.current;
        self.current = replacement;
        self.mutex.unlock();
        if (retired) |snapshot| snapshot.release();
    }

    fn acquireCurrent(self: *ReloadableProvider) ?*Snapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        const snapshot = self.current orelse return null;
        snapshot.retain();
        return snapshot;
    }

    const provider_vtable = credentials.CredentialProvider.VTable{ .select = select };

    fn select(ctx: *anyopaque, selection: *const credentials.SelectionContext) credentials.SelectError!credentials.Progress(credentials.SelectedCredential) {
        const self: *ReloadableProvider = @ptrCast(@alignCast(ctx));
        const snapshot = self.acquireCurrent() orelse return error.NoCredentialAvailable;
        errdefer snapshot.release();
        const selected = try snapshot.select(selection);
        return .{ .complete = selected };
    }
};

const SpinMutex = struct {
    state: std.atomic.Value(u8) = std.atomic.Value(u8).init(0),

    fn lock(self: *SpinMutex) void {
        while (self.state.cmpxchgStrong(0, 1, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    fn unlock(self: *SpinMutex) void {
        self.state.store(0, .release);
    }
};

const SelectedHandle = struct {
    snapshot: *Snapshot,
    bundle_index: usize,
    chosen_scheme: credentials.SignatureScheme,

    const vtable = credentials.SelectedCredential.VTable{
        .chain = chain,
        .sign = sign,
        .release = release,
    };

    fn chain(handle: *anyopaque) credentials.CertificateChain {
        const self: *SelectedHandle = @ptrCast(@alignCast(handle));
        return .{ .entries = self.snapshot.bundles[self.bundle_index].chain };
    }

    fn sign(handle: *anyopaque, scheme: credentials.SignatureScheme, input: []const u8, out: []u8) credentials.SignError!credentials.Progress(usize) {
        const self: *SelectedHandle = @ptrCast(@alignCast(handle));
        if (scheme != self.chosen_scheme) return error.InvalidCallbackBehavior;
        const bundle = &self.snapshot.bundles[self.bundle_index];
        return .{ .complete = try bundle.signer.sign(scheme, input, out) };
    }

    fn release(handle: *anyopaque) void {
        const self: *SelectedHandle = @ptrCast(@alignCast(handle));
        const snapshot = self.snapshot;
        const allocator = snapshot.allocator;
        allocator.destroy(self);
        snapshot.release();
    }
};

fn buildBundle(
    allocator: std.mem.Allocator,
    config: CredentialBundleConfig,
    install_order: usize,
) BuildError!CredentialBundle {
    var signer = config.signer;
    var signer_owned = true;
    errdefer if (signer_owned) signer.release();

    if (config.chain.len == 0) return error.EmptyChain;
    if (config.chain.len > credentials.max_chain_entries) return error.TooManyChainEntries;
    if (config.patterns.len == 0 or config.patterns.len > max_patterns_per_bundle) return error.EmptyHostPattern;

    var chain = allocator.alloc([]const u8, config.chain.len) catch return error.OutOfMemory;
    var copied_chain: usize = 0;
    errdefer {
        for (chain[0..copied_chain]) |entry| allocator.free(entry);
        allocator.free(chain);
    }
    for (config.chain, 0..) |entry, i| {
        if (entry.len == 0) return error.InvalidChain;
        try validateCertificateDer(entry);
        chain[i] = allocator.dupe(u8, entry) catch return error.OutOfMemory;
        copied_chain += 1;
    }

    const leaf_kind = leafKeyKind(chain[0]) catch |err| switch (err) {
        error.InvalidLeafKey => return error.InvalidLeafKey,
        error.UnsupportedKeyType => return error.UnsupportedKeyType,
    };
    if (leaf_kind != config.key_kind) return error.KeySignerMismatch;

    var patterns = allocator.alloc(HostPattern, config.patterns.len) catch return error.OutOfMemory;
    var copied_patterns: usize = 0;
    errdefer {
        for (patterns[0..copied_patterns]) |pattern| freePattern(allocator, pattern);
        allocator.free(patterns);
    }
    for (config.patterns, 0..) |raw, i| {
        patterns[i] = try parseHostPattern(allocator, raw);
        copied_patterns += 1;
        if (hasDuplicatePatternIn(patterns[0..i], patterns[i]))
            return error.DuplicateHostPattern;
    }

    const schemes = try copySupportedSchemes(allocator, config);
    errdefer allocator.free(schemes);
    if (schemes.len == 0) return error.NoSupportedSignatureScheme;
    for (schemes) |scheme| {
        if (!schemeLegalForKeyKind(config.key_kind, scheme)) return error.KeySignerMismatch;
    }

    switch (signer) {
        .external => {},
        .signing_key => |adapter| {
            if (adapter.release != null and adapter.release_context == null) return error.InvalidOwnershipContract;
        },
        .identity => |*identity| if (identity.signatureScheme() != schemes[0] or !schemeLegalForKeyKind(config.key_kind, identity.signatureScheme()))
            return error.KeySignerMismatch,
    }

    signer_owned = false;
    return .{
        .chain = chain,
        .patterns = patterns,
        .signer = signer,
        .key_kind = config.key_kind,
        .supported_schemes = schemes,
        .install_order = install_order,
        .is_default = config.is_default,
    };
}

fn copySupportedSchemes(allocator: std.mem.Allocator, config: CredentialBundleConfig) BuildError![]credentials.SignatureScheme {
    if (config.supported_schemes.len > 0) {
        const out = allocator.dupe(credentials.SignatureScheme, config.supported_schemes) catch return error.OutOfMemory;
        return out;
    }
    switch (config.signer) {
        .identity => |*identity| {
            const out = allocator.alloc(credentials.SignatureScheme, 1) catch return error.OutOfMemory;
            out[0] = identity.signatureScheme();
            return out;
        },
        .signing_key => |adapter| {
            const scheme = providerToTlsScheme(adapter.key.scheme()) orelse return error.NoSupportedSignatureScheme;
            const out = allocator.alloc(credentials.SignatureScheme, 1) catch return error.OutOfMemory;
            out[0] = scheme;
            return out;
        },
        .external => return error.NoSupportedSignatureScheme,
    }
}

fn leafKeyKind(der: []const u8) error{ InvalidLeafKey, UnsupportedKeyType }!KeyKind {
    const parsed = (std_crypto.Certificate{ .buffer = der, .index = 0 }).parse() catch return error.InvalidLeafKey;
    return switch (parsed.pub_key_algo) {
        .curveEd25519 => .ed25519,
        .X9_62_id_ecPublicKey => |curve| if (curve == .X9_62_prime256v1) .ecdsa_p256 else error.UnsupportedKeyType,
        else => error.UnsupportedKeyType,
    };
}

fn validateCertificateDer(der: []const u8) BuildError!void {
    if (!isCompleteDerSequence(der)) return error.InvalidChain;
    _ = (std_crypto.Certificate{ .buffer = der, .index = 0 }).parse() catch return error.InvalidChain;
}

fn isCompleteDerSequence(der: []const u8) bool {
    if (der.len < 2 or der[0] != 0x30) return false;
    var len_len: usize = 1;
    var payload_len: usize = der[1];
    if ((payload_len & 0x80) != 0) {
        len_len = payload_len & 0x7f;
        if (len_len == 0 or len_len > @sizeOf(usize) or 2 + len_len > der.len) return false;
        payload_len = 0;
        for (der[2 .. 2 + len_len]) |byte| {
            payload_len = std.math.mul(usize, payload_len, 256) catch return false;
            payload_len = std.math.add(usize, payload_len, byte) catch return false;
        }
        if (payload_len < 128) return false;
    }
    const header_len = 1 + 1 + if ((der[1] & 0x80) != 0) len_len else 0;
    return payload_len == der.len - header_len;
}

fn parseHostPattern(allocator: std.mem.Allocator, raw: []const u8) BuildError!HostPattern {
    if (raw.len == 0) return error.EmptyHostPattern;
    if (raw.len > max_host_pattern_len) return error.InvalidHostPattern;

    if (std.mem.indexOfScalar(u8, raw, '*')) |star| {
        if (star != 0 or raw.len < 3 or raw[1] != '.') return error.InvalidWildcardPattern;
        if (std.mem.indexOfScalar(u8, raw[1..], '*') != null) return error.InvalidWildcardPattern;
        const suffix_raw = raw[1..];
        try validateDnsName(suffix_raw[1..], true);
        const suffix = allocator.alloc(u8, suffix_raw.len) catch return error.OutOfMemory;
        for (suffix_raw, 0..) |ch, i| suffix[i] = asciiLower(ch);
        return .{ .wildcard_suffix = suffix };
    }

    try validateDnsName(raw, false);
    const exact = allocator.alloc(u8, raw.len) catch return error.OutOfMemory;
    for (raw, 0..) |ch, i| exact[i] = asciiLower(ch);
    return .{ .exact = exact };
}

fn validateDnsName(name: []const u8, wildcard_suffix: bool) BuildError!void {
    if (name.len == 0 or name.len > max_host_pattern_len) return error.InvalidHostPattern;
    if (name[0] == '.' or name[name.len - 1] == '.') return if (wildcard_suffix) error.InvalidWildcardPattern else error.InvalidHostPattern;
    var label_len: usize = 0;
    var labels: usize = 0;
    for (name) |ch| {
        if (ch == '.') {
            if (label_len == 0 or label_len > 63) return if (wildcard_suffix) error.InvalidWildcardPattern else error.InvalidHostPattern;
            labels += 1;
            label_len = 0;
            continue;
        }
        if (!isDnsLabelByte(ch)) return if (wildcard_suffix) error.InvalidWildcardPattern else error.InvalidHostPattern;
        label_len += 1;
    }
    if (label_len == 0 or label_len > 63) return if (wildcard_suffix) error.InvalidWildcardPattern else error.InvalidHostPattern;
    labels += 1;
    if (wildcard_suffix and labels < 2) return error.InvalidWildcardPattern;
}

fn isDnsLabelByte(ch: u8) bool {
    return (ch >= 'A' and ch <= 'Z') or
        (ch >= 'a' and ch <= 'z') or
        (ch >= '0' and ch <= '9') or
        ch == '-';
}

fn hasDuplicatePatternIn(patterns: []const HostPattern, candidate: HostPattern) bool {
    for (patterns) |pattern| {
        if (@as(std.meta.Tag(HostPattern), pattern) != @as(std.meta.Tag(HostPattern), candidate)) continue;
        if (std.mem.eql(u8, pattern.text(), candidate.text())) return true;
    }
    return false;
}

fn freePattern(allocator: std.mem.Allocator, pattern: HostPattern) void {
    switch (pattern) {
        .exact => |value| allocator.free(value),
        .wildcard_suffix => |value| allocator.free(value),
    }
}

pub fn asciiLower(ch: u8) u8 {
    return if (ch >= 'A' and ch <= 'Z') ch + ('a' - 'A') else ch;
}

pub fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |lhs, rhs| {
        if (asciiLower(lhs) != asciiLower(rhs)) return false;
    }
    return true;
}

pub fn wildcardMatchesSuffix(server_name: []const u8, suffix: []const u8) bool {
    if (suffix.len < 2 or suffix[0] != '.') return false;
    if (server_name.len <= suffix.len) return false;
    const suffix_start = server_name.len - suffix.len;
    if (!asciiEqlIgnoreCase(server_name[suffix_start..], suffix)) return false;
    const left_label = server_name[0..suffix_start];
    return left_label.len > 0 and std.mem.indexOfScalar(u8, left_label, '.') == null;
}

fn lowerHostInto(raw: []const u8, out: *[max_host_pattern_len]u8) BuildError![]const u8 {
    if (raw.len == 0 or raw.len > out.len) return error.InvalidHostPattern;
    try validateDnsName(raw, false);
    for (raw, 0..) |ch, i| out[i] = asciiLower(ch);
    return out[0..raw.len];
}

fn chooseCompatibleScheme(bundle: *const CredentialBundle, offered: []const u16) ?credentials.SignatureScheme {
    for (offered) |wire| {
        const scheme = schemeFromWire(wire) orelse continue;
        if (bundle.supportsScheme(scheme)) return scheme;
    }
    return null;
}

fn schemeFromWire(wire: u16) ?credentials.SignatureScheme {
    return switch (wire) {
        0x0807 => .ed25519,
        0x0403 => .ecdsa_secp256r1_sha256,
        else => null,
    };
}

fn schemeLegalForKeyKind(kind: KeyKind, scheme: credentials.SignatureScheme) bool {
    return switch (kind) {
        .ed25519 => scheme == .ed25519,
        .ecdsa_p256 => scheme == .ecdsa_secp256r1_sha256,
    };
}

fn providerToTlsScheme(scheme: crypto_provider.SignatureScheme) ?credentials.SignatureScheme {
    return switch (scheme) {
        .ed25519 => .ed25519,
        .ecdsa_secp256r1_sha256 => .ecdsa_secp256r1_sha256,
        else => null,
    };
}

fn tlsToProviderScheme(scheme: credentials.SignatureScheme) ?crypto_provider.SignatureScheme {
    return switch (scheme) {
        .ed25519 => .ed25519,
        .ecdsa_secp256r1_sha256 => .ecdsa_secp256r1_sha256,
        else => null,
    };
}

const testing = std.testing;

const p256_test_certificate_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIBmzCCAUGgAwIBAgIURydPBx1vjDTJUssyVTi74k48qnIwCgYIKoZIzj0EAwIw
    \\IzEhMB8GA1UEAwwYVGFyZGlncmFkZSBUZXN0IEVDRFNBIENBMB4XDTI2MDcxMzAy
    \\MDUxOFoXDTM0MDkyOTAyMDUxOFowIzEhMB8GA1UEAwwYVGFyZGlncmFkZSBUZXN0
    \\IEVDRFNBIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFjO2x/y3R5vvZdls
    \\KPVExKzZR9mdUMqPOXp/SfN4Z7of1ddxFWzxLFOdHLTzlQb09zZT5V5WoQXrhTA3
    \\pmhI0aNTMFEwHQYDVR0OBBYEFKe7pGrj6TrDR8CnvdL6MNPwkdKbMB8GA1UdIwQY
    \\MBaAFKe7pGrj6TrDR8CnvdL6MNPwkdKbMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZI
    \\zj0EAwIDSAAwRQIhAKPR86FA40f3W8x1OOMGerLsB4jN61BdmM4HRZGj9syMAiAc
    \\i+PZtkI67r6m/9cgMaix6IarU20mIJdvt0bM4+4uqA==
    \\-----END CERTIFICATE-----
;

fn testSelection(name: ?[]const u8, schemes: []const u16) credentials.SelectionContext {
    return .{
        .role = .server,
        .server_name = name,
        .peer_signature_schemes = schemes,
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = "h2",
        .auth_policy = .{},
    };
}

fn identityConfig(patterns: []const []const u8, default: bool) CredentialBundleConfig {
    return .{
        .chain = &.{credentials.testdata.certificate_der},
        .patterns = patterns,
        .signer = SignAdapter.fromIdentity(credentials.testdata.identity()),
        .key_kind = .ed25519,
        .is_default = default,
    };
}

fn p256ExternalConfig(patterns: []const []const u8, chain: []const []const u8, default: bool) CredentialBundleConfig {
    return .{
        .chain = chain,
        .patterns = patterns,
        .signer = SignAdapter.fromExternal(@ptrCast(@constCast(&noop_external_context)), noopExternalSign, noopExternalRelease),
        .key_kind = .ecdsa_p256,
        .supported_schemes = &.{.ecdsa_secp256r1_sha256},
        .is_default = default,
    };
}

fn syncSelect(provider: credentials.CredentialProvider, selection: *const credentials.SelectionContext) !credentials.SelectedCredential {
    return switch (try provider.selectCredential(selection)) {
        .complete => |credential| credential,
        .pending => error.TestUnexpectedPending,
    };
}

fn syncSign(credential: credentials.SelectedCredential, input: []const u8, out: []u8) !usize {
    return switch (try credential.sign(input, out)) {
        .complete => |written| written,
        .pending => error.TestUnexpectedPending,
    };
}

test "wildcard matcher consumes exactly one label" {
    try testing.expect(wildcardMatchesSuffix("a.example.test", ".example.test"));
    try testing.expect(!wildcardMatchesSuffix("example.test", ".example.test"));
    try testing.expect(!wildcardMatchesSuffix("a.b.example.test", ".example.test"));
    try testing.expect(wildcardMatchesSuffix("A.Example.Test", ".example.test"));
}

test "snapshot rejects invalid wildcards and duplicate normalized patterns inside one bundle" {
    const invalid = [_][]const u8{
        "foo*.example.test",
        "*foo.example.test",
        "api.*.example.test",
        "*.*.example.test",
        "example.*",
        "*",
    };
    for (invalid) |pattern| {
        const config = identityConfig(&.{pattern}, true);
        try testing.expectError(error.InvalidWildcardPattern, Snapshot.build(testing.allocator, &.{config}, .{}, 1));
    }

    const exact = identityConfig(&.{ "API.Example.Test", "api.example.test" }, true);
    try testing.expectError(error.DuplicateHostPattern, Snapshot.build(testing.allocator, &.{exact}, .{}, 1));

    const wildcard = identityConfig(&.{ "*.Example.Test", "*.example.test" }, true);
    try testing.expectError(error.DuplicateHostPattern, Snapshot.build(testing.allocator, &.{wildcard}, .{}, 1));
}

test "same SNI pattern can select among bundles by signature compatibility" {
    const ecdsa_der = try decodeSinglePemCertificate(testing.allocator, p256_test_certificate_pem);
    defer testing.allocator.free(ecdsa_der);
    const ecdsa_chain = [_][]const u8{ecdsa_der};

    {
        var provider = ReloadableProvider.init(testing.allocator);
        defer provider.deinit();
        const ed_exact = identityConfig(&.{"api.example.test"}, false);
        const p256_exact = p256ExternalConfig(&.{"API.Example.Test"}, ecdsa_chain[0..], false);
        try provider.reload(&.{ ed_exact, p256_exact }, .{ .absent_sni_policy = .fail_handshake });

        var ecdsa_only = testSelection("api.example.test", &.{0x0403});
        const selected_p256 = try syncSelect(provider.provider(), &ecdsa_only);
        defer selected_p256.release();
        try testing.expectEqual(credentials.SignatureScheme.ecdsa_secp256r1_sha256, selected_p256.scheme);

        var both = testSelection("api.example.test", &.{ 0x0403, 0x0807 });
        const selected_ed = try syncSelect(provider.provider(), &both);
        defer selected_ed.release();
        try testing.expectEqual(credentials.SignatureScheme.ed25519, selected_ed.scheme);
    }

    {
        var provider = ReloadableProvider.init(testing.allocator);
        defer provider.deinit();
        const ed_wildcard = identityConfig(&.{"*.example.test"}, false);
        const p256_wildcard = p256ExternalConfig(&.{"*.Example.Test"}, ecdsa_chain[0..], false);
        try provider.reload(&.{ ed_wildcard, p256_wildcard }, .{ .absent_sni_policy = .fail_handshake });

        var ecdsa_only = testSelection("www.example.test", &.{0x0403});
        const selected_p256 = try syncSelect(provider.provider(), &ecdsa_only);
        defer selected_p256.release();
        try testing.expectEqual(credentials.SignatureScheme.ecdsa_secp256r1_sha256, selected_p256.scheme);
    }
}

test "snapshot build rejects invalid bundles before publication" {
    const valid = identityConfig(&.{"valid.example.test"}, true);

    var empty_chain = valid;
    empty_chain.chain = &.{};
    try testing.expectError(error.EmptyChain, Snapshot.build(testing.allocator, &.{empty_chain}, .{}, 1));

    var malformed_chain = valid;
    malformed_chain.chain = &.{"not der"};
    try testing.expectError(error.InvalidChain, Snapshot.build(testing.allocator, &.{malformed_chain}, .{}, 1));

    const duplicate_default = identityConfig(&.{"other.example.test"}, true);
    try testing.expectError(error.DuplicateDefaultBundle, Snapshot.build(testing.allocator, &.{ valid, duplicate_default }, .{}, 1));

    var no_default = identityConfig(&.{"nodefault.example.test"}, false);
    try testing.expectError(error.NoUsableDefaultBundle, Snapshot.build(testing.allocator, &.{no_default}, .{}, 1));

    no_default.supported_schemes = &.{};
    no_default.signer = SignAdapter.fromExternal(@ptrCast(@constCast(&noop_external_context)), noopExternalSign, noopExternalRelease);
    try testing.expectError(error.NoSupportedSignatureScheme, Snapshot.build(testing.allocator, &.{no_default}, .{ .absent_sni_policy = .fail_handshake }, 1));
}

test "hostname precedence is exact then longest wildcard then default" {
    var provider = ReloadableProvider.init(testing.allocator);
    defer provider.deinit();
    const configs = [_]CredentialBundleConfig{
        identityConfig(&.{"*.example.test"}, false),
        identityConfig(&.{"*.svc.example.test"}, false),
        identityConfig(&.{"api.svc.example.test"}, false),
        identityConfig(&.{"default.example.test"}, true),
    };
    try provider.reload(&configs, .{ .unknown_sni_policy = .use_default });

    var exact = testSelection("API.Svc.Example.Test", &.{0x0807});
    var selected = try syncSelect(provider.provider(), &exact);
    defer selected.release();
    try testing.expectEqual(@as(u64, 1), provider.current.?.generation);

    var wildcard = testSelection("foo.svc.example.test", &.{0x0807});
    const w = try syncSelect(provider.provider(), &wildcard);
    w.release();

    var defaulted = testSelection("unknown.example.net", &.{0x0807});
    const d = try syncSelect(provider.provider(), &defaulted);
    d.release();
}

test "unknown and absent SNI policies are distinct" {
    var provider = ReloadableProvider.init(testing.allocator);
    defer provider.deinit();
    const config = identityConfig(&.{"default.example.test"}, true);
    try provider.reload(&.{config}, .{ .absent_sni_policy = .use_default, .unknown_sni_policy = .fail_handshake });

    var absent = testSelection(null, &.{0x0807});
    const a = try syncSelect(provider.provider(), &absent);
    a.release();

    var unknown = testSelection("missing.example.test", &.{0x0807});
    try testing.expectError(error.NoCredentialAvailable, provider.provider().selectCredential(&unknown));

    var fail_absent_provider = ReloadableProvider.init(testing.allocator);
    defer fail_absent_provider.deinit();
    try fail_absent_provider.reload(&.{config}, .{ .absent_sni_policy = .fail_handshake, .unknown_sni_policy = .use_default });
    try testing.expectError(error.NoCredentialAvailable, fail_absent_provider.provider().selectCredential(&absent));
}

test "signature compatibility follows peer order and exact class does not fall through" {
    var provider = ReloadableProvider.init(testing.allocator);
    defer provider.deinit();
    var exact_bad = identityConfig(&.{"api.example.test"}, false);
    exact_bad.supported_schemes = &.{.ecdsa_secp256r1_sha256};
    const wildcard = identityConfig(&.{"*.example.test"}, true);
    try testing.expectError(error.KeySignerMismatch, provider.reload(&.{ exact_bad, wildcard }, .{}));

    var exact = identityConfig(&.{"api.example.test"}, false);
    exact.supported_schemes = &.{.ed25519};
    const ecdsa_der = try decodeSinglePemCertificate(testing.allocator, p256_test_certificate_pem);
    defer testing.allocator.free(ecdsa_der);
    const ecdsa_chain = [_][]const u8{ecdsa_der};
    const compatible_wildcard = p256ExternalConfig(&.{"*.example.test"}, ecdsa_chain[0..], true);
    try provider.reload(&.{ exact, compatible_wildcard }, .{});

    var selection = testSelection("api.example.test", &.{0x0403});
    try testing.expectError(error.NoCompatibleSignatureAlgorithm, provider.provider().selectCredential(&selection));

    var wildcard_selection = testSelection("www.example.test", &.{0x0403});
    const wildcard_selected = try syncSelect(provider.provider(), &wildcard_selection);
    wildcard_selected.release();

    selection.peer_signature_schemes = &.{ 0xffff, 0x0807 };
    const selected = try syncSelect(provider.provider(), &selection);
    defer selected.release();
    try testing.expectEqual(credentials.SignatureScheme.ed25519, selected.scheme);
}

test "snapshot owns chain and pattern copies after caller mutation" {
    var provider = ReloadableProvider.init(testing.allocator);
    defer provider.deinit();

    const cert_copy = try testing.allocator.dupe(u8, credentials.testdata.certificate_der);
    defer testing.allocator.free(cert_copy);
    const pattern = try testing.allocator.dupe(u8, "MUTABLE.Example.Test");
    defer testing.allocator.free(pattern);

    var chain_entries = [_][]const u8{cert_copy};
    const config = CredentialBundleConfig{
        .chain = chain_entries[0..],
        .patterns = &.{pattern},
        .signer = SignAdapter.fromIdentity(credentials.testdata.identity()),
        .key_kind = .ed25519,
        .is_default = true,
    };
    try provider.reload(&.{config}, .{});
    @memset(cert_copy, 0);
    @memset(pattern, 'x');

    var selection = testSelection("mutable.example.test", &.{0x0807});
    const selected = try syncSelect(provider.provider(), &selection);
    defer selected.release();
    try testing.expectEqualSlices(u8, credentials.testdata.certificate_der, selected.certificateChain().leaf().?);
}

test "reload keeps selected generation alive until handle release" {
    var first_deinit: usize = 0;
    var second_deinit: usize = 0;
    var provider = ReloadableProvider.init(testing.allocator);
    defer provider.deinit();

    var first = try provider.buildSnapshot(&.{identityConfig(&.{"first.example.test"}, true)}, .{});
    first.deinit_count = &first_deinit;
    provider.install(first);

    var selection = testSelection("first.example.test", &.{0x0807});
    const selected = try syncSelect(provider.provider(), &selection);
    try testing.expectEqual(@as(usize, 0), first_deinit);

    var second = try provider.buildSnapshot(&.{identityConfig(&.{"second.example.test"}, true)}, .{});
    second.deinit_count = &second_deinit;
    provider.install(second);
    try testing.expectEqual(@as(usize, 0), first_deinit);

    var old_sig: [128]u8 = undefined;
    _ = try syncSign(selected, "still generation 1", &old_sig);
    selected.release();
    try testing.expectEqual(@as(usize, 1), first_deinit);

    var new_selection = testSelection("second.example.test", &.{0x0807});
    const new_selected = try syncSelect(provider.provider(), &new_selection);
    new_selected.release();
    try testing.expectEqual(@as(usize, 0), second_deinit);
}

test "failed reload leaves current snapshot usable" {
    var provider = ReloadableProvider.init(testing.allocator);
    defer provider.deinit();
    const good = identityConfig(&.{"ok.example.test"}, true);
    try provider.reload(&.{good}, .{});

    var bad = identityConfig(&.{"bad.example.test"}, false);
    bad.chain = &.{};
    try testing.expectError(error.EmptyChain, provider.reload(&.{bad}, .{}));

    var selection = testSelection("ok.example.test", &.{0x0807});
    const selected = try syncSelect(provider.provider(), &selection);
    selected.release();
}

test "selected handle release uses snapshot allocator after external install" {
    var snapshot_debug: std.heap.DebugAllocator(.{}) = .init;
    defer std.debug.assert(snapshot_debug.deinit() == .ok);
    const snapshot_allocator = snapshot_debug.allocator();

    var provider = ReloadableProvider.init(testing.allocator);
    defer provider.deinit();

    const config = identityConfig(&.{"allocator.example.test"}, true);
    const snapshot = try Snapshot.build(snapshot_allocator, &.{config}, .{}, 1);
    provider.install(snapshot);

    var selection = testSelection("allocator.example.test", &.{0x0807});
    const selected = try syncSelect(provider.provider(), &selection);
    selected.release();
}

test "allocation failure during snapshot build does not leak" {
    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var provider = ReloadableProvider.init(allocator);
            defer provider.deinit();
            const config = identityConfig(&.{"alloc.example.test"}, true);
            try provider.reload(&.{config}, .{});
        }
    }.run, .{});
}

test "fuzz: SNI pattern parsing and matching never panic" {
    try testing.fuzz({}, fuzzPatternParsing, .{ .corpus = &.{
        "",
        "*",
        "*.example.test",
        "api.example.test",
        "foo*.example.test",
        "a.b.example.test",
        "UPPER.Example.Test",
        "\x00\xff.example.test",
    } });
}

fn fuzzPatternParsing(_: void, smith: *testing.Smith) !void {
    var input_buf: [max_host_pattern_len + 8]u8 = undefined;
    const len = smith.slice(&input_buf);
    var storage: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&storage);
    const allocator = fba.allocator();
    if (parseHostPattern(allocator, input_buf[0..len])) |pattern| {
        defer freePattern(allocator, pattern);
        _ = wildcardMatchesSuffix(input_buf[0..len], pattern.text());
        _ = asciiEqlIgnoreCase(input_buf[0..len], pattern.text());
    } else |_| {}
}

test "fuzz: SNI selection is deterministic and wildcard consumes one label" {
    try testing.fuzz({}, fuzzSelectionDeterminism, .{ .corpus = &.{
        "",
        "api.example.test",
        "API.Example.Test",
        "www.example.test",
        "a.b.example.test",
        "missing.example.net",
    } });
}

const SelectionOutcome = union(enum) {
    selected: struct {
        scheme: credentials.SignatureScheme,
        chain_count: usize,
    },
    err: credentials.SelectError,
};

fn selectOutcome(provider: credentials.CredentialProvider, selection: *const credentials.SelectionContext) SelectionOutcome {
    const progress = provider.selectCredential(selection) catch |err| return .{ .err = err };
    return switch (progress) {
        .complete => |credential| blk: {
            const chain_count = credential.certificateChain().count();
            const scheme = credential.scheme;
            credential.release();
            break :blk .{ .selected = .{ .scheme = scheme, .chain_count = chain_count } };
        },
        .pending => |op| blk: {
            op.cancel();
            op.release();
            break :blk .{ .err = error.ProviderInternalFailure };
        },
    };
}

fn expectSameOutcome(a: SelectionOutcome, b: SelectionOutcome) !void {
    try testing.expectEqual(@as(std.meta.Tag(SelectionOutcome), a), @as(std.meta.Tag(SelectionOutcome), b));
    switch (a) {
        .selected => |selected| {
            try testing.expectEqual(selected.scheme, b.selected.scheme);
            try testing.expectEqual(selected.chain_count, b.selected.chain_count);
        },
        .err => |err| try testing.expectEqual(err, b.err),
    }
}

fn fuzzSelectionDeterminism(_: void, smith: *testing.Smith) !void {
    var raw_name: [max_host_pattern_len]u8 = undefined;
    const name_len = smith.slice(&raw_name);
    const sni: ?[]const u8 = if (name_len == 0) null else raw_name[0..name_len];
    var provider = ReloadableProvider.init(testing.allocator);
    defer provider.deinit();

    const chain_one = [_][]const u8{credentials.testdata.certificate_der};
    const chain_two = [_][]const u8{ credentials.testdata.certificate_der, credentials.testdata.certificate_der };
    const configs = [_]CredentialBundleConfig{
        sniIdentityConfigForFuzz(&.{"api.example.test"}, chain_one[0..], false),
        sniIdentityConfigForFuzz(&.{"*.example.test"}, chain_two[0..], true),
    };
    try provider.reload(&configs, .{ .unknown_sni_policy = .fail_handshake });

    var schemes = [_]u16{ 0xffff, 0x0807 };
    var first = testSelection(sni, schemes[0..]);
    var second = testSelection(sni, schemes[0..]);
    try expectSameOutcome(selectOutcome(provider.provider(), &first), selectOutcome(provider.provider(), &second));
}

fn sniIdentityConfigForFuzz(patterns: []const []const u8, chain: []const []const u8, default: bool) CredentialBundleConfig {
    return .{
        .chain = chain,
        .patterns = patterns,
        .signer = SignAdapter.fromIdentity(credentials.testdata.identity()),
        .key_kind = .ed25519,
        .is_default = default,
    };
}

test "ECDSA P-256 certificate metadata is selectable with a P-256 signer handle" {
    const ecdsa_der = try decodeSinglePemCertificate(testing.allocator, p256_test_certificate_pem);
    defer testing.allocator.free(ecdsa_der);

    var ext = CountingExternal{};
    const config = CredentialBundleConfig{
        .chain = &.{ecdsa_der},
        .patterns = &.{"p256.example.test"},
        .signer = SignAdapter.fromExternal(&ext, CountingExternal.sign, CountingExternal.release),
        .key_kind = .ecdsa_p256,
        .supported_schemes = &.{.ecdsa_secp256r1_sha256},
        .is_default = true,
    };
    const snapshot = try Snapshot.build(testing.allocator, &.{config}, .{}, 1);
    snapshot.release();
    try testing.expectEqual(@as(usize, 1), ext.release_count);
}

fn decodeSinglePemCertificate(allocator: std.mem.Allocator, pem: []const u8) ![]u8 {
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = "-----END CERTIFICATE-----";
    const begin_at = std.mem.indexOf(u8, pem, begin) orelse return error.PemBlockNotFound;
    const body_start = begin_at + begin.len;
    const end_at = std.mem.indexOfPos(u8, pem, body_start, end) orelse return error.PemBlockNotFound;
    var b64: std.ArrayList(u8) = .empty;
    defer b64.deinit(allocator);
    for (pem[body_start..end_at]) |ch| switch (ch) {
        '\n', '\r', ' ', '\t' => {},
        else => try b64.append(allocator, ch),
    };
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(b64.items) catch return error.InvalidPemBase64;
    const der = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(der);
    std.base64.standard.Decoder.decode(der, b64.items) catch return error.InvalidPemBase64;
    return der;
}

const CountingExternal = struct {
    release_count: usize = 0,

    fn sign(_: *anyopaque, _: credentials.SignatureScheme, _: []const u8, _: []u8) credentials.SignError!usize {
        return error.SigningProviderFailure;
    }

    fn release(ctx: *anyopaque) void {
        const self: *CountingExternal = @ptrCast(@alignCast(ctx));
        self.release_count += 1;
    }
};

var noop_external_context: u8 = 0;

fn noopExternalSign(_: *anyopaque, _: credentials.SignatureScheme, _: []const u8, _: []u8) credentials.SignError!usize {
    return error.SigningProviderFailure;
}

fn noopExternalRelease(_: *anyopaque) void {}

test "external signer owner release callback runs exactly once" {
    var ext = CountingExternal{};
    {
        var provider = ReloadableProvider.init(testing.allocator);
        defer provider.deinit();
        const config = CredentialBundleConfig{
            .chain = &.{credentials.testdata.certificate_der},
            .patterns = &.{"external.example.test"},
            .signer = SignAdapter.fromExternal(&ext, CountingExternal.sign, CountingExternal.release),
            .key_kind = .ed25519,
            .supported_schemes = &.{.ed25519},
            .is_default = true,
        };
        try provider.reload(&.{config}, .{});
        try testing.expectEqual(@as(usize, 0), ext.release_count);
    }
    try testing.expectEqual(@as(usize, 1), ext.release_count);
}

test "external signer is released when unpublished snapshot validation fails" {
    var ext = CountingExternal{};
    const bad = CredentialBundleConfig{
        .chain = &.{credentials.testdata.certificate_der},
        .patterns = &.{"bad*.example.test"},
        .signer = SignAdapter.fromExternal(&ext, CountingExternal.sign, CountingExternal.release),
        .key_kind = .ed25519,
        .supported_schemes = &.{.ed25519},
        .is_default = true,
    };
    try testing.expectError(error.InvalidWildcardPattern, Snapshot.build(testing.allocator, &.{bad}, .{}, 1));
    try testing.expectEqual(@as(usize, 1), ext.release_count);
}
