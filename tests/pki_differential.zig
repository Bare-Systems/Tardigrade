//! Bounded three-way PKI differential harness (#348).
//!
//! Tardigrade executes its pure-Zig parser, path builder, and validator in
//! process. OpenSSL and Go's crypto/x509 validator remain out of process. The
//! checked-in manifest records every expected decision and requires an
//! explicit normalization rationale before validators may intentionally
//! disagree.
//!
//! Every mismatch additionally runs bounded automated minimization: the
//! disagreeing leaf input is shrunk while Tardigrade's exact classification is
//! preserved, the reduced input is re-verified against all three validators,
//! and the reduced bytes are persisted next to the JSON artifact for promotion
//! into `tests/vectors/pki/reduced/manifest.zig`.

const std = @import("std");
const builtin = @import("builtin");
const compat = @import("zig_compat");
const crypto = @import("crypto");
const pki = @import("pki");
const manifest = @import("pki_differential_manifest.zig");
const reduce_mod = @import("pki_reduce.zig");

const testing = std.testing;
const validation_time: i64 = 1_784_332_800; // 2026-07-18T00:00:00Z
const validation_time_argument = std.fmt.comptimePrint("{d}", .{validation_time});
const max_oracle_output = 64 * 1024;
const max_fixture_size = 1024 * 1024;
const default_artifact_dir = "zig-out/pki-differential-artifacts";
const max_reduction_oracle_calls = 512;
const promotion_registry = "tests/vectors/pki/reduced/manifest.zig";

const Status = enum { accept, reject, tool_failure };

const RuntimeIdentity = struct {
    git_sha: []u8,
    openssl_version: []u8,
    go_version: []u8,
    zig_version: []u8,

    fn deinit(self: *RuntimeIdentity, allocator: std.mem.Allocator) void {
        allocator.free(self.git_sha);
        allocator.free(self.openssl_version);
        allocator.free(self.go_version);
        allocator.free(self.zig_version);
        self.* = undefined;
    }
};

const Observation = struct {
    status: Status,
    diagnostic: []u8,

    fn deinit(self: *Observation, allocator: std.mem.Allocator) void {
        allocator.free(self.diagnostic);
        self.* = undefined;
    }
};

const ParsedChain = struct {
    owned: pki.pem.CertificateChain,
    certificates: []pki.x509.Certificate,

    fn load(allocator: std.mem.Allocator, path: []const u8) !ParsedChain {
        var owned = try pki.pem.loadChainPemFile(allocator, compat.io(), .cwd(), path, .{});
        errdefer owned.deinit(allocator);
        return fromChain(allocator, &owned);
    }

    fn fromPemText(allocator: std.mem.Allocator, pem_text: []const u8) !ParsedChain {
        var owned = try pki.pem.loadChainPem(allocator, pem_text, .{});
        errdefer owned.deinit(allocator);
        return fromChain(allocator, &owned);
    }

    fn fromChain(allocator: std.mem.Allocator, owned: *pki.pem.CertificateChain) !ParsedChain {
        const certificates = try allocator.alloc(pki.x509.Certificate, owned.certificates.len);
        errdefer allocator.free(certificates);
        var initialized: usize = 0;
        errdefer for (certificates[0..initialized]) |*certificate| certificate.deinit(allocator);

        for (owned.certificates, certificates) |pem_certificate, *certificate| {
            certificate.* = try pki.x509.Certificate.parse(allocator, pem_certificate.der, .{});
            initialized += 1;
        }
        return .{ .owned = owned.*, .certificates = certificates };
    }

    fn deinit(self: *ParsedChain, allocator: std.mem.Allocator) void {
        for (self.certificates) |*certificate| certificate.deinit(allocator);
        allocator.free(self.certificates);
        self.owned.deinit(allocator);
        self.* = undefined;
    }
};

fn observation(
    allocator: std.mem.Allocator,
    status: Status,
    comptime format: []const u8,
    args: anytype,
) !Observation {
    return .{
        .status = status,
        .diagnostic = try std.fmt.allocPrint(allocator, format, args),
    };
}

fn rejectionFromError(allocator: std.mem.Allocator, err: anyerror) !Observation {
    if (err == error.OutOfMemory) return error.OutOfMemory;
    const status: Status = if (isResourceLimitError(err)) .tool_failure else .reject;
    return observation(allocator, status, "{s}", .{@errorName(err)});
}

fn isResourceLimitError(err: anyerror) bool {
    const name = @errorName(err);
    return std.mem.eql(u8, name, "InputTooLarge") or
        std.mem.eql(u8, name, "CertificateTooLarge") or
        std.mem.eql(u8, name, "TooManyCertificates") or
        std.mem.eql(u8, name, "TooManyAnchors") or
        std.mem.eql(u8, name, "CountLimitExceeded") or
        std.mem.eql(u8, name, "SearchLimitExceeded") or
        std.mem.eql(u8, name, "NestingLimit") or
        std.mem.eql(u8, name, "ElementCountLimit");
}

fn isResourceLimitReason(reason: pki.path_validator.FailureReason) bool {
    return switch (reason) {
        .out_of_memory,
        .validation_resource_limit_exceeded,
        .name_constraints_resource_limit_exceeded,
        .certificate_policy_resource_limit_exceeded,
        => true,
        else => false,
    };
}

fn tardigradeDecision(allocator: std.mem.Allocator, case: manifest.Case) !Observation {
    const anchor_inputs = [_]pki.trust_store.FileInput{.{ .pem = case.root_file }};
    var anchors = pki.trust_store.Snapshot.loadFiles(
        allocator,
        compat.io(),
        .cwd(),
        &anchor_inputs,
        .{},
    ) catch |err| return rejectionFromError(allocator, err);
    defer anchors.deinit(allocator);

    var leaf_chain = pki.pem.loadChainPemFile(allocator, compat.io(), .cwd(), case.leaf_file, .{}) catch |err|
        return rejectionFromError(allocator, err);
    defer leaf_chain.deinit(allocator);
    if (leaf_chain.certificates.len != 1) {
        return observation(allocator, .reject, "leaf bundle contains {d} certificates", .{leaf_chain.certificates.len});
    }

    var intermediates: ?ParsedChain = null;
    if (case.intermediate_file) |path| {
        intermediates = ParsedChain.load(allocator, path) catch |err|
            return rejectionFromError(allocator, err);
    }
    defer if (intermediates) |*chain| chain.deinit(allocator);
    const intermediate_certificates = if (intermediates) |*chain| chain.certificates else &.{};

    return tardigradeLeafObservation(
        allocator,
        anchors.anchors(),
        intermediate_certificates,
        case.dns_name,
        leaf_chain.certificates[0].der,
    );
}

/// In-process classification of one leaf DER against already-loaded trust
/// anchors and intermediates. This is both the file-based decision above and
/// the minimization oracle, so a reduced input is classified by exactly the
/// production pipeline that produced the original disagreement.
fn tardigradeLeafObservation(
    allocator: std.mem.Allocator,
    anchors: []const pki.x509.Certificate,
    intermediates: []const pki.x509.Certificate,
    dns_name: ?[]const u8,
    leaf_der: []const u8,
) error{OutOfMemory}!Observation {
    var leaf = pki.x509.Certificate.parse(allocator, leaf_der, .{}) catch |err|
        return rejectionFromError(allocator, err);
    defer leaf.deinit(allocator);

    var candidates = pki.path_builder.build(
        allocator,
        &leaf,
        intermediates,
        anchors,
        .{},
    ) catch |err| return rejectionFromError(allocator, err);
    defer candidates.deinit(allocator);

    var entropy = crypto.pure_zig.DeterministicEntropy.init(0x348);
    var provider = crypto.pure_zig.Provider.init(entropy.entropy());
    var result = pki.path_validator.validateCandidates(
        allocator,
        candidates,
        .{
            .validation_time = validation_time,
            .expected_dns_name = dns_name,
            .trust_anchors = anchors,
        },
        provider.cryptoProvider(),
    );
    defer result.deinit(allocator);
    return switch (result) {
        .accepted => observation(allocator, .accept, "accepted", .{}),
        .rejected => |failure| if (isResourceLimitReason(failure.reason))
            observation(allocator, .tool_failure, "validator resource failure: {s}", .{@tagName(failure.reason)})
        else
            observation(
                allocator,
                .reject,
                "{s} certificate_index={?d}",
                .{ @tagName(failure.reason), failure.certificate_index },
            ),
    };
}

fn externalDiagnostic(allocator: std.mem.Allocator, stdout: []const u8, stderr: []const u8) ![]u8 {
    const preferred = if (stderr.len != 0) stderr else stdout;
    const trimmed = std.mem.trim(u8, preferred, " \t\r\n");
    const bounded = trimmed[0..@min(trimmed.len, 2048)];
    if (bounded.len == 0) return allocator.dupe(u8, "no diagnostic");
    return allocator.dupe(u8, bounded);
}

fn commandSummary(allocator: std.mem.Allocator, argv: []const []const u8) ![]u8 {
    const result = std.process.run(allocator, compat.io(), .{
        .argv = argv,
        .stdout_limit = .limited(2048),
        .stderr_limit = .limited(2048),
    }) catch |err| return std.fmt.allocPrint(allocator, "unavailable: {s}", .{@errorName(err)});
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    return switch (result.term) {
        .exited => |code| if (code == 0)
            externalDiagnostic(allocator, result.stdout, result.stderr)
        else
            std.fmt.allocPrint(
                allocator,
                "exited {d}: {s}",
                .{ code, std.mem.trim(u8, if (result.stderr.len != 0) result.stderr else result.stdout, " \t\r\n") },
            ),
        else => allocator.dupe(u8, "terminated before producing a version string"),
    };
}

fn loadRuntimeIdentity(allocator: std.mem.Allocator) !RuntimeIdentity {
    const git_sha = compat.getEnvVarOwned(allocator, "GITHUB_SHA") catch
        try commandSummary(allocator, &.{ "git", "rev-parse", "HEAD" });
    errdefer allocator.free(git_sha);

    const openssl = compat.getEnvVarOwned(allocator, "OPENSSL_BIN") catch
        try allocator.dupe(u8, "openssl");
    defer allocator.free(openssl);
    const openssl_version = try commandSummary(allocator, &.{ openssl, "version" });
    errdefer allocator.free(openssl_version);

    const go_binary = compat.getEnvVarOwned(allocator, "GO_BIN") catch
        try allocator.dupe(u8, "go");
    defer allocator.free(go_binary);
    const go_version = try commandSummary(allocator, &.{ go_binary, "version" });
    errdefer allocator.free(go_version);

    return .{
        .git_sha = git_sha,
        .openssl_version = openssl_version,
        .go_version = go_version,
        .zig_version = try allocator.dupe(u8, builtin.zig_version_string),
    };
}

fn opensslDecision(allocator: std.mem.Allocator, case: manifest.Case) !Observation {
    const openssl = compat.getEnvVarOwned(allocator, "OPENSSL_BIN") catch
        try allocator.dupe(u8, "openssl");
    defer allocator.free(openssl);

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.appendSlice(allocator, &.{
        openssl,
        "verify",
        "-attime",
        validation_time_argument,
        "-purpose",
        "sslserver",
        "-trusted",
        case.root_file,
    });
    if (case.intermediate_file) |path| try argv.appendSlice(allocator, &.{ "-untrusted", path });
    if (case.dns_name) |dns_name| try argv.appendSlice(allocator, &.{ "-verify_hostname", dns_name });
    try argv.append(allocator, case.leaf_file);

    const result = std.process.run(allocator, compat.io(), .{
        .argv = argv.items,
        .stdout_limit = .limited(max_oracle_output),
        .stderr_limit = .limited(max_oracle_output),
    }) catch |err| return observation(allocator, .tool_failure, "spawn failed: {s}", .{@errorName(err)});
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    const status: Status = switch (result.term) {
        .exited => |code| switch (code) {
            0 => .accept,
            // `openssl verify` reserves 2 for a completed verification that
            // rejected the candidate. Usage, file, and setup failures use a
            // different exit and must never masquerade as negative vectors.
            2 => .reject,
            else => .tool_failure,
        },
        else => .tool_failure,
    };
    return .{
        .status = status,
        .diagnostic = try externalDiagnostic(allocator, result.stdout, result.stderr),
    };
}

const GoDecision = struct {
    validator: []const u8,
    accepted: bool,
    diagnostic: []const u8,
};

fn goDecision(allocator: std.mem.Allocator, case: manifest.Case) !Observation {
    const go_binary = compat.getEnvVarOwned(allocator, "GO_BIN") catch
        try allocator.dupe(u8, "go");
    defer allocator.free(go_binary);

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.appendSlice(allocator, &.{
        go_binary,
        "run",
        "tests/pki_go_validator.go",
        "--root",
        case.root_file,
    });
    if (case.intermediate_file) |path| try argv.appendSlice(allocator, &.{ "--intermediate", path });
    try argv.appendSlice(allocator, &.{
        "--leaf",
        case.leaf_file,
        "--time",
        validation_time_argument,
    });
    if (case.dns_name) |dns_name| try argv.appendSlice(allocator, &.{ "--dns-name", dns_name });

    const result = std.process.run(allocator, compat.io(), .{
        .argv = argv.items,
        .stdout_limit = .limited(max_oracle_output),
        .stderr_limit = .limited(max_oracle_output),
    }) catch |err| return observation(allocator, .tool_failure, "spawn failed: {s}", .{@errorName(err)});
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| if (code != 0) {
            return .{
                .status = .tool_failure,
                .diagnostic = try externalDiagnostic(allocator, result.stdout, result.stderr),
            };
        },
        else => return .{
            .status = .tool_failure,
            .diagnostic = try externalDiagnostic(allocator, result.stdout, result.stderr),
        },
    }

    var parsed = std.json.parseFromSlice(GoDecision, allocator, result.stdout, .{
        .ignore_unknown_fields = false,
    }) catch |err| return observation(allocator, .tool_failure, "invalid Go oracle JSON: {s}", .{@errorName(err)});
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.validator, "go-crypto-x509")) {
        return observation(allocator, .tool_failure, "unexpected Go oracle identity: {s}", .{parsed.value.validator});
    }
    return .{
        .status = if (parsed.value.accepted) .accept else .reject,
        .diagnostic = try allocator.dupe(u8, parsed.value.diagnostic[0..@min(parsed.value.diagnostic.len, 2048)]),
    };
}

fn expectedStatus(decision: manifest.Decision) Status {
    return switch (decision) {
        .accept => .accept,
        .reject => .reject,
    };
}

/// One stable string per observation class: status plus the deterministic
/// diagnostic. Minimization preserves this exact class, never just the
/// accept/reject bit, so a reduced input reproduces the same failure path.
fn classString(allocator: std.mem.Allocator, obs: Observation) error{OutOfMemory}![]u8 {
    return std.fmt.allocPrint(allocator, "{s}|{s}", .{ @tagName(obs.status), obs.diagnostic });
}

const LeafOracle = struct {
    allocator: std.mem.Allocator,
    anchors: []const pki.x509.Certificate,
    intermediates: []const pki.x509.Certificate,
    dns_name: ?[]const u8,
    target_class: []const u8,

    fn keeps(self: *const LeafOracle, candidate: []const u8) error{OutOfMemory}!bool {
        var obs = try tardigradeLeafObservation(
            self.allocator,
            self.anchors,
            self.intermediates,
            self.dns_name,
            candidate,
        );
        defer obs.deinit(self.allocator);
        const class = try classString(self.allocator, obs);
        defer self.allocator.free(class);
        return std.mem.eql(u8, class, self.target_class);
    }
};

/// Which certificate of the mismatching case is being reduced. Issue #348
/// covers whole chains: the offending bytes can live in the leaf, an
/// intermediate, or a trust input, so minimization tries every component.
const Component = union(enum) {
    leaf,
    intermediate: usize,
    root: usize,
};

const max_bundle_certificates = 8;

/// Owned DER bytes of every certificate in a case, loaded once so component
/// substitution during minimization needs no file I/O.
const CaseInputs = struct {
    roots: [][]u8,
    intermediates: [][]u8,
    leaf: []u8,

    fn load(allocator: std.mem.Allocator, case: manifest.Case) error{OutOfMemory}!?CaseInputs {
        const roots = (try loadBundle(allocator, case.root_file)) orelse return null;
        errdefer freeBundle(allocator, roots);
        const intermediates = if (case.intermediate_file) |path|
            (try loadBundle(allocator, path)) orelse return null
        else
            try allocator.alloc([]u8, 0);
        errdefer freeBundle(allocator, intermediates);
        const leaves = (try loadBundle(allocator, case.leaf_file)) orelse return null;
        if (leaves.len != 1) {
            freeBundle(allocator, leaves);
            return null;
        }
        const leaf = leaves[0];
        allocator.free(leaves);
        return .{ .roots = roots, .intermediates = intermediates, .leaf = leaf };
    }

    fn loadBundle(allocator: std.mem.Allocator, path: []const u8) error{OutOfMemory}!?[][]u8 {
        var chain = pki.pem.loadChainPemFile(allocator, compat.io(), .cwd(), path, .{}) catch |err|
            return if (err == error.OutOfMemory) error.OutOfMemory else null;
        defer chain.deinit(allocator);
        if (chain.certificates.len > max_bundle_certificates) return null;
        const bundle = try allocator.alloc([]u8, chain.certificates.len);
        errdefer allocator.free(bundle);
        var copied: usize = 0;
        errdefer for (bundle[0..copied]) |der| allocator.free(der);
        for (chain.certificates, bundle) |certificate, *slot| {
            slot.* = try allocator.dupe(u8, certificate.der);
            copied += 1;
        }
        return bundle;
    }

    fn freeBundle(allocator: std.mem.Allocator, bundle: [][]u8) void {
        for (bundle) |der| allocator.free(der);
        allocator.free(bundle);
    }

    fn componentDer(self: *const CaseInputs, component: Component) []const u8 {
        return switch (component) {
            .leaf => self.leaf,
            .intermediate => |index| self.intermediates[index],
            .root => |index| self.roots[index],
        };
    }

    fn deinit(self: *CaseInputs, allocator: std.mem.Allocator) void {
        freeBundle(allocator, self.roots);
        freeBundle(allocator, self.intermediates);
        allocator.free(self.leaf);
        self.* = undefined;
    }
};

/// In-process classification of a whole chain given raw DER bundles, so the
/// minimization oracle can substitute any single component — including trust
/// anchors — without touching the filesystem.
fn tardigradeChainObservation(
    allocator: std.mem.Allocator,
    roots_der: []const []const u8,
    intermediates_der: []const []const u8,
    dns_name: ?[]const u8,
    leaf_der: []const u8,
) error{OutOfMemory}!Observation {
    var anchor_inputs: [max_bundle_certificates]pki.trust_store.BufferInput = undefined;
    for (roots_der, anchor_inputs[0..roots_der.len]) |der, *input| input.* = .{ .der = der };
    var anchors = pki.trust_store.Snapshot.loadBuffers(
        allocator,
        anchor_inputs[0..roots_der.len],
        .{},
    ) catch |err| return rejectionFromError(allocator, err);
    defer anchors.deinit(allocator);

    var intermediates: [max_bundle_certificates]pki.x509.Certificate = undefined;
    var parsed: usize = 0;
    defer for (intermediates[0..parsed]) |*certificate| certificate.deinit(allocator);
    for (intermediates_der) |der| {
        intermediates[parsed] = pki.x509.Certificate.parse(allocator, der, .{}) catch |err|
            return rejectionFromError(allocator, err);
        parsed += 1;
    }

    return tardigradeLeafObservation(
        allocator,
        anchors.anchors(),
        intermediates[0..parsed],
        dns_name,
        leaf_der,
    );
}

const ComponentOracle = struct {
    allocator: std.mem.Allocator,
    inputs: *const CaseInputs,
    component: Component,
    dns_name: ?[]const u8,
    target_class: []const u8,

    fn keeps(self: *const ComponentOracle, candidate: []const u8) error{OutOfMemory}!bool {
        var roots: [max_bundle_certificates][]const u8 = undefined;
        for (self.inputs.roots, roots[0..self.inputs.roots.len]) |der, *slot| slot.* = der;
        var intermediates: [max_bundle_certificates][]const u8 = undefined;
        for (self.inputs.intermediates, intermediates[0..self.inputs.intermediates.len]) |der, *slot| slot.* = der;
        var leaf: []const u8 = self.inputs.leaf;
        switch (self.component) {
            .leaf => leaf = candidate,
            .intermediate => |index| intermediates[index] = candidate,
            .root => |index| roots[index] = candidate,
        }

        var obs = try tardigradeChainObservation(
            self.allocator,
            roots[0..self.inputs.roots.len],
            intermediates[0..self.inputs.intermediates.len],
            self.dns_name,
            leaf,
        );
        defer obs.deinit(self.allocator);
        const class = try classString(self.allocator, obs);
        defer self.allocator.free(class);
        return std.mem.eql(u8, class, self.target_class);
    }
};

const Reduction = struct {
    inputs: CaseInputs,
    component: Component,
    /// Bytes emitted for the reduced component. After an external-divergence
    /// revert these equal the original component, so every emitted fixture
    /// reproduces the observed mismatch.
    reduced_der: []u8,
    original_size: usize,
    /// Size the in-process search reached before any revert.
    candidate_size: usize,
    oracle_calls: usize,
    components_tried: usize,
    budget_exhausted: bool,
    one_minimal: bool,
    target_class: []u8,
    reverted_external_divergence: bool = false,

    fn revertToOriginal(self: *Reduction, allocator: std.mem.Allocator) error{OutOfMemory}!void {
        const original = try allocator.dupe(u8, self.inputs.componentDer(self.component));
        allocator.free(self.reduced_der);
        self.reduced_der = original;
        self.reverted_external_divergence = true;
    }

    fn deinit(self: *Reduction, allocator: std.mem.Allocator) void {
        allocator.free(self.reduced_der);
        allocator.free(self.target_class);
        self.inputs.deinit(allocator);
        self.* = undefined;
    }
};

/// Bounded automated minimization of a mismatching case. Every chain
/// component gets its own class-preserving reduction pass; the component with
/// the largest shrink wins (deterministic order breaks ties). Returns null
/// when the supporting inputs cannot be loaded or the file-based observation
/// cannot be reproduced in memory; the artifact then records the unreduced
/// disagreement.
fn minimizeCase(
    allocator: std.mem.Allocator,
    case: manifest.Case,
    tardigrade_obs: Observation,
) error{OutOfMemory}!?Reduction {
    var inputs = (try CaseInputs.load(allocator, case)) orelse return null;
    errdefer inputs.deinit(allocator);

    const target_class = try classString(allocator, tardigrade_obs);
    errdefer allocator.free(target_class);

    var components: [1 + 2 * max_bundle_certificates]Component = undefined;
    var component_count: usize = 0;
    components[component_count] = .leaf;
    component_count += 1;
    for (0..inputs.intermediates.len) |index| {
        components[component_count] = .{ .intermediate = index };
        component_count += 1;
    }
    for (0..inputs.roots.len) |index| {
        components[component_count] = .{ .root = index };
        component_count += 1;
    }

    var best: ?struct {
        component: Component,
        outcome: reduce_mod.Outcome,
        shrink: usize,
    } = null;
    errdefer if (best) |*candidate| candidate.outcome.deinit(allocator);
    for (components[0..component_count]) |component| {
        const original = inputs.componentDer(component);
        const oracle = ComponentOracle{
            .allocator = allocator,
            .inputs = &inputs,
            .component = component,
            .dns_name = case.dns_name,
            .target_class = target_class,
        };
        var outcome = reduce_mod.reduce(
            allocator,
            original,
            &oracle,
            ComponentOracle.keeps,
            .{ .max_oracle_calls = max_reduction_oracle_calls },
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // The file-based observation cannot be reproduced in memory (e.g.
            // it came from a file-load failure); nothing to preserve.
            error.UninterestingInput => {
                if (best) |*candidate| candidate.outcome.deinit(allocator);
                allocator.free(target_class);
                inputs.deinit(allocator);
                return null;
            },
        };
        const shrink = original.len - outcome.data.len;
        if (best == null or shrink > best.?.shrink) {
            if (best) |*candidate| candidate.outcome.deinit(allocator);
            best = .{ .component = component, .outcome = outcome, .shrink = shrink };
        } else {
            outcome.deinit(allocator);
        }
    }

    const chosen = best.?;
    return .{
        .inputs = inputs,
        .component = chosen.component,
        .reduced_der = chosen.outcome.data,
        .original_size = inputs.componentDer(chosen.component).len,
        .candidate_size = chosen.outcome.data.len,
        .oracle_calls = chosen.outcome.oracle_calls,
        .components_tried = component_count,
        .budget_exhausted = chosen.outcome.budget_exhausted,
        .one_minimal = chosen.outcome.one_minimal,
        .target_class = target_class,
    };
}

fn pemEncodeCertificate(allocator: std.mem.Allocator, der_bytes: []const u8) error{OutOfMemory}![]u8 {
    const encoder = std.base64.standard.Encoder;
    const b64 = try allocator.alloc(u8, encoder.calcSize(der_bytes.len));
    defer allocator.free(b64);
    _ = encoder.encode(b64, der_bytes);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "-----BEGIN CERTIFICATE-----\n");
    var rest: []const u8 = b64;
    while (rest.len > 0) {
        const line = rest[0..@min(rest.len, 64)];
        try out.appendSlice(allocator, line);
        try out.append(allocator, '\n');
        rest = rest[line.len..];
    }
    try out.appendSlice(allocator, "-----END CERTIFICATE-----\n");
    return out.toOwnedSlice(allocator);
}

const ObservationView = struct {
    status: Status,
    diagnostic: []const u8,

    fn of(obs: Observation) ObservationView {
        return .{ .status = obs.status, .diagnostic = obs.diagnostic };
    }
};

const ObservedTriple = struct {
    tardigrade: ObservationView,
    openssl: ObservationView,
    go: ObservationView,
};

const ReductionJson = struct {
    component: []const u8,
    original_size: usize,
    reduced_size: usize,
    candidate_size: usize,
    oracle_calls: usize,
    max_oracle_calls: usize,
    components_tried: usize,
    budget_exhausted: bool,
    one_minimal: bool,
    reverted_external_divergence: bool,
    target_class: []const u8,
    reduced_der_file: []const u8,
    reduced_pem_file: []const u8,
    reduced_sha256: []const u8,
    reduced_case: struct {
        root_file: []const u8,
        intermediate_file: ?[]const u8,
        leaf_file: []const u8,
    },
    observed_reduced: ObservedTriple,
    /// Present only after an external-divergence revert: the decisions that
    /// disqualified the in-process minimum.
    candidate_observed: ?ObservedTriple,
    preserves_observed_statuses: bool,
    promotable: bool,
    promotion_registry: []const u8,
    regression_target: []const u8,
};

fn artifactDir(allocator: std.mem.Allocator) error{OutOfMemory}![]u8 {
    return compat.getEnvVarOwned(allocator, "TARDIGRADE_PKI_DIFF_ARTIFACT_DIR") catch
        allocator.dupe(u8, default_artifact_dir);
}

fn sha256Hex(bytes: []const u8, out: *[64]u8) void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const hex = std.fmt.bufPrint(out, "{x}", .{&digest}) catch unreachable;
    std.debug.assert(hex.len == out.len);
}

fn pemEncodeBundleWithReplacement(
    allocator: std.mem.Allocator,
    ders: []const []u8,
    replace_index: usize,
    replacement: []const u8,
) error{OutOfMemory}![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (ders, 0..) |der, index| {
        const bytes: []const u8 = if (index == replace_index) replacement else der;
        const pem = try pemEncodeCertificate(allocator, bytes);
        defer allocator.free(pem);
        try out.appendSlice(allocator, pem);
    }
    return out.toOwnedSlice(allocator);
}

/// File inputs forming the reduced case: the three validator inputs with the
/// reduced component substituted, plus the standalone reduced component.
const ReducedPaths = struct {
    der_path: []u8,
    pem_path: []u8,
    root_file: []u8,
    intermediate_file: ?[]u8,
    leaf_file: []u8,

    fn deinit(self: *ReducedPaths, allocator: std.mem.Allocator) void {
        allocator.free(self.der_path);
        allocator.free(self.pem_path);
        allocator.free(self.root_file);
        if (self.intermediate_file) |path| allocator.free(path);
        allocator.free(self.leaf_file);
        self.* = undefined;
    }
};

/// Write the reduced component (raw DER plus PEM) and whichever substituted
/// bundle the external validators need, under `artifact_dir` inside `dir`.
/// Pure persistence: no external processes, so offline tests can drive it
/// against a temporary directory.
fn persistReducedCase(
    allocator: std.mem.Allocator,
    dir: compat.DirCompat,
    artifact_dir: []const u8,
    case: manifest.Case,
    r: *const Reduction,
) !ReducedPaths {
    try dir.makePath(artifact_dir);
    const der_path = try std.fmt.allocPrint(allocator, "{s}/{s}.reduced.der", .{ artifact_dir, case.id });
    errdefer allocator.free(der_path);
    try dir.writeFile(.{ .sub_path = der_path, .data = r.reduced_der });
    const pem_path = try std.fmt.allocPrint(allocator, "{s}/{s}.reduced.crt", .{ artifact_dir, case.id });
    errdefer allocator.free(pem_path);
    const reduced_pem = try pemEncodeCertificate(allocator, r.reduced_der);
    defer allocator.free(reduced_pem);
    try dir.writeFile(.{ .sub_path = pem_path, .data = reduced_pem });

    var root_file: ?[]u8 = null;
    errdefer if (root_file) |path| allocator.free(path);
    var intermediate_file: ?[]u8 = null;
    errdefer if (intermediate_file) |path| allocator.free(path);
    var leaf_file: ?[]u8 = null;
    errdefer if (leaf_file) |path| allocator.free(path);
    switch (r.component) {
        .leaf => {
            root_file = try allocator.dupe(u8, case.root_file);
            if (case.intermediate_file) |path| intermediate_file = try allocator.dupe(u8, path);
            leaf_file = try allocator.dupe(u8, pem_path);
        },
        .intermediate => |index| {
            const bundle_path = try std.fmt.allocPrint(
                allocator,
                "{s}/{s}.reduced-intermediates.crt",
                .{ artifact_dir, case.id },
            );
            errdefer allocator.free(bundle_path);
            const bundle = try pemEncodeBundleWithReplacement(allocator, r.inputs.intermediates, index, r.reduced_der);
            defer allocator.free(bundle);
            try dir.writeFile(.{ .sub_path = bundle_path, .data = bundle });
            root_file = try allocator.dupe(u8, case.root_file);
            intermediate_file = bundle_path;
            leaf_file = try allocator.dupe(u8, case.leaf_file);
        },
        .root => |index| {
            const bundle_path = try std.fmt.allocPrint(
                allocator,
                "{s}/{s}.reduced-roots.crt",
                .{ artifact_dir, case.id },
            );
            errdefer allocator.free(bundle_path);
            const bundle = try pemEncodeBundleWithReplacement(allocator, r.inputs.roots, index, r.reduced_der);
            defer allocator.free(bundle);
            try dir.writeFile(.{ .sub_path = bundle_path, .data = bundle });
            root_file = bundle_path;
            if (case.intermediate_file) |path| intermediate_file = try allocator.dupe(u8, path);
            leaf_file = try allocator.dupe(u8, case.leaf_file);
        },
    }
    return .{
        .der_path = der_path,
        .pem_path = pem_path,
        .root_file = root_file.?,
        .intermediate_file = intermediate_file,
        .leaf_file = leaf_file.?,
    };
}

/// The reduced case's persisted inputs plus its three-way verification.
const ReducedVerification = struct {
    paths: ReducedPaths,
    tardigrade: Observation,
    openssl: Observation,
    go: Observation,
    preserves: bool,
    candidate_tardigrade: ?Observation = null,
    candidate_openssl: ?Observation = null,
    candidate_go: ?Observation = null,

    fn deinit(self: *ReducedVerification, allocator: std.mem.Allocator) void {
        self.paths.deinit(allocator);
        self.tardigrade.deinit(allocator);
        self.openssl.deinit(allocator);
        self.go.deinit(allocator);
        if (self.candidate_tardigrade) |*obs| obs.deinit(allocator);
        if (self.candidate_openssl) |*obs| obs.deinit(allocator);
        if (self.candidate_go) |*obs| obs.deinit(allocator);
        self.* = undefined;
    }
};

fn verifyReducedCase(
    allocator: std.mem.Allocator,
    case: manifest.Case,
    paths: *const ReducedPaths,
) !struct { Observation, Observation, Observation } {
    var reduced_case = case;
    reduced_case.root_file = paths.root_file;
    reduced_case.intermediate_file = paths.intermediate_file;
    reduced_case.leaf_file = paths.leaf_file;
    var tardigrade = try tardigradeDecision(allocator, reduced_case);
    errdefer tardigrade.deinit(allocator);
    var openssl = try opensslDecision(allocator, reduced_case);
    errdefer openssl.deinit(allocator);
    const go = try goDecision(allocator, reduced_case);
    return .{ tardigrade, openssl, go };
}

/// Persist the reduced case and prove it still reproduces the observed
/// mismatch. An in-process minimum whose external decisions diverge from the
/// original tuple is reverted to the original component bytes — an emitted
/// "reduced" fixture must always be a reproduction, never a lossy artifact —
/// with the disqualifying decisions kept for the record.
fn verifyAndPersistReduced(
    allocator: std.mem.Allocator,
    dir: compat.DirCompat,
    artifact_dir: []const u8,
    case: manifest.Case,
    r: *Reduction,
    original_statuses: [3]Status,
) !ReducedVerification {
    var paths = try persistReducedCase(allocator, dir, artifact_dir, case, r);
    errdefer paths.deinit(allocator);
    var tardigrade, var openssl, var go = try verifyReducedCase(allocator, case, &paths);
    errdefer tardigrade.deinit(allocator);
    errdefer openssl.deinit(allocator);
    errdefer go.deinit(allocator);

    var preserves = tardigrade.status == original_statuses[0] and
        openssl.status == original_statuses[1] and
        go.status == original_statuses[2];
    const already_original = std.mem.eql(u8, r.reduced_der, r.inputs.componentDer(r.component));
    if (preserves or already_original) {
        return .{
            .paths = paths,
            .tardigrade = tardigrade,
            .openssl = openssl,
            .go = go,
            .preserves = preserves,
        };
    }

    // Divergence: fall back to the original component bytes and re-verify the
    // rewritten files so `observed_reduced` always describes emitted bytes.
    try r.revertToOriginal(allocator);
    var reverted_paths = try persistReducedCase(allocator, dir, artifact_dir, case, r);
    errdefer reverted_paths.deinit(allocator);
    const reverted_tardigrade, const reverted_openssl, const reverted_go = try verifyReducedCase(allocator, case, &reverted_paths);
    preserves = reverted_tardigrade.status == original_statuses[0] and
        reverted_openssl.status == original_statuses[1] and
        reverted_go.status == original_statuses[2];
    paths.deinit(allocator);
    return .{
        .paths = reverted_paths,
        .tardigrade = reverted_tardigrade,
        .openssl = reverted_openssl,
        .go = reverted_go,
        .preserves = preserves,
        .candidate_tardigrade = tardigrade,
        .candidate_openssl = openssl,
        .candidate_go = go,
    };
}

fn componentLabel(allocator: std.mem.Allocator, component: Component) error{OutOfMemory}![]u8 {
    return switch (component) {
        .leaf => allocator.dupe(u8, "leaf"),
        .intermediate => |index| std.fmt.allocPrint(allocator, "intermediate[{d}]", .{index}),
        .root => |index| std.fmt.allocPrint(allocator, "root[{d}]", .{index}),
    };
}

/// Serialize the mismatch artifact. Pure serialization over precomputed
/// observations so offline tests can assert the schema against a temporary
/// directory; external verification happens in `verifyAndPersistReduced`.
fn writeArtifact(
    allocator: std.mem.Allocator,
    dir: compat.DirCompat,
    artifact_dir: []const u8,
    runtime_identity: RuntimeIdentity,
    case: manifest.Case,
    tardigrade: Observation,
    openssl: Observation,
    go: Observation,
    reduction: ?*const Reduction,
    reduced: ?*const ReducedVerification,
) ![]u8 {
    try dir.makePath(artifact_dir);
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ artifact_dir, case.id });
    errdefer allocator.free(path);

    var component_label: ?[]u8 = null;
    defer if (component_label) |label| allocator.free(label);
    var reduced_sha256_hex: [64]u8 = undefined;
    var reduction_json: ?ReductionJson = null;
    if (reduction) |r| {
        const verified = reduced.?;
        component_label = try componentLabel(allocator, r.component);
        sha256Hex(r.reduced_der, &reduced_sha256_hex);
        reduction_json = .{
            .component = component_label.?,
            .original_size = r.original_size,
            .reduced_size = r.reduced_der.len,
            .candidate_size = r.candidate_size,
            .oracle_calls = r.oracle_calls,
            .max_oracle_calls = max_reduction_oracle_calls,
            .components_tried = r.components_tried,
            .budget_exhausted = r.budget_exhausted,
            .one_minimal = r.one_minimal,
            .reverted_external_divergence = r.reverted_external_divergence,
            .target_class = r.target_class,
            .reduced_der_file = verified.paths.der_path,
            .reduced_pem_file = verified.paths.pem_path,
            .reduced_sha256 = &reduced_sha256_hex,
            .reduced_case = .{
                .root_file = verified.paths.root_file,
                .intermediate_file = verified.paths.intermediate_file,
                .leaf_file = verified.paths.leaf_file,
            },
            .observed_reduced = .{
                .tardigrade = .of(verified.tardigrade),
                .openssl = .of(verified.openssl),
                .go = .of(verified.go),
            },
            .candidate_observed = if (verified.candidate_tardigrade != null) .{
                .tardigrade = .of(verified.candidate_tardigrade.?),
                .openssl = .of(verified.candidate_openssl.?),
                .go = .of(verified.candidate_go.?),
            } else null,
            .preserves_observed_statuses = verified.preserves,
            .promotable = verified.preserves,
            .promotion_registry = promotion_registry,
            .regression_target = case.regression_target,
        };
    }
    const build_step = if (case.profile == .extended)
        "test-pki-differential-extended"
    else
        "test-pki-differential";
    const reproduce = try std.fmt.allocPrint(
        allocator,
        "TARDIGRADE_PKI_DIFF_CASE={s} zig build {s} --summary all --error-style verbose",
        .{ case.id, build_step },
    );
    defer allocator.free(reproduce);
    const payload = try compat.stringifyAlloc(allocator, .{
        .schema_version = 3,
        .case_id = case.id,
        .profile = case.profile,
        .category = case.category,
        .validation_time = validation_time,
        .runtime = .{
            .git_sha = runtime_identity.git_sha,
            .openssl_version = runtime_identity.openssl_version,
            .go_version = runtime_identity.go_version,
            .zig_version = runtime_identity.zig_version,
        },
        .root_file = case.root_file,
        .intermediate_file = case.intermediate_file,
        .leaf_file = case.leaf_file,
        .dns_name = case.dns_name,
        .expected = case.expected,
        .normalization = case.normalization,
        .provenance = case.provenance,
        .license = case.license,
        .regression_target = case.regression_target,
        .reproduce = reproduce,
        .observed = .{
            .tardigrade = tardigrade,
            .openssl = openssl,
            .go = go,
        },
        .reduction = reduction_json,
    }, .{ .whitespace = .indent_2 });
    defer allocator.free(payload);
    try dir.writeFile(.{ .sub_path = path, .data = payload });
    return path;
}

fn runCase(allocator: std.mem.Allocator, runtime_identity: RuntimeIdentity, case: manifest.Case) !void {
    var tardigrade = try tardigradeDecision(allocator, case);
    defer tardigrade.deinit(allocator);
    var openssl = try opensslDecision(allocator, case);
    defer openssl.deinit(allocator);
    var go = try goDecision(allocator, case);
    defer go.deinit(allocator);

    const matches = tardigrade.status == expectedStatus(case.expected.tardigrade) and
        openssl.status == expectedStatus(case.expected.openssl) and
        go.status == expectedStatus(case.expected.go);
    if (matches) return;

    const artifact_dir = try artifactDir(allocator);
    defer allocator.free(artifact_dir);

    var reduction = try minimizeCase(allocator, case, tardigrade);
    defer if (reduction) |*r| r.deinit(allocator);
    var reduced: ?ReducedVerification = null;
    defer if (reduced) |*verification| verification.deinit(allocator);
    if (reduction) |*r| {
        reduced = verifyAndPersistReduced(allocator, compat.cwd(), artifact_dir, case, r, .{
            tardigrade.status,
            openssl.status,
            go.status,
        }) catch |err| blk: {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            std.debug.print(
                "failed to persist reduced inputs for {s}: {s}\n",
                .{ case.id, @errorName(err) },
            );
            break :blk null;
        };
        if (reduced == null) {
            reduction.?.deinit(allocator);
            reduction = null;
        }
    }
    const reduction_ptr: ?*const Reduction = if (reduction) |*r| r else null;
    const reduced_ptr: ?*const ReducedVerification = if (reduced) |*verification| verification else null;

    const artifact_path = writeArtifact(
        allocator,
        compat.cwd(),
        artifact_dir,
        runtime_identity,
        case,
        tardigrade,
        openssl,
        go,
        reduction_ptr,
        reduced_ptr,
    ) catch |err| {
        std.debug.print("failed to persist PKI differential artifact for {s}: {s}\n", .{ case.id, @errorName(err) });
        return error.TestUnexpectedResult;
    };
    defer allocator.free(artifact_path);
    if (reduction) |r| {
        std.debug.print(
            "PKI differential minimized case={s} component={s} {d} -> {d} bytes in {d} oracle calls (reverted={})\n",
            .{
                case.id,
                @tagName(r.component),
                r.original_size,
                r.reduced_der.len,
                r.oracle_calls,
                r.reverted_external_divergence,
            },
        );
    }
    std.debug.print(
        "PKI differential mismatch case={s} expected=({s},{s},{s}) observed=({s},{s},{s}) artifact={s}\n",
        .{
            case.id,
            @tagName(case.expected.tardigrade),
            @tagName(case.expected.openssl),
            @tagName(case.expected.go),
            @tagName(tardigrade.status),
            @tagName(openssl.status),
            @tagName(go.status),
            artifact_path,
        },
    );
    return error.TestUnexpectedResult;
}

fn validateManifest() !void {
    try testing.expect(manifest.cases.len > 0);
    try testing.expect(manifest.cases.len <= 128);
    for (manifest.cases, 0..) |case, index| {
        try testing.expect(case.id.len > 0 and case.id.len <= 96);
        try testing.expect(case.root_file.len > 0);
        try testing.expect(case.leaf_file.len > 0);
        try testing.expect(case.provenance.len > 0);
        try testing.expect(case.license.len > 0);
        try testing.expect(case.regression_target.len > 0);
        for (case.id) |byte| {
            try testing.expect(std.ascii.isLower(byte) or std.ascii.isDigit(byte) or byte == '-');
        }
        try testing.expect(!std.fs.path.isAbsolute(case.root_file));
        try testing.expect(!std.fs.path.isAbsolute(case.leaf_file));
        if (case.intermediate_file) |path| try testing.expect(!std.fs.path.isAbsolute(path));
        if (!case.expected.agree()) {
            try testing.expect(case.normalization != null);
            try testing.expect(case.normalization.?.len > 0);
        }
        try expectFixtureBounded(case.root_file);
        try expectFixtureBounded(case.leaf_file);
        if (case.intermediate_file) |path| try expectFixtureBounded(path);
        for (manifest.cases[0..index]) |earlier| {
            try testing.expect(!std.mem.eql(u8, earlier.id, case.id));
        }
    }
}

fn expectFixtureBounded(path: []const u8) !void {
    const stat = try compat.cwd().statFile(path);
    try testing.expect(stat.kind == .file);
    try testing.expect(stat.size > 0 and stat.size <= max_fixture_size);
}

fn runCorpus(include_extended: bool) !void {
    try validateManifest();
    var runtime_identity = try loadRuntimeIdentity(testing.allocator);
    defer runtime_identity.deinit(testing.allocator);
    const requested_case = compat.getEnvVarOwned(testing.allocator, "TARDIGRADE_PKI_DIFF_CASE") catch null;
    defer if (requested_case) |id| testing.allocator.free(id);

    var executed: usize = 0;
    for (manifest.cases) |case| {
        if (!include_extended and case.profile == .extended) continue;
        if (requested_case) |id| {
            if (!std.mem.eql(u8, id, case.id)) continue;
        }
        errdefer std.debug.print("failed PKI differential case: {s}\n", .{case.id});
        try runCase(testing.allocator, runtime_identity, case);
        executed += 1;
    }
    try testing.expect(executed > 0);
}

test "pki differential manifest is bounded and fully normalized" {
    try validateManifest();
}

// The "pki reduce" tests below are offline: they classify with the in-process
// pipeline only, using embedded fixtures, so they run without OpenSSL or Go.

/// Parse-level oracle used for seeds promoted into the reduced regression
/// corpus: interesting means `pki.x509.Certificate.parse` under default
/// limits fails with exactly the recorded error name.
const ParseOracle = struct {
    allocator: std.mem.Allocator,
    expected_error: []const u8,

    fn keeps(self: *const ParseOracle, candidate: []const u8) error{OutOfMemory}!bool {
        if (pki.x509.Certificate.parse(self.allocator, candidate, .{})) |parsed| {
            var certificate = parsed;
            certificate.deinit(self.allocator);
            return false;
        } else |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            return std.mem.eql(u8, @errorName(err), self.expected_error);
        }
    }
};

const reduced_corpus = @import("pki_reduced_corpus");

/// Embedded source and chain context for every promoted seed, keyed by seed
/// name. Reduction is deterministic, so each seed must regenerate
/// byte-for-byte from its documented source under its documented oracle.
const seed_sources = [_]struct {
    name: []const u8,
    source_pem: []const u8,
    roots_pem: []const u8,
    intermediates_pem: ?[]const u8,
    dns_name: ?[]const u8,
}{
    .{
        .name = "duplicate-critical-extension",
        .source_pem = @embedFile("pki_duplicate_extension_crt"),
        .roots_pem = @embedFile("pki_root_crt"),
        .intermediates_pem = @embedFile("pki_intermediate_crt"),
        .dns_name = "duplicate.example.test",
    },
    .{
        .name = "corrupt-certificate-signature",
        .source_pem = @embedFile("pki_signature_corrupt_crt"),
        .roots_pem = @embedFile("pki_root_crt"),
        .intermediates_pem = @embedFile("pki_intermediate_crt"),
        .dns_name = "api.example.test",
    },
};

const SeedContext = struct {
    anchors: pki.trust_store.Snapshot,
    intermediates: ?ParsedChain,
    source_chain: pki.pem.CertificateChain,
    dns_name: ?[]const u8,

    fn load(allocator: std.mem.Allocator, entry_name: []const u8) !SeedContext {
        const source = for (seed_sources) |candidate| {
            if (std.mem.eql(u8, candidate.name, entry_name)) break candidate;
        } else {
            std.debug.print("promoted seed has no embedded source context: {s}\n", .{entry_name});
            return error.TestUnexpectedResult;
        };
        var anchors = try pki.trust_store.Snapshot.loadBuffers(
            allocator,
            &.{.{ .pem = source.roots_pem }},
            .{},
        );
        errdefer anchors.deinit(allocator);
        var intermediates: ?ParsedChain = if (source.intermediates_pem) |pem_text|
            try ParsedChain.fromPemText(allocator, pem_text)
        else
            null;
        errdefer if (intermediates) |*chain| chain.deinit(allocator);
        var source_chain = try pki.pem.loadChainPem(allocator, source.source_pem, .{});
        errdefer source_chain.deinit(allocator);
        try testing.expectEqual(@as(usize, 1), source_chain.certificates.len);
        return .{
            .anchors = anchors,
            .intermediates = intermediates,
            .source_chain = source_chain,
            .dns_name = source.dns_name,
        };
    }

    fn intermediateCertificates(self: *const SeedContext) []const pki.x509.Certificate {
        return if (self.intermediates) |*chain| chain.certificates else &.{};
    }

    fn deinit(self: *SeedContext, allocator: std.mem.Allocator) void {
        self.anchors.deinit(allocator);
        if (self.intermediates) |*chain| chain.deinit(allocator);
        self.source_chain.deinit(allocator);
        self.* = undefined;
    }
};

test "pki reduce: promoted registry seeds reproduce byte-for-byte and are 1-minimal" {
    const allocator = testing.allocator;
    comptime std.debug.assert(seed_sources.len == reduced_corpus.entries.len);

    for (reduced_corpus.entries) |entry| {
        // The reconstruction below rebuilds the chain around the leaf slot;
        // extend it alongside the first intermediate- or root-placed seed.
        try testing.expect(entry.placement == .leaf);
        var context = try SeedContext.load(allocator, entry.name);
        defer context.deinit(allocator);
        const source_der = context.source_chain.certificates[0].der;

        // A budget generous enough to complete the chunk=1 sweep, so the
        // asserted `one_minimal` flag is a completed proof, never a claim cut
        // short by budget exhaustion.
        const budget = reduce_mod.Options{ .max_oracle_calls = 4096 };
        var outcome = switch (entry.expected) {
            .parse_error => |expected_error| blk: {
                const oracle = ParseOracle{ .allocator = allocator, .expected_error = expected_error };
                break :blk try reduce_mod.reduce(allocator, source_der, &oracle, ParseOracle.keeps, budget);
            },
            .tardigrade_class => |expected_class| blk: {
                const oracle = LeafOracle{
                    .allocator = allocator,
                    .anchors = context.anchors.anchors(),
                    .intermediates = context.intermediateCertificates(),
                    .dns_name = context.dns_name,
                    .target_class = expected_class,
                };
                break :blk try reduce_mod.reduce(allocator, source_der, &oracle, LeafOracle.keeps, budget);
            },
        };
        defer outcome.deinit(allocator);
        try testing.expect(outcome.one_minimal);
        try testing.expect(!outcome.budget_exhausted);
        try testing.expectEqualSlices(u8, entry.seed, outcome.data);
    }
}

test "pki reduce: registry entries resolve to real cases and replay their class" {
    const allocator = testing.allocator;
    for (reduced_corpus.entries) |entry| {
        // `source_case` must name an actual differential-manifest case.
        const source_case = for (manifest.cases) |case| {
            if (std.mem.eql(u8, case.id, entry.source_case)) break case;
        } else {
            std.debug.print("promoted seed references unknown case: {s}\n", .{entry.source_case});
            return error.TestUnexpectedResult;
        };
        // The embedded replay context must match the resolved case's identity
        // check, so the recorded class means what the source case meant.
        const source = for (seed_sources) |candidate| {
            if (std.mem.eql(u8, candidate.name, entry.name)) break candidate;
        } else return error.TestUnexpectedResult;
        try testing.expectEqual(source_case.dns_name == null, source.dns_name == null);
        if (source_case.dns_name) |dns_name| {
            try testing.expectEqualStrings(dns_name, source.dns_name.?);
        }

        // The focused regression: the promoted seed itself must yield the
        // recorded outcome, replayed through the exact oracle that defined it.
        switch (entry.expected) {
            .parse_error => |expected_error| {
                const oracle = ParseOracle{ .allocator = allocator, .expected_error = expected_error };
                try testing.expect(try oracle.keeps(entry.seed));
            },
            .tardigrade_class => |expected_class| {
                var context = try SeedContext.load(allocator, entry.name);
                defer context.deinit(allocator);
                var obs = try tardigradeLeafObservation(
                    allocator,
                    context.anchors.anchors(),
                    context.intermediateCertificates(),
                    context.dns_name,
                    entry.seed,
                );
                defer obs.deinit(allocator);
                const class = try classString(allocator, obs);
                defer allocator.free(class);
                try testing.expectEqualStrings(expected_class, class);
            },
        }
    }
}

fn fabricatedObservation(allocator: std.mem.Allocator, status: Status, text: []const u8) !Observation {
    return observation(allocator, status, "{s}", .{text});
}

// Minimal valid DER values (a SEQUENCE of INTEGERs) so the drill's PEM
// round-trip clears the loader's framing validation.
const drill_leaf_original = "\x30\x06\x02\x01\x01\x02\x01\x02";
const drill_leaf_reduced = "\x30\x03\x02\x01\x01";
const drill_intermediate_original = "\x30\x06\x02\x01\x07\x02\x01\x08";
const drill_intermediate_candidate = "\x30\x03\x02\x01\x07";

test "pki reduce: schema-v3 artifact is complete and reproducible" {
    const allocator = testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = compat.wrapDir(tmp.dir);

    const case = manifest.Case{
        .id = "artifact-schema-drill",
        .profile = .core,
        .category = .malformed_der,
        .root_file = "tests/vectors/pki/root.crt",
        .intermediate_file = "tests/vectors/pki/intermediate.crt",
        .leaf_file = "tests/vectors/pki/drill-leaf.crt",
        .dns_name = "drill.example.test",
        .expected = .all(.reject),
        .provenance = "fabricated artifact-schema drill",
        .license = "Apache-2.0",
        .regression_target = "src/pki/x509_tests.zig",
    };

    var runtime_identity = RuntimeIdentity{
        .git_sha = try allocator.dupe(u8, "drill-sha"),
        .openssl_version = try allocator.dupe(u8, "drill-openssl"),
        .go_version = try allocator.dupe(u8, "drill-go"),
        .zig_version = try allocator.dupe(u8, "drill-zig"),
    };
    defer runtime_identity.deinit(allocator);

    var tardigrade = try fabricatedObservation(allocator, .reject, "OriginalReject");
    defer tardigrade.deinit(allocator);
    var openssl = try fabricatedObservation(allocator, .reject, "openssl original");
    defer openssl.deinit(allocator);
    var go = try fabricatedObservation(allocator, .accept, "go original");
    defer go.deinit(allocator);

    // Case 1: a preserved leaf reduction.
    {
        var reduction = Reduction{
            .inputs = .{
                .roots = try allocator.alloc([]u8, 1),
                .intermediates = try allocator.alloc([]u8, 1),
                .leaf = try allocator.dupe(u8, drill_leaf_original),
            },
            .component = .leaf,
            .reduced_der = try allocator.dupe(u8, drill_leaf_reduced),
            .original_size = drill_leaf_original.len,
            .candidate_size = drill_leaf_reduced.len,
            .oracle_calls = 7,
            .components_tried = 3,
            .budget_exhausted = false,
            .one_minimal = true,
            .target_class = try allocator.dupe(u8, "reject|OriginalReject"),
        };
        reduction.inputs.roots[0] = try allocator.dupe(u8, "ROOT-BYTES");
        reduction.inputs.intermediates[0] = try allocator.dupe(u8, drill_intermediate_original);
        defer reduction.deinit(allocator);

        var verification = ReducedVerification{
            .paths = try persistReducedCase(allocator, dir, "artifacts", case, &reduction),
            .tardigrade = try fabricatedObservation(allocator, .reject, "OriginalReject"),
            .openssl = try fabricatedObservation(allocator, .reject, "openssl reduced"),
            .go = try fabricatedObservation(allocator, .accept, "go reduced"),
            .preserves = true,
        };
        defer verification.deinit(allocator);

        // Persisted files round-trip: raw DER matches, and the PEM decodes to
        // the same bytes.
        const raw = try dir.readFileAlloc(allocator, verification.paths.der_path, 1024);
        defer allocator.free(raw);
        try testing.expectEqualSlices(u8, drill_leaf_reduced, raw);
        const pem_text = try dir.readFileAlloc(allocator, verification.paths.pem_path, 4096);
        defer allocator.free(pem_text);
        var decoded = try pki.pem.loadChainPem(allocator, pem_text, .{});
        defer decoded.deinit(allocator);
        try testing.expectEqual(@as(usize, 1), decoded.certificates.len);
        try testing.expectEqualSlices(u8, drill_leaf_reduced, decoded.certificates[0].der);
        // A leaf reduction substitutes only the leaf input.
        try testing.expectEqualStrings(case.root_file, verification.paths.root_file);
        try testing.expectEqualStrings(case.intermediate_file.?, verification.paths.intermediate_file.?);
        try testing.expectEqualStrings(verification.paths.pem_path, verification.paths.leaf_file);

        const artifact_path = try writeArtifact(
            allocator,
            dir,
            "artifacts",
            runtime_identity,
            case,
            tardigrade,
            openssl,
            go,
            &reduction,
            &verification,
        );
        defer allocator.free(artifact_path);
        const payload = try dir.readFileAlloc(allocator, artifact_path, 64 * 1024);
        defer allocator.free(payload);
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
        defer parsed.deinit();
        const object = parsed.value.object;
        try testing.expectEqual(@as(i64, 3), object.get("schema_version").?.integer);
        try testing.expectEqualStrings("artifact-schema-drill", object.get("case_id").?.string);
        const reduction_json = object.get("reduction").?.object;
        try testing.expectEqualStrings("leaf", reduction_json.get("component").?.string);
        try testing.expectEqual(@as(i64, drill_leaf_original.len), reduction_json.get("original_size").?.integer);
        try testing.expectEqual(@as(i64, drill_leaf_reduced.len), reduction_json.get("reduced_size").?.integer);
        try testing.expectEqual(true, reduction_json.get("one_minimal").?.bool);
        try testing.expectEqual(false, reduction_json.get("budget_exhausted").?.bool);
        try testing.expectEqual(false, reduction_json.get("reverted_external_divergence").?.bool);
        try testing.expectEqual(true, reduction_json.get("preserves_observed_statuses").?.bool);
        try testing.expectEqual(true, reduction_json.get("promotable").?.bool);
        try testing.expect(reduction_json.get("candidate_observed").? == .null);
        var expected_sha: [64]u8 = undefined;
        sha256Hex(drill_leaf_reduced, &expected_sha);
        try testing.expectEqualStrings(&expected_sha, reduction_json.get("reduced_sha256").?.string);
        const observed_reduced = reduction_json.get("observed_reduced").?.object;
        try testing.expectEqualStrings("reject", observed_reduced.get("tardigrade").?.object.get("status").?.string);
        try testing.expectEqualStrings("accept", observed_reduced.get("go").?.object.get("status").?.string);
        const reduced_case = reduction_json.get("reduced_case").?.object;
        try testing.expectEqualStrings(case.root_file, reduced_case.get("root_file").?.string);
    }

    // Case 2: an intermediate reduction whose in-process minimum diverged
    // externally and was reverted.
    {
        var reverted_case = case;
        reverted_case.id = "artifact-schema-drill-reverted";
        var reduction = Reduction{
            .inputs = .{
                .roots = try allocator.alloc([]u8, 1),
                .intermediates = try allocator.alloc([]u8, 1),
                .leaf = try allocator.dupe(u8, drill_leaf_original),
            },
            .component = .{ .intermediate = 0 },
            .reduced_der = try allocator.dupe(u8, drill_intermediate_candidate),
            .original_size = drill_intermediate_original.len,
            .candidate_size = drill_intermediate_candidate.len,
            .oracle_calls = 512,
            .components_tried = 3,
            .budget_exhausted = true,
            .one_minimal = false,
            .target_class = try allocator.dupe(u8, "reject|OriginalReject"),
        };
        reduction.inputs.roots[0] = try allocator.dupe(u8, "ROOT-BYTES");
        reduction.inputs.intermediates[0] = try allocator.dupe(u8, drill_intermediate_original);
        defer reduction.deinit(allocator);
        try reduction.revertToOriginal(allocator);
        try testing.expectEqualSlices(u8, drill_intermediate_original, reduction.reduced_der);

        var verification = ReducedVerification{
            .paths = try persistReducedCase(allocator, dir, "artifacts", reverted_case, &reduction),
            .tardigrade = try fabricatedObservation(allocator, .reject, "OriginalReject"),
            .openssl = try fabricatedObservation(allocator, .reject, "openssl reduced"),
            .go = try fabricatedObservation(allocator, .accept, "go reduced"),
            .preserves = true,
            .candidate_tardigrade = try fabricatedObservation(allocator, .reject, "OriginalReject"),
            .candidate_openssl = try fabricatedObservation(allocator, .tool_failure, "openssl diverged"),
            .candidate_go = try fabricatedObservation(allocator, .accept, "go candidate"),
        };
        defer verification.deinit(allocator);

        // An intermediate reduction substitutes the intermediate bundle and
        // keeps the original leaf and root inputs.
        try testing.expectEqualStrings(reverted_case.root_file, verification.paths.root_file);
        try testing.expectEqualStrings(reverted_case.leaf_file, verification.paths.leaf_file);
        const bundle_text = try dir.readFileAlloc(allocator, verification.paths.intermediate_file.?, 4096);
        defer allocator.free(bundle_text);
        var bundle = try pki.pem.loadChainPem(allocator, bundle_text, .{});
        defer bundle.deinit(allocator);
        try testing.expectEqual(@as(usize, 1), bundle.certificates.len);
        try testing.expectEqualSlices(u8, drill_intermediate_original, bundle.certificates[0].der);

        const artifact_path = try writeArtifact(
            allocator,
            dir,
            "artifacts",
            runtime_identity,
            reverted_case,
            tardigrade,
            openssl,
            go,
            &reduction,
            &verification,
        );
        defer allocator.free(artifact_path);
        const payload = try dir.readFileAlloc(allocator, artifact_path, 64 * 1024);
        defer allocator.free(payload);
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
        defer parsed.deinit();
        const reduction_json = parsed.value.object.get("reduction").?.object;
        try testing.expectEqualStrings("intermediate[0]", reduction_json.get("component").?.string);
        try testing.expectEqual(true, reduction_json.get("reverted_external_divergence").?.bool);
        try testing.expectEqual(true, reduction_json.get("budget_exhausted").?.bool);
        try testing.expectEqual(false, reduction_json.get("one_minimal").?.bool);
        // Emitted bytes are the original component again.
        try testing.expectEqual(
            @as(i64, drill_intermediate_original.len),
            reduction_json.get("reduced_size").?.integer,
        );
        try testing.expectEqual(
            @as(i64, drill_intermediate_candidate.len),
            reduction_json.get("candidate_size").?.integer,
        );
        const candidate_observed = reduction_json.get("candidate_observed").?.object;
        try testing.expectEqualStrings(
            "tool_failure",
            candidate_observed.get("openssl").?.object.get("status").?.string,
        );
    }
}

test "pki reduce: component oracle substitutes any chain component" {
    const allocator = testing.allocator;
    var root_chain = try pki.pem.loadChainPem(allocator, @embedFile("pki_root_crt"), .{});
    defer root_chain.deinit(allocator);
    var intermediate_chain = try pki.pem.loadChainPem(allocator, @embedFile("pki_intermediate_crt"), .{});
    defer intermediate_chain.deinit(allocator);
    var leaf_chain = try pki.pem.loadChainPem(allocator, @embedFile("pki_signature_corrupt_crt"), .{});
    defer leaf_chain.deinit(allocator);

    var inputs = CaseInputs{
        .roots = try allocator.alloc([]u8, 1),
        .intermediates = try allocator.alloc([]u8, 1),
        .leaf = try allocator.dupe(u8, leaf_chain.certificates[0].der),
    };
    inputs.roots[0] = try allocator.dupe(u8, root_chain.certificates[0].der);
    inputs.intermediates[0] = try allocator.dupe(u8, intermediate_chain.certificates[0].der);
    defer inputs.deinit(allocator);

    var obs = try tardigradeChainObservation(
        allocator,
        &.{inputs.roots[0]},
        &.{inputs.intermediates[0]},
        "api.example.test",
        inputs.leaf,
    );
    defer obs.deinit(allocator);
    const target_class = try classString(allocator, obs);
    defer allocator.free(target_class);

    inline for (.{
        Component.leaf,
        Component{ .intermediate = 0 },
        Component{ .root = 0 },
    }) |component| {
        const oracle = ComponentOracle{
            .allocator = allocator,
            .inputs = &inputs,
            .component = component,
            .dns_name = "api.example.test",
            .target_class = target_class,
        };
        const original = inputs.componentDer(component);
        // Substituting the untouched component reproduces the class; a
        // truncated substitute must change the observation, proving the
        // oracle actually rebuilds the chain around that slot.
        try testing.expect(try oracle.keeps(original));
        try testing.expect(!try oracle.keeps(original[0 .. original.len / 2]));
    }
}

test "pki reduce: harness minimization preserves the tardigrade classification" {
    const allocator = testing.allocator;
    var anchors = try pki.trust_store.Snapshot.loadBuffers(
        allocator,
        &.{.{ .pem = @embedFile("pki_root_crt") }},
        .{},
    );
    defer anchors.deinit(allocator);
    var intermediates = try ParsedChain.fromPemText(allocator, @embedFile("pki_intermediate_crt"));
    defer intermediates.deinit(allocator);
    var leaf_chain = try pki.pem.loadChainPem(allocator, @embedFile("pki_duplicate_extension_crt"), .{});
    defer leaf_chain.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), leaf_chain.certificates.len);
    const leaf_der = leaf_chain.certificates[0].der;

    var obs = try tardigradeLeafObservation(
        allocator,
        anchors.anchors(),
        intermediates.certificates,
        "duplicate.example.test",
        leaf_der,
    );
    defer obs.deinit(allocator);
    try testing.expectEqual(Status.reject, obs.status);
    const target_class = try classString(allocator, obs);
    defer allocator.free(target_class);

    const oracle = LeafOracle{
        .allocator = allocator,
        .anchors = anchors.anchors(),
        .intermediates = intermediates.certificates,
        .dns_name = "duplicate.example.test",
        .target_class = target_class,
    };
    var outcome = try reduce_mod.reduce(
        allocator,
        leaf_der,
        &oracle,
        LeafOracle.keeps,
        .{ .max_oracle_calls = max_reduction_oracle_calls },
    );
    defer outcome.deinit(allocator);
    try testing.expect(outcome.data.len <= leaf_der.len);
    try testing.expect(outcome.oracle_calls <= max_reduction_oracle_calls);
    try testing.expect(try oracle.keeps(outcome.data));

    var second = try reduce_mod.reduce(
        allocator,
        leaf_der,
        &oracle,
        LeafOracle.keeps,
        .{ .max_oracle_calls = max_reduction_oracle_calls },
    );
    defer second.deinit(allocator);
    try testing.expectEqualSlices(u8, outcome.data, second.data);
}

test "pki differential core corpus" {
    try runCorpus(false);
}

test "pki differential full corpus" {
    try runCorpus(true);
}
