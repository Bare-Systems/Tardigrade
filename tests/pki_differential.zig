//! Bounded three-way PKI differential harness (#348).
//!
//! Tardigrade executes its pure-Zig parser, path builder, and validator in
//! process. OpenSSL and Go's crypto/x509 validator remain out of process. The
//! checked-in manifest records every expected decision and requires an
//! explicit normalization rationale before validators may intentionally
//! disagree.

const std = @import("std");
const builtin = @import("builtin");
const compat = @import("zig_compat");
const crypto = @import("crypto");
const pki = @import("pki");
const manifest = @import("pki_differential_manifest.zig");

const testing = std.testing;
const validation_time: i64 = 1_784_332_800; // 2026-07-18T00:00:00Z
const validation_time_argument = std.fmt.comptimePrint("{d}", .{validation_time});
const max_oracle_output = 64 * 1024;
const max_fixture_size = 1024 * 1024;
const default_artifact_dir = "zig-out/pki-differential-artifacts";

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

        const certificates = try allocator.alloc(pki.x509.Certificate, owned.certificates.len);
        errdefer allocator.free(certificates);
        var initialized: usize = 0;
        errdefer for (certificates[0..initialized]) |*certificate| certificate.deinit(allocator);

        for (owned.certificates, certificates) |pem_certificate, *certificate| {
            certificate.* = try pki.x509.Certificate.parse(allocator, pem_certificate.der, .{});
            initialized += 1;
        }
        return .{ .owned = owned, .certificates = certificates };
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

    var leaf_chain = ParsedChain.load(allocator, case.leaf_file) catch |err|
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

    var candidates = pki.path_builder.build(
        allocator,
        &leaf_chain.certificates[0],
        intermediate_certificates,
        anchors.anchors(),
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
            .expected_dns_name = case.dns_name,
            .trust_anchors = anchors.anchors(),
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

fn writeArtifact(
    allocator: std.mem.Allocator,
    runtime_identity: RuntimeIdentity,
    case: manifest.Case,
    tardigrade: Observation,
    openssl: Observation,
    go: Observation,
) ![]u8 {
    const artifact_dir = compat.getEnvVarOwned(allocator, "TARDIGRADE_PKI_DIFF_ARTIFACT_DIR") catch
        try allocator.dupe(u8, default_artifact_dir);
    defer allocator.free(artifact_dir);
    try compat.cwd().makePath(artifact_dir);

    const path = try std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ artifact_dir, case.id });
    errdefer allocator.free(path);
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
        .schema_version = 2,
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
    }, .{ .whitespace = .indent_2 });
    defer allocator.free(payload);
    try compat.cwd().writeFile(.{ .sub_path = path, .data = payload });
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

    const artifact_path = writeArtifact(allocator, runtime_identity, case, tardigrade, openssl, go) catch |err| {
        std.debug.print("failed to persist PKI differential artifact for {s}: {s}\n", .{ case.id, @errorName(err) });
        return error.TestUnexpectedResult;
    };
    defer allocator.free(artifact_path);
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

test "pki differential core corpus" {
    try runCorpus(false);
}

test "pki differential full corpus" {
    try runCorpus(true);
}
