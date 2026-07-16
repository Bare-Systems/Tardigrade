//! Offline bounded Wycheproof-style corpus runner for supported pure-Zig crypto.

const std = @import("std");
const crypto_pkg = @import("crypto");
const corpus_manifest = @import("crypto_corpus_manifest.zig");

const provider = crypto_pkg.provider;
const profile = crypto_pkg.profile;
const pure_zig = crypto_pkg.pure_zig;
const testing = std.testing;

const corpus_file = "tests/vectors/wycheproof/corpus.json";
const corpus_bytes = @embedFile("vectors/wycheproof/corpus.json");

const schema_version = "tardigrade-wycheproof-reduced-v1";

const Limits = struct {
    max_file_size: usize = 64 * 1024,
    max_depth: usize = 12,
    max_groups: usize = 8,
    max_cases: usize = 64,
    max_identifier_len: usize = 96,
    max_comment_len: usize = 256,
    max_flags: usize = 8,
    max_encoded_field_len: usize = 512,
    max_decoded_total: usize = 8192,
};

const Classification = enum {
    valid,
    invalid,
    acceptable,
};

const Algorithm = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_poly1305,
    x25519,
    ed25519,

    fn name(self: Algorithm) []const u8 {
        return switch (self) {
            .aes_128_gcm => "AES-128-GCM",
            .aes_256_gcm => "AES-256-GCM",
            .chacha20_poly1305 => "CHACHA20-POLY1305",
            .x25519 => "X25519",
            .ed25519 => "ED25519",
        };
    }

    fn aead(self: Algorithm) ?provider.Aead {
        return switch (self) {
            .aes_128_gcm => .aes_128_gcm,
            .aes_256_gcm => .aes_256_gcm,
            .chacha20_poly1305 => .chacha20_poly1305,
            .x25519, .ed25519 => null,
        };
    }
};

const Operation = enum {
    aead_open,
    derive_shared_secret,
    verify,
};

const Expected = enum {
    success,
    authentication_failed,
    invalid_input,

    fn name(self: Expected) []const u8 {
        return switch (self) {
            .success => "success",
            .authentication_failed => "authentication-failed",
            .invalid_input => "invalid-input",
        };
    }
};

const Observed = enum {
    success,
    authentication_failed,
    invalid_input,
    output_mismatch,

    fn name(self: Observed) []const u8 {
        return switch (self) {
            .success => "success",
            .authentication_failed => "authentication-failed",
            .invalid_input => "invalid-input",
            .output_mismatch => "output-mismatch",
        };
    }
};

const Source = struct {
    name: []const u8,
    repository: []const u8,
    commit: []const u8,
    license: []const u8,
    reduced_by: []const u8,
};

const SkippedSuite = struct {
    algorithm: []const u8,
    reason: []const u8,
    tracking_issue: []const u8,
};

const Case = struct {
    id: []const u8,
    upstream_tc_id: u32,
    classification: Classification,
    expected: Expected,
    comment: []const u8,
    flags: []const []const u8,
    key: []const u8 = &.{},
    nonce: []const u8 = &.{},
    aad: []const u8 = &.{},
    message: []const u8 = &.{},
    ciphertext: []const u8 = &.{},
    tag: []const u8 = &.{},
    private_key: []const u8 = &.{},
    public_key: []const u8 = &.{},
    shared: []const u8 = &.{},
    signature: []const u8 = &.{},
};

const Group = struct {
    id: []const u8,
    upstream_group_index: u32,
    cases: []Case,
};

const Suite = struct {
    id: []const u8,
    algorithm: Algorithm,
    operation: Operation,
    source_file: []const u8,
    groups: []Group,
};

const Corpus = struct {
    arena: std.heap.ArenaAllocator,
    source: Source,
    allowlist: []const Algorithm,
    skipped_suites: []SkippedSuite,
    suites: []Suite,

    fn deinit(self: *Corpus) void {
        self.arena.deinit();
    }
};

const Report = struct {
    executed_suites: usize = 0,
    executed_cases: usize = 0,
    valid: usize = 0,
    invalid: usize = 0,
    acceptable: usize = 0,
    skipped_suites: usize = 0,
};

fn cryptoProvider() provider.CryptoProvider {
    const Holder = struct {
        var entropy = pure_zig.DeterministicEntropy.init(0x374);
        var provider_instance = pure_zig.Provider.init(entropy.entropy());
    };
    return Holder.provider_instance.cryptoProvider();
}

fn parseCorpus(backing_allocator: std.mem.Allocator, input: []const u8, limits: Limits) !Corpus {
    if (input.len > limits.max_file_size) return error.FileTooLarge;
    if (maxJsonDepth(input) > limits.max_depth) return error.NestingDepthExceeded;

    var arena = std.heap.ArenaAllocator.init(backing_allocator);
    errdefer arena.deinit();
    const allocator = arena.allocator();

    const root = try std.json.parseFromSliceLeaky(std.json.Value, allocator, input, .{});
    const root_object = try expectObject(root);
    try ensureOnlyFields(root_object, &.{ "schema", "source", "allowlist", "skippedSuites", "suites" });
    if (!std.mem.eql(u8, try requireString(root_object, "schema", limits), schema_version)) {
        return error.UnsupportedSchema;
    }

    const source = try parseSource(try requireObject(root_object, "source"), limits);
    const allowlist = try parseAllowlist(allocator, try requireArray(root_object, "allowlist"), limits);
    const skipped_suites = try parseSkippedSuites(allocator, try requireArray(root_object, "skippedSuites"), limits);

    var seen_cases = std.StringHashMap(void).init(allocator);
    var parsed_cases: usize = 0;
    var decoded_total: usize = 0;
    const suites = try parseSuites(
        allocator,
        try requireArray(root_object, "suites"),
        allowlist,
        &seen_cases,
        &parsed_cases,
        &decoded_total,
        limits,
    );

    return .{
        .arena = arena,
        .source = source,
        .allowlist = allowlist,
        .skipped_suites = skipped_suites,
        .suites = suites,
    };
}

fn parseSource(obj: std.json.ObjectMap, limits: Limits) !Source {
    try ensureOnlyFields(obj, &.{ "name", "repository", "commit", "license", "reducedBy" });
    return .{
        .name = try requireString(obj, "name", limits),
        .repository = try requireString(obj, "repository", limits),
        .commit = try requireString(obj, "commit", limits),
        .license = try requireString(obj, "license", limits),
        .reduced_by = try requireString(obj, "reducedBy", limits),
    };
}

fn parseAllowlist(allocator: std.mem.Allocator, array: std.json.Array, limits: Limits) ![]const Algorithm {
    var out = std.array_list.Managed(Algorithm).init(allocator);
    for (array.items) |value| {
        const raw = try expectString(value, limits);
        try out.append(try parseAlgorithm(raw));
    }
    return out.toOwnedSlice();
}

fn parseSkippedSuites(allocator: std.mem.Allocator, array: std.json.Array, limits: Limits) ![]SkippedSuite {
    var out = std.array_list.Managed(SkippedSuite).init(allocator);
    for (array.items) |value| {
        const obj = try expectObject(value);
        try ensureOnlyFields(obj, &.{ "algorithm", "reason", "trackingIssue" });
        const skipped = SkippedSuite{
            .algorithm = try requireString(obj, "algorithm", limits),
            .reason = try requireString(obj, "reason", limits),
            .tracking_issue = try requireString(obj, "trackingIssue", limits),
        };
        if (skipped.reason.len == 0 or skipped.tracking_issue.len == 0) return error.MissingField;
        try out.append(skipped);
    }
    return out.toOwnedSlice();
}

fn parseSuites(
    allocator: std.mem.Allocator,
    array: std.json.Array,
    allowlist: []const Algorithm,
    seen_cases: *std.StringHashMap(void),
    parsed_cases: *usize,
    decoded_total: *usize,
    limits: Limits,
) ![]Suite {
    var out = std.array_list.Managed(Suite).init(allocator);
    for (array.items) |value| {
        const obj = try expectObject(value);
        try ensureOnlyFields(obj, &.{ "id", "algorithm", "operation", "sourceFile", "groups" });
        const id = try requireId(obj, "id", limits);
        const algorithm = try parseAlgorithm(try requireString(obj, "algorithm", limits));
        if (!algorithmAllowed(algorithm, allowlist)) return error.UnsupportedAlgorithm;
        const operation = try parseOperation(try requireString(obj, "operation", limits));
        validateOperation(algorithm, operation) catch return error.UnsupportedOperation;
        const groups = try parseGroups(
            allocator,
            try requireArray(obj, "groups"),
            algorithm,
            operation,
            seen_cases,
            parsed_cases,
            decoded_total,
            limits,
        );
        try out.append(.{
            .id = id,
            .algorithm = algorithm,
            .operation = operation,
            .source_file = try requireString(obj, "sourceFile", limits),
            .groups = groups,
        });
    }
    return out.toOwnedSlice();
}

fn parseGroups(
    allocator: std.mem.Allocator,
    array: std.json.Array,
    algorithm: Algorithm,
    operation: Operation,
    seen_cases: *std.StringHashMap(void),
    parsed_cases: *usize,
    decoded_total: *usize,
    limits: Limits,
) ![]Group {
    if (array.items.len > limits.max_groups) return error.TooManyGroups;
    var out = std.array_list.Managed(Group).init(allocator);
    for (array.items) |value| {
        const obj = try expectObject(value);
        try ensureOnlyFields(obj, &.{ "id", "upstreamGroupIndex", "cases" });
        try out.append(.{
            .id = try requireId(obj, "id", limits),
            .upstream_group_index = try requireU32(obj, "upstreamGroupIndex"),
            .cases = try parseCases(
                allocator,
                try requireArray(obj, "cases"),
                algorithm,
                operation,
                seen_cases,
                parsed_cases,
                decoded_total,
                limits,
            ),
        });
    }
    return out.toOwnedSlice();
}

fn parseCases(
    allocator: std.mem.Allocator,
    array: std.json.Array,
    algorithm: Algorithm,
    operation: Operation,
    seen_cases: *std.StringHashMap(void),
    parsed_cases: *usize,
    decoded_total: *usize,
    limits: Limits,
) ![]Case {
    if (array.items.len > limits.max_cases) return error.TooManyCases;
    var out = std.array_list.Managed(Case).init(allocator);
    for (array.items) |value| {
        const obj = try expectObject(value);
        switch (operation) {
            .aead_open => try ensureOnlyFields(obj, &.{ "id", "upstreamTcId", "classification", "expected", "comment", "flags", "key", "nonce", "aad", "message", "ciphertext", "tag" }),
            .derive_shared_secret => try ensureOnlyFields(obj, &.{ "id", "upstreamTcId", "classification", "expected", "comment", "flags", "private", "public", "shared" }),
            .verify => try ensureOnlyFields(obj, &.{ "id", "upstreamTcId", "classification", "expected", "comment", "flags", "publicKey", "message", "signature" }),
        }

        const id = try requireId(obj, "id", limits);
        if (seen_cases.contains(id)) return error.DuplicateCaseId;
        if (parsed_cases.* >= limits.max_cases) return error.TooManyCases;
        parsed_cases.* += 1;
        try seen_cases.put(id, {});

        const classification = try parseClassification(try requireString(obj, "classification", limits));
        const expected = try parseExpected(try requireString(obj, "expected", limits));
        try validateExpected(classification, expected);

        var parsed_case = Case{
            .id = id,
            .upstream_tc_id = try requireU32(obj, "upstreamTcId"),
            .classification = classification,
            .expected = expected,
            .comment = try requireComment(obj, "comment", limits),
            .flags = try parseFlags(allocator, try requireArray(obj, "flags"), limits),
        };

        switch (operation) {
            .aead_open => {
                parsed_case.key = try requireHex(allocator, obj, "key", decoded_total, limits);
                parsed_case.nonce = try requireHex(allocator, obj, "nonce", decoded_total, limits);
                parsed_case.aad = try requireHex(allocator, obj, "aad", decoded_total, limits);
                parsed_case.message = try requireHex(allocator, obj, "message", decoded_total, limits);
                parsed_case.ciphertext = try requireHex(allocator, obj, "ciphertext", decoded_total, limits);
                parsed_case.tag = try requireHex(allocator, obj, "tag", decoded_total, limits);
                if (algorithm.aead() == null) return error.UnsupportedOperation;
            },
            .derive_shared_secret => {
                parsed_case.private_key = try requireHex(allocator, obj, "private", decoded_total, limits);
                parsed_case.public_key = try requireHex(allocator, obj, "public", decoded_total, limits);
                parsed_case.shared = try requireHex(allocator, obj, "shared", decoded_total, limits);
                if (algorithm == .x25519) {
                    if (parsed_case.private_key.len != provider.Group.x25519.sharedSecretLength()) return error.InvalidCorpus;
                    if (parsed_case.public_key.len != provider.Group.x25519.publicKeyLength()) return error.InvalidCorpus;
                    if (parsed_case.shared.len != provider.Group.x25519.sharedSecretLength()) return error.InvalidCorpus;
                }
            },
            .verify => {
                parsed_case.public_key = try requireHex(allocator, obj, "publicKey", decoded_total, limits);
                parsed_case.message = try requireHex(allocator, obj, "message", decoded_total, limits);
                parsed_case.signature = try requireHex(allocator, obj, "signature", decoded_total, limits);
            },
        }
        try out.append(parsed_case);
    }
    return out.toOwnedSlice();
}

fn runCorpus(corpus: *const Corpus) !Report {
    const cp = cryptoProvider();
    var report = Report{ .skipped_suites = corpus.skipped_suites.len };

    for (corpus.suites) |suite| {
        var suite_cases: usize = 0;
        for (suite.groups) |group| {
            for (group.cases) |case| {
                try executeCase(cp, suite, group, case);
                suite_cases += 1;
                report.executed_cases += 1;
                switch (case.classification) {
                    .valid => report.valid += 1,
                    .invalid => report.invalid += 1,
                    .acceptable => report.acceptable += 1,
                }
            }
        }
        if (suite_cases == 0) return error.EmptySuite;
        report.executed_suites += 1;
    }

    try validateManifestCoverage(corpus, report);
    return report;
}

fn executeCase(cp: provider.CryptoProvider, suite: Suite, group: Group, case: Case) !void {
    const observed = switch (suite.operation) {
        .aead_open => try executeAeadOpen(cp, suite.algorithm.aead().?, case),
        .derive_shared_secret => try executeX25519(cp, case),
        .verify => try executeEd25519Verify(cp, case),
    };
    if (observed != expectedObserved(case.expected)) {
        std.debug.print(
            "crypto corpus mismatch file={s} group={s} case={s} upstreamTcId={d} algorithm={s} classification={s} expected={s} observed={s}\n",
            .{
                corpus_file,
                group.id,
                case.id,
                case.upstream_tc_id,
                suite.algorithm.name(),
                @tagName(case.classification),
                case.expected.name(),
                observed.name(),
            },
        );
        return error.CorpusCaseMismatch;
    }
}

fn executeAeadOpen(cp: provider.CryptoProvider, aead: provider.Aead, case: Case) !Observed {
    const plaintext = try testing.allocator.alloc(u8, case.ciphertext.len);
    defer testing.allocator.free(plaintext);
    cp.aeadOpen(aead, case.key, case.nonce, case.aad, case.ciphertext, case.tag, plaintext) catch |err| {
        return try observedFromError(err);
    };
    if (!std.mem.eql(u8, plaintext, case.message)) return .output_mismatch;
    return .success;
}

fn executeX25519(cp: provider.CryptoProvider, case: Case) !Observed {
    const shared_len = provider.Group.x25519.sharedSecretLength();
    if (case.shared.len != shared_len) return error.InvalidCorpus;
    var out: [provider.max_shared_secret_len]u8 = undefined;
    cp.deriveSharedSecret(.x25519, case.private_key, case.public_key, out[0..shared_len]) catch |err| {
        return try observedFromError(err);
    };
    if (!std.mem.eql(u8, out[0..shared_len], case.shared)) return .output_mismatch;
    return .success;
}

fn executeEd25519Verify(cp: provider.CryptoProvider, case: Case) !Observed {
    cp.verify(.ed25519, case.public_key, case.message, case.signature) catch |err| {
        return try observedFromError(err);
    };
    return .success;
}

fn observedFromError(err: anyerror) !Observed {
    return switch (err) {
        error.AuthenticationFailed => .authentication_failed,
        error.InvalidInput => .invalid_input,
        else => err,
    };
}

fn expectedObserved(expected: Expected) Observed {
    return switch (expected) {
        .success => .success,
        .authentication_failed => .authentication_failed,
        .invalid_input => .invalid_input,
    };
}

fn validateManifestCoverage(corpus: *const Corpus, report: Report) !void {
    try testing.expectEqual(corpus_manifest.suites.len, report.executed_suites);
    try testing.expectEqual(corpus_manifest.skipped_suites.len, report.skipped_suites);
    for (corpus_manifest.suites) |expected_suite| {
        var matched = false;
        for (corpus.suites) |actual_suite| {
            if (!std.mem.eql(u8, expected_suite.id, actual_suite.id)) continue;
            matched = true;
            try testing.expectEqual(expected_suite.case_count, countCases(actual_suite));
            try testing.expectEqualStrings(expected_suite.source_file, actual_suite.source_file);
            try testing.expect(std.meta.eql(expected_suite.algorithm, profileAlgorithm(actual_suite.algorithm)));
        }
        if (!matched) return error.UnexecutedRegisteredSuite;
    }
    for (corpus_manifest.skipped_suites) |expected_skip| {
        var matched = false;
        for (corpus.skipped_suites) |actual_skip| {
            if (std.mem.eql(u8, expected_skip.algorithm, actual_skip.algorithm)) {
                matched = true;
                try testing.expect(actual_skip.reason.len > 0);
                try testing.expectEqualStrings(expected_skip.tracking_issue, actual_skip.tracking_issue);
            }
        }
        if (!matched) return error.MissingSkippedSuite;
    }
}

fn profileAlgorithm(algorithm: Algorithm) profile.Algorithm {
    return switch (algorithm) {
        .aes_128_gcm => .{ .aead = .aes_128_gcm },
        .aes_256_gcm => .{ .aead = .aes_256_gcm },
        .chacha20_poly1305 => .{ .aead = .chacha20_poly1305 },
        .x25519 => .{ .group = .x25519 },
        .ed25519 => .{ .signature = .ed25519 },
    };
}

fn countCases(suite: Suite) usize {
    var total: usize = 0;
    for (suite.groups) |group| total += group.cases.len;
    return total;
}

fn parseAlgorithm(raw: []const u8) !Algorithm {
    if (std.mem.eql(u8, raw, "AES-128-GCM")) return .aes_128_gcm;
    if (std.mem.eql(u8, raw, "AES-256-GCM")) return .aes_256_gcm;
    if (std.mem.eql(u8, raw, "CHACHA20-POLY1305")) return .chacha20_poly1305;
    if (std.mem.eql(u8, raw, "X25519")) return .x25519;
    if (std.mem.eql(u8, raw, "ED25519")) return .ed25519;
    return error.UnsupportedAlgorithm;
}

fn parseOperation(raw: []const u8) !Operation {
    if (std.mem.eql(u8, raw, "aead-open")) return .aead_open;
    if (std.mem.eql(u8, raw, "derive-shared-secret")) return .derive_shared_secret;
    if (std.mem.eql(u8, raw, "verify")) return .verify;
    return error.UnsupportedOperation;
}

fn validateOperation(algorithm: Algorithm, operation: Operation) !void {
    switch (algorithm) {
        .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305 => if (operation != .aead_open) return error.UnsupportedOperation,
        .x25519 => if (operation != .derive_shared_secret) return error.UnsupportedOperation,
        .ed25519 => if (operation != .verify) return error.UnsupportedOperation,
    }
}

fn parseClassification(raw: []const u8) !Classification {
    if (std.mem.eql(u8, raw, "valid")) return .valid;
    if (std.mem.eql(u8, raw, "invalid")) return .invalid;
    if (std.mem.eql(u8, raw, "acceptable")) return .acceptable;
    return error.UnknownClassification;
}

fn parseExpected(raw: []const u8) !Expected {
    if (std.mem.eql(u8, raw, "success")) return .success;
    if (std.mem.eql(u8, raw, "authentication-failed")) return .authentication_failed;
    if (std.mem.eql(u8, raw, "invalid-input")) return .invalid_input;
    return error.UnknownExpectedOutcome;
}

fn validateExpected(classification: Classification, expected: Expected) !void {
    switch (classification) {
        .valid => if (expected != .success) return error.InvalidExpectedOutcome,
        .invalid => if (expected == .success) return error.InvalidExpectedOutcome,
        .acceptable => {},
    }
}

fn algorithmAllowed(algorithm: Algorithm, allowlist: []const Algorithm) bool {
    for (allowlist) |allowed| {
        if (allowed == algorithm) return true;
    }
    return false;
}

fn requireHex(
    allocator: std.mem.Allocator,
    obj: std.json.ObjectMap,
    key: []const u8,
    decoded_total: *usize,
    limits: Limits,
) ![]const u8 {
    const raw = try requireString(obj, key, limits);
    if (raw.len > limits.max_encoded_field_len) return error.OversizedValue;
    if (raw.len % 2 != 0) return error.MalformedHex;
    const decoded_len = raw.len / 2;
    if (decoded_total.* + decoded_len > limits.max_decoded_total) return error.DecodedByteLimitExceeded;
    const out = try allocator.alloc(u8, decoded_len);
    _ = std.fmt.hexToBytes(out, raw) catch return error.MalformedHex;
    decoded_total.* += decoded_len;
    return out;
}

fn parseFlags(allocator: std.mem.Allocator, array: std.json.Array, limits: Limits) ![]const []const u8 {
    if (array.items.len > limits.max_flags) return error.TooManyFlags;
    var out = std.array_list.Managed([]const u8).init(allocator);
    for (array.items) |value| {
        try out.append(try expectIdString(value, limits));
    }
    return out.toOwnedSlice();
}

fn requireObject(obj: std.json.ObjectMap, key: []const u8) !std.json.ObjectMap {
    const value = obj.get(key) orelse return error.MissingField;
    return expectObject(value);
}

fn requireArray(obj: std.json.ObjectMap, key: []const u8) !std.json.Array {
    const value = obj.get(key) orelse return error.MissingField;
    return expectArray(value);
}

fn requireString(obj: std.json.ObjectMap, key: []const u8, limits: Limits) ![]const u8 {
    const value = obj.get(key) orelse return error.MissingField;
    return expectString(value, limits);
}

fn requireId(obj: std.json.ObjectMap, key: []const u8, limits: Limits) ![]const u8 {
    const value = obj.get(key) orelse return error.MissingField;
    return expectIdString(value, limits);
}

fn requireComment(obj: std.json.ObjectMap, key: []const u8, limits: Limits) ![]const u8 {
    const value = obj.get(key) orelse return error.MissingField;
    const raw = try expectString(value, limits);
    if (raw.len > limits.max_comment_len) return error.OversizedValue;
    return raw;
}

fn requireU32(obj: std.json.ObjectMap, key: []const u8) !u32 {
    const value = obj.get(key) orelse return error.MissingField;
    return switch (value) {
        .integer => |int| if (int >= 0 and int <= std.math.maxInt(u32)) @intCast(int) else error.OversizedValue,
        else => error.TypeMismatch,
    };
}

fn expectObject(value: std.json.Value) !std.json.ObjectMap {
    return switch (value) {
        .object => |object| object,
        else => error.TypeMismatch,
    };
}

fn expectArray(value: std.json.Value) !std.json.Array {
    return switch (value) {
        .array => |array| array,
        else => error.TypeMismatch,
    };
}

fn expectString(value: std.json.Value, limits: Limits) ![]const u8 {
    return switch (value) {
        .string => |string| {
            if (string.len > limits.max_encoded_field_len) return error.OversizedValue;
            return string;
        },
        else => error.TypeMismatch,
    };
}

fn expectIdString(value: std.json.Value, limits: Limits) ![]const u8 {
    const raw = try expectString(value, limits);
    if (raw.len == 0 or raw.len > limits.max_identifier_len) return error.OversizedValue;
    return raw;
}

fn ensureOnlyFields(obj: std.json.ObjectMap, comptime allowed: []const []const u8) !void {
    var iterator = obj.iterator();
    while (iterator.next()) |entry| {
        inline for (allowed) |field| {
            if (std.mem.eql(u8, entry.key_ptr.*, field)) break;
        } else {
            return error.UnknownField;
        }
    }
}

fn maxJsonDepth(input: []const u8) usize {
    var in_string = false;
    var escaped = false;
    var depth: usize = 0;
    var max_depth: usize = 0;
    for (input) |byte| {
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (byte == '\\') {
                escaped = true;
            } else if (byte == '"') {
                in_string = false;
            }
            continue;
        }
        switch (byte) {
            '"' => in_string = true,
            '{', '[' => {
                depth += 1;
                max_depth = @max(max_depth, depth);
            },
            '}', ']' => depth -|= 1,
            else => {},
        }
    }
    return max_depth;
}

test "crypto corpus parser accepts checked-in corpus" {
    var corpus = try parseCorpus(testing.allocator, corpus_bytes, .{});
    defer corpus.deinit();
    try testing.expectEqual(@as(usize, 5), corpus.suites.len);
    try testing.expectEqual(@as(usize, 3), corpus.skipped_suites.len);
}

test "crypto corpus parser rejects bounded failure paths" {
    try testing.expectError(error.FileTooLarge, parseCorpus(testing.allocator, "{}", .{ .max_file_size = 1 }));
    try testing.expectError(error.NestingDepthExceeded, parseCorpus(testing.allocator, "[[[[]]]]", .{ .max_depth = 2 }));
    try testing.expectError(error.UnsupportedSchema, parseCorpus(testing.allocator, minimalCorpus(.schema_bad), .{}));
    try testing.expectError(error.MissingField, parseCorpus(testing.allocator, minimalCorpus(.missing_required), .{}));
    try testing.expectError(error.UnsupportedAlgorithm, parseCorpus(testing.allocator, minimalCorpus(.unknown_algorithm), .{}));
    try testing.expectError(error.UnknownClassification, parseCorpus(testing.allocator, minimalCorpus(.unknown_classification), .{}));
    try testing.expectError(error.MalformedHex, parseCorpus(testing.allocator, minimalCorpus(.malformed_hex), .{}));
    try testing.expectError(error.OversizedValue, parseCorpus(testing.allocator, minimalCorpus(.oversized_id), .{}));
    try testing.expectError(error.DuplicateCaseId, parseCorpus(testing.allocator, minimalCorpus(.duplicate_case_id), .{}));
    try testing.expectError(error.UnknownField, parseCorpus(testing.allocator, minimalCorpus(.unknown_field), .{}));
    try testing.expectError(error.TooManyCases, parseCorpus(testing.allocator, twoGroupCorpus(), .{ .max_cases = 1 }));
    try testing.expectError(error.UnsupportedCapability, observedFromError(error.UnsupportedCapability));
    try testing.expectError(error.InvalidCorpus, parseCorpus(testing.allocator, x25519ShortSharedCorpus(), .{}));
}

test "crypto corpus executes through provider and registered manifest" {
    var corpus = try parseCorpus(testing.allocator, corpus_bytes, .{});
    defer corpus.deinit();
    const report = try runCorpus(&corpus);
    try testing.expectEqual(@as(usize, 5), report.executed_suites);
    try testing.expectEqual(@as(usize, 11), report.executed_cases);
    try testing.expectEqual(@as(usize, 5), report.valid);
    try testing.expectEqual(@as(usize, 5), report.invalid);
    try testing.expectEqual(@as(usize, 1), report.acceptable);
    try testing.expectEqual(@as(usize, 3), report.skipped_suites);
}

test "crypto corpus validates classification policy" {
    try validateExpected(.valid, .success);
    try testing.expectError(error.InvalidExpectedOutcome, validateExpected(.valid, .authentication_failed));
    try testing.expectError(error.InvalidExpectedOutcome, validateExpected(.valid, .invalid_input));

    try testing.expectError(error.InvalidExpectedOutcome, validateExpected(.invalid, .success));
    try validateExpected(.invalid, .authentication_failed);
    try validateExpected(.invalid, .invalid_input);

    try validateExpected(.acceptable, .success);
    try validateExpected(.acceptable, .authentication_failed);
    try validateExpected(.acceptable, .invalid_input);
}

test "crypto corpus runner rejects provider success with mismatched AEAD output" {
    const key = [_]u8{0} ** provider.Aead.aes_128_gcm.keyLength();
    const nonce = [_]u8{0} ** provider.aead_nonce_len;
    const ciphertext = [_]u8{0};
    const message = [_]u8{0};
    const tag = [_]u8{0} ** provider.aead_tag_len;
    const case = Case{
        .id = "fake-case",
        .upstream_tc_id = 1,
        .classification = .invalid,
        .expected = .authentication_failed,
        .comment = "",
        .flags = &.{},
        .key = &key,
        .nonce = &nonce,
        .message = &message,
        .ciphertext = &ciphertext,
        .tag = &tag,
    };
    const observed = try executeAeadOpen(BadAeadProvider.cryptoProvider(), .aes_128_gcm, case);
    try testing.expectEqual(Observed.output_mismatch, observed);
    try testing.expect(observed != expectedObserved(case.expected));
}

const MinimalKind = enum {
    schema_bad,
    missing_required,
    unknown_algorithm,
    unknown_classification,
    malformed_hex,
    oversized_id,
    duplicate_case_id,
    unknown_field,
};

fn minimalCorpus(comptime kind: MinimalKind) []const u8 {
    const case_id = switch (kind) {
        .oversized_id => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        else => "case-1",
    };
    const classification = if (kind == .unknown_classification) "legacy" else "valid";
    const key_hex = if (kind == .malformed_hex) "0" else "00000000000000000000000000000000";
    const algorithm = if (kind == .unknown_algorithm) "AES-192-GCM" else "AES-128-GCM";
    const schema = if (kind == .schema_bad) "bad-schema" else schema_version;
    const second_case = if (kind == .duplicate_case_id)
        \\,{
        \\  "id": "case-1",
        \\  "upstreamTcId": 2,
        \\  "classification": "valid",
        \\  "expected": "success",
        \\  "comment": "",
        \\  "flags": [],
        \\  "key": "00000000000000000000000000000000",
        \\  "nonce": "000000000000000000000000",
        \\  "aad": "",
        \\  "message": "",
        \\  "ciphertext": "",
        \\  "tag": "00000000000000000000000000000000"
        \\}
    else
        "";
    const source = if (kind == .missing_required)
        "\"source\": {\"name\": \"x\"},"
    else
        "\"source\": {\"name\": \"x\", \"repository\": \"x\", \"commit\": \"x\", \"license\": \"x\", \"reducedBy\": \"x\"},";
    const extra = if (kind == .unknown_field) ", \"mode\": \"extra\"" else "";
    return std.fmt.comptimePrint(
        \\{{
        \\  "schema": "{s}",
        \\  {s}
        \\  "allowlist": ["AES-128-GCM"],
        \\  "skippedSuites": [],
        \\  "suites": [{{
        \\    "id": "suite-1",
        \\    "algorithm": "{s}",
        \\    "operation": "aead-open",
        \\    "sourceFile": "source.json",
        \\    "groups": [{{
        \\      "id": "group-1",
        \\      "upstreamGroupIndex": 0,
        \\      "cases": [{{
        \\        "id": "{s}",
        \\        "upstreamTcId": 1,
        \\        "classification": "{s}",
        \\        "expected": "success",
        \\        "comment": "",
        \\        "flags": [],
        \\        "key": "{s}",
        \\        "nonce": "000000000000000000000000",
        \\        "aad": "",
        \\        "message": "",
        \\        "ciphertext": "",
        \\        "tag": "00000000000000000000000000000000"{s}
        \\      }}{s}]
        \\    }}]
        \\  }}]
        \\}}
    , .{ schema, source, algorithm, case_id, classification, key_hex, extra, second_case });
}

fn twoGroupCorpus() []const u8 {
    return std.fmt.comptimePrint(
        \\{{
        \\  "schema": "{s}",
        \\  "source": {{"name": "x", "repository": "x", "commit": "x", "license": "x", "reducedBy": "x"}},
        \\  "allowlist": ["AES-128-GCM"],
        \\  "skippedSuites": [],
        \\  "suites": [{{
        \\    "id": "suite-1",
        \\    "algorithm": "AES-128-GCM",
        \\    "operation": "aead-open",
        \\    "sourceFile": "source.json",
        \\    "groups": [
        \\      {{
        \\        "id": "group-1",
        \\        "upstreamGroupIndex": 0,
        \\        "cases": [{{
        \\          "id": "case-1",
        \\          "upstreamTcId": 1,
        \\          "classification": "valid",
        \\          "expected": "success",
        \\          "comment": "",
        \\          "flags": [],
        \\          "key": "00000000000000000000000000000000",
        \\          "nonce": "000000000000000000000000",
        \\          "aad": "",
        \\          "message": "",
        \\          "ciphertext": "",
        \\          "tag": "00000000000000000000000000000000"
        \\        }}]
        \\      }},
        \\      {{
        \\        "id": "group-2",
        \\        "upstreamGroupIndex": 1,
        \\        "cases": [{{
        \\          "id": "case-2",
        \\          "upstreamTcId": 2,
        \\          "classification": "valid",
        \\          "expected": "success",
        \\          "comment": "",
        \\          "flags": [],
        \\          "key": "00000000000000000000000000000000",
        \\          "nonce": "000000000000000000000000",
        \\          "aad": "",
        \\          "message": "",
        \\          "ciphertext": "",
        \\          "tag": "00000000000000000000000000000000"
        \\        }}]
        \\      }}
        \\    ]
        \\  }}]
        \\}}
    , .{schema_version});
}

fn x25519ShortSharedCorpus() []const u8 {
    return std.fmt.comptimePrint(
        \\{{
        \\  "schema": "{s}",
        \\  "source": {{"name": "x", "repository": "x", "commit": "x", "license": "x", "reducedBy": "x"}},
        \\  "allowlist": ["X25519"],
        \\  "skippedSuites": [],
        \\  "suites": [{{
        \\    "id": "suite-1",
        \\    "algorithm": "X25519",
        \\    "operation": "derive-shared-secret",
        \\    "sourceFile": "source.json",
        \\    "groups": [{{
        \\      "id": "group-1",
        \\      "upstreamGroupIndex": 0,
        \\      "cases": [{{
        \\        "id": "x25519-short-shared",
        \\        "upstreamTcId": 1,
        \\        "classification": "valid",
        \\        "expected": "success",
        \\        "comment": "",
        \\        "flags": [],
        \\        "private": "c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475",
        \\        "public": "504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829",
        \\        "shared": ""
        \\      }}]
        \\    }}]
        \\  }}]
        \\}}
    , .{schema_version});
}

const BadAeadProvider = struct {
    var context: u8 = 0;
    var entropy_context: u8 = 0;

    const vtable = provider.CryptoProvider.VTable{
        .capabilities = capabilities,
        .hkdfExtract = hkdfExtract,
        .hkdfExpandLabel = hkdfExpandLabel,
        .aeadSeal = aeadSeal,
        .aeadOpen = aeadOpen,
        .generateKeyShare = generateKeyShare,
        .deriveSharedSecret = deriveSharedSecret,
        .verify = verify,
    };

    fn cryptoProvider() provider.CryptoProvider {
        return .{
            .context = &context,
            .vtable = &vtable,
            .entropy = .{ .context = &entropy_context, .fillFn = fillEntropy },
        };
    }

    fn capabilities(ctx: *anyopaque) provider.Capabilities {
        _ = ctx;
        var caps = provider.Capabilities{};
        caps.aeads.insert(.aes_128_gcm);
        return caps;
    }

    fn hkdfExtract(ctx: *anyopaque, hash: provider.Hash, salt: []const u8, ikm: []const u8, out: []u8) provider.HkdfError!void {
        _ = ctx;
        _ = hash;
        _ = salt;
        _ = ikm;
        _ = out;
        return error.UnsupportedCapability;
    }

    fn hkdfExpandLabel(ctx: *anyopaque, hash: provider.Hash, secret: []const u8, label: []const u8, hash_context: []const u8, out: []u8) provider.HkdfError!void {
        _ = ctx;
        _ = hash;
        _ = secret;
        _ = label;
        _ = hash_context;
        _ = out;
        return error.UnsupportedCapability;
    }

    fn aeadSeal(ctx: *anyopaque, aead: provider.Aead, key: []const u8, nonce: []const u8, aad: []const u8, plaintext: []const u8, ciphertext: []u8, tag: []u8) provider.SealError!void {
        _ = ctx;
        _ = aead;
        _ = key;
        _ = nonce;
        _ = aad;
        _ = plaintext;
        _ = ciphertext;
        _ = tag;
        return error.UnsupportedCapability;
    }

    fn aeadOpen(ctx: *anyopaque, aead: provider.Aead, key: []const u8, nonce: []const u8, aad: []const u8, ciphertext: []const u8, tag: []const u8, plaintext: []u8) provider.OpenError!void {
        _ = ctx;
        _ = aead;
        _ = key;
        _ = nonce;
        _ = aad;
        _ = ciphertext;
        _ = tag;
        @memset(plaintext, 0x42);
    }

    fn generateKeyShare(ctx: *anyopaque, group: provider.Group, public_out: []u8, private_out: []u8) provider.KeyShareError!void {
        _ = ctx;
        _ = group;
        _ = public_out;
        _ = private_out;
        return error.UnsupportedCapability;
    }

    fn deriveSharedSecret(ctx: *anyopaque, group: provider.Group, private_scalar: []const u8, peer_public: []const u8, out: []u8) provider.DeriveError!void {
        _ = ctx;
        _ = group;
        _ = private_scalar;
        _ = peer_public;
        _ = out;
        return error.UnsupportedCapability;
    }

    fn verify(ctx: *anyopaque, scheme: provider.SignatureScheme, public_key: []const u8, message: []const u8, signature: []const u8) provider.VerifyError!void {
        _ = ctx;
        _ = scheme;
        _ = public_key;
        _ = message;
        _ = signature;
        return error.UnsupportedCapability;
    }

    fn fillEntropy(ctx: *anyopaque, buffer: []u8) provider.EntropyError!void {
        _ = ctx;
        @memset(buffer, 0);
    }
};
