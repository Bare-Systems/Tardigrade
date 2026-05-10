const std = @import("std");
const compat = @import("zig_compat");
const request_mod = @import("request_mod");

const Expected = union(enum) {
    ok,
    err: request_mod.ParseError,
};

const CorpusCase = struct {
    path: []const u8,
    expected: Expected,
};

const corpus_cases = [_]CorpusCase{
    .{ .path = "tests/corpus/http/request/valid_get.http", .expected = .ok },
    .{ .path = "tests/corpus/http/request/duplicate_content_length.http", .expected = .{ .err = error.ConflictingHeaders } },
    .{ .path = "tests/corpus/http/request/conflicting_transfer_encoding.http", .expected = .{ .err = error.ConflictingHeaders } },
    .{ .path = "tests/corpus/http/request/obs_fold_header.http", .expected = .{ .err = error.InvalidHeader } },
    .{ .path = "tests/corpus/http/request/malformed_chunked.http", .expected = .{ .err = error.InvalidChunkedBody } },
};

fn loadCorpusCase(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const raw = try compat.cwd().readFileAlloc(allocator, path, 64 * 1024);
    errdefer allocator.free(raw);
    if (std.mem.indexOf(u8, raw, "\r\n") != null) return raw;

    var normalized = std.ArrayList(u8).empty;
    errdefer normalized.deinit(allocator);
    for (raw) |byte| {
        if (byte == '\n') {
            try normalized.appendSlice(allocator, "\r\n");
        } else {
            try normalized.append(allocator, byte);
        }
    }
    allocator.free(raw);
    return normalized.toOwnedSlice(allocator);
}

fn assertReplayCase(allocator: std.mem.Allocator, case: CorpusCase) !void {
    const raw = try loadCorpusCase(allocator, case.path);
    defer allocator.free(raw);

    switch (case.expected) {
        .ok => {
            const parsed = try request_mod.Request.parse(allocator, raw, request_mod.DEFAULT_MAX_BODY_SIZE);
            var request = parsed.request;
            defer request.deinit();
        },
        .err => |expected| {
            try std.testing.expectError(expected, request_mod.Request.parse(allocator, raw, request_mod.DEFAULT_MAX_BODY_SIZE));
        },
    }
}

fn assertMutationsDoNotCrash(allocator: std.mem.Allocator, path: []const u8) !void {
    const raw = try loadCorpusCase(allocator, path);
    defer allocator.free(raw);
    if (raw.len == 0) return;

    const mutation_values = [_]u8{ 0x00, '\r', '\n', '\t', '%', ':', '/' };
    const positions = [_]usize{ 0, raw.len / 2, raw.len - 1 };

    for (positions) |pos| {
        for (mutation_values) |value| {
            const mutated = try allocator.dupe(u8, raw);
            defer allocator.free(mutated);
            mutated[pos] = value;

            const parsed = request_mod.Request.parse(allocator, mutated, request_mod.DEFAULT_MAX_BODY_SIZE) catch |err| switch (err) {
                error.InvalidRequestLine,
                error.InvalidMethod,
                error.InvalidUri,
                error.InvalidVersion,
                error.InvalidHeader,
                error.IncompleteHeaders,
                error.HeaderTooLarge,
                error.HeadersTooLarge,
                error.TooManyHeaders,
                error.BodyTooLarge,
                error.InvalidContentLength,
                error.ConflictingHeaders,
                error.InvalidChunkedBody,
                => continue,
                error.OutOfMemory => return err,
            };
            var request = parsed.request;
            request.deinit();
        }
    }
}

test "request parser corpus replay" {
    const allocator = std.testing.allocator;
    for (corpus_cases) |case| {
        try assertReplayCase(allocator, case);
    }
}

test "request parser corpus deterministic mutations do not crash" {
    const allocator = std.testing.allocator;
    for (corpus_cases) |case| {
        try assertMutationsDoNotCrash(allocator, case.path);
    }
}
