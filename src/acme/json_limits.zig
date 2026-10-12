//! Bounded JSON admission for untrusted ACME input (#832, design §9.1).
//!
//! `validate` makes one non-allocating-in-the-data pass over the document with
//! `std.json.Scanner` and rejects it before any typed parse if it exceeds the
//! byte, depth, string, array or object-key limits. Typed parsing
//! (`parseBounded`) always runs after `validate`, so a hostile CA or a
//! corrupted state file cannot make the parser allocate proportionally to an
//! attacker-chosen shape.

const std = @import("std");

pub const Limits = struct {
    max_bytes: usize = 64 * 1024,
    max_depth: usize = 8,
    max_string: usize = 2048,
    max_array: usize = 128,
    max_keys: usize = 64,
};

pub const Error = error{
    Malformed,
    TooLarge,
    TooDeep,
    StringTooLong,
    ArrayTooLarge,
    TooManyKeys,
};

const Frame = struct {
    is_object: bool,
    expecting_key: bool = true,
    count: usize = 0,
};

pub fn validate(bytes: []const u8, limits: Limits) Error!void {
    if (bytes.len > limits.max_bytes) return error.TooLarge;
    if (limits.max_depth > 32) return error.TooDeep;

    // The scanner's container stack is a bit stack; one byte per eight levels.
    var scratch: [256]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&scratch);
    var scanner = std.json.Scanner.initCompleteInput(fba.allocator(), bytes);
    defer scanner.deinit();

    var frames: [32]Frame = undefined;
    var depth: usize = 0;
    var string_len: usize = 0;
    var saw_value = false;

    while (true) {
        const token = scanner.next() catch |err| switch (err) {
            error.OutOfMemory => return error.TooDeep,
            else => return error.Malformed,
        };
        switch (token) {
            .end_of_document => break,
            .object_begin, .array_begin => {
                if (depth >= limits.max_depth) return error.TooDeep;
                frames[depth] = .{ .is_object = token == .object_begin };
                depth += 1;
            },
            .object_end, .array_end => {
                depth -= 1;
                try completeValue(frames[0..depth], limits);
            },
            .partial_string => |piece| try addString(&string_len, piece.len, limits),
            .partial_string_escaped_1 => try addString(&string_len, 1, limits),
            .partial_string_escaped_2 => try addString(&string_len, 2, limits),
            .partial_string_escaped_3 => try addString(&string_len, 3, limits),
            .partial_string_escaped_4 => try addString(&string_len, 4, limits),
            .string => |piece| {
                try addString(&string_len, piece.len, limits);
                string_len = 0;
                if (depth > 0 and frames[depth - 1].is_object and frames[depth - 1].expecting_key) {
                    const frame = &frames[depth - 1];
                    frame.count += 1;
                    if (frame.count > limits.max_keys) return error.TooManyKeys;
                    frame.expecting_key = false;
                } else {
                    try completeValue(frames[0..depth], limits);
                }
            },
            .partial_number => {},
            .allocated_number, .allocated_string => return error.Malformed, // only produced by nextAlloc
            .number, .true, .false, .null => try completeValue(frames[0..depth], limits),
        }
        saw_value = true;
    }
    if (!saw_value) return error.Malformed;
}

fn addString(total: *usize, extra: usize, limits: Limits) Error!void {
    total.* += extra;
    if (total.* > limits.max_string) return error.StringTooLong;
}

/// A value just finished inside the innermost open container (if any).
fn completeValue(open: []Frame, limits: Limits) Error!void {
    if (open.len == 0) return;
    const frame = &open[open.len - 1];
    if (frame.is_object) {
        frame.expecting_key = true;
    } else {
        frame.count += 1;
        if (frame.count > limits.max_array) return error.ArrayTooLarge;
    }
}

/// Validate, then parse into `T`, ignoring unknown fields (RFC 8555 lets the
/// CA add members at will). Caller owns the result and must `deinit` it.
pub fn parseBounded(comptime T: type, allocator: std.mem.Allocator, bytes: []const u8, limits: Limits) !std.json.Parsed(T) {
    try validate(bytes, limits);
    return std.json.parseFromSlice(T, allocator, bytes, .{ .ignore_unknown_fields = true, .allocate = .alloc_always });
}

// ---------------------------------------------------------------------------

const testing = std.testing;

test "ACME json limits: accepts ordinary documents" {
    try validate("{}", .{});
    try validate("[]", .{});
    try validate("{\"a\":[1,2,{\"b\":\"c\"}],\"d\":null,\"e\":true}", .{});
    try validate("{\"s\":\"esc\\n\\u00e9\\\"\"}", .{});
}

test "ACME json limits: rejects malformed documents" {
    for ([_][]const u8{ "", " ", "{", "[1,", "{\"a\":}", "nul", "{\"a\" 1}", "{\"a\":1}x", "\"unterminated" }) |doc| {
        try testing.expectError(error.Malformed, validate(doc, .{}));
    }
}

test "ACME json limits: depth boundary" {
    const limits = Limits{ .max_depth = 3 };
    try validate("[[[]]]", limits);
    try testing.expectError(error.TooDeep, validate("[[[[]]]]", limits));
    try testing.expectError(error.TooDeep, validate("{\"a\":{\"a\":{\"a\":{}}}}", limits));
    // An absurd nesting must fail on depth, not exhaust memory.
    const deep = "[" ** 5000;
    try testing.expectError(error.TooDeep, validate(deep, .{ .max_bytes = 8192 }));
}

test "ACME json limits: string, array, key and byte boundaries" {
    const limits = Limits{ .max_string = 4, .max_array = 3, .max_keys = 2, .max_bytes = 64 };
    try validate("\"abcd\"", limits);
    try testing.expectError(error.StringTooLong, validate("\"abcde\"", limits));
    try testing.expectError(error.StringTooLong, validate("{\"abcde\":1}", limits));
    // Escapes count toward the cap too.
    try testing.expectError(error.StringTooLong, validate("\"\\n\\n\\n\\n\\n\"", limits));

    try validate("[1,2,3]", limits);
    try testing.expectError(error.ArrayTooLarge, validate("[1,2,3,4]", limits));
    try testing.expectError(error.ArrayTooLarge, validate("[[],[],[],[]]", limits));

    try validate("{\"a\":1,\"b\":2}", limits);
    try testing.expectError(error.TooManyKeys, validate("{\"a\":1,\"b\":2,\"c\":3}", limits));
    // Keys are counted per object, not globally.
    try validate("{\"a\":{\"a\":1,\"b\":2},\"b\":{\"a\":1,\"b\":2}}", .{ .max_keys = 2 });

    try validate("[" ++ "1," ** 20 ++ "1]", .{ .max_bytes = 64, .max_array = 64 });
    try testing.expectError(error.TooLarge, validate("[" ++ "1," ** 40 ++ "1]", .{ .max_bytes = 64, .max_array = 64 }));
}

test "ACME json limits: bounded typed parse ignores unknown members and rejects duplicates" {
    const T = struct { a: []const u8 };
    const ok = try parseBounded(T, testing.allocator, "{\"a\":\"x\",\"extra\":[1,2]}", .{});
    defer ok.deinit();
    try testing.expectEqualStrings("x", ok.value.a);
    try testing.expectError(error.DuplicateField, parseBounded(T, testing.allocator, "{\"a\":\"x\",\"a\":\"y\"}", .{}));
    try testing.expectError(error.MissingField, parseBounded(T, testing.allocator, "{\"b\":1}", .{}));
    try testing.expectError(error.TooLarge, parseBounded(T, testing.allocator, "{\"a\":\"xxxxxxxxxx\"}", .{ .max_bytes = 8 }));
}

fn fuzzJsonLimits(_: void, smith: *testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len = smith.slice(&buf);
    const limits = Limits{ .max_bytes = 512, .max_depth = 6, .max_string = 32, .max_array = 8, .max_keys = 8 };
    validate(buf[0..len], limits) catch return;
    // Admission is a pre-filter, not a full grammar check (e.g. lone
    // surrogates pass the scanner); the typed parse may still refuse, but it
    // must never crash or leak on anything admitted.
    const parsed = std.json.parseFromSlice(std.json.Value, testing.allocator, buf[0..len], .{}) catch return;
    parsed.deinit();
}

test "fuzz: ACME: bounded JSON admission and typed parse stay leak-free" {
    try testing.fuzz({}, fuzzJsonLimits, .{ .corpus = &.{
        "",
        "{}",
        "[[[[[[[[[[]]]]]]]]]]",
        "{\"a\":[1,2,3],\"b\":{\"c\":\"d\"}}",
        "{\"a\":\"\\ud800\"}",
        "{\"a\":1,\"a\":2}",
        &([_]u8{'['} ** 64),
    } });
}
