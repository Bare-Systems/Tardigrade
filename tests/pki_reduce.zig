//! Bounded deterministic input reduction for the PKI differential harness
//! (#348).
//!
//! `reduce` is a greedy delta-debugging loop over raw bytes: it repeatedly
//! deletes chunks, keeps a candidate only when the caller's oracle still
//! classifies it as interesting, and halves the chunk size once a sweep stops
//! making progress. The oracle must be deterministic; given the same input and
//! oracle the reducer always returns identical bytes. Work is bounded by
//! `Options.max_oracle_calls`, so a hostile input can never turn minimization
//! into unbounded work — on budget exhaustion the best reduction found so far
//! is returned.

const std = @import("std");

pub const Options = struct {
    /// Hard cap on oracle invocations, including the initial interest check.
    max_oracle_calls: usize = 2048,
};

pub const Error = error{
    OutOfMemory,
    /// The oracle rejected the unmodified input, so there is nothing to
    /// preserve while shrinking.
    UninterestingInput,
};

pub const Outcome = struct {
    /// Reduced bytes. The oracle classified exactly these bytes as
    /// interesting. Caller owns the memory.
    data: []u8,
    /// Oracle invocations consumed, never above `Options.max_oracle_calls`.
    oracle_calls: usize,

    pub fn deinit(self: *Outcome, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
        self.* = undefined;
    }
};

/// Shrink `input` while `oracle(context, candidate)` stays true.
///
/// The oracle must treat every internal classification failure as "not
/// interesting" rather than an error; only allocation failure propagates.
pub fn reduce(
    allocator: std.mem.Allocator,
    input: []const u8,
    context: anytype,
    comptime oracle: fn (ctx: @TypeOf(context), candidate: []const u8) error{OutOfMemory}!bool,
    options: Options,
) Error!Outcome {
    var calls: usize = 0;
    if (options.max_oracle_calls == 0) return error.UninterestingInput;
    calls += 1;
    if (!try oracle(context, input)) return error.UninterestingInput;

    var buffers: [2][]u8 = undefined;
    buffers[0] = try allocator.alloc(u8, input.len);
    errdefer allocator.free(buffers[0]);
    buffers[1] = try allocator.alloc(u8, input.len);
    errdefer allocator.free(buffers[1]);
    @memcpy(buffers[0], input);

    var current: usize = 0;
    var len: usize = input.len;

    var chunk: usize = len / 2;
    if (chunk == 0) chunk = len; // 1-byte inputs still get one deletion try
    budget: while (chunk >= 1) {
        var removed_any = false;
        var start: usize = 0;
        while (start < len) {
            if (calls == options.max_oracle_calls) break :budget;
            const end = @min(start + chunk, len);
            const candidate_len = len - (end - start);
            const scratch = buffers[1 - current];
            @memcpy(scratch[0..start], buffers[current][0..start]);
            @memcpy(scratch[start..candidate_len], buffers[current][end..len]);
            calls += 1;
            if (try oracle(context, scratch[0..candidate_len])) {
                current = 1 - current;
                len = candidate_len;
                removed_any = true;
                // Keep `start` in place: the bytes that slid into this window
                // have not been tried yet.
            } else {
                start = end;
            }
        }
        if (len == 0) break;
        if (!removed_any) {
            if (chunk == 1) break;
            chunk = chunk / 2;
        } else if (chunk > len) {
            chunk = @max(len / 2, 1);
        }
    }

    const data = try allocator.dupe(u8, buffers[current][0..len]);
    allocator.free(buffers[0]);
    allocator.free(buffers[1]);
    return .{ .data = data, .oracle_calls = calls };
}

const testing = std.testing;

const MarkerOracle = struct {
    marker: []const u8,
    calls: usize = 0,

    fn keeps(self: *MarkerOracle, candidate: []const u8) error{OutOfMemory}!bool {
        self.calls += 1;
        return std.mem.indexOf(u8, candidate, self.marker) != null;
    }
};

test "pki reduce: marker oracle converges to the marker" {
    var padded: [512]u8 = undefined;
    for (&padded, 0..) |*byte, index| byte.* = @truncate(index *% 31);
    const marker = "NEEDLE-348";
    @memcpy(padded[201 .. 201 + marker.len], marker);

    var oracle = MarkerOracle{ .marker = marker };
    var outcome = try reduce(testing.allocator, &padded, &oracle, MarkerOracle.keeps, .{});
    defer outcome.deinit(testing.allocator);

    try testing.expectEqualStrings(marker, outcome.data);
    try testing.expect(outcome.oracle_calls <= 2048);
}

test "pki reduce: identical inputs reduce to identical bytes" {
    var padded: [256]u8 = undefined;
    for (&padded, 0..) |*byte, index| byte.* = @truncate(index *% 7);
    const marker = "STABLE";
    @memcpy(padded[64 .. 64 + marker.len], marker);

    var first_oracle = MarkerOracle{ .marker = marker };
    var first = try reduce(testing.allocator, &padded, &first_oracle, MarkerOracle.keeps, .{});
    defer first.deinit(testing.allocator);
    var second_oracle = MarkerOracle{ .marker = marker };
    var second = try reduce(testing.allocator, &padded, &second_oracle, MarkerOracle.keeps, .{});
    defer second.deinit(testing.allocator);

    try testing.expectEqualSlices(u8, first.data, second.data);
    try testing.expectEqual(first.oracle_calls, second.oracle_calls);
}

test "pki reduce: budget exhaustion returns a valid partial reduction" {
    var padded: [128]u8 = undefined;
    @memset(&padded, 0xaa);
    const marker = "BUDGET";
    @memcpy(padded[40 .. 40 + marker.len], marker);

    var oracle = MarkerOracle{ .marker = marker };
    var outcome = try reduce(testing.allocator, &padded, &oracle, MarkerOracle.keeps, .{
        .max_oracle_calls = 5,
    });
    defer outcome.deinit(testing.allocator);

    try testing.expect(outcome.oracle_calls <= 5);
    try testing.expect(outcome.data.len <= padded.len);
    var check = MarkerOracle{ .marker = marker };
    try testing.expect(try check.keeps(outcome.data));
}

test "pki reduce: uninteresting input is rejected up front" {
    var oracle = MarkerOracle{ .marker = "ABSENT" };
    try testing.expectError(
        error.UninterestingInput,
        reduce(testing.allocator, "nothing to see here", &oracle, MarkerOracle.keeps, .{}),
    );
    try testing.expectEqual(@as(usize, 1), oracle.calls);
}

const AlwaysInteresting = struct {
    fn keeps(_: *const AlwaysInteresting, _: []const u8) error{OutOfMemory}!bool {
        return true;
    }
};

test "pki reduce: fully removable input reduces to empty" {
    const oracle = AlwaysInteresting{};
    var outcome = try reduce(testing.allocator, "delete me entirely", &oracle, AlwaysInteresting.keeps, .{});
    defer outcome.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), outcome.data.len);
}

test "pki reduce: empty input stays empty" {
    const oracle = AlwaysInteresting{};
    var outcome = try reduce(testing.allocator, "", &oracle, AlwaysInteresting.keeps, .{});
    defer outcome.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), outcome.data.len);
}
