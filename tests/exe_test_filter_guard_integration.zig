//! #944: end-to-end regression for the compiled-test-inventory zero-match
//! guard in `scripts/count_named_exe_test_matches.zig`.
//!
//! Proves the exact scenario the #944 review called out: a named test only
//! reachable through an untaken `comptime` conditional-compilation branch
//! must not produce a false-green "matched" result from the guard, the
//! guard must accept a filter that does reach a real named test, and an
//! ordinary failing *selected* named test must still fail the build on its
//! own (independent of the guard). Each case spawns the real `zig`
//! compiler against small fixture files written to a temp directory --
//! `zig test` directly rather than `zig build test-exe-filtered`, so this
//! exercises the exact compiler machinery that step wraps (compilation,
//! `--test-filter`, `--test-runner`) without the recursion and shared-cache
//! hazards of invoking the build system from inside its own test run.
//! `test-exe-filtered` itself has no build.zig hook to point at an
//! out-of-tree fixture root instead of `src/main.zig`, which is why this
//! regression drives the compiler directly.

const std = @import("std");
const compat = @import("zig_compat");
const bounded_process = @import("bounded_process.zig");
const guard_options = @import("exe_test_filter_guard_integration_options");

const testing = std.testing;
const deadline_ms: u32 = 30_000;

fn runZigTest(
    allocator: std.mem.Allocator,
    tmp_dir: std.Io.Dir,
    root_relative: []const u8,
    filter: []const u8,
    test_runner_path: ?[]const u8,
) !bounded_process.Result {
    const root = compat.wrapDir(tmp_dir);
    const root_path = try root.realpathAlloc(allocator, root_relative);
    defer allocator.free(root_path);

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.appendSlice(allocator, &.{
        guard_options.zig_exe_path,
        "test",
        root_path,
        "--test-filter",
        filter,
    });
    if (test_runner_path) |path| {
        try argv.appendSlice(allocator, &.{ "--test-runner", path });
    }

    return bounded_process.run(allocator, .{
        .argv = argv.items,
        .cwd = .{ .dir = tmp_dir },
        .stdout_limit = 8192,
        .stderr_limit = 8192,
        .deadline_ms = deadline_ms,
        .accepted_exit_codes = &.{ 0, 1 },
    });
}

fn expectExitCode(result: bounded_process.Result, expected: u8) !void {
    switch (result.outcome) {
        .normal_exit => |code| try testing.expectEqual(expected, code),
        else => {
            std.debug.print("unexpected outcome: {any}\n", .{result.outcome});
            return error.UnexpectedOutcome;
        },
    }
}

test "guard rejects a filter that only reaches a comptime-unselected branch" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = compat.wrapDir(tmp.dir);

    try root.writeFile(.{ .sub_path = "windows_only.zig", .data =
        \\test "windows_only_nonexistent_on_this_target" {}
    });
    try root.writeFile(.{ .sub_path = "main.zig", .data =
        \\const std = @import("std");
        \\const builtin = @import("builtin");
        \\const unused_platform_tests = if (builtin.target.os.tag == .windows)
        \\    @import("windows_only.zig")
        \\else
        \\    struct {};
        \\test { std.testing.refAllDecls(@This()); }
    });

    var result = try runZigTest(
        allocator,
        tmp.dir,
        "main.zig",
        "windows_only_nonexistent_on_this_target",
        guard_options.count_named_exe_test_matches_path,
    );
    defer result.deinit(allocator);
    try expectExitCode(result, 1);
}

test "guard accepts a filter that reaches a real named test" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = compat.wrapDir(tmp.dir);

    try root.writeFile(.{ .sub_path = "main.zig", .data =
        \\const std = @import("std");
        \\test "selected_branch_reachable_test" {}
        \\test { std.testing.refAllDecls(@This()); }
    });

    var result = try runZigTest(
        allocator,
        tmp.dir,
        "main.zig",
        "selected_branch_reachable_test",
        guard_options.count_named_exe_test_matches_path,
    );
    defer result.deinit(allocator);
    try expectExitCode(result, 0);
}

test "a real failing selected named test still fails the build, independent of the guard" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = compat.wrapDir(tmp.dir);

    try root.writeFile(.{ .sub_path = "main.zig", .data =
        \\const std = @import("std");
        \\test "selected_but_failing_test" {
        \\    try std.testing.expect(false);
        \\}
    });

    var result = try runZigTest(allocator, tmp.dir, "main.zig", "selected_but_failing_test", null);
    defer result.deinit(allocator);
    try expectExitCode(result, 1);
}
