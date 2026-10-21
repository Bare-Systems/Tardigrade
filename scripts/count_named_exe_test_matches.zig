//! #944: the zero-match guard for `-Dexe-test-filter=<substring>` /
//! `test-exe-filtered` (see `build.zig` and CONTRIBUTING.md's "Test
//! performance" section).
//!
//! This file is used two ways from `build.zig`:
//!
//!   1. As an ordinary test subject (`b.addTest(.{ .root_module = ... })`):
//!      exercises `isNamedTest` below against fixture names under the
//!      normal `test`/`test-fast` targets.
//!   2. As a `--test-runner` replacement
//!      (`.test_runner = .{ .path = ..., .mode = .simple }`), compiled
//!      *as part of the real `exe_test_mod` compilation with the requested
//!      `-Dexe-test-filter`*. In that role, `main` below becomes the test
//!      binary's actual entry point, and `builtin.test_functions` is the
//!      compiler's own post-filter, post-comptime-resolution test inventory
//!      for that exact compilation -- not a re-derived approximation of it.
//!
//! An earlier version of this guard walked `@import` strings and
//! `test "..."` declarations in source text to approximate which tests a
//! given filter would reach. That approach could not distinguish a named
//! test excluded by `comptime` conditional compilation (e.g. a
//! Windows-only test file never reached when building for Linux) from one
//! actually compiled, so a filter naming only such a test produced exactly
//! the false-green #944 forbids: zero tests actually selected, yet the
//! guard reported a match. Querying the compiler's own post-filter test
//! inventory instead of re-deriving it from source text closes that gap by
//! construction, not by approximation.
//!
//! Zig names a `test "<name>"` declaration `<module>.test.<name>` and an
//! unnamed `test { ... }` block (`src/main.zig`'s own `refAllDecls` smoke
//! test, which always runs and always reports success regardless of any
//! filter) `<module>.test_<index>`. The literal `.test.` substring is how
//! the compiler encodes "this test had a name", and is what distinguishes a
//! real named-filter match from the always-present unnamed smoke test.

const std = @import("std");
const builtin = @import("builtin");

fn isNamedTest(name: []const u8) bool {
    return std.mem.indexOf(u8, name, ".test.") != null;
}

pub fn main() void {
    var named_count: usize = 0;
    for (builtin.test_functions) |test_fn| {
        if (isNamedTest(test_fn.name)) named_count += 1;
    }
    if (named_count == 0) {
        std.debug.print(
            "-Dexe-test-filter matches no named test in the compiled test inventory: false-green is unacceptable for test-exe-filtered, failing instead of silently passing the always-present unnamed smoke test. Pick an existing test name/substring (see `zig build test --summary all` output) or update this filter after a rename.\n",
            .{},
        );
        std.process.exit(1);
    }
}

const testing = std.testing;

test "isNamedTest recognizes a named test's compiler-generated identifier" {
    try testing.expect(isNamedTest("main.test.jwt round trip"));
}

test "isNamedTest rejects an unnamed test block's compiler-generated identifier" {
    try testing.expect(!isNamedTest("main.test_0"));
    try testing.expect(!isNamedTest("main.test_12"));
}
