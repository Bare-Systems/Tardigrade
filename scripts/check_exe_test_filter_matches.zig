//! #944: a small, dependency-free static check used only by the
//! `-Dexe-test-filter=<substring>` / `test-exe-filtered` build step (see
//! `docs/CI.md` and `CONTRIBUTING.md`'s "Test performance" section).
//!
//! Zig's own `--filters`/`.filters` test selection has no "zero tests
//! matched" failure mode: an unnamed `test { ... }` block (`src/main.zig`'s
//! own `refAllDecls` smoke test, used to force every public declaration to
//! type-check) always runs regardless of the filter string, so a stale or
//! typo'd `-Dexe-test-filter` value still reports "1 pass" and a zero exit
//! code instead of failing -- the exact false-green the #944 acceptance
//! criteria calls out. This tool closes that gap for the one new filterable
//! target `test-exe-filtered` adds: it walks the same relative-`@import`
//! closure the Zig compiler follows from a given root file (stopping at any
//! non-relative/named-module import, e.g. `@import("tls_core")`, exactly
//! where a real module boundary would also stop it), collects every named
//! `test "..."` declaration it finds, and fails if none contain the
//! requested substring.
//!
//! A narrow static approximation, not a semantic replacement for Zig's own
//! test collection: it does not understand `@import` aliasing, conditional
//! compilation, or comptime-generated test names. It does, however, mask out
//! line comments, multiline-string-literal lines, and unrelated string/char
//! literals before scanning (see `maskNonSemanticText`), so a `test "..."`
//! mentioned only in a comment or an embedded string cannot be counted as a
//! real declaration.

const std = @import("std");
const compat = @import("zig_compat");

fn isRelativeImport(path: []const u8) bool {
    return std.mem.endsWith(u8, path, ".zig");
}

fn isIdentChar(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9') or c == '_';
}

/// Returns a copy of `contents` with line comments (`//` to end of line),
/// multiline-string-literal lines (`\\` to end of line), and char literals
/// replaced with spaces, and with every `"`-delimited string literal
/// replaced with spaces *except* the two forms this tool actually needs to
/// read verbatim: an `@import("...")` path argument and a `test "..."`
/// declaration's name argument. This stops a `test "..."` sequence written
/// inside a comment or an unrelated string literal (e.g. a doc fixture, or a
/// deleted test still mentioned in prose) from being mistaken for a real
/// test declaration -- the exact false-green #944 prohibits.
fn maskNonSemanticText(allocator: std.mem.Allocator, contents: []const u8) ![]u8 {
    const out = try allocator.dupe(u8, contents);
    var i: usize = 0;
    while (i < out.len) {
        const c = out[i];
        if (c == '/' and i + 1 < out.len and out[i + 1] == '/') {
            while (i < out.len and out[i] != '\n') : (i += 1) out[i] = ' ';
            continue;
        }
        if (c == '\\' and i + 1 < out.len and out[i + 1] == '\\') {
            while (i < out.len and out[i] != '\n') : (i += 1) out[i] = ' ';
            continue;
        }
        if (c == '\'') {
            i += 1;
            while (i < out.len and out[i] != '\'') : (i += 1) {
                if (out[i] == '\\' and i + 1 < out.len) i += 1;
            }
            if (i < out.len) i += 1;
            continue;
        }
        if (c == '"') {
            var before = i;
            while (before > 0 and (out[before - 1] == ' ' or out[before - 1] == '\t')) before -= 1;
            const preceded_by_paren = before >= 1 and out[before - 1] == '(';

            var is_import_path = false;
            if (preceded_by_paren) {
                const paren_pos = before - 1;
                const needle = "@import";
                if (paren_pos >= needle.len and std.mem.eql(u8, out[paren_pos - needle.len .. paren_pos], needle)) {
                    is_import_path = true;
                }
            }
            var is_test_name = false;
            if (!preceded_by_paren) {
                var word_start = before;
                while (word_start > 0 and isIdentChar(out[word_start - 1])) word_start -= 1;
                if (std.mem.eql(u8, out[word_start..before], "test")) is_test_name = true;
            }

            const start = i;
            i += 1;
            while (i < out.len and out[i] != '"') : (i += 1) {
                if (out[i] == '\\' and i + 1 < out.len) i += 1;
            }
            if (i < out.len) i += 1; // closing quote
            if (!is_import_path and !is_test_name) {
                for (out[start..i]) |*b| b.* = ' ';
            }
            continue;
        }
        i += 1;
    }
    return out;
}

/// Every `@import("<path>")` argument found in `contents`.
fn collectImports(allocator: std.mem.Allocator, contents: []const u8, out: *std.ArrayList([]const u8)) !void {
    const masked = try maskNonSemanticText(allocator, contents);
    defer allocator.free(masked);
    const needle = "@import(\"";
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, masked, i, needle)) |start| {
        const path_start = start + needle.len;
        const end = std.mem.indexOfScalarPos(u8, masked, path_start, '"') orelse break;
        try out.append(allocator, try allocator.dupe(u8, masked[path_start..end]));
        i = end + 1;
    }
}

/// Every named `test "<name>"` declaration's name found in `contents`.
/// Unnamed `test { ... }` blocks are intentionally not collected: they carry
/// no name for a substring filter to match in the first place. Scans
/// `contents` through `maskNonSemanticText` so a `test "..."`-shaped
/// sequence inside a comment or an unrelated string literal is not
/// mistaken for a real declaration.
fn collectTestNames(allocator: std.mem.Allocator, contents: []const u8, out: *std.ArrayList([]const u8)) !void {
    const masked = try maskNonSemanticText(allocator, contents);
    defer allocator.free(masked);
    const needle = "test \"";
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, masked, i, needle)) |start| {
        const name_start = start + needle.len;
        const end = std.mem.indexOfScalarPos(u8, masked, name_start, '"') orelse break;
        try out.append(allocator, try allocator.dupe(u8, masked[name_start..end]));
        i = end + 1;
    }
}

fn containsPath(haystack: []const []const u8, needle: []const u8) bool {
    for (haystack) |candidate| {
        if (std.mem.eql(u8, candidate, needle)) return true;
    }
    return false;
}

/// Joins `dir` and `rel` with `/`, lexically collapsing `.`/`..` components
/// (popping a directory component instead of appending one) rather than via
/// `std.fs.path.join`/`.resolve`, which either leave `..` uncollapsed or
/// assume an absolute base: either way, a `@import("../sibling.zig")` inside
/// an import cycle would otherwise grow the path by one `../` per repeat
/// visit instead of ever re-resolving to an already-visited name, making the
/// walk's own cycle guard ineffective and its allocations unbounded.
fn joinAndNormalize(allocator: std.mem.Allocator, dir: []const u8, rel: []const u8) ![]const u8 {
    var components: std.ArrayList([]const u8) = .empty;
    var dir_it = std.mem.tokenizeScalar(u8, dir, '/');
    while (dir_it.next()) |c| try components.append(allocator, c);
    var rel_it = std.mem.tokenizeScalar(u8, rel, '/');
    while (rel_it.next()) |c| {
        if (std.mem.eql(u8, c, ".")) continue;
        if (std.mem.eql(u8, c, "..")) {
            if (components.items.len > 0) _ = components.pop();
            continue;
        }
        try components.append(allocator, c);
    }
    return std.mem.join(allocator, "/", components.items);
}

/// The number of named test declarations, recursively across every relative
/// `@import` reachable from `root_relative_path`, whose name contains
/// `filter`. A file the walk cannot read (renamed/deleted root, a resolved
/// import path that does not exist) is skipped rather than treated as a hard
/// error: this tool's job is counting plausible matches, not validating the
/// module graph build.zig itself already enforces.
pub fn countMatches(backing_allocator: std.mem.Allocator, root: compat.DirCompat, root_relative_path: []const u8, filter: []const u8) !usize {
    // All of the file-scanning scratch allocations below (resolved import
    // paths, file contents, collected names) share the same short lifetime
    // as this one call, so an arena -- freed in one shot on return -- is a
    // simpler and more obviously leak-free fit than hand-tracking each
    // intermediate buffer's ownership through a recursive worklist walk.
    var arena_state = std.heap.ArenaAllocator.init(backing_allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var visited: std.ArrayList([]const u8) = .empty;
    var worklist: std.ArrayList([]const u8) = .empty;
    try worklist.append(allocator, root_relative_path);

    var match_count: usize = 0;
    while (worklist.pop()) |path| {
        if (containsPath(visited.items, path)) continue;
        try visited.append(allocator, path);

        const contents = root.readFileAlloc(allocator, path, 16 * 1024 * 1024) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };

        var names: std.ArrayList([]const u8) = .empty;
        try collectTestNames(allocator, contents, &names);
        for (names.items) |name| {
            if (std.mem.indexOf(u8, name, filter) != null) match_count += 1;
        }

        var imports: std.ArrayList([]const u8) = .empty;
        try collectImports(allocator, contents, &imports);
        const dir = std.fs.path.dirname(path) orelse "";
        for (imports.items) |import_path| {
            if (!isRelativeImport(import_path)) continue;
            const resolved = try joinAndNormalize(allocator, dir, import_path);
            try worklist.append(allocator, resolved);
        }
    }
    return match_count;
}

pub fn main(init: std.process.Init.Minimal) !void {
    const allocator = std.heap.page_allocator;

    var args_iter = init.args.iterate();
    _ = args_iter.next();
    const root_relative_path = args_iter.next() orelse {
        var stderr_buf: [512]u8 = undefined;
        var stderr = compat.stderrWriter(&stderr_buf);
        try stderr.print("usage: check_exe_test_filter_matches <root-relative-file> <filter-substring>\n", .{});
        std.process.exit(2);
    };
    const filter = args_iter.next() orelse {
        var stderr_buf: [512]u8 = undefined;
        var stderr = compat.stderrWriter(&stderr_buf);
        try stderr.print("usage: check_exe_test_filter_matches <root-relative-file> <filter-substring>\n", .{});
        std.process.exit(2);
    };

    if (std.mem.trim(u8, filter, " \t\r\n").len == 0) {
        var stderr_buf: [512]u8 = undefined;
        var stderr = compat.stderrWriter(&stderr_buf);
        try stderr.print("filter-substring must not be empty: an empty filter matches every named test, defeating the named/fast selection this check exists to enforce\n", .{});
        std.process.exit(2);
    }

    const root = compat.cwd();
    const count = try countMatches(allocator, root, root_relative_path, filter);
    if (count == 0) {
        var stderr_buf: [512]u8 = undefined;
        var stderr = compat.stderrWriter(&stderr_buf);
        try stderr.print(
            "-Dexe-test-filter=\"{s}\" matches no named test reachable from {s}: false-green is unacceptable for test-exe-filtered, failing instead of silently passing the always-present refAllDecls smoke test. Pick an existing test name/substring (see `zig build test --summary all` output) or update this filter after a rename.\n",
            .{ filter, root_relative_path },
        );
        std.process.exit(1);
    }
}

// ---------------------------------------------------------------------------
// Fixture tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "collectTestNames finds every named test and ignores unnamed test blocks" {
    const allocator = testing.allocator;
    var names: std.ArrayList([]const u8) = .empty;
    defer {
        for (names.items) |n| allocator.free(n);
        names.deinit(allocator);
    }
    try collectTestNames(allocator,
        \\test "jwt round trip" {}
        \\test { @import("std").testing.refAllDecls(@This()); }
        \\test "jwt rejects a tampered signature" {}
    , &names);
    try testing.expectEqual(@as(usize, 2), names.items.len);
    try testing.expectEqualStrings("jwt round trip", names.items[0]);
    try testing.expectEqualStrings("jwt rejects a tampered signature", names.items[1]);
}

test "collectImports keeps relative .zig imports and ignores named-module imports" {
    const allocator = testing.allocator;
    var imports: std.ArrayList([]const u8) = .empty;
    defer {
        for (imports.items) |p| allocator.free(p);
        imports.deinit(allocator);
    }
    try collectImports(allocator,
        \\const std = @import("std");
        \\const tls_core = @import("tls_core");
        \\const edge_config = @import("edge_config.zig");
    , &imports);
    var relative = blk: {
        var out: std.ArrayList([]const u8) = .empty;
        for (imports.items) |p| if (isRelativeImport(p)) try out.append(allocator, p);
        break :blk out;
    };
    defer relative.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), relative.items.len);
    try testing.expectEqualStrings("edge_config.zig", relative.items[0]);
}

test "countMatches follows a relative-import chain and finds a match in the imported file" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = compat.wrapDir(tmp.dir);

    try root.writeFile(.{ .sub_path = "main.zig", .data =
        \\const std = @import("std");
        \\const helper = @import("helper.zig");
        \\test "main smoke" {}
    });
    try root.writeFile(.{ .sub_path = "helper.zig", .data =
        \\test "helper does the real work" {}
    });

    try testing.expectEqual(@as(usize, 1), try countMatches(allocator, root, "main.zig", "real work"));
    try testing.expectEqual(@as(usize, 0), try countMatches(allocator, root, "main.zig", "no such test"));
}

test "countMatches does not follow a named-module import or loop on an import cycle" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = compat.wrapDir(tmp.dir);

    try root.writeFile(.{ .sub_path = "main.zig", .data =
        \\const tls_core = @import("tls_core");
        \\const sibling = @import("sibling.zig");
        \\test "main smoke" {}
    });
    try root.writeFile(.{ .sub_path = "sibling.zig", .data =
        \\const back = @import("main.zig");
        \\test "sibling smoke" {}
    });
    try root.writeFile(.{ .sub_path = "tls_core.zig", .data =
        \\test "this must never be reached via a named-module import" {}
    });

    // Finds both real files via the cycle without hanging...
    try testing.expectEqual(@as(usize, 2), try countMatches(allocator, root, "main.zig", "smoke"));
    // ...and never resolves the bare "tls_core" module name to tls_core.zig.
    try testing.expectEqual(@as(usize, 0), try countMatches(allocator, root, "main.zig", "never be reached"));
}

test "countMatches collapses .. in a nested import cycle instead of growing the path forever" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = compat.wrapDir(tmp.dir);

    try root.makePath("sub");
    try root.writeFile(.{ .sub_path = "main.zig", .data =
        \\const nested = @import("sub/nested.zig");
        \\test "main smoke" {}
    });
    // sub/nested.zig importing "../main.zig" must resolve back to "main.zig"
    // (already visited), not grow to "sub/../main.zig", then
    // "sub/../sub/../main.zig", and so on forever around the cycle.
    try root.writeFile(.{ .sub_path = "sub/nested.zig", .data =
        \\const back = @import("../main.zig");
        \\test "nested smoke" {}
    });

    try testing.expectEqual(@as(usize, 2), try countMatches(allocator, root, "main.zig", "smoke"));
}

test "countMatches does not count a test name mentioned only in a line comment" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = compat.wrapDir(tmp.dir);

    // A deleted test still mentioned in a comment, plus the always-present
    // unnamed refAllDecls smoke test Zig's own runner would still pass on.
    try root.writeFile(.{ .sub_path = "main.zig", .data =
        \\// test "removed_cache_regression" {}
        \\test { @import("std").testing.refAllDecls(@This()); }
    });

    try testing.expectEqual(@as(usize, 0), try countMatches(allocator, root, "main.zig", "removed_cache_regression"));
}

test "countMatches does not count a test name mentioned only inside an unrelated string literal" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = compat.wrapDir(tmp.dir);

    try root.writeFile(.{ .sub_path = "main.zig", .data =
        \\const msg = "see also: test \"removed_cache_regression\" above";
        \\test { @import("std").testing.refAllDecls(@This()); }
    });

    try testing.expectEqual(@as(usize, 0), try countMatches(allocator, root, "main.zig", "removed_cache_regression"));
}

test "countMatches still finds a real test declaration alongside an unrelated comment and string" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = compat.wrapDir(tmp.dir);

    try root.writeFile(.{ .sub_path = "main.zig", .data =
        \\// test "removed_cache_regression" {}
        \\const msg = "test \"not a real test\"";
        \\const helper = @import("helper.zig");
        \\test "cache_regression_still_covered" {}
    });
    try root.writeFile(.{ .sub_path = "helper.zig", .data =
        \\test "helper still reachable" {}
    });

    try testing.expectEqual(@as(usize, 0), try countMatches(allocator, root, "main.zig", "removed_cache_regression"));
    try testing.expectEqual(@as(usize, 1), try countMatches(allocator, root, "main.zig", "cache_regression_still_covered"));
    try testing.expectEqual(@as(usize, 1), try countMatches(allocator, root, "main.zig", "helper still reachable"));
}

test "countMatches skips an unreadable resolved import instead of failing" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = compat.wrapDir(tmp.dir);

    try root.writeFile(.{ .sub_path = "main.zig", .data =
        \\const missing = @import("does_not_exist.zig");
        \\test "main smoke" {}
    });

    try testing.expectEqual(@as(usize, 1), try countMatches(allocator, root, "main.zig", "smoke"));
}
