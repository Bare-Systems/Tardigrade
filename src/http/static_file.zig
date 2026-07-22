const std = @import("std");
const compat = @import("zig_compat");
const autoindex = @import("autoindex.zig");
const dates = @import("dates.zig");
const etag = @import("etag.zig");
const headers_mod = @import("headers.zig");
const range = @import("range.zig");
const status = @import("status.zig");

pub const Options = struct {
    root: []const u8,
    request_path: []const u8,
    matched_pattern: []const u8,
    alias: bool,
    index: []const u8,
    try_files: []const u8,
    autoindex: bool = false,
    headers: *const headers_mod.Headers,
    max_bytes: usize = 8 * 1024 * 1024,
    prefer_file_backed: bool = false,
};

pub const Result = struct {
    status_code: status.Status,
    body: ?[]u8 = null,
    body_owned: bool = false,
    file_path: ?[]u8 = null,
    file_offset: u64 = 0,
    file_len: u64 = 0,
    content_type: []const u8,
    content_length: usize,
    etag_value: ?[]u8 = null,
    last_modified_value: ?[]u8 = null,
    content_range_value: ?[]u8 = null,
    accept_ranges: bool = false,

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        if (self.body_owned) {
            if (self.body) |body| allocator.free(body);
        }
        if (self.file_path) |path| allocator.free(path);
        if (self.etag_value) |v| allocator.free(v);
        if (self.last_modified_value) |v| allocator.free(v);
        if (self.content_range_value) |v| allocator.free(v);
        self.* = undefined;
    }
};

pub fn serve(allocator: std.mem.Allocator, opts: Options) !?Result {
    var resolved = try resolvePath(allocator, opts);
    defer resolved.deinit(allocator);

    switch (resolved.kind) {
        .not_found => return null,
        .forbidden => {
            return .{
                .status_code = .forbidden,
                .body = try allocator.dupe(u8, ""),
                .body_owned = true,
                .content_type = "text/plain; charset=utf-8",
                .content_length = 0,
            };
        },
        .file => |file_path| {
            var file = try compat.cwd().openFile(file_path, .{});
            defer file.close();
            const stat_info = try file.stat();
            const mtime_secs: usize = @intCast(@divTrunc(stat_info.mtime, std.time.ns_per_s));
            const file_size: usize = @intCast(stat_info.size);
            const content_type = detectMimeType(file_path);

            const etag_value = @constCast(try etag.generateETag(allocator, stat_info.size, mtime_secs));
            errdefer allocator.free(etag_value);
            const last_modified = try formatHttpDateAlloc(allocator, @intCast(mtime_secs));
            errdefer allocator.free(last_modified);

            if (opts.headers.get("if-none-match")) |header_value| {
                if (etag.matchesIfNoneMatch(etag_value, header_value)) {
                    return .{
                        .status_code = .not_modified,
                        .body = try allocator.dupe(u8, ""),
                        .body_owned = true,
                        .content_type = content_type,
                        .content_length = 0,
                        .etag_value = etag_value,
                        .last_modified_value = last_modified,
                        .accept_ranges = true,
                    };
                }
            }

            if (opts.headers.get("if-modified-since")) |header_value| {
                if (dates.parseHttpDate(header_value)) |header_secs| {
                    if (header_secs >= @as(i64, @intCast(mtime_secs))) {
                        return .{
                            .status_code = .not_modified,
                            .body = try allocator.dupe(u8, ""),
                            .body_owned = true,
                            .content_type = content_type,
                            .content_length = 0,
                            .etag_value = etag_value,
                            .last_modified_value = last_modified,
                            .accept_ranges = true,
                        };
                    }
                }
            }

            if (opts.headers.get("range")) |header_value| {
                const parsed = range.parseSingle(header_value, file_size) catch |err| switch (err) {
                    error.RangeNotSatisfiable => {
                        return .{
                            .status_code = .range_not_satisfiable,
                            .body = try allocator.dupe(u8, ""),
                            .body_owned = true,
                            .content_type = content_type,
                            .content_length = 0,
                            .etag_value = etag_value,
                            .last_modified_value = last_modified,
                            .content_range_value = try std.fmt.allocPrint(allocator, "bytes */{d}", .{file_size}),
                            .accept_ranges = true,
                        };
                    },
                    else => return error.InvalidRange,
                };

                if (opts.prefer_file_backed) {
                    resolved.kind = .not_found;
                    return .{
                        .status_code = .partial_content,
                        .file_path = file_path,
                        .file_offset = parsed.start,
                        .file_len = parsed.end_inclusive - parsed.start + 1,
                        .content_type = content_type,
                        .content_length = parsed.end_inclusive - parsed.start + 1,
                        .etag_value = etag_value,
                        .last_modified_value = last_modified,
                        .content_range_value = try range.formatContentRange(allocator, parsed, file_size),
                        .accept_ranges = true,
                    };
                }

                const file_data = try file.readToEndAlloc(allocator, opts.max_bytes);
                errdefer allocator.free(file_data);
                const slice = try allocator.dupe(u8, file_data[parsed.start .. parsed.end_inclusive + 1]);
                allocator.free(file_data);
                return .{
                    .status_code = .partial_content,
                    .body = slice,
                    .body_owned = true,
                    .content_type = content_type,
                    .content_length = slice.len,
                    .etag_value = etag_value,
                    .last_modified_value = last_modified,
                    .content_range_value = try range.formatContentRange(allocator, parsed, file_size),
                    .accept_ranges = true,
                };
            }

            if (opts.prefer_file_backed) {
                resolved.kind = .not_found;
                return .{
                    .status_code = .ok,
                    .file_path = file_path,
                    .file_offset = 0,
                    .file_len = stat_info.size,
                    .content_type = content_type,
                    .content_length = file_size,
                    .etag_value = etag_value,
                    .last_modified_value = last_modified,
                    .accept_ranges = true,
                };
            }

            const file_data = try file.readToEndAlloc(allocator, opts.max_bytes);
            errdefer allocator.free(file_data);

            return .{
                .status_code = .ok,
                .body = file_data,
                .body_owned = true,
                .content_type = content_type,
                .content_length = file_data.len,
                .etag_value = etag_value,
                .last_modified_value = last_modified,
                .accept_ranges = true,
            };
        },
        .directory => |dir_path| {
            if (!opts.autoindex) return null;
            const listing = try autoindex.generateAutoIndex(compat.io(), allocator, dir_path, opts.request_path);
            return .{
                .status_code = .ok,
                .body = listing,
                .body_owned = true,
                .content_type = "text/html; charset=utf-8",
                .content_length = listing.len,
            };
        },
    }
}

const ResolvedKind = union(enum) {
    not_found,
    forbidden,
    file: []u8,
    directory: []u8,
};

const ResolvedPath = struct {
    kind: ResolvedKind,
    root_real: []u8,

    fn deinit(self: *ResolvedPath, allocator: std.mem.Allocator) void {
        allocator.free(self.root_real);
        switch (self.kind) {
            .file => |path| allocator.free(path),
            .directory => |path| allocator.free(path),
            else => {},
        }
        self.* = undefined;
    }
};

fn resolvePath(allocator: std.mem.Allocator, opts: Options) !ResolvedPath {
    const root_real = try compat.cwd().realpathAlloc(allocator, opts.root);
    errdefer allocator.free(root_real);

    const rel_path = if (opts.alias)
        std.mem.trimStart(u8, opts.request_path[opts.matched_pattern.len..], "/")
    else
        std.mem.trimStart(u8, opts.request_path, "/");

    if (opts.try_files.len > 0) {
        var candidates = std.mem.tokenizeAny(u8, opts.try_files, " ,");
        while (candidates.next()) |candidate_raw| {
            const candidate = std.mem.trim(u8, candidate_raw, " \t\r\n");
            if (candidate.len == 0) continue;
            const rel = if (std.mem.eql(u8, candidate, "$uri"))
                rel_path
            else
                std.mem.trimStart(u8, candidate, "/");
            const maybe_resolved = resolveExistingCandidate(allocator, root_real, rel) catch |err| switch (err) {
                error.PathEscapesRoot => return .{ .kind = .forbidden, .root_real = root_real },
                else => return err,
            };
            if (maybe_resolved) |resolved| {
                switch (resolved) {
                    .file => return .{ .kind = resolved, .root_real = root_real },
                    .directory => |path| {
                        // `path` is an owned allocation from here on; guard
                        // every error exit below (the PathEscapesRoot arm
                        // below returns a normal `.forbidden` value rather
                        // than an error, so errdefer does not cover it and
                        // still needs its own explicit free).
                        errdefer allocator.free(path);

                        // Try the directory-relative index before honoring
                        // autoindex, so an existing index.html takes priority
                        // over a directory listing (#437).
                        const maybe_index = resolveDirectoryIndex(allocator, root_real, rel, opts.index) catch |err| switch (err) {
                            error.PathEscapesRoot => {
                                allocator.free(path);
                                return .{ .kind = .forbidden, .root_real = root_real };
                            },
                            else => return err,
                        };
                        if (maybe_index) |index_path| {
                            allocator.free(path);
                            return .{ .kind = .{ .file = index_path }, .root_real = root_real };
                        }
                        if (opts.autoindex) return .{ .kind = resolved, .root_real = root_real };
                        allocator.free(path);
                    },
                    else => {},
                }
            }
        }
    }

    // Directory-style requests (empty relative path, or a trailing slash)
    // resolve their index relative to the *requested* directory, not just the
    // location root — `GET /docs/` must check `docs/index.html`, not fall
    // back to the root's `index.html` (#437).
    if (rel_path.len == 0 or std.mem.endsWith(u8, opts.request_path, "/")) {
        const maybe_index = resolveDirectoryIndex(allocator, root_real, rel_path, opts.index) catch |err| switch (err) {
            error.PathEscapesRoot => return .{ .kind = .forbidden, .root_real = root_real },
            else => return err,
        };
        if (maybe_index) |index_path| {
            return .{ .kind = .{ .file = index_path }, .root_real = root_real };
        }
    } else {
        const maybe_fallback = resolveExistingCandidate(allocator, root_real, rel_path) catch |err| switch (err) {
            error.PathEscapesRoot => return .{ .kind = .forbidden, .root_real = root_real },
            else => return err,
        };
        if (maybe_fallback) |resolved| {
            return .{ .kind = resolved, .root_real = root_real };
        }
    }

    if (opts.autoindex) {
        const maybe_directory = resolveExistingCandidate(allocator, root_real, rel_path) catch |err| switch (err) {
            error.PathEscapesRoot => return .{ .kind = .forbidden, .root_real = root_real },
            else => return err,
        };
        if (maybe_directory) |resolved| {
            switch (resolved) {
                .directory => return .{ .kind = resolved, .root_real = root_real },
                .file => |path| allocator.free(path),
                else => {},
            }
        }
    }

    return .{ .kind = .not_found, .root_real = root_real };
}

pub fn resolveFileCandidate(
    allocator: std.mem.Allocator,
    root_real: []const u8,
    rel: []const u8,
) !?[]u8 {
    const maybe_resolved = try resolveExistingCandidate(allocator, root_real, rel);
    if (maybe_resolved) |resolved| {
        return switch (resolved) {
            .file => |path| path,
            .directory => |path| blk: {
                allocator.free(path);
                break :blk null;
            },
            else => null,
        };
    }
    return null;
}

/// Resolves `index_name` relative to `dir_rel` (a directory-relative path,
/// possibly with a trailing slash or empty for the root) and returns it only
/// if it exists as a file. Returns null if `index_name` is empty (explicit
/// opt-out via `index "";`) or no such file exists.
fn resolveDirectoryIndex(
    allocator: std.mem.Allocator,
    root_real: []const u8,
    dir_rel: []const u8,
    index_name: []const u8,
) !?[]u8 {
    if (index_name.len == 0) return null;
    const trimmed_dir = std.mem.trimEnd(u8, dir_rel, "/");
    if (trimmed_dir.len == 0) return resolveFileCandidate(allocator, root_real, index_name);
    const index_rel = try std.Io.Dir.path.join(allocator, &[_][]const u8{ trimmed_dir, index_name });
    defer allocator.free(index_rel);
    return resolveFileCandidate(allocator, root_real, index_rel);
}

fn resolveExistingCandidate(
    allocator: std.mem.Allocator,
    root_real: []const u8,
    rel: []const u8,
) !?ResolvedKind {
    const normalized_rel = try normalizeRelativePath(allocator, rel);
    defer allocator.free(normalized_rel);
    const joined = try std.Io.Dir.path.join(allocator, &[_][]const u8{ root_real, normalized_rel });
    defer allocator.free(joined);

    const real = compat.cwd().realpathAlloc(allocator, joined) catch return null;
    errdefer allocator.free(real);

    if (!isWithinRoot(root_real, real)) return error.PathEscapesRoot;

    const stat_info = compat.cwd().statFile(real) catch {
        allocator.free(real);
        return null;
    };

    return switch (stat_info.kind) {
        .file => .{ .file = real },
        .directory => .{ .directory = real },
        else => blk: {
            allocator.free(real);
            break :blk null;
        },
    };
}

pub fn normalizeRelativePath(allocator: std.mem.Allocator, rel: []const u8) ![]u8 {
    const decoded_buf = try allocator.dupe(u8, std.mem.trimStart(u8, rel, "/"));
    defer allocator.free(decoded_buf);

    const decoded = std.Uri.percentDecodeInPlace(decoded_buf);
    var normalized = std.ArrayList(u8).empty;
    errdefer normalized.deinit(allocator);

    var cursor: usize = 0;
    while (cursor < decoded.len) {
        while (cursor < decoded.len and isPathSeparator(decoded[cursor])) : (cursor += 1) {}
        const segment_start = cursor;
        while (cursor < decoded.len and !isPathSeparator(decoded[cursor])) : (cursor += 1) {}

        const segment = decoded[segment_start..cursor];
        if (segment.len == 0 or std.mem.eql(u8, segment, ".")) continue;
        if (std.mem.eql(u8, segment, "..")) return error.PathEscapesRoot;

        if (normalized.items.len > 0) try normalized.append(allocator, std.Io.Dir.path.sep);
        try normalized.appendSlice(allocator, segment);
    }

    return normalized.toOwnedSlice(allocator);
}

fn isPathSeparator(ch: u8) bool {
    return ch == '/' or ch == '\\';
}

fn isWithinRoot(root_real: []const u8, target_real: []const u8) bool {
    if (!std.mem.startsWith(u8, target_real, root_real)) return false;
    if (target_real.len == root_real.len) return true;
    return target_real[root_real.len] == std.Io.Dir.path.sep;
}

fn detectMimeType(path: []const u8) []const u8 {
    const ext = std.Io.Dir.path.extension(path);
    if (std.ascii.eqlIgnoreCase(ext, ".html") or std.ascii.eqlIgnoreCase(ext, ".htm")) return "text/html; charset=utf-8";
    if (std.ascii.eqlIgnoreCase(ext, ".css")) return "text/css; charset=utf-8";
    if (std.ascii.eqlIgnoreCase(ext, ".js")) return "application/javascript; charset=utf-8";
    if (std.ascii.eqlIgnoreCase(ext, ".json")) return "application/json";
    if (std.ascii.eqlIgnoreCase(ext, ".svg")) return "image/svg+xml";
    if (std.ascii.eqlIgnoreCase(ext, ".txt")) return "text/plain; charset=utf-8";
    if (std.ascii.eqlIgnoreCase(ext, ".png")) return "image/png";
    if (std.ascii.eqlIgnoreCase(ext, ".jpg") or std.ascii.eqlIgnoreCase(ext, ".jpeg")) return "image/jpeg";
    if (std.ascii.eqlIgnoreCase(ext, ".gif")) return "image/gif";
    if (std.ascii.eqlIgnoreCase(ext, ".webp")) return "image/webp";
    if (std.ascii.eqlIgnoreCase(ext, ".wasm")) return "application/wasm";
    return "application/octet-stream";
}

fn formatHttpDateAlloc(allocator: std.mem.Allocator, timestamp_secs: i64) ![]u8 {
    const epoch_secs: std.time.epoch.EpochSeconds = .{ .secs = @intCast(timestamp_secs) };
    const day_secs = epoch_secs.getDaySeconds();
    const epoch_day = epoch_secs.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_names = [_][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" };
    const month_names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    const day_of_week = @mod(epoch_day.day, 7);
    return std.fmt.allocPrint(allocator, "{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        day_names[day_of_week],
        month_day.day_index + 1,
        month_names[@intFromEnum(month_day.month) - 1],
        year_day.year,
        day_secs.getHoursIntoDay(),
        day_secs.getMinutesIntoHour(),
        day_secs.getSecondsIntoMinute(),
    });
}

test "serve resolves nested directory index relative to the requested directory" {
    // Regression test for #437: the default (and any explicit) index must be
    // resolved relative to the requested directory, not just the location
    // root, so `GET /docs/` checks `docs/index.html` rather than falling
    // back to the root's `index.html`.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "index.html", .data = "root index" });
    try compat.wrapDir(tmp.dir).makePath("docs");
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "docs/index.html", .data = "docs index" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();

    var root_served = (try serve(allocator, .{
        .root = root_path,
        .request_path = "/",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs,
    })).?;
    defer root_served.deinit(allocator);
    try std.testing.expectEqual(status.Status.ok, root_served.status_code);
    try std.testing.expectEqualStrings("root index", root_served.body.?);

    var docs_served = (try serve(allocator, .{
        .root = root_path,
        .request_path = "/docs/",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs,
    })).?;
    defer docs_served.deinit(allocator);
    try std.testing.expectEqual(status.Status.ok, docs_served.status_code);
    try std.testing.expectEqualStrings("docs index", docs_served.body.?);
}

test "serve returns not found for a nonexistent directory even when the root index exists" {
    // Regression test for #437: a directory-style request for a path that
    // does not exist must not fall back to the root's index file.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "index.html", .data = "root index" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();

    const result = try serve(allocator, .{
        .root = root_path,
        .request_path = "/missing/",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs,
    });
    try std.testing.expect(result == null);
}

test "serve prefers directory-relative index over autoindex listing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "index.html", .data = "index wins" });
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "other.txt", .data = "other" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();

    var served = (try serve(allocator, .{
        .root = root_path,
        .request_path = "/",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "$uri",
        .autoindex = true,
        .headers = &hdrs,
    })).?;
    defer served.deinit(allocator);
    try std.testing.expectEqual(status.Status.ok, served.status_code);
    try std.testing.expectEqualStrings("index wins", served.body.?);
}

test "serve falls back to autoindex when index is explicitly disabled" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "index.html", .data = "should not be served" });
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "other.txt", .data = "other" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();

    var served = (try serve(allocator, .{
        .root = root_path,
        .request_path = "/",
        .matched_pattern = "/",
        .alias = false,
        .index = "",
        .try_files = "",
        .autoindex = true,
        .headers = &hdrs,
    })).?;
    defer served.deinit(allocator);
    try std.testing.expectEqual(status.Status.ok, served.status_code);
    try std.testing.expect(std.mem.find(u8, served.body.?, "other.txt") != null);
}

test "serve rejects traversal escaping root" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "index.html", .data = "ok" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    const parent = std.Io.Dir.path.dirname(root_path).?;
    const escape_name = "escape-target.txt";
    const escape_path = try std.Io.Dir.path.join(allocator, &[_][]const u8{ parent, escape_name });
    defer allocator.free(escape_path);
    try compat.cwd().writeFile(.{ .sub_path = escape_path, .data = "escape" });
    defer compat.cwd().deleteFile(escape_path) catch {}; // best-effort test cleanup; file may not exist if the test failed early
    const request_path = try std.fmt.allocPrint(allocator, "/../{s}", .{escape_name});
    defer allocator.free(request_path);

    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();

    const result = try serve(allocator, .{
        .root = root_path,
        .request_path = request_path,
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs,
    });
    try std.testing.expect(result != null);
    var served = result.?;
    defer served.deinit(allocator);
    try std.testing.expectEqual(status.Status.forbidden, served.status_code);
}

test "serve rejects percent-encoded traversal escaping root" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "index.html", .data = "ok" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    const parent = std.Io.Dir.path.dirname(root_path).?;
    const escape_name = "escape-encoded.txt";
    const escape_path = try std.Io.Dir.path.join(allocator, &[_][]const u8{ parent, escape_name });
    defer allocator.free(escape_path);
    try compat.cwd().writeFile(.{ .sub_path = escape_path, .data = "escape" });
    defer compat.cwd().deleteFile(escape_path) catch {}; // best-effort test cleanup; file may not exist if the test failed early

    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();

    const result = try serve(allocator, .{
        .root = root_path,
        .request_path = "/%2e%2e/escape-encoded.txt",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs,
    });
    try std.testing.expect(result != null);
    var served = result.?;
    defer served.deinit(allocator);
    try std.testing.expectEqual(status.Status.forbidden, served.status_code);
}

test "serve rejects double-encoded traversal escaping root" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "index.html", .data = "ok" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();

    const result = try serve(allocator, .{
        .root = root_path,
        .request_path = "/%252e%252e/escape-double.txt",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs,
    });
    try std.testing.expect(result == null or result.?.status_code == status.Status.forbidden);
    if (result) |served_result| {
        var served = served_result;
        defer served.deinit(allocator);
    }
}

test "serve rejects backslash traversal escaping root" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "index.html", .data = "ok" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    const parent = std.Io.Dir.path.dirname(root_path).?;
    const escape_name = "escape-backslash.txt";
    const escape_path = try std.Io.Dir.path.join(allocator, &[_][]const u8{ parent, escape_name });
    defer allocator.free(escape_path);
    try compat.cwd().writeFile(.{ .sub_path = escape_path, .data = "escape" });
    defer compat.cwd().deleteFile(escape_path) catch {}; // best-effort test cleanup; file may not exist if the test failed early

    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();

    const result = try serve(allocator, .{
        .root = root_path,
        .request_path = "/..\\escape-backslash.txt",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs,
    });
    try std.testing.expect(result != null);
    var served = result.?;
    defer served.deinit(allocator);
    try std.testing.expectEqual(status.Status.forbidden, served.status_code);
}

test "serve rejects symlink escape outside root" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "index.html", .data = "ok" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    const parent = std.Io.Dir.path.dirname(root_path).?;
    const escape_name = "escape-target.txt";
    const escape_path = try std.Io.Dir.path.join(allocator, &[_][]const u8{ parent, escape_name });
    defer allocator.free(escape_path);
    try compat.cwd().writeFile(.{ .sub_path = escape_path, .data = "escape" });
    defer compat.cwd().deleteFile(escape_path) catch {}; // best-effort test cleanup; file may not exist if the test failed early

    const symlink_path = try std.Io.Dir.path.join(allocator, &[_][]const u8{ root_path, "linked.txt" });
    defer allocator.free(symlink_path);
    try std.Io.Dir.symLinkAbsolute(compat.io(), escape_path, symlink_path, .{});

    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();

    const result = try serve(allocator, .{
        .root = root_path,
        .request_path = "/linked.txt",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs,
    });
    try std.testing.expect(result != null);
    var served = result.?;
    defer served.deinit(allocator);
    try std.testing.expectEqual(status.Status.forbidden, served.status_code);
}

test "serve rejects alias traversal escaping alias root" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).makePath("assets");
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "assets/index.html", .data = "asset" });
    const assets_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, "assets");
    defer allocator.free(assets_path);

    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();

    const result = try serve(allocator, .{
        .root = assets_path,
        .request_path = "/assets/%2e%2e/secrets.txt",
        .matched_pattern = "/assets/",
        .alias = true,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs,
    });
    try std.testing.expect(result != null);
    var served = result.?;
    defer served.deinit(allocator);
    try std.testing.expectEqual(status.Status.forbidden, served.status_code);
}

test "serve returns file-backed payload when preferred" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "asset.txt", .data = "hello file path" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();

    var served = (try serve(allocator, .{
        .root = root_path,
        .request_path = "/asset.txt",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs,
        .prefer_file_backed = true,
    })).?;
    defer served.deinit(allocator);

    try std.testing.expectEqual(status.Status.ok, served.status_code);
    try std.testing.expect(served.body == null);
    try std.testing.expect(served.file_path != null);
    try std.testing.expectEqual(@as(u64, 0), served.file_offset);
    try std.testing.expectEqual(@as(u64, 15), served.file_len);
    try std.testing.expectEqual(@as(usize, 15), served.content_length);
}

test "serve returns file-backed range payload when preferred" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "asset.txt", .data = "hello file path" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();
    try hdrs.append("Range", "bytes=6-9");

    var served = (try serve(allocator, .{
        .root = root_path,
        .request_path = "/asset.txt",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs,
        .prefer_file_backed = true,
    })).?;
    defer served.deinit(allocator);

    try std.testing.expectEqual(status.Status.partial_content, served.status_code);
    try std.testing.expect(served.body == null);
    try std.testing.expect(served.file_path != null);
    try std.testing.expectEqual(@as(u64, 6), served.file_offset);
    try std.testing.expectEqual(@as(u64, 4), served.file_len);
    try std.testing.expectEqual(@as(usize, 4), served.content_length);
    try std.testing.expectEqualStrings("bytes 6-9/15", served.content_range_value.?);
}

test "serve returns 206 with correct body slice and Content-Range for valid range" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // File content is exactly "0123456789" (10 bytes)
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "data.txt", .data = "0123456789" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();
    try hdrs.append("Range", "bytes=0-4");

    var served = (try serve(allocator, .{
        .root = root_path,
        .request_path = "/data.txt",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs,
    })).?;
    defer served.deinit(allocator);

    try std.testing.expectEqual(status.Status.partial_content, served.status_code);
    try std.testing.expectEqualStrings("01234", served.body.?);
    try std.testing.expectEqual(@as(usize, 5), served.content_length);
    try std.testing.expectEqualStrings("bytes 0-4/10", served.content_range_value.?);
    try std.testing.expect(served.accept_ranges);
}

test "serve returns 206 for suffix range (bytes=-N)" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "tail.txt", .data = "abcdefghij" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();
    try hdrs.append("Range", "bytes=-3");

    var served = (try serve(allocator, .{
        .root = root_path,
        .request_path = "/tail.txt",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs,
    })).?;
    defer served.deinit(allocator);

    try std.testing.expectEqual(status.Status.partial_content, served.status_code);
    try std.testing.expectEqualStrings("hij", served.body.?);
    try std.testing.expectEqualStrings("bytes 7-9/10", served.content_range_value.?);
}

test "serve returns 416 for unsatisfiable range" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "small.txt", .data = "hi" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();
    try hdrs.append("Range", "bytes=1000-2000");

    var served = (try serve(allocator, .{
        .root = root_path,
        .request_path = "/small.txt",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs,
    })).?;
    defer served.deinit(allocator);

    try std.testing.expectEqual(status.Status.range_not_satisfiable, served.status_code);
    // Content-Range must use wildcard form bytes */N for 416
    try std.testing.expect(served.content_range_value != null);
    try std.testing.expect(std.mem.startsWith(u8, served.content_range_value.?, "bytes */"));
}

test "serve returns 304 for matching If-None-Match" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "cached.txt", .data = "hello" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    // Obtain the real ETag by doing an initial unguarded request.
    var hdrs0 = headers_mod.Headers.init(allocator);
    defer hdrs0.deinit();
    var first = (try serve(allocator, .{
        .root = root_path,
        .request_path = "/cached.txt",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs0,
    })).?;
    const real_etag = try allocator.dupe(u8, first.etag_value.?);
    defer allocator.free(real_etag);
    first.deinit(allocator);

    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();
    try hdrs.append("If-None-Match", real_etag);

    var served = (try serve(allocator, .{
        .root = root_path,
        .request_path = "/cached.txt",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs,
    })).?;
    defer served.deinit(allocator);

    try std.testing.expectEqual(status.Status.not_modified, served.status_code);
    try std.testing.expectEqual(@as(usize, 0), served.content_length);
}

test "serve returns 304 for wildcard If-None-Match" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "wild.txt", .data = "data" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();
    try hdrs.append("If-None-Match", "*");

    var served = (try serve(allocator, .{
        .root = root_path,
        .request_path = "/wild.txt",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs,
    })).?;
    defer served.deinit(allocator);

    try std.testing.expectEqual(status.Status.not_modified, served.status_code);
}

test "serve returns 200 for non-matching If-None-Match" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "miss.txt", .data = "body" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();
    try hdrs.append("If-None-Match", "\"deadbeef-0\"");

    var served = (try serve(allocator, .{
        .root = root_path,
        .request_path = "/miss.txt",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs,
    })).?;
    defer served.deinit(allocator);

    try std.testing.expectEqual(status.Status.ok, served.status_code);
    try std.testing.expect(served.body != null);
}

test "serve returns 304 for If-Modified-Since not older than mtime" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "mod.txt", .data = "stale?" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    // Use a far-future date so mtime is always <= header.
    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();
    try hdrs.append("If-Modified-Since", "Sat, 01 Jan 2050 00:00:00 GMT");

    var served = (try serve(allocator, .{
        .root = root_path,
        .request_path = "/mod.txt",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs,
    })).?;
    defer served.deinit(allocator);

    try std.testing.expectEqual(status.Status.not_modified, served.status_code);
}

test "serve returns 200 for If-Modified-Since older than mtime" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "fresh.txt", .data = "new" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    // Epoch = before any real file mtime.
    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();
    try hdrs.append("If-Modified-Since", "Thu, 01 Jan 1970 00:00:00 GMT");

    var served = (try serve(allocator, .{
        .root = root_path,
        .request_path = "/fresh.txt",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs,
    })).?;
    defer served.deinit(allocator);

    try std.testing.expectEqual(status.Status.ok, served.status_code);
}

test "serve: If-None-Match match takes precedence over Range, returns 304 not 206" {
    // RFC 9110 §13.1: conditional headers are evaluated before range headers.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "cond.txt", .data = "0123456789" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    // Get real ETag first.
    var hdrs0 = headers_mod.Headers.init(allocator);
    defer hdrs0.deinit();
    var first = (try serve(allocator, .{
        .root = root_path,
        .request_path = "/cond.txt",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs0,
    })).?;
    const real_etag = try allocator.dupe(u8, first.etag_value.?);
    defer allocator.free(real_etag);
    first.deinit(allocator);

    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();
    try hdrs.append("If-None-Match", real_etag);
    try hdrs.append("Range", "bytes=0-4");

    var served = (try serve(allocator, .{
        .root = root_path,
        .request_path = "/cond.txt",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs,
    })).?;
    defer served.deinit(allocator);

    try std.testing.expectEqual(status.Status.not_modified, served.status_code);
}

test "serve large file returns 200 with full body" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Write a 512 KB file with a repeating pattern.
    const file_size: usize = 512 * 1024;
    const pattern = "TARDIGRADE";
    var data = try allocator.alloc(u8, file_size);
    defer allocator.free(data);
    var i: usize = 0;
    while (i < file_size) : (i += 1) data[i] = pattern[i % pattern.len];

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "large.bin", .data = data });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();

    var served = (try serve(allocator, .{
        .root = root_path,
        .request_path = "/large.bin",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs,
        .max_bytes = 1024 * 1024,
    })).?;
    defer served.deinit(allocator);

    try std.testing.expectEqual(status.Status.ok, served.status_code);
    try std.testing.expectEqual(file_size, served.content_length);
    try std.testing.expectEqual(file_size, served.body.?.len);
    // Spot-check first and last byte of the pattern.
    try std.testing.expectEqual(data[0], served.body.?[0]);
    try std.testing.expectEqual(data[file_size - 1], served.body.?[file_size - 1]);
}

test "serve uses application wasm mime type" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "app.wasm", .data = "wasm-bytes" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    var hdrs = headers_mod.Headers.init(allocator);
    defer hdrs.deinit();

    const result = (try serve(allocator, .{
        .root = root_path,
        .request_path = "/app.wasm",
        .matched_pattern = "/",
        .alias = false,
        .index = "index.html",
        .try_files = "",
        .headers = &hdrs,
    })).?;
    var served = result;
    defer served.deinit(allocator);
    try std.testing.expectEqualStrings("application/wasm", served.content_type);
}

test "fuzz: normalizeRelativePath never produces path traversal outputs" {
    try std.testing.fuzz({}, fuzzNormalizePath, .{ .corpus = &.{
        "/normal/path/file.txt",
        "/../escape",
        "/foo/../../bar",
        "/foo/%2e%2e/bar",
        "%2e%2e/secret",
        "/foo\\..\\bar",
        "",
    } });
}

fn fuzzNormalizePath(_: void, smith: *std.testing.Smith) !void {
    const allocator = std.testing.allocator;
    var buf: [256]u8 = undefined;
    const len = smith.sliceWeightedBytes(&buf, &.{
        .value(u8, '/', 5),
        .value(u8, '.', 4),
        .rangeAtMost(u8, 'a', 'z', 4),
        .value(u8, '%', 2),
        .value(u8, '\\', 1),
        .rangeAtMost(u8, 0x00, 0x1f, 1), // control characters
    });
    const result = normalizeRelativePath(allocator, buf[0..len]) catch return;
    defer allocator.free(result);
    // Security invariant: successful output must not contain ".." path segments.
    var it = std.mem.splitScalar(u8, result, std.Io.Dir.path.sep);
    while (it.next()) |seg| {
        if (std.mem.eql(u8, seg, "..")) return error.PathTraversalBypass;
    }
    // Output must not begin with a path separator (no absolute paths).
    if (result.len > 0 and (result[0] == '/' or result[0] == '\\'))
        return error.AbsolutePathReturned;
}
