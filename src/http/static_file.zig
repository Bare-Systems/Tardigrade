const std = @import("std");
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
};

pub const Result = struct {
    status_code: status.Status,
    body: []u8,
    content_type: []const u8,
    content_length: usize,
    etag_value: ?[]u8 = null,
    last_modified_value: ?[]u8 = null,
    content_range_value: ?[]u8 = null,
    accept_ranges: bool = false,

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
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
                .content_type = "text/plain; charset=utf-8",
                .content_length = 0,
            };
        },
        .file => |file_path| {
            const file = try std.fs.cwd().openFile(file_path, .{});
            defer file.close();
            const stat_info = try file.stat();
            const mtime_secs: usize = @intCast(@divTrunc(stat_info.mtime, std.time.ns_per_s));

            const etag_value = @constCast(try etag.generateETag(allocator, stat_info.size, mtime_secs));
            errdefer allocator.free(etag_value);
            const last_modified = try formatHttpDateAlloc(allocator, @intCast(mtime_secs));
            errdefer allocator.free(last_modified);

            if (opts.headers.get("if-none-match")) |header_value| {
                if (etag.matchesIfNoneMatch(etag_value, header_value)) {
                    return .{
                        .status_code = .not_modified,
                        .body = try allocator.dupe(u8, ""),
                        .content_type = detectMimeType(file_path),
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
                            .content_type = detectMimeType(file_path),
                            .content_length = 0,
                            .etag_value = etag_value,
                            .last_modified_value = last_modified,
                            .accept_ranges = true,
                        };
                    }
                }
            }

            const file_data = try file.readToEndAlloc(allocator, opts.max_bytes);
            errdefer allocator.free(file_data);

            var out = Result{
                .status_code = .ok,
                .body = file_data,
                .content_type = detectMimeType(file_path),
                .content_length = file_data.len,
                .etag_value = etag_value,
                .last_modified_value = last_modified,
                .accept_ranges = true,
            };

            if (opts.headers.get("range")) |header_value| {
                const parsed = range.parseSingle(header_value, file_data.len) catch |err| switch (err) {
                    error.RangeNotSatisfiable => {
                        allocator.free(out.body);
                        out.body = try allocator.dupe(u8, "");
                        out.content_length = 0;
                        out.status_code = .range_not_satisfiable;
                        out.content_range_value = try std.fmt.allocPrint(allocator, "bytes */{d}", .{file_data.len});
                        return out;
                    },
                    else => return error.InvalidRange,
                };
                const slice = try allocator.dupe(u8, file_data[parsed.start .. parsed.end_inclusive + 1]);
                allocator.free(out.body);
                out.body = slice;
                out.content_length = slice.len;
                out.status_code = .partial_content;
                out.content_range_value = try range.formatContentRange(allocator, parsed, file_data.len);
            }

            return out;
        },
        .directory => |dir_path| {
            if (!opts.autoindex) return null;
            const listing = try autoindex.generateAutoIndex(allocator, dir_path, opts.request_path);
            return .{
                .status_code = .ok,
                .body = listing,
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
    const root_real = try std.fs.cwd().realpathAlloc(allocator, opts.root);
    errdefer allocator.free(root_real);

    const rel_path = if (opts.alias)
        std.mem.trimLeft(u8, opts.request_path[opts.matched_pattern.len..], "/")
    else
        std.mem.trimLeft(u8, opts.request_path, "/");

    if (opts.try_files.len > 0) {
        var candidates = std.mem.tokenizeAny(u8, opts.try_files, " ,");
        while (candidates.next()) |candidate_raw| {
            const candidate = std.mem.trim(u8, candidate_raw, " \t\r\n");
            if (candidate.len == 0) continue;
            const rel = if (std.mem.eql(u8, candidate, "$uri"))
                rel_path
            else
                std.mem.trimLeft(u8, candidate, "/");
            const maybe_resolved = resolveExistingCandidate(allocator, root_real, rel) catch |err| switch (err) {
                error.PathEscapesRoot => return .{ .kind = .forbidden, .root_real = root_real },
                else => return err,
            };
            if (maybe_resolved) |resolved| {
                switch (resolved) {
                    .file => return .{ .kind = resolved, .root_real = root_real },
                    .directory => |path| {
                        if (opts.autoindex) return .{ .kind = resolved, .root_real = root_real };
                        allocator.free(path);
                    },
                    else => {},
                }
            }
        }
    }

    const fallback_rel = if (rel_path.len == 0 or std.mem.endsWith(u8, opts.request_path, "/"))
        opts.index
    else
        rel_path;
    const maybe_fallback = resolveExistingCandidate(allocator, root_real, fallback_rel) catch |err| switch (err) {
        error.PathEscapesRoot => return .{ .kind = .forbidden, .root_real = root_real },
        else => return err,
    };
    if (maybe_fallback) |resolved| {
        return .{ .kind = resolved, .root_real = root_real };
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

fn resolveExistingCandidate(
    allocator: std.mem.Allocator,
    root_real: []const u8,
    rel: []const u8,
) !?ResolvedKind {
    const normalized_rel = try normalizeRelativePath(allocator, rel);
    defer allocator.free(normalized_rel);
    const joined = try std.fs.path.join(allocator, &[_][]const u8{ root_real, normalized_rel });
    defer allocator.free(joined);

    const real = std.fs.cwd().realpathAlloc(allocator, joined) catch return null;
    errdefer allocator.free(real);

    if (!isWithinRoot(root_real, real)) return error.PathEscapesRoot;

    const stat_info = std.fs.cwd().statFile(real) catch {
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

fn normalizeRelativePath(allocator: std.mem.Allocator, rel: []const u8) ![]u8 {
    const decoded_buf = try allocator.dupe(u8, std.mem.trimLeft(u8, rel, "/"));
    defer allocator.free(decoded_buf);

    const decoded = std.Uri.percentDecodeInPlace(decoded_buf);
    var normalized = std.ArrayList(u8).init(allocator);
    errdefer normalized.deinit();

    var cursor: usize = 0;
    while (cursor < decoded.len) {
        while (cursor < decoded.len and isPathSeparator(decoded[cursor])) : (cursor += 1) {}
        const segment_start = cursor;
        while (cursor < decoded.len and !isPathSeparator(decoded[cursor])) : (cursor += 1) {}

        const segment = decoded[segment_start..cursor];
        if (segment.len == 0 or std.mem.eql(u8, segment, ".")) continue;
        if (std.mem.eql(u8, segment, "..")) return error.PathEscapesRoot;

        if (normalized.items.len > 0) try normalized.append(std.fs.path.sep);
        try normalized.appendSlice(segment);
    }

    return normalized.toOwnedSlice();
}

fn isPathSeparator(ch: u8) bool {
    return ch == '/' or ch == '\\';
}

fn isWithinRoot(root_real: []const u8, target_real: []const u8) bool {
    if (!std.mem.startsWith(u8, target_real, root_real)) return false;
    if (target_real.len == root_real.len) return true;
    return target_real[root_real.len] == std.fs.path.sep;
}

fn detectMimeType(path: []const u8) []const u8 {
    const ext = std.fs.path.extension(path);
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

test "serve rejects traversal escaping root" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "index.html", .data = "ok" });
    const root_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    const parent = std.fs.path.dirname(root_path).?;
    const escape_name = "escape-target.txt";
    const escape_path = try std.fs.path.join(allocator, &[_][]const u8{ parent, escape_name });
    defer allocator.free(escape_path);
    try std.fs.cwd().writeFile(.{ .sub_path = escape_path, .data = "escape" });
    defer std.fs.cwd().deleteFile(escape_path) catch {};
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

    try tmp.dir.writeFile(.{ .sub_path = "index.html", .data = "ok" });
    const root_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    const parent = std.fs.path.dirname(root_path).?;
    const escape_name = "escape-encoded.txt";
    const escape_path = try std.fs.path.join(allocator, &[_][]const u8{ parent, escape_name });
    defer allocator.free(escape_path);
    try std.fs.cwd().writeFile(.{ .sub_path = escape_path, .data = "escape" });
    defer std.fs.cwd().deleteFile(escape_path) catch {};

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

test "serve rejects backslash traversal escaping root" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "index.html", .data = "ok" });
    const root_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    const parent = std.fs.path.dirname(root_path).?;
    const escape_name = "escape-backslash.txt";
    const escape_path = try std.fs.path.join(allocator, &[_][]const u8{ parent, escape_name });
    defer allocator.free(escape_path);
    try std.fs.cwd().writeFile(.{ .sub_path = escape_path, .data = "escape" });
    defer std.fs.cwd().deleteFile(escape_path) catch {};

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

    try tmp.dir.writeFile(.{ .sub_path = "index.html", .data = "ok" });
    const root_path = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    const parent = std.fs.path.dirname(root_path).?;
    const escape_name = "escape-target.txt";
    const escape_path = try std.fs.path.join(allocator, &[_][]const u8{ parent, escape_name });
    defer allocator.free(escape_path);
    try std.fs.cwd().writeFile(.{ .sub_path = escape_path, .data = "escape" });
    defer std.fs.cwd().deleteFile(escape_path) catch {};

    const symlink_path = try std.fs.path.join(allocator, &[_][]const u8{ root_path, "linked.txt" });
    defer allocator.free(symlink_path);
    try std.fs.symLinkAbsolute(escape_path, symlink_path, .{});

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

test "serve uses application wasm mime type" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "app.wasm", .data = "wasm-bytes" });
    const root_path = try tmp.dir.realpathAlloc(allocator, ".");
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
