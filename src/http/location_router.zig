const std = @import("std");
const rewrite = @import("rewrite.zig");

pub const MatchType = enum {
    exact,
    prefix_priority,
    regex,
    regex_case_insensitive,
    prefix,

    pub fn parse(raw: []const u8) ?MatchType {
        if (std.ascii.eqlIgnoreCase(raw, "exact")) return .exact;
        if (std.ascii.eqlIgnoreCase(raw, "prefix_priority") or std.ascii.eqlIgnoreCase(raw, "prefix-priority")) return .prefix_priority;
        if (std.ascii.eqlIgnoreCase(raw, "regex")) return .regex;
        if (std.ascii.eqlIgnoreCase(raw, "regex_case_insensitive") or std.ascii.eqlIgnoreCase(raw, "regex-case-insensitive")) return .regex_case_insensitive;
        if (std.ascii.eqlIgnoreCase(raw, "prefix")) return .prefix;
        return null;
    }
};

pub const Action = union(enum) {
    proxy_pass: []const u8,
    fastcgi_pass: []const u8,
    return_response: struct {
        status: u16,
        body: []const u8,
    },
    rewrite: struct {
        replacement: []const u8,
        flag: rewrite.RewriteFlag,
    },
    static_root: struct {
        root: []const u8,
        alias: bool,
        autoindex: bool,
        index: []const u8,
        try_files: []const u8,
    },

    pub fn deinit(self: *Action, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .proxy_pass => |target| allocator.free(target),
            .fastcgi_pass => |target| allocator.free(target),
            .return_response => |response| allocator.free(response.body),
            .rewrite => |rule| allocator.free(rule.replacement),
            .static_root => |root| {
                allocator.free(root.root);
                allocator.free(root.index);
                allocator.free(root.try_files);
            },
        }
        self.* = undefined;
    }
};

pub const ErrorPageRule = struct {
    status_codes: []u16,
    target: []const u8,

    pub fn deinit(self: *ErrorPageRule, allocator: std.mem.Allocator) void {
        allocator.free(self.status_codes);
        allocator.free(self.target);
        self.* = undefined;
    }
};

pub const AuthMode = enum {
    off,
    required,

    pub fn parse(value: []const u8) ?AuthMode {
        if (std.ascii.eqlIgnoreCase(value, "off")) return .off;
        if (std.ascii.eqlIgnoreCase(value, "required")) return .required;
        return null;
    }
};

pub const LocationBlock = struct {
    match_type: MatchType,
    pattern: []const u8,
    priority: usize,
    action: Action,
    error_pages: []ErrorPageRule = &.{},
    auth: AuthMode = .off,

    pub fn deinit(self: *LocationBlock, allocator: std.mem.Allocator) void {
        allocator.free(self.pattern);
        self.action.deinit(allocator);
        for (self.error_pages) |*rule| rule.deinit(allocator);
        if (self.error_pages.len > 0) allocator.free(self.error_pages);
        self.* = undefined;
    }
};

pub const MatchResult = struct {
    index: usize,
    block: *const LocationBlock,
    matched_path: []const u8,
};

pub fn matchLocation(request_uri: []const u8, blocks: []const LocationBlock) ?MatchResult {
    const path = normalizeRequestPath(request_uri);

    var best_priority_prefix: ?usize = null;
    var best_priority_prefix_len: usize = 0;
    var best_plain_prefix: ?usize = null;
    var best_plain_prefix_len: usize = 0;

    for (blocks, 0..) |*block, idx| {
        switch (block.match_type) {
            .exact => {
                if (std.mem.eql(u8, path, block.pattern)) {
                    return .{ .index = idx, .block = block, .matched_path = path };
                }
            },
            .prefix_priority => {
                if (std.mem.startsWith(u8, path, block.pattern) and isBetterPrefixMatch(blocks, idx, best_priority_prefix, block.pattern.len, best_priority_prefix_len)) {
                    best_priority_prefix = idx;
                    best_priority_prefix_len = block.pattern.len;
                }
            },
            .prefix => {
                if (std.mem.startsWith(u8, path, block.pattern) and isBetterPrefixMatch(blocks, idx, best_plain_prefix, block.pattern.len, best_plain_prefix_len)) {
                    best_plain_prefix = idx;
                    best_plain_prefix_len = block.pattern.len;
                }
            },
            .regex => {},
            .regex_case_insensitive => {},
        }
    }

    if (best_priority_prefix) |idx| {
        return .{ .index = idx, .block = &blocks[idx], .matched_path = path };
    }

    for (blocks, 0..) |*block, idx| {
        switch (block.match_type) {
            .regex => {
                if (rewrite.regexMatchesOptions(block.pattern, path, false)) {
                    return .{ .index = idx, .block = block, .matched_path = path };
                }
            },
            .regex_case_insensitive => {
                if (rewrite.regexMatchesOptions(block.pattern, path, true)) {
                    return .{ .index = idx, .block = block, .matched_path = path };
                }
            },
            else => {},
        }
    }

    if (best_plain_prefix) |idx| {
        return .{ .index = idx, .block = &blocks[idx], .matched_path = path };
    }

    return null;
}

fn isBetterPrefixMatch(
    blocks: []const LocationBlock,
    candidate_idx: usize,
    current_idx: ?usize,
    candidate_len: usize,
    current_len: usize,
) bool {
    if (candidate_len > current_len) return true;
    if (candidate_len < current_len) return false;
    if (current_idx == null) return true;
    return blocks[candidate_idx].priority < blocks[current_idx.?].priority;
}

fn normalizeRequestPath(request_uri: []const u8) []const u8 {
    const query_start = std.mem.indexOfScalar(u8, request_uri, '?') orelse request_uri.len;
    const fragment_start = std.mem.indexOfScalar(u8, request_uri[0..query_start], '#') orelse query_start;
    return request_uri[0..fragment_start];
}

test "exact match beats prefix match" {
    const blocks = [_]LocationBlock{
        .{
            .match_type = .prefix,
            .pattern = "/stat",
            .priority = 0,
            .action = .{ .proxy_pass = "" },
        },
        .{
            .match_type = .exact,
            .pattern = "/status",
            .priority = 1,
            .action = .{ .return_response = .{ .status = 200, .body = "" } },
        },
    };

    const matched = matchLocation("/status", &blocks).?;
    try std.testing.expectEqual(@as(usize, 1), matched.index);
}

test "longest prefix priority beats regex and prefix" {
    const blocks = [_]LocationBlock{
        .{
            .match_type = .regex,
            .pattern = "^/api/(.*)$",
            .priority = 0,
            .action = .{ .proxy_pass = "http://regex" },
        },
        .{
            .match_type = .prefix,
            .pattern = "/api/",
            .priority = 1,
            .action = .{ .proxy_pass = "http://prefix" },
        },
        .{
            .match_type = .prefix_priority,
            .pattern = "/api/private/",
            .priority = 2,
            .action = .{ .proxy_pass = "http://priority" },
        },
    };

    const matched = matchLocation("/api/private/users", &blocks).?;
    try std.testing.expectEqual(@as(usize, 2), matched.index);
}

test "first regex match wins when no priority prefix exists" {
    const blocks = [_]LocationBlock{
        .{
            .match_type = .regex,
            .pattern = "^/api/(.*)$",
            .priority = 0,
            .action = .{ .proxy_pass = "http://regex-1" },
        },
        .{
            .match_type = .regex,
            .pattern = "^/api/users/(.*)$",
            .priority = 1,
            .action = .{ .proxy_pass = "http://regex-2" },
        },
    };

    const matched = matchLocation("/api/users/42", &blocks).?;
    try std.testing.expectEqual(@as(usize, 0), matched.index);
}

test "case insensitive regex matches request path without query" {
    const blocks = [_]LocationBlock{
        .{
            .match_type = .regex_case_insensitive,
            .pattern = "^/assets/[a-z]+\\.css$",
            .priority = 0,
            .action = .{ .static_root = .{
                .root = "/srv/www",
                .alias = false,
                .autoindex = false,
                .index = "index.html",
                .try_files = "$uri",
            } },
        },
    };

    const matched = matchLocation("/Assets/SITE.css?v=1", &blocks).?;
    try std.testing.expectEqual(@as(usize, 0), matched.index);
    try std.testing.expectEqualStrings("/Assets/SITE.css", matched.matched_path);
}

test "longest plain prefix wins when no exact priority or regex matches" {
    const blocks = [_]LocationBlock{
        .{
            .match_type = .prefix,
            .pattern = "/",
            .priority = 0,
            .action = .{ .static_root = .{
                .root = "/srv/www",
                .alias = false,
                .autoindex = false,
                .index = "index.html",
                .try_files = "",
            } },
        },
        .{
            .match_type = .prefix,
            .pattern = "/images/",
            .priority = 1,
            .action = .{ .static_root = .{
                .root = "/srv/images",
                .alias = true,
                .autoindex = false,
                .index = "",
                .try_files = "",
            } },
        },
    };

    const matched = matchLocation("/images/logo.png", &blocks).?;
    try std.testing.expectEqual(@as(usize, 1), matched.index);
}

test "equal length prefixes keep first configured block" {
    const blocks = [_]LocationBlock{
        .{
            .match_type = .prefix,
            .pattern = "/api",
            .priority = 0,
            .action = .{ .proxy_pass = "http://first" },
        },
        .{
            .match_type = .prefix,
            .pattern = "/api",
            .priority = 1,
            .action = .{ .proxy_pass = "http://second" },
        },
    };

    const matched = matchLocation("/api/users", &blocks).?;
    try std.testing.expectEqual(@as(usize, 0), matched.index);
}
