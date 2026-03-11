const std = @import("std");
const c = @cImport({
    @cInclude("regex.h");
});

pub const RewriteFlag = enum {
    last,
    @"break",
    redirect,
    permanent,

    pub fn parse(raw: []const u8) ?RewriteFlag {
        if (std.ascii.eqlIgnoreCase(raw, "last")) return .last;
        if (std.ascii.eqlIgnoreCase(raw, "break")) return .@"break";
        if (std.ascii.eqlIgnoreCase(raw, "redirect")) return .redirect;
        if (std.ascii.eqlIgnoreCase(raw, "permanent")) return .permanent;
        return null;
    }
};

pub const RewriteRule = struct {
    method: []const u8, // "*" means any method
    pattern: []const u8, // POSIX extended regex
    replacement: []const u8,
    flag: RewriteFlag,
};

pub const ReturnRule = struct {
    method: []const u8, // "*" means any method
    pattern: []const u8, // POSIX extended regex
    status: u16,
    body: []const u8,
};

pub const ConditionalVariable = enum {
    request_uri,
    http_host,
    args,

    pub fn parse(raw: []const u8) ?ConditionalVariable {
        if (std.ascii.eqlIgnoreCase(raw, "request_uri")) return .request_uri;
        if (std.ascii.eqlIgnoreCase(raw, "http_host")) return .http_host;
        if (std.ascii.eqlIgnoreCase(raw, "args")) return .args;
        return null;
    }
};

pub const ConditionalAction = union(enum) {
    rewrite: struct {
        replacement: []const u8,
        flag: RewriteFlag,
    },
    returned: struct {
        status: u16,
        body: []const u8,
    },
};

pub const ConditionalRule = struct {
    variable: ConditionalVariable,
    case_insensitive: bool,
    pattern: []const u8,
    action: ConditionalAction,
};

pub const Outcome = union(enum) {
    pass: []const u8,
    redirect: struct { status: u16, location: []const u8 },
    returned: struct { status: u16, body: []const u8 },

    pub fn deinit(self: *Outcome, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .pass => |path| allocator.free(path),
            .redirect => |r| allocator.free(r.location),
            .returned => |r| allocator.free(r.body),
        }
        self.* = undefined;
    }
};

const NamedCapture = struct {
    name: []u8,
    index: usize,
};

const PreparedPattern = struct {
    allocator: std.mem.Allocator,
    normalized_pattern: []u8,
    named_captures: []NamedCapture,

    fn deinit(self: *PreparedPattern) void {
        self.allocator.free(self.normalized_pattern);
        for (self.named_captures) |entry| self.allocator.free(entry.name);
        self.allocator.free(self.named_captures);
        self.* = undefined;
    }
};

pub fn methodMatches(rule_method: []const u8, method: []const u8) bool {
    return std.mem.eql(u8, rule_method, "*") or std.ascii.eqlIgnoreCase(rule_method, method);
}

pub fn regexMatches(pattern: []const u8, input: []const u8) bool {
    return regexMatchesOptions(pattern, input, false);
}

pub fn regexMatchesOptions(pattern: []const u8, input: []const u8, case_insensitive: bool) bool {
    const allocator = std.heap.page_allocator;
    var prepared = preparePattern(allocator, pattern) catch return false;
    defer prepared.deinit();

    const pattern_z = allocator.alloc(u8, prepared.normalized_pattern.len + 1) catch return false;
    defer allocator.free(pattern_z);
    @memcpy(pattern_z[0..prepared.normalized_pattern.len], prepared.normalized_pattern);
    pattern_z[prepared.normalized_pattern.len] = 0;

    const input_z = allocator.alloc(u8, input.len + 1) catch return false;
    defer allocator.free(input_z);
    @memcpy(input_z[0..input.len], input);
    input_z[input.len] = 0;

    var regex: c.regex_t = undefined;
    const compile_flags = c.REG_EXTENDED | c.REG_NOSUB | if (case_insensitive) @as(c_int, c.REG_ICASE) else 0;
    const compile_rc = c.regcomp(&regex, pattern_z.ptr, compile_flags);
    if (compile_rc != 0) return false;
    defer _ = c.regfree(&regex);
    return c.regexec(&regex, input_z.ptr, 0, null, 0) == 0;
}

pub fn evaluate(
    allocator: std.mem.Allocator,
    method: []const u8,
    path: []const u8,
    request_uri: []const u8,
    rewrite_rules: []const RewriteRule,
    return_rules: []const ReturnRule,
) !Outcome {
    var current = try allocator.dupe(u8, path);
    errdefer allocator.free(current);
    var loops: usize = 0;

    while (loops < 8) : (loops += 1) {
        var did_last_rewrite = false;
        for (rewrite_rules) |rule| {
            if (!methodMatches(rule.method, method)) continue;
            const replacement = try regexReplace(allocator, rule.pattern, current, request_uri, rule.replacement, false) orelse continue;

            switch (rule.flag) {
                .redirect => {
                    allocator.free(current);
                    return .{ .redirect = .{ .status = 302, .location = replacement } };
                },
                .permanent => {
                    allocator.free(current);
                    return .{ .redirect = .{ .status = 301, .location = replacement } };
                },
                .@"break" => {
                    allocator.free(current);
                    current = replacement;
                    break;
                },
                .last => {
                    allocator.free(current);
                    current = replacement;
                    did_last_rewrite = true;
                    break;
                },
            }
        }
        if (!did_last_rewrite) break;
    }

    for (return_rules) |rule| {
        if (!methodMatches(rule.method, method)) continue;
        const body = try regexReplace(allocator, rule.pattern, current, request_uri, rule.body, false) orelse continue;
        allocator.free(current);
        return .{ .returned = .{ .status = rule.status, .body = body } };
    }
    return .{ .pass = current };
}

pub fn substitutePattern(
    allocator: std.mem.Allocator,
    pattern: []const u8,
    input: []const u8,
    request_uri: []const u8,
    replacement: []const u8,
    case_insensitive: bool,
) !?[]u8 {
    return regexReplace(allocator, pattern, input, request_uri, replacement, case_insensitive);
}

fn regexReplace(
    allocator: std.mem.Allocator,
    pattern: []const u8,
    input: []const u8,
    request_uri: []const u8,
    replacement: []const u8,
    case_insensitive: bool,
) !?[]u8 {
    var prepared = try preparePattern(allocator, pattern);
    defer prepared.deinit();

    const pattern_z = try allocator.alloc(u8, prepared.normalized_pattern.len + 1);
    defer allocator.free(pattern_z);
    @memcpy(pattern_z[0..prepared.normalized_pattern.len], prepared.normalized_pattern);
    pattern_z[prepared.normalized_pattern.len] = 0;

    const input_z = try allocator.alloc(u8, input.len + 1);
    defer allocator.free(input_z);
    @memcpy(input_z[0..input.len], input);
    input_z[input.len] = 0;

    var regex: c.regex_t = undefined;
    const compile_flags = c.REG_EXTENDED | if (case_insensitive) @as(c_int, c.REG_ICASE) else 0;
    const compile_rc = c.regcomp(&regex, pattern_z.ptr, compile_flags);
    if (compile_rc != 0) return null;
    defer _ = c.regfree(&regex);

    var captures: [10]c.regmatch_t = undefined;
    if (c.regexec(&regex, input_z.ptr, captures.len, &captures, 0) != 0) return null;

    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    var i: usize = 0;
    while (i < replacement.len) : (i += 1) {
        if (replacement[i] != '$' or i + 1 >= replacement.len) {
            try out.append(replacement[i]);
            continue;
        }

        if (std.mem.startsWith(u8, replacement[i..], "$request_uri")) {
            try out.appendSlice(request_uri);
            i += "$request_uri".len - 1;
            continue;
        }
        if (std.mem.startsWith(u8, replacement[i..], "$uri")) {
            try out.appendSlice(input);
            i += "$uri".len - 1;
            continue;
        }

        const next = replacement[i + 1];
        if (next >= '0' and next <= '9') {
            const capture_index: usize = next - '0';
            try appendCapture(&out, input, &captures, capture_index);
            i += 1;
            continue;
        }
        if ((std.ascii.isAlphabetic(next) or next == '_')) {
            var end = i + 1;
            while (end < replacement.len and (std.ascii.isAlphanumeric(replacement[end]) or replacement[end] == '_')) : (end += 1) {}
            const capture_name = replacement[i + 1 .. end];
            if (namedCaptureIndex(prepared.named_captures, capture_name)) |capture_index| {
                try appendCapture(&out, input, &captures, capture_index);
                i = end - 1;
                continue;
            }
        }

        try out.append(replacement[i]);
    }
    const result = try out.toOwnedSlice();
    return result;
}

fn preparePattern(allocator: std.mem.Allocator, pattern: []const u8) !PreparedPattern {
    var normalized = std.ArrayList(u8).init(allocator);
    errdefer normalized.deinit();
    var named = std.ArrayList(NamedCapture).init(allocator);
    errdefer {
        for (named.items) |entry| allocator.free(entry.name);
        named.deinit();
    }

    var capture_index: usize = 0;
    var i: usize = 0;
    var in_class = false;
    while (i < pattern.len) : (i += 1) {
        if (pattern[i] == '\\') {
            try normalized.append(pattern[i]);
            if (i + 1 < pattern.len) {
                i += 1;
                try normalized.append(pattern[i]);
            }
            continue;
        }
        if (pattern[i] == '[') in_class = true;
        if (pattern[i] == ']' and in_class) in_class = false;

        if (!in_class and std.mem.startsWith(u8, pattern[i..], "(?P<")) {
            const name_start = i + "(?P<".len;
            const name_end = std.mem.indexOfScalarPos(u8, pattern, name_start, '>') orelse return error.InvalidNamedCapture;
            capture_index += 1;
            try named.append(.{
                .name = try allocator.dupe(u8, pattern[name_start..name_end]),
                .index = capture_index,
            });
            try normalized.append('(');
            i = name_end;
            continue;
        }
        if (!in_class and pattern[i] == '(') {
            capture_index += 1;
        }
        try normalized.append(pattern[i]);
    }

    return .{
        .allocator = allocator,
        .normalized_pattern = try normalized.toOwnedSlice(),
        .named_captures = try named.toOwnedSlice(),
    };
}

fn namedCaptureIndex(named_captures: []const NamedCapture, name: []const u8) ?usize {
    for (named_captures) |entry| {
        if (std.mem.eql(u8, entry.name, name)) return entry.index;
    }
    return null;
}

fn appendCapture(
    out: *std.ArrayList(u8),
    input: []const u8,
    captures: []const c.regmatch_t,
    capture_index: usize,
) !void {
    if (capture_index >= captures.len) return;
    if (captures[capture_index].rm_so < 0 or captures[capture_index].rm_eo < captures[capture_index].rm_so) return;
    const start: usize = @intCast(captures[capture_index].rm_so);
    const end: usize = @intCast(captures[capture_index].rm_eo);
    try out.appendSlice(input[start..end]);
}

test "parse rewrite flag aliases" {
    try std.testing.expectEqual(RewriteFlag.last, RewriteFlag.parse("last").?);
    try std.testing.expectEqual(RewriteFlag.@"break", RewriteFlag.parse("break").?);
    try std.testing.expectEqual(RewriteFlag.redirect, RewriteFlag.parse("redirect").?);
    try std.testing.expectEqual(RewriteFlag.permanent, RewriteFlag.parse("permanent").?);
    try std.testing.expect(RewriteFlag.parse("invalid") == null);
}

test "regexMatches supports simple pattern" {
    try std.testing.expect(regexMatches("^/api/messages$", "/api/messages"));
    try std.testing.expect(!regexMatches("^/api/messages$", "/api/tasks"));
}

test "regexMatchesOptions supports case-insensitive matches" {
    try std.testing.expect(regexMatchesOptions("^example\\.com$", "Example.COM", true));
    try std.testing.expect(!regexMatchesOptions("^example\\.com$", "Example.COM", false));
}

test "evaluate applies rewrite and return rules" {
    const rewrites = [_]RewriteRule{
        .{ .method = "GET", .pattern = "^/old$", .replacement = "/new", .flag = .last },
    };
    const returns = [_]ReturnRule{
        .{ .method = "GET", .pattern = "^/new$", .status = 204, .body = "" },
    };
    var out = try evaluate(std.testing.allocator, "GET", "/old", "/old", rewrites[0..], returns[0..]);
    defer out.deinit(std.testing.allocator);
    switch (out) {
        .returned => |r| {
            try std.testing.expectEqual(@as(u16, 204), r.status);
            try std.testing.expectEqualStrings("", r.body);
        },
        else => return error.UnexpectedTestResult,
    }
}

test "evaluate substitutes capture groups in rewrite replacement" {
    const rewrites = [_]RewriteRule{
        .{ .method = "GET", .pattern = "^/old/(.*)$", .replacement = "/new/$1", .flag = .@"break" },
    };
    var out = try evaluate(std.testing.allocator, "GET", "/old/page", "/old/page", rewrites[0..], &.{});
    defer out.deinit(std.testing.allocator);
    switch (out) {
        .pass => |path| try std.testing.expectEqualStrings("/new/page", path),
        else => return error.UnexpectedTestResult,
    }
}

test "evaluate returns redirect and permanent status codes" {
    const redirect_rules = [_]RewriteRule{
        .{ .method = "GET", .pattern = "^/temp/(.*)$", .replacement = "/dst/$1", .flag = .redirect },
        .{ .method = "GET", .pattern = "^/perm/(.*)$", .replacement = "/dst/$1", .flag = .permanent },
    };

    var temp = try evaluate(std.testing.allocator, "GET", "/temp/path", "/temp/path", redirect_rules[0..1], &.{});
    defer temp.deinit(std.testing.allocator);
    switch (temp) {
        .redirect => |r| {
            try std.testing.expectEqual(@as(u16, 302), r.status);
            try std.testing.expectEqualStrings("/dst/path", r.location);
        },
        else => return error.UnexpectedTestResult,
    }

    var perm = try evaluate(std.testing.allocator, "GET", "/perm/path", "/perm/path", redirect_rules[1..], &.{});
    defer perm.deinit(std.testing.allocator);
    switch (perm) {
        .redirect => |r| {
            try std.testing.expectEqual(@as(u16, 301), r.status);
            try std.testing.expectEqualStrings("/dst/path", r.location);
        },
        else => return error.UnexpectedTestResult,
    }
}

test "evaluate rewrites with last and rematches from top" {
    const rewrites = [_]RewriteRule{
        .{ .method = "GET", .pattern = "^/old/(.*)$", .replacement = "/mid/$1", .flag = .last },
        .{ .method = "GET", .pattern = "^/mid/(.*)$", .replacement = "/final/$1", .flag = .@"break" },
    };
    var out = try evaluate(std.testing.allocator, "GET", "/old/page", "/old/page", rewrites[0..], &.{});
    defer out.deinit(std.testing.allocator);
    switch (out) {
        .pass => |path| try std.testing.expectEqualStrings("/final/page", path),
        else => return error.UnexpectedTestResult,
    }
}

test "evaluate stops after first matching break rule" {
    const rewrites = [_]RewriteRule{
        .{ .method = "GET", .pattern = "^/old/(.*)$", .replacement = "/first/$1", .flag = .@"break" },
        .{ .method = "GET", .pattern = "^/first/(.*)$", .replacement = "/second/$1", .flag = .@"break" },
    };
    var out = try evaluate(std.testing.allocator, "GET", "/old/page", "/old/page", rewrites[0..], &.{});
    defer out.deinit(std.testing.allocator);
    switch (out) {
        .pass => |path| try std.testing.expectEqualStrings("/first/page", path),
        else => return error.UnexpectedTestResult,
    }
}

test "evaluate expands request_uri in return body" {
    const returns = [_]ReturnRule{
        .{ .method = "GET", .pattern = "^/old/(.*)$", .status = 301, .body = "https://example.com$request_uri" },
    };
    var out = try evaluate(std.testing.allocator, "GET", "/old/page", "/old/page?x=1", &.{}, returns[0..]);
    defer out.deinit(std.testing.allocator);
    switch (out) {
        .returned => |r| {
            try std.testing.expectEqual(@as(u16, 301), r.status);
            try std.testing.expectEqualStrings("https://example.com/old/page?x=1", r.body);
        },
        else => return error.UnexpectedTestResult,
    }
}

test "evaluate substitutes named capture groups in rewrite replacement" {
    const rewrites = [_]RewriteRule{
        .{ .method = "GET", .pattern = "^/user/(?P<id>[0-9]+)$", .replacement = "/profile/$id", .flag = .@"break" },
    };
    var out = try evaluate(std.testing.allocator, "GET", "/user/42", "/user/42", rewrites[0..], &.{});
    defer out.deinit(std.testing.allocator);
    switch (out) {
        .pass => |path| try std.testing.expectEqualStrings("/profile/42", path),
        else => return error.UnexpectedTestResult,
    }
}
