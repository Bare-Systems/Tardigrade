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

pub const Outcome = union(enum) {
    pass: []const u8,
    redirect: struct { status: u16, location: []const u8 },
    returned: struct { status: u16, body: []const u8 },
};

pub fn methodMatches(rule_method: []const u8, method: []const u8) bool {
    return std.mem.eql(u8, rule_method, "*") or std.ascii.eqlIgnoreCase(rule_method, method);
}

pub fn regexMatches(pattern: []const u8, input: []const u8) bool {
    var regex: c.regex_t = undefined;
    const compile_rc = c.regcomp(&regex, pattern.ptr, c.REG_EXTENDED | c.REG_NOSUB);
    if (compile_rc != 0) return false;
    defer _ = c.regfree(&regex);
    return c.regexec(&regex, input.ptr, 0, null, 0) == 0;
}

pub fn evaluate(
    method: []const u8,
    path: []const u8,
    rewrite_rules: []const RewriteRule,
    return_rules: []const ReturnRule,
) Outcome {
    var current = path;
    var loops: usize = 0;

    while (loops < 8) : (loops += 1) {
        var did_last_rewrite = false;
        for (rewrite_rules) |rule| {
            if (!methodMatches(rule.method, method)) continue;
            if (!regexMatches(rule.pattern, current)) continue;

            switch (rule.flag) {
                .redirect => return .{ .redirect = .{ .status = 302, .location = rule.replacement } },
                .permanent => return .{ .redirect = .{ .status = 301, .location = rule.replacement } },
                .@"break" => {
                    current = rule.replacement;
                    break;
                },
                .last => {
                    current = rule.replacement;
                    did_last_rewrite = true;
                    break;
                },
            }
        }
        if (!did_last_rewrite) break;
    }

    for (return_rules) |rule| {
        if (!methodMatches(rule.method, method)) continue;
        if (!regexMatches(rule.pattern, current)) continue;
        return .{ .returned = .{ .status = rule.status, .body = rule.body } };
    }
    return .{ .pass = current };
}

test "parse rewrite flag aliases" {
    try std.testing.expectEqual(RewriteFlag.last, RewriteFlag.parse("last").?);
    try std.testing.expectEqual(RewriteFlag.@"break", RewriteFlag.parse("break").?);
    try std.testing.expectEqual(RewriteFlag.redirect, RewriteFlag.parse("redirect").?);
    try std.testing.expectEqual(RewriteFlag.permanent, RewriteFlag.parse("permanent").?);
    try std.testing.expect(RewriteFlag.parse("invalid") == null);
}

test "regexMatches supports simple pattern" {
    try std.testing.expect(regexMatches("^/v1/chat$", "/v1/chat"));
    try std.testing.expect(!regexMatches("^/v1/chat$", "/v1/commands"));
}

test "evaluate applies rewrite and return rules" {
    const rewrites = [_]RewriteRule{
        .{ .method = "GET", .pattern = "^/old$", .replacement = "/new", .flag = .last },
    };
    const returns = [_]ReturnRule{
        .{ .method = "GET", .pattern = "^/new$", .status = 204, .body = "" },
    };
    const out = evaluate("GET", "/old", rewrites[0..], returns[0..]);
    switch (out) {
        .returned => |r| {
            try std.testing.expectEqual(@as(u16, 204), r.status);
            try std.testing.expectEqualStrings("", r.body);
        },
        else => return error.UnexpectedTestResult,
    }
}
