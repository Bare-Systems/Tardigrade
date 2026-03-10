const std = @import("std");

pub const Overrides = struct {
    map: std.StringHashMap([]const u8),

    pub fn init(allocator: std.mem.Allocator) Overrides {
        return .{ .map = std.StringHashMap([]const u8).init(allocator) };
    }

    pub fn deinit(self: *Overrides, allocator: std.mem.Allocator) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.map.deinit();
    }
};

pub fn loadOverrides(allocator: std.mem.Allocator) !Overrides {
    const cfg_path = std.process.getEnvVarOwned(allocator, "TARDIGRADE_CONFIG_PATH") catch {
        return Overrides.init(allocator);
    };
    defer allocator.free(cfg_path);

    var overrides = Overrides.init(allocator);
    errdefer overrides.deinit(allocator);

    var vars = std.StringHashMap([]const u8).init(allocator);
    defer {
        var it = vars.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        vars.deinit();
    }

    var visited = std.StringHashMap(void).init(allocator);
    defer {
        var it = visited.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        visited.deinit();
    }

    try parseFile(allocator, cfg_path, &overrides, &vars, &visited);
    return overrides;
}

fn parseFile(
    allocator: std.mem.Allocator,
    path: []const u8,
    overrides: *Overrides,
    vars: *std.StringHashMap([]const u8),
    visited: *std.StringHashMap(void),
) anyerror!void {
    const normalized = try normalizePath(allocator, path);
    defer allocator.free(normalized);
    if (visited.contains(normalized)) return;
    const owned_key = try allocator.dupe(u8, normalized);
    try visited.put(owned_key, {});

    const raw = try std.fs.cwd().readFileAlloc(allocator, normalized, 4 * 1024 * 1024);
    defer allocator.free(raw);

    var line_no: usize = 0;
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line_raw| {
        line_no += 1;
        const comment_idx = std.mem.indexOfScalar(u8, line_raw, '#') orelse line_raw.len;
        const line = std.mem.trim(u8, line_raw[0..comment_idx], " \t\r\n");
        if (line.len == 0) continue;
        if (line[line.len - 1] != ';') {
            std.log.err("config syntax error at {s}:{d}: missing ';'", .{ normalized, line_no });
            return error.InvalidConfigSyntax;
        }
        const stmt = std.mem.trimRight(u8, line[0 .. line.len - 1], " \t\r\n");
        try parseStatement(allocator, normalized, stmt, overrides, vars, visited, line_no);
    }
}

fn parseStatement(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    stmt: []const u8,
    overrides: *Overrides,
    vars: *std.StringHashMap([]const u8),
    visited: *std.StringHashMap(void),
    line_no: usize,
) anyerror!void {
    var it = std.mem.tokenizeAny(u8, stmt, " \t");
    const directive = it.next() orelse return;

    if (std.ascii.eqlIgnoreCase(directive, "include")) {
        const include_path_raw = it.rest();
        const include_path_interp = try interpolate(allocator, std.mem.trim(u8, include_path_raw, " \t\"'"), vars);
        defer allocator.free(include_path_interp);
        try parseInclude(allocator, file_path, include_path_interp, overrides, vars, visited);
        return;
    }

    if (std.ascii.eqlIgnoreCase(directive, "set")) {
        const var_name_raw = it.next() orelse return error.InvalidConfigSyntax;
        const var_value_raw = std.mem.trim(u8, it.rest(), " \t");
        if (var_name_raw.len < 2 or var_name_raw[0] != '$') {
            std.log.err("config syntax error at {s}:{d}: set requires $name", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        }
        const value_interp = try interpolate(allocator, std.mem.trim(u8, var_value_raw, " \t\"'"), vars);
        defer allocator.free(value_interp);
        const key = try allocator.dupe(u8, var_name_raw[1..]);
        const val = try allocator.dupe(u8, value_interp);
        if (vars.fetchRemove(var_name_raw[1..])) |old| {
            allocator.free(old.key);
            allocator.free(old.value);
        }
        try vars.put(key, val);
        return;
    }

    const value_raw = std.mem.trim(u8, it.rest(), " \t");
    if (value_raw.len == 0) {
        std.log.err("config syntax error at {s}:{d}: directive '{s}' missing value", .{ file_path, line_no, directive });
        return error.InvalidConfigSyntax;
    }
    const trimmed_value = std.mem.trim(u8, value_raw, " \t\"'");

    // Core directive aliases (phase 3.2)
    if (std.ascii.eqlIgnoreCase(directive, "worker_processes")) {
        const mapped = if (std.ascii.eqlIgnoreCase(trimmed_value, "auto")) "0" else trimmed_value;
        try putOverride(allocator, &overrides.map, "TARDIGRADE_WORKER_PROCESSES", mapped);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "worker_connections")) {
        try putOverride(allocator, &overrides.map, "TARDIGRADE_MAX_ACTIVE_CONNECTIONS", trimmed_value);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "pid")) {
        try putOverride(allocator, &overrides.map, "TARDIGRADE_PID_FILE", trimmed_value);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "user")) {
        var toks = std.mem.tokenizeAny(u8, trimmed_value, " \t");
        if (toks.next()) |user| try putOverride(allocator, &overrides.map, "TARDIGRADE_RUN_USER", user);
        if (toks.next()) |group| try putOverride(allocator, &overrides.map, "TARDIGRADE_RUN_GROUP", group);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "error_log")) {
        var toks = std.mem.tokenizeAny(u8, trimmed_value, " \t");
        if (toks.next()) |path| try putOverride(allocator, &overrides.map, "TARDIGRADE_ERROR_LOG_PATH", path);
        if (toks.next()) |level| try putOverride(allocator, &overrides.map, "TARDIGRADE_LOG_LEVEL", level);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "secrets_file")) {
        try putOverride(allocator, &overrides.map, "TARDIGRADE_SECRETS_PATH", trimmed_value);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "secret_key")) {
        try putOverride(allocator, &overrides.map, "TARDIGRADE_SECRET_KEYS", trimmed_value);
        return;
    }

    // HTTP-block style aliases (phase 3.3 foundation)
    if (std.ascii.eqlIgnoreCase(directive, "listen")) {
        try mapListenDirective(allocator, &overrides.map, trimmed_value);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "server_name")) {
        try putOverride(allocator, &overrides.map, "TARDIGRADE_SERVER_NAMES", trimmed_value);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "root")) {
        try putOverride(allocator, &overrides.map, "TARDIGRADE_DOC_ROOT", trimmed_value);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "try_files")) {
        try putOverride(allocator, &overrides.map, "TARDIGRADE_TRY_FILES", trimmed_value);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "fastcgi_pass")) {
        try putOverride(allocator, &overrides.map, "TARDIGRADE_FASTCGI_UPSTREAM", trimmed_value);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "scgi_pass")) {
        try putOverride(allocator, &overrides.map, "TARDIGRADE_SCGI_UPSTREAM", trimmed_value);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "uwsgi_pass")) {
        try putOverride(allocator, &overrides.map, "TARDIGRADE_UWSGI_UPSTREAM", trimmed_value);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "fastcgi_index")) {
        try putOverride(allocator, &overrides.map, "TARDIGRADE_FASTCGI_INDEX", trimmed_value);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "fastcgi_param")) {
        var toks = std.mem.tokenizeAny(u8, value_raw, " \t");
        const name = toks.next() orelse {
            std.log.err("config syntax error at {s}:{d}: fastcgi_param requires name and value", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        };
        const value_part_raw = std.mem.trim(u8, toks.rest(), " \t");
        if (value_part_raw.len == 0) {
            std.log.err("config syntax error at {s}:{d}: fastcgi_param requires name and value", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        }
        const value_part = try interpolate(allocator, std.mem.trim(u8, value_part_raw, "\"'"), vars);
        defer allocator.free(value_part);
        const entry = try std.fmt.allocPrint(allocator, "{s}={s}", .{ name, value_part });
        defer allocator.free(entry);
        try appendOverride(allocator, &overrides.map, "TARDIGRADE_FASTCGI_PARAMS", entry, "|");
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "rewrite")) {
        var toks = std.mem.tokenizeAny(u8, value_raw, " \t");
        const pattern = toks.next() orelse {
            std.log.err("config syntax error at {s}:{d}: rewrite requires pattern and replacement", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        };
        const replacement_raw = toks.next() orelse {
            std.log.err("config syntax error at {s}:{d}: rewrite requires pattern and replacement", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        };
        const flag = toks.next() orelse "last";
        if (toks.next() != null) {
            std.log.err("config syntax error at {s}:{d}: rewrite accepts at most one flag", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        }
        const replacement_interp = try interpolate(allocator, std.mem.trim(u8, replacement_raw, "\"'"), vars);
        defer allocator.free(replacement_interp);
        const entry = try std.fmt.allocPrint(allocator, "*|{s}|{s}|{s}", .{ pattern, replacement_interp, flag });
        defer allocator.free(entry);
        try appendOverride(allocator, &overrides.map, "TARDIGRADE_REWRITE_RULES", entry, ";");
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "return")) {
        var toks = std.mem.tokenizeAny(u8, value_raw, " \t");
        const status_raw = toks.next() orelse {
            std.log.err("config syntax error at {s}:{d}: return requires status", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        };
        const body_raw = std.mem.trim(u8, toks.rest(), " \t");
        const status = std.fmt.parseInt(u16, status_raw, 10) catch {
            std.log.err("config syntax error at {s}:{d}: invalid return status '{s}'", .{ file_path, line_no, status_raw });
            return error.InvalidConfigSyntax;
        };
        const body_interp = if (body_raw.len > 0)
            try interpolate(allocator, std.mem.trim(u8, body_raw, "\"'"), vars)
        else
            try allocator.dupe(u8, "");
        defer allocator.free(body_interp);
        const entry = try std.fmt.allocPrint(allocator, "*|^.*$|{d}|{s}", .{ status, body_interp });
        defer allocator.free(entry);
        try appendOverride(allocator, &overrides.map, "TARDIGRADE_RETURN_RULES", entry, ";");
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "if")) {
        const open_paren = std.mem.indexOfScalar(u8, value_raw, '(') orelse {
            std.log.err("config syntax error at {s}:{d}: if requires condition in parentheses", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        };
        const close_paren = std.mem.lastIndexOfScalar(u8, value_raw, ')') orelse {
            std.log.err("config syntax error at {s}:{d}: if requires closing ')'", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        };
        if (close_paren <= open_paren) {
            std.log.err("config syntax error at {s}:{d}: invalid if condition", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        }
        const condition_raw = std.mem.trim(u8, value_raw[open_paren + 1 .. close_paren], " \t");
        const action_stmt = std.mem.trim(u8, value_raw[close_paren + 1 ..], " \t");
        if (action_stmt.len == 0) {
            std.log.err("config syntax error at {s}:{d}: if requires inline action", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        }

        var cond_toks = std.mem.tokenizeAny(u8, condition_raw, " \t");
        const variable_raw = cond_toks.next() orelse return error.InvalidConfigSyntax;
        const operator_raw = cond_toks.next() orelse return error.InvalidConfigSyntax;
        const pattern_raw = std.mem.trim(u8, cond_toks.rest(), " \t");
        if (variable_raw.len < 2 or variable_raw[0] != '$' or pattern_raw.len == 0) {
            std.log.err("config syntax error at {s}:{d}: invalid if condition", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        }
        const variable_name = variable_raw[1..];
        const sensitivity = if (std.mem.eql(u8, operator_raw, "~*"))
            "ci"
        else if (std.mem.eql(u8, operator_raw, "~"))
            "cs"
        else {
            std.log.err("config syntax error at {s}:{d}: unsupported if operator '{s}'", .{ file_path, line_no, operator_raw });
            return error.InvalidConfigSyntax;
        };
        const pattern_interp = try interpolate(allocator, std.mem.trim(u8, pattern_raw, "\"'"), vars);
        defer allocator.free(pattern_interp);

        var action_toks = std.mem.tokenizeAny(u8, action_stmt, " \t");
        const action_name = action_toks.next() orelse return error.InvalidConfigSyntax;
        if (std.ascii.eqlIgnoreCase(action_name, "return")) {
            const status_raw = action_toks.next() orelse {
                std.log.err("config syntax error at {s}:{d}: if return requires status", .{ file_path, line_no });
                return error.InvalidConfigSyntax;
            };
            const body_raw = std.mem.trim(u8, action_toks.rest(), " \t");
            const status = std.fmt.parseInt(u16, status_raw, 10) catch {
                std.log.err("config syntax error at {s}:{d}: invalid if return status '{s}'", .{ file_path, line_no, status_raw });
                return error.InvalidConfigSyntax;
            };
            const body_interp = if (body_raw.len > 0)
                try interpolate(allocator, std.mem.trim(u8, body_raw, "\"'"), vars)
            else
                try allocator.dupe(u8, "");
            defer allocator.free(body_interp);
            const entry = try std.fmt.allocPrint(allocator, "{s}|{s}|{s}|return|{d}|{s}", .{
                variable_name,
                sensitivity,
                pattern_interp,
                status,
                body_interp,
            });
            defer allocator.free(entry);
            try appendOverride(allocator, &overrides.map, "TARDIGRADE_CONDITIONAL_RULES", entry, ";");
            return;
        }
        if (std.ascii.eqlIgnoreCase(action_name, "rewrite")) {
            const replacement_raw = action_toks.next() orelse {
                std.log.err("config syntax error at {s}:{d}: if rewrite requires replacement", .{ file_path, line_no });
                return error.InvalidConfigSyntax;
            };
            const flag = action_toks.next() orelse "last";
            if (action_toks.next() != null) {
                std.log.err("config syntax error at {s}:{d}: if rewrite accepts at most one flag", .{ file_path, line_no });
                return error.InvalidConfigSyntax;
            }
            const replacement_interp = try interpolate(allocator, std.mem.trim(u8, replacement_raw, "\"'"), vars);
            defer allocator.free(replacement_interp);
            const entry = try std.fmt.allocPrint(allocator, "{s}|{s}|{s}|rewrite|{s}|{s}", .{
                variable_name,
                sensitivity,
                pattern_interp,
                replacement_interp,
                flag,
            });
            defer allocator.free(entry);
            try appendOverride(allocator, &overrides.map, "TARDIGRADE_CONDITIONAL_RULES", entry, ";");
            return;
        }
        std.log.err("config syntax error at {s}:{d}: unsupported if action '{s}'", .{ file_path, line_no, action_name });
        return error.InvalidConfigSyntax;
    }

    const value_interp = try interpolate(allocator, trimmed_value, vars);
    defer allocator.free(value_interp);
    const env_key = try normalizeDirectiveToEnv(allocator, directive);
    defer allocator.free(env_key);
    try putOverride(allocator, &overrides.map, env_key, value_interp);
}

fn putOverride(allocator: std.mem.Allocator, map: *std.StringHashMap([]const u8), key_raw: []const u8, value_raw: []const u8) !void {
    const key = try allocator.dupe(u8, key_raw);
    errdefer allocator.free(key);
    const val = try allocator.dupe(u8, value_raw);
    errdefer allocator.free(val);
    if (map.fetchRemove(key_raw)) |old| {
        allocator.free(old.key);
        allocator.free(old.value);
    }
    try map.put(key, val);
}

fn appendOverride(
    allocator: std.mem.Allocator,
    map: *std.StringHashMap([]const u8),
    key_raw: []const u8,
    value_raw: []const u8,
    separator: []const u8,
) !void {
    if (map.get(key_raw)) |existing| {
        const joined = try std.fmt.allocPrint(allocator, "{s}{s}{s}", .{ existing, separator, value_raw });
        defer allocator.free(joined);
        try putOverride(allocator, map, key_raw, joined);
        return;
    }
    try putOverride(allocator, map, key_raw, value_raw);
}

fn mapListenDirective(allocator: std.mem.Allocator, map: *std.StringHashMap([]const u8), raw: []const u8) !void {
    var it = std.mem.tokenizeAny(u8, raw, " \t");
    const addr = it.next() orelse return;
    if (std.mem.indexOfScalar(u8, addr, ':')) |colon| {
        const host = addr[0..colon];
        const port = addr[colon + 1 ..];
        if (host.len > 0) try putOverride(allocator, map, "TARDIGRADE_LISTEN_HOST", host);
        if (port.len > 0) try putOverride(allocator, map, "TARDIGRADE_LISTEN_PORT", port);
    } else {
        const as_int = std.fmt.parseInt(u16, addr, 10) catch null;
        if (as_int != null) {
            try putOverride(allocator, map, "TARDIGRADE_LISTEN_PORT", addr);
        } else {
            try putOverride(allocator, map, "TARDIGRADE_LISTEN_HOST", addr);
        }
    }
    while (it.next()) |flag| {
        if (std.ascii.eqlIgnoreCase(flag, "http2")) try putOverride(allocator, map, "TARDIGRADE_HTTP2_ENABLED", "true");
    }
}

fn parseInclude(
    allocator: std.mem.Allocator,
    current_file_path: []const u8,
    include_path: []const u8,
    overrides: *Overrides,
    vars: *std.StringHashMap([]const u8),
    visited: *std.StringHashMap(void),
) anyerror!void {
    const resolved = try resolveIncludePath(allocator, current_file_path, include_path);
    defer allocator.free(resolved);

    if (std.mem.indexOfScalar(u8, resolved, '*')) |star| {
        const slash = std.mem.lastIndexOfScalar(u8, resolved[0..star], '/') orelse return error.InvalidIncludePattern;
        const dir_path = resolved[0..slash];
        const pattern = resolved[slash + 1 ..];
        const suffix = if (std.mem.startsWith(u8, pattern, "*")) pattern[1..] else "";
        var dir = try std.fs.cwd().openDir(dir_path, .{ .iterate = true });
        defer dir.close();
        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .file) continue;
            if (suffix.len > 0 and !std.mem.endsWith(u8, entry.name, suffix)) continue;
            const child = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir_path, entry.name });
            defer allocator.free(child);
            try parseFile(allocator, child, overrides, vars, visited);
        }
        return;
    }

    try parseFile(allocator, resolved, overrides, vars, visited);
}

fn normalizeDirectiveToEnv(allocator: std.mem.Allocator, directive: []const u8) ![]u8 {
    if (std.mem.startsWith(u8, directive, "TARDIGRADE_")) {
        const out = try allocator.dupe(u8, directive);
        for (out) |*ch| ch.* = std.ascii.toUpper(ch.*);
        return out;
    }

    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try out.appendSlice("TARDIGRADE_");
    for (directive) |ch| {
        const c = if (ch == '-') '_' else ch;
        try out.append(std.ascii.toUpper(c));
    }
    return out.toOwnedSlice();
}

fn interpolate(allocator: std.mem.Allocator, raw: []const u8, vars: *std.StringHashMap([]const u8)) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    var i: usize = 0;
    while (i < raw.len) {
        if (raw[i] == '$' and i + 1 < raw.len and raw[i + 1] == '{') {
            const end = std.mem.indexOfScalarPos(u8, raw, i + 2, '}') orelse return error.InvalidVariableInterpolation;
            const key = raw[i + 2 .. end];
            if (vars.get(key)) |value| {
                try out.appendSlice(value);
            } else {
                const env_value = std.process.getEnvVarOwned(allocator, key) catch "";
                defer if (env_value.len > 0) allocator.free(env_value);
                try out.appendSlice(env_value);
            }
            i = end + 1;
            continue;
        }
        try out.append(raw[i]);
        i += 1;
    }
    return out.toOwnedSlice();
}

fn resolveIncludePath(allocator: std.mem.Allocator, current_file: []const u8, include_path: []const u8) ![]u8 {
    if (std.fs.path.isAbsolute(include_path)) return allocator.dupe(u8, include_path);
    const dir = std.fs.path.dirname(current_file) orelse ".";
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir, include_path });
}

fn normalizePath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    if (std.fs.path.isAbsolute(path)) return allocator.dupe(u8, path);
    return std.fmt.allocPrint(allocator, "./{s}", .{path});
}

test "normalize directive name to env key" {
    const allocator = std.testing.allocator;
    const key = try normalizeDirectiveToEnv(allocator, "listen_port");
    defer allocator.free(key);
    try std.testing.expectEqualStrings("TARDIGRADE_LISTEN_PORT", key);
}

test "interpolate replaces known vars" {
    const allocator = std.testing.allocator;
    var vars = std.StringHashMap([]const u8).init(allocator);
    defer {
        var it = vars.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        vars.deinit();
    }
    try vars.put(try allocator.dupe(u8, "base"), try allocator.dupe(u8, "/srv"));
    const out = try interpolate(allocator, "${base}/app", &vars);
    defer allocator.free(out);
    try std.testing.expectEqualStrings("/srv/app", out);
}

test "listen directive mapping" {
    const allocator = std.testing.allocator;
    var map = std.StringHashMap([]const u8).init(allocator);
    defer {
        var it = map.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        map.deinit();
    }

    try mapListenDirective(allocator, &map, "127.0.0.1:9443 http2");
    try std.testing.expectEqualStrings("127.0.0.1", map.get("TARDIGRADE_LISTEN_HOST").?);
    try std.testing.expectEqualStrings("9443", map.get("TARDIGRADE_LISTEN_PORT").?);
    try std.testing.expectEqualStrings("true", map.get("TARDIGRADE_HTTP2_ENABLED").?);
}

test "backend protocol directives map to explicit upstream env keys" {
    const allocator = std.testing.allocator;
    var overrides = Overrides.init(allocator);
    defer overrides.deinit(allocator);
    var vars = std.StringHashMap([]const u8).init(allocator);
    defer vars.deinit();
    var visited = std.StringHashMap(void).init(allocator);
    defer visited.deinit();

    try parseStatement(allocator, "test.conf", "fastcgi_pass unix:/tmp/php-fpm.sock", &overrides, &vars, &visited, 1);
    try parseStatement(allocator, "test.conf", "scgi_pass 127.0.0.1:4100", &overrides, &vars, &visited, 2);
    try parseStatement(allocator, "test.conf", "uwsgi_pass 127.0.0.1:4200", &overrides, &vars, &visited, 3);
    try parseStatement(allocator, "test.conf", "fastcgi_index index.php", &overrides, &vars, &visited, 4);

    try std.testing.expectEqualStrings("unix:/tmp/php-fpm.sock", overrides.map.get("TARDIGRADE_FASTCGI_UPSTREAM").?);
    try std.testing.expectEqualStrings("127.0.0.1:4100", overrides.map.get("TARDIGRADE_SCGI_UPSTREAM").?);
    try std.testing.expectEqualStrings("127.0.0.1:4200", overrides.map.get("TARDIGRADE_UWSGI_UPSTREAM").?);
    try std.testing.expectEqualStrings("index.php", overrides.map.get("TARDIGRADE_FASTCGI_INDEX").?);
}

test "fastcgi_param directives accumulate into fastcgi params env" {
    const allocator = std.testing.allocator;
    var overrides = Overrides.init(allocator);
    defer overrides.deinit(allocator);
    var vars = std.StringHashMap([]const u8).init(allocator);
    defer {
        var it = vars.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        vars.deinit();
    }
    var visited = std.StringHashMap(void).init(allocator);
    defer visited.deinit();
    try vars.put(try allocator.dupe(u8, "app_env"), try allocator.dupe(u8, "staging"));

    try parseStatement(allocator, "test.conf", "fastcgi_param APP_ENV ${app_env}", &overrides, &vars, &visited, 1);
    try parseStatement(allocator, "test.conf", "fastcgi_param APP_ROLE api", &overrides, &vars, &visited, 2);

    try std.testing.expectEqualStrings("APP_ENV=staging|APP_ROLE=api", overrides.map.get("TARDIGRADE_FASTCGI_PARAMS").?);
}

test "rewrite directives accumulate into rewrite rules env" {
    const allocator = std.testing.allocator;
    var overrides = Overrides.init(allocator);
    defer overrides.deinit(allocator);
    var vars = std.StringHashMap([]const u8).init(allocator);
    defer vars.deinit();
    var visited = std.StringHashMap(void).init(allocator);
    defer visited.deinit();

    try parseStatement(allocator, "test.conf", "rewrite ^/old/(.*)$ /$1 last", &overrides, &vars, &visited, 1);
    try parseStatement(allocator, "test.conf", "rewrite ^/temp$ /redirect redirect", &overrides, &vars, &visited, 2);

    try std.testing.expectEqualStrings(
        "*|^/old/(.*)$|/$1|last;*|^/temp$|/redirect|redirect",
        overrides.map.get("TARDIGRADE_REWRITE_RULES").?,
    );
}

test "return directives accumulate into return rules env" {
    const allocator = std.testing.allocator;
    var overrides = Overrides.init(allocator);
    defer overrides.deinit(allocator);
    var vars = std.StringHashMap([]const u8).init(allocator);
    defer vars.deinit();
    var visited = std.StringHashMap(void).init(allocator);
    defer visited.deinit();

    try parseStatement(allocator, "test.conf", "return 301 https://example.com$request_uri", &overrides, &vars, &visited, 1);
    try parseStatement(allocator, "test.conf", "return 204", &overrides, &vars, &visited, 2);

    try std.testing.expectEqualStrings(
        "*|^.*$|301|https://example.com$request_uri;*|^.*$|204|",
        overrides.map.get("TARDIGRADE_RETURN_RULES").?,
    );
}

test "if directives accumulate into conditional rules env" {
    const allocator = std.testing.allocator;
    var overrides = Overrides.init(allocator);
    defer overrides.deinit(allocator);
    var vars = std.StringHashMap([]const u8).init(allocator);
    defer vars.deinit();
    var visited = std.StringHashMap(void).init(allocator);
    defer visited.deinit();

    try parseStatement(allocator, "test.conf", "if ($request_uri ~* ^/legacy/(.*)$) rewrite /$1 last", &overrides, &vars, &visited, 1);
    try parseStatement(allocator, "test.conf", "if ($http_host ~* ^admin\\.example\\.com$) return 301 https://example.com$request_uri", &overrides, &vars, &visited, 2);

    try std.testing.expectEqualStrings(
        "request_uri|ci|^/legacy/(.*)$|rewrite|/$1|last;http_host|ci|^admin\\.example\\.com$|return|301|https://example.com$request_uri",
        overrides.map.get("TARDIGRADE_CONDITIONAL_RULES").?,
    );
}
