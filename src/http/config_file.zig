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
) !void {
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
) !void {
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
    const value_interp = try interpolate(allocator, std.mem.trim(u8, value_raw, " \t\"'"), vars);
    defer allocator.free(value_interp);
    const env_key = try normalizeDirectiveToEnv(allocator, directive);
    defer allocator.free(env_key);
    const key = try allocator.dupe(u8, env_key);
    const val = try allocator.dupe(u8, value_interp);
    if (overrides.map.fetchRemove(env_key)) |old| {
        allocator.free(old.key);
        allocator.free(old.value);
    }
    try overrides.map.put(key, val);
}

fn parseInclude(
    allocator: std.mem.Allocator,
    current_file_path: []const u8,
    include_path: []const u8,
    overrides: *Overrides,
    vars: *std.StringHashMap([]const u8),
    visited: *std.StringHashMap(void),
) !void {
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
