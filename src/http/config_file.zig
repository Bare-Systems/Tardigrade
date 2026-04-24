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

const BlockContext = union(enum) {
    passthrough,
    server: ServerBlockBuilder,
    location: LocationBlockBuilder,
};

const server_block_record_sep = "\x1e";
const server_block_field_sep = "\x1f";

const LocationBlockBuilder = struct {
    const ErrorPageBuilder = struct {
        status_codes_csv: []u8,
        target: []u8,
    };

    match_type: []u8,
    pattern: []u8,
    proxy_pass: ?[]u8 = null,
    fastcgi_pass: ?[]u8 = null,
    scgi_pass: ?[]u8 = null,
    uwsgi_pass: ?[]u8 = null,
    root: ?[]u8 = null,
    alias: ?[]u8 = null,
    autoindex: ?bool = null,
    index: ?[]u8 = null,
    try_files: ?[]u8 = null,
    return_status: ?u16 = null,
    return_body: ?[]u8 = null,
    rewrite_replacement: ?[]u8 = null,
    rewrite_flag: ?[]u8 = null,
    auth: ?[]u8 = null,
    error_pages: std.ArrayListUnmanaged(ErrorPageBuilder) = .{},

    fn deinit(self: *LocationBlockBuilder, allocator: std.mem.Allocator) void {
        allocator.free(self.match_type);
        allocator.free(self.pattern);
        if (self.proxy_pass) |value| allocator.free(value);
        if (self.fastcgi_pass) |value| allocator.free(value);
        if (self.scgi_pass) |value| allocator.free(value);
        if (self.uwsgi_pass) |value| allocator.free(value);
        if (self.root) |value| allocator.free(value);
        if (self.alias) |value| allocator.free(value);
        if (self.index) |value| allocator.free(value);
        if (self.try_files) |value| allocator.free(value);
        if (self.return_body) |value| allocator.free(value);
        if (self.rewrite_replacement) |value| allocator.free(value);
        if (self.rewrite_flag) |value| allocator.free(value);
        if (self.auth) |value| allocator.free(value);
        for (self.error_pages.items) |entry| {
            allocator.free(entry.status_codes_csv);
            allocator.free(entry.target);
        }
        self.error_pages.deinit(allocator);
        self.* = undefined;
    }
};

const ServerBlockBuilder = struct {
    server_names: ?[]u8 = null,
    doc_root: ?[]u8 = null,
    try_files: ?[]u8 = null,
    tls_cert_path: ?[]u8 = null,
    tls_key_path: ?[]u8 = null,
    upstream_base_url: ?[]u8 = null,
    proxy_pass_chat: ?[]u8 = null,
    proxy_pass_commands_prefix: ?[]u8 = null,
    location_entries: std.ArrayListUnmanaged([]u8) = .{},

    fn deinit(self: *ServerBlockBuilder, allocator: std.mem.Allocator) void {
        if (self.server_names) |value| allocator.free(value);
        if (self.doc_root) |value| allocator.free(value);
        if (self.try_files) |value| allocator.free(value);
        if (self.tls_cert_path) |value| allocator.free(value);
        if (self.tls_key_path) |value| allocator.free(value);
        if (self.upstream_base_url) |value| allocator.free(value);
        if (self.proxy_pass_chat) |value| allocator.free(value);
        if (self.proxy_pass_commands_prefix) |value| allocator.free(value);
        for (self.location_entries.items) |entry| allocator.free(entry);
        self.location_entries.deinit(allocator);
        self.* = undefined;
    }
};

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
    var blocks = std.ArrayList(BlockContext).init(allocator);
    defer {
        for (blocks.items) |*block| {
            switch (block.*) {
                .passthrough => {},
                .server => |*builder| builder.deinit(allocator),
                .location => |*builder| builder.deinit(allocator),
            }
        }
        blocks.deinit();
    }
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line_raw| {
        line_no += 1;
        const comment_idx = std.mem.indexOfScalar(u8, line_raw, '#') orelse line_raw.len;
        const line = std.mem.trim(u8, line_raw[0..comment_idx], " \t\r\n");
        if (line.len == 0) continue;
        if (std.mem.eql(u8, line, "}")) {
            if (blocks.items.len == 0) {
                std.log.err("config syntax error at {s}:{d}: unexpected '}}'", .{ normalized, line_no });
                return error.InvalidConfigSyntax;
            }
            const block = blocks.pop().?;
            switch (block) {
                .passthrough => {},
                .server => |builder| {
                    var owned_builder = builder;
                    defer owned_builder.deinit(allocator);
                    try flushServerBlock(allocator, overrides, &owned_builder);
                },
                .location => |builder| {
                    var owned_builder = builder;
                    defer owned_builder.deinit(allocator);
                    if (blocks.items.len > 0) {
                        switch (blocks.items[blocks.items.len - 1]) {
                            .server => |*server_builder| {
                                const entry = try buildLocationBlockEntry(allocator, &owned_builder);
                                errdefer allocator.free(entry);
                                try server_builder.location_entries.append(allocator, entry);
                            },
                            else => try flushLocationBlock(allocator, overrides, &owned_builder),
                        }
                    } else {
                        try flushLocationBlock(allocator, overrides, &owned_builder);
                    }
                },
            }
            continue;
        }
        if (line[line.len - 1] == '{') {
            const header = std.mem.trimRight(u8, line[0 .. line.len - 1], " \t\r\n");
            if (std.ascii.eqlIgnoreCase(header, "server")) {
                try blocks.append(.{ .server = .{} });
            } else if (std.mem.startsWith(u8, header, "location")) {
                const builder = try parseLocationHeader(allocator, normalized, header, line_no);
                try blocks.append(.{ .location = builder });
            } else {
                try blocks.append(.passthrough);
            }
            continue;
        }
        if (line[line.len - 1] != ';') {
            std.log.err("config syntax error at {s}:{d}: missing ';'", .{ normalized, line_no });
            return error.InvalidConfigSyntax;
        }
        const stmt = std.mem.trimRight(u8, line[0 .. line.len - 1], " \t\r\n");
        if (blocks.items.len > 0) {
            switch (blocks.items[blocks.items.len - 1]) {
                .passthrough => try parseStatement(allocator, normalized, stmt, overrides, vars, visited, line_no),
                .server => |*builder| try parseServerStatement(allocator, normalized, stmt, builder, vars, line_no),
                .location => |*builder| try parseLocationStatement(allocator, normalized, stmt, builder, vars, line_no),
            }
        } else {
            try parseStatement(allocator, normalized, stmt, overrides, vars, visited, line_no);
        }
    }

    if (blocks.items.len != 0) {
        std.log.err("config syntax error at {s}:{d}: unterminated block", .{ normalized, line_no });
        return error.InvalidConfigSyntax;
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
    if (std.ascii.eqlIgnoreCase(directive, "smtp_pass")) {
        try putOverride(allocator, &overrides.map, "TARDIGRADE_SMTP_UPSTREAM", trimmed_value);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "imap_pass")) {
        try putOverride(allocator, &overrides.map, "TARDIGRADE_IMAP_UPSTREAM", trimmed_value);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "pop3_pass")) {
        try putOverride(allocator, &overrides.map, "TARDIGRADE_POP3_UPSTREAM", trimmed_value);
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

fn parseServerStatement(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    stmt: []const u8,
    builder: *ServerBlockBuilder,
    vars: *std.StringHashMap([]const u8),
    line_no: usize,
) !void {
    var it = std.mem.tokenizeAny(u8, stmt, " \t");
    const directive = it.next() orelse return;
    const value_raw = std.mem.trim(u8, it.rest(), " \t");
    if (value_raw.len == 0) {
        std.log.err("config syntax error at {s}:{d}: directive '{s}' missing value", .{ file_path, line_no, directive });
        return error.InvalidConfigSyntax;
    }
    const value_interp = try interpolate(allocator, std.mem.trim(u8, value_raw, " \t\"'"), vars);
    defer allocator.free(value_interp);

    if (std.ascii.eqlIgnoreCase(directive, "server_name")) {
        try replaceOptionalOwned(allocator, &builder.server_names, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "root")) {
        try replaceOptionalOwned(allocator, &builder.doc_root, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "try_files")) {
        try replaceOptionalOwned(allocator, &builder.try_files, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "tls_cert_path")) {
        try replaceOptionalOwned(allocator, &builder.tls_cert_path, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "tls_key_path")) {
        try replaceOptionalOwned(allocator, &builder.tls_key_path, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "upstream_base_url")) {
        try replaceOptionalOwned(allocator, &builder.upstream_base_url, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "proxy_pass_chat")) {
        try replaceOptionalOwned(allocator, &builder.proxy_pass_chat, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "proxy_pass_commands_prefix")) {
        try replaceOptionalOwned(allocator, &builder.proxy_pass_commands_prefix, value_interp);
        return;
    }
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

fn parseLocationHeader(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    header: []const u8,
    line_no: usize,
) !LocationBlockBuilder {
    const rest = std.mem.trim(u8, header["location".len..], " \t");
    if (rest.len == 0) {
        std.log.err("config syntax error at {s}:{d}: location requires matcher", .{ file_path, line_no });
        return error.InvalidConfigSyntax;
    }

    var match_type: []const u8 = "prefix";
    var pattern: []const u8 = rest;
    if (std.mem.startsWith(u8, rest, "= ")) {
        match_type = "exact";
        pattern = std.mem.trim(u8, rest[2..], " \t");
    } else if (std.mem.startsWith(u8, rest, "^~ ")) {
        match_type = "prefix_priority";
        pattern = std.mem.trim(u8, rest[3..], " \t");
    } else if (std.mem.startsWith(u8, rest, "~* ")) {
        match_type = "regex_case_insensitive";
        pattern = std.mem.trim(u8, rest[3..], " \t");
    } else if (std.mem.startsWith(u8, rest, "~ ")) {
        match_type = "regex";
        pattern = std.mem.trim(u8, rest[2..], " \t");
    }

    if (pattern.len == 0) {
        std.log.err("config syntax error at {s}:{d}: location requires pattern", .{ file_path, line_no });
        return error.InvalidConfigSyntax;
    }

    return .{
        .match_type = try allocator.dupe(u8, match_type),
        .pattern = try allocator.dupe(u8, pattern),
    };
}

fn parseLocationStatement(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    stmt: []const u8,
    builder: *LocationBlockBuilder,
    vars: *std.StringHashMap([]const u8),
    line_no: usize,
) !void {
    var it = std.mem.tokenizeAny(u8, stmt, " \t");
    const directive = it.next() orelse return;
    const value_raw = std.mem.trim(u8, it.rest(), " \t");
    if (value_raw.len == 0) {
        std.log.err("config syntax error at {s}:{d}: directive '{s}' missing value", .{ file_path, line_no, directive });
        return error.InvalidConfigSyntax;
    }
    const trimmed_value = std.mem.trim(u8, value_raw, " \t\"'");
    const value_interp = try interpolate(allocator, trimmed_value, vars);
    defer allocator.free(value_interp);

    if (std.ascii.eqlIgnoreCase(directive, "proxy_pass")) {
        try replaceOptionalOwned(allocator, &builder.proxy_pass, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "fastcgi_pass")) {
        try replaceOptionalOwned(allocator, &builder.fastcgi_pass, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "scgi_pass")) {
        try replaceOptionalOwned(allocator, &builder.scgi_pass, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "uwsgi_pass")) {
        try replaceOptionalOwned(allocator, &builder.uwsgi_pass, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "root")) {
        try replaceOptionalOwned(allocator, &builder.root, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "alias")) {
        try replaceOptionalOwned(allocator, &builder.alias, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "index")) {
        try replaceOptionalOwned(allocator, &builder.index, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "autoindex")) {
        builder.autoindex = parseOnOffBool(value_interp) orelse return error.InvalidConfigSyntax;
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "try_files")) {
        try replaceOptionalOwned(allocator, &builder.try_files, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "error_page")) {
        var toks = std.mem.tokenizeAny(u8, value_raw, " \t");
        var status_codes = std.ArrayList([]const u8).init(allocator);
        defer status_codes.deinit();
        var target_raw: ?[]const u8 = null;
        while (toks.next()) |token| {
            if (std.mem.startsWith(u8, token, "/") or std.mem.startsWith(u8, token, "http://") or std.mem.startsWith(u8, token, "https://")) {
                target_raw = token;
                break;
            }
            _ = std.fmt.parseInt(u16, token, 10) catch return error.InvalidConfigSyntax;
            try status_codes.append(token);
        }
        const target_token = target_raw orelse return error.InvalidConfigSyntax;
        if (status_codes.items.len == 0) return error.InvalidConfigSyntax;
        if (toks.next() != null) return error.InvalidConfigSyntax;

        const target_interp = try interpolate(allocator, std.mem.trim(u8, target_token, "\"'"), vars);
        defer allocator.free(target_interp);

        const codes_csv = try std.mem.join(allocator, ",", status_codes.items);
        errdefer allocator.free(codes_csv);
        try builder.error_pages.append(allocator, .{
            .status_codes_csv = codes_csv,
            .target = try allocator.dupe(u8, target_interp),
        });
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "return")) {
        var toks = std.mem.tokenizeAny(u8, value_raw, " \t");
        const status_raw = toks.next() orelse return error.InvalidConfigSyntax;
        const body_raw = std.mem.trim(u8, toks.rest(), " \t");
        builder.return_status = std.fmt.parseInt(u16, status_raw, 10) catch {
            std.log.err("config syntax error at {s}:{d}: invalid return status '{s}'", .{ file_path, line_no, status_raw });
            return error.InvalidConfigSyntax;
        };
        const body_interp = if (body_raw.len > 0)
            try interpolate(allocator, std.mem.trim(u8, body_raw, "\"'"), vars)
        else
            try allocator.dupe(u8, "");
        defer allocator.free(body_interp);
        try replaceOptionalOwned(allocator, &builder.return_body, body_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "rewrite")) {
        var toks = std.mem.tokenizeAny(u8, value_raw, " \t");
        _ = toks.next() orelse return error.InvalidConfigSyntax;
        const replacement_raw = toks.next() orelse return error.InvalidConfigSyntax;
        const flag_raw = toks.next() orelse "last";
        if (toks.next() != null) return error.InvalidConfigSyntax;
        const replacement_interp = try interpolate(allocator, std.mem.trim(u8, replacement_raw, "\"'"), vars);
        defer allocator.free(replacement_interp);
        try replaceOptionalOwned(allocator, &builder.rewrite_replacement, replacement_interp);
        try replaceOptionalOwned(allocator, &builder.rewrite_flag, flag_raw);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "auth")) {
        if (!std.ascii.eqlIgnoreCase(value_interp, "required") and !std.ascii.eqlIgnoreCase(value_interp, "off")) {
            std.log.err("config syntax error at {s}:{d}: auth must be 'required' or 'off'", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        }
        try replaceOptionalOwned(allocator, &builder.auth, value_interp);
        return;
    }
}

fn buildLocationBlockEntry(allocator: std.mem.Allocator, builder: *LocationBlockBuilder) ![]u8 {
    var entry = if (builder.proxy_pass) |target|
        try std.fmt.allocPrint(allocator, "{s}|{s}|proxy_pass|{s}", .{ builder.match_type, builder.pattern, target })
    else if (builder.fastcgi_pass) |target|
        try std.fmt.allocPrint(allocator, "{s}|{s}|fastcgi_pass|{s}", .{ builder.match_type, builder.pattern, target })
    else if (builder.scgi_pass) |target|
        try std.fmt.allocPrint(allocator, "{s}|{s}|proxy_pass|scgi:{s}", .{ builder.match_type, builder.pattern, target })
    else if (builder.uwsgi_pass) |target|
        try std.fmt.allocPrint(allocator, "{s}|{s}|proxy_pass|uwsgi:{s}", .{ builder.match_type, builder.pattern, target })
    else if (builder.return_status) |status|
        try std.fmt.allocPrint(allocator, "{s}|{s}|return|{d}|{s}", .{ builder.match_type, builder.pattern, status, builder.return_body orelse "" })
    else if (builder.root != null or builder.alias != null or builder.index != null or builder.try_files != null or builder.autoindex != null)
        try std.fmt.allocPrint(
            allocator,
            "{s}|{s}|static_root|{s}|{s}|{s}|{s}|{s}",
            .{
                builder.match_type,
                builder.pattern,
                builder.alias orelse builder.root orelse "",
                if (builder.alias != null) "on" else "off",
                if (builder.autoindex orelse false) "on" else "off",
                builder.index orelse "",
                builder.try_files orelse "",
            },
        )
    else if (builder.rewrite_replacement) |replacement|
        try std.fmt.allocPrint(allocator, "{s}|{s}|rewrite|{s}|{s}", .{
            builder.match_type,
            builder.pattern,
            replacement,
            builder.rewrite_flag orelse "last",
        })
    else
        return error.InvalidConfigSyntax;

    if (builder.auth) |auth_mode| {
        if (!std.ascii.eqlIgnoreCase(auth_mode, "off")) {
            const with_auth = try std.fmt.allocPrint(allocator, "{s}|auth:{s}", .{ entry, auth_mode });
            allocator.free(entry);
            entry = with_auth;
        }
    }
    return entry;
}

fn flushLocationBlock(allocator: std.mem.Allocator, overrides: *Overrides, builder: *LocationBlockBuilder) !void {
    const entry = buildLocationBlockEntry(allocator, builder) catch |err| switch (err) {
        error.InvalidConfigSyntax => return,
        else => return err,
    };
    defer allocator.free(entry);
    try appendOverride(allocator, &overrides.map, "TARDIGRADE_LOCATION_BLOCKS", entry, ";");

    for (builder.error_pages.items) |rule| {
        const error_entry = try std.fmt.allocPrint(allocator, "{s}|{s}|{s}|{s}", .{
            builder.match_type,
            builder.pattern,
            rule.status_codes_csv,
            rule.target,
        });
        defer allocator.free(error_entry);
        try appendOverride(allocator, &overrides.map, "TARDIGRADE_LOCATION_ERROR_PAGES", error_entry, ";");
    }
}

fn flushServerBlock(allocator: std.mem.Allocator, overrides: *Overrides, builder: *ServerBlockBuilder) !void {
    var location_blob = std.ArrayList(u8).init(allocator);
    defer location_blob.deinit();
    for (builder.location_entries.items, 0..) |entry, idx| {
        if (idx != 0) try location_blob.append(';');
        try location_blob.appendSlice(entry);
    }
    const record = try std.fmt.allocPrint(
        allocator,
        "{s}{s}{s}{s}{s}{s}{s}{s}{s}{s}{s}{s}{s}{s}{s}{s}{s}",
        .{
            builder.server_names orelse "",
            server_block_field_sep,
            builder.doc_root orelse "",
            server_block_field_sep,
            builder.try_files orelse "",
            server_block_field_sep,
            builder.tls_cert_path orelse "",
            server_block_field_sep,
            builder.tls_key_path orelse "",
            server_block_field_sep,
            builder.upstream_base_url orelse "",
            server_block_field_sep,
            builder.proxy_pass_chat orelse "",
            server_block_field_sep,
            builder.proxy_pass_commands_prefix orelse "",
            server_block_field_sep,
            location_blob.items,
        },
    );
    defer allocator.free(record);
    try appendOverride(allocator, &overrides.map, "TARDIGRADE_SERVER_BLOCKS", record, server_block_record_sep);
}

fn replaceOptionalOwned(allocator: std.mem.Allocator, target: *?[]u8, value: []const u8) !void {
    if (target.*) |existing| allocator.free(existing);
    target.* = try allocator.dupe(u8, value);
}

fn parseOnOffBool(raw: []const u8) ?bool {
    if (std.ascii.eqlIgnoreCase(raw, "on")) return true;
    if (std.ascii.eqlIgnoreCase(raw, "off")) return false;
    if (std.ascii.eqlIgnoreCase(raw, "true")) return true;
    if (std.ascii.eqlIgnoreCase(raw, "false")) return false;
    return null;
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
    defer {
        var it = visited.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        visited.deinit();
    }

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
    defer {
        var it = visited.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        visited.deinit();
    }
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
    defer {
        var it = visited.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        visited.deinit();
    }

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
    defer {
        var it = visited.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        visited.deinit();
    }

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
    defer {
        var it = visited.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        visited.deinit();
    }

    try parseStatement(allocator, "test.conf", "if ($request_uri ~* ^/legacy/(.*)$) rewrite /$1 last", &overrides, &vars, &visited, 1);
    try parseStatement(allocator, "test.conf", "if ($http_host ~* ^admin\\.example\\.com$) return 301 https://example.com$request_uri", &overrides, &vars, &visited, 2);

    try std.testing.expectEqualStrings(
        "request_uri|ci|^/legacy/(.*)$|rewrite|/$1|last;http_host|ci|^admin\\.example\\.com$|return|301|https://example.com$request_uri",
        overrides.map.get("TARDIGRADE_CONDITIONAL_RULES").?,
    );
}

test "location blocks accumulate into location block env" {
    const allocator = std.testing.allocator;
    var cfg_dir = std.testing.tmpDir(.{});
    defer cfg_dir.cleanup();

    try cfg_dir.dir.writeFile(.{
        .sub_path = "location.conf",
        .data =
        \\location = /health {
        \\    return 200 ok;
        \\}
        \\location ^~ /api/private/ {
        \\    proxy_pass http://127.0.0.1:9001;
        \\}
        \\location ~* ^/assets/.*$ {
        \\    root /srv/www;
        \\    index index.html;
        \\    try_files $uri /index.html;
        \\}
        ,
    });

    const cwd = std.fs.cwd();
    const absolute = try cfg_dir.dir.realpathAlloc(allocator, "location.conf");
    defer allocator.free(absolute);

    var overrides = Overrides.init(allocator);
    defer overrides.deinit(allocator);
    var vars = std.StringHashMap([]const u8).init(allocator);
    defer vars.deinit();
    var visited = std.StringHashMap(void).init(allocator);
    defer {
        var it = visited.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        visited.deinit();
    }

    _ = cwd;
    try parseFile(allocator, absolute, &overrides, &vars, &visited);

    try std.testing.expectEqualStrings(
        "exact|/health|return|200|ok;prefix_priority|/api/private/|proxy_pass|http://127.0.0.1:9001;regex_case_insensitive|^/assets/.*$|static_root|/srv/www|off|off|index.html|$uri /index.html",
        overrides.map.get("TARDIGRADE_LOCATION_BLOCKS").?,
    );
}

test "location block supports alias and fastcgi pass serialization" {
    const allocator = std.testing.allocator;
    var cfg_dir = std.testing.tmpDir(.{});
    defer cfg_dir.cleanup();

    try cfg_dir.dir.writeFile(.{
        .sub_path = "location-fastcgi.conf",
        .data =
        \\location /php/ {
        \\    fastcgi_pass unix:/tmp/php-fpm.sock;
        \\}
        \\location /images/ {
        \\    alias /srv/images;
        \\    index home.html;
        \\}
        ,
    });

    const absolute = try cfg_dir.dir.realpathAlloc(allocator, "location-fastcgi.conf");
    defer allocator.free(absolute);

    var overrides = Overrides.init(allocator);
    defer overrides.deinit(allocator);
    var vars = std.StringHashMap([]const u8).init(allocator);
    defer vars.deinit();
    var visited = std.StringHashMap(void).init(allocator);
    defer {
        var it = visited.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        visited.deinit();
    }

    try parseFile(allocator, absolute, &overrides, &vars, &visited);

    try std.testing.expectEqualStrings(
        "prefix|/php/|fastcgi_pass|unix:/tmp/php-fpm.sock;prefix|/images/|static_root|/srv/images|on|off|home.html|",
        overrides.map.get("TARDIGRADE_LOCATION_BLOCKS").?,
    );
}

test "location block supports error_page serialization" {
    const allocator = std.testing.allocator;
    var cfg_dir = std.testing.tmpDir(.{});
    defer cfg_dir.cleanup();

    try cfg_dir.dir.writeFile(.{
        .sub_path = "location-error-page.conf",
        .data =
        \\location / {
        \\    root /srv/www;
        \\    error_page 404 /errors/404.html;
        \\    error_page 500 502 503 504 https://example.com/50x;
        \\}
        ,
    });

    const absolute = try cfg_dir.dir.realpathAlloc(allocator, "location-error-page.conf");
    defer allocator.free(absolute);

    var overrides = Overrides.init(allocator);
    defer overrides.deinit(allocator);
    var vars = std.StringHashMap([]const u8).init(allocator);
    defer vars.deinit();
    var visited = std.StringHashMap(void).init(allocator);
    defer {
        var it = visited.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        visited.deinit();
    }

    try parseFile(allocator, absolute, &overrides, &vars, &visited);

    try std.testing.expectEqualStrings(
        "prefix|/|404|/errors/404.html;prefix|/|500,502,503,504|https://example.com/50x",
        overrides.map.get("TARDIGRADE_LOCATION_ERROR_PAGES").?,
    );
}

test "server block supports nested location serialization" {
    const allocator = std.testing.allocator;
    var cfg_dir = std.testing.tmpDir(.{});
    defer cfg_dir.cleanup();

    try cfg_dir.dir.writeFile(.{
        .sub_path = "server-block.conf",
        .data =
        \\server {
        \\    server_name api.example.test;
        \\    root /srv/api;
        \\    try_files $uri /index.html;
        \\    tls_cert_path /certs/api.crt;
        \\    tls_key_path /certs/api.key;
        \\    location / {
        \\        proxy_pass http://127.0.0.1:9101;
        \\    }
        \\}
        ,
    });

    const absolute = try cfg_dir.dir.realpathAlloc(allocator, "server-block.conf");
    defer allocator.free(absolute);

    var overrides = Overrides.init(allocator);
    defer overrides.deinit(allocator);
    var vars = std.StringHashMap([]const u8).init(allocator);
    defer vars.deinit();
    var visited = std.StringHashMap(void).init(allocator);
    defer {
        var it = visited.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        visited.deinit();
    }

    try parseFile(allocator, absolute, &overrides, &vars, &visited);

    const expected = "api.example.test" ++
        server_block_field_sep ++ "/srv/api" ++
        server_block_field_sep ++ "$uri /index.html" ++
        server_block_field_sep ++ "/certs/api.crt" ++
        server_block_field_sep ++ "/certs/api.key" ++
        server_block_field_sep ++ "" ++
        server_block_field_sep ++ "" ++
        server_block_field_sep ++ "" ++
        server_block_field_sep ++ "prefix|/|proxy_pass|http://127.0.0.1:9101";
    try std.testing.expectEqualStrings(expected, overrides.map.get("TARDIGRADE_SERVER_BLOCKS").?);
}
