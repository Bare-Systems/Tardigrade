const std = @import("std");
const builtin = @import("builtin");
const compat = @import("zig_compat");
const location_router = @import("location_router.zig");
const response_stream_lifecycle = @import("response_stream_lifecycle.zig");
const http_headers = @import("headers.zig");

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
    const cfg_path = compat.getEnvVarOwned(allocator, "TARDIGRADE_CONFIG_PATH") catch {
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

/// One parsed `proxy_set_header NAME VALUE;` (#809), owned by its builder.
const ProxySetHeaderBuilder = struct {
    name: []u8,
    value: []u8,
};

fn deinitProxySetHeaders(allocator: std.mem.Allocator, list: *std.ArrayList(ProxySetHeaderBuilder)) void {
    for (list.items) |rule| {
        allocator.free(rule.name);
        allocator.free(rule.value);
    }
    list.deinit(allocator);
}

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
    proxy_streaming: ?[]u8 = null,
    early_data: ?[]u8 = null,
    proxy_early_data: ?[]u8 = null,
    forward_auth: ?[]u8 = null,
    forward_auth_upstream_headers: ?[]u8 = null,
    forward_auth_client_headers: ?[]u8 = null,
    forward_auth_body: ?usize = null,
    forward_auth_timeout_ms: ?u32 = null,
    forward_auth_failure_status: ?u16 = null,
    proxy_websocket: ?bool = null,
    proxy_websocket_idle_timeout_ms: ?u32 = null,
    proxy_websocket_max_lifetime_ms: ?u32 = null,
    proxy_websocket_origins: ?[]u8 = null,
    proxy_websocket_reload: ?location_router.WebSocketReloadPolicy = null,
    proxy_websocket_reload_timeout_ms: ?u32 = null,
    proxy_response_stream_reload: ?response_stream_lifecycle.ReloadPolicy = null,
    proxy_response_stream_reload_timeout_ms: ?u32 = null,
    error_pages: std.ArrayList(ErrorPageBuilder) = .empty,
    proxy_set_headers: std.ArrayList(ProxySetHeaderBuilder) = .empty,

    fn actionKind(self: *const LocationBlockBuilder) ?[]const u8 {
        if (self.proxy_pass != null) return "proxy_pass";
        if (self.fastcgi_pass != null) return "fastcgi_pass";
        if (self.scgi_pass != null) return "scgi_pass";
        if (self.uwsgi_pass != null) return "uwsgi_pass";
        if (self.return_status != null) return "return";
        if (self.root != null or self.alias != null or self.autoindex != null or self.index != null or self.try_files != null) return "static";
        if (self.rewrite_replacement != null) return "rewrite";
        return null;
    }

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
        if (self.proxy_streaming) |value| allocator.free(value);
        if (self.early_data) |value| allocator.free(value);
        if (self.proxy_early_data) |value| allocator.free(value);
        if (self.forward_auth) |value| allocator.free(value);
        if (self.forward_auth_upstream_headers) |value| allocator.free(value);
        if (self.forward_auth_client_headers) |value| allocator.free(value);
        if (self.proxy_websocket_origins) |value| allocator.free(value);
        for (self.error_pages.items) |entry| {
            allocator.free(entry.status_codes_csv);
            allocator.free(entry.target);
        }
        self.error_pages.deinit(allocator);
        deinitProxySetHeaders(allocator, &self.proxy_set_headers);
        self.* = undefined;
    }
};

const ServerLocationEntry = struct {
    entry: []u8,
    /// A `proxy_pass` location with no `proxy_set_header` of its own takes the
    /// server block's rules; one with any rule replaces them (nginx's rule).
    inherits_proxy_set_headers: bool,
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
    location_entries: std.ArrayList(ServerLocationEntry) = .empty,
    proxy_set_headers: std.ArrayList(ProxySetHeaderBuilder) = .empty,

    fn deinit(self: *ServerBlockBuilder, allocator: std.mem.Allocator) void {
        if (self.server_names) |value| allocator.free(value);
        if (self.doc_root) |value| allocator.free(value);
        if (self.try_files) |value| allocator.free(value);
        if (self.tls_cert_path) |value| allocator.free(value);
        if (self.tls_key_path) |value| allocator.free(value);
        if (self.upstream_base_url) |value| allocator.free(value);
        if (self.proxy_pass_chat) |value| allocator.free(value);
        if (self.proxy_pass_commands_prefix) |value| allocator.free(value);
        for (self.location_entries.items) |location| allocator.free(location.entry);
        self.location_entries.deinit(allocator);
        deinitProxySetHeaders(allocator, &self.proxy_set_headers);
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

    const raw = try compat.cwd().readFileAlloc(allocator, normalized, 4 * 1024 * 1024);
    defer allocator.free(raw);

    var line_no: usize = 0;
    var blocks = std.ArrayList(BlockContext).empty;
    defer {
        for (blocks.items) |*block| {
            switch (block.*) {
                .passthrough => {},
                .server => |*builder| builder.deinit(allocator),
                .location => |*builder| builder.deinit(allocator),
            }
        }
        blocks.deinit(allocator);
    }
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line_raw| {
        line_no += 1;
        const comment_idx = std.mem.findScalar(u8, line_raw, '#') orelse line_raw.len;
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
                                try server_builder.location_entries.append(allocator, .{
                                    .entry = entry,
                                    .inherits_proxy_set_headers = owned_builder.proxy_pass != null and owned_builder.proxy_set_headers.items.len == 0,
                                });
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
            const header = compat.trimRight(u8, line[0 .. line.len - 1], " \t\r\n");
            if (std.ascii.eqlIgnoreCase(header, "server")) {
                try blocks.append(allocator, .{ .server = .{} });
            } else if (std.mem.startsWith(u8, header, "location")) {
                const builder = try parseLocationHeader(allocator, normalized, header, line_no);
                try blocks.append(allocator, .{ .location = builder });
            } else {
                try blocks.append(allocator, .passthrough);
            }
            continue;
        }
        if (line[line.len - 1] != ';') {
            std.log.err("config syntax error at {s}:{d}: missing ';'", .{ normalized, line_no });
            return error.InvalidConfigSyntax;
        }
        const stmt = compat.trimRight(u8, line[0 .. line.len - 1], " \t\r\n");
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

    if (std.ascii.eqlIgnoreCase(directive, "proxy_set_header")) {
        logConfigSyntaxDiagnostic("config syntax error at {s}:{d}: proxy_set_header is only supported inside server and location blocks", .{ file_path, line_no });
        return error.InvalidConfigSyntax;
    }

    const value_raw = std.mem.trim(u8, it.rest(), " \t");
    if (value_raw.len == 0) {
        std.log.err("config syntax error at {s}:{d}: directive '{s}' missing value", .{ file_path, line_no, directive });
        return error.InvalidConfigSyntax;
    }
    const trimmed_value = std.mem.trim(u8, value_raw, " \t\"'");
    try rejectEmptyStrictValue(allocator, file_path, line_no, directive, trimmed_value, vars);

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
    if (std.ascii.eqlIgnoreCase(directive, "tls_server_name")) {
        try putOverride(allocator, &overrides.map, "TARDIGRADE_TLS_SERVER_NAME", trimmed_value);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "tls_cert_path")) {
        try putOverride(allocator, &overrides.map, "TARDIGRADE_TLS_CERT_PATH", trimmed_value);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "tls_key_path")) {
        try putOverride(allocator, &overrides.map, "TARDIGRADE_TLS_KEY_PATH", trimmed_value);
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
        const open_paren = std.mem.findScalar(u8, value_raw, '(') orelse {
            std.log.err("config syntax error at {s}:{d}: if requires condition in parentheses", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        };
        const close_paren = std.mem.findScalarLast(u8, value_raw, ')') orelse {
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
    if (std.ascii.eqlIgnoreCase(directive, "proxy_set_header")) {
        try parseProxySetHeader(allocator, file_path, line_no, value_raw, vars, &builder.proxy_set_headers);
        return;
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
    if (std.ascii.eqlIgnoreCase(directive, "proxy_set_header")) {
        try parseProxySetHeader(allocator, file_path, line_no, value_raw, vars, &builder.proxy_set_headers);
        return;
    }
    const trimmed_value = std.mem.trim(u8, value_raw, " \t\"'");
    const value_interp = try interpolate(allocator, trimmed_value, vars);
    defer allocator.free(value_interp);

    if (std.ascii.eqlIgnoreCase(directive, "proxy_pass")) {
        try ensureLocationActionAllowed(file_path, line_no, builder, "proxy_pass");
        try replaceOptionalOwned(allocator, &builder.proxy_pass, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "fastcgi_pass")) {
        try ensureLocationActionAllowed(file_path, line_no, builder, "fastcgi_pass");
        try replaceOptionalOwned(allocator, &builder.fastcgi_pass, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "scgi_pass")) {
        try ensureLocationActionAllowed(file_path, line_no, builder, "scgi_pass");
        try replaceOptionalOwned(allocator, &builder.scgi_pass, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "uwsgi_pass")) {
        try ensureLocationActionAllowed(file_path, line_no, builder, "uwsgi_pass");
        try replaceOptionalOwned(allocator, &builder.uwsgi_pass, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "root")) {
        try ensureLocationActionAllowed(file_path, line_no, builder, "static");
        try replaceOptionalOwned(allocator, &builder.root, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "alias")) {
        try ensureLocationActionAllowed(file_path, line_no, builder, "static");
        try replaceOptionalOwned(allocator, &builder.alias, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "index")) {
        try ensureLocationActionAllowed(file_path, line_no, builder, "static");
        try replaceOptionalOwned(allocator, &builder.index, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "autoindex")) {
        try ensureLocationActionAllowed(file_path, line_no, builder, "static");
        builder.autoindex = parseOnOffBool(value_interp) orelse return error.InvalidConfigSyntax;
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "try_files")) {
        try ensureLocationActionAllowed(file_path, line_no, builder, "static");
        try replaceOptionalOwned(allocator, &builder.try_files, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "error_page")) {
        var toks = std.mem.tokenizeAny(u8, value_raw, " \t");
        var status_codes = std.ArrayList([]const u8).empty;
        defer status_codes.deinit(allocator);
        var target_raw: ?[]const u8 = null;
        while (toks.next()) |token| {
            if (std.mem.startsWith(u8, token, "/") or std.mem.startsWith(u8, token, "http://") or std.mem.startsWith(u8, token, "https://")) {
                target_raw = token;
                break;
            }
            _ = std.fmt.parseInt(u16, token, 10) catch return error.InvalidConfigSyntax;
            try status_codes.append(allocator, token);
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
        try ensureLocationActionAllowed(file_path, line_no, builder, "return");
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
        try ensureLocationActionAllowed(file_path, line_no, builder, "rewrite");
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
    if (std.ascii.eqlIgnoreCase(directive, "forward_auth")) {
        // The URL travels through the `|`/`;`-delimited location encoding, and
        // must stay a single absolute http(s) URL.
        if (std.mem.findAny(u8, value_interp, "|; \t") != null or
            !(std.ascii.startsWithIgnoreCase(value_interp, "http://") or std.ascii.startsWithIgnoreCase(value_interp, "https://")))
        {
            logConfigSyntaxDiagnostic("config syntax error at {s}:{d}: forward_auth must be a single absolute http:// or https:// URL", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        }
        try replaceOptionalOwned(allocator, &builder.forward_auth, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "forward_auth_upstream_headers") or
        std.ascii.eqlIgnoreCase(directive, "forward_auth_client_headers"))
    {
        const joined = try joinForwardAuthHeaderNames(allocator, file_path, line_no, directive, value_interp);
        defer allocator.free(joined);
        const target = if (std.ascii.eqlIgnoreCase(directive, "forward_auth_upstream_headers"))
            &builder.forward_auth_upstream_headers
        else
            &builder.forward_auth_client_headers;
        try replaceOptionalOwned(allocator, target, joined);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "forward_auth_body")) {
        builder.forward_auth_body = if (std.ascii.eqlIgnoreCase(value_interp, "off"))
            0
        else
            std.fmt.parseInt(usize, value_interp, 10) catch {
                logConfigSyntaxDiagnostic("config syntax error at {s}:{d}: forward_auth_body must be 'off' or a byte count", .{ file_path, line_no });
                return error.InvalidConfigSyntax;
            };
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "forward_auth_timeout_ms")) {
        const timeout_ms = std.fmt.parseInt(u32, value_interp, 10) catch 0;
        if (timeout_ms == 0) {
            logConfigSyntaxDiagnostic("config syntax error at {s}:{d}: forward_auth_timeout_ms must be a positive number of milliseconds", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        }
        builder.forward_auth_timeout_ms = timeout_ms;
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "forward_auth_failure_status")) {
        const status = std.fmt.parseInt(u16, value_interp, 10) catch 0;
        if (!isForwardAuthFailureStatus(status)) {
            logConfigSyntaxDiagnostic("config syntax error at {s}:{d}: forward_auth_failure_status must be one of 401, 403, 500, 502, 503, 504", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        }
        builder.forward_auth_failure_status = status;
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
    if (std.ascii.eqlIgnoreCase(directive, "proxy_streaming") or std.ascii.eqlIgnoreCase(directive, "proxy_streaming_mode")) {
        if (!isLocationProxyStreamingPolicy(value_interp)) {
            std.log.err("config syntax error at {s}:{d}: proxy_streaming must be one of inherit, off, response, full", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        }
        try replaceOptionalOwned(allocator, &builder.proxy_streaming, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "early_data")) {
        if (!isLocationEarlyDataPolicy(value_interp)) {
            std.log.err("config syntax error at {s}:{d}: early_data must be one of off, replay_safe", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        }
        try replaceOptionalOwned(allocator, &builder.early_data, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "proxy_early_data")) {
        if (!isLocationProxyEarlyDataPolicy(value_interp)) {
            std.log.err("config syntax error at {s}:{d}: proxy_early_data must be one of off, rfc8470", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        }
        try replaceOptionalOwned(allocator, &builder.proxy_early_data, value_interp);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "proxy_websocket")) {
        if (std.ascii.eqlIgnoreCase(value_interp, "on")) {
            builder.proxy_websocket = true;
        } else if (std.ascii.eqlIgnoreCase(value_interp, "off")) {
            builder.proxy_websocket = false;
        } else {
            logConfigSyntaxDiagnostic("config syntax error at {s}:{d}: proxy_websocket must be 'on' or 'off'", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        }
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "proxy_websocket_idle_timeout_ms")) {
        const timeout_ms = std.fmt.parseInt(u32, value_interp, 10) catch 0;
        if (timeout_ms == 0) {
            logConfigSyntaxDiagnostic("config syntax error at {s}:{d}: proxy_websocket_idle_timeout_ms must be a positive number of milliseconds", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        }
        builder.proxy_websocket_idle_timeout_ms = timeout_ms;
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "proxy_websocket_max_lifetime_ms")) {
        builder.proxy_websocket_max_lifetime_ms = std.fmt.parseInt(u32, value_interp, 10) catch {
            logConfigSyntaxDiagnostic("config syntax error at {s}:{d}: proxy_websocket_max_lifetime_ms must be a number of milliseconds (0 = unlimited)", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        };
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "proxy_websocket_reload")) {
        builder.proxy_websocket_reload = location_router.WebSocketReloadPolicy.parse(value_interp) orelse {
            logConfigSyntaxDiagnostic("config syntax error at {s}:{d}: proxy_websocket_reload must be 'preserve' or 'drain'", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        };
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "proxy_websocket_reload_timeout_ms")) {
        builder.proxy_websocket_reload_timeout_ms = std.fmt.parseInt(u32, value_interp, 10) catch {
            logConfigSyntaxDiagnostic("config syntax error at {s}:{d}: proxy_websocket_reload_timeout_ms must be a number of milliseconds", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        };
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "proxy_websocket_origins")) {
        const joined = try joinWebSocketOrigins(allocator, file_path, line_no, value_interp);
        defer allocator.free(joined);
        try replaceOptionalOwned(allocator, &builder.proxy_websocket_origins, joined);
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "proxy_response_stream_reload")) {
        builder.proxy_response_stream_reload = response_stream_lifecycle.ReloadPolicy.parse(value_interp) orelse {
            logConfigSyntaxDiagnostic("config syntax error at {s}:{d}: proxy_response_stream_reload must be 'preserve' or 'drain'", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        };
        return;
    }
    if (std.ascii.eqlIgnoreCase(directive, "proxy_response_stream_reload_timeout_ms")) {
        builder.proxy_response_stream_reload_timeout_ms = std.fmt.parseInt(u32, value_interp, 10) catch {
            logConfigSyntaxDiagnostic("config syntax error at {s}:{d}: proxy_response_stream_reload_timeout_ms must be a number of milliseconds", .{ file_path, line_no });
            return error.InvalidConfigSyntax;
        };
        return;
    }
}

/// Top-level settings that must never silently take their default: an
/// empty value (`""`, or a variable that expands to nothing) is an error
/// rather than "unset", because accepting it would let an invalid reload
/// publish and start draining long-lived work (#812, #841).
const strict_numeric_env_keys = [_][]const u8{
    "TARDIGRADE_PROXY_WEBSOCKET_RELOAD_TIMEOUT_MS",
    "TARDIGRADE_PROXY_WEBSOCKET_MAX_TUNNELS",
    "TARDIGRADE_PROXY_WEBSOCKET_REACTOR_THREADS",
    "TARDIGRADE_PROXY_RESPONSE_STREAM_MAX_ACTIVE",
    "TARDIGRADE_PROXY_RESPONSE_STREAM_RELOAD_TIMEOUT_MS",
};

fn rejectEmptyStrictValue(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    line_no: usize,
    directive: []const u8,
    trimmed_value: []const u8,
    vars: *std.StringHashMap([]const u8),
) !void {
    const env_key = try normalizeDirectiveToEnv(allocator, directive);
    defer allocator.free(env_key);
    for (strict_numeric_env_keys) |key| {
        if (!std.mem.eql(u8, env_key, key)) continue;
        const expanded = try interpolate(allocator, trimmed_value, vars);
        defer allocator.free(expanded);
        if (std.mem.trim(u8, expanded, " \t\r\n").len == 0) {
            logConfigSyntaxDiagnostic("config syntax error at {s}:{d}: {s} must be an unsigned integer, not empty", .{ file_path, line_no, directive });
            return error.InvalidConfigSyntax;
        }
        return;
    }
}

/// Normalize `proxy_websocket_origins` (origins separated by spaces or
/// commas) into the comma-joined form the location encoding carries. Each
/// entry is a serialized origin, `scheme://host[:port]`, compared exactly
/// (case-insensitively) against the handshake's `Origin`.
fn joinWebSocketOrigins(allocator: std.mem.Allocator, file_path: []const u8, line_no: usize, value: []const u8) ![]u8 {
    var origins = std.ArrayList([]const u8).empty;
    defer origins.deinit(allocator);
    var toks = std.mem.tokenizeAny(u8, value, " \t,");
    while (toks.next()) |origin| {
        if (!location_router.isValidWebSocketOrigin(origin)) {
            logConfigSyntaxDiagnostic("config syntax error at {s}:{d}: proxy_websocket_origins entry '{s}' must be an origin like https://app.example.com", .{ file_path, line_no, origin });
            return error.InvalidConfigSyntax;
        }
        try origins.append(allocator, origin);
    }
    if (origins.items.len == 0) {
        logConfigSyntaxDiagnostic("config syntax error at {s}:{d}: proxy_websocket_origins needs at least one origin", .{ file_path, line_no });
        return error.InvalidConfigSyntax;
    }
    return std.mem.join(allocator, ",", origins.items);
}

fn isForwardAuthFailureStatus(status: u16) bool {
    return switch (status) {
        401, 403, 500, 502, 503, 504 => true,
        else => false,
    };
}

/// Normalize a `forward_auth_*_headers` value (names separated by spaces or
/// commas) into the comma-joined form the location encoding carries.
fn joinForwardAuthHeaderNames(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    line_no: usize,
    directive: []const u8,
    value: []const u8,
) ![]u8 {
    var names = std.ArrayList([]const u8).empty;
    defer names.deinit(allocator);
    var toks = std.mem.tokenizeAny(u8, value, " \t,");
    while (toks.next()) |name| {
        if (!http_headers.isValidHeaderName(name) or location_router.isProtectedForwardAuthHeader(name)) {
            logConfigSyntaxDiagnostic(
                "config syntax error at {s}:{d}: {s} cannot name '{s}' (invalid or Tardigrade-owned header)",
                .{ file_path, line_no, directive, name },
            );
            return error.InvalidConfigSyntax;
        }
        try names.append(allocator, name);
    }
    if (names.items.len == 0) return error.InvalidConfigSyntax;
    return std.mem.join(allocator, ",", names.items);
}

fn isLocationProxyStreamingPolicy(value: []const u8) bool {
    return std.ascii.eqlIgnoreCase(value, "inherit") or
        std.ascii.eqlIgnoreCase(value, "off") or
        std.ascii.eqlIgnoreCase(value, "buffered") or
        std.ascii.eqlIgnoreCase(value, "response") or
        std.ascii.eqlIgnoreCase(value, "responses") or
        std.ascii.eqlIgnoreCase(value, "full") or
        std.ascii.eqlIgnoreCase(value, "request_response") or
        std.ascii.eqlIgnoreCase(value, "request-response");
}

fn isLocationEarlyDataPolicy(value: []const u8) bool {
    return std.ascii.eqlIgnoreCase(value, "off") or
        std.ascii.eqlIgnoreCase(value, "replay_safe") or
        std.ascii.eqlIgnoreCase(value, "replay-safe");
}

fn isLocationProxyEarlyDataPolicy(value: []const u8) bool {
    return std.ascii.eqlIgnoreCase(value, "off") or
        std.ascii.eqlIgnoreCase(value, "rfc8470") or
        std.ascii.eqlIgnoreCase(value, "rfc-8470");
}

fn ensureLocationActionAllowed(
    file_path: []const u8,
    line_no: usize,
    builder: *const LocationBlockBuilder,
    requested: []const u8,
) !void {
    const existing = builder.actionKind() orelse return;
    if (std.mem.eql(u8, existing, requested)) return;
    logConfigSyntaxDiagnostic(
        "config syntax error at {s}:{d}: location '{s}' has conflicting action directives ({s} and {s}); choose one",
        .{ file_path, line_no, builder.pattern, existing, requested },
    );
    return error.InvalidConfigSyntax;
}

fn logConfigSyntaxDiagnostic(comptime fmt: []const u8, args: anytype) void {
    if (!builtin.is_test) std.log.err(fmt, args);
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
                // nginx-compatible default: a `root`/`alias` location with no
                // explicit `index` directive falls back to `index.html` for
                // directory-style requests (#437). Operators can still opt out
                // of any index fallback with an explicit `index "";`.
                builder.index orelse "index.html",
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
    if (builder.proxy_streaming) |mode| {
        if (!std.ascii.eqlIgnoreCase(mode, "inherit")) {
            const with_stream_policy = try std.fmt.allocPrint(allocator, "{s}|stream:{s}", .{ entry, mode });
            allocator.free(entry);
            entry = with_stream_policy;
        }
    }
    if (builder.early_data) |policy| {
        if (!std.ascii.eqlIgnoreCase(policy, "off")) {
            const with_early_data = try std.fmt.allocPrint(allocator, "{s}|early_data:{s}", .{ entry, policy });
            allocator.free(entry);
            entry = with_early_data;
        }
    }
    if (builder.proxy_early_data) |policy| {
        if (!std.ascii.eqlIgnoreCase(policy, "off")) {
            if (builder.proxy_pass == null) {
                allocator.free(entry);
                return error.InvalidConfigSyntax;
            }
            const with_proxy_early_data = try std.fmt.allocPrint(allocator, "{s}|proxy_early_data:{s}", .{ entry, policy });
            allocator.free(entry);
            entry = with_proxy_early_data;
        }
    }
    if (builder.proxy_set_headers.items.len > 0) {
        if (builder.proxy_pass == null) {
            logConfigSyntaxDiagnostic("config syntax error: location '{s}' uses proxy_set_header without proxy_pass", .{builder.pattern});
            allocator.free(entry);
            return error.InvalidConfigSyntax;
        }
        const with_set_headers = try appendProxySetHeaderOptions(allocator, entry, builder.proxy_set_headers.items);
        allocator.free(entry);
        entry = with_set_headers;
    }
    if (builder.forward_auth) |url| {
        var fa_entry: std.ArrayList(u8) = .empty;
        defer fa_entry.deinit(allocator);
        try fa_entry.print(allocator, "{s}|forward_auth:{s}", .{ entry, url });
        if (builder.forward_auth_upstream_headers) |names| try fa_entry.print(allocator, "|forward_auth_upstream_headers:{s}", .{names});
        if (builder.forward_auth_client_headers) |names| try fa_entry.print(allocator, "|forward_auth_client_headers:{s}", .{names});
        if (builder.forward_auth_body) |max_bytes| try fa_entry.print(allocator, "|forward_auth_body:{d}", .{max_bytes});
        if (builder.forward_auth_timeout_ms) |timeout_ms| try fa_entry.print(allocator, "|forward_auth_timeout_ms:{d}", .{timeout_ms});
        if (builder.forward_auth_failure_status) |status| try fa_entry.print(allocator, "|forward_auth_failure_status:{d}", .{status});
        allocator.free(entry);
        entry = try fa_entry.toOwnedSlice(allocator);
    } else if (builder.forward_auth_upstream_headers != null or builder.forward_auth_client_headers != null or
        builder.forward_auth_body != null or builder.forward_auth_timeout_ms != null or builder.forward_auth_failure_status != null)
    {
        logConfigSyntaxDiagnostic("config syntax error: location '{s}' sets forward_auth_* options without forward_auth", .{builder.pattern});
        allocator.free(entry);
        return error.InvalidConfigSyntax;
    }
    if (builder.proxy_websocket orelse false) {
        if (builder.proxy_pass == null) {
            logConfigSyntaxDiagnostic("config syntax error: location '{s}' uses proxy_websocket without proxy_pass", .{builder.pattern});
            allocator.free(entry);
            return error.InvalidConfigSyntax;
        }
        var ws_entry: std.ArrayList(u8) = .empty;
        defer ws_entry.deinit(allocator);
        try ws_entry.print(allocator, "{s}|websocket:on", .{entry});
        if (builder.proxy_websocket_idle_timeout_ms) |timeout_ms| try ws_entry.print(allocator, "|websocket_idle_timeout_ms:{d}", .{timeout_ms});
        if (builder.proxy_websocket_max_lifetime_ms) |lifetime_ms| try ws_entry.print(allocator, "|websocket_max_lifetime_ms:{d}", .{lifetime_ms});
        if (builder.proxy_websocket_origins) |origins| try ws_entry.print(allocator, "|websocket_origins:{s}", .{origins});
        if (builder.proxy_websocket_reload) |policy| try ws_entry.print(allocator, "|websocket_reload:{s}", .{@tagName(policy)});
        if (builder.proxy_websocket_reload_timeout_ms) |timeout_ms| try ws_entry.print(allocator, "|websocket_reload_timeout_ms:{d}", .{timeout_ms});
        allocator.free(entry);
        entry = try ws_entry.toOwnedSlice(allocator);
    } else if (builder.proxy_websocket_idle_timeout_ms != null or builder.proxy_websocket_max_lifetime_ms != null or builder.proxy_websocket_origins != null or
        builder.proxy_websocket_reload != null or builder.proxy_websocket_reload_timeout_ms != null)
    {
        logConfigSyntaxDiagnostic("config syntax error: location '{s}' sets proxy_websocket_* options without proxy_websocket on", .{builder.pattern});
        allocator.free(entry);
        return error.InvalidConfigSyntax;
    }
    if (builder.proxy_response_stream_reload != null or builder.proxy_response_stream_reload_timeout_ms != null) {
        if (builder.proxy_pass == null) {
            logConfigSyntaxDiagnostic("config syntax error: location '{s}' sets proxy_response_stream_* options without proxy_pass", .{builder.pattern});
            allocator.free(entry);
            return error.InvalidConfigSyntax;
        }
        var stream_entry: std.ArrayList(u8) = .empty;
        defer stream_entry.deinit(allocator);
        try stream_entry.appendSlice(allocator, entry);
        if (builder.proxy_response_stream_reload) |policy| try stream_entry.print(allocator, "|response_stream_reload:{s}", .{@tagName(policy)});
        if (builder.proxy_response_stream_reload_timeout_ms) |timeout_ms| try stream_entry.print(allocator, "|response_stream_reload_timeout_ms:{d}", .{timeout_ms});
        allocator.free(entry);
        entry = try stream_entry.toOwnedSlice(allocator);
    }
    return entry;
}

/// Encode `proxy_set_header` rules as `|set_header:<hex name>:<hex value>`
/// location-entry options. Hex keeps arbitrary header values (which may carry
/// the `|`/`;` entry separators) out of the entry grammar.
fn appendProxySetHeaderOptions(allocator: std.mem.Allocator, entry: []const u8, rules: []const ProxySetHeaderBuilder) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, entry);
    for (rules) |rule| {
        try out.appendSlice(allocator, "|set_header:");
        try appendHexLower(allocator, &out, rule.name);
        try out.append(allocator, ':');
        try appendHexLower(allocator, &out, rule.value);
    }
    return out.toOwnedSlice(allocator);
}

fn appendHexLower(allocator: std.mem.Allocator, out: *std.ArrayList(u8), bytes: []const u8) !void {
    const digits = "0123456789abcdef";
    for (bytes) |b| {
        try out.append(allocator, digits[b >> 4]);
        try out.append(allocator, digits[b & 0x0f]);
    }
}

/// Parse the arguments of `proxy_set_header NAME VALUE;` (#809). The value may
/// be quoted, and `""` clears the header. `${VAR}` config interpolation runs as
/// for other directives; `$name` request variables are kept for runtime
/// expansion and checked against the supported set here, so `tardi check`
/// reports a typo instead of the proxy forwarding a literal `$hots`.
fn parseProxySetHeader(
    allocator: std.mem.Allocator,
    file_path: []const u8,
    line_no: usize,
    args_raw: []const u8,
    vars: *std.StringHashMap([]const u8),
    rules: *std.ArrayList(ProxySetHeaderBuilder),
) !void {
    const args = std.mem.trim(u8, args_raw, " \t");
    const name_end = std.mem.findAny(u8, args, " \t") orelse {
        logConfigSyntaxDiagnostic("config syntax error at {s}:{d}: proxy_set_header requires a name and a value (use \"\" to clear a header)", .{ file_path, line_no });
        return error.InvalidConfigSyntax;
    };
    const name = args[0..name_end];
    var value_raw = std.mem.trim(u8, args[name_end..], " \t");
    if (value_raw.len >= 2 and (value_raw[0] == '"' or value_raw[0] == '\'') and value_raw[value_raw.len - 1] == value_raw[0]) {
        value_raw = value_raw[1 .. value_raw.len - 1];
    }
    const value = try interpolate(allocator, value_raw, vars);
    errdefer allocator.free(value);

    location_router.validateProxySetHeader(name, value) catch |err| {
        switch (err) {
            error.InvalidProxySetHeaderName => logConfigSyntaxDiagnostic("config syntax error at {s}:{d}: proxy_set_header name '{s}' is not a valid header name", .{ file_path, line_no, name }),
            error.InvalidProxySetHeaderValue => logConfigSyntaxDiagnostic("config syntax error at {s}:{d}: proxy_set_header {s} value contains CR, LF or another control character", .{ file_path, line_no, name }),
            error.ForbiddenProxySetHeader => logConfigSyntaxDiagnostic("config syntax error at {s}:{d}: proxy_set_header cannot set {s}; request framing, hop-by-hop and X-Tardigrade-* headers are managed by Tardigrade", .{ file_path, line_no, name }),
            error.EmptyProxySetHeaderHost => logConfigSyntaxDiagnostic("config syntax error at {s}:{d}: proxy_set_header Host cannot be empty; Host is required upstream, so omit the rule to send the proxy_pass host", .{ file_path, line_no }),
            error.UnknownProxySetHeaderVariable => logConfigSyntaxDiagnostic("config syntax error at {s}:{d}: proxy_set_header {s} uses an unsupported variable; supported: $host $http_host $remote_addr $scheme $proxy_add_x_forwarded_for $request_id", .{ file_path, line_no, name }),
        }
        return error.InvalidConfigSyntax;
    };
    for (rules.items) |existing| {
        if (std.ascii.eqlIgnoreCase(existing.name, name)) {
            logConfigSyntaxDiagnostic("config syntax error at {s}:{d}: duplicate proxy_set_header {s} in the same block", .{ file_path, line_no, name });
            return error.InvalidConfigSyntax;
        }
    }
    const owned_name = try allocator.dupe(u8, name);
    errdefer allocator.free(owned_name);
    try rules.append(allocator, .{ .name = owned_name, .value = value });
}

fn flushLocationBlock(allocator: std.mem.Allocator, overrides: *Overrides, builder: *LocationBlockBuilder) !void {
    const entry = buildLocationBlockEntry(allocator, builder) catch |err| switch (err) {
        error.InvalidConfigSyntax => {
            if (builder.actionKind() == null) {
                logConfigSyntaxDiagnostic("config syntax error: location '{s}' has no action directive", .{builder.pattern});
            }
            return err;
        },
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
    var location_blob = std.ArrayList(u8).empty;
    defer location_blob.deinit(allocator);
    for (builder.location_entries.items, 0..) |location, idx| {
        if (idx != 0) try location_blob.append(allocator, ';');
        if (location.inherits_proxy_set_headers and builder.proxy_set_headers.items.len > 0) {
            const inherited = try appendProxySetHeaderOptions(allocator, location.entry, builder.proxy_set_headers.items);
            defer allocator.free(inherited);
            try location_blob.appendSlice(allocator, inherited);
        } else {
            try location_blob.appendSlice(allocator, location.entry);
        }
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
    if (std.mem.findScalar(u8, addr, ':')) |colon| {
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

    if (std.mem.findScalar(u8, resolved, '*')) |star| {
        const slash = std.mem.findScalarLast(u8, resolved[0..star], '/') orelse return error.InvalidIncludePattern;
        const dir_path = resolved[0..slash];
        const pattern = resolved[slash + 1 ..];
        const suffix = if (std.mem.startsWith(u8, pattern, "*")) pattern[1..] else "";
        var dir = try std.Io.Dir.cwd().openDir(compat.io(), dir_path, .{ .iterate = true });
        defer dir.close(compat.io());
        var iter = dir.iterate();
        while (try iter.next(compat.io())) |entry| {
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

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "TARDIGRADE_");
    for (directive) |ch| {
        const c = if (ch == '-') '_' else ch;
        try out.append(allocator, std.ascii.toUpper(c));
    }
    return out.toOwnedSlice(allocator);
}

fn interpolate(allocator: std.mem.Allocator, raw: []const u8, vars: *std.StringHashMap([]const u8)) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    var i: usize = 0;
    while (i < raw.len) {
        if (raw[i] == '$' and i + 1 < raw.len and raw[i + 1] == '{') {
            const end = std.mem.findScalarPos(u8, raw, i + 2, '}') orelse return error.InvalidVariableInterpolation;
            const key = raw[i + 2 .. end];
            if (vars.get(key)) |value| {
                try out.appendSlice(allocator, value);
            } else {
                const env_value = compat.getEnvVarOwned(allocator, key) catch "";
                defer if (env_value.len > 0) allocator.free(env_value);
                try out.appendSlice(allocator, env_value);
            }
            i = end + 1;
            continue;
        }
        try out.append(allocator, raw[i]);
        i += 1;
    }
    return out.toOwnedSlice(allocator);
}

fn resolveIncludePath(allocator: std.mem.Allocator, current_file: []const u8, include_path: []const u8) ![]u8 {
    if (std.Io.Dir.path.isAbsolute(include_path)) return allocator.dupe(u8, include_path);
    const dir = std.Io.Dir.path.dirname(current_file) orelse ".";
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir, include_path });
}

fn normalizePath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    if (std.Io.Dir.path.isAbsolute(path)) return allocator.dupe(u8, path);
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

    try compat.wrapDir(cfg_dir.dir).writeFile(.{
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

    const cwd = compat.cwd().dir;
    const absolute = try compat.wrapDir(cfg_dir.dir).realpathAlloc(allocator, "location.conf");
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

test "location block serializes proxy streaming policy" {
    const allocator = std.testing.allocator;
    var cfg_dir = std.testing.tmpDir(.{});
    defer cfg_dir.cleanup();

    try compat.wrapDir(cfg_dir.dir).writeFile(.{
        .sub_path = "location-streaming.conf",
        .data =
        \\location /bulk/ {
        \\    proxy_pass http://127.0.0.1:9001;
        \\    proxy_streaming full;
        \\}
        \\location /compat/ {
        \\    proxy_pass http://127.0.0.1:9002;
        \\    proxy_streaming_mode off;
        \\}
        ,
    });

    const absolute = try compat.wrapDir(cfg_dir.dir).realpathAlloc(allocator, "location-streaming.conf");
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
        "prefix|/bulk/|proxy_pass|http://127.0.0.1:9001|stream:full;prefix|/compat/|proxy_pass|http://127.0.0.1:9002|stream:off",
        overrides.map.get("TARDIGRADE_LOCATION_BLOCKS").?,
    );
}

test "location block serializes early data policies" {
    const allocator = std.testing.allocator;
    var cfg_dir = std.testing.tmpDir(.{});
    defer cfg_dir.cleanup();

    try compat.wrapDir(cfg_dir.dir).writeFile(.{
        .sub_path = "location-early-data.conf",
        .data =
        \\location /submit/ {
        \\    proxy_pass http://127.0.0.1:9001;
        \\    early_data replay_safe;
        \\    proxy_early_data rfc8470;
        \\}
        ,
    });

    const absolute = try compat.wrapDir(cfg_dir.dir).realpathAlloc(allocator, "location-early-data.conf");
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
        "prefix|/submit/|proxy_pass|http://127.0.0.1:9001|early_data:replay_safe|proxy_early_data:rfc8470",
        overrides.map.get("TARDIGRADE_LOCATION_BLOCKS").?,
    );
}

fn parseLocationConfigForTest(allocator: std.mem.Allocator, data: []const u8, overrides: *Overrides) !void {
    var cfg_dir = std.testing.tmpDir(.{});
    defer cfg_dir.cleanup();
    try compat.wrapDir(cfg_dir.dir).writeFile(.{ .sub_path = "location.conf", .data = data });
    const absolute = try compat.wrapDir(cfg_dir.dir).realpathAlloc(allocator, "location.conf");
    defer allocator.free(absolute);
    var vars = std.StringHashMap([]const u8).init(allocator);
    defer vars.deinit();
    var visited = std.StringHashMap(void).init(allocator);
    defer {
        var it = visited.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        visited.deinit();
    }
    try parseFile(allocator, absolute, overrides, &vars, &visited);
}

test "top-level response-stream lifecycle directives lower to strict env keys (#841)" {
    const allocator = std.testing.allocator;
    var overrides = Overrides.init(allocator);
    defer overrides.deinit(allocator);
    try parseLocationConfigForTest(allocator,
        \\proxy_response_stream_max_active 64;
        \\proxy_response_stream_reload drain;
        \\proxy_response_stream_reload_timeout_ms 5000;
    , &overrides);
    try std.testing.expectEqualStrings("64", overrides.map.get("TARDIGRADE_PROXY_RESPONSE_STREAM_MAX_ACTIVE").?);
    try std.testing.expectEqualStrings("drain", overrides.map.get("TARDIGRADE_PROXY_RESPONSE_STREAM_RELOAD").?);
    try std.testing.expectEqualStrings("5000", overrides.map.get("TARDIGRADE_PROXY_RESPONSE_STREAM_RELOAD_TIMEOUT_MS").?);
}

test "top-level response-stream numeric settings reject explicit empties (#841)" {
    const allocator = std.testing.allocator;
    const cases = [_][]const u8{
        "proxy_response_stream_max_active \"\";\n",
        "proxy_response_stream_reload_timeout_ms \"\";\n",
    };
    for (cases) |data| {
        var overrides = Overrides.init(allocator);
        defer overrides.deinit(allocator);
        try std.testing.expectError(error.InvalidConfigSyntax, parseLocationConfigForTest(allocator, data, &overrides));
    }
}

test "location block serializes forward_auth directives" {
    const allocator = std.testing.allocator;
    var overrides = Overrides.init(allocator);
    defer overrides.deinit(allocator);
    try parseLocationConfigForTest(allocator,
        \\location /admin/ {
        \\    forward_auth http://127.0.0.1:4180/oauth2/auth;
        \\    forward_auth_upstream_headers X-Auth-Request-User X-Auth-Request-Email;
        \\    forward_auth_client_headers Set-Cookie;
        \\    forward_auth_body off;
        \\    forward_auth_timeout_ms 750;
        \\    forward_auth_failure_status 502;
        \\    proxy_pass http://127.0.0.1:9000;
        \\}
    , &overrides);

    try std.testing.expectEqualStrings(
        "prefix|/admin/|proxy_pass|http://127.0.0.1:9000|forward_auth:http://127.0.0.1:4180/oauth2/auth" ++
            "|forward_auth_upstream_headers:X-Auth-Request-User,X-Auth-Request-Email|forward_auth_client_headers:Set-Cookie" ++
            "|forward_auth_body:0|forward_auth_timeout_ms:750|forward_auth_failure_status:502",
        overrides.map.get("TARDIGRADE_LOCATION_BLOCKS").?,
    );
}

test "location block serializes proxy_websocket directives (#812)" {
    const allocator = std.testing.allocator;
    var overrides = Overrides.init(allocator);
    defer overrides.deinit(allocator);
    try parseLocationConfigForTest(allocator,
        \\location /ws/ {
        \\    proxy_pass http://127.0.0.1:9000;
        \\    proxy_websocket on;
        \\    proxy_websocket_idle_timeout_ms 1500;
        \\    proxy_websocket_max_lifetime_ms 60000;
        \\    proxy_websocket_origins https://app.example.test, http://127.0.0.1:8080;
        \\    proxy_websocket_reload drain;
        \\    proxy_websocket_reload_timeout_ms 2500;
        \\}
        \\location /api/ {
        \\    proxy_pass http://127.0.0.1:9000;
        \\    proxy_websocket off;
        \\}
    , &overrides);

    try std.testing.expectEqualStrings(
        "prefix|/ws/|proxy_pass|http://127.0.0.1:9000|websocket:on|websocket_idle_timeout_ms:1500" ++
            "|websocket_max_lifetime_ms:60000|websocket_origins:https://app.example.test,http://127.0.0.1:8080" ++
            "|websocket_reload:drain|websocket_reload_timeout_ms:2500" ++
            ";prefix|/api/|proxy_pass|http://127.0.0.1:9000",
        overrides.map.get("TARDIGRADE_LOCATION_BLOCKS").?,
    );
}

test "location block serializes response-stream reload overrides (#841)" {
    const allocator = std.testing.allocator;
    var overrides = Overrides.init(allocator);
    defer overrides.deinit(allocator);
    try parseLocationConfigForTest(allocator,
        \\location /events/ {
        \\    proxy_pass http://127.0.0.1:9000;
        \\    proxy_response_stream_reload drain;
        \\    proxy_response_stream_reload_timeout_ms 2500;
        \\}
    , &overrides);

    try std.testing.expectEqualStrings(
        "prefix|/events/|proxy_pass|http://127.0.0.1:9000|response_stream_reload:drain|response_stream_reload_timeout_ms:2500",
        overrides.map.get("TARDIGRADE_LOCATION_BLOCKS").?,
    );
}

test "location block rejects invalid response-stream overrides (#841)" {
    const allocator = std.testing.allocator;
    const cases = [_][]const u8{
        "location /events/ {\n    return 200 ok;\n    proxy_response_stream_reload drain;\n}\n",
        "location /events/ {\n    proxy_pass http://127.0.0.1:9000;\n    proxy_response_stream_reload restart;\n}\n",
        "location /events/ {\n    proxy_pass http://127.0.0.1:9000;\n    proxy_response_stream_reload_timeout_ms 1s;\n}\n",
    };
    for (cases) |data| {
        var overrides = Overrides.init(allocator);
        defer overrides.deinit(allocator);
        try std.testing.expectError(error.InvalidConfigSyntax, parseLocationConfigForTest(allocator, data, &overrides));
    }
}

test "location block rejects unsafe proxy_websocket directives (#812)" {
    const allocator = std.testing.allocator;
    const cases = [_][]const u8{
        "location /ws/ {\n    proxy_websocket on;\n    return 200 ok;\n}\n",
        "location /ws/ {\n    proxy_pass http://127.0.0.1:9000;\n    proxy_websocket_idle_timeout_ms 100;\n}\n",
        "location /ws/ {\n    proxy_pass http://127.0.0.1:9000;\n    proxy_websocket yes;\n}\n",
        "location /ws/ {\n    proxy_pass http://127.0.0.1:9000;\n    proxy_websocket on;\n    proxy_websocket_idle_timeout_ms 0;\n}\n",
        "location /ws/ {\n    proxy_pass http://127.0.0.1:9000;\n    proxy_websocket on;\n    proxy_websocket_origins app.example.test;\n}\n",
        "location /ws/ {\n    proxy_pass http://127.0.0.1:9000;\n    proxy_websocket on;\n    proxy_websocket_reload restart;\n}\n",
        "location /ws/ {\n    proxy_pass http://127.0.0.1:9000;\n    proxy_websocket_reload drain;\n}\n",
        "location /ws/ {\n    proxy_pass http://127.0.0.1:9000;\n    proxy_websocket on;\n    proxy_websocket_reload_timeout_ms soon;\n}\n",
    };
    for (cases) |data| {
        var overrides = Overrides.init(allocator);
        defer overrides.deinit(allocator);
        try std.testing.expectError(error.InvalidConfigSyntax, parseLocationConfigForTest(allocator, data, &overrides));
    }
}

test "location block rejects unsafe forward_auth directives" {
    const allocator = std.testing.allocator;
    const cases = [_][]const u8{
        "location /a/ {\n    forward_auth_timeout_ms 100;\n    return 200 ok;\n}\n",
        "location /a/ {\n    forward_auth http://127.0.0.1/v;\n    forward_auth_upstream_headers X-Tardigrade-User-ID;\n    return 200 ok;\n}\n",
        "location /a/ {\n    forward_auth http://127.0.0.1/v;\n    forward_auth_client_headers Content-Length;\n    return 200 ok;\n}\n",
        "location /a/ {\n    forward_auth http://127.0.0.1/v;\n    forward_auth_client_headers Set-Cookie Cache-Control;\n    return 200 ok;\n}\n",
        "location /a/ {\n    forward_auth 127.0.0.1:4180;\n    return 200 ok;\n}\n",
        "location /a/ {\n    forward_auth http://127.0.0.1/v;\n    forward_auth_failure_status 200;\n    return 200 ok;\n}\n",
    };
    for (cases) |data| {
        var overrides = Overrides.init(allocator);
        defer overrides.deinit(allocator);
        try std.testing.expectError(error.InvalidConfigSyntax, parseLocationConfigForTest(allocator, data, &overrides));
    }
}

test "location block rejects proxy early data on non proxy action" {
    const allocator = std.testing.allocator;
    var cfg_dir = std.testing.tmpDir(.{});
    defer cfg_dir.cleanup();

    try compat.wrapDir(cfg_dir.dir).writeFile(.{
        .sub_path = "location-early-data-invalid.conf",
        .data =
        \\location /local/ {
        \\    return 200 ok;
        \\    proxy_early_data rfc8470;
        \\}
        ,
    });

    const absolute = try compat.wrapDir(cfg_dir.dir).realpathAlloc(allocator, "location-early-data-invalid.conf");
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

    try std.testing.expectError(error.InvalidConfigSyntax, parseFile(allocator, absolute, &overrides, &vars, &visited));
}

test "location block supports alias and fastcgi pass serialization" {
    const allocator = std.testing.allocator;
    var cfg_dir = std.testing.tmpDir(.{});
    defer cfg_dir.cleanup();

    try compat.wrapDir(cfg_dir.dir).writeFile(.{
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

    const absolute = try compat.wrapDir(cfg_dir.dir).realpathAlloc(allocator, "location-fastcgi.conf");
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

test "location block with root and no index or try_files defaults index to index.html" {
    // Regression test for #437: `root` set without an explicit `index` (or
    // `try_files`) directive used to serialize an empty index, causing
    // directory-style requests (e.g. `/`) to 404 even when an `index.html`
    // existed in the root. The default now matches nginx's `index index.html;`.
    const allocator = std.testing.allocator;
    var cfg_dir = std.testing.tmpDir(.{});
    defer cfg_dir.cleanup();

    try compat.wrapDir(cfg_dir.dir).writeFile(.{
        .sub_path = "location-default-index.conf",
        .data =
        \\location / {
        \\    root /srv/www;
        \\}
        ,
    });

    const absolute = try compat.wrapDir(cfg_dir.dir).realpathAlloc(allocator, "location-default-index.conf");
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
        "prefix|/|static_root|/srv/www|off|off|index.html|",
        overrides.map.get("TARDIGRADE_LOCATION_BLOCKS").?,
    );
}

test "location block supports error_page serialization" {
    const allocator = std.testing.allocator;
    var cfg_dir = std.testing.tmpDir(.{});
    defer cfg_dir.cleanup();

    try compat.wrapDir(cfg_dir.dir).writeFile(.{
        .sub_path = "location-error-page.conf",
        .data =
        \\location / {
        \\    root /srv/www;
        \\    error_page 404 /errors/404.html;
        \\    error_page 500 502 503 504 https://example.com/50x;
        \\}
        ,
    });

    const absolute = try compat.wrapDir(cfg_dir.dir).realpathAlloc(allocator, "location-error-page.conf");
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

test "location block rejects conflicting proxy and static actions" {
    const allocator = std.testing.allocator;
    var cfg_dir = std.testing.tmpDir(.{});
    defer cfg_dir.cleanup();

    try compat.wrapDir(cfg_dir.dir).writeFile(.{
        .sub_path = "location-conflict.conf",
        .data =
        \\location / {
        \\    proxy_pass http://127.0.0.1:9001;
        \\    root /srv/www;
        \\}
        ,
    });

    const absolute = try compat.wrapDir(cfg_dir.dir).realpathAlloc(allocator, "location-conflict.conf");
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

    try std.testing.expectError(error.InvalidConfigSyntax, parseFile(allocator, absolute, &overrides, &vars, &visited));
}

test "location block rejects missing action directive" {
    const allocator = std.testing.allocator;
    var cfg_dir = std.testing.tmpDir(.{});
    defer cfg_dir.cleanup();

    try compat.wrapDir(cfg_dir.dir).writeFile(.{
        .sub_path = "location-empty.conf",
        .data =
        \\location /empty {
        \\}
        ,
    });

    const absolute = try compat.wrapDir(cfg_dir.dir).realpathAlloc(allocator, "location-empty.conf");
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

    try std.testing.expectError(error.InvalidConfigSyntax, parseFile(allocator, absolute, &overrides, &vars, &visited));
}

test "server block supports nested location serialization" {
    const allocator = std.testing.allocator;
    var cfg_dir = std.testing.tmpDir(.{});
    defer cfg_dir.cleanup();

    try compat.wrapDir(cfg_dir.dir).writeFile(.{
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

    const absolute = try compat.wrapDir(cfg_dir.dir).realpathAlloc(allocator, "server-block.conf");
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

fn parseProxySetHeaderTestConfig(allocator: std.mem.Allocator, overrides: *Overrides, text: []const u8) !void {
    var cfg_dir = std.testing.tmpDir(.{});
    defer cfg_dir.cleanup();
    try compat.wrapDir(cfg_dir.dir).writeFile(.{ .sub_path = "proxy-set-header.conf", .data = text });
    const absolute = try compat.wrapDir(cfg_dir.dir).realpathAlloc(allocator, "proxy-set-header.conf");
    defer allocator.free(absolute);

    var vars = std.StringHashMap([]const u8).init(allocator);
    defer vars.deinit();
    var visited = std.StringHashMap(void).init(allocator);
    defer {
        var it = visited.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        visited.deinit();
    }
    try parseFile(allocator, absolute, overrides, &vars, &visited);
}

fn expectProxySetHeaderConfigRejected(text: []const u8) !void {
    var overrides = Overrides.init(std.testing.allocator);
    defer overrides.deinit(std.testing.allocator);
    try std.testing.expectError(error.InvalidConfigSyntax, parseProxySetHeaderTestConfig(std.testing.allocator, &overrides, text));
}

test "location proxy_set_header serializes hex-encoded rules (#809)" {
    const allocator = std.testing.allocator;
    var overrides = Overrides.init(allocator);
    defer overrides.deinit(allocator);
    try parseProxySetHeaderTestConfig(allocator, &overrides,
        \\location /realms/ekho/ {
        \\    proxy_set_header Host auth.baresystems.com;
        \\    proxy_pass http://keycloak:8080/realms/ekho/;
        \\    proxy_set_header X-Forwarded-For "";
        \\    proxy_set_header X-Origin "$scheme://$host|a;b";
        \\}
    );
    // Host=auth.baresystems.com, X-Forwarded-For="", X-Origin="$scheme://$host|a;b"
    try std.testing.expectEqualStrings(
        "prefix|/realms/ekho/|proxy_pass|http://keycloak:8080/realms/ekho/" ++
            "|set_header:486f7374:617574682e6261726573797374656d732e636f6d" ++
            "|set_header:582d466f727761726465642d466f72:" ++
            "|set_header:582d4f726967696e:24736368656d653a2f2f24686f73747c613b62",
        overrides.map.get("TARDIGRADE_LOCATION_BLOCKS").?,
    );
}

test "server proxy_set_header is inherited only by proxy locations without their own rules (#809)" {
    const allocator = std.testing.allocator;
    var overrides = Overrides.init(allocator);
    defer overrides.deinit(allocator);
    try parseProxySetHeaderTestConfig(allocator, &overrides,
        \\server {
        \\    server_name auth.example.test;
        \\    location /inherit/ {
        \\        proxy_pass http://127.0.0.1:9101;
        \\    }
        \\    location /own/ {
        \\        proxy_pass http://127.0.0.1:9102;
        \\        proxy_set_header X-B b;
        \\    }
        \\    location /static/ {
        \\        root /srv;
        \\    }
        \\    proxy_set_header X-A a;
        \\}
    );
    const record = overrides.map.get("TARDIGRADE_SERVER_BLOCKS").?;
    const blob = record[std.mem.findScalarLast(u8, record, server_block_field_sep[0]).? + 1 ..];
    try std.testing.expectEqualStrings(
        // X-A=a is declared after the locations but still inherited.
        "prefix|/inherit/|proxy_pass|http://127.0.0.1:9101|set_header:582d41:61;" ++
            // A location with its own rule replaces, not merges with, the server rules.
            "prefix|/own/|proxy_pass|http://127.0.0.1:9102|set_header:582d42:62;" ++
            "prefix|/static/|static_root|/srv|off|off|index.html|",
        blob,
    );
}

test "proxy_set_header rejects framing headers, CR/LF, unknown variables and misplacement (#809)" {
    try expectProxySetHeaderConfigRejected(
        \\location / {
        \\    proxy_pass http://127.0.0.1:9101;
        \\    proxy_set_header Content-Length 0;
        \\}
    );
    try expectProxySetHeaderConfigRejected(
        \\location / {
        \\    proxy_pass http://127.0.0.1:9101;
        \\    proxy_set_header Transfer-Encoding chunked;
        \\}
    );
    try expectProxySetHeaderConfigRejected("location / {\n    proxy_pass http://127.0.0.1:9101;\n    proxy_set_header X-A \"a\rX-Injected: 1\";\n}\n");
    try expectProxySetHeaderConfigRejected(
        \\location / {
        \\    proxy_pass http://127.0.0.1:9101;
        \\    proxy_set_header X-A $hots;
        \\}
    );
    try expectProxySetHeaderConfigRejected(
        \\location / {
        \\    proxy_pass http://127.0.0.1:9101;
        \\    proxy_set_header X-A;
        \\}
    );
    try expectProxySetHeaderConfigRejected(
        \\location / {
        \\    proxy_pass http://127.0.0.1:9101;
        \\    proxy_set_header X-A a;
        \\    proxy_set_header x-a b;
        \\}
    );
    try expectProxySetHeaderConfigRejected(
        \\location / {
        \\    root /srv;
        \\    proxy_set_header X-A a;
        \\}
    );
    try expectProxySetHeaderConfigRejected("proxy_set_header X-A a;\n");
    try expectProxySetHeaderConfigRejected(
        \\location / {
        \\    proxy_pass http://127.0.0.1:9101;
        \\    proxy_set_header Host "";
        \\}
    );
}
