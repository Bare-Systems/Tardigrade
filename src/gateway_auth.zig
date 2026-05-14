const compat = @import("zig_compat.zig");
const std = @import("std");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");
const gs = @import("gateway_state.zig");
const GatewayState = gs.GatewayState;
const ApprovalDecision = gs.ApprovalDecision;

const JSON_CONTENT_TYPE = "application/json";

pub const AuthResult = struct {
    ok: bool,
    identity: ?[]u8 = null,
    user_id: ?[]u8 = null,
    device_id: ?[]u8 = null,
    scopes: ?[]u8 = null,
    failure_reason: ?AuthFailureReason = null,

    pub fn deinit(self: *AuthResult, allocator: std.mem.Allocator) void {
        if (self.identity) |value| allocator.free(value);
        if (self.user_id) |value| allocator.free(value);
        if (self.device_id) |value| allocator.free(value);
        if (self.scopes) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub const AuthFailureReason = enum {
    missing,
    invalid,
};

pub fn authorizeRequest(allocator: std.mem.Allocator, cfg: *const edge_config.EdgeConfig, headers: *const http.Headers) !AuthResult {
    const auth_header = headers.get("authorization");

    if (cfg.basic_auth_hashes.len > 0) {
        var cred_buf: [512]u8 = undefined;
        if (http.basic_auth.fromHeaders(headers, &cred_buf)) |creds| {
            if (http.basic_auth.verifyCredentials(creds, cfg.basic_auth_hashes)) {
                return .{ .ok = true, .failure_reason = null };
            }
        } else |_| {}
    }

    if (auth_header) |raw_auth| {
        if (http.auth.parseBearerToken(raw_auth)) |token| {
            if (cfg.auth_token_hashes.len > 0) {
                const token_hash = hashBearerToken(token);
                for (cfg.auth_token_hashes) |allowed| {
                    if (std.mem.eql(u8, allowed, token_hash[0..])) {
                        return .{
                            .ok = true,
                            .identity = try allocator.dupe(u8, token_hash[0..]),
                            .failure_reason = null,
                        };
                    }
                }
            }

            if (cfg.jwt_secret.len > 0) {
                var claims = http.jwt.validateHs256Owned(allocator, token, .{
                    .secret = cfg.jwt_secret,
                    .required_issuer = if (cfg.jwt_issuer.len > 0) cfg.jwt_issuer else null,
                    .required_audience = if (cfg.jwt_audience.len > 0) cfg.jwt_audience else null,
                }) catch {
                    return .{
                        .ok = false,
                        .failure_reason = .invalid,
                    };
                };
                if (claims.subject == null) {
                    claims.deinit(allocator);
                    return .{
                        .ok = false,
                        .failure_reason = .invalid,
                    };
                }

                const subject = claims.subject.?;
                claims.subject = null;
                const scope = claims.scope;
                claims.scope = null;
                const device_id = claims.device_id;
                claims.device_id = null;
                claims.deinit(allocator);

                return .{
                    .ok = true,
                    .identity = subject,
                    .user_id = try allocator.dupe(u8, subject),
                    .device_id = device_id,
                    .scopes = scope,
                    .failure_reason = null,
                };
            }
        }
    }

    return .{
        .ok = false,
        .failure_reason = if (auth_header == null) .missing else .invalid,
    };
}

pub fn hashBearerToken(token: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(token, &digest, .{});
    var digest_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&digest_hex, "{f}", .{compat.fmtSliceHexLower(&digest)}) catch unreachable;
    return digest_hex;
}

fn isJsonContentType(content_type: ?[]const u8) bool {
    const ct = content_type orelse return false;
    var lower_buf: [128]u8 = undefined;
    const lower = if (ct.len <= lower_buf.len)
        std.ascii.lowerString(lower_buf[0..ct.len], ct)
    else
        ct;
    return std.mem.find(u8, lower, JSON_CONTENT_TYPE) != null;
}

fn shouldBypassProxyCache(headers: *const http.Headers) bool {
    if (headers.get("x-proxy-cache-bypass")) |raw| {
        const trimmed = std.mem.trim(u8, raw, " \t\r\n");
        if (std.ascii.eqlIgnoreCase(trimmed, "1") or std.ascii.eqlIgnoreCase(trimmed, "true") or std.ascii.eqlIgnoreCase(trimmed, "yes")) {
            return true;
        }
    }

    if (headers.get("pragma")) |pragma| {
        if (std.ascii.indexOfIgnoreCase(pragma, "no-cache") != null) return true;
    }

    if (headers.get("cache-control")) |cache_control| {
        var it = std.mem.splitScalar(u8, cache_control, ',');
        while (it.next()) |part| {
            const token = std.mem.trim(u8, part, " \t\r\n");
            if (std.ascii.eqlIgnoreCase(token, "no-cache") or std.ascii.eqlIgnoreCase(token, "no-store")) return true;
            if (std.ascii.startsWithIgnoreCase(token, "max-age=")) {
                const val = std.mem.trim(u8, token["max-age=".len..], " \t\r\n");
                if (std.mem.eql(u8, val, "0")) return true;
            }
        }
    }
    return false;
}

pub fn isGeoBlocked(blocked: []const []const u8, country: ?[]const u8) bool {
    const code = country orelse return false;
    const trimmed = std.mem.trim(u8, code, " \t\r\n");
    if (trimmed.len == 0) return false;
    for (blocked) |entry| {
        if (std.ascii.eqlIgnoreCase(entry, trimmed)) return true;
    }
    return false;
}

pub fn resolveRequestConfig(base_cfg: *const edge_config.EdgeConfig, raw_host: ?[]const u8, out: *edge_config.EdgeConfig) ?*const edge_config.EdgeConfig {
    out.* = base_cfg.*;
    if (base_cfg.server_blocks.len > 0) {
        const block = selectServerBlock(base_cfg, raw_host) orelse return null;
        if (block.server_names.len > 0 and !hostMatchesPatterns(block.server_names, raw_host)) return null;
        out.server_names = block.server_names;
        if (block.doc_root.len > 0) out.doc_root = block.doc_root;
        if (block.try_files.len > 0) out.try_files = block.try_files;
        if (block.location_blocks.len > 0) out.location_blocks = block.location_blocks;
        if (block.tls_cert_path.len > 0) out.tls_cert_path = block.tls_cert_path;
        if (block.tls_key_path.len > 0) out.tls_key_path = block.tls_key_path;
        if (block.upstream_base_url.len > 0) out.upstream_base_url = block.upstream_base_url;
        if (block.proxy_pass_chat.len > 0) out.proxy_pass_chat = block.proxy_pass_chat;
        if (block.proxy_pass_commands_prefix.len > 0) out.proxy_pass_commands_prefix = block.proxy_pass_commands_prefix;
        return out;
    }
    if (!hostMatchesPatterns(base_cfg.server_names, raw_host)) return null;
    return out;
}

fn selectServerBlock(cfg: *const edge_config.EdgeConfig, raw_host: ?[]const u8) ?*const edge_config.EdgeConfig.ServerBlock {
    var default_block: ?*const edge_config.EdgeConfig.ServerBlock = null;
    for (cfg.server_blocks) |*block| {
        if (block.server_names.len == 0 and default_block == null) default_block = block;
        if (hostMatchesPatterns(block.server_names, raw_host)) return block;
    }
    return default_block orelse if (cfg.server_blocks.len > 0) &cfg.server_blocks[0] else null;
}

pub fn hostMatchesServerNames(cfg: *const edge_config.EdgeConfig, request: *const http.Request) bool {
    return hostMatchesPatterns(cfg.server_names, request.headers.get("host"));
}

pub fn hostMatchesPatterns(patterns: []const []const u8, raw_host: ?[]const u8) bool {
    if (patterns.len == 0) return true;
    const host = stripHostPort(raw_host orelse return false);
    for (patterns) |pattern| {
        if (matchHostPattern(pattern, host)) return true;
    }
    return false;
}

fn stripHostPort(raw_host: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, raw_host, " \t\r\n");
    if (trimmed.len == 0) return trimmed;
    if (trimmed[0] == '[') {
        const end = std.mem.findScalar(u8, trimmed, ']') orelse return trimmed;
        return trimmed[1..end];
    }
    const colon = std.mem.findScalarLast(u8, trimmed, ':') orelse return trimmed;
    const head = trimmed[0..colon];
    if (std.mem.findScalar(u8, head, ':') != null) return trimmed;
    return head;
}

fn hostPort(raw_host: []const u8) ?u16 {
    const trimmed = std.mem.trim(u8, raw_host, " \t\r\n");
    if (trimmed.len == 0) return null;
    if (trimmed[0] == '[') {
        const end = std.mem.findScalar(u8, trimmed, ']') orelse return null;
        if (end + 1 >= trimmed.len or trimmed[end + 1] != ':') return null;
        return std.fmt.parseInt(u16, trimmed[end + 2 ..], 10) catch null;
    }
    const colon = std.mem.findScalarLast(u8, trimmed, ':') orelse return null;
    const head = trimmed[0..colon];
    if (std.mem.findScalar(u8, head, ':') != null) return null;
    return std.fmt.parseInt(u16, trimmed[colon + 1 ..], 10) catch null;
}

fn matchHostPattern(pattern_raw: []const u8, host: []const u8) bool {
    const pattern = std.mem.trim(u8, pattern_raw, " \t");
    if (pattern.len == 0) return false;
    if (pattern[0] == '~') {
        return http.rewrite.regexMatches(pattern[1..], host);
    }
    if (std.mem.startsWith(u8, pattern, "*.")) {
        const suffix = pattern[1..];
        return std.mem.endsWith(u8, host, suffix);
    }
    return std.ascii.eqlIgnoreCase(pattern, host);
}

const ApprovalRequestBody = struct {
    method: []u8,
    path: []u8,
    command_id: ?[]u8,

    pub fn deinit(self: *ApprovalRequestBody, allocator: std.mem.Allocator) void {
        allocator.free(self.method);
        allocator.free(self.path);
        if (self.command_id) |cid| allocator.free(cid);
        self.* = undefined;
    }
};

const ApprovalResponsePayload = struct {
    token: []u8,
    decision: ApprovalDecision,

    pub fn deinit(self: *ApprovalResponsePayload, allocator: std.mem.Allocator) void {
        allocator.free(self.token);
        self.* = undefined;
    }
};

const DeviceRegistration = struct {
    device_id: []const u8,
    public_key: []const u8,
};

pub fn parseApprovalRequestBody(allocator: std.mem.Allocator, body: []const u8) !ApprovalRequestBody {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidApprovalRequest;
    const obj = parsed.value.object;
    const method_val = obj.get("method") orelse return error.InvalidApprovalRequest;
    const path_val = obj.get("path") orelse return error.InvalidApprovalRequest;
    if (method_val != .string or path_val != .string) return error.InvalidApprovalRequest;
    const method = std.mem.trim(u8, method_val.string, " \t\r\n");
    const path = std.mem.trim(u8, path_val.string, " \t\r\n");
    if (method.len == 0 or path.len == 0) return error.InvalidApprovalRequest;
    var command_id: ?[]u8 = null;
    if (obj.get("command_id")) |cid_val| {
        if (cid_val == .string) {
            const cid = std.mem.trim(u8, cid_val.string, " \t\r\n");
            if (cid.len > 0) command_id = try allocator.dupe(u8, cid);
        }
    }
    return .{
        .method = try allocator.dupe(u8, method),
        .path = try allocator.dupe(u8, path),
        .command_id = command_id,
    };
}

pub fn parseApprovalResponseBody(allocator: std.mem.Allocator, body: []const u8) !ApprovalResponsePayload {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidApprovalResponse;
    const obj = parsed.value.object;
    const token_val = obj.get("approval_token") orelse return error.InvalidApprovalResponse;
    const decision_val = obj.get("decision") orelse return error.InvalidApprovalResponse;
    if (token_val != .string or decision_val != .string) return error.InvalidApprovalResponse;
    const token = std.mem.trim(u8, token_val.string, " \t\r\n");
    const decision_raw = std.mem.trim(u8, decision_val.string, " \t\r\n");
    if (token.len == 0 or decision_raw.len == 0) return error.InvalidApprovalResponse;
    const decision = if (std.ascii.eqlIgnoreCase(decision_raw, "approve"))
        ApprovalDecision.approve
    else if (std.ascii.eqlIgnoreCase(decision_raw, "deny"))
        ApprovalDecision.deny
    else
        return error.InvalidApprovalResponse;
    return .{
        .token = try allocator.dupe(u8, token),
        .decision = decision,
    };
}

fn parseDeviceRegistration(allocator: std.mem.Allocator, body: []const u8) !DeviceRegistration {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const root = parsed.value;
    if (root != .object) return error.InvalidDeviceRegistration;
    const obj = root.object;
    const did_val = obj.get("device_id") orelse return error.InvalidDeviceRegistration;
    const pk_val = obj.get("public_key") orelse return error.InvalidDeviceRegistration;
    if (did_val != .string or pk_val != .string) return error.InvalidDeviceRegistration;
    const device_id = std.mem.trim(u8, did_val.string, " \t\r\n");
    const public_key = std.mem.trim(u8, pk_val.string, " \t\r\n");
    if (device_id.len == 0 or public_key.len == 0) return error.InvalidDeviceRegistration;
    return .{
        .device_id = try allocator.dupe(u8, device_id),
        .public_key = try allocator.dupe(u8, public_key),
    };
}

fn registerDeviceIdentity(path: []const u8, device_id: []const u8, public_key: []const u8) !void {
    const path_z = try std.heap.page_allocator.dupeZ(u8, path);
    defer std.heap.page_allocator.free(path_z);
    const fd = std.c.open(path_z.ptr, std.c.O.WRONLY | std.c.O.CREAT | std.c.O.APPEND, 0o644);
    if (fd < 0) return error.FileOpenFailed;
    defer _ = std.c.close(fd);
    const line = try std.fmt.allocPrint(std.heap.page_allocator, "{s}|{s}\n", .{ device_id, public_key });
    defer std.heap.page_allocator.free(line);
    const stream = compat.netStreamFromFd(fd);
    try stream.writeAll(line);
}

fn loadRegisteredDeviceKey(allocator: std.mem.Allocator, registry_path: []const u8, device_id: []const u8) ?[]const u8 {
    const raw = compat.cwd().readFileAlloc(allocator, registry_path, 2 * 1024 * 1024) catch return null;
    defer allocator.free(raw);
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, " \t\r\n");
        if (line.len == 0) continue;
        const sep = std.mem.findScalar(u8, line, '|') orelse continue;
        const did = std.mem.trim(u8, line[0..sep], " \t");
        const key = std.mem.trim(u8, line[sep + 1 ..], " \t");
        if (std.mem.eql(u8, did, device_id)) return allocator.dupe(u8, key) catch null;
    }
    return null;
}

fn validateDeviceRequest(
    cfg: *const edge_config.EdgeConfig,
    method: []const u8,
    path: []const u8,
    headers: *const http.Headers,
    body: []const u8,
) bool {
    if (cfg.device_registry_path.len == 0) return false;
    const device_id = headers.get("x-device-id") orelse return false;
    const ts_str = headers.get("x-device-timestamp") orelse return false;
    const provided_sig = headers.get("x-device-signature") orelse return false;
    const ts = std.fmt.parseInt(i64, ts_str, 10) catch return false;
    const now = compat.unixTimestamp();
    const delta = if (now > ts) now - ts else ts - now;
    if (delta > 300) return false;

    const allocator = std.heap.page_allocator;
    const key = loadRegisteredDeviceKey(allocator, cfg.device_registry_path, device_id) orelse return false;
    defer allocator.free(key);
    const signed = std.fmt.allocPrint(allocator, "{s}\n{s}\n{s}\n{s}\n{s}", .{ key, method, path, ts_str, body }) catch return false;
    defer allocator.free(signed);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(signed, &digest, .{});
    var digest_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&digest_hex, "{f}", .{compat.fmtSliceHexLower(&digest)}) catch return false;
    return std.ascii.eqlIgnoreCase(std.mem.trim(u8, provided_sig, " \t\r\n"), digest_hex[0..]);
}

fn extractIdentityForPolicy(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    request: *const http.Request,
) !?[]const u8 {
    var auth_res = try authorizeRequest(allocator, cfg, &request.headers);
    defer auth_res.deinit(allocator);
    if (auth_res.ok and auth_res.identity != null) {
        const identity = auth_res.identity.?;
        auth_res.identity = null;
        return identity;
    }
    if (http.session.fromHeaders(&request.headers)) |session_token| {
        if (state.validateSessionIdentity(allocator, session_token)) |identity| return identity;
    }
    return null;
}

fn approvalPolicyError(state: *GatewayState, method: []const u8, path: []const u8, identity: ?[]const u8, headers: *const http.Headers) ?[]const u8 {
    const approval = headers.get("x-approval-token") orelse return "Approval required";
    const token = std.mem.trim(u8, approval, " \t\r\n");
    if (token.len == 0) return "Approval required";
    return switch (state.approvalValidate(token, method, path, identity)) {
        .approved => null,
        .pending => "Approval pending",
        .denied => "Approval denied",
        .escalated => "Approval timed out and escalated",
        .invalid => "Invalid approval token",
        .missing => "Approval required",
    };
}

pub fn evaluatePolicy(
    state: *GatewayState,
    cfg: *const edge_config.EdgeConfig,
    method: []const u8,
    path: []const u8,
    identity: ?[]const u8,
    device_id: ?[]const u8,
    headers: *const http.Headers,
) ?[]const u8 {
    if (http.api_router.matchRoute(path, 1, "/approvals/request") or
        http.api_router.matchRoute(path, 1, "/approvals/respond") or
        http.api_router.matchRoute(path, 1, "/approvals/status"))
    {
        return null;
    }
    if (cfg.policy_approval_routes_raw.len > 0 and routeNeedsApproval(method, path, cfg.policy_approval_routes_raw)) {
        if (approvalPolicyError(state, method, path, identity, headers)) |reason| return reason;
    }
    if (cfg.policy_rules_raw.len == 0) return null;
    var rules = std.mem.splitScalar(u8, cfg.policy_rules_raw, ';');
    while (rules.next()) |entry_raw| {
        const entry = std.mem.trim(u8, entry_raw, " \t\r\n");
        if (entry.len == 0) continue;
        var parts = std.mem.splitScalar(u8, entry, '|');
        const rule_method = std.mem.trim(u8, parts.next() orelse "", " \t");
        const rule_pattern = std.mem.trim(u8, parts.next() orelse "", " \t");
        const req_scope = std.mem.trim(u8, parts.next() orelse "", " \t");
        const req_approval = std.mem.trim(u8, parts.next() orelse "false", " \t");
        const allowed_hours = std.mem.trim(u8, parts.next() orelse "", " \t");
        const device_pattern = std.mem.trim(u8, parts.next() orelse "", " \t");
        if (rule_method.len == 0 or rule_pattern.len == 0) continue;
        if (!http.rewrite.methodMatches(rule_method, method)) continue;
        if (!http.rewrite.regexMatches(rule_pattern, path)) continue;

        if (req_scope.len > 0 and !identityHasScope(cfg.policy_user_scopes_raw, identity, req_scope)) return "Missing required scope";
        if (std.ascii.eqlIgnoreCase(req_approval, "true")) {
            if (approvalPolicyError(state, method, path, identity, headers)) |reason| return reason;
        }
        if (allowed_hours.len > 0 and !timeWindowAllows(allowed_hours)) return "Route not allowed at this time";
        if (device_pattern.len > 0) {
            const did = device_id orelse return "Device restriction denied";
            if (!http.rewrite.regexMatches(device_pattern, did)) return "Device restriction denied";
        }
    }
    return null;
}

pub fn routeRequiresApprovalRule(method: []const u8, path: []const u8, policy_rules_raw: []const u8) bool {
    if (policy_rules_raw.len == 0) return false;
    var rules = std.mem.splitScalar(u8, policy_rules_raw, ';');
    while (rules.next()) |entry_raw| {
        const entry = std.mem.trim(u8, entry_raw, " \t\r\n");
        if (entry.len == 0) continue;
        var parts = std.mem.splitScalar(u8, entry, '|');
        const rule_method = std.mem.trim(u8, parts.next() orelse "", " \t");
        const rule_pattern = std.mem.trim(u8, parts.next() orelse "", " \t");
        _ = parts.next(); // scope
        const req_approval = std.mem.trim(u8, parts.next() orelse "false", " \t");
        if (rule_method.len == 0 or rule_pattern.len == 0) continue;
        if (!http.rewrite.methodMatches(rule_method, method)) continue;
        if (!http.rewrite.regexMatches(rule_pattern, path)) continue;
        if (std.ascii.eqlIgnoreCase(req_approval, "true")) return true;
    }
    return false;
}

fn routeNeedsApproval(method: []const u8, path: []const u8, raw: []const u8) bool {
    var it = std.mem.splitScalar(u8, raw, ';');
    while (it.next()) |entry_raw| {
        const entry = std.mem.trim(u8, entry_raw, " \t\r\n");
        if (entry.len == 0) continue;
        var parts = std.mem.splitScalar(u8, entry, '|');
        const rm = std.mem.trim(u8, parts.next() orelse "", " \t");
        const rp = std.mem.trim(u8, parts.next() orelse "", " \t");
        if (rm.len == 0 or rp.len == 0) continue;
        if (http.rewrite.methodMatches(rm, method) and http.rewrite.regexMatches(rp, path)) return true;
    }
    return false;
}

fn identityHasScope(scopes_raw: []const u8, identity: ?[]const u8, required: []const u8) bool {
    if (identity == null) return false;
    var it = std.mem.splitScalar(u8, scopes_raw, ';');
    while (it.next()) |entry_raw| {
        const entry = std.mem.trim(u8, entry_raw, " \t\r\n");
        if (entry.len == 0) continue;
        const colon = std.mem.findScalar(u8, entry, ':') orelse continue;
        const id = std.mem.trim(u8, entry[0..colon], " \t");
        if (!std.mem.eql(u8, id, identity.?)) continue;
        var s_it = std.mem.splitScalar(u8, entry[colon + 1 ..], ',');
        while (s_it.next()) |scope| {
            if (std.mem.eql(u8, std.mem.trim(u8, scope, " \t"), required)) return true;
        }
    }
    return false;
}

fn timeWindowAllows(raw: []const u8) bool {
    const dash = std.mem.findScalar(u8, raw, '-') orelse return true;
    const start = std.fmt.parseInt(u8, std.mem.trim(u8, raw[0..dash], " \t"), 10) catch return true;
    const stop = std.fmt.parseInt(u8, std.mem.trim(u8, raw[dash + 1 ..], " \t"), 10) catch return true;
    const now = compat.unixTimestamp();
    const hour = @as(u8, @intCast(@mod(@divFloor(now, 3600), 24)));
    if (start <= stop) return hour >= start and hour < stop;
    return hour >= start or hour < stop;
}

pub fn authorizeViaSubrequest(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    request: *const http.Request,
    correlation_id: []const u8,
    client_ip: []const u8,
) bool {
    if (cfg.auth_request_url.len == 0) return true;
    const uri = std.Uri.parse(cfg.auth_request_url) catch return false;
    var client = std.http.Client{ .allocator = allocator, .io = compat.io() };
    defer client.deinit();

    var header_buf: [4 * 1024]u8 = undefined;
    var headers_buf: [8]std.http.Header = undefined;
    var header_count: usize = 0;
    headers_buf[header_count] = .{ .name = "X-Original-Method", .value = request.method.toString() };
    header_count += 1;
    headers_buf[header_count] = .{ .name = "X-Original-URI", .value = request.uri.path };
    header_count += 1;
    headers_buf[header_count] = .{ .name = "X-Client-IP", .value = client_ip };
    header_count += 1;
    headers_buf[header_count] = .{ .name = http.correlation.REQUEST_HEADER_NAME, .value = correlation_id };
    header_count += 1;
    headers_buf[header_count] = .{ .name = http.correlation.HEADER_NAME, .value = correlation_id };
    header_count += 1;
    if (request.headers.get("authorization")) |authz| {
        headers_buf[header_count] = .{ .name = "Authorization", .value = authz };
        header_count += 1;
    }
    if (request.headers.get(http.session.SESSION_HEADER)) |session_token| {
        headers_buf[header_count] = .{ .name = http.session.SESSION_HEADER, .value = session_token };
        header_count += 1;
    }

    var req = client.request(.GET, uri, .{
        .extra_headers = headers_buf[0..header_count],
    }) catch return false;
    defer req.deinit();
    req.sendBodiless() catch return false;
    const resp = req.receiveHead(&header_buf) catch return false;
    const status = @intFromEnum(resp.head.status);
    return status >= 200 and status < 300;
}

fn parseDeviceId(allocator: std.mem.Allocator, body: []const u8) ![]const u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    const device_val = obj.get("device_id") orelse return error.NoDeviceId;
    if (device_val != .string) return error.InvalidDeviceId;

    const device_id = std.mem.trim(u8, device_val.string, " \t\r\n");
    if (device_id.len == 0) return error.EmptyDeviceId;
    if (device_id.len > 256) return error.DeviceIdTooLong;
    return try allocator.dupe(u8, device_id);
}

fn parseCachePurgeKey(allocator: std.mem.Allocator, body: []const u8) ![]const u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    const key_val = obj.get("key") orelse return error.NoPurgeKey;
    if (key_val != .string) return error.NoPurgeKey;
    const key = std.mem.trim(u8, key_val.string, " \t\r\n");
    if (key.len == 0) return error.NoPurgeKey;
    return try allocator.dupe(u8, key);
}

pub fn parseChatMessage(allocator: std.mem.Allocator, body: []const u8, max_len: usize) ![]const u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    const message_val = obj.get("message") orelse return error.InvalidRequest;
    if (message_val != .string) return error.InvalidRequest;

    const message = std.mem.trim(u8, message_val.string, " \t\r\n");
    if (message.len == 0) return error.EmptyMessage;
    if (message.len > max_len) return error.MessageTooLarge;
    return try allocator.dupe(u8, message);
}
