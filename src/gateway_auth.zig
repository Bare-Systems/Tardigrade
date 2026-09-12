const builtin = @import("builtin");
const compat = @import("zig_compat");
const std = @import("std");
const secrets = @import("crypto").secrets;
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");
const gp = @import("gateway_proxy.zig");
const gs = @import("gateway_state.zig");
const GatewayState = gs.GatewayState;
const ApprovalDecision = gs.ApprovalDecision;

const JSON_CONTENT_TYPE = "application/json";

/// Device registry entries are HMAC shared secrets, so the file is owner-only.
const owner_only_permissions: std.Io.File.Permissions = .fromMode(0o600);

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
                    // The configured digest and the request-derived digest
                    // are secret-derived authentication material. Keep the
                    // public length check ordinary, then compare all digest
                    // bytes in constant time like Basic/JWT verification.
                    if (allowed.len == token_hash.len and compat.timingSafeEql([64]u8, allowed[0..64].*, token_hash)) {
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
                if (!authClaimsHeaderSafe(claims.subject.?, claims.scope, claims.device_id)) {
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

fn authClaimsHeaderSafe(subject: []const u8, scope: ?[]const u8, device_id: ?[]const u8) bool {
    return http.headers.isValidHeaderValue(subject) and
        (scope == null or http.headers.isValidHeaderValue(scope.?)) and
        (device_id == null or http.headers.isValidHeaderValue(device_id.?));
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

/// A device registration. `hmac_key` is a SHARED SECRET, not public material:
/// device request authentication is HMAC-SHA256 over the request, so whoever
/// holds this value can sign as the device. The legacy `public_key` JSON field
/// name is accepted for compatibility but is a misnomer.
const DeviceRegistration = struct {
    device_id: []const u8,
    hmac_key: []const u8,

    fn deinit(self: *DeviceRegistration, allocator: std.mem.Allocator) void {
        allocator.free(self.device_id);
        secrets.secureZeroAndFree(allocator, @constCast(self.hmac_key));
        self.* = undefined;
    }
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
    // `hmac_key` is the accurate name; `public_key` is accepted because it is
    // the field this payload shipped with before the protocol moved to HMAC.
    const key_val = obj.get("hmac_key") orelse obj.get("public_key") orelse return error.InvalidDeviceRegistration;
    if (did_val != .string or key_val != .string) return error.InvalidDeviceRegistration;
    const device_id = std.mem.trim(u8, did_val.string, " \t\r\n");
    const hmac_key = std.mem.trim(u8, key_val.string, " \t\r\n");
    if (!deviceRegistryFieldSafe(device_id, 256) or !deviceRegistryFieldSafe(hmac_key, 4096)) {
        return error.InvalidDeviceRegistration;
    }
    return .{
        .device_id = try allocator.dupe(u8, device_id),
        .hmac_key = try allocator.dupe(u8, hmac_key),
    };
}

/// Append a device's HMAC key to the registry.
///
/// The registry holds shared secrets for every registered device, so it is
/// created owner-only (0600) in the `open` syscall itself — a later `chmod`
/// would leave a window where another local user could read it. An existing
/// registry that is group/world accessible is refused rather than appended to,
/// because writing a new secret into a readable file is the same exposure.
fn registerDeviceIdentity(path: []const u8, device_id: []const u8, hmac_key: []const u8) !void {
    // The on-disk representation is `device_id|key\n`. Validate again at the
    // persistence boundary so a future non-JSON caller cannot inject another
    // credential record or change which key a lookup returns.
    if (!deviceRegistryFieldSafe(device_id, 256) or !deviceRegistryFieldSafe(hmac_key, 4096)) {
        return error.InvalidDeviceRegistration;
    }
    var file = try compat.cwd().createFile(path, .{
        .read = true,
        .truncate = false,
        .permissions = owner_only_permissions,
    });
    defer file.close();
    try requireOwnerOnlyRegistry(file);
    _ = std.c.lseek(file.file.handle, 0, std.c.SEEK.END);

    const line = try std.fmt.allocPrint(std.heap.page_allocator, "{s}|{s}\n", .{ device_id, hmac_key });
    defer secrets.secureZeroAndFree(std.heap.page_allocator, line);
    try file.writeAll(line);
}

fn deviceRegistryFieldSafe(value: []const u8, max_len: usize) bool {
    if (value.len == 0 or value.len > max_len) return false;
    for (value) |byte| {
        if (byte == '|' or byte == '\r' or byte == '\n' or byte == 0) return false;
    }
    return true;
}

/// Reject a device registry that any account other than the owner can read or
/// write. Returns `error.InsecureDeviceRegistryPermissions` so the caller fails
/// closed instead of appending a secret to a readable file.
fn requireOwnerOnlyRegistry(file: compat.FileCompat) !void {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) return;
    const stat = file.file.stat(compat.io()) catch return error.FileOpenFailed;
    if (stat.permissions.toMode() & 0o077 != 0) return error.InsecureDeviceRegistryPermissions;
}

/// Look up one device's HMAC key.
///
/// The registry file holds every device's shared secret, so the raw buffer is
/// wiped before release rather than left in freed heap memory. The returned key
/// is secret material too: callers must release it with
/// `secrets.secureZeroAndFree`.
fn loadRegisteredDeviceKey(allocator: std.mem.Allocator, registry_path: []const u8, device_id: []const u8) ?[]const u8 {
    const raw = compat.cwd().readFileAlloc(allocator, registry_path, 2 * 1024 * 1024) catch return null;
    defer secrets.secureZeroAndFree(allocator, raw);
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
    defer secrets.secureZeroAndFree(allocator, @constCast(key));
    const signing_input = std.fmt.allocPrint(allocator, "{s}\n{s}\n{s}\n{s}", .{ method, path, ts_str, body }) catch return false;
    // The signing input embeds the request body, which can carry credentials of
    // its own, so it is wiped alongside the key.
    defer secrets.secureZeroAndFree(allocator, signing_input);
    return verifyDeviceRequestSignature(key, signing_input, provided_sig);
}

fn verifyDeviceRequestSignature(key: []const u8, signing_input: []const u8, provided_raw: []const u8) bool {
    const provided = std.mem.trim(u8, provided_raw, " \t\r\n");
    if (provided.len != 64) return false;

    var provided_mac: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&provided_mac, provided) catch return false;

    var expected_mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&expected_mac, signing_input, key);
    return compat.timingSafeEql([32]u8, provided_mac, expected_mac);
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
        const pattern_matches = http.rewrite.regexMatchesChecked(rule_pattern, path) catch return "Invalid policy rule";
        if (!pattern_matches) continue;

        const approval_required = if (std.ascii.eqlIgnoreCase(req_approval, "true"))
            true
        else if (std.ascii.eqlIgnoreCase(req_approval, "false"))
            false
        else
            return "Invalid policy rule";

        if (req_scope.len > 0 and !identityHasScope(cfg.policy_user_scopes_raw, identity, req_scope)) return "Missing required scope";
        if (approval_required) {
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
        if (!std.ascii.eqlIgnoreCase(req_approval, "true")) continue;
        const pattern_matches = http.rewrite.regexMatchesChecked(rule_pattern, path) catch return true;
        if (pattern_matches) return true;
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
        if (!http.rewrite.methodMatches(rm, method)) continue;
        const pattern_matches = http.rewrite.regexMatchesChecked(rp, path) catch return true;
        if (pattern_matches) return true;
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
    const dash = std.mem.findScalar(u8, raw, '-') orelse return false;
    const start = std.fmt.parseInt(u8, std.mem.trim(u8, raw[0..dash], " \t"), 10) catch return false;
    const stop = std.fmt.parseInt(u8, std.mem.trim(u8, raw[dash + 1 ..], " \t"), 10) catch return false;
    // Start is an actual UTC hour. Stop may be 24 so `0-24` can represent
    // the full day; zero remains valid for overnight windows such as `22-0`.
    if (start > 23 or stop > 24) return false;
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
    const is_https = std.ascii.eqlIgnoreCase(uri.scheme, "https");
    if (!is_https and !std.ascii.eqlIgnoreCase(uri.scheme, "http")) return false;
    if (!authSubrequestUriSafe(uri)) return false;
    var host_buf: [std.Io.net.HostName.max_len]u8 = undefined;
    const decoded_host = (uri.getHost(&host_buf) catch return false).bytes;
    if (!authSubrequestBytesSafe(decoded_host, false)) return false;
    const host = unbracketUriHost(decoded_host);
    const port = uri.port orelse if (is_https) @as(u16, 443) else @as(u16, 80);

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

    const tls_options: ?http.upstream_tls.UpstreamTlsOptions = if (is_https) authSubrequestTlsOptions(cfg) else null;
    const connect_timeout_ms = if (cfg.upstream_connect_timeout_ms > 0)
        cfg.upstream_connect_timeout_ms
    else if (cfg.upstream_timeout_ms > 0)
        cfg.upstream_timeout_ms
    else
        5_000;
    const response_timeout_ms = if (cfg.upstream_response_timeout_ms > 0)
        cfg.upstream_response_timeout_ms
    else if (cfg.upstream_timeout_ms > 0)
        cfg.upstream_timeout_ms
    else
        5_000;
    var response = gp.executeBoundedBufferedTcpHttpRequest(
        allocator,
        host,
        port,
        tls_options,
        uri,
        "GET",
        headers_buf[0..header_count],
        "",
        null,
        64 * 1024,
        connect_timeout_ms,
        response_timeout_ms,
        null,
        null,
        false,
    ) catch return false;
    defer response.deinit(allocator);
    const status = response.status_code;
    return status >= 200 and status < 300;
}

fn authSubrequestTlsOptions(cfg: *const edge_config.EdgeConfig) http.upstream_tls.UpstreamTlsOptions {
    return .{
        // The authorization service is a separate trust boundary from the
        // normal reverse-proxy origin. An operator may deliberately disable
        // verification or override SNI for that origin; inheriting either
        // setting here would silently weaken (or redirect) the decision that
        // gates every protected request. Keep verification and URL-host
        // identity mandatory while still allowing private roots and mTLS.
        .skip_verify = false,
        .ca_bundle_path = cfg.upstream_tls_ca_bundle,
        .sni_override = "",
        .client_cert_path = cfg.upstream_tls_client_cert,
        .client_key_path = cfg.upstream_tls_client_key,
        .alpn_policy = .require_http1,
    };
}

fn authSubrequestUriSafe(uri: std.Uri) bool {
    // Userinfo is not forwarded by the bounded transport, so reject it rather
    // than accidentally changing the authentication contract. Fragments are
    // never part of an HTTP request target and are likewise configuration
    // errors here.
    if (uri.user != null or uri.password != null or uri.fragment != null) return false;
    const host = uri.host orelse return false;
    if (!authSubrequestUriComponentSafe(host, false)) return false;
    if (!authSubrequestUriComponentSafe(uri.path, true)) return false;
    if (uri.query) |query| {
        if (!authSubrequestUriComponentSafe(query, true)) return false;
    }
    return true;
}

fn authSubrequestUriComponentSafe(component: std.Uri.Component, allow_empty: bool) bool {
    return authSubrequestBytesSafe(gp.uriComponentBytes(component), allow_empty);
}

fn authSubrequestBytesSafe(value: []const u8, allow_empty: bool) bool {
    if (value.len == 0) return allow_empty;
    for (value) |byte| {
        // Parsed Uri components are marked percent-encoded even when the
        // configuration contains raw bytes. The native request builder writes
        // them verbatim, so reject request-line/header delimiters explicitly.
        if (byte <= 0x20 or byte == 0x7f) return false;
    }
    return true;
}

fn unbracketUriHost(host: []const u8) []const u8 {
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') return host[1 .. host.len - 1];
    return host;
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

test "parseChatMessage validates payload" {
    const allocator = std.testing.allocator;
    const message = try parseChatMessage(allocator, "{\"message\":\"hello\"}", 10);
    defer allocator.free(message);
    try std.testing.expectEqualStrings("hello", message);

    try std.testing.expectError(error.MessageTooLarge, parseChatMessage(allocator, "{\"message\":\"hello\"}", 2));
}

test "asserted JWT claims reject upstream header delimiters" {
    try std.testing.expect(authClaimsHeaderSafe("user-1", "read write", "device-1"));
    try std.testing.expect(!authClaimsHeaderSafe("user-1\r\nX-Injected: yes", null, null));
    try std.testing.expect(!authClaimsHeaderSafe("user-1", "read\nX-Injected: yes", null));
    try std.testing.expect(!authClaimsHeaderSafe("user-1", null, "device\x00suffix"));
}

test "auth subrequest URL rejects request injection and unsupported authority fields" {
    try std.testing.expect(authSubrequestUriSafe(try std.Uri.parse("https://auth.example.test/check?mode=strict")));
    try std.testing.expect(!authSubrequestUriSafe(try std.Uri.parse("https://auth.example.test/check\r\nX-Injected:%20yes")));
    try std.testing.expect(!authSubrequestUriSafe(try std.Uri.parse("https://user:secret@auth.example.test/check")));
    try std.testing.expect(!authSubrequestUriSafe(try std.Uri.parse("https://auth.example.test/check#fragment")));
    try std.testing.expectEqualStrings("::1", unbracketUriHost("[::1]"));
    try std.testing.expectEqualStrings("auth.example.test", unbracketUriHost("auth.example.test"));
    try std.testing.expect(!authSubrequestBytesSafe("auth.example.test\r\nX-Injected: yes", false));
}

test "auth subrequest TLS cannot inherit an insecure origin policy" {
    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    cfg.upstream_tls_verify = false;
    cfg.upstream_tls_server_name = "unrelated-origin.example.test";
    cfg.upstream_tls_ca_bundle = "/private/ca.pem";
    cfg.upstream_tls_client_cert = "/private/client.pem";
    cfg.upstream_tls_client_key = "/private/client.key";

    const options = authSubrequestTlsOptions(&cfg);
    try std.testing.expect(!options.skip_verify);
    try std.testing.expectEqualStrings("", options.sni_override);
    try std.testing.expectEqualStrings(cfg.upstream_tls_ca_bundle, options.ca_bundle_path);
    try std.testing.expectEqualStrings(cfg.upstream_tls_client_cert, options.client_cert_path);
    try std.testing.expectEqualStrings(cfg.upstream_tls_client_key, options.client_key_path);
}

test "routeRequiresApprovalRule detects approval requirement" {
    try std.testing.expect(routeRequiresApprovalRule("POST", "/api/tasks", "POST|/api/tasks|ops|true||"));
    try std.testing.expect(!routeRequiresApprovalRule("POST", "/api/messages", "POST|/api/tasks|ops|true||"));
}

test "time windows fail closed on malformed and out-of-range policy values" {
    try std.testing.expect(!timeWindowAllows("all-day"));
    try std.testing.expect(!timeWindowAllows("0-255"));
    try std.testing.expect(!timeWindowAllows("24-1"));
    try std.testing.expect(!timeWindowAllows("0-25"));
    try std.testing.expect(!timeWindowAllows("1-2-3"));
    try std.testing.expect(timeWindowAllows("0-24"));
}

test "policy evaluation denies invalid regex and approval boolean" {
    const allocator = std.testing.allocator;
    var headers = http.Headers.init(allocator);
    defer headers.deinit();

    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    var state: GatewayState = undefined;

    cfg.policy_rules_raw = "POST|[|commands.execute|false||";
    try std.testing.expectEqualStrings("Invalid policy rule", evaluatePolicy(&state, &cfg, "POST", "/v1/commands", null, null, &headers).?);

    cfg.policy_rules_raw = "POST|^/v1/commands$||tru||";
    try std.testing.expectEqualStrings("Invalid policy rule", evaluatePolicy(&state, &cfg, "POST", "/v1/commands", null, null, &headers).?);
}

test "device request signatures use HMAC-SHA256 and exact constant-time MAC comparison" {
    const key = "device-secret";
    const signing_input = "POST\n/v1/commands\n1700000000\n{\"command\":\"status\"}";
    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, signing_input, key);
    var encoded: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&encoded, "{f}", .{compat.fmtSliceHexLower(&mac)}) catch unreachable;

    try std.testing.expect(verifyDeviceRequestSignature(key, signing_input, &encoded));
    encoded[63] = if (encoded[63] == '0') '1' else '0';
    try std.testing.expect(!verifyDeviceRequestSignature(key, signing_input, &encoded));
    try std.testing.expect(!verifyDeviceRequestSignature(key, signing_input, encoded[0..63]));
    try std.testing.expect(!verifyDeviceRequestSignature(key, signing_input, "not-hex-not-a-mac"));
}

test "evaluatePolicy bypasses approval management endpoints" {
    const allocator = std.testing.allocator;
    var headers = http.Headers.init(allocator);
    defer headers.deinit();

    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    cfg.policy_approval_routes_raw = "POST|^/v1/commands$";

    var state: GatewayState = undefined;
    try std.testing.expect(evaluatePolicy(&state, &cfg, "POST", "/approvals/request", null, null, &headers) == null);
    try std.testing.expect(evaluatePolicy(&state, &cfg, "POST", "/approvals/respond", null, null, &headers) == null);
    try std.testing.expect(evaluatePolicy(&state, &cfg, "GET", "/approvals/status", null, null, &headers) == null);
}

test "parseApprovalResponseBody parses approve and deny" {
    const allocator = std.testing.allocator;
    var approve = try parseApprovalResponseBody(allocator, "{\"approval_token\":\"tok-1\",\"decision\":\"approve\"}");
    defer approve.deinit(allocator);
    try std.testing.expectEqualStrings("tok-1", approve.token);
    try std.testing.expectEqual(ApprovalDecision.approve, approve.decision);

    var deny = try parseApprovalResponseBody(allocator, "{\"approval_token\":\"tok-2\",\"decision\":\"deny\"}");
    defer deny.deinit(allocator);
    try std.testing.expectEqualStrings("tok-2", deny.token);
    try std.testing.expectEqual(ApprovalDecision.deny, deny.decision);
}

test "parseApprovalRequestBody parses command scoped request" {
    const allocator = std.testing.allocator;
    var req = try parseApprovalRequestBody(allocator, "{\"method\":\"POST\",\"path\":\"/api/tasks\",\"command_id\":\"cmd-123\"}");
    defer req.deinit(allocator);
    try std.testing.expectEqualStrings("POST", req.method);
    try std.testing.expectEqualStrings("/api/tasks", req.path);
    try std.testing.expect(req.command_id != null);
    try std.testing.expectEqualStrings("cmd-123", req.command_id.?);
}

test "device registry is created owner-only and refuses insecure permissions" {
    // The registry holds HMAC shared secrets for every device, so Tardigrade
    // must not create it 0644 (the pre-HMAC default) and must not append a new
    // secret to a registry other local accounts can read.
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);

    const path = try std.fmt.allocPrint(allocator, "{s}/devices.registry", .{tmp_abs});
    defer allocator.free(path);
    try registerDeviceIdentity(path, "device-1", "s3cret-hmac-key");

    {
        const created = try std.Io.Dir.openFileAbsolute(compat.io(), path, .{});
        defer created.close(compat.io());
        const stat = try created.stat(compat.io());
        try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), stat.permissions.toMode() & 0o777);
    }

    // A registry loosened out-of-band must fail closed rather than gain
    // another device secret.
    {
        var loosened = try compat.cwd().openFile(path, .{ .mode = .read_write });
        defer loosened.close();
        try std.testing.expectEqual(@as(c_int, 0), std.c.fchmod(loosened.file.handle, 0o644));
    }
    try std.testing.expectError(
        error.InsecureDeviceRegistryPermissions,
        registerDeviceIdentity(path, "device-2", "another-secret"),
    );
}

test "device HMAC key material is wiped after verification" {
    // Regression: the registry read buffer holds every device's secret and the
    // returned key is secret material; both were previously freed unwiped.
    var detector = secrets.CredentialWipeDetector.init(std.testing.allocator);
    const allocator = detector.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_abs);
    const path = try std.fmt.allocPrint(allocator, "{s}/devices.registry", .{tmp_abs});
    defer allocator.free(path);
    try registerDeviceIdentity(path, "device-1", "s3cret-hmac-key");

    const key = loadRegisteredDeviceKey(allocator, path, "device-1").?;
    try std.testing.expectEqualStrings("s3cret-hmac-key", key);
    detector.watch(key);
    secrets.secureZeroAndFree(allocator, @constCast(key));
    try std.testing.expect(detector.allWatchedWiped());

    // An unknown device yields no key at all.
    try std.testing.expect(loadRegisteredDeviceKey(allocator, path, "device-absent") == null);
}

test "device registration accepts the hmac_key name and the legacy spelling" {
    const allocator = std.testing.allocator;
    var current = try parseDeviceRegistration(allocator, "{\"device_id\":\"d1\",\"hmac_key\":\"k1\"}");
    defer current.deinit(allocator);
    try std.testing.expectEqualStrings("k1", current.hmac_key);

    var legacy = try parseDeviceRegistration(allocator, "{\"device_id\":\"d1\",\"public_key\":\"k2\"}");
    defer legacy.deinit(allocator);
    try std.testing.expectEqualStrings("k2", legacy.hmac_key);

    try std.testing.expectError(
        error.InvalidDeviceRegistration,
        parseDeviceRegistration(allocator, "{\"device_id\":\"d1\"}"),
    );
    try std.testing.expectError(
        error.InvalidDeviceRegistration,
        parseDeviceRegistration(allocator, "{\"device_id\":\"victim|forged\",\"hmac_key\":\"key\"}"),
    );
    try std.testing.expectError(
        error.InvalidDeviceRegistration,
        parseDeviceRegistration(allocator, "{\"device_id\":\"victim\\nforged\",\"hmac_key\":\"key\"}"),
    );
    try std.testing.expectError(
        error.InvalidDeviceRegistration,
        parseDeviceRegistration(allocator, "{\"device_id\":\"victim\",\"hmac_key\":\"key|forged\"}"),
    );
}
