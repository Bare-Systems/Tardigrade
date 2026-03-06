const std = @import("std");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");

const MAX_REQUEST_SIZE: usize = 256 * 1024;
const JSON_CONTENT_TYPE = "application/json";

pub fn run(cfg: *const edge_config.EdgeConfig) !void {
    const address = try std.net.Address.parseIp(cfg.listen_host, cfg.listen_port);
    var server = try std.net.Address.listen(address, .{ .reuse_address = true });
    defer server.deinit();

    std.log.info("Tardigrade edge listening on {s}:{d}", .{ cfg.listen_host, cfg.listen_port });
    if (!edge_config.hasTlsFiles(cfg)) {
        std.log.warn("TLS cert/key not set; serving HTTP only. Set TARDIGRADE_TLS_CERT_PATH and TARDIGRADE_TLS_KEY_PATH.", .{});
    } else {
        std.log.info("TLS cert/key configured at {s} and {s}", .{ cfg.tls_cert_path, cfg.tls_key_path });
    }

    while (true) {
        const conn = try server.accept();
        handleConnection(conn.stream, cfg) catch |err| {
            std.log.err("edge connection error: {}", .{err});
        };
        conn.stream.close();
    }
}

fn handleConnection(stream: std.net.Stream, cfg: *const edge_config.EdgeConfig) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var req_buf: [MAX_REQUEST_SIZE]u8 = undefined;
    const total_read = try readHttpRequest(stream, req_buf[0..]);
    if (total_read == 0) return;

    const parse_result = http.Request.parse(allocator, req_buf[0..total_read], MAX_REQUEST_SIZE) catch |err| {
        try sendApiError(allocator, stream.writer(), .bad_request, "invalid_request", "Malformed request", null, false);
        std.log.warn("parse error: {}", .{err});
        return;
    };

    var request = parse_result.request;
    defer request.deinit();
    const writer = stream.writer();

    const correlation_id = try http.correlation.fromHeadersOrGenerate(allocator, &request.headers);
    defer allocator.free(correlation_id);

    const started = std.time.milliTimestamp();

    if (request.method == .GET and std.mem.eql(u8, request.uri.path, "/health")) {
        var response = http.Response.json(allocator, "{\"status\":\"ok\",\"service\":\"tardigrade-edge\"}");
        defer response.deinit();
        _ = response.setConnection(false).setHeader(http.correlation.HEADER_NAME, correlation_id);
        try response.write(writer);
        logAudit("/health", @intFromEnum(response.status), correlation_id, true, std.time.milliTimestamp() - started);
        return;
    }

    if (request.method == .POST and std.mem.eql(u8, request.uri.path, "/v1/chat")) {
        const auth_result = authorizeRequest(cfg, &request.headers);
        if (!auth_result.ok) {
            try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, false);
            logAudit("/v1/chat", 401, correlation_id, false, std.time.milliTimestamp() - started);
            return;
        }

        if (!isJsonContentType(request.contentType())) {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Content-Type must be application/json", correlation_id, false);
            logAudit("/v1/chat", 400, correlation_id, true, std.time.milliTimestamp() - started);
            return;
        }

        const body = request.body orelse {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Missing request body", correlation_id, false);
            logAudit("/v1/chat", 400, correlation_id, true, std.time.milliTimestamp() - started);
            return;
        };

        const message = parseChatMessage(allocator, body, cfg.max_message_chars) catch |err| {
            const msg = switch (err) {
                error.EmptyMessage => "message must not be empty",
                error.MessageTooLarge => "message too long",
                else => "invalid chat payload",
            };
            try sendApiError(allocator, writer, .bad_request, "invalid_request", msg, correlation_id, false);
            logAudit("/v1/chat", 400, correlation_id, true, std.time.milliTimestamp() - started);
            return;
        };

        const proxy_result = proxyChat(allocator, cfg, message, correlation_id) catch {
            try sendApiError(allocator, writer, .gateway_timeout, "upstream_timeout", "Upstream timeout", correlation_id, false);
            logAudit("/v1/chat", 504, correlation_id, true, std.time.milliTimestamp() - started);
            return;
        };
        defer allocator.free(proxy_result.body);

        var final_status: u16 = proxy_result.status;
        var final_body: []const u8 = proxy_result.body;
        if (proxy_result.status != 200) {
            const mapped = mapUpstreamError(proxy_result.status);
            final_status = mapped.status;
            final_body = try buildApiErrorJson(allocator, mapped.code, mapped.message, correlation_id);
            defer allocator.free(final_body);
        }

        var response = http.Response.json(allocator, final_body);
        defer response.deinit();
        _ = response.setStatus(@enumFromInt(final_status)).setConnection(false).setHeader(http.correlation.HEADER_NAME, correlation_id);
        try response.write(writer);
        logAudit("/v1/chat", final_status, correlation_id, true, std.time.milliTimestamp() - started);
        return;
    }

    try sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, false);
    logAudit(request.uri.path, 404, correlation_id, true, std.time.milliTimestamp() - started);
}

const AuthResult = struct { ok: bool };

fn authorizeRequest(cfg: *const edge_config.EdgeConfig, headers: *const http.Headers) AuthResult {
    if (cfg.auth_token_hashes.len == 0) return .{ .ok = false };
    const token = http.auth.authorize(headers, null) catch return .{ .ok = false };

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(token, &digest, .{});

    var digest_hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&digest_hex, "{s}", .{std.fmt.fmtSliceHexLower(&digest)}) catch return .{ .ok = false };

    for (cfg.auth_token_hashes) |allowed| {
        if (std.mem.eql(u8, allowed, digest_hex[0..])) return .{ .ok = true };
    }
    return .{ .ok = false };
}

fn isJsonContentType(content_type: ?[]const u8) bool {
    const ct = content_type orelse return false;
    var lower_buf: [128]u8 = undefined;
    const lower = if (ct.len <= lower_buf.len)
        std.ascii.lowerString(lower_buf[0..ct.len], ct)
    else
        ct;
    return std.mem.indexOf(u8, lower, JSON_CONTENT_TYPE) != null;
}

fn parseChatMessage(allocator: std.mem.Allocator, body: []const u8, max_len: usize) ![]const u8 {
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

const ProxyResult = struct {
    status: u16,
    body: []u8,
};

fn proxyChat(allocator: std.mem.Allocator, cfg: *const edge_config.EdgeConfig, message: []const u8, correlation_id: []const u8) !ProxyResult {
    defer allocator.free(message);

    const url = try std.fmt.allocPrint(allocator, "{s}/v1/chat", .{cfg.upstream_base_url});
    defer allocator.free(url);

    const request_body = try std.fmt.allocPrint(allocator, "{{\"message\":{s}}}", .{std.json.fmt(message, .{})});
    defer allocator.free(request_body);

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var body = std.ArrayList(u8).init(allocator);
    errdefer body.deinit();

    const opts = std.http.Client.FetchOptions{
        .location = .{ .url = url },
        .method = .POST,
        .payload = request_body,
        .response_storage = .{ .dynamic = &body },
        .headers = .{ .content_type = .{ .override = "application/json" } },
        .extra_headers = &[_]std.http.Header{
            .{ .name = http.correlation.HEADER_NAME, .value = correlation_id },
        },
    };

    const result = try client.fetch(opts);
    return .{
        .status = @intFromEnum(result.status),
        .body = try body.toOwnedSlice(),
    };
}

const UpstreamMappedError = struct {
    status: u16,
    code: []const u8,
    message: []const u8,
};

fn mapUpstreamError(status: u16) UpstreamMappedError {
    return switch (status) {
        401 => .{ .status = 401, .code = "unauthorized", .message = "Unauthorized" },
        429 => .{ .status = 429, .code = "rate_limited", .message = "Rate limited" },
        502, 503 => .{ .status = 503, .code = "tool_unavailable", .message = "Upstream unavailable" },
        504 => .{ .status = 504, .code = "upstream_timeout", .message = "Upstream timeout" },
        else => .{ .status = 500, .code = "internal_error", .message = "Internal error" },
    };
}

fn buildApiErrorJson(allocator: std.mem.Allocator, code: []const u8, message: []const u8, request_id: ?[]const u8) ![]u8 {
    if (request_id) |rid| {
        return std.fmt.allocPrint(allocator, "{{\"code\":\"{s}\",\"message\":\"{s}\",\"request_id\":\"{s}\"}}", .{ code, message, rid });
    }
    return std.fmt.allocPrint(allocator, "{{\"code\":\"{s}\",\"message\":\"{s}\",\"request_id\":null}}", .{ code, message });
}

fn sendApiError(allocator: std.mem.Allocator, writer: anytype, status: http.Status, code: []const u8, message: []const u8, request_id: ?[]const u8, keep_alive: bool) !void {
    const payload = try buildApiErrorJson(allocator, code, message, request_id);
    defer allocator.free(payload);

    var response = http.Response.json(allocator, payload);
    defer response.deinit();
    _ = response.setStatus(status).setConnection(keep_alive);
    if (request_id) |rid| {
        _ = response.setHeader(http.correlation.HEADER_NAME, rid);
    }
    try response.write(writer);
}

fn readHttpRequest(stream: std.net.Stream, buf: []u8) !usize {
    var total_read: usize = 0;
    var header_end: ?usize = null;

    while (total_read < buf.len) {
        const n = try stream.read(buf[total_read..]);
        if (n == 0) break;
        total_read += n;

        if (header_end == null) {
            if (std.mem.indexOf(u8, buf[0..total_read], "\r\n\r\n")) |pos| {
                header_end = pos + 4;
            }
        }

        if (header_end) |headers_len| {
            const content_length = parseContentLength(buf[0..headers_len]) orelse 0;
            if (total_read >= headers_len + content_length) break;
        }
    }

    return total_read;
}

fn parseContentLength(headers: []const u8) ?usize {
    var it = std.mem.tokenizeAny(u8, headers, "\r\n");
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        if (!std.ascii.eqlIgnoreCase(name, "content-length")) continue;

        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        return std.fmt.parseInt(usize, value, 10) catch null;
    }
    return null;
}

fn logAudit(route: []const u8, status: u16, correlation_id: []const u8, auth_ok: bool, latency_ms: i64) void {
    std.log.info("audit route={s} status={d} auth_ok={} correlation_id={s} latency_ms={d}", .{
        route,
        status,
        auth_ok,
        correlation_id,
        latency_ms,
    });
}

test "authorizeRequest accepts valid hash" {
    const allocator = std.testing.allocator;
    const token = "secret-token";

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(token, &digest, .{});
    const hash = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&digest)});
    defer allocator.free(hash);

    const hashes = try allocator.alloc([]const u8, 1);
    defer allocator.free(hashes);
    hashes[0] = hash;

    var cfg = edge_config.EdgeConfig{
        .listen_host = "0.0.0.0",
        .listen_port = 8069,
        .tls_cert_path = "",
        .tls_key_path = "",
        .upstream_base_url = "http://127.0.0.1:8080",
        .auth_token_hashes = hashes,
        .max_message_chars = 4000,
        .upstream_timeout_ms = 10000,
    };

    var headers = http.Headers.init(allocator);
    defer headers.deinit();
    try headers.append("Authorization", "Bearer secret-token");

    try std.testing.expect(authorizeRequest(&cfg, &headers).ok);
}

test "parseChatMessage validates payload" {
    const allocator = std.testing.allocator;
    const message = try parseChatMessage(allocator, "{\"message\":\"hello\"}", 10);
    defer allocator.free(message);
    try std.testing.expectEqualStrings("hello", message);

    try std.testing.expectError(error.MessageTooLarge, parseChatMessage(allocator, "{\"message\":\"hello\"}", 2));
}

test "mapUpstreamError returns stable codes" {
    const mapped = mapUpstreamError(502);
    try std.testing.expectEqual(@as(u16, 503), mapped.status);
    try std.testing.expectEqualStrings("tool_unavailable", mapped.code);
}
