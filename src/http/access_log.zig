const compat = @import("../zig_compat.zig");
const std = @import("std");
const logger = @import("logger.zig");

pub const AccessLogEntry = struct {
    method: []const u8,
    path: []const u8,
    status: u16,
    latency_ms: i64,
    client_ip: []const u8,
    correlation_id: []const u8,
    upstream_addr: []const u8,
    upstream_status: ?u16,
    identity: []const u8,
    user_agent: []const u8,
    bytes_sent: usize,
    response_bytes: usize,
    error_category: []const u8,
    /// Cancellation or timeout reason when the request was terminated early.
    /// Empty string when the request completed normally.
    cancel_reason: []const u8 = "",

    pub fn log(self: AccessLogEntry) void {
        emit(self);
    }
};

pub const Format = enum {
    json,
    plain,
    custom,

    pub fn parse(raw: []const u8) ?Format {
        if (std.ascii.eqlIgnoreCase(raw, "json")) return .json;
        if (std.ascii.eqlIgnoreCase(raw, "plain")) return .plain;
        if (std.ascii.eqlIgnoreCase(raw, "custom")) return .custom;
        return null;
    }
};

/// Default set of header names that are always redacted.
/// These are lowercased and compared case-insensitively against incoming names.
pub const default_redact_header_names: []const []const u8 = &.{
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "proxy-authorization",
    "www-authenticate",
};

pub const Config = struct {
    format: Format = .json,
    custom_template: []const u8 = "",
    min_status: u16 = 0,
    buffer_size_bytes: usize = 0,
    syslog_udp_endpoint: []const u8 = "",
    /// Header names (lowercase) that must never appear in logs.
    /// Matched case-insensitively.  Defaults to `default_redact_header_names`
    /// when empty.  Pass a non-empty slice to override the default list.
    redact_header_names: []const []const u8 = &.{},
};

/// Returns true if `header_name` should be redacted from log output.
/// Comparison is case-insensitive.  When `redact_names` is empty the check
/// falls back to the built-in `default_redact_header_names` list.
pub fn shouldRedactHeader(header_name: []const u8, redact_names: []const []const u8) bool {
    const list = if (redact_names.len > 0) redact_names else default_redact_header_names;
    for (list) |name| {
        if (std.ascii.eqlIgnoreCase(header_name, name)) return true;
    }
    return false;
}

/// Sanitize a single header value for log output: returns `[REDACTED]` when
/// `header_name` appears in the configured (or default) redaction list, or the
/// original `value` otherwise.
pub fn sanitizeHeaderValue(header_name: []const u8, value: []const u8, redact_names: []const []const u8) []const u8 {
    return if (shouldRedactHeader(header_name, redact_names)) "[REDACTED]" else value;
}

const State = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    mutex: compat.Mutex = .{},
    buffer: std.ArrayList(u8),
    line_scratch: std.ArrayList(u8),
};

var global_state: ?*State = null;

pub fn init(allocator: std.mem.Allocator, cfg: Config) !void {
    if (global_state != null) return;
    const st = try allocator.create(State);
    st.* = .{
        .allocator = allocator,
        .cfg = cfg,
        .buffer = .empty,
        .line_scratch = .empty,
    };
    global_state = st;
}

pub fn deinit() void {
    if (global_state) |st| {
        st.mutex.lock();
        flushLocked(st);
        st.mutex.unlock();
        st.buffer.deinit(st.allocator);
        st.line_scratch.deinit(st.allocator);
        st.allocator.destroy(st);
        global_state = null;
    }
}

pub fn flush() void {
    if (global_state) |st| {
        st.mutex.lock();
        defer st.mutex.unlock();
        flushLocked(st);
    }
}

pub fn emit(entry: AccessLogEntry) void {
    if (global_state) |st| {
        if (st.cfg.min_status > 0 and entry.status < st.cfg.min_status) return;
        st.mutex.lock();
        defer st.mutex.unlock();

        if (st.cfg.buffer_size_bytes == 0) {
            formatEntryInto(st.allocator, &st.line_scratch, st.cfg, entry) catch return;
            writeLine(st.line_scratch.items, st.cfg.syslog_udp_endpoint);
            return;
        }
        appendEntry(st.allocator, &st.buffer, st.cfg, entry) catch return;
        if (st.buffer.items.len >= st.cfg.buffer_size_bytes) flushLocked(st);
        return;
    }

    const line = formatEntry(std.heap.page_allocator, .{}, entry) catch return;
    defer std.heap.page_allocator.free(line);
    writeLine(line, "");
}

fn formatEntry(allocator: std.mem.Allocator, cfg: Config, entry: AccessLogEntry) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try formatEntryInto(allocator, &out, cfg, entry);
    return out.toOwnedSlice(allocator);
}

fn formatEntryInto(allocator: std.mem.Allocator, out: *std.ArrayList(u8), cfg: Config, entry: AccessLogEntry) !void {
    out.clearRetainingCapacity();
    try appendEntry(allocator, out, cfg, entry);
}

fn appendEntry(allocator: std.mem.Allocator, out: *std.ArrayList(u8), cfg: Config, entry: AccessLogEntry) !void {
    var ts_buf: [32]u8 = undefined;
    const ts = logger.formatTimestamp(&ts_buf);
    var upstream_status_buf: [16]u8 = undefined;
    const upstream_status_text = if (entry.upstream_status) |status|
        std.fmt.bufPrint(&upstream_status_buf, "{d}", .{status}) catch "null"
    else
        "null";

    switch (cfg.format) {
        .json => try out.print(
            allocator,
            "{{\"type\":\"access\",\"ts\":\"{s}\",\"request_id\":\"{s}\",\"correlation_id\":\"{s}\",\"method\":\"{s}\",\"path\":\"{s}\",\"status\":{d},\"latency_ms\":{d},\"client_ip\":\"{s}\",\"upstream_addr\":\"{s}\",\"upstream_status\":{s},\"identity\":\"{s}\",\"user_agent\":\"{s}\",\"bytes_sent\":{d},\"response_bytes\":{d},\"error_category\":\"{s}\",\"cancel_reason\":\"{s}\"}}\n",
            .{
                ts,
                entry.correlation_id,
                entry.correlation_id,
                entry.method,
                entry.path,
                entry.status,
                entry.latency_ms,
                entry.client_ip,
                entry.upstream_addr,
                upstream_status_text,
                entry.identity,
                entry.user_agent,
                entry.bytes_sent,
                entry.response_bytes,
                entry.error_category,
                entry.cancel_reason,
            },
        ),
        .plain => if (entry.cancel_reason.len > 0)
            try out.print(
                allocator,
                "{s} {s} {d} {d}ms ip={s} req={s} upstream={s} upstream_status={?d} bytes={d} ua=\"{s}\" err={s} cancel={s}\n",
                .{ entry.method, entry.path, entry.status, entry.latency_ms, entry.client_ip, entry.correlation_id, entry.upstream_addr, entry.upstream_status, entry.response_bytes, entry.user_agent, entry.error_category, entry.cancel_reason },
            )
        else
            try out.print(
                allocator,
                "{s} {s} {d} {d}ms ip={s} req={s} upstream={s} upstream_status={?d} bytes={d} ua=\"{s}\" err={s}\n",
                .{ entry.method, entry.path, entry.status, entry.latency_ms, entry.client_ip, entry.correlation_id, entry.upstream_addr, entry.upstream_status, entry.response_bytes, entry.user_agent, entry.error_category },
            ),
        .custom => try appendTemplate(allocator, out, if (cfg.custom_template.len > 0) cfg.custom_template else "{method} {path} {status}", ts, entry),
    }
}

fn appendTemplate(allocator: std.mem.Allocator, out: *std.ArrayList(u8), template: []const u8, ts: []const u8, entry: AccessLogEntry) !void {
    var i: usize = 0;
    while (i < template.len) {
        if (template[i] == '{') {
            const close = std.mem.findScalarPos(u8, template, i + 1, '}') orelse {
                try out.append(allocator, template[i]);
                i += 1;
                continue;
            };
            const key = template[i + 1 .. close];
            if (std.mem.eql(u8, key, "status")) {
                try out.print(allocator, "{d}", .{entry.status});
            } else if (std.mem.eql(u8, key, "latency_ms")) {
                try out.print(allocator, "{d}", .{entry.latency_ms});
            } else if (std.mem.eql(u8, key, "bytes_sent")) {
                try out.print(allocator, "{d}", .{entry.bytes_sent});
            } else if (std.mem.eql(u8, key, "response_bytes")) {
                try out.print(allocator, "{d}", .{entry.response_bytes});
            } else if (std.mem.eql(u8, key, "upstream_status")) {
                if (entry.upstream_status) |status| {
                    try out.print(allocator, "{d}", .{status});
                }
            } else {
                const replacement: []const u8 = if (std.mem.eql(u8, key, "ts"))
                    ts
                else if (std.mem.eql(u8, key, "method"))
                    entry.method
                else if (std.mem.eql(u8, key, "path"))
                    entry.path
                else if (std.mem.eql(u8, key, "client_ip"))
                    entry.client_ip
                else if (std.mem.eql(u8, key, "request_id"))
                    entry.correlation_id
                else if (std.mem.eql(u8, key, "correlation_id"))
                    entry.correlation_id
                else if (std.mem.eql(u8, key, "upstream_addr"))
                    entry.upstream_addr
                else if (std.mem.eql(u8, key, "identity"))
                    entry.identity
                else if (std.mem.eql(u8, key, "user_agent"))
                    entry.user_agent
                else if (std.mem.eql(u8, key, "error_category"))
                    entry.error_category
                else if (std.mem.eql(u8, key, "cancel_reason"))
                    entry.cancel_reason
                else
                    "";
                try out.appendSlice(allocator, replacement);
            }
            i = close + 1;
            continue;
        }
        try out.append(allocator, template[i]);
        i += 1;
    }

    if (out.items.len == 0 or out.items[out.items.len - 1] != '\n') try out.append(allocator, '\n');
}

fn writeLine(line: []const u8, syslog_udp_endpoint: []const u8) void {
    var remaining = line;
    while (remaining.len > 0) {
        const n = std.c.write(std.posix.STDERR_FILENO, remaining.ptr, remaining.len);
        if (n <= 0) break;
        remaining = remaining[@as(usize, @intCast(n))..];
    }
    if (syslog_udp_endpoint.len > 0) sendSyslogUdp(syslog_udp_endpoint, line);
}

fn flushLocked(st: *State) void {
    if (st.buffer.items.len == 0) return;
    writeLine(st.buffer.items, st.cfg.syslog_udp_endpoint);
    st.buffer.clearRetainingCapacity();
}

fn sendSyslogUdp(endpoint: []const u8, msg: []const u8) void {
    const colon = std.mem.findScalarLast(u8, endpoint, ':') orelse return;
    const host = endpoint[0..colon];
    const port = std.fmt.parseInt(u16, endpoint[colon + 1 ..], 10) catch return;
    const addr = std.Io.net.IpAddress.resolve(compat.io(), host, port) catch return;
    switch (addr) {
        .ip4 => |ip4| {
            const sin = std.c.sockaddr.in{
                .family = std.posix.AF.INET,
                .port = std.mem.nativeToBig(u16, ip4.port),
                .addr = std.mem.readInt(u32, &ip4.bytes, .big),
                .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
            };
            const sock = std.c.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
            if (sock < 0) return;
            defer _ = std.c.close(sock);
            _ = std.c.sendto(sock, msg.ptr, msg.len, 0, @ptrCast(&sin), @sizeOf(std.c.sockaddr.in));
        },
        .ip6 => {},
    }
}

test "AccessLogEntry fields are set correctly" {
    const entry = AccessLogEntry{
        .method = "POST",
        .path = "/api/messages",
        .status = 200,
        .latency_ms = 42,
        .client_ip = "1.2.3.4",
        .correlation_id = "req-001",
        .upstream_addr = "http://127.0.0.1:8080",
        .upstream_status = 200,
        .identity = "token-abc",
        .user_agent = "curl/8.0",
        .bytes_sent = 256,
        .response_bytes = 256,
        .error_category = "-",
    };

    try std.testing.expectEqualStrings("POST", entry.method);
    try std.testing.expectEqualStrings("/api/messages", entry.path);
    try std.testing.expectEqual(@as(u16, 200), entry.status);
    try std.testing.expectEqual(@as(i64, 42), entry.latency_ms);
}

test "AccessLog format parse" {
    try std.testing.expectEqual(Format.json, Format.parse("json").?);
    try std.testing.expectEqual(Format.plain, Format.parse("plain").?);
    try std.testing.expectEqual(Format.custom, Format.parse("custom").?);
}

test "AccessLogEntry log does not panic" {
    const entry = AccessLogEntry{
        .method = "GET",
        .path = "/status/metrics",
        .status = 200,
        .latency_ms = 0,
        .client_ip = "127.0.0.1",
        .correlation_id = "test-001",
        .upstream_addr = "",
        .upstream_status = null,
        .identity = "-",
        .user_agent = "",
        .bytes_sent = 0,
        .response_bytes = 0,
        .error_category = "-",
    };
    entry.log();
}

test "formatEntry json contains required fields" {
    const entry = AccessLogEntry{
        .method = "POST",
        .path = "/api/chat",
        .status = 201,
        .latency_ms = 15,
        .client_ip = "10.0.0.1",
        .correlation_id = "corr-xyz",
        .upstream_addr = "http://127.0.0.1:9000",
        .upstream_status = 200,
        .identity = "user-1",
        .user_agent = "test-agent/1.0",
        .bytes_sent = 128,
        .response_bytes = 128,
        .error_category = "-",
    };
    const line = try formatEntry(std.testing.allocator, .{}, entry);
    defer std.testing.allocator.free(line);
    try std.testing.expect(std.mem.find(u8, line, "\"method\":\"POST\"") != null);
    try std.testing.expect(std.mem.find(u8, line, "\"path\":\"/api/chat\"") != null);
    try std.testing.expect(std.mem.find(u8, line, "\"status\":201") != null);
    try std.testing.expect(std.mem.find(u8, line, "\"identity\":\"user-1\"") != null);
    try std.testing.expect(std.mem.find(u8, line, "\"upstream_status\":200") != null);
    try std.testing.expect(std.mem.find(u8, line, "\"cancel_reason\":\"\"") != null);
}

test "formatEntry json encodes null upstream_status as literal null" {
    const entry = AccessLogEntry{
        .method = "GET",
        .path = "/health",
        .status = 200,
        .latency_ms = 0,
        .client_ip = "127.0.0.1",
        .correlation_id = "hc",
        .upstream_addr = "",
        .upstream_status = null,
        .identity = "-",
        .user_agent = "",
        .bytes_sent = 0,
        .response_bytes = 0,
        .error_category = "-",
    };
    const line = try formatEntry(std.testing.allocator, .{}, entry);
    defer std.testing.allocator.free(line);
    try std.testing.expect(std.mem.find(u8, line, "\"upstream_status\":null") != null);
}

test "formatEntryInto reuses a scratch buffer and matches formatEntry" {
    const entry = AccessLogEntry{
        .method = "GET",
        .path = "/proxy/health",
        .status = 200,
        .latency_ms = 1,
        .client_ip = "127.0.0.1",
        .correlation_id = "req-123",
        .upstream_addr = "http://127.0.0.1:8080/health",
        .upstream_status = 200,
        .identity = "-",
        .user_agent = "wrk/4.2.0",
        .bytes_sent = 2,
        .response_bytes = 2,
        .error_category = "-",
    };
    const cfg = Config{ .format = .plain };

    const expected = try formatEntry(std.testing.allocator, cfg, entry);
    defer std.testing.allocator.free(expected);

    var scratch = std.ArrayList(u8).empty;
    defer scratch.deinit(std.testing.allocator);
    try scratch.appendSlice(std.testing.allocator, "stale");

    try formatEntryInto(std.testing.allocator, &scratch, cfg, entry);
    try std.testing.expectEqualStrings(expected, scratch.items);
}

test "shouldRedactHeader matches default sensitive headers case-insensitively" {
    // Default sensitive headers should be redacted.
    try std.testing.expect(shouldRedactHeader("Authorization", &.{}));
    try std.testing.expect(shouldRedactHeader("AUTHORIZATION", &.{}));
    try std.testing.expect(shouldRedactHeader("authorization", &.{}));
    try std.testing.expect(shouldRedactHeader("Cookie", &.{}));
    try std.testing.expect(shouldRedactHeader("SET-COOKIE", &.{}));
    try std.testing.expect(shouldRedactHeader("X-Api-Key", &.{}));
    try std.testing.expect(shouldRedactHeader("Proxy-Authorization", &.{}));
    try std.testing.expect(shouldRedactHeader("WWW-Authenticate", &.{}));
    // Non-sensitive headers should pass through.
    try std.testing.expect(!shouldRedactHeader("Content-Type", &.{}));
    try std.testing.expect(!shouldRedactHeader("User-Agent", &.{}));
    try std.testing.expect(!shouldRedactHeader("Accept", &.{}));
    try std.testing.expect(!shouldRedactHeader("X-Request-ID", &.{}));
}

test "shouldRedactHeader uses custom list when provided" {
    const custom = &[_][]const u8{ "x-secret", "x-internal-token" };
    try std.testing.expect(shouldRedactHeader("X-Secret", custom));
    try std.testing.expect(shouldRedactHeader("x-internal-token", custom));
    // Custom list overrides defaults — Authorization is NOT in this custom list.
    try std.testing.expect(!shouldRedactHeader("Authorization", custom));
}

test "sanitizeHeaderValue returns [REDACTED] for sensitive headers" {
    try std.testing.expectEqualStrings("[REDACTED]", sanitizeHeaderValue("Authorization", "Bearer secret-token", &.{}));
    try std.testing.expectEqualStrings("[REDACTED]", sanitizeHeaderValue("cookie", "session=abc123", &.{}));
    // Safe header value passes through unchanged.
    try std.testing.expectEqualStrings("application/json", sanitizeHeaderValue("Content-Type", "application/json", &.{}));
}
