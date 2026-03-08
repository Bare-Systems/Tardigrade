const std = @import("std");
const logger = @import("logger.zig");

pub const AccessLogEntry = struct {
    method: []const u8,
    path: []const u8,
    status: u16,
    latency_ms: i64,
    client_ip: []const u8,
    correlation_id: []const u8,
    identity: []const u8,
    user_agent: []const u8,
    bytes_sent: usize,
    error_category: []const u8,

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

pub const Config = struct {
    format: Format = .json,
    custom_template: []const u8 = "",
    min_status: u16 = 0,
    buffer_size_bytes: usize = 0,
    syslog_udp_endpoint: []const u8 = "",
};

const State = struct {
    allocator: std.mem.Allocator,
    cfg: Config,
    mutex: std.Thread.Mutex = .{},
    buffer: std.ArrayList(u8),
};

var global_state: ?*State = null;

pub fn init(allocator: std.mem.Allocator, cfg: Config) !void {
    if (global_state != null) return;
    const st = try allocator.create(State);
    st.* = .{
        .allocator = allocator,
        .cfg = cfg,
        .buffer = std.ArrayList(u8).init(allocator),
    };
    global_state = st;
}

pub fn deinit() void {
    if (global_state) |st| {
        st.mutex.lock();
        flushLocked(st);
        st.mutex.unlock();
        st.buffer.deinit();
        st.allocator.destroy(st);
        global_state = null;
    }
}

pub fn emit(entry: AccessLogEntry) void {
    if (global_state) |st| {
        if (st.cfg.min_status > 0 and entry.status < st.cfg.min_status) return;
        const line = formatEntry(st.allocator, st.cfg, entry) catch return;
        defer st.allocator.free(line);

        st.mutex.lock();
        defer st.mutex.unlock();

        if (st.cfg.buffer_size_bytes == 0) {
            writeLine(line, st.cfg.syslog_udp_endpoint);
            return;
        }
        st.buffer.appendSlice(line) catch return;
        if (st.buffer.items.len >= st.cfg.buffer_size_bytes) flushLocked(st);
        return;
    }

    const line = formatEntry(std.heap.page_allocator, .{}, entry) catch return;
    defer std.heap.page_allocator.free(line);
    writeLine(line, "");
}

fn formatEntry(allocator: std.mem.Allocator, cfg: Config, entry: AccessLogEntry) ![]u8 {
    var ts_buf: [32]u8 = undefined;
    const ts = logger.formatTimestamp(&ts_buf);
    return switch (cfg.format) {
        .json => std.fmt.allocPrint(
            allocator,
            "{{\"type\":\"access\",\"ts\":\"{s}\",\"method\":\"{s}\",\"path\":\"{s}\",\"status\":{d},\"latency_ms\":{d},\"client_ip\":\"{s}\",\"correlation_id\":\"{s}\",\"identity\":\"{s}\",\"user_agent\":\"{s}\",\"bytes_sent\":{d},\"error_category\":\"{s}\"}}\n",
            .{ ts, entry.method, entry.path, entry.status, entry.latency_ms, entry.client_ip, entry.correlation_id, entry.identity, entry.user_agent, entry.bytes_sent, entry.error_category },
        ),
        .plain => std.fmt.allocPrint(
            allocator,
            "{s} {s} {d} {d}ms ip={s} req={s} id={s} ua=\"{s}\" err={s}\n",
            .{ entry.method, entry.path, entry.status, entry.latency_ms, entry.client_ip, entry.correlation_id, entry.identity, entry.user_agent, entry.error_category },
        ),
        .custom => renderTemplate(allocator, if (cfg.custom_template.len > 0) cfg.custom_template else "{method} {path} {status}", ts, entry),
    };
}

fn renderTemplate(allocator: std.mem.Allocator, template: []const u8, ts: []const u8, entry: AccessLogEntry) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    var i: usize = 0;
    while (i < template.len) {
        if (template[i] == '{') {
            const close = std.mem.indexOfScalarPos(u8, template, i + 1, '}') orelse {
                try out.append(template[i]);
                i += 1;
                continue;
            };
            const key = template[i + 1 .. close];
            if (std.mem.eql(u8, key, "status")) {
                try out.writer().print("{d}", .{entry.status});
            } else if (std.mem.eql(u8, key, "latency_ms")) {
                try out.writer().print("{d}", .{entry.latency_ms});
            } else if (std.mem.eql(u8, key, "bytes_sent")) {
                try out.writer().print("{d}", .{entry.bytes_sent});
            } else {
                const replacement: []const u8 = if (std.mem.eql(u8, key, "ts"))
                    ts
                else if (std.mem.eql(u8, key, "method"))
                    entry.method
                else if (std.mem.eql(u8, key, "path"))
                    entry.path
                else if (std.mem.eql(u8, key, "client_ip"))
                    entry.client_ip
                else if (std.mem.eql(u8, key, "correlation_id"))
                    entry.correlation_id
                else if (std.mem.eql(u8, key, "identity"))
                    entry.identity
                else if (std.mem.eql(u8, key, "user_agent"))
                    entry.user_agent
                else if (std.mem.eql(u8, key, "error_category"))
                    entry.error_category
                else
                    "";
                try out.appendSlice(replacement);
            }
            i = close + 1;
            continue;
        }
        try out.append(template[i]);
        i += 1;
    }

    if (out.items.len == 0 or out.items[out.items.len - 1] != '\n') try out.append('\n');
    return out.toOwnedSlice();
}

fn writeLine(line: []const u8, syslog_udp_endpoint: []const u8) void {
    std.io.getStdErr().writer().writeAll(line) catch {};
    if (syslog_udp_endpoint.len > 0) sendSyslogUdp(syslog_udp_endpoint, line);
}

fn flushLocked(st: *State) void {
    if (st.buffer.items.len == 0) return;
    writeLine(st.buffer.items, st.cfg.syslog_udp_endpoint);
    st.buffer.clearRetainingCapacity();
}

fn sendSyslogUdp(endpoint: []const u8, msg: []const u8) void {
    const colon = std.mem.lastIndexOfScalar(u8, endpoint, ':') orelse return;
    const host = endpoint[0..colon];
    const port = std.fmt.parseInt(u16, endpoint[colon + 1 ..], 10) catch return;
    const addr = std.net.Address.resolveIp(host, port) catch return;
    const sock = std.posix.socket(addr.any.family, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP) catch return;
    defer std.posix.close(sock);
    _ = std.posix.sendto(sock, msg, 0, &addr.any, addr.getOsSockLen()) catch {};
}

test "AccessLogEntry fields are set correctly" {
    const entry = AccessLogEntry{
        .method = "POST",
        .path = "/v1/chat",
        .status = 200,
        .latency_ms = 42,
        .client_ip = "1.2.3.4",
        .correlation_id = "req-001",
        .identity = "token-abc",
        .user_agent = "curl/8.0",
        .bytes_sent = 256,
        .error_category = "-",
    };

    try std.testing.expectEqualStrings("POST", entry.method);
    try std.testing.expectEqualStrings("/v1/chat", entry.path);
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
        .path = "/metrics",
        .status = 200,
        .latency_ms = 0,
        .client_ip = "127.0.0.1",
        .correlation_id = "test-001",
        .identity = "-",
        .user_agent = "",
        .bytes_sent = 0,
        .error_category = "-",
    };
    entry.log();
}
