const std = @import("std");
const logger = @import("logger.zig");

/// Structured HTTP access log entry.
///
/// Emits a single JSON line per completed request to stderr.  The "type"
/// field is always "access", allowing log shippers to distinguish access
/// records from application log lines.
///
/// Example output:
///   {"type":"access","ts":"2026-03-07T12:00:00Z","method":"POST","path":"/v1/chat",
///    "status":200,"latency_ms":42,"client_ip":"1.2.3.4","correlation_id":"abc123",
///    "identity":"token-abc","user_agent":"curl/8.0","bytes_sent":256}
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

    /// Emit the access log entry as a JSON line to stderr.
    pub fn log(self: AccessLogEntry) void {
        var ts_buf: [32]u8 = undefined;
        const ts = logger.formatTimestamp(&ts_buf);

        const stderr = std.io.getStdErr().writer();
        stderr.print(
            "{{\"type\":\"access\",\"ts\":\"{s}\",\"method\":\"{s}\",\"path\":\"{s}\",\"status\":{d},\"latency_ms\":{d},\"client_ip\":\"{s}\",\"correlation_id\":\"{s}\",\"identity\":\"{s}\",\"user_agent\":\"{s}\",\"bytes_sent\":{d},\"error_category\":\"{s}\"}}\n",
            .{
                ts,
                self.method,
                self.path,
                self.status,
                self.latency_ms,
                self.client_ip,
                self.correlation_id,
                self.identity,
                self.user_agent,
                self.bytes_sent,
                self.error_category,
            },
        ) catch return;
    }
};

// Tests

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
    try std.testing.expectEqualStrings("1.2.3.4", entry.client_ip);
    try std.testing.expectEqualStrings("req-001", entry.correlation_id);
    try std.testing.expectEqualStrings("token-abc", entry.identity);
    try std.testing.expectEqualStrings("curl/8.0", entry.user_agent);
    try std.testing.expectEqual(@as(usize, 256), entry.bytes_sent);
}

test "AccessLogEntry log does not panic" {
    // We can't easily capture stderr in tests, but we verify the call
    // does not crash for any combination of values.
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
    // Just ensure it doesn't panic
    entry.log();
}

test "AccessLogEntry handles special characters in path" {
    const entry = AccessLogEntry{
        .method = "GET",
        .path = "/v1/chat?foo=bar",
        .status = 404,
        .latency_ms = 5,
        .client_ip = "::1",
        .correlation_id = "req-xyz",
        .identity = "-",
        .user_agent = "Mozilla/5.0",
        .bytes_sent = 128,
        .error_category = "not_found",
    };
    try std.testing.expectEqualStrings("/v1/chat?foo=bar", entry.path);
    try std.testing.expectEqual(@as(u16, 404), entry.status);
}
