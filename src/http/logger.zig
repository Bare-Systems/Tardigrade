const std = @import("std");
const compat = @import("../zig_compat.zig");

/// Log severity levels, ordered from most to least verbose.
pub const Level = enum(u8) {
    debug = 0,
    info = 1,
    warn = 2,
    err = 3,

    pub fn toString(self: Level) []const u8 {
        return switch (self) {
            .debug => "DEBUG",
            .info => "INFO",
            .warn => "WARN",
            .err => "ERROR",
        };
    }

    pub fn parse(s: []const u8) ?Level {
        if (std.ascii.eqlIgnoreCase(s, "debug")) return .debug;
        if (std.ascii.eqlIgnoreCase(s, "info")) return .info;
        if (std.ascii.eqlIgnoreCase(s, "warn") or std.ascii.eqlIgnoreCase(s, "warning")) return .warn;
        if (std.ascii.eqlIgnoreCase(s, "err") or std.ascii.eqlIgnoreCase(s, "error")) return .err;
        return null;
    }
};

/// Structured logger with severity levels, timestamps, and contextual fields.
///
/// Outputs JSON-structured log lines to stderr:
///   {"ts":"2026-03-07T12:00:00Z","level":"INFO","component":"gateway","msg":"..."}
pub const Logger = struct {
    min_level: Level,
    component: []const u8,

    pub const default_gateway = Logger{
        .min_level = .info,
        .component = "gateway",
    };

    pub fn init(min_level: Level, component: []const u8) Logger {
        return .{
            .min_level = min_level,
            .component = component,
        };
    }

    pub fn shouldLog(self: Logger, level: Level) bool {
        return @intFromEnum(level) >= @intFromEnum(self.min_level);
    }

    /// Log a message with optional correlation_id and extra key-value context.
    pub fn log(
        self: Logger,
        level: Level,
        correlation_id: ?[]const u8,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        if (!self.shouldLog(level)) return;

        var msg_buf: [2048]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, fmt, args) catch "(message too long)";

        self.emitJson(level, correlation_id, msg);
    }

    pub fn debug(self: Logger, correlation_id: ?[]const u8, comptime fmt: []const u8, args: anytype) void {
        self.log(.debug, correlation_id, fmt, args);
    }

    pub fn info(self: Logger, correlation_id: ?[]const u8, comptime fmt: []const u8, args: anytype) void {
        self.log(.info, correlation_id, fmt, args);
    }

    pub fn warn(self: Logger, correlation_id: ?[]const u8, comptime fmt: []const u8, args: anytype) void {
        self.log(.warn, correlation_id, fmt, args);
    }

    pub fn err(self: Logger, correlation_id: ?[]const u8, comptime fmt: []const u8, args: anytype) void {
        self.log(.err, correlation_id, fmt, args);
    }

    fn emitJson(self: Logger, level: Level, correlation_id: ?[]const u8, msg: []const u8) void {
        var ts_buf: [32]u8 = undefined;
        const ts = formatTimestamp(&ts_buf);

        var line_buf: [4096]u8 = undefined;
        var line_stream = compat.fixedBufferStream(&line_buf);
        appendJsonLine(line_stream.writer(), self, level, correlation_id, ts, msg) catch {
            var stderr_buf: [1024]u8 = undefined;
            var stderr = compat.stderrWriter(&stderr_buf);
            appendJsonLine(stderr, self, level, correlation_id, ts, msg) catch return;
            stderr.flush() catch {}; // best-effort flush; log loss on stderr is acceptable
            return;
        };
        writeLine(line_stream.getWritten());
    }
};

/// Format a UTC ISO 8601 timestamp into the provided buffer.
pub fn formatTimestamp(buf: *[32]u8) []const u8 {
    const timestamp = compat.unixTimestamp();
    const epoch_secs: std.time.epoch.EpochSeconds = .{ .secs = @intCast(timestamp) };
    const day_secs = epoch_secs.getDaySeconds();
    const epoch_day = epoch_secs.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    return std.fmt.bufPrint(buf, "{d}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        year_day.year,
        @intFromEnum(month_day.month),
        month_day.day_index + 1,
        day_secs.getHoursIntoDay(),
        day_secs.getMinutesIntoHour(),
        day_secs.getSecondsIntoMinute(),
    }) catch "1970-01-01T00:00:00Z";
}

fn appendJsonLine(writer: anytype, self: Logger, level: Level, correlation_id: ?[]const u8, ts: []const u8, msg: []const u8) !void {
    try writer.print("{{\"ts\":\"{s}\",\"level\":\"{s}\",\"component\":\"{s}\"", .{
        ts,
        level.toString(),
        self.component,
    });

    if (correlation_id) |cid| {
        try writer.print(",\"request_id\":\"{s}\",\"correlation_id\":\"{s}\"", .{ cid, cid });
    }

    try writer.writeAll(",\"msg\":\"");
    try writeJsonEscaped(writer, msg);
    try writer.writeAll("\"}\n");
}

fn writeLine(line: []const u8) void {
    var remaining = line;
    while (remaining.len > 0) {
        const n = std.c.write(std.posix.STDERR_FILENO, remaining.ptr, remaining.len);
        if (n <= 0) break;
        remaining = remaining[@as(usize, @intCast(n))..];
    }
}

/// Write a string to a writer with JSON escaping for special characters.
fn writeJsonEscaped(writer: anytype, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    try writer.print("\\u{d:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
}

// Tests

test "Level.parse valid levels" {
    try std.testing.expectEqual(Level.debug, Level.parse("debug").?);
    try std.testing.expectEqual(Level.info, Level.parse("INFO").?);
    try std.testing.expectEqual(Level.warn, Level.parse("warn").?);
    try std.testing.expectEqual(Level.warn, Level.parse("WARNING").?);
    try std.testing.expectEqual(Level.err, Level.parse("error").?);
    try std.testing.expectEqual(Level.err, Level.parse("ERR").?);
}

test "Level.parse invalid level" {
    try std.testing.expect(Level.parse("trace") == null);
    try std.testing.expect(Level.parse("fatal") == null);
    try std.testing.expect(Level.parse("") == null);
}

test "Level.toString round-trips" {
    try std.testing.expectEqualStrings("DEBUG", Level.debug.toString());
    try std.testing.expectEqualStrings("INFO", Level.info.toString());
    try std.testing.expectEqualStrings("WARN", Level.warn.toString());
    try std.testing.expectEqualStrings("ERROR", Level.err.toString());
}

test "Logger.shouldLog respects minimum level" {
    const logger = Logger.init(.warn, "test");
    try std.testing.expect(!logger.shouldLog(.debug));
    try std.testing.expect(!logger.shouldLog(.info));
    try std.testing.expect(logger.shouldLog(.warn));
    try std.testing.expect(logger.shouldLog(.err));
}

test "Logger.shouldLog debug allows all" {
    const logger = Logger.init(.debug, "test");
    try std.testing.expect(logger.shouldLog(.debug));
    try std.testing.expect(logger.shouldLog(.info));
    try std.testing.expect(logger.shouldLog(.warn));
    try std.testing.expect(logger.shouldLog(.err));
}

test "formatTimestamp produces valid ISO 8601" {
    var buf: [32]u8 = undefined;
    const ts = formatTimestamp(&buf);
    // Should contain 'T' and end with 'Z'
    try std.testing.expect(std.mem.find(u8, ts, "T") != null);
    try std.testing.expect(std.mem.endsWith(u8, ts, "Z"));
    // Should be at least 20 chars: "2026-03-07T12:00:00Z"
    try std.testing.expect(ts.len >= 20);
}

test "appendJsonLine escapes message content and includes correlation id" {
    const log = Logger.init(.info, "gateway");
    var buf: [256]u8 = undefined;
    var fbs = compat.fixedBufferStream(&buf);
    try appendJsonLine(fbs.writer(), log, .warn, "cid-1", "2026-05-11T00:00:00Z", "quote\"\nslash\\tab\t");
    const line = fbs.getWritten();
    try std.testing.expect(std.mem.find(u8, line, "\"level\":\"WARN\"") != null);
    try std.testing.expect(std.mem.find(u8, line, "\"request_id\":\"cid-1\"") != null);
    try std.testing.expect(std.mem.find(u8, line, "\"correlation_id\":\"cid-1\"") != null);
    try std.testing.expect(std.mem.find(u8, line, "\"msg\":\"quote\\\"\\nslash\\\\tab\\t\"") != null);
}
