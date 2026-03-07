const std = @import("std");
const Allocator = std.mem.Allocator;

/// Supported command types that can be routed through the gateway.
pub const CommandType = enum {
    chat,
    tool_list,
    tool_run,
    status,

    pub fn fromString(s: []const u8) ?CommandType {
        const map = std.StaticStringMap(CommandType).initComptime(.{
            .{ "chat", .chat },
            .{ "tool.list", .tool_list },
            .{ "tool.run", .tool_run },
            .{ "status", .status },
        });
        return map.get(s);
    }

    pub fn toString(self: CommandType) []const u8 {
        return switch (self) {
            .chat => "chat",
            .tool_list => "tool.list",
            .tool_run => "tool.run",
            .status => "status",
        };
    }

    /// Returns the upstream path suffix for this command type.
    pub fn upstreamPath(self: CommandType) []const u8 {
        return switch (self) {
            .chat => "/v1/chat",
            .tool_list => "/v1/tools",
            .tool_run => "/v1/tools/run",
            .status => "/v1/status",
        };
    }
};

/// Parsed command envelope from the client.
pub const Command = struct {
    command_type: CommandType,
    /// Raw JSON params object (unparsed, forwarded to upstream).
    params_raw: []const u8,
    /// Caller-supplied idempotency key (inline in envelope).
    idempotency_key: ?[]const u8,

    pub fn deinit(self: *Command, allocator: Allocator) void {
        allocator.free(self.params_raw);
        if (self.idempotency_key) |k| allocator.free(k);
        self.* = undefined;
    }
};

pub const ParseError = error{
    InvalidJson,
    MissingCommand,
    UnknownCommand,
    InvalidParams,
};

/// Maximum size for the raw params JSON blob.
pub const MAX_PARAMS_SIZE: usize = 128 * 1024;

/// Parse a command envelope from a JSON body.
///
/// Expected shape:
/// ```json
/// {
///   "command": "chat",
///   "params": { ... },
///   "idempotency_key": "optional-key"
/// }
/// ```
pub fn parseCommand(allocator: Allocator, body: []const u8) !Command {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch
        return ParseError.InvalidJson;
    defer parsed.deinit();

    if (parsed.value != .object) return ParseError.InvalidJson;
    const obj = parsed.value.object;

    // "command" field (required)
    const cmd_val = obj.get("command") orelse return ParseError.MissingCommand;
    if (cmd_val != .string) return ParseError.MissingCommand;
    const command_type = CommandType.fromString(cmd_val.string) orelse return ParseError.UnknownCommand;

    // "params" field (required, must be object)
    const params_val = obj.get("params") orelse return ParseError.InvalidParams;
    if (params_val != .object) return ParseError.InvalidParams;

    // Re-serialize params to JSON string
    const params_raw = std.json.stringifyAlloc(allocator, params_val, .{}) catch
        return ParseError.InvalidParams;
    errdefer allocator.free(params_raw);

    if (params_raw.len > MAX_PARAMS_SIZE) {
        allocator.free(params_raw);
        return ParseError.InvalidParams;
    }

    // "idempotency_key" field (optional)
    var idempotency_key: ?[]const u8 = null;
    if (obj.get("idempotency_key")) |ik_val| {
        if (ik_val == .string and ik_val.string.len > 0 and ik_val.string.len <= 256) {
            idempotency_key = try allocator.dupe(u8, ik_val.string);
        }
    }

    return .{
        .command_type = command_type,
        .params_raw = params_raw,
        .idempotency_key = idempotency_key,
    };
}

/// Build an upstream request envelope that wraps the command params
/// with gateway context (identity, correlation, client info).
pub fn buildUpstreamEnvelope(
    allocator: Allocator,
    command_type: CommandType,
    params_raw: []const u8,
    correlation_id: []const u8,
    identity: []const u8,
    client_ip: []const u8,
    api_version: ?u16,
) ![]u8 {
    const version_str = if (api_version) |v|
        try std.fmt.allocPrint(allocator, "{d}", .{v})
    else
        try allocator.dupe(u8, "null");
    defer allocator.free(version_str);

    return std.fmt.allocPrint(allocator,
        \\{{"command":"{s}","params":{s},"context":{{"correlation_id":"{s}","identity":"{s}","client_ip":"{s}","api_version":{s},"timestamp":{d}}}}}
    , .{
        command_type.toString(),
        params_raw,
        correlation_id,
        identity,
        client_ip,
        version_str,
        std.time.timestamp(),
    });
}

/// Audit record for a processed command.
pub const CommandAudit = struct {
    command: []const u8,
    correlation_id: []const u8,
    identity: []const u8,
    status: u16,
    latency_ms: i64,

    pub fn log(self: CommandAudit) void {
        std.log.info("cmd={s} correlation_id={s} identity={s} status={d} latency_ms={d}", .{
            self.command,
            self.correlation_id,
            self.identity,
            self.status,
            self.latency_ms,
        });
    }
};

// Tests

test "CommandType fromString valid" {
    try std.testing.expectEqual(CommandType.chat, CommandType.fromString("chat").?);
    try std.testing.expectEqual(CommandType.tool_list, CommandType.fromString("tool.list").?);
    try std.testing.expectEqual(CommandType.tool_run, CommandType.fromString("tool.run").?);
    try std.testing.expectEqual(CommandType.status, CommandType.fromString("status").?);
}

test "CommandType fromString unknown" {
    try std.testing.expect(CommandType.fromString("nonexistent") == null);
    try std.testing.expect(CommandType.fromString("") == null);
}

test "CommandType upstreamPath" {
    try std.testing.expectEqualStrings("/v1/chat", CommandType.chat.upstreamPath());
    try std.testing.expectEqualStrings("/v1/tools", CommandType.tool_list.upstreamPath());
    try std.testing.expectEqualStrings("/v1/tools/run", CommandType.tool_run.upstreamPath());
    try std.testing.expectEqualStrings("/v1/status", CommandType.status.upstreamPath());
}

test "parseCommand valid chat" {
    const allocator = std.testing.allocator;
    var cmd = try parseCommand(allocator, "{\"command\":\"chat\",\"params\":{\"message\":\"hello\"}}");
    defer cmd.deinit(allocator);

    try std.testing.expectEqual(CommandType.chat, cmd.command_type);
    try std.testing.expect(cmd.idempotency_key == null);
    // params_raw should contain the message
    try std.testing.expect(std.mem.indexOf(u8, cmd.params_raw, "hello") != null);
}

test "parseCommand with idempotency key" {
    const allocator = std.testing.allocator;
    var cmd = try parseCommand(allocator, "{\"command\":\"tool.run\",\"params\":{\"tool\":\"calc\"},\"idempotency_key\":\"abc-123\"}");
    defer cmd.deinit(allocator);

    try std.testing.expectEqual(CommandType.tool_run, cmd.command_type);
    try std.testing.expectEqualStrings("abc-123", cmd.idempotency_key.?);
}

test "parseCommand missing command field" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(ParseError.MissingCommand, parseCommand(allocator, "{\"params\":{}}"));
}

test "parseCommand unknown command" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(ParseError.UnknownCommand, parseCommand(allocator, "{\"command\":\"bogus\",\"params\":{}}"));
}

test "parseCommand missing params" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(ParseError.InvalidParams, parseCommand(allocator, "{\"command\":\"chat\"}"));
}

test "parseCommand params not object" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(ParseError.InvalidParams, parseCommand(allocator, "{\"command\":\"chat\",\"params\":\"string\"}"));
}

test "parseCommand invalid json" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(ParseError.InvalidJson, parseCommand(allocator, "not json"));
}

test "buildUpstreamEnvelope produces valid JSON" {
    const allocator = std.testing.allocator;
    const envelope = try buildUpstreamEnvelope(
        allocator,
        .chat,
        "{\"message\":\"hi\"}",
        "corr-123",
        "user-abc",
        "10.0.0.1",
        1,
    );
    defer allocator.free(envelope);

    // Verify it parses as valid JSON
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, envelope, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("chat", obj.get("command").?.string);

    const ctx = obj.get("context").?.object;
    try std.testing.expectEqualStrings("corr-123", ctx.get("correlation_id").?.string);
    try std.testing.expectEqualStrings("user-abc", ctx.get("identity").?.string);
    try std.testing.expectEqualStrings("10.0.0.1", ctx.get("client_ip").?.string);
    try std.testing.expectEqual(@as(i64, 1), ctx.get("api_version").?.integer);
}

test "buildUpstreamEnvelope null api_version" {
    const allocator = std.testing.allocator;
    const envelope = try buildUpstreamEnvelope(
        allocator,
        .status,
        "{}",
        "corr-456",
        "anon",
        "127.0.0.1",
        null,
    );
    defer allocator.free(envelope);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, envelope, .{});
    defer parsed.deinit();

    const ctx = parsed.value.object.get("context").?.object;
    try std.testing.expect(ctx.get("api_version").? == .null);
}

test "CommandType toString roundtrip" {
    const types = [_]CommandType{ .chat, .tool_list, .tool_run, .status };
    for (types) |ct| {
        try std.testing.expectEqual(ct, CommandType.fromString(ct.toString()).?);
    }
}
