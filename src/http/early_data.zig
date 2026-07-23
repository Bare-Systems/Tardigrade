const std = @import("std");
const status = @import("status.zig");

pub const HEADER_NAME = "Early-Data";
pub const HEADER_VALUE = "1";

pub const ActionClass = enum {
    local,
    proxy,
    defer_until_handshake,
};

pub const Decision = enum {
    ordinary,
    execute_local,
    forward_rfc8470,
    too_early,
    defer_until_handshake,
};

pub const Inputs = struct {
    replay_exposed: bool,
    transport_early: bool,
    inbound_marker: bool,
    method_safe: bool,
    route_replay_safe: bool,
    action_class: ActionClass,
    proxy_origin_rfc8470: bool,
};

pub const TooEarlyPlan = struct {
    status: status.Status = .too_early,
    code: []const u8 = "too_early",
    message: []const u8 = "Request rejected because it was sent in early data and the route is not replay safe.",
};

pub fn decide(inputs: Inputs) Decision {
    const exposed = inputs.replay_exposed or inputs.transport_early or inputs.inbound_marker;
    if (!exposed) return .ordinary;

    if (inputs.action_class == .defer_until_handshake) return .defer_until_handshake;

    const replay_safe = inputs.method_safe or inputs.route_replay_safe;
    if (!replay_safe) return .too_early;

    return switch (inputs.action_class) {
        .local => .execute_local,
        .proxy => if (inputs.proxy_origin_rfc8470) .forward_rfc8470 else .too_early,
        .defer_until_handshake => unreachable,
    };
}

pub fn tooEarlyPlan() TooEarlyPlan {
    return .{};
}

pub fn methodSafe(method: []const u8) bool {
    return std.ascii.eqlIgnoreCase(method, "GET") or
        std.ascii.eqlIgnoreCase(method, "HEAD") or
        std.ascii.eqlIgnoreCase(method, "OPTIONS") or
        std.ascii.eqlIgnoreCase(method, "TRACE");
}

test "early data decision treats unexposed requests as ordinary" {
    try std.testing.expectEqual(Decision.ordinary, decide(.{
        .replay_exposed = false,
        .transport_early = false,
        .inbound_marker = false,
        .method_safe = false,
        .route_replay_safe = false,
        .action_class = .proxy,
        .proxy_origin_rfc8470 = false,
    }));
}

test "early data decision rejects unsafe replay-exposed work" {
    try std.testing.expectEqual(Decision.too_early, decide(.{
        .replay_exposed = true,
        .transport_early = false,
        .inbound_marker = false,
        .method_safe = false,
        .route_replay_safe = false,
        .action_class = .local,
        .proxy_origin_rfc8470 = false,
    }));
}

test "early data decision executes replay-safe local work" {
    try std.testing.expectEqual(Decision.execute_local, decide(.{
        .replay_exposed = false,
        .transport_early = true,
        .inbound_marker = false,
        .method_safe = false,
        .route_replay_safe = true,
        .action_class = .local,
        .proxy_origin_rfc8470 = false,
    }));
}

test "early data decision forwards only to RFC 8470 aware proxy origins" {
    const base = Inputs{
        .replay_exposed = false,
        .transport_early = false,
        .inbound_marker = true,
        .method_safe = true,
        .route_replay_safe = false,
        .action_class = .proxy,
        .proxy_origin_rfc8470 = false,
    };

    try std.testing.expectEqual(Decision.too_early, decide(base));
    var aware = base;
    aware.proxy_origin_rfc8470 = true;
    try std.testing.expectEqual(Decision.forward_rfc8470, decide(aware));
}

test "early data decision supports explicit handshake deferral" {
    try std.testing.expectEqual(Decision.defer_until_handshake, decide(.{
        .replay_exposed = false,
        .transport_early = true,
        .inbound_marker = false,
        .method_safe = true,
        .route_replay_safe = false,
        .action_class = .defer_until_handshake,
        .proxy_origin_rfc8470 = false,
    }));
}

test "early data method safety follows HTTP safe methods" {
    try std.testing.expect(methodSafe("GET"));
    try std.testing.expect(methodSafe("head"));
    try std.testing.expect(methodSafe("OPTIONS"));
    try std.testing.expect(methodSafe("TRACE"));
    try std.testing.expect(!methodSafe("POST"));
}
