//! Gateway-facing HTTP/3 helpers that sit above the native runtime
//! (`http3_runtime.zig`): Alt-Svc advertisement and the configuration status
//! string surfaced by the status API.

const std = @import("std");

pub fn formatAltSvc(allocator: std.mem.Allocator, https_port: u16) ![]u8 {
    return std.fmt.allocPrint(allocator, "h3=\":{d}\"", .{https_port});
}

pub fn configurationStatus(http3_enabled: bool, tls_ready: bool) []const u8 {
    if (!http3_enabled) return "disabled";
    if (!tls_ready) return "config_incomplete";
    return "configured";
}

test "http3 handler alt-svc formatting" {
    const value = try formatAltSvc(std.testing.allocator, 443);
    defer std.testing.allocator.free(value);
    try std.testing.expectEqualStrings("h3=\":443\"", value);
}

test "http3 handler configuration status reports expected states" {
    try std.testing.expectEqualStrings("disabled", configurationStatus(false, false));
    try std.testing.expectEqualStrings("config_incomplete", configurationStatus(true, false));
    try std.testing.expectEqualStrings("configured", configurationStatus(true, true));
}
