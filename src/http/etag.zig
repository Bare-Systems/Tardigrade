const std = @import("std");

pub fn generateETag(allocator: std.mem.Allocator, size: usize, mtime: ?usize) ![]const u8 {
    // Format: "{hex_size}-{hex_mtime}"
    const m = if (mtime) |t| t else 0;
    return try std.fmt.allocPrint(allocator, "\"{x}-{x}\"", .{ size, m });
}

pub fn matchesIfNoneMatch(etag: []const u8, header: []const u8) bool {
    // If header is '*', it always matches
    if (std.mem.eql(u8, std.mem.trim(u8, header, " \t"), "*")) return true;
    // Simple substring match handles lists like '"a","b"'
    return std.mem.indexOf(u8, header, etag) != null;
}
