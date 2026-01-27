const std = @import("std");
const Allocator = std.mem.Allocator;

/// Maximum number of headers allowed
pub const MAX_HEADERS = 100;

/// Maximum size of a single header line (name + value)
pub const MAX_HEADER_SIZE = 8 * 1024; // 8KB

/// Maximum total size of all headers
pub const MAX_HEADERS_TOTAL_SIZE = 32 * 1024; // 32KB

/// A single HTTP header
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// HTTP Headers collection
/// Stores headers with lowercase names for case-insensitive lookup
pub const Headers = struct {
    allocator: Allocator,
    items: std.ArrayList(Header),

    pub fn init(allocator: Allocator) Headers {
        return .{
            .allocator = allocator,
            .items = std.ArrayList(Header).init(allocator),
        };
    }

    pub fn deinit(self: *Headers) void {
        // Free duplicated strings
        for (self.items.items) |header| {
            self.allocator.free(header.name);
            self.allocator.free(header.value);
        }
        self.items.deinit();
    }

    /// Add a header (name will be lowercased)
    pub fn append(self: *Headers, name: []const u8, value: []const u8) !void {
        if (self.items.items.len >= MAX_HEADERS) {
            return error.TooManyHeaders;
        }

        // Lowercase the name for consistent lookup
        const lower_name = try self.allocator.alloc(u8, name.len);
        for (name, 0..) |c, i| {
            lower_name[i] = std.ascii.toLower(c);
        }

        // Trim whitespace from value
        const trimmed_value = std.mem.trim(u8, value, " \t");
        const value_copy = try self.allocator.dupe(u8, trimmed_value);

        try self.items.append(.{
            .name = lower_name,
            .value = value_copy,
        });
    }

    /// Get the first header value by name (case-insensitive)
    pub fn get(self: *const Headers, name: []const u8) ?[]const u8 {
        // Create lowercase version for comparison
        var lower_buf: [256]u8 = undefined;
        if (name.len > lower_buf.len) return null;

        for (name, 0..) |c, i| {
            lower_buf[i] = std.ascii.toLower(c);
        }
        const lower_name = lower_buf[0..name.len];

        for (self.items.items) |header| {
            if (std.mem.eql(u8, header.name, lower_name)) {
                return header.value;
            }
        }
        return null;
    }

    /// Get all header values by name (for headers that can appear multiple times)
    pub fn getAll(self: *const Headers, allocator: Allocator, name: []const u8) ![]const []const u8 {
        var lower_buf: [256]u8 = undefined;
        if (name.len > lower_buf.len) return &[_][]const u8{};

        for (name, 0..) |c, i| {
            lower_buf[i] = std.ascii.toLower(c);
        }
        const lower_name = lower_buf[0..name.len];

        var result = std.ArrayList([]const u8).init(allocator);
        for (self.items.items) |header| {
            if (std.mem.eql(u8, header.name, lower_name)) {
                try result.append(header.value);
            }
        }
        return result.toOwnedSlice();
    }

    /// Check if a header exists
    pub fn contains(self: *const Headers, name: []const u8) bool {
        return self.get(name) != null;
    }

    /// Get the number of headers
    pub fn count(self: *const Headers) usize {
        return self.items.items.len;
    }

    /// Iterator for all headers
    pub fn iterator(self: *const Headers) []const Header {
        return self.items.items;
    }
};

/// Parse headers from a buffer
/// Returns the headers and the position after the header block
pub fn parseHeaders(allocator: Allocator, data: []const u8) !struct { headers: Headers, body_start: usize } {
    var headers = Headers.init(allocator);
    errdefer headers.deinit();

    var pos: usize = 0;
    var total_size: usize = 0;

    while (pos < data.len) {
        // Find end of line
        const line_end = std.mem.indexOfPos(u8, data, pos, "\r\n") orelse {
            return error.IncompleteHeaders;
        };

        const line = data[pos..line_end];
        total_size += line.len + 2; // +2 for \r\n

        if (total_size > MAX_HEADERS_TOTAL_SIZE) {
            return error.HeadersTooLarge;
        }

        // Empty line marks end of headers
        if (line.len == 0) {
            return .{
                .headers = headers,
                .body_start = line_end + 2,
            };
        }

        // Check for line size limit
        if (line.len > MAX_HEADER_SIZE) {
            return error.HeaderTooLarge;
        }

        // Parse header: find the colon separator
        const colon_pos = std.mem.indexOf(u8, line, ":") orelse {
            return error.InvalidHeader;
        };

        if (colon_pos == 0) {
            return error.InvalidHeader; // Empty header name
        }

        const name = line[0..colon_pos];
        const value = if (colon_pos + 1 < line.len) line[colon_pos + 1 ..] else "";

        // Validate header name (no whitespace allowed)
        for (name) |c| {
            if (std.ascii.isWhitespace(c)) {
                return error.InvalidHeader;
            }
        }

        try headers.append(name, value);
        pos = line_end + 2;
    }

    return error.IncompleteHeaders;
}

test "parse simple headers" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const data = "Host: localhost\r\nContent-Type: text/html\r\n\r\n";
    const result = try parseHeaders(allocator, data);
    var headers = result.headers;
    defer headers.deinit();

    try testing.expectEqual(@as(usize, 2), headers.count());
    try testing.expectEqualStrings("localhost", headers.get("Host").?);
    try testing.expectEqualStrings("text/html", headers.get("Content-Type").?);
    try testing.expectEqual(@as(usize, 44), result.body_start);
}

test "case insensitive header lookup" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const data = "HOST: localhost\r\nContent-TYPE: text/html\r\n\r\n";
    const result = try parseHeaders(allocator, data);
    var headers = result.headers;
    defer headers.deinit();

    try testing.expectEqualStrings("localhost", headers.get("host").?);
    try testing.expectEqualStrings("localhost", headers.get("Host").?);
    try testing.expectEqualStrings("localhost", headers.get("HOST").?);
    try testing.expectEqualStrings("text/html", headers.get("content-type").?);
}

test "header value whitespace trimmed" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const data = "Host:   localhost   \r\nX-Custom: \t value \t\r\n\r\n";
    const result = try parseHeaders(allocator, data);
    var headers = result.headers;
    defer headers.deinit();

    try testing.expectEqualStrings("localhost", headers.get("Host").?);
    try testing.expectEqualStrings("value", headers.get("X-Custom").?);
}

test "empty header value" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const data = "X-Empty:\r\nHost: localhost\r\n\r\n";
    const result = try parseHeaders(allocator, data);
    var headers = result.headers;
    defer headers.deinit();

    try testing.expectEqualStrings("", headers.get("X-Empty").?);
    try testing.expectEqualStrings("localhost", headers.get("Host").?);
}

test "missing header returns null" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const data = "Host: localhost\r\n\r\n";
    const result = try parseHeaders(allocator, data);
    var headers = result.headers;
    defer headers.deinit();

    try testing.expect(headers.get("X-Missing") == null);
    try testing.expect(!headers.contains("X-Missing"));
    try testing.expect(headers.contains("Host"));
}

test "invalid header - no colon" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const data = "Invalid header line\r\n\r\n";
    try testing.expectError(error.InvalidHeader, parseHeaders(allocator, data));
}

test "invalid header - empty name" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const data = ": value\r\n\r\n";
    try testing.expectError(error.InvalidHeader, parseHeaders(allocator, data));
}

test "incomplete headers" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const data = "Host: localhost\r\n";
    try testing.expectError(error.IncompleteHeaders, parseHeaders(allocator, data));
}
