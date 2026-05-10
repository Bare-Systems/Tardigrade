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
            .items = .empty,
        };
    }

    pub fn deinit(self: *Headers) void {
        // Free duplicated strings
        for (self.items.items) |header| {
            self.allocator.free(header.name);
            self.allocator.free(header.value);
        }
        self.items.deinit(self.allocator);
    }

    /// Add a header (name will be lowercased).
    /// Returns `error.InvalidHeader` if the name or value contains control
    /// characters, CRLF sequences, or other bytes prohibited by RFC 7230 §3.2.6.
    pub fn append(self: *Headers, name: []const u8, value: []const u8) !void {
        if (self.items.items.len >= MAX_HEADERS) {
            return error.TooManyHeaders;
        }

        // Validate before storing to prevent injection via programmatic paths
        // (e.g., HTTP/2 HPACK headers that bypass parseHeaders).
        if (!isValidHeaderName(name)) return error.InvalidHeader;
        if (!isValidHeaderValue(value)) return error.InvalidHeader;

        // Lowercase the name for consistent lookup
        const lower_name = try self.allocator.alloc(u8, name.len);
        for (name, 0..) |c, i| {
            lower_name[i] = std.ascii.toLower(c);
        }

        // Trim whitespace from value
        const trimmed_value = std.mem.trim(u8, value, " \t");
        const value_copy = try self.allocator.dupe(u8, trimmed_value);

        try self.items.append(self.allocator, .{
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

        var result = std.ArrayList([]const u8).empty;
        errdefer result.deinit(allocator);
        for (self.items.items) |header| {
            if (std.mem.eql(u8, header.name, lower_name)) {
                try result.append(allocator, header.value);
            }
        }
        return result.toOwnedSlice(allocator);
    }

    /// Check if a header exists
    pub fn contains(self: *const Headers, name: []const u8) bool {
        return self.get(name) != null;
    }

    /// Count how many times a header name appears.
    pub fn countByName(self: *const Headers, name: []const u8) usize {
        var lower_buf: [256]u8 = undefined;
        if (name.len > lower_buf.len) return 0;

        for (name, 0..) |c, i| {
            lower_buf[i] = std.ascii.toLower(c);
        }
        const lower_name = lower_buf[0..name.len];

        var matches: usize = 0;
        for (self.items.items) |header| {
            if (std.mem.eql(u8, header.name, lower_name)) matches += 1;
        }
        return matches;
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

/// Returns true if every byte of the header name is a valid RFC 7230 token
/// character.  Control characters (0x00–0x1F) and DEL (0x7F) are forbidden;
/// so are ASCII separators that would be ambiguous in a raw header stream.
pub fn isValidHeaderName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| {
        // Reject control chars, DEL, space, and the colon separator.
        if (c <= 0x20 or c == 0x7F or c == ':') return false;
    }
    return true;
}

/// Returns true if every byte of the header value is permitted by RFC 7230
/// §3.2.6.  Visible ASCII (0x21–0x7E), SP (0x20), HTAB (0x09), and obs-text
/// (0x80–0xFF) are all valid.  CR (0x0D), LF (0x0A), NUL (0x00), and other
/// control characters are rejected to prevent header injection and log poisoning.
pub fn isValidHeaderValue(value: []const u8) bool {
    for (value) |c| {
        // Allow HTAB and space; reject other control chars and DEL.
        if (c == 0x09 or c >= 0x20) {
            if (c == 0x7F) return false; // DEL
            continue;
        }
        return false; // any other control char (0x00-0x08, 0x0A-0x1F)
    }
    return true;
}

/// Parse headers from a buffer
/// Returns the headers and the position after the header block
pub fn parseHeaders(allocator: Allocator, data: []const u8) !struct { headers: Headers, body_start: usize } {
    var headers = Headers.init(allocator);
    errdefer headers.deinit();

    var pos: usize = 0;
    var total_size: usize = 0;

    while (pos < data.len) {
        // Find end of line
        const line_end = std.mem.findPos(u8, data, pos, "\r\n") orelse {
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
        const colon_pos = std.mem.find(u8, line, ":") orelse {
            return error.InvalidHeader;
        };

        if (colon_pos == 0) {
            return error.InvalidHeader; // Empty header name
        }

        const name = line[0..colon_pos];
        const value = if (colon_pos + 1 < line.len) line[colon_pos + 1 ..] else "";

        // Reject header names that contain control characters or separators
        // (CRLF injection, NUL bytes, etc.) per RFC 7230 §3.2.6.
        if (!isValidHeaderName(name)) return error.InvalidHeader;

        // Reject header values that contain CR, LF, NUL, or other control
        // characters to prevent CRLF injection and log poisoning.
        if (!isValidHeaderValue(value)) return error.InvalidHeader;

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

test "isValidHeaderName rejects control chars and accepts valid tokens" {
    try std.testing.expect(isValidHeaderName("Host"));
    try std.testing.expect(isValidHeaderName("X-Custom-Header"));
    try std.testing.expect(isValidHeaderName("Content-Type"));
    // Control chars
    try std.testing.expect(!isValidHeaderName("Bad\x00Name"));
    try std.testing.expect(!isValidHeaderName("Bad\x0DName")); // CR
    try std.testing.expect(!isValidHeaderName("Bad\x0AName")); // LF
    try std.testing.expect(!isValidHeaderName("Bad\x1FName")); // other control
    // Space and colon are separators — not allowed in names
    try std.testing.expect(!isValidHeaderName("Bad Name"));
    try std.testing.expect(!isValidHeaderName("Bad:Name"));
    // DEL
    try std.testing.expect(!isValidHeaderName("Bad\x7FName"));
    // Empty
    try std.testing.expect(!isValidHeaderName(""));
}

test "isValidHeaderValue rejects CR LF and NUL but allows HTAB and printable chars" {
    try std.testing.expect(isValidHeaderValue("application/json"));
    try std.testing.expect(isValidHeaderValue("value with spaces"));
    try std.testing.expect(isValidHeaderValue("value\twith\ttabs"));
    try std.testing.expect(isValidHeaderValue("")); // empty value is fine
    // CRLF injection
    try std.testing.expect(!isValidHeaderValue("val\r\nX-Injected: evil"));
    try std.testing.expect(!isValidHeaderValue("val\ralone"));
    try std.testing.expect(!isValidHeaderValue("val\nalone"));
    // NUL byte
    try std.testing.expect(!isValidHeaderValue("val\x00ue"));
    // Other control chars
    try std.testing.expect(!isValidHeaderValue("val\x01ue"));
    try std.testing.expect(!isValidHeaderValue("val\x1Fue"));
    // DEL
    try std.testing.expect(!isValidHeaderValue("val\x7Fue"));
}

test "parseHeaders rejects CRLF injection in header value" {
    const allocator = std.testing.allocator;
    // A lone CR in the value field (LF is already the line split character)
    const cr_in_value = "X-Bad: value\rinjected\r\n\r\n";
    try std.testing.expectError(error.InvalidHeader, parseHeaders(allocator, cr_in_value));
    // NUL byte in value
    const nul_in_value = "X-Bad: value\x00null\r\n\r\n";
    try std.testing.expectError(error.InvalidHeader, parseHeaders(allocator, nul_in_value));
}

test "parseHeaders rejects control characters in header name" {
    const allocator = std.testing.allocator;
    // NUL in name
    const nul_in_name = "X-Bad\x00: value\r\n\r\n";
    try std.testing.expectError(error.InvalidHeader, parseHeaders(allocator, nul_in_name));
    // Control char in name
    const ctrl_in_name = "X-Bad\x01: value\r\n\r\n";
    try std.testing.expectError(error.InvalidHeader, parseHeaders(allocator, ctrl_in_name));
}

test "Headers.append rejects invalid names and values" {
    const allocator = std.testing.allocator;
    var headers = Headers.init(allocator);
    defer headers.deinit();
    // Programmatic CRLF injection attempt in value
    try std.testing.expectError(error.InvalidHeader, headers.append("X-Test", "bad\r\nX-Injected: evil"));
    // Control char in name
    try std.testing.expectError(error.InvalidHeader, headers.append("X-Bad\x00Name", "value"));
    // Valid header passes
    try headers.append("X-Good", "valid value");
    try std.testing.expectEqualStrings("valid value", headers.get("X-Good").?);
}

test "parseHeaders rejects obs-fold continuation lines" {
    const allocator = std.testing.allocator;
    const folded = "Host: localhost\r\n\tX-Folded: no\r\n\r\n";
    try std.testing.expectError(error.InvalidHeader, parseHeaders(allocator, folded));
}

test "parseHeaders rejects too many headers" {
    const allocator = std.testing.allocator;
    var data = std.ArrayList(u8).empty;
    defer data.deinit(allocator);

    for (0..MAX_HEADERS + 1) |idx| {
        const line = try std.fmt.allocPrint(allocator, "X-{d}: value\r\n", .{idx});
        defer allocator.free(line);
        try data.appendSlice(allocator, line);
    }
    try data.appendSlice(allocator, "\r\n");
    try std.testing.expectError(error.TooManyHeaders, parseHeaders(allocator, data.items));
}

test "parseHeaders rejects header line above single-header limit" {
    const allocator = std.testing.allocator;
    const oversized_value = "a" ** (MAX_HEADER_SIZE + 1);
    const data = "X-Test: " ++ oversized_value ++ "\r\n\r\n";
    try std.testing.expectError(error.HeaderTooLarge, parseHeaders(allocator, data));
}

test "parseHeaders rejects aggregate header bytes above total limit" {
    const allocator = std.testing.allocator;
    const big_value = "a" ** 2048;
    var data = std.ArrayList(u8).empty;
    defer data.deinit(allocator);

    while (data.items.len <= MAX_HEADERS_TOTAL_SIZE) {
        const line = try std.fmt.allocPrint(allocator, "X-Test: {s}\r\n", .{big_value});
        defer allocator.free(line);
        try data.appendSlice(allocator, line);
    }
    try data.appendSlice(allocator, "\r\n");
    try std.testing.expectError(error.HeadersTooLarge, parseHeaders(allocator, data.items));
}
