const std = @import("std");

/// HTTP protocol version
pub const Version = enum {
    http10,
    http11,

    /// Parse HTTP version from string (e.g., "HTTP/1.1")
    pub fn parse(str: []const u8) ?Version {
        if (std.mem.eql(u8, str, "HTTP/1.1")) {
            return .http11;
        } else if (std.mem.eql(u8, str, "HTTP/1.0")) {
            return .http10;
        }
        return null;
    }

    /// Convert version to string
    pub fn toString(self: Version) []const u8 {
        return switch (self) {
            .http10 => "HTTP/1.0",
            .http11 => "HTTP/1.1",
        };
    }

    /// Returns true if keep-alive is the default for this version
    pub fn defaultKeepAlive(self: Version) bool {
        return switch (self) {
            .http11 => true, // HTTP/1.1 defaults to keep-alive
            .http10 => false, // HTTP/1.0 defaults to close
        };
    }
};

test "parse valid versions" {
    const testing = std.testing;

    try testing.expectEqual(Version.http11, Version.parse("HTTP/1.1").?);
    try testing.expectEqual(Version.http10, Version.parse("HTTP/1.0").?);
}

test "parse invalid versions" {
    const testing = std.testing;

    try testing.expect(Version.parse("HTTP/2.0") == null);
    try testing.expect(Version.parse("HTTP/1.2") == null);
    try testing.expect(Version.parse("http/1.1") == null); // case sensitive
    try testing.expect(Version.parse("") == null);
    try testing.expect(Version.parse("HTTP") == null);
}

test "version toString" {
    const testing = std.testing;

    try testing.expectEqualStrings("HTTP/1.1", Version.http11.toString());
    try testing.expectEqualStrings("HTTP/1.0", Version.http10.toString());
}

test "default keep-alive" {
    const testing = std.testing;

    try testing.expect(Version.http11.defaultKeepAlive());
    try testing.expect(!Version.http10.defaultKeepAlive());
}
