const std = @import("std");

/// HTTP request methods as defined in RFC 7231 and RFC 5789
pub const Method = enum {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    CONNECT,
    OPTIONS,
    TRACE,
    PATCH,

    /// Parse an HTTP method from a string
    pub fn parse(str: []const u8) ?Method {
        const map = std.StaticStringMap(Method).initComptime(.{
            .{ "GET", .GET },
            .{ "HEAD", .HEAD },
            .{ "POST", .POST },
            .{ "PUT", .PUT },
            .{ "DELETE", .DELETE },
            .{ "CONNECT", .CONNECT },
            .{ "OPTIONS", .OPTIONS },
            .{ "TRACE", .TRACE },
            .{ "PATCH", .PATCH },
        });
        return map.get(str);
    }

    /// Convert method to string
    pub fn toString(self: Method) []const u8 {
        return switch (self) {
            .GET => "GET",
            .HEAD => "HEAD",
            .POST => "POST",
            .PUT => "PUT",
            .DELETE => "DELETE",
            .CONNECT => "CONNECT",
            .OPTIONS => "OPTIONS",
            .TRACE => "TRACE",
            .PATCH => "PATCH",
        };
    }

    /// Returns true if the method typically has a request body
    pub fn hasRequestBody(self: Method) bool {
        return switch (self) {
            .POST, .PUT, .PATCH => true,
            else => false,
        };
    }

    /// Returns true if the method is safe (doesn't modify resources)
    pub fn isSafe(self: Method) bool {
        return switch (self) {
            .GET, .HEAD, .OPTIONS, .TRACE => true,
            else => false,
        };
    }

    /// Returns true if the method is idempotent
    pub fn isIdempotent(self: Method) bool {
        return switch (self) {
            .GET, .HEAD, .PUT, .DELETE, .OPTIONS, .TRACE => true,
            else => false,
        };
    }
};

test "parse valid methods" {
    const testing = std.testing;

    try testing.expectEqual(Method.GET, Method.parse("GET").?);
    try testing.expectEqual(Method.POST, Method.parse("POST").?);
    try testing.expectEqual(Method.PUT, Method.parse("PUT").?);
    try testing.expectEqual(Method.DELETE, Method.parse("DELETE").?);
    try testing.expectEqual(Method.HEAD, Method.parse("HEAD").?);
    try testing.expectEqual(Method.OPTIONS, Method.parse("OPTIONS").?);
    try testing.expectEqual(Method.PATCH, Method.parse("PATCH").?);
    try testing.expectEqual(Method.CONNECT, Method.parse("CONNECT").?);
    try testing.expectEqual(Method.TRACE, Method.parse("TRACE").?);
}

test "parse invalid methods" {
    const testing = std.testing;

    try testing.expect(Method.parse("INVALID") == null);
    try testing.expect(Method.parse("get") == null); // case sensitive
    try testing.expect(Method.parse("") == null);
    try testing.expect(Method.parse("GETS") == null);
}

test "method toString" {
    const testing = std.testing;

    try testing.expectEqualStrings("GET", Method.GET.toString());
    try testing.expectEqualStrings("POST", Method.POST.toString());
}

test "method properties" {
    const testing = std.testing;

    // Safe methods
    try testing.expect(Method.GET.isSafe());
    try testing.expect(Method.HEAD.isSafe());
    try testing.expect(!Method.POST.isSafe());
    try testing.expect(!Method.DELETE.isSafe());

    // Idempotent methods
    try testing.expect(Method.GET.isIdempotent());
    try testing.expect(Method.PUT.isIdempotent());
    try testing.expect(Method.DELETE.isIdempotent());
    try testing.expect(!Method.POST.isIdempotent());

    // Request body
    try testing.expect(Method.POST.hasRequestBody());
    try testing.expect(Method.PUT.hasRequestBody());
    try testing.expect(!Method.GET.hasRequestBody());
}
