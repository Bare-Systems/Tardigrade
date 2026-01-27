const std = @import("std");
const Allocator = std.mem.Allocator;
const Method = @import("method.zig").Method;
const Version = @import("version.zig").Version;
const Headers = @import("headers.zig").Headers;
const parseHeaders = @import("headers.zig").parseHeaders;

/// Maximum request line size
pub const MAX_REQUEST_LINE_SIZE = 8 * 1024; // 8KB

/// Default maximum body size
pub const DEFAULT_MAX_BODY_SIZE = 1 * 1024 * 1024; // 1MB

/// Parsed URI components
pub const Uri = struct {
    raw: []const u8,
    path: []const u8,
    query: ?[]const u8,
};

/// HTTP Request parsing errors
pub const ParseError = error{
    InvalidRequestLine,
    InvalidMethod,
    InvalidUri,
    InvalidVersion,
    InvalidHeader,
    IncompleteHeaders,
    HeaderTooLarge,
    HeadersTooLarge,
    TooManyHeaders,
    BodyTooLarge,
    InvalidContentLength,
    OutOfMemory,
};

/// Parsed HTTP Request
pub const Request = struct {
    allocator: Allocator,
    method: Method,
    uri: Uri,
    version: Version,
    headers: Headers,
    body: ?[]const u8,

    /// Free resources
    pub fn deinit(self: *Request) void {
        self.headers.deinit();
        if (self.body) |b| {
            self.allocator.free(b);
        }
    }

    /// Parse an HTTP request from raw bytes
    /// Returns the request and the total number of bytes consumed
    pub fn parse(allocator: Allocator, data: []const u8, max_body_size: usize) ParseError!struct { request: Request, bytes_consumed: usize } {
        // Find end of request line
        const request_line_end = std.mem.indexOf(u8, data, "\r\n") orelse {
            return error.InvalidRequestLine;
        };

        if (request_line_end > MAX_REQUEST_LINE_SIZE) {
            return error.InvalidRequestLine;
        }

        const request_line = data[0..request_line_end];

        // Parse request line: METHOD SP URI SP VERSION
        const parsed_line = parseRequestLine(request_line) orelse {
            return error.InvalidRequestLine;
        };

        // Parse method
        const method = Method.parse(parsed_line.method) orelse {
            return error.InvalidMethod;
        };

        // Parse version
        const version = Version.parse(parsed_line.version) orelse {
            return error.InvalidVersion;
        };

        // Parse URI
        const uri = parseUri(parsed_line.uri) orelse {
            return error.InvalidUri;
        };

        // Parse headers (starting after request line)
        const header_data = data[request_line_end + 2 ..];
        const header_result = parseHeaders(allocator, header_data) catch |err| {
            return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                else => @as(ParseError, err),
            };
        };
        var headers = header_result.headers;
        errdefer headers.deinit();

        const body_start = request_line_end + 2 + header_result.body_start;

        // Parse body if Content-Length is present
        var body: ?[]const u8 = null;
        var total_bytes = body_start;

        if (headers.get("content-length")) |cl_str| {
            const content_length = std.fmt.parseInt(usize, cl_str, 10) catch {
                return error.InvalidContentLength;
            };

            if (content_length > max_body_size) {
                return error.BodyTooLarge;
            }

            if (body_start + content_length > data.len) {
                // Not enough data yet - for streaming this would need different handling
                return error.InvalidContentLength;
            }

            body = try allocator.dupe(u8, data[body_start .. body_start + content_length]);
            total_bytes = body_start + content_length;
        }

        return .{
            .request = Request{
                .allocator = allocator,
                .method = method,
                .uri = uri,
                .version = version,
                .headers = headers,
                .body = body,
            },
            .bytes_consumed = total_bytes,
        };
    }

    /// Get the Host header value
    pub fn host(self: *const Request) ?[]const u8 {
        return self.headers.get("host");
    }

    /// Get the Content-Type header value
    pub fn contentType(self: *const Request) ?[]const u8 {
        return self.headers.get("content-type");
    }

    /// Get the Content-Length header value as integer
    pub fn contentLength(self: *const Request) ?usize {
        const cl_str = self.headers.get("content-length") orelse return null;
        return std.fmt.parseInt(usize, cl_str, 10) catch null;
    }

    /// Check if the client wants to keep the connection alive
    pub fn keepAlive(self: *const Request) bool {
        if (self.headers.get("connection")) |conn| {
            var lower_buf: [64]u8 = undefined;
            const len = @min(conn.len, lower_buf.len);
            for (conn[0..len], 0..) |c, i| {
                lower_buf[i] = std.ascii.toLower(c);
            }
            const lower = lower_buf[0..len];

            if (std.mem.indexOf(u8, lower, "close") != null) {
                return false;
            }
            if (std.mem.indexOf(u8, lower, "keep-alive") != null) {
                return true;
            }
        }
        // Default based on HTTP version
        return self.version.defaultKeepAlive();
    }
};

/// Parse the request line into its components
fn parseRequestLine(line: []const u8) ?struct { method: []const u8, uri: []const u8, version: []const u8 } {
    // Find first space (after method)
    const first_space = std.mem.indexOf(u8, line, " ") orelse return null;
    if (first_space == 0) return null;

    const method = line[0..first_space];

    // Find second space (after URI)
    const rest = line[first_space + 1 ..];
    const second_space = std.mem.indexOf(u8, rest, " ") orelse return null;
    if (second_space == 0) return null;

    const uri = rest[0..second_space];
    const version = rest[second_space + 1 ..];

    if (version.len == 0) return null;

    return .{
        .method = method,
        .uri = uri,
        .version = version,
    };
}

/// Parse URI into path and query components
fn parseUri(uri: []const u8) ?Uri {
    if (uri.len == 0) return null;

    // URI must start with / for absolute path (or be *)
    if (uri[0] != '/' and !std.mem.eql(u8, uri, "*")) {
        // Could be absolute URI, just take the path portion
        if (std.mem.indexOf(u8, uri, "://")) |proto_end| {
            if (std.mem.indexOfPos(u8, uri, proto_end + 3, "/")) |path_start| {
                return parseUri(uri[path_start..]);
            }
        }
        return null;
    }

    // Find query string
    if (std.mem.indexOf(u8, uri, "?")) |query_start| {
        return Uri{
            .raw = uri,
            .path = uri[0..query_start],
            .query = if (query_start + 1 < uri.len) uri[query_start + 1 ..] else null,
        };
    }

    return Uri{
        .raw = uri,
        .path = uri,
        .query = null,
    };
}

// Tests
test "parse simple GET request" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const raw = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const result = try Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE);
    var req = result.request;
    defer req.deinit();

    try testing.expectEqual(Method.GET, req.method);
    try testing.expectEqualStrings("/", req.uri.path);
    try testing.expect(req.uri.query == null);
    try testing.expectEqual(Version.http11, req.version);
    try testing.expectEqualStrings("localhost", req.host().?);
    try testing.expect(req.body == null);
}

test "parse GET with query string" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const raw = "GET /search?q=hello&lang=en HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const result = try Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE);
    var req = result.request;
    defer req.deinit();

    try testing.expectEqual(Method.GET, req.method);
    try testing.expectEqualStrings("/search", req.uri.path);
    try testing.expectEqualStrings("q=hello&lang=en", req.uri.query.?);
}

test "parse POST with body" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const raw = "POST /api/data HTTP/1.1\r\nHost: localhost\r\nContent-Length: 13\r\nContent-Type: text/plain\r\n\r\nHello, World!";
    const result = try Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE);
    var req = result.request;
    defer req.deinit();

    try testing.expectEqual(Method.POST, req.method);
    try testing.expectEqualStrings("/api/data", req.uri.path);
    try testing.expectEqualStrings("Hello, World!", req.body.?);
    try testing.expectEqualStrings("text/plain", req.contentType().?);
    try testing.expectEqual(@as(usize, 13), req.contentLength().?);
}

test "parse all HTTP methods" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const methods = [_][]const u8{ "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH" };

    for (methods) |method| {
        var buf: [256]u8 = undefined;
        const raw = try std.fmt.bufPrint(&buf, "{s} / HTTP/1.1\r\nHost: localhost\r\n\r\n", .{method});
        const result = try Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE);
        var req = result.request;
        defer req.deinit();

        try testing.expectEqualStrings(method, req.method.toString());
    }
}

test "parse HTTP/1.0 request" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const raw = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n";
    const result = try Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE);
    var req = result.request;
    defer req.deinit();

    try testing.expectEqual(Version.http10, req.version);
    try testing.expect(!req.keepAlive()); // HTTP/1.0 defaults to close
}

test "keep-alive detection" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // HTTP/1.1 defaults to keep-alive
    {
        const raw = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        const result = try Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE);
        var req = result.request;
        defer req.deinit();
        try testing.expect(req.keepAlive());
    }

    // HTTP/1.1 with Connection: close
    {
        const raw = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        const result = try Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE);
        var req = result.request;
        defer req.deinit();
        try testing.expect(!req.keepAlive());
    }

    // HTTP/1.0 with Connection: keep-alive
    {
        const raw = "GET / HTTP/1.0\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";
        const result = try Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE);
        var req = result.request;
        defer req.deinit();
        try testing.expect(req.keepAlive());
    }
}

test "reject invalid method" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const raw = "INVALID / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    try testing.expectError(error.InvalidMethod, Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE));
}

test "reject invalid version" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const raw = "GET / HTTP/2.0\r\nHost: localhost\r\n\r\n";
    try testing.expectError(error.InvalidVersion, Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE));
}

test "reject malformed request line" {
    const testing = std.testing;
    const allocator = testing.allocator;

    try testing.expectError(error.InvalidRequestLine, Request.parse(allocator, "GET\r\n\r\n", DEFAULT_MAX_BODY_SIZE));
    try testing.expectError(error.InvalidRequestLine, Request.parse(allocator, "GET /\r\n\r\n", DEFAULT_MAX_BODY_SIZE));
    try testing.expectError(error.InvalidRequestLine, Request.parse(allocator, " / HTTP/1.1\r\n\r\n", DEFAULT_MAX_BODY_SIZE));
}

test "reject body too large" {
    const testing = std.testing;
    const allocator = testing.allocator;

    const raw = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1000\r\n\r\n" ++ ("x" ** 1000);
    try testing.expectError(error.BodyTooLarge, Request.parse(allocator, raw, 100));
}

test "bytes consumed tracking" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Request without body
    {
        const raw = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\nextra data";
        const result = try Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE);
        var req = result.request;
        defer req.deinit();
        try testing.expectEqual(@as(usize, 35), result.bytes_consumed);
    }

    // Request with body
    {
        const raw = "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhelloextra";
        const result = try Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE);
        var req = result.request;
        defer req.deinit();
        try testing.expectEqualStrings("hello", req.body.?);
    }
}
