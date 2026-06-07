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
    /// Both Transfer-Encoding and Content-Length are present.
    /// Per RFC 7230 §3.3.3 this is a potential request-smuggling vector and
    /// MUST be rejected.
    ConflictingHeaders,
    /// Transfer-Encoding: chunked body is malformed.
    InvalidChunkedBody,
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
        const request_line_end = std.mem.find(u8, data, "\r\n") orelse {
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

        const te_count = headers.countByName("transfer-encoding");
        const cl_count = headers.countByName("content-length");
        const has_te = te_count > 0;
        const has_cl = cl_count > 0;

        if (cl_count > 1 or te_count > 1) return error.ConflictingHeaders;

        // RFC 7230 §3.3.3: If both Transfer-Encoding and Content-Length are
        // present, reject as a potential request-smuggling attack.
        if (has_te and has_cl) return error.ConflictingHeaders;

        var body: ?[]const u8 = null;
        var total_bytes = body_start;

        if (has_te) {
            // Only chunked is supported; other transfer codings are not valid
            // for HTTP/1.1 requests from clients.
            const te_value = headers.get("transfer-encoding").?;
            var is_chunked = false;
            var it = std.mem.splitSequence(u8, te_value, ",");
            while (it.next()) |token| {
                const trimmed = std.mem.trim(u8, token, " \t");
                if (std.ascii.eqlIgnoreCase(trimmed, "chunked")) is_chunked = true;
            }
            if (!is_chunked) return error.ConflictingHeaders; // unsupported TE
            // Decode chunked body from data[body_start..].
            const decoded = try decodeChunkedBody(allocator, data[body_start..], max_body_size);
            errdefer allocator.free(decoded);
            body = decoded;
            total_bytes = data.len; // consumed the rest of the buffer
        } else if (has_cl) {
            const cl_str = headers.get("content-length").?;
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

    /// Parse only the request line and headers from raw bytes.
    ///
    /// This is used by streaming proxy paths that must route and authorize a
    /// request before the full body has been read into memory. Header-level
    /// smuggling checks are still enforced; the returned request never owns a
    /// body and `bytes_consumed` points at the first body byte.
    pub fn parseHead(allocator: Allocator, data: []const u8, max_body_size: usize) ParseError!struct { request: Request, bytes_consumed: usize } {
        _ = max_body_size;
        const request_line_end = std.mem.find(u8, data, "\r\n") orelse {
            return error.InvalidRequestLine;
        };

        if (request_line_end > MAX_REQUEST_LINE_SIZE) {
            return error.InvalidRequestLine;
        }

        const request_line = data[0..request_line_end];
        const parsed_line = parseRequestLine(request_line) orelse {
            return error.InvalidRequestLine;
        };
        const method = Method.parse(parsed_line.method) orelse {
            return error.InvalidMethod;
        };
        const version = Version.parse(parsed_line.version) orelse {
            return error.InvalidVersion;
        };
        const uri = parseUri(parsed_line.uri) orelse {
            return error.InvalidUri;
        };

        const header_data = data[request_line_end + 2 ..];
        const header_result = parseHeaders(allocator, header_data) catch |err| {
            return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                else => @as(ParseError, err),
            };
        };
        var headers = header_result.headers;
        errdefer headers.deinit();

        const te_count = headers.countByName("transfer-encoding");
        const cl_count = headers.countByName("content-length");
        if (cl_count > 1 or te_count > 1) return error.ConflictingHeaders;
        if (te_count > 0 and cl_count > 0) return error.ConflictingHeaders;
        if (cl_count == 1) {
            _ = std.fmt.parseInt(usize, headers.get("content-length").?, 10) catch {
                return error.InvalidContentLength;
            };
        }
        if (te_count == 1) {
            const te_value = headers.get("transfer-encoding").?;
            var is_chunked = false;
            var it = std.mem.splitSequence(u8, te_value, ",");
            while (it.next()) |token| {
                const trimmed = std.mem.trim(u8, token, " \t");
                if (std.ascii.eqlIgnoreCase(trimmed, "chunked")) is_chunked = true;
            }
            if (!is_chunked) return error.ConflictingHeaders;
        }

        return .{
            .request = Request{
                .allocator = allocator,
                .method = method,
                .uri = uri,
                .version = version,
                .headers = headers,
                .body = null,
            },
            .bytes_consumed = request_line_end + 2 + header_result.body_start,
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

    pub fn hasTransferEncoding(self: *const Request) bool {
        return self.headers.get("transfer-encoding") != null;
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

            if (std.mem.find(u8, lower, "close") != null) {
                return false;
            }
            if (std.mem.find(u8, lower, "keep-alive") != null) {
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
    const first_space = std.mem.find(u8, line, " ") orelse return null;
    if (first_space == 0) return null;

    const method = line[0..first_space];

    // Find second space (after URI)
    const rest = line[first_space + 1 ..];
    const second_space = std.mem.find(u8, rest, " ") orelse return null;
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
        if (std.mem.find(u8, uri, "://")) |proto_end| {
            if (std.mem.findPos(u8, uri, proto_end + 3, "/")) |path_start| {
                return parseUri(uri[path_start..]);
            }
        }
        return null;
    }

    // Find query string
    if (std.mem.find(u8, uri, "?")) |query_start| {
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

/// Decode an HTTP/1.1 chunked-encoded body per RFC 7230 §4.1.
/// Returns an owned slice with the decoded content.  Caller must free.
fn decodeChunkedBody(allocator: Allocator, data: []const u8, max_body_size: usize) ParseError![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    var pos: usize = 0;
    while (pos < data.len) {
        // Find end of chunk-size line.
        const line_end = std.mem.find(u8, data[pos..], "\r\n") orelse return error.InvalidChunkedBody;
        const chunk_size_line = data[pos .. pos + line_end];
        // Strip optional chunk extensions (;ext=value …).
        const semi = std.mem.findScalar(u8, chunk_size_line, ';');
        const hex = std.mem.trim(u8, if (semi) |s| chunk_size_line[0..s] else chunk_size_line, " \t");
        const chunk_size = std.fmt.parseInt(usize, hex, 16) catch return error.InvalidChunkedBody;
        pos += line_end + 2; // skip size line + CRLF
        if (chunk_size == 0) break; // last-chunk
        if (out.items.len + chunk_size > max_body_size) return error.BodyTooLarge;
        if (pos + chunk_size > data.len) return error.InvalidChunkedBody;
        out.appendSlice(allocator, data[pos .. pos + chunk_size]) catch return error.OutOfMemory;
        pos += chunk_size;
        // Each chunk must end with CRLF.
        if (pos + 2 > data.len or data[pos] != '\r' or data[pos + 1] != '\n') return error.InvalidChunkedBody;
        pos += 2;
    }
    return out.toOwnedSlice(allocator) catch error.OutOfMemory;
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

test "parseHead parses headers without requiring body bytes" {
    const allocator = std.testing.allocator;
    const raw = "POST /upload?x=1 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10485760\r\nContent-Type: application/octet-stream\r\n\r\nprefix";
    const result = try Request.parseHead(allocator, raw, DEFAULT_MAX_BODY_SIZE);
    var req = result.request;
    defer req.deinit();

    try std.testing.expectEqual(Method.POST, req.method);
    try std.testing.expectEqualStrings("/upload", req.uri.path);
    try std.testing.expectEqualStrings("x=1", req.uri.query.?);
    try std.testing.expectEqual(@as(usize, 10485760), req.contentLength().?);
    try std.testing.expect(req.body == null);
    try std.testing.expectEqual(raw.len - "prefix".len, result.bytes_consumed);
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

test "reject oversized request line" {
    const testing = std.testing;
    const allocator = testing.allocator;
    const long_uri = "/" ++ ("a" ** (MAX_REQUEST_LINE_SIZE + 1));
    const raw = "GET " ++ long_uri ++ " HTTP/1.1\r\nHost: localhost\r\n\r\n";
    try testing.expectError(error.InvalidRequestLine, Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE));
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

test "reject request with both Transfer-Encoding and Content-Length (smuggling defense)" {
    const allocator = std.testing.allocator;
    // Per RFC 7230 §3.3.3, having both TE and CL is a request-smuggling risk.
    const raw = "POST /api HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    try std.testing.expectError(error.ConflictingHeaders, Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE));
}

test "reject duplicate Content-Length headers" {
    const allocator = std.testing.allocator;
    const raw = "POST /api HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nContent-Length: 7\r\n\r\nhello!!";
    try std.testing.expectError(error.ConflictingHeaders, Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE));
}

test "parse chunked body correctly" {
    const allocator = std.testing.allocator;
    // Two chunks: "Hello, " (7 bytes) + "World!" (6 bytes) = "Hello, World!"
    const raw = "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n7\r\nHello, \r\n6\r\nWorld!\r\n0\r\n\r\n";
    const result = try Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE);
    var req = result.request;
    defer req.deinit();
    try std.testing.expectEqualStrings("Hello, World!", req.body.?);
}

test "chunked body with chunk extensions is parsed correctly" {
    const allocator = std.testing.allocator;
    // Chunk extensions (;name=value) must be stripped before parsing hex size.
    const raw = "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=ignore\r\nhello\r\n0\r\n\r\n";
    const result = try Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE);
    var req = result.request;
    defer req.deinit();
    try std.testing.expectEqualStrings("hello", req.body.?);
}

test "malformed chunked body returns InvalidChunkedBody" {
    const allocator = std.testing.allocator;
    // Missing CRLF after chunk data.
    const raw = "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello0\r\n\r\n";
    try std.testing.expectError(error.InvalidChunkedBody, Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE));
}

test "premature EOF in chunked body returns InvalidChunkedBody" {
    const allocator = std.testing.allocator;
    const raw = "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";
    try std.testing.expectError(error.InvalidChunkedBody, Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE));
}

test "chunked body exceeding max body size returns BodyTooLarge" {
    const allocator = std.testing.allocator;
    const raw = "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    try std.testing.expectError(error.BodyTooLarge, Request.parse(allocator, raw, 3));
}
