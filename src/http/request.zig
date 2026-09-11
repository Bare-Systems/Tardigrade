const std = @import("std");
const Allocator = std.mem.Allocator;
const Method = @import("method.zig").Method;
const Version = @import("version.zig").Version;
const Headers = @import("headers.zig").Headers;
const parseHeaders = @import("headers.zig").parseHeaders;
const isValidTrailerLine = @import("headers.zig").isValidTrailerLine;

/// Maximum request line size
pub const MAX_REQUEST_LINE_SIZE = 8 * 1024; // 8KB

/// Default maximum body size
pub const DEFAULT_MAX_BODY_SIZE = 1 * 1024 * 1024; // 1MB

/// Parsed URI components
pub const Uri = struct {
    raw: []const u8,
    path: []const u8,
    query: ?[]const u8,
    scheme: ?[]const u8 = null,
    authority: ?[]const u8 = null,
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
    /// More than one `Authorization` header field was present. HTTP does
    /// not define combination semantics for `Authorization`, so accepting
    /// either occurrence creates the same class of ambiguity risk as
    /// duplicate `Content-Length` (WSTG-ATHZ-01/02, #673 F-06) -- reject
    /// outright rather than silently preferring one field.
    DuplicateAuthorizationHeader,
    /// More than one `Host` header field was present. RFC 9112 § 3.2
    /// requires a server to reject this even when the values are identical:
    /// different HTTP hops choosing different occurrences creates virtual
    /// host, authorization, and cache-routing ambiguity.
    DuplicateHostHeader,
    /// Host is empty/malformed or disagrees with an absolute-form request
    /// target's authority. Routing must have one canonical authority.
    InvalidHostHeader,
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

        if (headers.countByName("authorization") > 1) return error.DuplicateAuthorizationHeader;
        if (headers.countByName("host") > 1) return error.DuplicateHostHeader;
        try validateRoutingAuthority(&headers, uri);

        var body: ?[]const u8 = null;
        var total_bytes = body_start;

        if (has_te) {
            // Only chunked is supported, and the value must equal "chunked"
            // exactly -- a coding *list* (e.g. "chunked, gzip", "gzip,
            // chunked") is rejected rather than pattern-matched for a
            // "chunked" token, since Tardigrade cannot apply an unrecognized
            // coding and "chunked" is only valid as the final coding anyway
            // (RFC 7230 §3.3.1) (#673 review).
            const te_value = headers.get("transfer-encoding").?;
            if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, te_value, " \t"), "chunked")) {
                return error.ConflictingHeaders; // unsupported/misordered TE
            }
            // Decode chunked body from data[body_start..].
            const decoded = try decodeChunkedBody(allocator, data[body_start..], max_body_size);
            errdefer allocator.free(decoded.body);
            body = decoded.body;
            total_bytes = body_start + decoded.consumed;
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
        if (headers.countByName("authorization") > 1) return error.DuplicateAuthorizationHeader;
        if (headers.countByName("host") > 1) return error.DuplicateHostHeader;
        try validateRoutingAuthority(&headers, uri);
        if (cl_count == 1) {
            _ = std.fmt.parseInt(usize, headers.get("content-length").?, 10) catch {
                return error.InvalidContentLength;
            };
        }
        if (te_count == 1) {
            // Same exact-match policy as `parse()`: a coding list is
            // rejected rather than pattern-matched for a "chunked" token
            // (#673 review).
            const te_value = headers.get("transfer-encoding").?;
            if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, te_value, " \t"), "chunked")) {
                return error.ConflictingHeaders;
            }
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
    if (std.mem.findScalar(u8, uri, '#') != null) return null;

    // URI must start with / for absolute path (or be *)
    if (uri[0] != '/' and !std.mem.eql(u8, uri, "*")) {
        // Absolute-form is accepted only for HTTP(S), and retains its
        // authority so it can be checked against Host after header parsing.
        if (std.mem.find(u8, uri, "://")) |proto_end| {
            const scheme = uri[0..proto_end];
            if (!(std.ascii.eqlIgnoreCase(scheme, "http") or std.ascii.eqlIgnoreCase(scheme, "https"))) return null;
            const authority_start = proto_end + 3;
            if (std.mem.findPos(u8, uri, proto_end + 3, "/")) |path_start| {
                const authority = uri[authority_start..path_start];
                if (parseAuthority(authority) == null) return null;
                var parsed = parseUri(uri[path_start..]) orelse return null;
                parsed.raw = uri;
                parsed.scheme = scheme;
                parsed.authority = authority;
                return parsed;
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

const ParsedAuthority = struct {
    host: []const u8,
    port: ?u16,
};

fn parseAuthority(raw: []const u8) ?ParsedAuthority {
    if (raw.len == 0 or !isAuthorityValueSafe(raw)) return null;
    if (raw[0] == '[') {
        const close = std.mem.findScalar(u8, raw, ']') orelse return null;
        if (close == 1) return null;
        const suffix = raw[close + 1 ..];
        const port = if (suffix.len == 0)
            null
        else blk: {
            if (suffix[0] != ':' or suffix.len == 1) return null;
            break :blk std.fmt.parseInt(u16, suffix[1..], 10) catch return null;
        };
        return .{ .host = raw[1..close], .port = port };
    }

    const colon = std.mem.findScalarLast(u8, raw, ':');
    if (colon) |index| {
        if (std.mem.findScalar(u8, raw[0..index], ':') != null) return null; // IPv6 requires brackets.
        if (index == 0 or index + 1 == raw.len) return null;
        const port = std.fmt.parseInt(u16, raw[index + 1 ..], 10) catch return null;
        return .{ .host = raw[0..index], .port = port };
    }
    return .{ .host = raw, .port = null };
}

/// Public syntax check for protocol adapters (HTTP/2 and HTTP/3) before they
/// map `:authority` into the shared HTTP/1-shaped request representation.
pub fn isValidAuthority(raw: []const u8) bool {
    return parseAuthority(raw) != null;
}

fn isAuthorityValueSafe(raw: []const u8) bool {
    for (raw) |c| {
        if (c <= 0x20 or c == 0x7f) return false;
        if (std.mem.indexOfScalar(u8, "/\\?#@,;", c) != null) return false;
    }
    return true;
}

fn validateRoutingAuthority(headers: *const Headers, uri: Uri) ParseError!void {
    const raw_host = headers.get("host");
    const host = if (raw_host) |value| parseAuthority(value) orelse return error.InvalidHostHeader else null;
    if (uri.authority) |target_raw| {
        const target = parseAuthority(target_raw) orelse return error.InvalidHostHeader;
        if (host) |host_value| {
            if (!std.ascii.eqlIgnoreCase(target.host, host_value.host)) return error.InvalidHostHeader;
            const default_port: u16 = if (std.ascii.eqlIgnoreCase(uri.scheme.?, "https")) 443 else 80;
            if ((target.port orelse default_port) != (host_value.port orelse default_port)) return error.InvalidHostHeader;
        }
    }
}

/// Decoded chunked-body payload plus how many leading bytes of `data` the
/// decode actually consumed (through and including the terminating chunk's
/// trailer section). The caller (`Request.parse()`) must use `consumed`
/// rather than assuming the whole buffer belongs to this one request's body:
/// otherwise a pipelined request already sitting past the real terminator
/// would either be silently discarded or misread as part of this body
/// (#673 review).
const ChunkedDecodeResult = struct { body: []u8, consumed: usize };

/// Decode an HTTP/1.1 chunked-encoded body per RFC 7230 §4.1.
/// Returns an owned slice with the decoded content.  Caller must free.
fn decodeChunkedBody(allocator: Allocator, data: []const u8, max_body_size: usize) ParseError!ChunkedDecodeResult {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    var pos: usize = 0;
    while (true) {
        // Find end of chunk-size line. Reaching the end of `data` without
        // ever finding a terminating zero-size chunk is a truncated body,
        // not a complete one -- unlike a bare `while (pos < data.len)` loop,
        // which would silently accept EOF right after a nonzero chunk as
        // "done" (#673 review).
        const line_end = std.mem.find(u8, data[pos..], "\r\n") orelse return error.InvalidChunkedBody;
        const chunk_size_line = data[pos .. pos + line_end];
        // Strip optional chunk extensions (;ext=value …).
        const semi = std.mem.findScalar(u8, chunk_size_line, ';');
        const hex = std.mem.trim(u8, if (semi) |s| chunk_size_line[0..s] else chunk_size_line, " \t");
        const chunk_size = std.fmt.parseInt(usize, hex, 16) catch return error.InvalidChunkedBody;
        pos += line_end + 2; // skip size line + CRLF
        if (chunk_size == 0) {
            // Last-chunk: require the (possibly empty) trailer section to
            // actually end in a blank line (RFC 7230 §4.1) rather than
            // stopping at "0\r\n" and trusting whatever follows -- otherwise
            // bytes that are really a pipelined next request could be
            // silently swallowed or misread as trailers.
            var tpos = pos;
            while (true) {
                const tlen = std.mem.find(u8, data[tpos..], "\r\n") orelse return error.InvalidChunkedBody;
                if (tlen == 0) return .{ .body = out.toOwnedSlice(allocator) catch return error.OutOfMemory, .consumed = tpos + 2 };
                // RFC 9112 §7.1.2: the trailer part is `*( field-line CRLF
                // )` -- a non-blank line must actually be valid
                // `field-name ":" OWS field-value OWS` syntax, not merely
                // "contains a colon somewhere" (#673 review round 8: a
                // colon-only check still let a malformed name/value like
                // "Bad Name: x" or "X-Good: bad\x00value" through).
                const trailer_line = data[tpos .. tpos + tlen];
                if (!isValidTrailerLine(trailer_line)) return error.InvalidChunkedBody;
                tpos += tlen + 2;
            }
        }
        if (out.items.len + chunk_size > max_body_size) return error.BodyTooLarge;
        // Checked arithmetic: an oversized hex chunk-size must fail the
        // request rather than overflow (#673 review).
        const data_end = std.math.add(usize, pos, chunk_size) catch return error.InvalidChunkedBody;
        const chunk_end = std.math.add(usize, data_end, 2) catch return error.InvalidChunkedBody;
        if (chunk_end > data.len) return error.InvalidChunkedBody;
        // Each chunk must end with a literal CRLF, not just two arbitrary
        // bytes the decoder skips past.
        if (!std.mem.eql(u8, data[data_end..chunk_end], "\r\n")) return error.InvalidChunkedBody;
        out.appendSlice(allocator, data[pos..data_end]) catch return error.OutOfMemory;
        pos = chunk_end;
    }
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

test "reject duplicate Authorization headers even when one occurrence is well-formed (#673)" {
    // Duplicate Authorization is ambiguous the same way duplicate
    // Content-Length is: HTTP defines no combination semantics for it, so
    // this must be rejected outright rather than silently preferring
    // whichever occurrence a given code path happens to read first --
    // regardless of which occurrence (first or second) would otherwise have
    // been a valid credential.
    const allocator = std.testing.allocator;

    {
        const raw = "GET /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer garbage\r\nAuthorization: Bearer valid-token\r\n\r\n";
        try std.testing.expectError(error.DuplicateAuthorizationHeader, Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE));
        try std.testing.expectError(error.DuplicateAuthorizationHeader, Request.parseHead(allocator, raw, DEFAULT_MAX_BODY_SIZE));
    }
    {
        const raw = "GET /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer valid-token\r\nAuthorization: Bearer garbage\r\n\r\n";
        try std.testing.expectError(error.DuplicateAuthorizationHeader, Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE));
        try std.testing.expectError(error.DuplicateAuthorizationHeader, Request.parseHead(allocator, raw, DEFAULT_MAX_BODY_SIZE));
    }
}

test "reject duplicate Host headers before virtual-host routing" {
    const allocator = std.testing.allocator;

    // Identical duplicates are invalid too. Rejecting only conflicting values
    // still leaves downstream hops free to combine or select fields
    // differently from Tardigrade.
    const identical = "GET / HTTP/1.1\r\nHost: example.test\r\nHost: example.test\r\n\r\n";
    try std.testing.expectError(error.DuplicateHostHeader, Request.parse(allocator, identical, DEFAULT_MAX_BODY_SIZE));
    try std.testing.expectError(error.DuplicateHostHeader, Request.parseHead(allocator, identical, DEFAULT_MAX_BODY_SIZE));

    const conflicting = "GET /protected HTTP/1.1\r\nHost: trusted.example\r\nHost: attacker.example\r\n\r\n";
    try std.testing.expectError(error.DuplicateHostHeader, Request.parse(allocator, conflicting, DEFAULT_MAX_BODY_SIZE));
    try std.testing.expectError(error.DuplicateHostHeader, Request.parseHead(allocator, conflicting, DEFAULT_MAX_BODY_SIZE));
}

test "reject empty or malformed Host authority" {
    const allocator = std.testing.allocator;
    const invalid = [_][]const u8{
        "GET / HTTP/1.1\r\nHost:\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: example.test:\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: user@example.test\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: example.test/path\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: 2001:db8::1\r\n\r\n",
    };
    for (invalid) |raw| {
        try std.testing.expectError(error.InvalidHostHeader, Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE));
        try std.testing.expectError(error.InvalidHostHeader, Request.parseHead(allocator, raw, DEFAULT_MAX_BODY_SIZE));
    }
}

test "absolute-form authority must agree with Host" {
    const allocator = std.testing.allocator;
    const mismatched = "GET http://trusted.test/private HTTP/1.1\r\nHost: attacker.test\r\n\r\n";
    try std.testing.expectError(error.InvalidHostHeader, Request.parse(allocator, mismatched, DEFAULT_MAX_BODY_SIZE));
    try std.testing.expectError(error.InvalidHostHeader, Request.parseHead(allocator, mismatched, DEFAULT_MAX_BODY_SIZE));

    var parsed = try Request.parse(
        allocator,
        "GET https://Example.test/private HTTP/1.1\r\nHost: example.test:443\r\n\r\n",
        DEFAULT_MAX_BODY_SIZE,
    );
    defer parsed.request.deinit();
    try std.testing.expectEqualStrings("/private", parsed.request.uri.path);
    try std.testing.expectEqualStrings("Example.test", parsed.request.uri.authority.?);
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

test "reject a Transfer-Encoding coding list instead of pattern-matching a chunked token (#673 review)" {
    // Both orderings of "chunked, gzip" used to be ACCEPTED as plain chunked
    // framing because the old check only asked "does any comma-separated
    // token equal chunked", ignoring the rest of the list. Tardigrade has no
    // way to apply the "gzip" coding, and "chunked" is only valid as the
    // final coding anyway (RFC 7230 §3.3.1), so the whole request must be
    // rejected rather than decoded as if chunked were the only coding.
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.ConflictingHeaders, Request.parse(
        allocator,
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked, gzip\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        DEFAULT_MAX_BODY_SIZE,
    ));
    try std.testing.expectError(error.ConflictingHeaders, Request.parse(
        allocator,
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: gzip, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        DEFAULT_MAX_BODY_SIZE,
    ));
    try std.testing.expectError(error.ConflictingHeaders, Request.parseHead(
        allocator,
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
        DEFAULT_MAX_BODY_SIZE,
    ));
}

test "chunked body with no terminating zero chunk is rejected, not silently accepted at EOF (#673 review)" {
    // The old decoder's outer loop condition was `while (pos < data.len)`,
    // so reaching the end of the buffer right after a nonzero chunk's data
    // (with no "0\r\n" terminator ever seen) fell out of the loop and
    // returned successfully -- treating a truncated chunked body as if it
    // were complete.
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidChunkedBody, Request.parse(
        allocator,
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n",
        DEFAULT_MAX_BODY_SIZE,
    ));
}

test "chunked body's trailer section must actually end in a blank line (#673 review)" {
    // The old decoder stopped scanning the instant it saw "0\r\n" and never
    // required the trailer section to reach its own terminating blank line,
    // so trailing bytes right after "0\r\n" -- including what could be a
    // pipelined next request -- were never validated as part of this body's
    // framing.
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidChunkedBody, Request.parse(
        allocator,
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n",
        DEFAULT_MAX_BODY_SIZE,
    ));
}

test "chunked request reports the exact consumed offset, not the whole buffer, as its body boundary (#673 review)" {
    // The old decoder always set `total_bytes = data.len`, so a pipelined
    // second request already sitting right after a chunked body's real
    // terminator was silently swallowed into "this request's consumed
    // bytes" instead of being left for the next parse.
    const allocator = std.testing.allocator;
    const raw = "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n" ++
        "GET /next HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const result = try Request.parse(allocator, raw, DEFAULT_MAX_BODY_SIZE);
    var req = result.request;
    defer req.deinit();
    try std.testing.expectEqualStrings("hello", req.body.?);
    const consumed_prefix_len = raw.len - "GET /next HTTP/1.1\r\nHost: localhost\r\n\r\n".len;
    try std.testing.expectEqual(consumed_prefix_len, result.bytes_consumed);
}

test "chunked body's trailer lines must actually be header-field syntax (#673 review)" {
    // A trailer line with no colon is not `header-field` per RFC 7230
    // §4.1.2 -- the old decoder accepted any non-blank line as "a trailer"
    // without checking, so unstructured bytes here (which could really be
    // part of a pipelined next request) were silently swallowed as if they
    // were legitimate trailer syntax.
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidChunkedBody, Request.parse(
        allocator,
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nBad Trailer No Colon\r\n\r\n",
        DEFAULT_MAX_BODY_SIZE,
    ));
    // A well-formed trailer (has a colon) is still accepted.
    const result = try Request.parse(
        allocator,
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Checksum: abc123\r\n\r\n",
        DEFAULT_MAX_BODY_SIZE,
    );
    var req = result.request;
    defer req.deinit();
    try std.testing.expectEqual(@as(usize, 0), req.body.?.len);
}

test "chunked body's trailer lines must be a valid header field, not just contain a colon (#673 review round 8)" {
    // A colon-only check (the round-7 version of this validation) would
    // have accepted all of these: a colon is present, but the name or
    // value is malformed.
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidChunkedBody, Request.parse(
        allocator,
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nBad Name: x\r\n\r\n",
        DEFAULT_MAX_BODY_SIZE,
    ));
    try std.testing.expectError(error.InvalidChunkedBody, Request.parse(
        allocator,
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Bad\x00Name: x\r\n\r\n",
        DEFAULT_MAX_BODY_SIZE,
    ));
    try std.testing.expectError(error.InvalidChunkedBody, Request.parse(
        allocator,
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Good: bad\x00value\r\n\r\n",
        DEFAULT_MAX_BODY_SIZE,
    ));
}

test "fuzz: Request.parse never panics on arbitrary HTTP input" {
    try std.testing.fuzz({}, fuzzRequestParse, .{ .corpus = &.{
        "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "POST /api HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello",
        "GET / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        "",
    } });
}

fn fuzzRequestParse(_: void, smith: *std.testing.Smith) !void {
    const allocator = std.testing.allocator;
    var buf: [4096]u8 = undefined;
    const len = smith.sliceWeightedBytes(&buf, &.{
        .rangeAtMost(u8, 0x20, 0x7e, 6), // printable ASCII
        .value(u8, '\r', 3),
        .value(u8, '\n', 3),
        .value(u8, ':', 1),
        .rangeAtMost(u8, 0x00, 0x1f, 1), // control characters
    });
    var parsed = Request.parse(allocator, buf[0..len], DEFAULT_MAX_BODY_SIZE) catch return;
    parsed.request.deinit();
}
