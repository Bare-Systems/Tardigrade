const std = @import("std");
const build_options = @import("build_options");
const Allocator = std.mem.Allocator;
const Status = @import("status.zig").Status;
const Headers = @import("headers.zig").Headers;
const Version = @import("version.zig").Version;
const correlation = @import("correlation_id.zig");

/// Server name and version for Server header
pub const SERVER_NAME = "tardigrade";
pub const SERVER_VERSION = build_options.version;

// Try to load a custom error page from `public/errors/<code>.html`.
fn loadCustomErrorPage(allocator: Allocator, status: Status) ?[]const u8 {
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "public/errors/{d}.html", .{status.code()}) catch return null;

    var file = std.fs.cwd().openFile(path, .{}) catch return null;
    defer file.close();

    const stat = file.stat() catch return null;
    const file_size = @as(usize, stat.size);
    if (file_size == 0) return null;

    const buf = allocator.alloc(u8, file_size) catch return null;
    const bytes_read = file.readAll(buf) catch {
        allocator.free(buf);
        return null;
    };

    return buf[0..bytes_read];
}

/// HTTP Response builder
pub const Response = struct {
    allocator: Allocator,
    version: Version,
    status: Status,
    headers: Headers,
    body: ?[]const u8,
    body_owned: bool,

    /// Initialize a new response
    pub fn init(allocator: Allocator) Response {
        return .{
            .allocator = allocator,
            .version = .http11,
            .status = .ok,
            .headers = Headers.init(allocator),
            .body = null,
            .body_owned = false,
        };
    }

    /// Free resources
    pub fn deinit(self: *Response) void {
        self.headers.deinit();
        if (self.body_owned) {
            if (self.body) |b| {
                self.allocator.free(b);
            }
        }
    }

    /// Set the HTTP version
    pub fn setVersion(self: *Response, version: Version) *Response {
        self.version = version;
        return self;
    }

    /// Set the status code
    pub fn setStatus(self: *Response, status: Status) *Response {
        self.status = status;
        return self;
    }

    /// Set a header value
    pub fn setHeader(self: *Response, name: []const u8, value: []const u8) *Response {
        self.headers.append(name, value) catch {};
        return self;
    }

    /// Set the response body (non-owning, caller retains ownership)
    pub fn setBody(self: *Response, body: []const u8) *Response {
        if (self.body_owned) {
            if (self.body) |b| {
                self.allocator.free(b);
            }
        }
        self.body = body;
        self.body_owned = false;
        return self;
    }

    /// Set the response body (owning, response will free it)
    pub fn setBodyOwned(self: *Response, body: []const u8) *Response {
        if (self.body_owned) {
            if (self.body) |b| {
                self.allocator.free(b);
            }
        }
        self.body = body;
        self.body_owned = true;
        return self;
    }

    /// Set Content-Type header
    pub fn setContentType(self: *Response, content_type: []const u8) *Response {
        return self.setHeader("Content-Type", content_type);
    }

    /// Set Content-Length header
    pub fn setContentLength(self: *Response, content_length: usize) *Response {
        var buf: [32]u8 = undefined;
        const rendered = std.fmt.bufPrint(&buf, "{d}", .{content_length}) catch return self;
        return self.setHeader("Content-Length", rendered);
    }

    /// Set Connection header (keep-alive or close)
    pub fn setConnection(self: *Response, keep_alive: bool) *Response {
        return self.setHeader("Connection", if (keep_alive) "keep-alive" else "close");
    }

    /// Write the response to a writer
    pub fn write(self: *Response, writer: anytype) !void {
        // Status line
        try writer.print("{s} {d} {s}\r\n", .{
            self.version.toString(),
            self.status.code(),
            self.status.phrase(),
        });

        // Auto-generate Date header
        try self.writeDate(writer);

        // Server header
        try writer.print("Server: {s}/{s}\r\n", .{ SERVER_NAME, SERVER_VERSION });

        // Content-Length
        if (self.headers.get("content-length")) |content_length| {
            try writer.print("Content-Length: {s}\r\n", .{content_length});
        } else {
            const body_len = if (self.body) |b| b.len else 0;
            try writer.print("Content-Length: {d}\r\n", .{body_len});
        }

        try self.writeRequestIdHeaders(writer);

        // User-defined headers
        for (self.headers.iterator()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "content-length")) continue;
            if (std.ascii.eqlIgnoreCase(header.name, correlation.HEADER_NAME) or
                std.ascii.eqlIgnoreCase(header.name, correlation.REQUEST_HEADER_NAME)) continue;
            try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
        }

        // End of headers
        try writer.writeAll("\r\n");

        // Body
        if (self.body) |b| {
            try writer.writeAll(b);
        }
    }

    /// Write the response without body (for HEAD requests)
    pub fn writeHead(self: *Response, writer: anytype) !void {
        // Status line
        try writer.print("{s} {d} {s}\r\n", .{
            self.version.toString(),
            self.status.code(),
            self.status.phrase(),
        });

        // Auto-generate Date header
        try self.writeDate(writer);

        // Server header
        try writer.print("Server: {s}/{s}\r\n", .{ SERVER_NAME, SERVER_VERSION });

        // Content-Length (still include even for HEAD)
        if (self.headers.get("content-length")) |content_length| {
            try writer.print("Content-Length: {s}\r\n", .{content_length});
        } else {
            const body_len = if (self.body) |b| b.len else 0;
            try writer.print("Content-Length: {d}\r\n", .{body_len});
        }

        try self.writeRequestIdHeaders(writer);

        // User-defined headers
        for (self.headers.iterator()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "content-length")) continue;
            if (std.ascii.eqlIgnoreCase(header.name, correlation.HEADER_NAME) or
                std.ascii.eqlIgnoreCase(header.name, correlation.REQUEST_HEADER_NAME)) continue;
            try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
        }

        // End of headers
        try writer.writeAll("\r\n");
    }

    fn writeDate(self: *Response, writer: anytype) !void {
        _ = self;
        const timestamp = std.time.timestamp();
        const epoch_secs: std.time.epoch.EpochSeconds = .{ .secs = @intCast(timestamp) };
        const day_secs = epoch_secs.getDaySeconds();
        const epoch_day = epoch_secs.getEpochDay();
        const year_day = epoch_day.calculateYearDay();
        const month_day = year_day.calculateMonthDay();

        // Day names starting from Thursday (epoch day 0 = 1970-01-01 = Thursday)
        const day_names = [_][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" };
        const month_names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

        // Calculate day of week: epoch (1970-01-01) was a Thursday (index 0)
        const day_of_week = @mod(epoch_day.day, 7);
        const day_name = day_names[day_of_week];
        const month_name = month_names[@intFromEnum(month_day.month) - 1];

        try writer.print("Date: {s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} GMT\r\n", .{
            day_name,
            month_day.day_index + 1, // day_index is 0-based, HTTP date is 1-based
            month_name,
            year_day.year,
            day_secs.getHoursIntoDay(),
            day_secs.getMinutesIntoHour(),
            day_secs.getSecondsIntoMinute(),
        });
    }

    fn writeRequestIdHeaders(self: *Response, writer: anytype) !void {
        const request_id = self.headers.get("x-request-id");
        const correlation_id = self.headers.get("x-correlation-id");
        const effective = request_id orelse correlation_id orelse return;

        try writer.print("{s}: {s}\r\n", .{ correlation.REQUEST_HEADER_NAME, effective });
        try writer.print("{s}: {s}\r\n", .{ correlation.HEADER_NAME, effective });
    }

    // ============ Convenience constructors ============

    /// Create a 200 OK response with body
    pub fn ok(allocator: Allocator, body: []const u8, content_type: []const u8) Response {
        var resp = Response.init(allocator);
        _ = resp.setStatus(.ok).setBody(body).setContentType(content_type);
        return resp;
    }

    /// Create a 201 Created response
    pub fn created(allocator: Allocator, body: []const u8, location: ?[]const u8) Response {
        var resp = Response.init(allocator);
        _ = resp.setStatus(.created).setBody(body);
        if (location) |loc| {
            _ = resp.setHeader("Location", loc);
        }
        return resp;
    }

    /// Create a 204 No Content response
    pub fn noContent(allocator: Allocator) Response {
        var resp = Response.init(allocator);
        _ = resp.setStatus(.no_content);
        return resp;
    }

    /// Create a redirect response
    pub fn redirect(allocator: Allocator, location: []const u8, status: Status) Response {
        var resp = Response.init(allocator);
        _ = resp.setStatus(status).setHeader("Location", location);
        return resp;
    }

    /// Create a 301 Moved Permanently redirect
    pub fn movedPermanently(allocator: Allocator, location: []const u8) Response {
        return redirect(allocator, location, .moved_permanently);
    }

    /// Create a 302 Found redirect
    pub fn found(allocator: Allocator, location: []const u8) Response {
        return redirect(allocator, location, .found);
    }

    /// Create a 400 Bad Request response
    pub fn badRequest(allocator: Allocator, message: []const u8) Response {
        var resp = Response.init(allocator);
        const custom = loadCustomErrorPage(allocator, .bad_request);
        if (custom) |c| {
            _ = resp.setStatus(.bad_request).setBodyOwned(c).setContentType("text/html; charset=utf-8");
        } else {
            _ = resp.setStatus(.bad_request).setBody(message).setContentType("text/plain; charset=utf-8");
        }
        return resp;
    }

    /// Create a 401 Unauthorized response
    pub fn unauthorized(allocator: Allocator, realm: []const u8) Response {
        var resp = Response.init(allocator);
        const custom = loadCustomErrorPage(allocator, .unauthorized);
        if (custom) |c| {
            _ = resp.setStatus(.unauthorized).setBodyOwned(c).setContentType("text/html; charset=utf-8");
        } else {
            _ = resp.setStatus(.unauthorized).setBody("Unauthorized");
        }

        var buf: [256]u8 = undefined;
        const auth_header = std.fmt.bufPrint(&buf, "Basic realm=\"{s}\"", .{realm}) catch "Basic";
        _ = resp.setHeader("WWW-Authenticate", auth_header);

        return resp;
    }

    /// Create a 403 Forbidden response
    pub fn forbidden(allocator: Allocator) Response {
        var resp = Response.init(allocator);
        const custom = loadCustomErrorPage(allocator, .forbidden);
        if (custom) |c| {
            _ = resp.setStatus(.forbidden).setBodyOwned(c).setContentType("text/html; charset=utf-8");
        } else {
            _ = resp.setStatus(.forbidden).setBody("Forbidden").setContentType("text/plain; charset=utf-8");
        }
        return resp;
    }

    /// Create a 404 Not Found response
    pub fn notFound(allocator: Allocator) Response {
        var resp = Response.init(allocator);
        const custom = loadCustomErrorPage(allocator, .not_found);
        if (custom) |c| {
            _ = resp.setStatus(.not_found).setBodyOwned(c).setContentType("text/html; charset=utf-8");
        } else {
            _ = resp.setStatus(.not_found).setBody("Not Found").setContentType("text/plain; charset=utf-8");
        }
        return resp;
    }

    /// Create a 405 Method Not Allowed response
    pub fn methodNotAllowed(allocator: Allocator, allowed: []const u8) Response {
        var resp = Response.init(allocator);
        _ = resp.setStatus(.method_not_allowed).setBody("Method Not Allowed").setContentType("text/plain; charset=utf-8").setHeader("Allow", allowed);
        return resp;
    }

    /// Create a 413 Payload Too Large response
    pub fn payloadTooLarge(allocator: Allocator) Response {
        var resp = Response.init(allocator);
        _ = resp.setStatus(.payload_too_large).setBody("Payload Too Large").setContentType("text/plain; charset=utf-8");
        return resp;
    }

    /// Create a 414 URI Too Long response
    pub fn uriTooLong(allocator: Allocator) Response {
        var resp = Response.init(allocator);
        _ = resp.setStatus(.uri_too_long).setBody("URI Too Long").setContentType("text/plain; charset=utf-8");
        return resp;
    }

    /// Create a 431 Request Header Fields Too Large response
    pub fn headersTooLarge(allocator: Allocator) Response {
        var resp = Response.init(allocator);
        _ = resp.setStatus(.request_header_fields_too_large).setBody("Request Header Fields Too Large").setContentType("text/plain; charset=utf-8");
        return resp;
    }

    /// Create a 500 Internal Server Error response
    pub fn internalServerError(allocator: Allocator) Response {
        var resp = Response.init(allocator);
        const custom = loadCustomErrorPage(allocator, .internal_server_error);
        if (custom) |c| {
            _ = resp.setStatus(.internal_server_error).setBodyOwned(c).setContentType("text/html; charset=utf-8");
        } else {
            _ = resp.setStatus(.internal_server_error).setBody("Internal Server Error").setContentType("text/plain; charset=utf-8");
        }
        return resp;
    }

    /// Create a 501 Not Implemented response
    pub fn notImplemented(allocator: Allocator) Response {
        var resp = Response.init(allocator);
        _ = resp.setStatus(.not_implemented).setBody("Not Implemented").setContentType("text/plain; charset=utf-8");
        return resp;
    }

    /// Create a 502 Bad Gateway response
    pub fn badGateway(allocator: Allocator) Response {
        var resp = Response.init(allocator);
        const custom = loadCustomErrorPage(allocator, .bad_gateway);
        if (custom) |c| {
            _ = resp.setStatus(.bad_gateway).setBodyOwned(c).setContentType("text/html; charset=utf-8");
        } else {
            _ = resp.setStatus(.bad_gateway).setBody("Bad Gateway").setContentType("text/plain; charset=utf-8");
        }
        return resp;
    }

    /// Create a 503 Service Unavailable response
    pub fn serviceUnavailable(allocator: Allocator) Response {
        var resp = Response.init(allocator);
        const custom = loadCustomErrorPage(allocator, .service_unavailable);
        if (custom) |c| {
            _ = resp.setStatus(.service_unavailable).setBodyOwned(c).setContentType("text/html; charset=utf-8");
        } else {
            _ = resp.setStatus(.service_unavailable).setBody("Service Unavailable").setContentType("text/plain; charset=utf-8");
        }
        return resp;
    }

    /// Create a 504 Gateway Timeout response
    pub fn gatewayTimeout(allocator: Allocator) Response {
        var resp = Response.init(allocator);
        const custom = loadCustomErrorPage(allocator, .gateway_timeout);
        if (custom) |c| {
            _ = resp.setStatus(.gateway_timeout).setBodyOwned(c).setContentType("text/html; charset=utf-8");
        } else {
            _ = resp.setStatus(.gateway_timeout).setBody("Gateway Timeout").setContentType("text/plain; charset=utf-8");
        }
        return resp;
    }

    /// Create a 505 HTTP Version Not Supported response
    pub fn httpVersionNotSupported(allocator: Allocator) Response {
        var resp = Response.init(allocator);
        _ = resp.setStatus(.http_version_not_supported).setBody("HTTP Version Not Supported").setContentType("text/plain; charset=utf-8");
        return resp;
    }

    /// Create a JSON response
    pub fn json(allocator: Allocator, body: []const u8) Response {
        var resp = Response.init(allocator);
        _ = resp.setStatus(.ok).setBody(body).setContentType("application/json");
        return resp;
    }

    /// Create an HTML response
    pub fn html(allocator: Allocator, body: []const u8) Response {
        var resp = Response.init(allocator);
        _ = resp.setStatus(.ok).setBody(body).setContentType("text/html; charset=utf-8");
        return resp;
    }

    /// Create a plain text response
    pub fn text(allocator: Allocator, body: []const u8) Response {
        var resp = Response.init(allocator);
        _ = resp.setStatus(.ok).setBody(body).setContentType("text/plain; charset=utf-8");
        return resp;
    }
};

// Tests
test "build simple 200 response" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var response = Response.init(allocator);
    defer response.deinit();

    _ = response.setStatus(.ok).setBody("Hello, World!").setContentType("text/plain");

    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try response.write(stream.writer());

    const output = stream.getWritten();
    try testing.expect(std.mem.startsWith(u8, output, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, output, "Content-Length: 13\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, output, "Server: tardigrade/") != null);
    try testing.expect(std.mem.indexOf(u8, output, "Date: ") != null);
    try testing.expect(std.mem.endsWith(u8, output, "Hello, World!"));
}

test "404 response" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var response = Response.notFound(allocator);
    defer response.deinit();

    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try response.write(stream.writer());

    const output = stream.getWritten();
    try testing.expect(std.mem.startsWith(u8, output, "HTTP/1.1 404 Not Found\r\n"));
    // Headers are lowercased when stored. Accept plain text or html if a custom page is present.
    const has_plain = std.mem.indexOf(u8, output, "content-type: text/plain") != null;
    const has_html = std.mem.indexOf(u8, output, "content-type: text/html") != null;
    try testing.expect(has_plain or has_html);
}

test "redirect response" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var response = Response.movedPermanently(allocator, "/new-location");
    defer response.deinit();

    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try response.write(stream.writer());

    const output = stream.getWritten();
    try testing.expect(std.mem.startsWith(u8, output, "HTTP/1.1 301 Moved Permanently\r\n"));
    try testing.expect(std.mem.indexOf(u8, output, "location: /new-location\r\n") != null);
}

test "custom headers" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var response = Response.init(allocator);
    defer response.deinit();

    _ = response.setStatus(.ok).setHeader("X-Custom", "my-value").setHeader("X-Another", "another-value");

    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try response.write(stream.writer());

    const output = stream.getWritten();
    try testing.expect(std.mem.indexOf(u8, output, "x-custom: my-value\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, output, "x-another: another-value\r\n") != null);
}

test "head response excludes body" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var response = Response.init(allocator);
    defer response.deinit();

    _ = response.setStatus(.ok).setBody("This body should not appear");

    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try response.writeHead(stream.writer());

    const output = stream.getWritten();
    // Should have Content-Length but not the body
    try testing.expect(std.mem.indexOf(u8, output, "Content-Length: 27\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, output, "This body should not appear") == null);
}

test "json response" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var response = Response.json(allocator, "{\"status\": \"ok\"}");
    defer response.deinit();

    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try response.write(stream.writer());

    const output = stream.getWritten();
    // Headers are lowercased when stored
    try testing.expect(std.mem.indexOf(u8, output, "content-type: application/json\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, output, "{\"status\": \"ok\"}"));
}

test "method not allowed includes Allow header" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var response = Response.methodNotAllowed(allocator, "GET, HEAD");
    defer response.deinit();

    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try response.write(stream.writer());

    const output = stream.getWritten();
    try testing.expect(std.mem.startsWith(u8, output, "HTTP/1.1 405 Method Not Allowed\r\n"));
    try testing.expect(std.mem.indexOf(u8, output, "allow: GET, HEAD\r\n") != null);
}

test "date header format" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var response = Response.init(allocator);
    defer response.deinit();

    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try response.write(stream.writer());

    const output = stream.getWritten();
    // Date format: "Date: Mon, 27 Jan 2026 03:00:00 GMT"
    // Check it contains "Date: " and " GMT"
    try testing.expect(std.mem.indexOf(u8, output, "Date: ") != null);
    try testing.expect(std.mem.indexOf(u8, output, " GMT\r\n") != null);
}

test "connection header when setConnection(true)" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var response = Response.init(allocator);
    defer response.deinit();

    _ = response.setBody("hi").setConnection(true);

    var buf: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try response.write(stream.writer());

    const output = stream.getWritten();
    try testing.expect(std.mem.indexOf(u8, output, "connection: keep-alive\r\n") != null);
}

test "connection header when setConnection(false)" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var response = Response.init(allocator);
    defer response.deinit();

    _ = response.setBody("hi").setConnection(false);

    var buf: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try response.write(stream.writer());

    const output = stream.getWritten();
    try testing.expect(std.mem.indexOf(u8, output, "connection: close\r\n") != null);
}
