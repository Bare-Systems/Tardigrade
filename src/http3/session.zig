//! HTTP/3 request/response mapping (#246): turns request stream frames into the
//! shared `stream_transport` shape and emits response HEADERS/DATA frames.
//!
//! This is the minimal pure-Zig HTTP/3 session layer. The request/response
//! helpers still use the static-only QPACK fallback from `qpack.zig` while the
//! dynamic table and encoder/decoder stream state are exposed separately for
//! negotiated HTTP/3 connections. Request bodies are buffered only inside the
//! per-stream assembler used by unit tests and the future QUIC connection
//! driver; priority and downstream listener rollout remain out of scope.

const std = @import("std");

const frame = @import("frame.zig");
const priority = @import("priority.zig");
const qpack = @import("qpack.zig");
const varint = @import("quic_varint");
const stream_transport = @import("stream_transport");

pub const protocol: stream_transport.Protocol = .h3;

pub const SessionError = error{
    BufferTooShort,
    FrameLengthOverflow,
    FrameTooLarge,
    InvalidRequestFrame,
    DuplicateHeaders,
    HeadersAfterDataUnsupported,
    MissingRequiredPseudoHeader,
    DuplicatePseudoHeader,
    PseudoHeaderAfterRegularHeader,
    InvalidPseudoHeader,
    UnexpectedFrame,
    InvalidStatus,
    QpackDecodeFailed,
    InvalidHeader,
    InvalidContentLength,
    BodyTooLarge,
    OutputOverflow,
    OutOfMemory,
};

pub const Metrics = struct {
    requests_started: u64 = 0,
    requests_completed: u64 = 0,
    malformed_frames: u64 = 0,
    protocol_errors: u64 = 0,
    goaway_received: u64 = 0,
    active_streams: u64 = 0,
};

pub const RequestStream = struct {
    pub const max_frame_payload_len: usize = 1024 * 1024;
    pub const default_max_body_len: usize = 1024 * 1024;

    allocator: std.mem.Allocator,
    stream_id: u64,
    pending: std.ArrayList(u8) = .empty,
    method: ?[]u8 = null,
    scheme: ?[]u8 = null,
    authority: ?[]u8 = null,
    path: ?[]u8 = null,
    headers: std.ArrayList(stream_transport.Header) = .empty,
    body: std.ArrayList(u8) = .empty,
    priority: priority.Priority = priority.Priority.default,
    priority_parse_error: bool = false,
    priority_invalid_parameter: bool = false,
    priority_duplicate_parameter: bool = false,
    saw_headers: bool = false,
    saw_data: bool = false,
    finished: bool = false,
    max_body_len: usize = default_max_body_len,

    pub fn init(allocator: std.mem.Allocator, stream_id: u64) RequestStream {
        return .{ .allocator = allocator, .stream_id = stream_id };
    }

    pub fn initWithBodyLimit(allocator: std.mem.Allocator, stream_id: u64, max_body_len: usize) RequestStream {
        return .{ .allocator = allocator, .stream_id = stream_id, .max_body_len = max_body_len };
    }

    pub fn deinit(self: *RequestStream) void {
        if (self.method) |value| self.allocator.free(value);
        if (self.scheme) |value| self.allocator.free(value);
        if (self.authority) |value| self.allocator.free(value);
        if (self.path) |value| self.allocator.free(value);
        for (self.headers.items) |header| {
            self.allocator.free(header.name);
            self.allocator.free(header.value);
        }
        self.pending.deinit(self.allocator);
        self.headers.deinit(self.allocator);
        self.body.deinit(self.allocator);
        self.* = undefined;
    }

    /// Dynamic bytes retained for this in-flight request.  The HTTP/3
    /// connection uses this to enforce an aggregate per-connection budget;
    /// a per-stream body limit alone still permits many concurrent streams to
    /// multiply memory use.
    pub fn retainedBytes(self: *const RequestStream) usize {
        var total = self.pending.capacity +| self.body.capacity;
        total +|= self.headers.capacity *| @sizeOf(stream_transport.Header);
        if (self.method) |value| total +|= value.len;
        if (self.scheme) |value| total +|= value.len;
        if (self.authority) |value| total +|= value.len;
        if (self.path) |value| total +|= value.len;
        for (self.headers.items) |header| {
            total +|= header.name.len;
            total +|= header.value.len;
        }
        return total;
    }

    pub fn ingestBytes(self: *RequestStream, bytes: []const u8, qpack_scratch: []u8) SessionError!usize {
        return self.ingestBytesWithObserver(bytes, qpack_scratch, null);
    }

    pub const FrameObserver = struct {
        context: ?*anyopaque = null,
        parsedFn: ?*const fn (?*anyopaque, frame.RawFrame) void = null,

        fn parsed(self: FrameObserver, raw: frame.RawFrame) void {
            if (self.parsedFn) |parsed_fn| parsed_fn(self.context, raw);
        }
    };

    pub fn ingestBytesWithObserver(self: *RequestStream, bytes: []const u8, qpack_scratch: []u8, observer: ?FrameObserver) SessionError!usize {
        self.pending.appendSlice(self.allocator, bytes) catch return error.OutOfMemory;
        while (true) {
            const raw = frame.decodeFrameWithLimit(self.pending.items, max_frame_payload_len) catch |err| switch (err) {
                error.BufferTooShort => return bytes.len,
                else => return mapFrameDecodeError(err),
            };
            if (observer) |obs| obs.parsed(raw);
            try self.ingestFrame(raw, qpack_scratch);
            discardPrefix(&self.pending, raw.len);
        }
    }

    pub fn ingestFrame(self: *RequestStream, raw: frame.RawFrame, qpack_scratch: []u8) SessionError!void {
        switch (raw.typ) {
            .headers => {
                if (self.saw_data) return error.HeadersAfterDataUnsupported;
                if (self.saw_headers) return error.DuplicateHeaders;
                try self.ingestHeaders(raw.payload, qpack_scratch);
            },
            .data => {
                if (!self.saw_headers) return error.InvalidRequestFrame;
                self.saw_data = true;
                if (raw.payload.len > self.max_body_len -| self.body.items.len) return error.BodyTooLarge;
                try self.body.appendSlice(self.allocator, raw.payload);
            },
            .goaway => return error.InvalidRequestFrame,
            .priority_update_request, .priority_update_push => return error.UnexpectedFrame,
            .settings, .cancel_push, .push_promise, .max_push_id => return error.InvalidRequestFrame,
            .unknown => {},
        }
    }

    fn ingestHeaders(self: *RequestStream, payload: []const u8, qpack_scratch: []u8) SessionError!void {
        var fields: [128]qpack.HeaderField = undefined;
        const count = qpack.decode(payload, &fields, qpack_scratch) catch return error.QpackDecodeFailed;
        var regular_seen = false;
        var host: ?[]const u8 = null;
        var authorization_seen = false;
        var content_length_seen = false;
        var priority_seen = false;
        var priority_value: std.ArrayList(u8) = .empty;
        defer priority_value.deinit(self.allocator);
        for (fields[0..count]) |field| {
            if (field.name.len > 0 and field.name[0] == ':') {
                if (regular_seen) return error.PseudoHeaderAfterRegularHeader;
                try self.applyPseudoHeader(field);
            } else {
                regular_seen = true;
                if (!validH3HeaderName(field.name) or !validH3HeaderValue(field.value)) return error.InvalidHeader;
                if (std.mem.eql(u8, field.name, "host")) {
                    if (host != null) return error.InvalidHeader;
                    host = field.value;
                }
                if (std.mem.eql(u8, field.name, "authorization")) {
                    if (authorization_seen) return error.InvalidHeader;
                    authorization_seen = true;
                }
                if (std.mem.eql(u8, field.name, "content-length")) {
                    if (content_length_seen) return error.InvalidContentLength;
                    content_length_seen = true;
                }
                if (h3ConnectionSpecificHeader(field.name, field.value)) return error.InvalidHeader;
                if (std.ascii.eqlIgnoreCase(field.name, "priority")) {
                    if (priority_seen) try priority_value.appendSlice(self.allocator, ", ");
                    try priority_value.appendSlice(self.allocator, field.value);
                    priority_seen = true;
                }
                try self.appendHeader(field.name, field.value);
            }
        }
        if (self.authority) |authority| {
            if (!validH3HeaderValue(authority)) return error.InvalidHeader;
            if (host) |host_value| {
                if (!std.ascii.eqlIgnoreCase(authority, host_value)) return error.InvalidHeader;
            }
        }
        if (priority_seen) {
            if (priority.parse(priority_value.items)) |parsed| {
                self.priority = parsed.effective();
                self.priority_parse_error = false;
                self.priority_invalid_parameter = parsed.invalid_parameter;
                self.priority_duplicate_parameter = parsed.duplicate_parameter;
            } else |_| {
                self.priority = priority.Priority.default;
                self.priority_parse_error = true;
                self.priority_invalid_parameter = false;
                self.priority_duplicate_parameter = false;
            }
        }
        self.saw_headers = true;
    }

    fn applyPseudoHeader(self: *RequestStream, field: qpack.HeaderField) SessionError!void {
        if (!validH3HeaderValue(field.value)) return error.InvalidHeader;
        if (std.mem.eql(u8, field.name, ":method")) return replaceOnce(self.allocator, &self.method, field.value);
        if (std.mem.eql(u8, field.name, ":scheme")) return replaceOnce(self.allocator, &self.scheme, field.value);
        if (std.mem.eql(u8, field.name, ":authority")) return replaceOnce(self.allocator, &self.authority, field.value);
        if (std.mem.eql(u8, field.name, ":path")) return replaceOnce(self.allocator, &self.path, field.value);
        return error.InvalidPseudoHeader;
    }

    fn appendHeader(self: *RequestStream, name: []const u8, value: []const u8) !void {
        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        const owned_value = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(owned_value);
        try self.headers.append(self.allocator, .{ .name = owned_name, .value = owned_value });
    }

    pub fn finish(self: *RequestStream) SessionError!stream_transport.Exchange {
        if (self.pending.items.len != 0 or !self.saw_headers) return error.MissingRequiredPseudoHeader;
        const method = self.method orelse return error.MissingRequiredPseudoHeader;
        const scheme = self.scheme orelse return error.MissingRequiredPseudoHeader;
        const authority = self.authority orelse return error.MissingRequiredPseudoHeader;
        const path = self.path orelse return error.MissingRequiredPseudoHeader;
        if (!validH3Method(method) or
            !(std.mem.eql(u8, scheme, "http") or std.mem.eql(u8, scheme, "https")) or
            !validH3Path(path) or
            !validH3Authority(authority))
        {
            return error.InvalidHeader;
        }
        for (self.headers.items) |header| {
            if (std.mem.eql(u8, header.name, "content-length")) {
                const declared = std.fmt.parseInt(usize, header.value, 10) catch return error.InvalidContentLength;
                if (declared != self.body.items.len) return error.InvalidContentLength;
            }
        }
        self.finished = true;
        return .{
            .request = .{
                .method = method,
                .scheme = scheme,
                .authority = authority,
                .path = path,
                .headers = self.headers.items,
            },
            .body = if (self.body.items.len == 0) .none else .{ .buffered = self.body.items },
        };
    }
};

fn validH3HeaderName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| {
        // HTTP/3 field names are lowercase. This tchar subset also rejects
        // separators and controls before the gateway's shared Headers owner.
        if (std.ascii.isUpper(c)) return false;
        if (!(std.ascii.isAlphanumeric(c) or std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", c) != null)) return false;
    }
    return true;
}

fn validH3HeaderValue(value: []const u8) bool {
    for (value) |c| {
        if ((c < 0x20 and c != '\t') or c == 0x7f) return false;
    }
    return true;
}

fn validH3Method(method: []const u8) bool {
    if (method.len == 0) return false;
    for (method) |c| {
        if (!(std.ascii.isAlphanumeric(c) or std.mem.indexOfScalar(u8, "!#$%&'*+-.^_`|~", c) != null)) return false;
    }
    return true;
}

fn validH3Path(path: []const u8) bool {
    if (!(std.mem.eql(u8, path, "*") or (path.len > 0 and path[0] == '/'))) return false;
    for (path) |c| {
        if (c <= 0x20 or c == 0x7f or c == '#') return false;
    }
    return true;
}

fn validH3Authority(authority: []const u8) bool {
    if (authority.len == 0) return false;
    for (authority) |c| {
        if (c <= 0x20 or c == 0x7f) return false;
        if (std.mem.indexOfScalar(u8, "/\\?#@,;", c) != null) return false;
    }
    if (authority[0] == '[') {
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return false;
        if (close == 1) return false;
        const suffix = authority[close + 1 ..];
        if (suffix.len == 0) return true;
        if (suffix[0] != ':' or suffix.len == 1) return false;
        _ = std.fmt.parseInt(u16, suffix[1..], 10) catch return false;
        return true;
    }
    if (std.mem.findScalarLast(u8, authority, ':')) |colon| {
        if (colon == 0 or colon + 1 == authority.len) return false;
        if (std.mem.indexOfScalar(u8, authority[0..colon], ':') != null) return false;
        _ = std.fmt.parseInt(u16, authority[colon + 1 ..], 10) catch return false;
    }
    return true;
}

fn h3ConnectionSpecificHeader(name: []const u8, value: []const u8) bool {
    if (std.mem.eql(u8, name, "connection") or
        std.mem.eql(u8, name, "proxy-connection") or
        std.mem.eql(u8, name, "keep-alive") or
        std.mem.eql(u8, name, "transfer-encoding") or
        std.mem.eql(u8, name, "upgrade")) return true;
    return std.mem.eql(u8, name, "te") and !std.ascii.eqlIgnoreCase(std.mem.trim(u8, value, " \t"), "trailers");
}

fn discardPrefix(list: *std.ArrayList(u8), len: usize) void {
    if (len == 0) return;
    if (len >= list.items.len) {
        list.clearRetainingCapacity();
        return;
    }
    std.mem.copyForwards(u8, list.items[0 .. list.items.len - len], list.items[len..]);
    list.shrinkRetainingCapacity(list.items.len - len);
}

fn replaceOnce(allocator: std.mem.Allocator, slot: *?[]u8, value: []const u8) SessionError!void {
    if (slot.* != null) return error.DuplicatePseudoHeader;
    slot.* = try allocator.dupe(u8, value);
}

pub const ResponseEncoder = struct {
    pub fn encodeHeaders(status: u16, headers: []const stream_transport.Header, out: []u8) SessionError![]u8 {
        var fields_buf: [128]qpack.HeaderField = undefined;
        if (headers.len + 1 > fields_buf.len) return error.OutputOverflow;
        var status_buf: [3]u8 = undefined;
        const status_text = try formatStatus(status, &status_buf);
        fields_buf[0] = .{ .name = ":status", .value = status_text };
        for (headers, 0..) |header, i| {
            fields_buf[i + 1] = .{ .name = header.name, .value = header.value };
        }

        var qpack_buf: [4096]u8 = undefined;
        const block = qpack.encode(fields_buf[0 .. headers.len + 1], &qpack_buf) catch return error.OutputOverflow;
        return frame.encodeKnownFrame(.headers, block, out) catch return error.OutputOverflow;
    }

    pub fn encodeData(chunk: []const u8, out: []u8) SessionError![]u8 {
        return frame.encodeKnownFrame(.data, chunk, out) catch return error.OutputOverflow;
    }

    pub fn encodeGoaway(stream_id: u64, out: []u8) SessionError![]u8 {
        var payload: [8]u8 = undefined;
        const len = varint.encode(stream_id, &payload) catch return error.OutputOverflow;
        return frame.encodeKnownFrame(.goaway, payload[0..len], out) catch return error.OutputOverflow;
    }
};

fn formatStatus(status: u16, buf: *[3]u8) SessionError![]const u8 {
    if (status < 100 or status > 999) return error.InvalidStatus;
    _ = std.fmt.bufPrint(buf, "{d}", .{status}) catch return error.InvalidStatus;
    return buf[0..3];
}

fn mapFrameDecodeError(err: frame.DecodeError) SessionError {
    return switch (err) {
        error.BufferTooShort => error.BufferTooShort,
        error.FrameLengthOverflow => error.FrameLengthOverflow,
        error.FrameTooLarge => error.FrameTooLarge,
        else => error.InvalidRequestFrame,
    };
}

const testing = std.testing;

const ParsedFrameRecorder = struct {
    frames: std.ArrayList(frame.RawFrame) = .empty,

    fn deinit(self: *ParsedFrameRecorder, allocator: std.mem.Allocator) void {
        self.frames.deinit(allocator);
    }

    fn observer(self: *ParsedFrameRecorder) RequestStream.FrameObserver {
        return .{ .context = self, .parsedFn = parsed };
    }

    fn parsed(ctx: ?*anyopaque, raw: frame.RawFrame) void {
        const self: *ParsedFrameRecorder = @ptrCast(@alignCast(ctx.?));
        self.frames.append(testing.allocator, raw) catch unreachable;
    }
};

test "request stream maps HEADERS and DATA onto stream_transport Exchange" {
    const allocator = testing.allocator;
    var qpack_buf: [512]u8 = undefined;
    const block = try qpack.encode(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/api/messages" },
        .{ .name = "content-type", .value = "application/json" },
    }, &qpack_buf);

    var wire: [1024]u8 = undefined;
    var pos: usize = 0;
    pos += (try frame.encodeKnownFrame(.headers, block, wire[pos..])).len;
    pos += (try frame.encodeKnownFrame(.data, "{\"ok\":true}", wire[pos..])).len;

    var req = RequestStream.init(allocator, 0);
    defer req.deinit();
    var scratch: [512]u8 = undefined;
    try testing.expectEqual(pos, try req.ingestBytes(wire[0..pos], &scratch));
    const exchange = try req.finish();

    try testing.expectEqual(stream_transport.Protocol.h3, protocol);
    try testing.expectEqualStrings("POST", exchange.request.method);
    try testing.expectEqualStrings("https", exchange.request.scheme);
    try testing.expectEqualStrings("example.com", exchange.request.authority);
    try testing.expectEqualStrings("/api/messages", exchange.request.path);
    try testing.expectEqualStrings("content-type", exchange.request.headers[0].name);
    try testing.expectEqualStrings("application/json", exchange.request.headers[0].value);
    try testing.expectEqualStrings("{\"ok\":true}", exchange.body.buffered);
}

test "request stream parses RFC 9218 priority header as a scheduling hint" {
    const allocator = testing.allocator;
    var qpack_buf: [512]u8 = undefined;
    const block = try qpack.encode(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "priority", .value = "u=1, i" },
    }, &qpack_buf);

    var req = RequestStream.init(allocator, 0);
    defer req.deinit();
    var scratch: [512]u8 = undefined;
    try req.ingestFrame(.{ .typ = .headers, .type_value = 1, .payload = block, .len = block.len + 2 }, &scratch);
    const exchange = try req.finish();

    try testing.expectEqual(priority.Priority{ .urgency = 1, .incremental = true }, req.priority);
    try testing.expectEqualStrings("priority", exchange.request.headers[0].name);
    try testing.expectEqualStrings("u=1, i", exchange.request.headers[0].value);
}

test "request stream combines multiple priority field lines before parsing" {
    const allocator = testing.allocator;
    var qpack_buf: [512]u8 = undefined;
    const block = try qpack.encode(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "priority", .value = "u=1" },
        .{ .name = "priority", .value = "i" },
    }, &qpack_buf);

    var req = RequestStream.init(allocator, 0);
    defer req.deinit();
    var scratch: [512]u8 = undefined;
    try req.ingestFrame(.{ .typ = .headers, .type_value = 1, .payload = block, .len = block.len + 2 }, &scratch);
    const exchange = try req.finish();

    try testing.expectEqual(priority.Priority{ .urgency = 1, .incremental = true }, req.priority);
    try testing.expectEqual(@as(usize, 2), exchange.request.headers.len);
    try testing.expectEqualStrings("u=1", exchange.request.headers[0].value);
    try testing.expectEqualStrings("i", exchange.request.headers[1].value);
}

test "request stream treats malformed combined priority field as default" {
    var qpack_buf: [512]u8 = undefined;
    const block = try qpack.encode(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "priority", .value = "u=1" },
        .{ .name = "priority", .value = "=bad" },
    }, &qpack_buf);

    var req = RequestStream.init(testing.allocator, 0);
    defer req.deinit();
    var scratch: [512]u8 = undefined;
    try req.ingestFrame(.{ .typ = .headers, .type_value = 1, .payload = block, .len = block.len + 2 }, &scratch);
    try testing.expectEqual(priority.Priority.default, req.priority);
    try testing.expect(req.priority_parse_error);
}

test "request stream combines empty priority field lines by presence" {
    var qpack_buf: [512]u8 = undefined;
    var scratch: [512]u8 = undefined;

    const empty_first = try qpack.encode(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "priority", .value = "" },
        .{ .name = "priority", .value = "u=1" },
    }, &qpack_buf);
    var req_empty_first = RequestStream.init(testing.allocator, 0);
    defer req_empty_first.deinit();
    try req_empty_first.ingestFrame(.{ .typ = .headers, .type_value = 1, .payload = empty_first, .len = empty_first.len + 2 }, &scratch);
    try testing.expectEqual(priority.Priority.default, req_empty_first.priority);
    try testing.expect(req_empty_first.priority_parse_error);

    const empty_last = try qpack.encode(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "priority", .value = "u=1" },
        .{ .name = "priority", .value = "" },
    }, &qpack_buf);
    var req_empty_last = RequestStream.init(testing.allocator, 4);
    defer req_empty_last.deinit();
    try req_empty_last.ingestFrame(.{ .typ = .headers, .type_value = 1, .payload = empty_last, .len = empty_last.len + 2 }, &scratch);
    try testing.expectEqual(priority.Priority.default, req_empty_last.priority);
    try testing.expect(req_empty_last.priority_parse_error);
}

test "request stream ignores malformed priority header and records parse quality" {
    var qpack_buf: [512]u8 = undefined;
    const malformed = try qpack.encode(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "priority", .value = "=bad" },
    }, &qpack_buf);

    var req = RequestStream.init(testing.allocator, 0);
    defer req.deinit();
    var scratch: [512]u8 = undefined;
    try req.ingestFrame(.{ .typ = .headers, .type_value = 1, .payload = malformed, .len = malformed.len + 2 }, &scratch);
    const exchange = try req.finish();
    try testing.expectEqual(priority.Priority.default, req.priority);
    try testing.expect(req.priority_parse_error);
    try testing.expectEqualStrings("priority", exchange.request.headers[0].name);
    try testing.expectEqualStrings("=bad", exchange.request.headers[0].value);

    const invalid = try qpack.encode(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "priority", .value = "u=8, i=5" },
    }, &qpack_buf);

    var req_invalid = RequestStream.init(testing.allocator, 4);
    defer req_invalid.deinit();
    try req_invalid.ingestFrame(.{ .typ = .headers, .type_value = 1, .payload = invalid, .len = invalid.len + 2 }, &scratch);
    try testing.expectEqual(priority.Priority.default, req_invalid.priority);
    try testing.expect(req_invalid.priority_invalid_parameter);
}

test "request stream ingests split frame type length and payload incrementally" {
    const allocator = testing.allocator;
    var qpack_buf: [512]u8 = undefined;
    const block = try qpack.encode(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
    }, &qpack_buf);

    var wire: [1024]u8 = undefined;
    const headers = try frame.encodeKnownFrame(.headers, block, &wire);

    var req = RequestStream.init(allocator, 0);
    defer req.deinit();
    var scratch: [512]u8 = undefined;

    try testing.expectEqual(@as(usize, 1), try req.ingestBytes(headers[0..1], &scratch));
    try testing.expect(!req.saw_headers);
    try testing.expectEqual(@as(usize, 1), try req.ingestBytes(headers[1..2], &scratch));
    try testing.expect(!req.saw_headers);
    try testing.expectEqual(headers.len - 3, try req.ingestBytes(headers[2 .. headers.len - 1], &scratch));
    try testing.expect(!req.saw_headers);
    try testing.expectEqual(@as(usize, 1), try req.ingestBytes(headers[headers.len - 1 ..], &scratch));
    try testing.expect(req.saw_headers);

    const exchange = try req.finish();
    try testing.expectEqualStrings("GET", exchange.request.method);
}

test "request stream frame observer reports every decoded frame with exact wire length" {
    const allocator = testing.allocator;
    var qpack_buf: [512]u8 = undefined;
    const block = try qpack.encode(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
    }, &qpack_buf);

    var wire: [1024]u8 = undefined;
    var pos: usize = 0;
    const headers = try frame.encodeKnownFrame(.headers, block, wire[pos..]);
    pos += headers.len;
    const data_a = try frame.encodeKnownFrame(.data, "abc", wire[pos..]);
    pos += data_a.len;
    const data_b = try frame.encodeKnownFrame(.data, "defg", wire[pos..]);
    pos += data_b.len;

    var req = RequestStream.init(allocator, 0);
    defer req.deinit();
    var recorder = ParsedFrameRecorder{};
    defer recorder.deinit(allocator);
    var scratch: [512]u8 = undefined;

    try testing.expectEqual(pos - 1, try req.ingestBytesWithObserver(wire[0 .. pos - 1], &scratch, recorder.observer()));
    try testing.expectEqual(@as(usize, 2), recorder.frames.items.len);
    try testing.expectEqual(@as(usize, 1), try req.ingestBytesWithObserver(wire[pos - 1 .. pos], &scratch, recorder.observer()));
    try testing.expectEqual(@as(usize, 3), recorder.frames.items.len);
    try testing.expectEqual(frame.FrameType.headers, recorder.frames.items[0].typ);
    try testing.expectEqual(headers.len, recorder.frames.items[0].len);
    try testing.expectEqual(frame.FrameType.data, recorder.frames.items[1].typ);
    try testing.expectEqual(data_a.len, recorder.frames.items[1].len);
    try testing.expectEqual(frame.FrameType.data, recorder.frames.items[2].typ);
    try testing.expectEqual(data_b.len, recorder.frames.items[2].len);
}

test "request stream frame observer reports DATA before semantic rejection" {
    var wire: [64]u8 = undefined;
    const data = try frame.encodeKnownFrame(.data, "x", &wire);

    var req = RequestStream.init(testing.allocator, 0);
    defer req.deinit();
    var recorder = ParsedFrameRecorder{};
    defer recorder.deinit(testing.allocator);
    var scratch: [128]u8 = undefined;

    try testing.expectError(error.InvalidRequestFrame, req.ingestBytesWithObserver(data, &scratch, recorder.observer()));
    try testing.expectEqual(@as(usize, 1), recorder.frames.items.len);
    try testing.expectEqual(frame.FrameType.data, recorder.frames.items[0].typ);
    try testing.expectEqual(data.len, recorder.frames.items[0].len);
}

test "request stream rejects DATA before HEADERS and trailers for the MVP" {
    var req = RequestStream.init(testing.allocator, 0);
    defer req.deinit();
    var scratch: [128]u8 = undefined;
    try testing.expectError(error.InvalidRequestFrame, req.ingestFrame(.{ .typ = .data, .type_value = 0, .payload = "x", .len = 2 }, &scratch));

    var qpack_buf: [256]u8 = undefined;
    const block = try qpack.encode(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
    }, &qpack_buf);
    try req.ingestFrame(.{ .typ = .headers, .type_value = 1, .payload = block, .len = block.len + 2 }, &scratch);
    try req.ingestFrame(.{ .typ = .data, .type_value = 0, .payload = "body", .len = 6 }, &scratch);
    try testing.expectError(error.HeadersAfterDataUnsupported, req.ingestFrame(.{ .typ = .headers, .type_value = 1, .payload = block, .len = block.len + 2 }, &scratch));
}

test "request stream rejects duplicate initial HEADERS before DATA" {
    var req = RequestStream.init(testing.allocator, 0);
    defer req.deinit();

    var qpack_buf: [256]u8 = undefined;
    var regular_buf: [128]u8 = undefined;
    const block = try qpack.encode(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
    }, &qpack_buf);
    const regular = try qpack.encode(&.{.{ .name = "accept", .value = "*/*" }}, &regular_buf);
    var scratch: [256]u8 = undefined;

    try req.ingestFrame(.{ .typ = .headers, .type_value = 1, .payload = block, .len = block.len + 2 }, &scratch);
    try testing.expectError(error.DuplicateHeaders, req.ingestFrame(.{ .typ = .headers, .type_value = 1, .payload = regular, .len = regular.len + 2 }, &scratch));
}

test "request stream finish fails without complete initial HEADERS" {
    var req = RequestStream.init(testing.allocator, 0);
    defer req.deinit();

    try testing.expectError(error.MissingRequiredPseudoHeader, req.finish());
}

test "request stream validates pseudo headers" {
    var req = RequestStream.init(testing.allocator, 0);
    defer req.deinit();

    var qpack_buf: [256]u8 = undefined;
    const duplicate_method = try qpack.encode(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
    }, &qpack_buf);
    var scratch: [256]u8 = undefined;
    try testing.expectError(error.DuplicatePseudoHeader, req.ingestFrame(.{ .typ = .headers, .type_value = 1, .payload = duplicate_method, .len = duplicate_method.len + 2 }, &scratch));
}

test "request stream rejects authority and authentication ambiguity" {
    var qpack_buf: [1024]u8 = undefined;
    var scratch: [1024]u8 = undefined;

    {
        var req = RequestStream.init(testing.allocator, 0);
        defer req.deinit();
        const conflicting_host = try qpack.encode(&.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "trusted.test" },
            .{ .name = ":path", .value = "/private" },
            .{ .name = "host", .value = "attacker.test" },
        }, &qpack_buf);
        try testing.expectError(error.InvalidHeader, req.ingestFrame(.{ .typ = .headers, .type_value = 1, .payload = conflicting_host, .len = conflicting_host.len + 2 }, &scratch));
    }

    {
        var req = RequestStream.init(testing.allocator, 4);
        defer req.deinit();
        const duplicate_auth = try qpack.encode(&.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "trusted.test" },
            .{ .name = ":path", .value = "/private" },
            .{ .name = "authorization", .value = "Bearer first" },
            .{ .name = "authorization", .value = "Bearer second" },
        }, &qpack_buf);
        try testing.expectError(error.InvalidHeader, req.ingestFrame(.{ .typ = .headers, .type_value = 1, .payload = duplicate_auth, .len = duplicate_auth.len + 2 }, &scratch));
    }
}

test "request stream enforces body and content-length while ingesting" {
    var req = RequestStream.initWithBodyLimit(testing.allocator, 0, 2);
    defer req.deinit();
    var qpack_buf: [512]u8 = undefined;
    const block = try qpack.encode(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = ":path", .value = "/upload" },
        .{ .name = "content-length", .value = "1" },
    }, &qpack_buf);
    var scratch: [512]u8 = undefined;
    try req.ingestFrame(.{ .typ = .headers, .type_value = 1, .payload = block, .len = block.len + 2 }, &scratch);
    try req.ingestFrame(.{ .typ = .data, .type_value = 0, .payload = "ab", .len = 4 }, &scratch);
    try testing.expectError(error.InvalidContentLength, req.finish());
    try testing.expectError(error.BodyTooLarge, req.ingestFrame(.{ .typ = .data, .type_value = 0, .payload = "c", .len = 3 }, &scratch));
}

test "request stream rejects uppercase and connection-specific fields" {
    var qpack_buf: [1024]u8 = undefined;
    var scratch: [1024]u8 = undefined;
    const base = [_]qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "X-Upper", .value = "bad" },
    };
    const block = try qpack.encode(&base, &qpack_buf);
    var req = RequestStream.init(testing.allocator, 0);
    defer req.deinit();
    try testing.expectError(error.InvalidHeader, req.ingestFrame(.{ .typ = .headers, .type_value = 1, .payload = block, .len = block.len + 2 }, &scratch));
}

test "request stream rejects unsafe pseudo-header syntax before dispatch" {
    var qpack_buf: [1024]u8 = undefined;
    var scratch: [1024]u8 = undefined;
    const block = try qpack.encode(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "user@example.test" },
        .{ .name = ":path", .value = "/private\tspoof" },
    }, &qpack_buf);
    var req = RequestStream.init(testing.allocator, 0);
    defer req.deinit();
    try req.ingestFrame(.{ .typ = .headers, .type_value = 1, .payload = block, .len = block.len + 2 }, &scratch);
    try testing.expectError(error.InvalidHeader, req.finish());
}

test "request stream maps static-only QPACK dynamic references to protocol error" {
    var req = RequestStream.init(testing.allocator, 0);
    defer req.deinit();
    var scratch: [256]u8 = undefined;

    try testing.expectError(error.QpackDecodeFailed, req.ingestFrame(.{ .typ = .headers, .type_value = 1, .payload = &.{ 0x00, 0x00, 0x80 }, .len = 5 }, &scratch));
}

test "request stream rejects oversized frame payload lengths before buffering payload" {
    var req = RequestStream.init(testing.allocator, 0);
    defer req.deinit();

    var wire: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(@intFromEnum(frame.FrameType.data), wire[pos..]);
    pos += try varint.encode(RequestStream.max_frame_payload_len + 1, wire[pos..]);

    var scratch: [16]u8 = undefined;
    try testing.expectError(error.FrameTooLarge, req.ingestBytes(wire[0..pos], &scratch));
}

test "response encoder emits HEADERS DATA and GOAWAY frames" {
    var out: [4096]u8 = undefined;
    const headers = try ResponseEncoder.encodeHeaders(200, &.{.{ .name = "content-type", .value = "text/plain" }}, &out);
    const headers_frame = try frame.decodeFrame(headers);
    try testing.expectEqual(frame.FrameType.headers, headers_frame.typ);

    var decoded_fields: [8]qpack.HeaderField = undefined;
    var scratch: [256]u8 = undefined;
    const count = try qpack.decode(headers_frame.payload, &decoded_fields, &scratch);
    try testing.expectEqual(@as(usize, 2), count);
    try testing.expectEqualStrings(":status", decoded_fields[0].name);
    try testing.expectEqualStrings("200", decoded_fields[0].value);

    const data = try ResponseEncoder.encodeData("chunk", &out);
    const data_frame = try frame.decodeFrame(data);
    try testing.expectEqual(frame.FrameType.data, data_frame.typ);
    try testing.expectEqualStrings("chunk", data_frame.payload);

    const goaway = try ResponseEncoder.encodeGoaway(16, &out);
    const goaway_frame = try frame.decodeFrame(goaway);
    try testing.expectEqual(frame.FrameType.goaway, goaway_frame.typ);
}

test {
    std.testing.refAllDecls(@This());
}
