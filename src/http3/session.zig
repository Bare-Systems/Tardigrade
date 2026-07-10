//! HTTP/3 request/response mapping (#246): turns request stream frames into the
//! shared `stream_transport` shape and emits response HEADERS/DATA frames.
//!
//! This is the minimal pure-Zig HTTP/3 session layer. It uses static-only QPACK
//! from `qpack.zig`, buffers request bodies only inside the per-stream
//! assembler used by unit tests and the future QUIC connection driver, and keeps
//! dynamic QPACK, priority, and downstream listener rollout out of scope.

const std = @import("std");

const frame = @import("frame.zig");
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
    InvalidStatus,
    QpackDecodeFailed,
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

    allocator: std.mem.Allocator,
    stream_id: u64,
    pending: std.ArrayList(u8) = .empty,
    method: ?[]u8 = null,
    scheme: ?[]u8 = null,
    authority: ?[]u8 = null,
    path: ?[]u8 = null,
    headers: std.ArrayList(stream_transport.Header) = .empty,
    body: std.ArrayList(u8) = .empty,
    saw_headers: bool = false,
    saw_data: bool = false,
    finished: bool = false,

    pub fn init(allocator: std.mem.Allocator, stream_id: u64) RequestStream {
        return .{ .allocator = allocator, .stream_id = stream_id };
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

    pub fn ingestBytes(self: *RequestStream, bytes: []const u8, qpack_scratch: []u8) SessionError!usize {
        self.pending.appendSlice(self.allocator, bytes) catch return error.OutOfMemory;
        while (true) {
            const raw = frame.decodeFrameWithLimit(self.pending.items, max_frame_payload_len) catch |err| switch (err) {
                error.BufferTooShort => return bytes.len,
                else => return mapFrameDecodeError(err),
            };
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
                try self.body.appendSlice(self.allocator, raw.payload);
            },
            .goaway => return error.InvalidRequestFrame,
            .settings, .cancel_push, .push_promise, .max_push_id, .priority_update_request, .priority_update_push => return error.InvalidRequestFrame,
            .unknown => {},
        }
    }

    fn ingestHeaders(self: *RequestStream, payload: []const u8, qpack_scratch: []u8) SessionError!void {
        var fields: [128]qpack.HeaderField = undefined;
        const count = qpack.decode(payload, &fields, qpack_scratch) catch return error.QpackDecodeFailed;
        var regular_seen = false;
        for (fields[0..count]) |field| {
            if (field.name.len > 0 and field.name[0] == ':') {
                if (regular_seen) return error.PseudoHeaderAfterRegularHeader;
                try self.applyPseudoHeader(field);
            } else {
                regular_seen = true;
                try self.appendHeader(field.name, field.value);
            }
        }
        self.saw_headers = true;
    }

    fn applyPseudoHeader(self: *RequestStream, field: qpack.HeaderField) SessionError!void {
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
