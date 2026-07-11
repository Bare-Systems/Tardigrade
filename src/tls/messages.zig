//! Bounded TLS 1.3 handshake message codec.
//!
//! This module owns only TLS handshake framing and small wire helpers. It does
//! not know about QUIC CRYPTO frames, TLS records, sockets, HTTP, or certificate
//! policy. Callers feed complete or fragmented handshake bytes from their
//! transport and update the transcript with `HandshakeMessage.raw`.

const std = @import("std");

pub const max_message_len = 16 * 1024 * 1024 - 1;

pub const Error = error{
    MalformedHandshake,
    HandshakeBufferOverflow,
    MessageTooLarge,
    DuplicateExtension,
    TooManyExtensions,
};

pub const MessageType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_verify = 15,
    finished = 20,
};

pub const HandshakeMessage = struct {
    kind: MessageType,
    /// Exact handshake bytes: type + u24 length + body.
    raw: []const u8,
    body: []const u8,
};

pub fn decode(raw: []const u8) Error!HandshakeMessage {
    if (raw.len < 4) return error.MalformedHandshake;
    const body_len: usize = @intCast(std.mem.readInt(u24, raw[1..4], .big));
    if (body_len > max_message_len) return error.MessageTooLarge;
    if (raw.len != 4 + body_len) return error.MalformedHandshake;
    return .{
        .kind = std.enums.fromInt(MessageType, raw[0]) orelse return error.MalformedHandshake,
        .raw = raw,
        .body = raw[4..],
    };
}

pub fn encode(kind: MessageType, body: []const u8, out: []u8) Error![]const u8 {
    if (body.len > max_message_len) return error.MessageTooLarge;
    if (out.len < 4 + body.len) return error.HandshakeBufferOverflow;
    out[0] = @intFromEnum(kind);
    writeU24(out[1..4], @intCast(body.len));
    @memcpy(out[4..][0..body.len], body);
    return out[0 .. 4 + body.len];
}

fn writeU24(out: []u8, value: u24) void {
    std.debug.assert(out.len == 3);
    std.mem.writeInt(u24, out[0..3], value, .big);
}

pub const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,

    pub fn remaining(self: *const Reader) usize {
        return self.bytes.len - self.offset;
    }

    pub fn u8_(self: *Reader) Error!u8 {
        if (self.remaining() < 1) return error.MalformedHandshake;
        defer self.offset += 1;
        return self.bytes[self.offset];
    }

    pub fn u16_(self: *Reader) Error!u16 {
        if (self.remaining() < 2) return error.MalformedHandshake;
        defer self.offset += 2;
        return std.mem.readInt(u16, self.bytes[self.offset..][0..2], .big);
    }

    pub fn u24_(self: *Reader) Error!u24 {
        if (self.remaining() < 3) return error.MalformedHandshake;
        defer self.offset += 3;
        return std.mem.readInt(u24, self.bytes[self.offset..][0..3], .big);
    }

    pub fn slice(self: *Reader, len: usize) Error![]const u8 {
        if (self.remaining() < len) return error.MalformedHandshake;
        defer self.offset += len;
        return self.bytes[self.offset..][0..len];
    }

    pub fn expectEnd(self: *const Reader) Error!void {
        if (self.remaining() != 0) return error.MalformedHandshake;
    }
};

pub const Writer = struct {
    buf: []u8,
    len: usize = 0,

    pub fn u8_(self: *Writer, value: u8) Error!void {
        try self.bytes(&[_]u8{value});
    }

    pub fn u16_(self: *Writer, value: u16) Error!void {
        var encoded: [2]u8 = undefined;
        std.mem.writeInt(u16, &encoded, value, .big);
        try self.bytes(&encoded);
    }

    pub fn bytes(self: *Writer, data: []const u8) Error!void {
        if (data.len > self.buf.len - self.len) return error.HandshakeBufferOverflow;
        @memcpy(self.buf[self.len..][0..data.len], data);
        self.len += data.len;
    }

    pub fn reserve(self: *Writer, comptime width: usize) Error!usize {
        const index = self.len;
        try self.bytes(&([_]u8{0} ** width));
        return index;
    }

    pub fn patch(self: *Writer, comptime width: usize, index: usize) void {
        const value = self.len - index - width;
        var encoded: [width]u8 = undefined;
        const IntT = std.meta.Int(.unsigned, width * 8);
        std.mem.writeInt(IntT, &encoded, @intCast(value), .big);
        @memcpy(self.buf[index..][0..width], &encoded);
    }

    pub fn written(self: *const Writer) []const u8 {
        return self.buf[0..self.len];
    }
};

pub const Extension = struct {
    id: u16,
    data: []const u8,
};

pub const ExtensionGuard = struct {
    pub const max_extensions = 64;

    ids: [max_extensions]u16 = undefined,
    len: usize = 0,

    pub fn check(self: *ExtensionGuard, ext_id: u16) Error!void {
        for (self.ids[0..self.len]) |seen| {
            if (seen == ext_id) return error.DuplicateExtension;
        }
        if (self.len == self.ids.len) return error.TooManyExtensions;
        self.ids[self.len] = ext_id;
        self.len += 1;
    }
};

pub const ExtensionIterator = struct {
    reader: Reader,
    guard: ExtensionGuard = .{},

    pub fn init(bytes: []const u8) ExtensionIterator {
        return .{ .reader = .{ .bytes = bytes } };
    }

    pub fn next(self: *ExtensionIterator) Error!?Extension {
        if (self.reader.remaining() == 0) return null;
        const id = try self.reader.u16_();
        try self.guard.check(id);
        const data = try self.reader.slice(try self.reader.u16_());
        return .{ .id = id, .data = data };
    }
};

pub fn Reassembler(comptime capacity: usize) type {
    return struct {
        data: [capacity]u8 = undefined,
        len: usize = 0,

        const Self = @This();

        pub fn append(self: *Self, bytes: []const u8) Error!void {
            if (bytes.len > self.data.len - self.len) return error.HandshakeBufferOverflow;
            @memcpy(self.data[self.len..][0..bytes.len], bytes);
            self.len += bytes.len;
        }

        pub fn peek(self: *Self) Error!?HandshakeMessage {
            if (self.len < 4) return null;
            const body_len: usize = @intCast(std.mem.readInt(u24, self.data[1..4], .big));
            if (body_len > max_message_len) return error.MessageTooLarge;
            const message_len = 4 + body_len;
            if (message_len > self.data.len) return error.HandshakeBufferOverflow;
            if (self.len < message_len) return null;
            return try decode(self.data[0..message_len]);
        }

        pub fn discard(self: *Self, count: usize) Error!void {
            if (count > self.len) return error.MalformedHandshake;
            std.mem.copyForwards(u8, self.data[0 .. self.len - count], self.data[count..self.len]);
            self.len -= count;
        }
    };
}

const testing = std.testing;

test "encode and decode exact handshake bytes" {
    var out: [16]u8 = undefined;
    const raw = try encode(.finished, &.{ 1, 2, 3 }, &out);
    try testing.expectEqualSlices(u8, &.{ 20, 0, 0, 3, 1, 2, 3 }, raw);
    const msg = try decode(raw);
    try testing.expectEqual(MessageType.finished, msg.kind);
    try testing.expectEqualSlices(u8, raw, msg.raw);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, msg.body);
}

test "fragmented and coalesced messages reassemble without losing transcript bytes" {
    var buf: [32]u8 = undefined;
    const first = try encode(.client_hello, "hello", &buf);
    var buf2: [32]u8 = undefined;
    const second = try encode(.finished, "done", &buf2);

    var reasm = Reassembler(64){};
    try reasm.append(first[0..2]);
    try testing.expect(try reasm.peek() == null);
    try reasm.append(first[2..]);
    try reasm.append(second);

    const msg1 = (try reasm.peek()).?;
    try testing.expectEqual(MessageType.client_hello, msg1.kind);
    try testing.expectEqualSlices(u8, first, msg1.raw);
    try reasm.discard(msg1.raw.len);

    const msg2 = (try reasm.peek()).?;
    try testing.expectEqual(MessageType.finished, msg2.kind);
    try testing.expectEqualSlices(u8, second, msg2.raw);
    try reasm.discard(msg2.raw.len);
    try testing.expectEqual(@as(usize, 0), reasm.len);
}

test "extension iterator rejects duplicate singleton extensions" {
    const bytes = [_]u8{
        0, 43, 0, 2, 3, 4,
        0, 43, 0, 2, 3, 4,
    };
    var it = ExtensionIterator.init(&bytes);
    const first = (try it.next()).?;
    try testing.expectEqual(@as(u16, 43), first.id);
    try testing.expectError(error.DuplicateExtension, it.next());
}

test "reader and writer enforce bounds" {
    var out: [4]u8 = undefined;
    var w = Writer{ .buf = &out };
    try w.u16_(0x1301);
    try w.u8_(0);
    try testing.expectError(error.HandshakeBufferOverflow, w.u16_(1));

    var r = Reader{ .bytes = w.written() };
    try testing.expectEqual(@as(u16, 0x1301), try r.u16_());
    try testing.expectEqual(@as(u8, 0), try r.u8_());
    try testing.expectError(error.MalformedHandshake, r.u8_());
}
