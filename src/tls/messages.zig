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
    IncompleteHandshake,
};

pub const ReadError = error{MalformedHandshake};
pub const WriteError = error{HandshakeBufferOverflow};

pub const ReassemblerError = error{
    MalformedHandshake,
    HandshakeBufferOverflow,
    MessageTooLarge,
    DuplicateExtension,
    TooManyExtensions,
    IncompleteHandshake,
};

pub const MessageType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
    message_hash = 254,
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

pub fn frameLength(bytes: []const u8) ReassemblerError!?usize {
    if (bytes.len < 4) return null;
    const body_len: usize = @intCast(std.mem.readInt(u24, bytes[1..4], .big));
    if (body_len > max_message_len) return error.MessageTooLarge;
    const length = 4 + body_len;
    if (length > bytes.len) return null;
    return length;
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

    pub fn u8_(self: *Reader) ReadError!u8 {
        if (self.remaining() < 1) return error.MalformedHandshake;
        defer self.offset += 1;
        return self.bytes[self.offset];
    }

    pub fn u16_(self: *Reader) ReadError!u16 {
        if (self.remaining() < 2) return error.MalformedHandshake;
        defer self.offset += 2;
        return std.mem.readInt(u16, self.bytes[self.offset..][0..2], .big);
    }

    pub fn u24_(self: *Reader) ReadError!u24 {
        if (self.remaining() < 3) return error.MalformedHandshake;
        defer self.offset += 3;
        return std.mem.readInt(u24, self.bytes[self.offset..][0..3], .big);
    }

    pub fn slice(self: *Reader, len: usize) ReadError![]const u8 {
        if (self.remaining() < len) return error.MalformedHandshake;
        defer self.offset += len;
        return self.bytes[self.offset..][0..len];
    }

    pub fn expectEnd(self: *const Reader) ReadError!void {
        if (self.remaining() != 0) return error.MalformedHandshake;
    }
};

pub const Writer = struct {
    buf: []u8,
    len: usize = 0,

    pub fn u8_(self: *Writer, value: u8) WriteError!void {
        try self.bytes(&[_]u8{value});
    }

    pub fn u16_(self: *Writer, value: u16) WriteError!void {
        var encoded: [2]u8 = undefined;
        std.mem.writeInt(u16, &encoded, value, .big);
        try self.bytes(&encoded);
    }

    pub fn bytes(self: *Writer, data: []const u8) WriteError!void {
        if (data.len > self.buf.len - self.len) return error.HandshakeBufferOverflow;
        @memcpy(self.buf[self.len..][0..data.len], data);
        self.len += data.len;
    }

    pub fn reserve(self: *Writer, comptime width: usize) WriteError!usize {
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

        pub fn append(self: *Self, bytes: []const u8) ReassemblerError!void {
            if (bytes.len > self.data.len - self.len) return error.HandshakeBufferOverflow;
            @memcpy(self.data[self.len..][0..bytes.len], bytes);
            self.len += bytes.len;
        }

        pub fn peek(self: *Self) ReassemblerError!?HandshakeMessage {
            const message_len = (try frameLength(self.data[0..self.len])) orelse return null;
            if (message_len > self.data.len) return error.HandshakeBufferOverflow;
            if (self.len < message_len) return null;
            return try decode(self.data[0..message_len]);
        }

        pub fn discard(self: *Self, count: usize) ReassemblerError!void {
            if (count > self.len) return error.MalformedHandshake;
            const old_len = self.len;
            std.mem.copyForwards(u8, self.data[0 .. old_len - count], self.data[count..old_len]);
            self.len = old_len - count;
            // Canonical helper, not `std.crypto.secureZero`: since #675 the two
            // are no longer the same primitive, and these are handshake bytes.
            @import("crypto").secrets.secureZero(self.data[self.len..old_len]);
        }
    };
}

const testing = std.testing;

test "reassembler discard clears consumed tail bytes" {
    var r = Reassembler(32){};
    const first = [_]u8{ @intFromEnum(MessageType.finished), 0, 0, 4, 0xaa, 0xbb, 0xcc, 0xdd };
    const second = [_]u8{ @intFromEnum(MessageType.finished), 0, 0, 1, 0xee };
    try r.append(&first);
    try r.append(&second);
    try r.discard(first.len);
    try testing.expectEqualSlices(u8, &second, r.data[0..r.len]);
    try testing.expect(std.mem.allEqual(u8, r.data[r.len .. first.len + second.len], 0));
}

test "encode and decode exact handshake bytes" {
    var out: [16]u8 = undefined;
    const raw = try encode(.finished, &.{ 1, 2, 3 }, &out);
    try testing.expectEqualSlices(u8, &.{ 20, 0, 0, 3, 1, 2, 3 }, raw);
    const msg = try decode(raw);
    try testing.expectEqual(MessageType.finished, msg.kind);
    try testing.expectEqualSlices(u8, raw, msg.raw);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, msg.body);
}

test "decode accepts TLS 1.3 handshake types used outside the common flight" {
    const message_hash = [_]u8{ 254, 0, 0, 32 } ++ ([_]u8{0} ** 32);
    const cases = [_]struct {
        raw: []const u8,
        kind: MessageType,
    }{
        .{ .raw = &.{ 5, 0, 0, 0 }, .kind = .end_of_early_data },
        .{ .raw = &.{ 13, 0, 0, 0 }, .kind = .certificate_request },
        .{ .raw = &.{ 24, 0, 0, 0 }, .kind = .key_update },
        .{ .raw = &message_hash, .kind = .message_hash },
    };

    for (cases) |case| {
        const msg = try decode(case.raw);
        try testing.expectEqual(case.kind, msg.kind);
        try testing.expectEqualSlices(u8, case.raw, msg.raw);
    }
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

test "fuzz: TLS protocol: handshake framing extensions and reassembly preserve bounded cursor invariants" {
    try testing.fuzz({}, fuzzHandshakeCodecAndReassembly, .{ .corpus = &.{
        "",
        &[_]u8{ @intFromEnum(MessageType.client_hello), 0, 0, 0 },
        &[_]u8{ @intFromEnum(MessageType.finished), 0, 0, 1, 0xaa },
        &[_]u8{ 0xff, 0, 0, 0 },
        &[_]u8{ @intFromEnum(MessageType.client_hello), 0, 0, 0, @intFromEnum(MessageType.finished), 0, 0, 0 },
        &[_]u8{ @intFromEnum(MessageType.finished), 0, 0xff, 0xff, 0xff },
        &([_]u8{0xaa} ** 64),
        &([_]u8{0xbb} ** 65),
        &[_]u8{ 0, 43, 0, 2, 3, 4, 0, 43, 0, 2, 3, 4 },
        &([_]u8{0xff} ** 128),
    } });
}

fn fuzzHandshakeCodecAndReassembly(_: void, smith: *testing.Smith) !void {
    var raw_buf: [256]u8 = undefined;
    const raw_len = smith.index(raw_buf.len + 1);
    smith.bytes(raw_buf[0..raw_len]);
    const raw = raw_buf[0..raw_len];

    if (decode(raw)) |message| {
        try testing.expectEqual(raw.len, message.raw.len);
        try testing.expectEqual(raw.len - 4, message.body.len);
        try testing.expectEqual(raw.ptr, message.raw.ptr);
        try testing.expectEqual(raw[4..].ptr, message.body.ptr);
    } else |err| switch (err) {
        error.MalformedHandshake, error.MessageTooLarge, error.DuplicateExtension, error.TooManyExtensions, error.HandshakeBufferOverflow, error.IncompleteHandshake => {},
    }

    var extensions = ExtensionIterator.init(raw);
    var seen: [ExtensionGuard.max_extensions]u16 = undefined;
    var seen_len: usize = 0;
    while (extensions.next()) |maybe_extension| {
        const extension = maybe_extension orelse break;
        for (seen[0..seen_len]) |id| try testing.expect(id != extension.id);
        try testing.expect(@intFromPtr(extension.data.ptr) >= @intFromPtr(raw.ptr));
        try testing.expect(@intFromPtr(extension.data.ptr) + extension.data.len <= @intFromPtr(raw.ptr) + raw.len);
        seen[seen_len] = extension.id;
        seen_len += 1;
    } else |err| switch (err) {
        error.MalformedHandshake, error.DuplicateExtension, error.TooManyExtensions, error.HandshakeBufferOverflow, error.MessageTooLarge, error.IncompleteHandshake => {},
    }

    var encoded_storage: [256]u8 = undefined;
    var body_storage: [128]u8 = undefined;
    const body_len = smith.index(body_storage.len + 1);
    smith.bytes(body_storage[0..body_len]);
    const kinds = [_]MessageType{ .client_hello, .server_hello, .encrypted_extensions, .certificate, .finished, .message_hash };
    const encoded = try encode(kinds[smith.index(kinds.len)], body_storage[0..body_len], &encoded_storage);
    const decoded = try decode(encoded);
    try testing.expectEqualSlices(u8, encoded, decoded.raw);
    try testing.expectEqualSlices(u8, body_storage[0..body_len], decoded.body);

    var reassembler = Reassembler(512){};
    var cursor: usize = 0;
    while (cursor < encoded.len) {
        const remaining = encoded.len - cursor;
        const chunk_len = 1 + smith.index(remaining);
        try reassembler.append(encoded[cursor..][0..chunk_len]);
        cursor += chunk_len;
        if (cursor < encoded.len) {
            try testing.expect((try reassembler.peek()) == null);
        }
    }
    const reassembled = (try reassembler.peek()).?;
    try testing.expectEqualSlices(u8, encoded, reassembled.raw);
    try reassembler.discard(reassembled.raw.len);
    try testing.expectEqual(@as(usize, 0), reassembler.len);

    var second_encoded_storage: [256]u8 = undefined;
    var second_body_storage: [128]u8 = undefined;
    const second_body_len = smith.index(second_body_storage.len + 1);
    smith.bytes(second_body_storage[0..second_body_len]);
    const second_encoded = try encode(kinds[smith.index(kinds.len)], second_body_storage[0..second_body_len], &second_encoded_storage);

    var coalesced_storage: [512]u8 = undefined;
    @memcpy(coalesced_storage[0..encoded.len], encoded);
    @memcpy(coalesced_storage[encoded.len..][0..second_encoded.len], second_encoded);
    const coalesced = coalesced_storage[0 .. encoded.len + second_encoded.len];
    var coalesced_reassembler = Reassembler(512){};
    var coalesced_cursor: usize = 0;
    while (coalesced_cursor < coalesced.len) {
        const remaining = coalesced.len - coalesced_cursor;
        const chunk_len = 1 + smith.index(remaining);
        try coalesced_reassembler.append(coalesced[coalesced_cursor..][0..chunk_len]);
        coalesced_cursor += chunk_len;
    }
    for ([_][]const u8{ encoded, second_encoded }) |frame| {
        const message = (try coalesced_reassembler.peek()).?;
        try testing.expectEqualSlices(u8, frame, message.raw);
        try coalesced_reassembler.discard(message.raw.len);
    }
    try testing.expectEqual(@as(usize, 0), coalesced_reassembler.len);

    var raw_reassembler = Reassembler(64){};
    const raw_before_len = raw_reassembler.len;
    const append_result = raw_reassembler.append(raw);
    if (append_result) |_| {
        try testing.expectEqual(raw.len, raw_reassembler.len);
        const peek_result = raw_reassembler.peek();
        if (peek_result) |maybe_message| {
            if (maybe_message) |message| {
                try testing.expect(message.raw.len <= raw_reassembler.len);
                try testing.expectEqualSlices(u8, raw_reassembler.data[0..message.raw.len], message.raw);
                const bad_discard = raw_reassembler.len + 1 + smith.index(8);
                const before_bad_discard = raw_reassembler.len;
                try testing.expectError(error.MalformedHandshake, raw_reassembler.discard(bad_discard));
                try testing.expectEqual(before_bad_discard, raw_reassembler.len);
                try raw_reassembler.discard(message.raw.len);
                try testing.expectEqual(raw.len - message.raw.len, raw_reassembler.len);
            }
        } else |err| switch (err) {
            error.MalformedHandshake, error.MessageTooLarge, error.HandshakeBufferOverflow, error.DuplicateExtension, error.TooManyExtensions, error.IncompleteHandshake => {},
        }
    } else |err| switch (err) {
        error.HandshakeBufferOverflow => try testing.expectEqual(raw_before_len, raw_reassembler.len),
        error.MalformedHandshake, error.MessageTooLarge, error.DuplicateExtension, error.TooManyExtensions, error.IncompleteHandshake => {},
    }
}
