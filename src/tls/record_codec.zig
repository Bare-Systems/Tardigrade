//! Bounded TLS 1.3 record codec.
//!
//! This module owns only TLS record envelopes and `TLSInnerPlaintext` framing.
//! It never performs socket I/O, AEAD sealing/opening, key selection, or
//! handshake progression. Callers feed arbitrary TCP fragments into `Parser`,
//! consume copied `Record` payloads from a bounded sink, and pass decrypted
//! ciphertext payloads to `decodeInnerPlaintext`.

const std = @import("std");

pub const header_len = 5;
pub const legacy_record_version: u16 = 0x0303;
pub const max_plaintext_fragment_len = 16 * 1024;
pub const max_ciphertext_fragment_len = max_plaintext_fragment_len + 256;
pub const max_ciphertext_record_len = header_len + max_ciphertext_fragment_len;

pub const Error = error{
    InvalidRecordType,
    InvalidRecordVersion,
    RecordTooLarge,
    RecordBufferOverflow,
    RecordSinkOverflow,
    TruncatedRecord,
    MalformedInnerPlaintext,
};

pub const ContentType = enum(u8) {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
};

pub const RecordMode = enum {
    plaintext,
    ciphertext,
};

pub const Record = struct {
    content_type: ContentType,
    legacy_version: u16,
    payload: []const u8,
};

pub const TLSPlaintext = Record;
pub const TLSCiphertext = Record;

pub const InnerPlaintext = struct {
    content_type: ContentType,
    content: []const u8,
    padding_len: usize,
};

pub const TLSInnerPlaintext = InnerPlaintext;

/// Legacy record-version acceptance policy for one header parse.
///
/// RFC 8446 SS5.1: `legacy_record_version` MUST be `0x0303` for every record a
/// TLS 1.3 implementation sends or expects, *except* an initial ClientHello
/// (one not generated after a HelloRetryRequest), which MAY use `0x0301` for
/// middlebox compatibility. `record_codec` never inspects handshake message
/// types, so it cannot itself recognize "this is a ClientHello" — the caller,
/// which knows its own role and which parser instance owns the initial epoch,
/// supplies this policy per parse.
pub const VersionPolicy = enum {
    /// Only `0x0303` is accepted. Used for every record after the first, and
    /// for any parser that never legitimately sees the compatibility version
    /// (a client's view of the server's records, and every ciphertext record).
    strict,
    /// `0x0301` or `0x0303` is accepted. Scoped by the caller to exactly the
    /// first record a server-role initial-epoch parser observes.
    allow_initial_client_hello_compat,
};

const compat_client_hello_version: u16 = 0x0301;
/// RFC 8446 Handshake.msg_type value for client_hello -- the only message
/// the `0x0301` compatibility version may legally accompany.
const client_hello_msg_type: u8 = 1;
/// RFC 8446 Handshake { HandshakeType msg_type; uint24 length; ... }: a
/// 1-byte type tag followed by a 3-byte big-endian length.
const handshake_header_len = 4;

/// Progress of the very first handshake message a server-role initial-epoch
/// parser sees, tracked so the RFC 8446 SS5.1 compatibility window can span
/// however many records it fragments across. This message may fragment at
/// *any* byte boundary -- including inside its own 4-byte `msg_type`+length
/// header, not just inside the body -- and its records are not required to
/// consistently declare `0x0301`: RFC 8446 permits the compatibility
/// version on any record of the initial ClientHello, so one fragment may use
/// `0x0303` while another uses `0x0301`. Tracking therefore starts at the
/// first handshake-content-type record regardless of its declared version,
/// and only the eventual message identity (ClientHello or not) decides
/// whether a `0x0301` claim anywhere in the sequence was legal.
const ClientHelloState = union(enum) {
    /// Not currently inside the initial handshake message.
    idle,
    /// Accumulating the 4-byte handshake header itself; `len` of `buf`'s
    /// bytes are filled so far. `used_compat` records whether any record
    /// contributing to the header so far claimed `0x0301`, so that once the
    /// header completes a non-ClientHello message can be rejected only if
    /// the exception was actually invoked (an ordinary `0x0303` non-
    /// ClientHello first message is none of this layer's business).
    collecting_header: struct { buf: [handshake_header_len]u8, len: usize, used_compat: bool },
    /// Header complete and confirmed to be a ClientHello; this many more
    /// body bytes are owed. Any record from here on may freely use `0x0301`
    /// without re-checking `msg_type` (a raw continuation, not a new
    /// message).
    collecting_body: usize,
};

/// Computes the next `ClientHelloState` for one record without mutating
/// `Parser` -- `sink.push` can still fail after this and leave the record
/// buffered for a later retry, so the caller only commits the result once
/// the record has actually been emitted (see `Parser.drain`/`drainOne`).
///
/// - `.idle`: a fresh record. Only a handshake-content-type record can
///   possibly be starting the initial message; anything else leaves the
///   window closed. This does not require `0x0301` -- the first record of
///   the initial ClientHello may just as legally be `0x0303`.
/// - `.collecting_header`/`.collecting_body`: RFC 8446 SS5.1 forbids other
///   record types from interleaving within a fragmented handshake message,
///   so a continuation must also be handshake-content-type or the whole
///   sequence is rejected (without committing any state, since this
///   returns an error).
///
/// Once the 4-byte header is complete, the declared length decides whether
/// the window closes now (the message fits, with or without trailing bytes
/// belonging to something else) or stays open for a further
/// `.collecting_body` record. If the completed header turns out not to be a
/// ClientHello, that is only an error when some record in the sequence
/// actually claimed `0x0301` for it -- otherwise the window simply closes
/// having never granted anything.
fn nextClientHelloState(current: ClientHelloState, header: RecordHeader, payload: []const u8) Error!ClientHelloState {
    var header_buf: [handshake_header_len]u8 = undefined;
    var header_have: usize = 0;
    var used_compat = header.legacy_version == compat_client_hello_version;

    switch (current) {
        .idle => {
            if (header.content_type != .handshake) return .idle;
        },
        .collecting_header => |progress| {
            if (header.content_type != .handshake) return error.InvalidRecordType;
            header_buf = progress.buf;
            header_have = progress.len;
            used_compat = used_compat or progress.used_compat;
        },
        .collecting_body => |remaining| {
            if (header.content_type != .handshake) return error.InvalidRecordType;
            const left = remaining - @min(payload.len, remaining);
            return if (left == 0) .idle else ClientHelloState{ .collecting_body = left };
        },
    }

    const take = @min(payload.len, handshake_header_len - header_have);
    @memcpy(header_buf[header_have..][0..take], payload[0..take]);
    header_have += take;
    if (header_have < handshake_header_len) {
        return ClientHelloState{ .collecting_header = .{ .buf = header_buf, .len = header_have, .used_compat = used_compat } };
    }

    if (header_buf[0] != client_hello_msg_type) {
        if (used_compat) return error.InvalidRecordVersion;
        return .idle;
    }

    const declared_len = (@as(usize, header_buf[1]) << 16) | (@as(usize, header_buf[2]) << 8) | header_buf[3];
    const payload_after_header = payload.len - take;
    const body_remaining = if (declared_len > payload_after_header) declared_len - payload_after_header else 0;
    return if (body_remaining == 0) .idle else ClientHelloState{ .collecting_body = body_remaining };
}

pub fn RecordSink(comptime max_record_count: usize, comptime max_payload_bytes: usize) type {
    return struct {
        items: [max_record_count]Record = undefined,
        len: usize = 0,
        scratch: [max_payload_bytes]u8 = undefined,
        used: usize = 0,

        const Self = @This();

        pub fn reset(self: *Self) void {
            self.len = 0;
            self.used = 0;
        }

        fn store(self: *Self, payload: []const u8) Error![]const u8 {
            if (payload.len > self.scratch.len - self.used) return error.RecordSinkOverflow;
            const start = self.used;
            @memcpy(self.scratch[start..][0..payload.len], payload);
            self.used += payload.len;
            return self.scratch[start..][0..payload.len];
        }

        pub fn push(self: *Self, record: Record) Error!void {
            if (self.len == self.items.len) return error.RecordSinkOverflow;
            self.items[self.len] = .{
                .content_type = record.content_type,
                .legacy_version = record.legacy_version,
                .payload = try self.store(record.payload),
            };
            self.len += 1;
        }
    };
}

pub const DefaultSink = RecordSink(16, 64 * 1024);

/// Checked `self_len + queued_len`, factored out of
/// `Parser.pendingRecordBytesNeededWith`/`pendingRecordPayloadLenWith` so a
/// synthetic near-`usize`-max length -- impossible to represent with any
/// real allocation, but exactly the "arithmetic/offset overflow-adjacent
/// synthetic limits" #493 requires coverage for -- can be driven directly
/// by a test/fuzzer as a bare scalar, without needing a slice anywhere near
/// that size.
fn checkedOwnedLen(self_len: usize, queued_len: usize) Error!usize {
    return std.math.add(usize, self_len, queued_len) catch error.RecordTooLarge;
}

/// Checked `header_len + payload_len`, split out for the same reason as
/// `checkedOwnedLen`. `payload_len` is wire-bounded to a `u16` in practice
/// (see `parseHeader`), so this can never actually overflow today, but it
/// stays checked rather than relying on that invariant holding forever.
fn checkedRecordLen(payload_len: usize) Error!usize {
    return std.math.add(usize, header_len, payload_len) catch error.RecordTooLarge;
}

pub const Parser = struct {
    mode: RecordMode,
    pending: [max_ciphertext_record_len]u8 = undefined,
    len: usize = 0,
    /// Policy applied only to the very first record this parser instance
    /// successfully consumes; every subsequent record is `.strict` regardless
    /// of this setting. See `VersionPolicy`.
    first_record_version_policy: VersionPolicy = .strict,
    parsed_first_record: bool = false,
    /// Progress of an in-progress compatibility-window ClientHello
    /// handshake message that is fragmenting across record boundaries --
    /// see `ClientHelloState` and `nextClientHelloState`.
    client_hello_state: ClientHelloState = .idle,

    pub fn init(mode: RecordMode) Parser {
        return .{ .mode = mode };
    }

    /// Construct a parser whose first successfully-consumed record may use
    /// `policy` instead of the default strict `0x0303`-only acceptance. Only a
    /// server-role parser dedicated to the initial (plaintext) epoch should
    /// pass `.allow_initial_client_hello_compat`.
    pub fn initWithVersionPolicy(mode: RecordMode, policy: VersionPolicy) Parser {
        return .{ .mode = mode, .first_record_version_policy = policy };
    }

    pub fn reset(self: *Parser) void {
        @memset(self.pending[0..], 0);
        self.len = 0;
        self.parsed_first_record = false;
        self.client_hello_state = .idle;
    }

    /// Feed arbitrary TCP bytes into the parser. Completed records are copied
    /// into `sink`; incomplete headers/bodies stay buffered for the next feed.
    pub fn feed(self: *Parser, bytes: []const u8, sink: anytype) Error!void {
        try self.drain(sink);
        var consumed: usize = 0;
        while (consumed < bytes.len) {
            consumed += try self.appendToNextBoundary(bytes[consumed..]);
            try self.drain(sink);
        }
    }

    pub const FeedOneResult = struct {
        consumed: usize,
        emitted: bool,
    };

    /// Feed bytes until at most one complete record is emitted. The returned
    /// `consumed` count is exact, so callers can retain `bytes[consumed..]`
    /// without replaying or dropping carrier input.
    pub fn feedOne(self: *Parser, bytes: []const u8, sink: anytype) Error!FeedOneResult {
        try self.drainOne(sink);
        if (sink.len > 0) return .{ .consumed = 0, .emitted = true };

        var consumed: usize = 0;
        while (consumed < bytes.len and sink.len == 0) {
            consumed += try self.appendToNextBoundary(bytes[consumed..]);
            try self.drainOne(sink);
        }
        return .{ .consumed = consumed, .emitted = sink.len > 0 };
    }

    /// Copy as much caller input as possible without crossing the next point
    /// where parsing can change state: first the complete header, then the
    /// complete record. The old byte-at-a-time loop reparsed an unchanged
    /// header after every payload byte, making a maximum-sized record perform
    /// roughly 16K redundant header parses.
    fn appendToNextBoundary(self: *Parser, bytes: []const u8) Error!usize {
        if (self.len == self.pending.len) return error.RecordBufferOverflow;

        const boundary = if (self.len < header_len)
            header_len
        else boundary: {
            const header = try parseHeader(
                self.pending[0..header_len],
                self.mode,
                self.currentVersionPolicy(),
            );
            break :boundary header_len + header.payload_len;
        };
        std.debug.assert(boundary > self.len);

        const copied = @min(bytes.len, boundary - self.len);
        @memcpy(self.pending[self.len..][0..copied], bytes[0..copied]);
        self.len += copied;
        return copied;
    }

    /// Retry emission of already-buffered complete records after the caller has
    /// made room in `sink`. This supports bounded sink/backpressure loops
    /// without appending unrelated bytes first.
    pub fn drainReady(self: *Parser, sink: anytype) Error!void {
        try self.drain(sink);
    }

    pub fn finish(self: *const Parser) Error!void {
        if (self.len != 0) return error.TruncatedRecord;
    }

    /// Returns the number of bytes still needed to complete the buffered
    /// record. A partial header needs only its remaining header bytes; once a
    /// header is complete this is the exact encoded-record remainder.
    pub fn pendingRecordBytesNeeded(self: *const Parser) Error!usize {
        return self.pendingRecordBytesNeededWith(&.{});
    }

    /// Like `pendingRecordBytesNeeded`, but includes a caller-owned queued
    /// prefix when determining how many *additional socket bytes* could still
    /// advance this record. The queued prefix is not consumed or retained.
    pub fn pendingRecordBytesNeededWith(self: *const Parser, queued: []const u8) Error!usize {
        const owned = try checkedOwnedLen(self.len, queued.len);
        if (owned < header_len) return header_len - owned;
        const payload_len = try self.pendingRecordPayloadLenWith(queued) orelse unreachable;
        const record_len = try checkedRecordLen(payload_len);
        const already_owned = @min(record_len, owned);
        return record_len - already_owned;
    }

    /// Returns the declared payload length when `bytes` completes the pending
    /// header, without consuming either the parser or caller-owned input.
    pub fn pendingRecordPayloadLenWith(self: *const Parser, bytes: []const u8) Error!?usize {
        if (self.len >= header_len) {
            const header = try parseHeader(self.pending[0..header_len], self.mode, self.currentVersionPolicy());
            return header.payload_len;
        }
        const combined = try checkedOwnedLen(self.len, bytes.len);
        if (combined < header_len) return null;

        var header_bytes: [header_len]u8 = undefined;
        @memcpy(header_bytes[0..self.len], self.pending[0..self.len]);
        const needed = header_len - self.len;
        @memcpy(header_bytes[self.len..], bytes[0..needed]);
        const header = try parseHeader(&header_bytes, self.mode, self.currentVersionPolicy());
        return header.payload_len;
    }

    fn drain(self: *Parser, sink: anytype) Error!void {
        while (self.len >= header_len) {
            const header = try parseHeader(self.pending[0..header_len], self.mode, self.currentVersionPolicy());
            const record_len = header_len + header.payload_len;
            if (self.len < record_len) return;
            const payload = self.pending[header_len..record_len];
            // Compute the next compatibility-window state without mutating
            // `self` yet: `sink.push` can still fail (RecordSinkOverflow),
            // in which case this record stays buffered and `drain`/`drainOne`
            // must be retried later against the *same* bytes. Committing the
            // state here unconditionally would double-count that retry.
            const next_client_hello_state = try self.nextClientHelloStateForRecord(header, payload);
            try sink.push(.{
                .content_type = header.content_type,
                .legacy_version = header.legacy_version,
                .payload = payload,
            });
            self.client_hello_state = next_client_hello_state;
            self.parsed_first_record = (next_client_hello_state == .idle);
            self.discard(record_len);
        }
    }

    fn drainOne(self: *Parser, sink: anytype) Error!void {
        if (self.len < header_len) return;
        const header = try parseHeader(self.pending[0..header_len], self.mode, self.currentVersionPolicy());
        const record_len = header_len + header.payload_len;
        if (self.len < record_len) return;
        const payload = self.pending[header_len..record_len];
        const next_client_hello_state = try self.nextClientHelloStateForRecord(header, payload);
        try sink.push(.{
            .content_type = header.content_type,
            .legacy_version = header.legacy_version,
            .payload = payload,
        });
        self.client_hello_state = next_client_hello_state;
        self.parsed_first_record = (next_client_hello_state == .idle);
        self.discard(record_len);
    }

    /// The compatibility window covers every record of the initial
    /// ClientHello -- which may fragment across several records -- and
    /// closes for good once that message is fully consumed, matching the
    /// RFC 8446 SS5.1 scoping to an initial (non-post-HRR) ClientHello.
    fn currentVersionPolicy(self: *const Parser) VersionPolicy {
        if (self.client_hello_state != .idle) return self.first_record_version_policy;
        return if (self.parsed_first_record) .strict else self.first_record_version_policy;
    }

    /// ClientHello-message tracking exists only to delimit the compatibility
    /// window; a `.strict` parser never grants that exception and must not
    /// pay its cost either -- in particular, `nextClientHelloState`'s
    /// content-type-interleaving check has no business rejecting an
    /// ordinary handshake record immediately followed by an unrelated alert
    /// or change_cipher_spec record, which is completely normal traffic
    /// outside the compatibility window.
    fn nextClientHelloStateForRecord(self: *const Parser, header: RecordHeader, payload: []const u8) Error!ClientHelloState {
        if (self.first_record_version_policy != .allow_initial_client_hello_compat) return .idle;
        return nextClientHelloState(self.client_hello_state, header, payload);
    }

    fn discard(self: *Parser, count: usize) void {
        std.debug.assert(count <= self.len);
        const old_len = self.len;
        const remaining = old_len - count;
        std.mem.copyForwards(u8, self.pending[0..remaining], self.pending[count..old_len]);
        @memset(self.pending[remaining..old_len], 0);
        self.len = remaining;
    }
};

pub const RecordHeader = struct {
    content_type: ContentType,
    legacy_version: u16,
    payload_len: usize,
};

pub fn parseHeader(bytes: []const u8, mode: RecordMode, version_policy: VersionPolicy) Error!RecordHeader {
    if (bytes.len != header_len) return error.TruncatedRecord;
    const content_type = parseContentType(bytes[0]) catch return error.InvalidRecordType;
    const version = std.mem.readInt(u16, bytes[1..3], .big);
    // The compatibility version has no meaning once records are encrypted: a
    // ciphertext-mode parser always requires exactly 0x0303, regardless of
    // the caller-supplied policy, so a misconfigured parser instance still
    // fails closed rather than accepting it on the wrong record stream.
    // The compatibility exception is RFC 8446 SS5.1's initial-ClientHello
    // allowance specifically -- not a blanket pass for any first plaintext
    // record -- so it is further scoped to handshake-content-type records
    // here. `parseHeader` cannot see the payload, so this only rules out a
    // same-header-shaped alert/change_cipher_spec; whether the payload is
    // actually a ClientHello (and not some other handshake message) is
    // checked once the full record is assembled, in `Parser.drain`/`drainOne`.
    const version_ok = version == legacy_record_version or
        (mode == .plaintext and version_policy == .allow_initial_client_hello_compat and
            version == compat_client_hello_version and content_type == .handshake);
    if (!version_ok) return error.InvalidRecordVersion;
    const payload_len: usize = std.mem.readInt(u16, bytes[3..5], .big);
    const max_len: usize = switch (mode) {
        .plaintext => max_plaintext_fragment_len,
        .ciphertext => max_ciphertext_fragment_len,
    };
    if (payload_len > max_len) return error.RecordTooLarge;
    // RFC 8446 Appendix D.4: a peer in middlebox-compatibility mode sends an
    // unprotected, single-byte change_cipher_spec record at this point in the
    // handshake purely for middlebox traversal; every TLS 1.3 stack MUST
    // tolerate it even though the ciphertext parser otherwise requires every
    // record to carry the application_data envelope post-encryption. Any
    // other length for it is malformed and stays rejected here; the exact
    // {0x01} payload check happens once the body is assembled, since this
    // function never sees the payload.
    const is_compat_change_cipher_spec = content_type == .change_cipher_spec and payload_len == 1;
    if (mode == .ciphertext and content_type != .application_data and !is_compat_change_cipher_spec) {
        return error.InvalidRecordType;
    }
    return .{ .content_type = content_type, .legacy_version = version, .payload_len = payload_len };
}

pub fn encodePlaintextRecord(content_type: ContentType, payload: []const u8, out: []u8) Error![]const u8 {
    if (content_type == .application_data) return error.InvalidRecordType;
    if (payload.len > max_plaintext_fragment_len) return error.RecordTooLarge;
    return encodeRecord(content_type, payload, out);
}

pub fn encodeCiphertextRecord(payload: []const u8, out: []u8) Error![]const u8 {
    if (payload.len > max_ciphertext_fragment_len) return error.RecordTooLarge;
    return encodeRecord(.application_data, payload, out);
}

fn encodeRecord(content_type: ContentType, payload: []const u8, out: []u8) Error![]const u8 {
    if (out.len < header_len + payload.len) return error.RecordBufferOverflow;
    out[0] = @intFromEnum(content_type);
    std.mem.writeInt(u16, out[1..3], legacy_record_version, .big);
    std.mem.writeInt(u16, out[3..5], @intCast(payload.len), .big);
    @memcpy(out[header_len..][0..payload.len], payload);
    return out[0 .. header_len + payload.len];
}

pub fn encodeInnerPlaintext(content_type: ContentType, content: []const u8, padding_len: usize, out: []u8) Error![]const u8 {
    if (content_type == .change_cipher_spec) return error.InvalidRecordType;
    if (content.len > max_plaintext_fragment_len) return error.RecordTooLarge;
    const content_and_type = std.math.add(usize, content.len, 1) catch return error.RecordTooLarge;
    const total = std.math.add(usize, content_and_type, padding_len) catch return error.RecordTooLarge;
    if (total > max_ciphertext_fragment_len) return error.RecordTooLarge;
    if (out.len < total) return error.RecordBufferOverflow;
    @memcpy(out[0..content.len], content);
    out[content.len] = @intFromEnum(content_type);
    @memset(out[content.len + 1 ..][0..padding_len], 0);
    return out[0..total];
}

pub fn decodeInnerPlaintext(bytes: []const u8) Error!InnerPlaintext {
    if (bytes.len == 0) return error.MalformedInnerPlaintext;
    if (bytes.len > max_ciphertext_fragment_len) return error.RecordTooLarge;

    var index = bytes.len;
    while (index > 0) {
        index -= 1;
        if (bytes[index] != 0) {
            const content_type = parseContentType(bytes[index]) catch return error.MalformedInnerPlaintext;
            if (content_type == .change_cipher_spec) return error.MalformedInnerPlaintext;
            return .{
                .content_type = content_type,
                .content = bytes[0..index],
                .padding_len = bytes.len - index - 1,
            };
        }
    }
    return error.MalformedInnerPlaintext;
}

fn parseContentType(value: u8) Error!ContentType {
    return std.enums.fromInt(ContentType, value) orelse error.InvalidRecordType;
}

const testing = std.testing;

/// Builds a synthetic ClientHello handshake message
/// (`msg_type=1, uint24 length, body`) into `out` and returns the written
/// slice, so compatibility-window tests exercise a real length field
/// instead of an arbitrary string payload.
fn clientHelloMessage(body: []const u8, out: []u8) []const u8 {
    out[0] = client_hello_msg_type;
    out[1] = @intCast((body.len >> 16) & 0xff);
    out[2] = @intCast((body.len >> 8) & 0xff);
    out[3] = @intCast(body.len & 0xff);
    @memcpy(out[handshake_header_len..][0..body.len], body);
    return out[0 .. handshake_header_len + body.len];
}

test "plaintext parser reassembles split header and body" {
    var parser = Parser.init(.plaintext);
    var sink = DefaultSink{};
    var encoded: [32]u8 = undefined;
    const record = try encodePlaintextRecord(.handshake, "hello", &encoded);

    try parser.feed(record[0..2], &sink);
    try testing.expectEqual(@as(usize, 0), sink.len);
    try parser.feed(record[2..4], &sink);
    try testing.expectEqual(@as(usize, 0), sink.len);
    try parser.feed(record[4..], &sink);

    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqual(ContentType.handshake, sink.items[0].content_type);
    try testing.expectEqual(legacy_record_version, sink.items[0].legacy_version);
    try testing.expectEqualStrings("hello", sink.items[0].payload);
    try parser.finish();
}

test "plaintext parser accepts byte-at-a-time input" {
    var parser = Parser.init(.plaintext);
    var sink = DefaultSink{};
    var encoded: [32]u8 = undefined;
    const record = try encodePlaintextRecord(.alert, &.{ 2, 50 }, &encoded);

    for (record) |byte| try parser.feed(&.{byte}, &sink);
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqual(ContentType.alert, sink.items[0].content_type);
    try testing.expectEqualSlices(u8, &.{ 2, 50 }, sink.items[0].payload);
    try parser.finish();
}

test "parser feedOne reports exact consumption for coalesced records" {
    var parser = Parser.init(.plaintext);
    var first_encoded: [32]u8 = undefined;
    var second_encoded: [32]u8 = undefined;
    const first = try encodePlaintextRecord(.handshake, "one", &first_encoded);
    const second = try encodePlaintextRecord(.handshake, "two", &second_encoded);

    var coalesced: [64]u8 = undefined;
    @memcpy(coalesced[0..first.len], first);
    @memcpy(coalesced[first.len..][0..second.len], second);

    var sink = RecordSink(1, max_plaintext_fragment_len){};
    const first_result = try parser.feedOne(coalesced[0 .. first.len + second.len], &sink);
    try testing.expect(first_result.emitted);
    try testing.expectEqual(first.len, first_result.consumed);
    try testing.expectEqualStrings("one", sink.items[0].payload);

    sink.reset();
    const second_result = try parser.feedOne(coalesced[first_result.consumed .. first.len + second.len], &sink);
    try testing.expect(second_result.emitted);
    try testing.expectEqual(second.len, second_result.consumed);
    try testing.expectEqualStrings("two", sink.items[0].payload);
}

test "parser feedOne against an already-saturated sink consumes nothing" {
    var parser = Parser.init(.plaintext);
    var encoded: [32]u8 = undefined;
    const record = try encodePlaintextRecord(.handshake, "one", &encoded);

    // Simulate a caller that has not yet drained a previous feedOne result:
    // the sink already holds an item before this call.
    var sink = RecordSink(1, max_plaintext_fragment_len){};
    try sink.push(.{ .content_type = .handshake, .legacy_version = legacy_record_version, .payload = "stale" });

    const result = try parser.feedOne(record, &sink);
    try testing.expectEqual(@as(usize, 0), result.consumed);
    try testing.expect(result.emitted);
    // The stale entry is untouched, and none of `record`'s bytes were
    // absorbed into the parser's internal buffer -- the caller can retry
    // the exact same slice once the sink is drained.
    try testing.expectEqualStrings("stale", sink.items[0].payload);
    try testing.expectEqual(@as(usize, 0), parser.len);

    sink.reset();
    const retry = try parser.feedOne(record, &sink);
    try testing.expectEqual(record.len, retry.consumed);
    try testing.expect(retry.emitted);
    try testing.expectEqualStrings("one", sink.items[0].payload);
}

test "strict parser feed and feedOne ignore ClientHello compatibility tracking identically" {
    var message_buf: [32]u8 = undefined;
    const message = clientHelloMessage("hello", &message_buf);

    var handshake_encoded: [32]u8 = undefined;
    const handshake_fragment = try encodePlaintextRecord(.handshake, message[0..1], &handshake_encoded);
    var alert_encoded: [16]u8 = undefined;
    const alert = try encodePlaintextRecord(.alert, &.{ 1, 0 }, &alert_encoded);

    var coalesced: [64]u8 = undefined;
    @memcpy(coalesced[0..handshake_fragment.len], handshake_fragment);
    @memcpy(coalesced[handshake_fragment.len..][0..alert.len], alert);
    const stream = coalesced[0 .. handshake_fragment.len + alert.len];

    var feed_parser = Parser.init(.plaintext);
    var feed_sink = DefaultSink{};
    try feed_parser.feed(stream, &feed_sink);
    try testing.expectEqual(@as(usize, 2), feed_sink.len);
    try testing.expectEqual(ContentType.handshake, feed_sink.items[0].content_type);
    try testing.expectEqualSlices(u8, message[0..1], feed_sink.items[0].payload);
    try testing.expectEqual(ContentType.alert, feed_sink.items[1].content_type);
    try testing.expectEqualSlices(u8, &.{ 1, 0 }, feed_sink.items[1].payload);
    try feed_parser.finish();

    var feed_one_parser = Parser.init(.plaintext);
    var feed_one_sink = RecordSink(1, max_plaintext_fragment_len){};
    const first = try feed_one_parser.feedOne(stream, &feed_one_sink);
    try testing.expect(first.emitted);
    try testing.expectEqual(handshake_fragment.len, first.consumed);
    try testing.expectEqual(ContentType.handshake, feed_one_sink.items[0].content_type);
    try testing.expectEqualSlices(u8, message[0..1], feed_one_sink.items[0].payload);

    feed_one_sink.reset();
    const second = try feed_one_parser.feedOne(stream[first.consumed..], &feed_one_sink);
    try testing.expect(second.emitted);
    try testing.expectEqual(alert.len, second.consumed);
    try testing.expectEqual(ContentType.alert, feed_one_sink.items[0].content_type);
    try testing.expectEqualSlices(u8, &.{ 1, 0 }, feed_one_sink.items[0].payload);
    try feed_one_parser.finish();
}

test "plaintext parser emits multiple coalesced records" {
    var parser = Parser.init(.plaintext);
    var sink = DefaultSink{};
    var encoded: [64]u8 = undefined;
    const first = try encodePlaintextRecord(.handshake, "one", encoded[0..]);
    const second = try encodePlaintextRecord(.alert, "two", encoded[first.len..]);

    try parser.feed(encoded[0 .. first.len + second.len], &sink);
    try testing.expectEqual(@as(usize, 2), sink.len);
    try testing.expectEqualStrings("one", sink.items[0].payload);
    try testing.expectEqualStrings("two", sink.items[1].payload);
    try parser.finish();
}

test "record parser rejects oversized and invalid headers deterministically" {
    var parser = Parser.init(.plaintext);
    var sink = DefaultSink{};
    try testing.expectError(error.InvalidRecordVersion, parser.feed(&.{ 22, 3, 1, 0, 0 }, &sink));

    parser.reset();
    try testing.expectError(error.InvalidRecordType, parser.feed(&.{ 99, 3, 3, 0, 0 }, &sink));

    parser.reset();
    try testing.expectError(error.RecordTooLarge, parser.feed(&.{ 22, 3, 3, 0x40, 0x01 }, &sink));
}

test "strict parser rejects the 0x0301 ClientHello compatibility version by default" {
    var parser = Parser.init(.plaintext);
    var sink = DefaultSink{};
    var encoded: [32]u8 = undefined;
    const record = try encodePlaintextRecord(.handshake, "client hello", &encoded);
    var compat_record: [64]u8 = undefined;
    @memcpy(compat_record[0..record.len], record);
    compat_record[1] = 0x03;
    compat_record[2] = 0x01;

    try testing.expectError(error.InvalidRecordVersion, parser.feed(compat_record[0..record.len], &sink));
}

test "server initial parser accepts 0x0301 only for the first record, then requires 0x0303" {
    var parser = Parser.initWithVersionPolicy(.plaintext, .allow_initial_client_hello_compat);
    var sink = DefaultSink{};
    var message_buf: [64]u8 = undefined;
    const message = clientHelloMessage("client hello", &message_buf);
    var encoded: [64]u8 = undefined;
    const client_hello = try encodePlaintextRecord(.handshake, message, &encoded);
    var compat_client_hello: [64]u8 = undefined;
    @memcpy(compat_client_hello[0..client_hello.len], client_hello);
    compat_client_hello[1] = 0x03;
    compat_client_hello[2] = 0x01;

    try parser.feed(compat_client_hello[0..client_hello.len], &sink);
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqual(@as(u16, 0x0301), sink.items[0].legacy_version);
    try testing.expectEqualStrings(message, sink.items[0].payload);

    // A second post-HRR ClientHello (or any later record) MUST be 0x0303;
    // the compatibility window closes once the first ClientHello message is
    // fully consumed.
    sink.reset();
    var second_message_buf: [64]u8 = undefined;
    const second_message = clientHelloMessage("second client hello", &second_message_buf);
    var second_encoded: [64]u8 = undefined;
    const second_client_hello = try encodePlaintextRecord(.handshake, second_message, &second_encoded);
    var compat_second: [64]u8 = undefined;
    @memcpy(compat_second[0..second_client_hello.len], second_client_hello);
    compat_second[1] = 0x03;
    compat_second[2] = 0x01;
    try testing.expectError(error.InvalidRecordVersion, parser.feed(compat_second[0..second_client_hello.len], &sink));
}

test "server initial parser keeps the compatibility window open across a fragmented ClientHello" {
    var parser = Parser.initWithVersionPolicy(.plaintext, .allow_initial_client_hello_compat);
    var sink = DefaultSink{};

    // A ClientHello body large enough to be split across two records.
    var body: [40]u8 = undefined;
    for (&body, 0..) |*b, i| b.* = @intCast(i);
    var message_buf: [64]u8 = undefined;
    const message = clientHelloMessage(&body, &message_buf);

    // First record carries only part of the message.
    const first_part = message[0..20];
    var first_encoded: [32]u8 = undefined;
    const first_record = try encodePlaintextRecord(.handshake, first_part, &first_encoded);
    var compat_first: [32]u8 = undefined;
    @memcpy(compat_first[0..first_record.len], first_record);
    compat_first[1] = 0x03;
    compat_first[2] = 0x01;

    try parser.feed(compat_first[0..first_record.len], &sink);
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqual(@as(u16, 0x0301), sink.items[0].legacy_version);
    try testing.expectEqualSlices(u8, first_part, sink.items[0].payload);

    // The continuation record is a raw fragment, not a new handshake
    // message -- it does not begin with a msg_type byte -- but the window
    // must still accept 0x0301 on it because the ClientHello is not done.
    sink.reset();
    const second_part = message[20..];
    var second_encoded: [32]u8 = undefined;
    const second_record = try encodePlaintextRecord(.handshake, second_part, &second_encoded);
    var compat_second: [32]u8 = undefined;
    @memcpy(compat_second[0..second_record.len], second_record);
    compat_second[1] = 0x03;
    compat_second[2] = 0x01;

    try parser.feed(compat_second[0..second_record.len], &sink);
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqual(@as(u16, 0x0301), sink.items[0].legacy_version);
    try testing.expectEqualSlices(u8, second_part, sink.items[0].payload);

    // The ClientHello is now fully consumed: the window is closed for good.
    sink.reset();
    var third_message_buf: [64]u8 = undefined;
    const third_message = clientHelloMessage("post-hrr client hello", &third_message_buf);
    var third_encoded: [64]u8 = undefined;
    const third_record = try encodePlaintextRecord(.handshake, third_message, &third_encoded);
    var compat_third: [64]u8 = undefined;
    @memcpy(compat_third[0..third_record.len], third_record);
    compat_third[1] = 0x03;
    compat_third[2] = 0x01;
    try testing.expectError(error.InvalidRecordVersion, parser.feed(compat_third[0..third_record.len], &sink));
}

test "server initial parser keeps the compatibility window open across a fragmented ClientHello header" {
    // The 4-byte msg_type+length handshake header may itself split at any
    // record boundary, not just the body after it -- split after 1, 2, and
    // 3 header bytes.
    for ([_]usize{ 1, 2, 3 }) |split_at| {
        var parser = Parser.initWithVersionPolicy(.plaintext, .allow_initial_client_hello_compat);
        var sink = DefaultSink{};

        var message_buf: [32]u8 = undefined;
        const message = clientHelloMessage("hello", &message_buf);

        const first_part = message[0..split_at];
        var first_encoded: [32]u8 = undefined;
        const first_record = try encodePlaintextRecord(.handshake, first_part, &first_encoded);
        var compat_first: [32]u8 = undefined;
        @memcpy(compat_first[0..first_record.len], first_record);
        compat_first[1] = 0x03;
        compat_first[2] = 0x01;

        try parser.feed(compat_first[0..first_record.len], &sink);
        try testing.expectEqual(@as(usize, 1), sink.len);
        try testing.expectEqual(@as(u16, 0x0301), sink.items[0].legacy_version);

        const second_part = message[split_at..];
        var second_encoded: [32]u8 = undefined;
        const second_record = try encodePlaintextRecord(.handshake, second_part, &second_encoded);
        var compat_second: [32]u8 = undefined;
        @memcpy(compat_second[0..second_record.len], second_record);
        compat_second[1] = 0x03;
        compat_second[2] = 0x01;

        sink.reset();
        try parser.feed(compat_second[0..second_record.len], &sink);
        try testing.expectEqual(@as(usize, 1), sink.len);
        try testing.expectEqual(@as(u16, 0x0301), sink.items[0].legacy_version);
        try testing.expectEqualSlices(u8, second_part, sink.items[0].payload);

        // Fully consumed: a further compat-versioned record is rejected.
        sink.reset();
        try testing.expectError(error.InvalidRecordVersion, parser.feed(&.{ 22, 3, 1, 0, 1, 1 }, &sink));
    }
}

test "sink overflow during a compatibility fragment does not double-count the retried record" {
    var parser = Parser.initWithVersionPolicy(.plaintext, .allow_initial_client_hello_compat);
    // Capacity for only one record at a time, forcing an overflow-then-retry.
    var sink = RecordSink(1, 64){};

    var body: [20]u8 = undefined;
    for (&body, 0..) |*b, i| b.* = @intCast(i);
    var message_buf: [32]u8 = undefined;
    const message = clientHelloMessage(&body, &message_buf);

    const first_part = message[0..8];
    var first_encoded: [32]u8 = undefined;
    const first_record = try encodePlaintextRecord(.handshake, first_part, &first_encoded);
    var compat_first: [32]u8 = undefined;
    @memcpy(compat_first[0..first_record.len], first_record);
    compat_first[1] = 0x03;
    compat_first[2] = 0x01;

    const second_part = message[8..];
    var second_encoded: [32]u8 = undefined;
    const second_record = try encodePlaintextRecord(.handshake, second_part, &second_encoded);
    var compat_second: [32]u8 = undefined;
    @memcpy(compat_second[0..second_record.len], second_record);
    compat_second[1] = 0x03;
    compat_second[2] = 0x01;

    // Fill the sink before feeding anything, so the very first fragment's
    // `sink.push` overflows and the record is left buffered -- the
    // compatibility state must not have advanced past that failed push.
    try sink.push(.{ .content_type = .alert, .legacy_version = legacy_record_version, .payload = "x" });
    try testing.expectError(error.RecordSinkOverflow, parser.feed(compat_first[0..first_record.len], &sink));

    // Drain the blocker and retry: this must process the *same* first
    // fragment exactly once, not re-consume it as if it were a second
    // fragment (which would desynchronize the declared-length accounting
    // and either reject the real continuation or accept bytes beyond it).
    sink.reset();
    try parser.drainReady(&sink);
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqualSlices(u8, first_part, sink.items[0].payload);

    sink.reset();
    try parser.feed(compat_second[0..second_record.len], &sink);
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqualSlices(u8, second_part, sink.items[0].payload);

    // Fully consumed: the window is closed for good.
    sink.reset();
    try testing.expectError(error.InvalidRecordVersion, parser.feed(&.{ 22, 3, 1, 0, 1, 1 }, &sink));
}

test "server initial parser tracks the initial ClientHello even when its first fragment is 0x0303" {
    // RFC 8446 SS5.1 permits 0x0301 on any record of the initial
    // ClientHello, not just the first one to arrive -- a sender may fragment
    // with the first record at 0x0303 and a later one at 0x0301. Tracking
    // must start regardless of which version the first fragment used, or
    // the window closes prematurely and the legal 0x0301 continuation is
    // rejected under .strict.
    var parser = Parser.initWithVersionPolicy(.plaintext, .allow_initial_client_hello_compat);
    var sink = DefaultSink{};

    var body: [20]u8 = undefined;
    for (&body, 0..) |*b, i| b.* = @intCast(i);
    var message_buf: [32]u8 = undefined;
    const message = clientHelloMessage(&body, &message_buf);

    // First record: ordinary 0x0303, only the msg_type byte of the header.
    const first_part = message[0..1];
    var first_encoded: [32]u8 = undefined;
    const first_record = try encodePlaintextRecord(.handshake, first_part, &first_encoded);

    try parser.feed(first_record, &sink);
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqual(@as(u16, legacy_record_version), sink.items[0].legacy_version);

    // Second record: the rest of the header plus the whole body, at 0x0301.
    // This must be accepted precisely because tracking already started.
    const second_part = message[1..];
    var second_encoded: [32]u8 = undefined;
    const second_record = try encodePlaintextRecord(.handshake, second_part, &second_encoded);
    var compat_second: [32]u8 = undefined;
    @memcpy(compat_second[0..second_record.len], second_record);
    compat_second[1] = 0x03;
    compat_second[2] = 0x01;

    sink.reset();
    try parser.feed(compat_second[0..second_record.len], &sink);
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqual(@as(u16, 0x0301), sink.items[0].legacy_version);
    try testing.expectEqualSlices(u8, second_part, sink.items[0].payload);

    // Fully consumed: a further 0x0301 record is rejected under .strict.
    sink.reset();
    try testing.expectError(error.InvalidRecordVersion, parser.feed(&.{ 22, 3, 1, 0, 1, 1 }, &sink));
}

test "server initial parser rejects other record types interleaved within a fragmenting ClientHello" {
    var body: [20]u8 = undefined;
    for (&body, 0..) |*b, i| b.* = @intCast(i);
    var message_buf: [32]u8 = undefined;
    const message = clientHelloMessage(&body, &message_buf);

    // Interleaved during header collection: the first record supplies only
    // 1 of the 4 header bytes, then an alert arrives instead of a
    // continuation.
    {
        var parser = Parser.initWithVersionPolicy(.plaintext, .allow_initial_client_hello_compat);
        var sink = DefaultSink{};
        var first_encoded: [32]u8 = undefined;
        const first_record = try encodePlaintextRecord(.handshake, message[0..1], &first_encoded);
        try parser.feed(first_record, &sink);
        try testing.expectEqual(@as(usize, 1), sink.len);

        sink.reset();
        try testing.expectError(error.InvalidRecordType, parser.feed(&.{ 21, 3, 3, 0, 2, 1, 0 }, &sink));
    }

    // Interleaved during body collection: the header completes but the body
    // is still owed when a change_cipher_spec record arrives.
    {
        var parser = Parser.initWithVersionPolicy(.plaintext, .allow_initial_client_hello_compat);
        var sink = DefaultSink{};
        var first_encoded: [32]u8 = undefined;
        const first_record = try encodePlaintextRecord(.handshake, message[0..8], &first_encoded);
        try parser.feed(first_record, &sink);
        try testing.expectEqual(@as(usize, 1), sink.len);

        sink.reset();
        try testing.expectError(error.InvalidRecordType, parser.feed(&.{ 20, 3, 3, 0, 1, 1 }, &sink));
    }
}

test "server initial parser rejects 0x0301 on a non-handshake first record" {
    var sink = DefaultSink{};

    // An alert record shaped exactly like the accepted ClientHello case
    // above, but content_type = alert (21) instead of handshake (22):
    // parseHeader must reject this before ever looking at the payload.
    {
        var parser = Parser.initWithVersionPolicy(.plaintext, .allow_initial_client_hello_compat);
        try testing.expectError(error.InvalidRecordVersion, parser.feed(&.{ 21, 3, 1, 0, 2, 1, 0 }, &sink));
    }
    sink.reset();
    // Same for change_cipher_spec (20).
    {
        var parser = Parser.initWithVersionPolicy(.plaintext, .allow_initial_client_hello_compat);
        try testing.expectError(error.InvalidRecordVersion, parser.feed(&.{ 20, 3, 1, 0, 1, 1 }, &sink));
    }
}

test "server initial parser rejects 0x0301 on a handshake record that is not a ClientHello" {
    var parser = Parser.initWithVersionPolicy(.plaintext, .allow_initial_client_hello_compat);
    var sink = DefaultSink{};
    var encoded: [64]u8 = undefined;
    // Handshake content type, compat version, but the payload's first byte
    // (the Handshake.msg_type) is 2 (server_hello), not 1 (client_hello).
    const record = try encodePlaintextRecord(.handshake, "\x02not a client hello", &encoded);
    var compat_record: [64]u8 = undefined;
    @memcpy(compat_record[0..record.len], record);
    compat_record[1] = 0x03;
    compat_record[2] = 0x01;

    try testing.expectError(error.InvalidRecordVersion, parser.feed(compat_record[0..record.len], &sink));
    try testing.expectEqual(@as(usize, 0), sink.len);
}

test "compat policy still rejects legacy versions other than 0x0301 and 0x0303" {
    var parser = Parser.initWithVersionPolicy(.plaintext, .allow_initial_client_hello_compat);
    var sink = DefaultSink{};
    // 0x0300 (SSLv3) and 0x0302 (TLS 1.1) are not in the permitted set even
    // during the first-record compatibility window.
    try testing.expectError(error.InvalidRecordVersion, parser.feed(&.{ 22, 3, 0, 0, 0 }, &sink));
    parser.reset();
    try testing.expectError(error.InvalidRecordVersion, parser.feed(&.{ 22, 3, 2, 0, 0 }, &sink));
}

test "compat policy does not apply to the ciphertext parser" {
    var parser = Parser.initWithVersionPolicy(.ciphertext, .allow_initial_client_hello_compat);
    var sink = RecordSink(1, max_ciphertext_fragment_len){};
    // Even with the compat policy set, a ciphertext-mode header must still be
    // application_data at 0x0303; 0x0301 has no meaning post-encryption.
    try testing.expectError(error.InvalidRecordVersion, parser.feed(&.{ 23, 3, 1, 0, 0 }, &sink));
}

test "ciphertext parser requires application_data envelope and allows TLS 1.3 expansion" {
    var parser = Parser.init(.ciphertext);
    var sink = RecordSink(1, max_ciphertext_fragment_len){};
    var encoded: [max_ciphertext_record_len]u8 = undefined;
    const payload = [_]u8{0xaa} ** max_ciphertext_fragment_len;
    const record = try encodeCiphertextRecord(&payload, &encoded);

    try parser.feed(record, &sink);
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqual(ContentType.application_data, sink.items[0].content_type);
    try testing.expectEqual(@as(usize, max_ciphertext_fragment_len), sink.items[0].payload.len);

    var bad_parser = Parser.init(.ciphertext);
    try testing.expectError(error.InvalidRecordType, bad_parser.feed(&.{ 22, 3, 3, 0, 0 }, &sink));
}

test "ciphertext parser tolerates the RFC 8446 Appendix D.4 middlebox-compat change_cipher_spec envelope" {
    var parser = Parser.init(.ciphertext);
    var sink = RecordSink(1, max_ciphertext_fragment_len){};
    // {0x14, 03, 03, 00, 01, 01} == change_cipher_spec, legacy version 0x0303,
    // length 1, payload {0x01} -- the exact wire shape a middlebox-compat
    // peer sends unprotected at any point before its own Finished.
    try parser.feed(&.{ 20, 3, 3, 0, 1, 1 }, &sink);
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqual(ContentType.change_cipher_spec, sink.items[0].content_type);
    try testing.expectEqualSlices(u8, &.{1}, sink.items[0].payload);

    // Any other declared length for it is still rejected at the header --
    // RFC 8446 requires aborting on "any other change_cipher_spec value".
    var bad_parser = Parser.init(.ciphertext);
    try testing.expectError(error.InvalidRecordType, bad_parser.feed(&.{ 20, 3, 3, 0, 2, 1, 0 }, &sink));
}

test "parser reset and discard wipe vacated pending bytes" {
    var parser = Parser.init(.plaintext);
    var sink = DefaultSink{};
    var encoded: [64]u8 = undefined;
    const record = try encodePlaintextRecord(.handshake, "secret", &encoded);

    try testing.expectEqual(@as(usize, 4), (try parser.feedOne(record[0..4], &sink)).consumed);
    try testing.expectEqual(@as(usize, 4), parser.len);
    try testing.expect(std.mem.indexOf(u8, parser.pending[0..parser.len], record[0..4]) != null);
    try testing.expectError(error.TruncatedRecord, parser.finish());

    parser.reset();
    try testing.expectEqual(@as(usize, 0), parser.len);
    try testing.expect(std.mem.allEqual(u8, parser.pending[0..], 0));

    try parser.feed(record, &sink);
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqual(@as(usize, 0), parser.len);
    try testing.expect(std.mem.indexOf(u8, parser.pending[0..], "secret") == null);
}

test "finish reports truncated records" {
    var parser = Parser.init(.plaintext);
    var sink = DefaultSink{};
    try parser.feed(&.{ 22, 3, 3, 0, 4, 1 }, &sink);
    try testing.expectError(error.TruncatedRecord, parser.finish());
}

test "record sink bounds copied payload storage" {
    var parser = Parser.init(.plaintext);
    var sink = RecordSink(1, 1){};
    var encoded: [32]u8 = undefined;
    const record = try encodePlaintextRecord(.handshake, "too large", &encoded);
    try testing.expectError(error.RecordSinkOverflow, parser.feed(record, &sink));
}

test "parser can retry buffered record after sink backpressure" {
    var parser = Parser.init(.plaintext);
    var sink = RecordSink(1, 32){};
    var encoded: [64]u8 = undefined;
    const first = try encodePlaintextRecord(.handshake, "one", encoded[0..]);
    const second = try encodePlaintextRecord(.alert, "two", encoded[first.len..]);

    try testing.expectError(error.RecordSinkOverflow, parser.feed(encoded[0 .. first.len + second.len], &sink));
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqualStrings("one", sink.items[0].payload);

    sink.reset();
    try parser.drainReady(&sink);
    try testing.expectEqual(@as(usize, 1), sink.len);
    try testing.expectEqualStrings("two", sink.items[0].payload);
    try parser.finish();
}

test "plaintext and ciphertext serializers enforce limits and envelope type" {
    var out: [header_len + 4]u8 = undefined;
    const plain = try encodePlaintextRecord(.handshake, "abcd", &out);
    try testing.expectEqualSlices(u8, &.{ 22, 3, 3, 0, 4, 'a', 'b', 'c', 'd' }, plain);

    try testing.expectError(error.InvalidRecordType, encodePlaintextRecord(.application_data, "", &out));
    try testing.expectError(error.RecordBufferOverflow, encodeCiphertextRecord("abcd", out[0..4]));

    const oversized_plaintext = [_]u8{0} ** (max_plaintext_fragment_len + 1);
    try testing.expectError(error.RecordTooLarge, encodePlaintextRecord(.handshake, &oversized_plaintext, &out));
}

test "inner plaintext encodes content type followed by zero padding" {
    var out: [32]u8 = undefined;
    const inner = try encodeInnerPlaintext(.handshake, "finished", 3, &out);
    try testing.expectEqualSlices(u8, &.{ 'f', 'i', 'n', 'i', 's', 'h', 'e', 'd', 22, 0, 0, 0 }, inner);

    const decoded = try decodeInnerPlaintext(inner);
    try testing.expectEqual(ContentType.handshake, decoded.content_type);
    try testing.expectEqualStrings("finished", decoded.content);
    try testing.expectEqual(@as(usize, 3), decoded.padding_len);
}

// Pins each of `encodeInnerPlaintext`'s four typed outcomes at its exact
// boundary, in the documented rejection order. The fuzz target below asserts
// the same classification against generated inputs, but its `.corpus` replay
// (what plain `zig build test`/CI runs) is not guaranteed to reach every arm,
// so an error-class regression -- e.g. returning `RecordTooLarge` for an
// ordinary undersized output -- needs deterministic coverage here too. This
// was verified by mutation: swapping the `out.len < total` error makes this
// test fail.
test "encodeInnerPlaintext classifies every rejection stage at its exact boundary" {
    var out: [max_ciphertext_fragment_len]u8 = undefined;
    const content = "finished";

    // 1. change_cipher_spec has no legal inner-plaintext encoding, and is
    // refused before any length is even considered.
    try testing.expectError(error.InvalidRecordType, encodeInnerPlaintext(.change_cipher_spec, content, 0, &out));
    try testing.expectError(error.InvalidRecordType, encodeInnerPlaintext(.change_cipher_spec, "", 0, out[0..0]));

    // 2. content longer than the plaintext fragment maximum.
    const oversized_content = [_]u8{0} ** (max_plaintext_fragment_len + 1);
    try testing.expectError(error.RecordTooLarge, encodeInnerPlaintext(.handshake, &oversized_content, 0, &out));
    // Exactly at the maximum, content alone is fine; it is the total that
    // then exceeds the ciphertext fragment maximum only once padding pushes
    // it over (checked in stage 3).
    const max_content = [_]u8{0} ** max_plaintext_fragment_len;
    const at_max = try encodeInnerPlaintext(.handshake, &max_content, 0, &out);
    try testing.expectEqual(max_plaintext_fragment_len + 1, at_max.len);

    // 3. total (content || type || padding) across the ciphertext fragment
    // maximum: exact-minus-one and exact succeed, exact-plus-one does not.
    const max_total = max_ciphertext_fragment_len;
    const under = try encodeInnerPlaintext(.handshake, content, max_total - content.len - 2, &out);
    try testing.expectEqual(max_total - 1, under.len);
    const exact = try encodeInnerPlaintext(.handshake, content, max_total - content.len - 1, &out);
    try testing.expectEqual(max_total, exact.len);
    try testing.expectError(
        error.RecordTooLarge,
        encodeInnerPlaintext(.handshake, content, max_total - content.len, &out),
    );
    // And a padding length that overflows `usize` arithmetic outright.
    try testing.expectError(error.RecordTooLarge, encodeInnerPlaintext(.handshake, content, std.math.maxInt(usize), &out));

    // 4. output capacity, at exact-minus-one / exact / exact-plus-one. This
    // is the arm that must stay `RecordBufferOverflow` and not collapse into
    // `RecordTooLarge`.
    const needed = content.len + 1 + 3;
    try testing.expectError(
        error.RecordBufferOverflow,
        encodeInnerPlaintext(.handshake, content, 3, out[0 .. needed - 1]),
    );
    const exact_out = try encodeInnerPlaintext(.handshake, content, 3, out[0..needed]);
    try testing.expectEqual(needed, exact_out.len);
    const roomy_out = try encodeInnerPlaintext(.handshake, content, 3, out[0 .. needed + 1]);
    try testing.expectEqual(needed, roomy_out.len);
    // A zero-capacity destination is still the output-capacity error, not a
    // size error, even for the smallest possible encoding.
    try testing.expectError(error.RecordBufferOverflow, encodeInnerPlaintext(.handshake, "", 0, out[0..0]));
}

test "inner plaintext rejects all-zero, invalid type, and oversized content" {
    try testing.expectError(error.MalformedInnerPlaintext, decodeInnerPlaintext(&.{ 0, 0, 0 }));
    try testing.expectError(error.MalformedInnerPlaintext, decodeInnerPlaintext(&.{ 1, 99, 0 }));
    try testing.expectError(error.MalformedInnerPlaintext, decodeInnerPlaintext(&.{ 20, 0 }));

    var out: [4]u8 = undefined;
    try testing.expectError(error.InvalidRecordType, encodeInnerPlaintext(.change_cipher_spec, "", 0, &out));
    try testing.expectError(error.RecordTooLarge, encodeInnerPlaintext(.handshake, "", std.math.maxInt(usize), &out));
}

test "checkedOwnedLen rejects a synthetic near-usize-max queued length instead of wrapping" {
    try testing.expectEqual(@as(usize, 15), try checkedOwnedLen(5, 10));
    try testing.expectEqual(@as(usize, std.math.maxInt(usize)), try checkedOwnedLen(0, std.math.maxInt(usize)));
    try testing.expectError(error.RecordTooLarge, checkedOwnedLen(5, std.math.maxInt(usize)));
    try testing.expectError(error.RecordTooLarge, checkedOwnedLen(std.math.maxInt(usize), std.math.maxInt(usize)));
}

test "checkedRecordLen rejects a synthetic near-usize-max payload length instead of wrapping" {
    try testing.expectEqual(@as(usize, header_len + 10), try checkedRecordLen(10));
    try testing.expectError(error.RecordTooLarge, checkedRecordLen(std.math.maxInt(usize)));
}

test "pendingRecordBytesNeededWith and pendingRecordPayloadLenWith stay accurate once combined length no longer overflows" {
    var parser = Parser.init(.plaintext);
    var sink = DefaultSink{};
    var encoded: [32]u8 = undefined;
    const record = try encodePlaintextRecord(.handshake, "hi", &encoded);

    // Header not yet complete: exercises the `checkedOwnedLen` path inside
    // both `pendingRecordBytesNeededWith` and `pendingRecordPayloadLenWith`.
    _ = try parser.feedOne(record[0..2], &sink);
    try testing.expectEqual(@as(usize, header_len - 2), try parser.pendingRecordBytesNeededWith(&.{}));
    try testing.expectEqual(@as(?usize, null), try parser.pendingRecordPayloadLenWith(&.{}));

    // Header completes exactly from a 3-byte queued prefix (parser already
    // owns 2 of the 5 header bytes): the still-needed count is the payload
    // length alone, since header_len (5) == parser.len (2) + queued.len (3).
    try testing.expectEqual(@as(usize, 2), try parser.pendingRecordPayloadLenWith(record[2..5]));
    try testing.expectEqual(@as(usize, 2), try parser.pendingRecordBytesNeededWith(record[2..5]));
}

// -----------------------------------------------------------------------
// #493 fuzz targets. See docs/CRYPTO_FUZZ_CONTRACT.md's "#493" section for
// the shared rules these follow (fresh state per case, fixed buffers,
// explicit bounds, typed-error classification, sanitized diagnostics).
// -----------------------------------------------------------------------

/// True when `inner` is empty or wholly contained within `outer`'s backing
/// bytes (pointer-range containment) -- the #493 borrowed-slice-safety
/// property for sink/decode payload views, matching the equivalent helper
/// in new_session_ticket.zig's #494 fuzz target.
fn withinBounds(outer: []const u8, inner: []const u8) bool {
    if (inner.len == 0) return true;
    const outer_start = @intFromPtr(outer.ptr);
    const outer_end = outer_start + outer.len;
    const inner_start = @intFromPtr(inner.ptr);
    const inner_end = inner_start + inner.len;
    return inner_start >= outer_start and inner_end <= outer_end and inner_end >= inner_start;
}

const fuzz_codec_max_records = 4;
const fuzz_codec_max_payload = 48;
/// Bounded so a whole generated ClientHello message
/// (`handshake_header_len + body`) still fits in one `fuzz_codec_max_payload`
/// record payload, which is what makes a single-fragment compatibility-window
/// case representable alongside the multi-fragment ones.
const fuzz_codec_max_compat_body = fuzz_codec_max_payload - handshake_header_len;

// Every split point of a two-call `feedOne` sequence must preserve exact
// consumption: splitting after each of the five header bytes, and at
// representative payload boundaries, leaves the remainder buffered and
// resumes it on the next call without losing or duplicating a byte. The
// fuzz target below randomizes this; this pins it deterministically at every
// header offset, which a coverage-guided run should never have to
// rediscover.
test "feedOne preserves exact consumption across every header and payload split point" {
    var encoded: [header_len + 6]u8 = undefined;
    const record = try encodePlaintextRecord(.handshake, "abcdef", &encoded);

    for (1..record.len) |split_at| {
        var parser = Parser.init(.plaintext);
        var sink = RecordSink(1, 32){};

        const first = try parser.feedOne(record[0..split_at], &sink);
        // A prefix shorter than the whole record can never emit, and must
        // absorb every offered byte into the pending buffer.
        try testing.expect(!first.emitted);
        try testing.expectEqual(split_at, first.consumed);
        try testing.expectEqual(@as(usize, 0), sink.len);
        try testing.expectError(error.TruncatedRecord, parser.finish());

        const second = try parser.feedOne(record[split_at..], &sink);
        try testing.expect(second.emitted);
        try testing.expectEqual(record.len - split_at, second.consumed);
        try testing.expectEqual(@as(usize, 1), sink.len);
        try testing.expectEqual(ContentType.handshake, sink.items[0].content_type);
        try testing.expectEqualStrings("abcdef", sink.items[0].payload);
        try parser.finish();
    }
}

test "fuzz: TLS record: codec fragmentation, coalescing, and sink saturation preserve exact consumption" {
    try std.testing.fuzz({}, fuzzCodecFragmentationInput, .{ .corpus = &.{
        "",
        &[_]u8{0},
        &[_]u8{ 0, 0 },
        &[_]u8{ 1, 1 },
        &[_]u8{ 0, 1, 0, 1 },
        &[_]u8{ 22, 3, 3, 0, 0 },
        &[_]u8{ 22, 3, 3, 0, 5, 1, 2, 3, 4, 5 },
        &[_]u8{ 22, 3, 1, 0, 4, 1, 0, 0, 0 },
        &[_]u8{ 21, 3, 3, 0, 2, 1, 0 },
        &[_]u8{ 20, 3, 3, 0, 1, 1 },
        &[_]u8{ 23, 3, 3, 0, 3, 9, 9, 9 },
        &[_]u8{ 0, 0, 1, 2, 3, 4, 0x40, 0x00 },
        &[_]u8{ 3, 3, 1, 1, 0x40, 0x01 },
        &([_]u8{0xff} ** 64),
        &([_]u8{0x01} ** 200),
        &([_]u8{ 0, 2, 4, 8, 16, 32, 64, 128 } ** 8),
    } });
}

fn fuzzCodecFragmentationInput(_: void, smith: *std.testing.Smith) !void {
    const mode: RecordMode = if (smith.index(2) == 0) .plaintext else .ciphertext;
    // The initial-ClientHello `0x0301` compatibility window is part of the
    // generated case, not a separate deterministic-only scenario: when it is
    // selected the whole oracle stream below becomes the fragments of one
    // real ClientHello message (all handshake-content-type, so RFC 8446
    // SS5.1's no-interleaving rule is respected), with each fragment's
    // declared legacy version independently chosen from {0x0303, 0x0301}.
    // Every such fragment is inside the window and therefore legal
    // regardless of the mix, so the exact-consumption oracle applies
    // unchanged; the illegal placements are asserted separately below.
    const allow_compat = mode == .plaintext and smith.index(2) == 0;
    var parser = if (allow_compat)
        Parser.initWithVersionPolicy(.plaintext, .allow_initial_client_hello_compat)
    else
        Parser.init(mode);

    const Expected = struct {
        content_type: ContentType,
        legacy_version: u16,
        payload: [fuzz_codec_max_payload]u8,
        payload_len: usize,
    };
    var expected: [fuzz_codec_max_records]Expected = undefined;
    var stream_buf: [fuzz_codec_max_records * (header_len + fuzz_codec_max_payload)]u8 = undefined;
    var stream_len: usize = 0;
    var record_count: usize = 0;

    if (allow_compat) {
        // One real `msg_type=1, uint24 length, body` ClientHello, split at
        // fuzzer-chosen boundaries -- including inside its own 4-byte
        // handshake header, which is exactly the #408 compatibility-window
        // fragmentation class.
        var body: [fuzz_codec_max_compat_body]u8 = undefined;
        const body_len = smith.index(body.len + 1);
        smith.bytes(body[0..body_len]);
        var message_buf: [handshake_header_len + fuzz_codec_max_compat_body]u8 = undefined;
        const message = clientHelloMessage(body[0..body_len], &message_buf);

        const max_fragments = @min(fuzz_codec_max_records, message.len);
        record_count = 1 + smith.index(max_fragments);
        var message_offset: usize = 0;
        for (0..record_count) |i| {
            const fragments_left = record_count - i;
            const take = if (fragments_left == 1)
                message.len - message_offset
            else
                1 + smith.index(message.len - message_offset - (fragments_left - 1));
            const fragment = message[message_offset..][0..take];
            message_offset += take;

            var record_out: [header_len + fuzz_codec_max_payload]u8 = undefined;
            const encoded = try encodePlaintextRecord(.handshake, fragment, &record_out);
            const record_start = stream_len;
            @memcpy(stream_buf[record_start..][0..encoded.len], encoded);
            stream_len += encoded.len;

            // `encodePlaintextRecord` always writes 0x0303; rewrite the
            // version field in place when this fragment should claim the
            // compatibility version instead.
            const use_compat_version = smith.index(2) == 0;
            if (use_compat_version) {
                std.mem.writeInt(u16, stream_buf[record_start + 1 ..][0..2], compat_client_hello_version, .big);
            }

            var payload: [fuzz_codec_max_payload]u8 = undefined;
            @memcpy(payload[0..take], fragment);
            expected[i] = .{
                .content_type = .handshake,
                .legacy_version = if (use_compat_version) compat_client_hello_version else legacy_record_version,
                .payload = payload,
                .payload_len = take,
            };
        }
        try testing.expectEqual(message.len, message_offset);
    } else {
        record_count = 1 + smith.index(fuzz_codec_max_records);
        for (0..record_count) |i| {
            var payload_buf: [fuzz_codec_max_payload]u8 = undefined;
            const payload_len = smith.index(payload_buf.len + 1);
            smith.bytes(payload_buf[0..payload_len]);
            const content_type: ContentType = switch (mode) {
                .plaintext => switch (smith.index(3)) {
                    0 => .handshake,
                    1 => .alert,
                    else => .change_cipher_spec,
                },
                .ciphertext => .application_data,
            };
            var record_out: [header_len + fuzz_codec_max_payload]u8 = undefined;
            const encoded = switch (mode) {
                .plaintext => try encodePlaintextRecord(content_type, payload_buf[0..payload_len], &record_out),
                .ciphertext => try encodeCiphertextRecord(payload_buf[0..payload_len], &record_out),
            };
            @memcpy(stream_buf[stream_len..][0..encoded.len], encoded);
            stream_len += encoded.len;
            expected[i] = .{
                .content_type = content_type,
                .legacy_version = legacy_record_version,
                .payload = payload_buf,
                .payload_len = payload_len,
            };
        }
    }

    // Drive the coalesced oracle stream through `feedOne` with a
    // single-record-capacity sink, offering a fuzzer-chosen *prefix* of the
    // remaining bytes on every call. Offering less than a whole record is
    // the point: a partial header or body then stays buffered across the
    // invocation boundary and must resume exactly on a later call, which is
    // the caller-visible fragmentation boundary (not merely `feedOne`'s
    // internal byte loop). Every source byte must still be consumed exactly
    // once, in order, with no record skipped or duplicated.
    var sink = RecordSink(1, fuzz_codec_max_payload + header_len){};
    var offset: usize = 0;
    var expected_idx: usize = 0;
    // Progress bound: each iteration consumes at least one offered byte, so
    // this can only be reached if the parser stops making progress.
    var iterations: usize = 0;
    const max_iterations = stream_len * 2 + 16;
    while (offset < stream_len) {
        iterations += 1;
        try testing.expect(iterations <= max_iterations);
        try testing.expectEqual(@as(usize, 0), sink.len);

        const remaining = stream_len - offset;
        const offered_len = 1 + smith.index(remaining);
        const result = try parser.feedOne(stream_buf[offset..][0..offered_len], &sink);
        try testing.expect(parser.len <= parser.pending.len);
        try testing.expect(result.consumed <= offered_len);
        offset += result.consumed;

        if (!result.emitted) {
            // No record completed within the offered fragment, so the whole
            // fragment must have been absorbed into the bounded pending
            // buffer -- nothing dropped, nothing emitted.
            try testing.expectEqual(@as(usize, 0), sink.len);
            try testing.expectEqual(offered_len, result.consumed);
            continue;
        }

        try testing.expect(result.consumed > 0);
        try testing.expectEqual(@as(usize, 1), sink.len);
        try testing.expect(expected_idx < record_count);
        const exp = expected[expected_idx];
        try testing.expectEqual(exp.content_type, sink.items[0].content_type);
        try testing.expectEqual(exp.legacy_version, sink.items[0].legacy_version);
        try testing.expectEqualSlices(u8, exp.payload[0..exp.payload_len], sink.items[0].payload);
        try testing.expect(withinBounds(sink.scratch[0..], sink.items[0].payload));

        expected_idx += 1;

        // Occasionally simulate a caller that has not drained the sink yet:
        // the next `feedOne` must consume nothing and leave parser and
        // stale-sink state untouched, and a reset + exact retry must then
        // succeed once.
        if (smith.index(2) == 0 and offset < stream_len) {
            const parser_len_before = parser.len;
            const stale = try parser.feedOne(stream_buf[offset..stream_len], &sink);
            try testing.expectEqual(@as(usize, 0), stale.consumed);
            try testing.expect(stale.emitted);
            try testing.expectEqual(parser_len_before, parser.len);
            try testing.expectEqualSlices(u8, exp.payload[0..exp.payload_len], sink.items[0].payload);
        }
        sink.reset();
    }
    try testing.expectEqual(record_count, expected_idx);
    try parser.finish();

    // The compatibility window closes for good once that initial
    // ClientHello has been fully consumed: a further `0x0301` record on the
    // same parser must now be refused.
    if (allow_compat) {
        var closed_sink = DefaultSink{};
        try testing.expectError(
            error.InvalidRecordVersion,
            parser.feed(&.{ 22, 3, 1, 0, 1, 1 }, &closed_sink),
        );
    }

    // Illegal `0x0301` placements. The exception is scoped to an initial
    // ClientHello on a plaintext parser, so it must be refused for a
    // non-ClientHello handshake message, a non-handshake content type, and
    // every ciphertext-mode record -- each against a fresh parser that has
    // the compatibility policy enabled, so only the placement differs.
    {
        // (a) handshake content type, compat version, but `msg_type != 1`.
        var msg_type_byte: [1]u8 = undefined;
        smith.bytes(&msg_type_byte);
        const non_client_hello_type: u8 = if (msg_type_byte[0] == client_hello_msg_type)
            client_hello_msg_type + 1
        else
            msg_type_byte[0];
        var other_message: [handshake_header_len + 4]u8 = undefined;
        other_message[0] = non_client_hello_type;
        other_message[1] = 0;
        other_message[2] = 0;
        other_message[3] = 4;
        smith.bytes(other_message[handshake_header_len..]);
        var other_record: [header_len + handshake_header_len + 4]u8 = undefined;
        const other_encoded = try encodePlaintextRecord(.handshake, &other_message, &other_record);
        std.mem.writeInt(u16, other_record[1..3], compat_client_hello_version, .big);

        var other_parser = Parser.initWithVersionPolicy(.plaintext, .allow_initial_client_hello_compat);
        var other_sink = DefaultSink{};
        try testing.expectError(
            error.InvalidRecordVersion,
            other_parser.feed(other_encoded, &other_sink),
        );

        // (b) compat version on a non-handshake content type.
        const non_handshake: u8 = if (smith.index(2) == 0)
            @intFromEnum(ContentType.alert)
        else
            @intFromEnum(ContentType.change_cipher_spec);
        var non_handshake_parser = Parser.initWithVersionPolicy(.plaintext, .allow_initial_client_hello_compat);
        var non_handshake_sink = DefaultSink{};
        try testing.expectError(
            error.InvalidRecordVersion,
            non_handshake_parser.feed(&.{ non_handshake, 3, 1, 0, 1, 1 }, &non_handshake_sink),
        );

        // (c) compat version has no meaning post-encryption: a
        // ciphertext-mode parser must refuse it even with the policy set.
        var cipher_parser = Parser.initWithVersionPolicy(.ciphertext, .allow_initial_client_hello_compat);
        var cipher_sink = DefaultSink{};
        try testing.expectError(
            error.InvalidRecordVersion,
            cipher_parser.feed(&.{ 23, 3, 1, 0, 0 }, &cipher_sink),
        );
    }

    // Record-size boundaries, as a bounded single-record subcase rather
    // than by making every generated record maximum-sized: zero, one,
    // exact-maximum-minus-one, and exact-maximum payloads must all traverse
    // the valid encode/parse/oracle path, and a header that merely
    // *declares* maximum-plus-one must be refused with `RecordTooLarge`
    // without that payload ever having to exist.
    {
        const max_len: usize = switch (mode) {
            .plaintext => max_plaintext_fragment_len,
            .ciphertext => max_ciphertext_fragment_len,
        };
        const payload_len = switch (smith.index(5)) {
            0 => 0,
            1 => 1,
            2 => max_len - 1,
            3 => max_len,
            else => smith.index(max_len + 1),
        };

        // Cheap deterministic fill: a fuzzer-chosen seed byte expanded over
        // the (possibly 16 KiB) payload, rather than drawing that many
        // bytes from Smith per case. The bytes are not the property under
        // test here -- the length boundary is.
        var seed: [1]u8 = undefined;
        smith.bytes(&seed);
        var payload_buf: [max_ciphertext_fragment_len]u8 = undefined;
        for (payload_buf[0..payload_len], 0..) |*byte, i| {
            byte.* = seed[0] ^ @as(u8, @truncate(i));
        }

        var record_buf: [max_ciphertext_record_len]u8 = undefined;
        const boundary_content_type: ContentType = if (mode == .plaintext) .handshake else .application_data;
        const encoded = switch (mode) {
            .plaintext => try encodePlaintextRecord(.handshake, payload_buf[0..payload_len], &record_buf),
            .ciphertext => try encodeCiphertextRecord(payload_buf[0..payload_len], &record_buf),
        };
        try testing.expectEqual(header_len + payload_len, encoded.len);

        var boundary_parser = Parser.init(mode);
        var boundary_sink = RecordSink(1, max_ciphertext_fragment_len){};
        const boundary_result = try boundary_parser.feedOne(encoded, &boundary_sink);
        try testing.expect(boundary_result.emitted);
        try testing.expectEqual(encoded.len, boundary_result.consumed);
        try testing.expectEqual(@as(usize, 1), boundary_sink.len);
        try testing.expectEqual(boundary_content_type, boundary_sink.items[0].content_type);
        try testing.expectEqualSlices(u8, payload_buf[0..payload_len], boundary_sink.items[0].payload);
        try boundary_parser.finish();

        // Declared maximum-plus-one: only the 2-byte length field changes,
        // and `max_len + 1` still fits in a `u16` for both modes, so this
        // needs no oversized allocation at all.
        var oversized_header: [header_len]u8 = undefined;
        @memcpy(&oversized_header, encoded[0..header_len]);
        std.mem.writeInt(u16, oversized_header[3..5], @intCast(max_len + 1), .big);
        var oversized_parser = Parser.init(mode);
        var oversized_sink = RecordSink(1, 16){};
        try testing.expectError(
            error.RecordTooLarge,
            oversized_parser.feed(&oversized_header, &oversized_sink),
        );
    }

    // `drainReady` publishes an already-complete buffered record without
    // accepting new input, and a record that overflows the sink at push
    // time stays buffered for an exact retry rather than being dropped or
    // double-counted -- the #408 sink-saturation regression class, replayed
    // here against fuzzer-chosen content.
    {
        var backpressure_parser = Parser.init(mode);
        var backpressure_sink = RecordSink(1, 32){};
        try backpressure_sink.push(.{ .content_type = .alert, .legacy_version = legacy_record_version, .payload = "x" });

        var one_byte: [1]u8 = undefined;
        smith.bytes(&one_byte);
        var record_out: [header_len + 1]u8 = undefined;
        const encoded = switch (mode) {
            .plaintext => try encodePlaintextRecord(.handshake, &one_byte, &record_out),
            .ciphertext => try encodeCiphertextRecord(&one_byte, &record_out),
        };

        try testing.expectError(error.RecordSinkOverflow, backpressure_parser.feed(encoded, &backpressure_sink));
        try testing.expectEqualStrings("x", backpressure_sink.items[0].payload);

        backpressure_sink.reset();
        try backpressure_parser.drainReady(&backpressure_sink);
        try testing.expectEqual(@as(usize, 1), backpressure_sink.len);
        try testing.expectEqualSlices(u8, &one_byte, backpressure_sink.items[0].payload);
        try backpressure_parser.finish();
    }

    // `finish()` only succeeds with no partial record buffered.
    {
        var truncated_parser = Parser.init(mode);
        var truncated_sink = DefaultSink{};
        var trunc_byte: [1]u8 = undefined;
        smith.bytes(&trunc_byte);
        try truncated_parser.feed(trunc_byte[0..1], &truncated_sink);
        try testing.expectError(error.TruncatedRecord, truncated_parser.finish());
    }

    // Arbitrary bytes into a fresh parser: malformed input is the expected
    // majority outcome and must produce only the documented codec errors
    // (guaranteed by `Error`'s return type) without panicking, spinning, or
    // growing the pending buffer beyond its fixed capacity.
    var junk_buf: [256]u8 = undefined;
    const junk_len = smith.slice(&junk_buf);
    var junk_parser = Parser.init(mode);
    var junk_sink = DefaultSink{};
    junk_parser.feed(junk_buf[0..junk_len], &junk_sink) catch {};
    junk_parser.finish() catch {};
    try testing.expect(junk_parser.len <= junk_parser.pending.len);
}

const fuzz_inner_plaintext_max_content = 512;
const fuzz_inner_plaintext_max_out = max_ciphertext_fragment_len + 16;
const fuzz_inner_plaintext_max_padding = 512;

test "fuzz: TLS record: inner plaintext framing, padding, and bounds remain transactional" {
    try std.testing.fuzz({}, fuzzInnerPlaintextInput, .{
        .corpus = &.{
            "",
            &[_]u8{0},
            &[_]u8{ 0, 0, 0 },
            &[_]u8{ 1, 99, 0 },
            &[_]u8{ 20, 0 },
            &[_]u8{ 'f', 'i', 'n', 22, 0, 0, 0 },
            // Length/capacity-matrix selectors: small leading indices steer the
            // content/padding/output-capacity switches toward their boundary
            // arms (0, 1, exact-max-minus-one, exact-max, exact-max-plus-one).
            &[_]u8{ 0, 0, 0, 0, 0, 0 },
            &[_]u8{ 1, 1, 1, 1, 1, 1 },
            &[_]u8{ 2, 3, 4, 5, 0, 1 },
            &[_]u8{ 3, 4, 5, 2, 1, 0 },
            &[_]u8{ 4, 5, 3, 0, 2, 1 },
            &[_]u8{ 5, 2, 0, 1, 3, 4 },
            &([_]u8{0} ** 64 ++ [_]u8{23}),
            &([_]u8{0xff} ** 128),
        },
    });
}

/// Independent re-derivation of `decodeInnerPlaintext`'s documented
/// semantics (RFC 8446 SS5.2: strip trailing zero padding, the last nonzero
/// byte is the real `ContentType`), so the fuzz property compares the
/// implementation against a second, explicit statement of the contract
/// rather than just checking "does not crash".
const InnerPlaintextOracle = union(enum) {
    malformed,
    too_large,
    ok: struct { content_type: ContentType, content_len: usize, padding_len: usize },
};

fn expectedInnerPlaintext(bytes: []const u8) InnerPlaintextOracle {
    if (bytes.len == 0) return .malformed;
    if (bytes.len > max_ciphertext_fragment_len) return .too_large;
    var index = bytes.len;
    while (index > 0) {
        index -= 1;
        if (bytes[index] != 0) {
            const content_type = std.enums.fromInt(ContentType, bytes[index]) orelse return .malformed;
            if (content_type == .change_cipher_spec) return .malformed;
            return .{ .ok = .{ .content_type = content_type, .content_len = index, .padding_len = bytes.len - index - 1 } };
        }
    }
    return .malformed;
}

/// The expected outcome of one `encodeInnerPlaintext` call, computed from the
/// generated inputs *before* the call so the fuzz target asserts an exact
/// typed error rather than accepting any rejection. Mirrors the documented
/// rejection order in `encodeInnerPlaintext`: illegal content type, then
/// oversized content, then overflow/oversized total, then output capacity.
const InnerPlaintextEncodeOracle = union(enum) {
    invalid_type,
    too_large,
    output_overflow,
    ok: usize,
};

fn expectedInnerPlaintextEncode(
    content_type: ContentType,
    content_len: usize,
    padding_len: usize,
    out_cap: usize,
) InnerPlaintextEncodeOracle {
    if (content_type == .change_cipher_spec) return .invalid_type;
    if (content_len > max_plaintext_fragment_len) return .too_large;
    const with_type = std.math.add(usize, content_len, 1) catch return .too_large;
    const total = std.math.add(usize, with_type, padding_len) catch return .too_large;
    if (total > max_ciphertext_fragment_len) return .too_large;
    if (out_cap < total) return .output_overflow;
    return .{ .ok = total };
}

fn fuzzInnerPlaintextInput(_: void, smith: *std.testing.Smith) !void {
    // 1. Content type/content/padding/output-capacity generation, driving
    // encode -> decode round trips, an exact expected-error classification
    // on every rejection, and transactional-output verification.
    const valid_types = [_]ContentType{ .alert, .handshake, .application_data };
    // `change_cipher_spec` has no legal `TLSInnerPlaintext` encoding and must
    // always be refused with `InvalidRecordType`, so generate it sometimes
    // rather than only ever generating encodable types.
    const content_type: ContentType = if (smith.index(8) == 0)
        .change_cipher_spec
    else
        valid_types[smith.index(valid_types.len)];

    // Content length matrix around the plaintext-fragment maximum, so the
    // `content.len > max_plaintext_fragment_len` rejection stage is a
    // property rather than a deterministic-only test. Large contents are
    // filled from a cheap seeded pattern instead of drawing 16 KiB from
    // Smith per case -- the length boundary is what is under test here, not
    // the byte values.
    var content_buf: [max_plaintext_fragment_len + 1]u8 = undefined;
    const content_len = switch (smith.index(7)) {
        0 => 0,
        1 => 1,
        2 => max_plaintext_fragment_len - 1,
        3 => max_plaintext_fragment_len,
        4 => max_plaintext_fragment_len + 1,
        else => smith.index(fuzz_inner_plaintext_max_content + 1),
    };
    var content_seed: [1]u8 = undefined;
    smith.bytes(&content_seed);
    for (content_buf[0..content_len], 0..) |*byte, i| {
        byte.* = content_seed[0] ^ @as(u8, @truncate(i));
    }

    // Padding matrix around the *total* inner-plaintext maximum
    // (`content || type || padding`). Padding carries the bulk of a
    // maximum-sized total because it is a scalar the encoder zero-fills, so
    // exact-max and max-plus-one totals need no oversized content buffer.
    // The `maxInt(usize)` case is the #493 overflow-adjacent synthetic
    // limit, which no real padding allocation could represent.
    const padding_headroom = max_ciphertext_fragment_len - @min(content_len, max_ciphertext_fragment_len);
    const padding_len: usize = switch (smith.index(8)) {
        0 => std.math.maxInt(usize),
        1 => 0,
        2 => 1,
        // Exact-maximum total, one under, and one over, when the chosen
        // content length leaves room to express them.
        3 => if (padding_headroom >= 2) padding_headroom - 2 else 0,
        4 => if (padding_headroom >= 1) padding_headroom - 1 else 0,
        5 => padding_headroom,
        else => smith.index(fuzz_inner_plaintext_max_padding + 1),
    };

    // Output-capacity matrix around the exact required total, so the
    // `RecordBufferOverflow` boundary is exercised at exact-minus-one,
    // exact, and exact-plus-one rather than only at random capacities.
    var out_buf: [fuzz_inner_plaintext_max_out]u8 = undefined;
    const required_total: ?usize = switch (expectedInnerPlaintextEncode(content_type, content_len, padding_len, out_buf.len)) {
        .ok => |total| total,
        else => null,
    };
    const out_cap = switch (smith.index(6)) {
        0 => if (required_total) |total| @min(total, out_buf.len) else smith.index(out_buf.len + 1),
        1 => if (required_total) |total| (if (total == 0) 0 else @min(total - 1, out_buf.len)) else smith.index(out_buf.len + 1),
        2 => if (required_total) |total| @min(total + 1, out_buf.len) else smith.index(out_buf.len + 1),
        else => smith.index(out_buf.len + 1),
    };
    const out = out_buf[0..out_cap];
    const sentinel: u8 = 0xa5;
    @memset(out, sentinel);

    switch (expectedInnerPlaintextEncode(content_type, content_len, padding_len, out_cap)) {
        .invalid_type => {
            try testing.expectError(
                error.InvalidRecordType,
                encodeInnerPlaintext(content_type, content_buf[0..content_len], padding_len, out),
            );
            try testing.expect(std.mem.allEqual(u8, out, sentinel));
        },
        .too_large => {
            try testing.expectError(
                error.RecordTooLarge,
                encodeInnerPlaintext(content_type, content_buf[0..content_len], padding_len, out),
            );
            try testing.expect(std.mem.allEqual(u8, out, sentinel));
        },
        .output_overflow => {
            try testing.expectError(
                error.RecordBufferOverflow,
                encodeInnerPlaintext(content_type, content_buf[0..content_len], padding_len, out),
            );
            try testing.expect(std.mem.allEqual(u8, out, sentinel));
        },
        .ok => |total| {
            const encoded = try encodeInnerPlaintext(content_type, content_buf[0..content_len], padding_len, out);
            try testing.expectEqual(total, encoded.len);
            try testing.expect(withinBounds(out, encoded));
            const decoded = try decodeInnerPlaintext(encoded);
            try testing.expectEqual(content_type, decoded.content_type);
            try testing.expectEqualSlices(u8, content_buf[0..content_len], decoded.content);
            try testing.expectEqual(padding_len, decoded.padding_len);
            try testing.expect(withinBounds(encoded, decoded.content));
            // Bytes past the encoded region must still be untouched.
            try testing.expect(std.mem.allEqual(u8, out[total..], sentinel));
        },
    }

    // 2. Raw-bytes decode fuzzing against the independent oracle above,
    // with a length matrix that reaches the exact ciphertext-fragment
    // maximum and one past it (the `RecordTooLarge` decode stage).
    var raw_buf: [fuzz_inner_plaintext_max_out]u8 = undefined;
    const raw_len = switch (smith.index(8)) {
        0 => 0,
        1 => 1,
        2 => max_ciphertext_fragment_len - 1,
        3 => max_ciphertext_fragment_len,
        4 => max_ciphertext_fragment_len + 1,
        else => smith.index(fuzz_inner_plaintext_max_content + 1),
    };
    // Seeded pattern for the bulk, with the trailing window Smith-filled:
    // the last nonzero byte is what decides the decoded type/padding split,
    // so that is the region worth fuzzer control.
    var raw_seed: [1]u8 = undefined;
    smith.bytes(&raw_seed);
    for (raw_buf[0..raw_len], 0..) |*byte, i| {
        byte.* = raw_seed[0] ^ @as(u8, @truncate(i));
    }
    const tail_len = @min(raw_len, 8);
    smith.bytes(raw_buf[raw_len - tail_len ..][0..tail_len]);
    const raw = raw_buf[0..raw_len];

    const oracle = expectedInnerPlaintext(raw);
    switch (oracle) {
        .malformed => try testing.expectError(error.MalformedInnerPlaintext, decodeInnerPlaintext(raw)),
        .too_large => try testing.expectError(error.RecordTooLarge, decodeInnerPlaintext(raw)),
        .ok => |exp| {
            const got = try decodeInnerPlaintext(raw);
            try testing.expectEqual(exp.content_type, got.content_type);
            try testing.expectEqualSlices(u8, raw[0..exp.content_len], got.content);
            try testing.expectEqual(exp.padding_len, got.padding_len);
            try testing.expect(withinBounds(raw, got.content));
        },
    }
}
