//! TLS 1.3 NewSessionTicket wire codec and session-model conversion.
//!
//! This module owns only the RFC 8446 handshake body shape. It borrows slices
//! from validated input during decode and requires callers to supply all
//! connection metadata explicitly when constructing owned resumable state.

const std = @import("std");
const crypto = std.crypto;
const algorithms = @import("algorithms.zig");
const key_schedule = @import("key_schedule.zig");
const session = @import("session.zig");

pub const max_lifetime_seconds = session.max_lifetime_seconds;
pub const max_ticket_nonce_len = session.max_ticket_nonce_len;
pub const absolute_ticket_wire_max = session.absolute_ticket_wire_max;
pub const ext_early_data: u16 = 42;
pub const max_extensions_wire_len: usize = std.math.maxInt(u16) - 1;

pub const Parsed = struct {
    ticket_lifetime: u32,
    ticket_age_add: u32,
    ticket_nonce: []const u8,
    ticket: []const u8,
    max_early_data_size: ?u32,
};

pub const EmitParams = struct {
    ticket_lifetime: u32,
    ticket_age_add: u32,
    ticket_nonce: []const u8,
    ticket: []const u8,
    max_early_data_size: ?u32 = null,
};

pub const CompatBlob = session.ResumableSessionCommon.CompatBlobParams;

pub const ConnectionResumptionContext = struct {
    cipher_suite: algorithms.CipherSuite,
    server_name: ?[]const u8 = null,
    application_protocol: ?[]const u8 = null,
    auth_binding: session.AuthBinding,
    transport_compat: ?CompatBlob = null,
    application_compat: ?CompatBlob = null,
};

pub const EncodeError = error{
    IllegalParameter,
    OutputTooSmall,
    LengthOverflow,
};

pub const DecodeError = error{
    MalformedHandshake,
    IllegalParameter,
};

pub const BuildError =
    key_schedule.Error ||
    session.ResumableSessionCommon.InitError ||
    session.ClientTicketState.InitError ||
    error{InvalidLimits};

pub const BuildServerError =
    key_schedule.Error ||
    session.ResumableSessionCommon.InitError ||
    error{InvalidLimits};

pub fn encodedLen(params: EmitParams) EncodeError!usize {
    try validateEmitParams(params);
    var len: usize = 0;
    len = try checkedAdd(len, 4); // ticket_lifetime
    len = try checkedAdd(len, 4); // ticket_age_add
    len = try checkedAdd(len, 1 + params.ticket_nonce.len);
    len = try checkedAdd(len, 2 + params.ticket.len);
    len = try checkedAdd(len, 2 + extensionsLen(params));
    return len;
}

pub fn encode(params: EmitParams, out: []u8) EncodeError![]const u8 {
    const len = try encodedLen(params);
    if (out.len < len) return error.OutputTooSmall;

    var pos: usize = 0;
    writeU32(out[pos..][0..4], params.ticket_lifetime);
    pos += 4;
    writeU32(out[pos..][0..4], params.ticket_age_add);
    pos += 4;
    out[pos] = @intCast(params.ticket_nonce.len);
    pos += 1;
    @memcpy(out[pos..][0..params.ticket_nonce.len], params.ticket_nonce);
    pos += params.ticket_nonce.len;
    writeU16(out[pos..][0..2], @intCast(params.ticket.len));
    pos += 2;
    @memcpy(out[pos..][0..params.ticket.len], params.ticket);
    pos += params.ticket.len;
    const ext_len = extensionsLen(params);
    writeU16(out[pos..][0..2], @intCast(ext_len));
    pos += 2;
    if (params.max_early_data_size) |max_early_data_size| {
        writeU16(out[pos..][0..2], ext_early_data);
        pos += 2;
        writeU16(out[pos..][0..2], 4);
        pos += 2;
        writeU32(out[pos..][0..4], max_early_data_size);
        pos += 4;
    }
    std.debug.assert(pos == len);
    return out[0..len];
}

pub fn decode(body: []const u8) DecodeError!Parsed {
    var r = Reader{ .bytes = body };
    const ticket_lifetime = try r.readU32();
    const ticket_age_add = try r.readU32();
    const ticket_nonce = try r.slice(try r.readU8());
    const ticket = try r.slice(try r.readU16());
    if (ticket.len == 0) return error.MalformedHandshake;
    if (ticket_lifetime > max_lifetime_seconds) return error.IllegalParameter;

    const extensions = try r.slice(try r.readU16());
    try r.expectEnd();

    var guard = ExtensionGuard{};
    var ext_reader = Reader{ .bytes = extensions };
    var max_early_data_size: ?u32 = null;
    while (!ext_reader.atEnd()) {
        const ext_type = try ext_reader.readU16();
        const ext_body = try ext_reader.slice(try ext_reader.readU16());
        try guard.check(ext_type);
        if (ext_type == ext_early_data) {
            if (ext_body.len != 4) return error.MalformedHandshake;
            max_early_data_size = readIntU32(ext_body[0..4]);
        }
    }

    return .{
        .ticket_lifetime = ticket_lifetime,
        .ticket_age_add = ticket_age_add,
        .ticket_nonce = ticket_nonce,
        .ticket = ticket,
        .max_early_data_size = max_early_data_size,
    };
}

pub fn buildClientTicketState(
    allocator: std.mem.Allocator,
    parsed: Parsed,
    connection: ConnectionResumptionContext,
    resumption_master_secret: []const u8,
    received_at_unix_ms: i64,
    limits: session.Limits,
) BuildError!?session.ClientTicketState {
    try limits.validate();
    if (parsed.ticket_lifetime == 0) return null;

    const hash = algorithms.transcriptHash(connection.cipher_suite);
    var psk: [session.max_psk_len]u8 = undefined;
    defer crypto.secureZero(u8, &psk);
    try key_schedule.KeySchedule.resumptionPsk(
        hash,
        resumption_master_secret,
        parsed.ticket_nonce,
        psk[0..hash.digestLength()],
    );

    var common: session.ResumableSessionCommon = .{};
    errdefer common.deinit();
    try common.init(allocator, limits, .{
        .cipher_suite = connection.cipher_suite,
        .resumption_psk = psk[0..hash.digestLength()],
        .server_name = connection.server_name,
        .application_protocol = connection.application_protocol,
        .auth_binding = connection.auth_binding,
        .issued_at_unix_ms = received_at_unix_ms,
        .lifetime_seconds = parsed.ticket_lifetime,
        .early_data = earlyDataPolicy(parsed.max_early_data_size),
        .transport_compat = connection.transport_compat,
        .application_compat = connection.application_compat,
    });

    var state: session.ClientTicketState = .{};
    try state.init(allocator, limits, &common, .{
        .ticket = parsed.ticket,
        .ticket_age_add = parsed.ticket_age_add,
        .ticket_nonce = parsed.ticket_nonce,
        .received_at_unix_ms = received_at_unix_ms,
    });
    return state;
}

pub fn buildServerRecoverableState(
    allocator: std.mem.Allocator,
    params: EmitParams,
    connection: ConnectionResumptionContext,
    resumption_master_secret: []const u8,
    issued_at_unix_ms: i64,
    limits: session.Limits,
) BuildServerError!session.ServerRecoverableState {
    try limits.validate();
    if (params.ticket_lifetime == 0) return error.InvalidLifetime;
    const hash = algorithms.transcriptHash(connection.cipher_suite);
    var psk: [session.max_psk_len]u8 = undefined;
    defer crypto.secureZero(u8, &psk);
    try key_schedule.KeySchedule.resumptionPsk(
        hash,
        resumption_master_secret,
        params.ticket_nonce,
        psk[0..hash.digestLength()],
    );

    var common: session.ResumableSessionCommon = .{};
    errdefer common.deinit();
    try common.init(allocator, limits, .{
        .cipher_suite = connection.cipher_suite,
        .resumption_psk = psk[0..hash.digestLength()],
        .server_name = connection.server_name,
        .application_protocol = connection.application_protocol,
        .auth_binding = connection.auth_binding,
        .issued_at_unix_ms = issued_at_unix_ms,
        .lifetime_seconds = params.ticket_lifetime,
        .early_data = earlyDataPolicy(params.max_early_data_size),
        .transport_compat = connection.transport_compat,
        .application_compat = connection.application_compat,
    });

    var state: session.ServerRecoverableState = .{};
    state.init(&common);
    return state;
}

fn earlyDataPolicy(max_early_data_size: ?u32) session.EarlyDataPolicy {
    return if (max_early_data_size) |max|
        if (max == 0) .resume_only else .{ .early_data_capable = max }
    else
        .resume_only;
}

fn validateEmitParams(params: EmitParams) EncodeError!void {
    if (params.ticket_lifetime > max_lifetime_seconds) return error.IllegalParameter;
    if (params.ticket_nonce.len > max_ticket_nonce_len) return error.IllegalParameter;
    if (params.ticket.len == 0 or params.ticket.len > absolute_ticket_wire_max) return error.IllegalParameter;
    if (extensionsLen(params) > max_extensions_wire_len) return error.IllegalParameter;
}

fn extensionsLen(params: EmitParams) usize {
    return if (params.max_early_data_size == null) 0 else 8;
}

fn checkedAdd(a: usize, b: usize) EncodeError!usize {
    return std.math.add(usize, a, b) catch return error.LengthOverflow;
}

const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn atEnd(self: *const Reader) bool {
        return self.pos == self.bytes.len;
    }

    fn readU8(self: *Reader) DecodeError!u8 {
        return (try self.slice(1))[0];
    }

    fn readU16(self: *Reader) DecodeError!u16 {
        return readIntU16(try self.slice(2));
    }

    fn readU32(self: *Reader) DecodeError!u32 {
        return readIntU32(try self.slice(4));
    }

    fn slice(self: *Reader, len: usize) DecodeError![]const u8 {
        if (len > self.bytes.len - self.pos) return error.MalformedHandshake;
        const start = self.pos;
        self.pos += len;
        return self.bytes[start..self.pos];
    }

    fn expectEnd(self: *const Reader) DecodeError!void {
        if (!self.atEnd()) return error.MalformedHandshake;
    }
};

const ExtensionGuard = struct {
    ids: [64]u16 = undefined,
    len: usize = 0,

    fn check(self: *ExtensionGuard, ext_type: u16) DecodeError!void {
        for (self.ids[0..self.len]) |seen| {
            if (seen == ext_type) return error.IllegalParameter;
        }
        if (self.len == self.ids.len) return error.MalformedHandshake;
        self.ids[self.len] = ext_type;
        self.len += 1;
    }
};

fn readIntU16(bytes: []const u8) u16 {
    return std.mem.readInt(u16, bytes[0..2], .big);
}

fn readIntU32(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .big);
}

fn writeU16(out: *[2]u8, value: u16) void {
    std.mem.writeInt(u16, out, value, .big);
}

fn writeU32(out: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, out, value, .big);
}

test "NewSessionTicket codec round trips without extensions" {
    var buf: [64]u8 = undefined;
    const encoded = try encode(.{
        .ticket_lifetime = 60,
        .ticket_age_add = 0x11223344,
        .ticket_nonce = "\x01\x02",
        .ticket = "ticket",
    }, &buf);
    try std.testing.expectEqual(try encodedLen(.{
        .ticket_lifetime = 60,
        .ticket_age_add = 0x11223344,
        .ticket_nonce = "\x01\x02",
        .ticket = "ticket",
    }), encoded.len);
    const parsed = try decode(encoded);
    try std.testing.expectEqual(@as(u32, 60), parsed.ticket_lifetime);
    try std.testing.expectEqual(@as(u32, 0x11223344), parsed.ticket_age_add);
    try std.testing.expectEqualSlices(u8, "\x01\x02", parsed.ticket_nonce);
    try std.testing.expectEqualSlices(u8, "ticket", parsed.ticket);
    try std.testing.expectEqual(@as(?u32, null), parsed.max_early_data_size);
}

test "NewSessionTicket codec handles early_data and ignores unknown extensions" {
    var buf: [128]u8 = undefined;
    const encoded = try encode(.{
        .ticket_lifetime = max_lifetime_seconds,
        .ticket_age_add = 7,
        .ticket_nonce = "",
        .ticket = "opaque",
        .max_early_data_size = 16,
    }, &buf);
    const parsed = try decode(encoded);
    try std.testing.expectEqual(@as(?u32, 16), parsed.max_early_data_size);

    const with_unknown = [_]u8{
        0, 0, 0,    1,
        0, 0, 0,    2,
        0, 0, 1,    'x',
        0, 4, 0x12, 0x34,
        0, 0,
    };
    const unknown = try decode(&with_unknown);
    try std.testing.expectEqual(@as(?u32, null), unknown.max_early_data_size);
}

test "NewSessionTicket decode rejects malformed and illegal inputs distinctly" {
    try std.testing.expectError(error.MalformedHandshake, decode(""));
    const empty_ticket = [_]u8{
        0, 0, 0, 1,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0,
    };
    try std.testing.expectError(error.MalformedHandshake, decode(&empty_ticket));

    const too_long_lifetime = [_]u8{
        0, 0x09, 0x3a, 0x81,
        0, 0,    0,    0,
        0, 0,    1,    'x',
        0, 0,
    };
    try std.testing.expectError(error.IllegalParameter, decode(&too_long_lifetime));

    const duplicate_unknown = [_]u8{
        0, 0, 0,    1,
        0, 0, 0,    0,
        0, 0, 1,    'x',
        0, 8, 0x12, 0x34,
        0, 0, 0x12, 0x34,
        0, 0,
    };
    try std.testing.expectError(error.IllegalParameter, decode(&duplicate_unknown));

    const malformed_early_data = [_]u8{
        0, 0, 0, 1,
        0, 0, 0, 0,
        0, 0, 1, 'x',
        0, 5, 0, 42,
        0, 1, 0,
    };
    try std.testing.expectError(error.MalformedHandshake, decode(&malformed_early_data));
}

test "NewSessionTicket encode validates bounds and output size" {
    var buf: [8]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, encode(.{
        .ticket_lifetime = 1,
        .ticket_age_add = 0,
        .ticket_nonce = "",
        .ticket = "ticket",
    }, &buf));
    try std.testing.expectError(error.IllegalParameter, encodedLen(.{
        .ticket_lifetime = max_lifetime_seconds + 1,
        .ticket_age_add = 0,
        .ticket_nonce = "",
        .ticket = "ticket",
    }));
    try std.testing.expectError(error.IllegalParameter, encodedLen(.{
        .ticket_lifetime = 1,
        .ticket_age_add = 0,
        .ticket_nonce = "",
        .ticket = "",
    }));
}

test "lifetime zero parses but does not build cacheable client state" {
    const parsed = Parsed{
        .ticket_lifetime = 0,
        .ticket_age_add = 0,
        .ticket_nonce = "",
        .ticket = "ticket",
        .max_early_data_size = null,
    };
    const state = try buildClientTicketState(
        std.testing.allocator,
        parsed,
        .{
            .cipher_suite = .tls_aes_128_gcm_sha256,
            .auth_binding = session.AuthBinding.fromLeafCertificateDer("leaf"),
        },
        &([_]u8{0x42} ** 32),
        123,
        session.Limits.default,
    );
    try std.testing.expectEqual(@as(?session.ClientTicketState, null), state);
}
