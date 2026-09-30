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
const provider = @import("crypto").provider;

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
    early_data_transport_compat: ?CompatBlob = null,
    early_data_application_compat: ?CompatBlob = null,
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
    error{ InvalidLimits, TicketTooLarge, IllegalParameter };

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

    const extensions_len = try r.readU16();
    if (extensions_len > max_extensions_wire_len) return error.MalformedHandshake;
    const extensions = try r.slice(extensions_len);
    try r.expectEnd();

    var ext_reader = Reader{ .bytes = extensions };
    var seen_extensions = ExtensionSeenSet{};
    var max_early_data_size: ?u32 = null;
    while (!ext_reader.atEnd()) {
        const ext_type = try ext_reader.readU16();
        const ext_body = try ext_reader.slice(try ext_reader.readU16());
        if (seen_extensions.mark(ext_type)) return error.IllegalParameter;
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
    crypto_provider: provider.CryptoProvider,
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
    defer provider.secureZero(&psk);
    try key_schedule.KeySchedule.resumptionPsk(
        crypto_provider,
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
        .early_data_transport_compat = connection.early_data_transport_compat,
        .early_data_application_compat = connection.early_data_application_compat,
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

/// Ticket-identity-free subset of `EmitParams` for #488's two-phase
/// preparation: the opaque bearer identity (stateful handle or stateless
/// envelope) is only known *after* `ServerRecoverableState` is derived
/// (stateful issuance derives the handle from inserting the state itself;
/// stateless issuance seals the state to produce it), so preparation cannot
/// require it up front the way single-phase `buildServerRecoverableState`
/// does.
pub const PrepareParams = struct {
    ticket_lifetime: u32,
    ticket_age_add: u32,
    ticket_nonce: []const u8,
    max_early_data_size: ?u32 = null,
};

/// Derives the per-ticket PSK and builds the exact `ServerRecoverableState`
/// a later stateful insertion or stateless seal will consume, without
/// requiring the opaque bearer identity that only exists once one of those
/// two issuance paths has run. Callers that already know the final identity
/// should use `buildServerRecoverableState` instead.
pub fn buildServerRecoverableStateNoIdentity(
    allocator: std.mem.Allocator,
    crypto_provider: provider.CryptoProvider,
    params: PrepareParams,
    connection: ConnectionResumptionContext,
    resumption_master_secret: []const u8,
    issued_at_unix_ms: i64,
    limits: session.Limits,
) BuildServerError!session.ServerRecoverableState {
    try limits.validate();
    if (params.ticket_lifetime > max_lifetime_seconds) return error.IllegalParameter;
    if (params.ticket_nonce.len > max_ticket_nonce_len) return error.IllegalParameter;
    if (params.ticket_lifetime == 0) return error.InvalidLifetime;
    const hash = algorithms.transcriptHash(connection.cipher_suite);
    var psk: [session.max_psk_len]u8 = undefined;
    defer provider.secureZero(&psk);
    try key_schedule.KeySchedule.resumptionPsk(
        crypto_provider,
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
        .early_data_transport_compat = connection.early_data_transport_compat,
        .early_data_application_compat = connection.early_data_application_compat,
    });

    var state: session.ServerRecoverableState = .{};
    state.init(&common, params.ticket_age_add);
    return state;
}

pub fn buildServerRecoverableState(
    allocator: std.mem.Allocator,
    crypto_provider: provider.CryptoProvider,
    params: EmitParams,
    connection: ConnectionResumptionContext,
    resumption_master_secret: []const u8,
    issued_at_unix_ms: i64,
    limits: session.Limits,
) BuildServerError!session.ServerRecoverableState {
    validateEmitParams(params) catch return error.IllegalParameter;
    if (params.ticket.len == 0 or params.ticket.len > limits.max_ticket_len) return error.TicketTooLarge;
    return buildServerRecoverableStateNoIdentity(allocator, crypto_provider, .{
        .ticket_lifetime = params.ticket_lifetime,
        .ticket_age_add = params.ticket_age_add,
        .ticket_nonce = params.ticket_nonce,
        .max_early_data_size = params.max_early_data_size,
    }, connection, resumption_master_secret, issued_at_unix_ms, limits);
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

const ExtensionSeenSet = struct {
    bits: [std.math.maxInt(u16) / 8 + 1]u8 = [_]u8{0} ** (std.math.maxInt(u16) / 8 + 1),

    fn mark(self: *ExtensionSeenSet, ext_type: u16) bool {
        const index: usize = @intCast(ext_type / 8);
        const mask: u8 = @as(u8, 1) << @intCast(ext_type % 8);
        const duplicate = (self.bits[index] & mask) != 0;
        self.bits[index] |= mask;
        return duplicate;
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

/// A fresh deterministic pure-Zig `CryptoProvider` for this module's own
/// tests (#490), matching the fixture pattern `key_schedule.zig`'s test
/// block uses: `DeterministicEntropy` (explicitly not a CSPRNG) plus the
/// pure-Zig `Provider`, held as a per-call-site persistent local so every
/// test call gets a live, valid provider without a hidden global default.
fn testCryptoProvider() provider.CryptoProvider {
    const pure_zig = @import("crypto").pure_zig;
    const State = struct {
        var entropy = pure_zig.DeterministicEntropy.init(0x1cec_5);
        var backing = pure_zig.Provider.init(entropy.entropy());
    };
    return State.backing.cryptoProvider();
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

test "NewSessionTicket extension vector permits legal counts and rejects illegal length" {
    const allocator = std.testing.allocator;
    var many_extensions: std.ArrayList(u8) = .empty;
    defer many_extensions.deinit(allocator);
    try appendBaseTicketPrefix(&many_extensions, 1, 0, "", "x");
    try many_extensions.appendSlice(allocator, &.{ 0, 0 });
    const ext_len_pos = many_extensions.items.len - 2;
    for (0..65) |i| {
        try appendExtension(&many_extensions, @intCast(1000 + i), "");
    }
    std.mem.writeInt(u16, many_extensions.items[ext_len_pos..][0..2], @intCast(many_extensions.items.len - ext_len_pos - 2), .big);
    const parsed_many = try decode(many_extensions.items);
    try std.testing.expectEqualSlices(u8, "x", parsed_many.ticket);

    var exact: std.ArrayList(u8) = .empty;
    defer exact.deinit(allocator);
    try appendBaseTicketPrefix(&exact, 1, 0, "", "x");
    try exact.appendSlice(allocator, &.{ 0xff, 0xfe });
    var written: usize = 0;
    var ext_id: u16 = 1000;
    while (written + 4 <= max_extensions_wire_len - 6) : ({
        written += 4;
        ext_id += 1;
    }) {
        try appendExtension(&exact, ext_id, "");
    }
    try appendExtension(&exact, ext_id, "\xaa\xbb");
    written += 6;
    try std.testing.expectEqual(max_extensions_wire_len, written);
    const parsed_exact = try decode(exact.items);
    try std.testing.expectEqualSlices(u8, "x", parsed_exact.ticket);

    var illegal: std.ArrayList(u8) = .empty;
    defer illegal.deinit(allocator);
    try appendBaseTicketPrefix(&illegal, 1, 0, "", "x");
    try illegal.appendSlice(allocator, &.{ 0xff, 0xff });
    try illegal.appendNTimes(allocator, 0, std.math.maxInt(u16));
    try std.testing.expectError(error.MalformedHandshake, decode(illegal.items));
}

test "NewSessionTicket duplicate known and unknown extensions are illegal" {
    const allocator = std.testing.allocator;
    var duplicate_known: std.ArrayList(u8) = .empty;
    defer duplicate_known.deinit(allocator);
    try appendBaseTicketPrefix(&duplicate_known, 1, 0, "", "x");
    try duplicate_known.appendSlice(allocator, &.{ 0, 16 });
    try appendExtension(&duplicate_known, ext_early_data, "\x00\x00\x00\x01");
    try appendExtension(&duplicate_known, ext_early_data, "\x00\x00\x00\x02");
    try std.testing.expectError(error.IllegalParameter, decode(duplicate_known.items));

    var duplicate_unknown: std.ArrayList(u8) = .empty;
    defer duplicate_unknown.deinit(allocator);
    try appendBaseTicketPrefix(&duplicate_unknown, 1, 0, "", "x");
    try duplicate_unknown.appendSlice(allocator, &.{ 0, 8 });
    try appendExtension(&duplicate_unknown, 0x1234, "");
    try appendExtension(&duplicate_unknown, 0x1234, "");
    try std.testing.expectError(error.IllegalParameter, decode(duplicate_unknown.items));
}

test "NewSessionTicket encode validates bounds and output size" {
    var buf: [8]u8 = undefined;
    @memset(&buf, 0xa5);
    const before = buf;
    try std.testing.expectError(error.OutputTooSmall, encode(.{
        .ticket_lifetime = 1,
        .ticket_age_add = 0,
        .ticket_nonce = "",
        .ticket = "ticket",
    }, &buf));
    try std.testing.expectEqualSlices(u8, &before, &buf);
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

test "NewSessionTicket decode rejects every truncated fixture prefix" {
    var storage: [128]u8 = undefined;
    const fixture = try encode(.{
        .ticket_lifetime = 60,
        .ticket_age_add = 0x11223344,
        .ticket_nonce = "\x01\x02",
        .ticket = "opaque-ticket",
        .max_early_data_size = 32,
    }, &storage);

    for (0..fixture.len) |cut| {
        try std.testing.expectError(error.MalformedHandshake, decode(fixture[0..cut]));
    }
    const parsed = try decode(fixture);
    try std.testing.expectEqual(@as(u32, 60), parsed.ticket_lifetime);
}

test "NewSessionTicket length field mutation matrix" {
    const allocator = std.testing.allocator;

    const nonce_255 = try allocator.alloc(u8, 255);
    defer allocator.free(nonce_255);
    @memset(nonce_255, 0x01);
    var nonce_buf: [512]u8 = undefined;
    const nonce_exact = try encode(.{ .ticket_lifetime = 1, .ticket_age_add = 0, .ticket_nonce = nonce_255, .ticket = "x" }, &nonce_buf);
    try std.testing.expectEqual(@as(usize, 255), (try decode(nonce_exact)).ticket_nonce.len);
    const nonce_256 = try allocator.alloc(u8, 256);
    defer allocator.free(nonce_256);
    try std.testing.expectError(error.IllegalParameter, encodedLen(.{ .ticket_lifetime = 1, .ticket_age_add = 0, .ticket_nonce = nonce_256, .ticket = "x" }));

    const default_ticket = try allocator.alloc(u8, session.Limits.default.max_ticket_len);
    defer allocator.free(default_ticket);
    @memset(default_ticket, 0x02);
    const absolute_ticket = try allocator.alloc(u8, absolute_ticket_wire_max);
    defer allocator.free(absolute_ticket);
    @memset(absolute_ticket, 0x03);
    const default_buf = try allocator.alloc(u8, try encodedLen(.{ .ticket_lifetime = 1, .ticket_age_add = 0, .ticket_nonce = "", .ticket = default_ticket }));
    defer allocator.free(default_buf);
    try std.testing.expectEqual(default_ticket.len, (try decode(try encode(.{ .ticket_lifetime = 1, .ticket_age_add = 0, .ticket_nonce = "", .ticket = default_ticket }, default_buf))).ticket.len);
    const absolute_buf = try allocator.alloc(u8, try encodedLen(.{ .ticket_lifetime = 1, .ticket_age_add = 0, .ticket_nonce = "", .ticket = absolute_ticket }));
    defer allocator.free(absolute_buf);
    try std.testing.expectEqual(absolute_ticket.len, (try decode(try encode(.{ .ticket_lifetime = 1, .ticket_age_add = 0, .ticket_nonce = "", .ticket = absolute_ticket }, absolute_buf))).ticket.len);
    const over_ticket = try allocator.alloc(u8, absolute_ticket_wire_max + 1);
    defer allocator.free(over_ticket);
    try std.testing.expectError(error.IllegalParameter, encodedLen(.{ .ticket_lifetime = 1, .ticket_age_add = 0, .ticket_nonce = "", .ticket = over_ticket }));

    var empty_ticket = std.ArrayList(u8).empty;
    defer empty_ticket.deinit(allocator);
    try appendBaseTicketPrefix(&empty_ticket, 1, 0, "", "");
    try empty_ticket.appendSlice(allocator, &.{ 0, 0 });
    try std.testing.expectError(error.MalformedHandshake, decode(empty_ticket.items));
    var trailing = std.ArrayList(u8).empty;
    defer trailing.deinit(allocator);
    try appendBaseTicketPrefix(&trailing, 1, 0, "", "x");
    try trailing.appendSlice(allocator, &.{ 0, 0, 0xaa });
    try std.testing.expectError(error.MalformedHandshake, decode(trailing.items));

    var ext_zero = std.ArrayList(u8).empty;
    defer ext_zero.deinit(allocator);
    try appendBaseTicketPrefix(&ext_zero, 1, 0, "", "x");
    try ext_zero.appendSlice(allocator, &.{ 0, 0 });
    try std.testing.expectEqualSlices(u8, "x", (try decode(ext_zero.items)).ticket);
    var ext_short = std.ArrayList(u8).empty;
    defer ext_short.deinit(allocator);
    try appendBaseTicketPrefix(&ext_short, 1, 0, "", "x");
    try ext_short.appendSlice(allocator, &.{ 0, 3, 0, 42, 0 });
    try std.testing.expectError(error.MalformedHandshake, decode(ext_short.items));
    var ext_over_declared = std.ArrayList(u8).empty;
    defer ext_over_declared.deinit(allocator);
    try appendBaseTicketPrefix(&ext_over_declared, 1, 0, "", "x");
    try ext_over_declared.appendSlice(allocator, &.{ 0, 9 });
    try appendExtension(&ext_over_declared, ext_early_data, "\x00\x00\x00\x20");
    try std.testing.expectError(error.MalformedHandshake, decode(ext_over_declared.items));

    inline for (.{ 0, 3, 5 }) |bad_len| {
        var early = std.ArrayList(u8).empty;
        defer early.deinit(allocator);
        try appendBaseTicketPrefix(&early, 1, 0, "", "x");
        var ext_len: [2]u8 = undefined;
        std.mem.writeInt(u16, &ext_len, 4 + bad_len, .big);
        try early.appendSlice(allocator, &ext_len);
        var payload = [_]u8{0} ** 5;
        try appendExtension(&early, ext_early_data, payload[0..bad_len]);
        try std.testing.expectError(error.MalformedHandshake, decode(early.items));
    }
    var early_ok = std.ArrayList(u8).empty;
    defer early_ok.deinit(allocator);
    try appendBaseTicketPrefix(&early_ok, 1, 0, "", "x");
    try early_ok.appendSlice(allocator, &.{ 0, 8 });
    try appendExtension(&early_ok, ext_early_data, "\x00\x00\x00\x20");
    try std.testing.expectEqual(@as(?u32, 32), (try decode(early_ok.items)).max_early_data_size);

    var lifetime_ok = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 'x', 0, 0 };
    std.mem.writeInt(u32, lifetime_ok[0..4], max_lifetime_seconds, .big);
    try std.testing.expectEqual(max_lifetime_seconds, (try decode(&lifetime_ok)).ticket_lifetime);
    std.mem.writeInt(u32, lifetime_ok[0..4], max_lifetime_seconds + 1, .big);
    try std.testing.expectError(error.IllegalParameter, decode(&lifetime_ok));
    std.mem.writeInt(u32, lifetime_ok[0..4], 0, .big);
    try std.testing.expectEqual(@as(u32, 0), (try decode(&lifetime_ok)).ticket_lifetime);
}

test "server recoverable state honors caller ticket limits" {
    const context: ConnectionResumptionContext = .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .auth_binding = session.AuthBinding.fromLeafCertificateDer("leaf"),
    };
    const rms = [_]u8{0x42} ** 32;

    var default_over = [_]u8{0xa5} ** (session.Limits.default.max_ticket_len + 1);
    try std.testing.expectError(error.TicketTooLarge, buildServerRecoverableState(
        std.testing.allocator,
        testCryptoProvider(),
        .{
            .ticket_lifetime = 1,
            .ticket_age_add = 0,
            .ticket_nonce = "",
            .ticket = &default_over,
        },
        context,
        &rms,
        1,
        session.Limits.default,
    ));

    const custom_limits = session.Limits{ .max_ticket_len = default_over.len };
    var custom_state = try buildServerRecoverableState(
        std.testing.allocator,
        testCryptoProvider(),
        .{
            .ticket_lifetime = 1,
            .ticket_age_add = 0,
            .ticket_nonce = "",
            .ticket = &default_over,
        },
        context,
        &rms,
        1,
        custom_limits,
    );
    custom_state.deinit();

    const max_ticket = try std.testing.allocator.alloc(u8, absolute_ticket_wire_max);
    defer std.testing.allocator.free(max_ticket);
    @memset(max_ticket, 0x5a);
    var max_state = try buildServerRecoverableState(
        std.testing.allocator,
        testCryptoProvider(),
        .{
            .ticket_lifetime = 1,
            .ticket_age_add = 0,
            .ticket_nonce = "",
            .ticket = max_ticket,
        },
        context,
        &rms,
        1,
        .{ .max_ticket_len = absolute_ticket_wire_max, .max_serialized_len = session.Limits.default.max_serialized_len },
    );
    max_state.deinit();

    const one_over = try std.testing.allocator.alloc(u8, absolute_ticket_wire_max + 1);
    defer std.testing.allocator.free(one_over);
    @memset(one_over, 0x5b);
    try std.testing.expectError(error.IllegalParameter, buildServerRecoverableState(
        std.testing.allocator,
        testCryptoProvider(),
        .{
            .ticket_lifetime = 1,
            .ticket_age_add = 0,
            .ticket_nonce = "",
            .ticket = one_over,
        },
        context,
        &rms,
        1,
        .{ .max_ticket_len = absolute_ticket_wire_max },
    ));

    var nonce_255 = [_]u8{0x01} ** 255;
    var nonce_256 = [_]u8{0x02} ** 256;
    var nonce_state = try buildServerRecoverableState(
        std.testing.allocator,
        testCryptoProvider(),
        .{
            .ticket_lifetime = 1,
            .ticket_age_add = 0,
            .ticket_nonce = &nonce_255,
            .ticket = "ticket",
        },
        context,
        &rms,
        1,
        session.Limits.default,
    );
    nonce_state.deinit();
    try std.testing.expectError(error.IllegalParameter, buildServerRecoverableState(
        std.testing.allocator,
        testCryptoProvider(),
        .{
            .ticket_lifetime = 1,
            .ticket_age_add = 0,
            .ticket_nonce = &nonce_256,
            .ticket = "ticket",
        },
        context,
        &rms,
        1,
        session.Limits.default,
    ));
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
        testCryptoProvider(),
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

test "client ticket state derives distinct PSKs for distinct nonces" {
    const context: ConnectionResumptionContext = .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .auth_binding = session.AuthBinding.fromLeafCertificateDer("leaf"),
    };
    const rms = [_]u8{0x42} ** 32;
    var first = (try buildClientTicketState(
        std.testing.allocator,
        testCryptoProvider(),
        .{
            .ticket_lifetime = 60,
            .ticket_age_add = 0,
            .ticket_nonce = "\x01",
            .ticket = "ticket-1",
            .max_early_data_size = null,
        },
        context,
        &rms,
        10,
        session.Limits.default,
    )).?;
    defer first.deinit();
    var second = (try buildClientTicketState(
        std.testing.allocator,
        testCryptoProvider(),
        .{
            .ticket_lifetime = 60,
            .ticket_age_add = 0,
            .ticket_nonce = "\x02",
            .ticket = "ticket-2",
            .max_early_data_size = null,
        },
        context,
        &rms,
        10,
        session.Limits.default,
    )).?;
    defer second.deinit();
    try std.testing.expect(!std.mem.eql(u8, first.common.resumption_psk.slice(), second.common.resumption_psk.slice()));
}

test "ticket owned state builders and clone are allocation-failure clean" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, exerciseClientTicketBuild, .{});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, exerciseServerTicketBuild, .{});
    try std.testing.checkAllAllocationFailures(std.testing.allocator, exerciseClientTicketClone, .{});
}

fn allocationSweepContext() ConnectionResumptionContext {
    return .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .server_name = "example.com",
        .application_protocol = "h2",
        .auth_binding = session.AuthBinding.fromLeafCertificateDer("leaf"),
        .transport_compat = .{ .format_id = 1, .format_version = 1, .bytes = "transport-compat" },
        .application_compat = .{ .format_id = 2, .format_version = 1, .bytes = "application-compat" },
        .early_data_transport_compat = .{ .format_id = 3, .format_version = 1, .bytes = "early-transport-compat" },
        .early_data_application_compat = .{ .format_id = 4, .format_version = 1, .bytes = "early-application-compat" },
    };
}

fn exerciseClientTicketBuild(allocator: std.mem.Allocator) !void {
    const rms = [_]u8{0x42} ** 32;
    var state = (try buildClientTicketState(
        allocator,
        testCryptoProvider(),
        .{
            .ticket_lifetime = 60,
            .ticket_age_add = 0x11223344,
            .ticket_nonce = "\x01\x02",
            .ticket = "client-owned-ticket",
            .max_early_data_size = 32,
        },
        allocationSweepContext(),
        &rms,
        1234,
        session.Limits.default,
    )).?;
    defer state.deinit();
    try std.testing.expectEqualSlices(u8, "client-owned-ticket", state.ticket.slice());
    try std.testing.expectEqualSlices(u8, "\x01\x02", state.ticket_nonce.slice());
    try std.testing.expectEqualStrings("example.com", state.common.server_name.?.slice());
    try std.testing.expectEqualStrings("h2", state.common.application_protocol.?.slice());
    try std.testing.expect(state.common.transport_compat != null);
    try std.testing.expect(state.common.early_data_transport_compat != null);
    try std.testing.expect(state.common.application_compat != null);
    try std.testing.expect(state.common.early_data_application_compat != null);
}

fn exerciseServerTicketBuild(allocator: std.mem.Allocator) !void {
    const rms = [_]u8{0x42} ** 32;
    var state = try buildServerRecoverableState(
        allocator,
        testCryptoProvider(),
        .{
            .ticket_lifetime = 60,
            .ticket_age_add = 0x11223344,
            .ticket_nonce = "\x01\x02",
            .ticket = "server-owned-ticket",
            .max_early_data_size = 32,
        },
        allocationSweepContext(),
        &rms,
        1234,
        session.Limits.default,
    );
    defer state.deinit();
    try std.testing.expectEqualStrings("example.com", state.common.server_name.?.slice());
    try std.testing.expectEqualStrings("h2", state.common.application_protocol.?.slice());
    try std.testing.expect(state.common.transport_compat != null);
    try std.testing.expect(state.common.early_data_transport_compat != null);
    try std.testing.expect(state.common.application_compat != null);
    try std.testing.expect(state.common.early_data_application_compat != null);
}

fn exerciseClientTicketClone(allocator: std.mem.Allocator) !void {
    const rms = [_]u8{0x42} ** 32;
    var source = (try buildClientTicketState(
        std.testing.allocator,
        testCryptoProvider(),
        .{
            .ticket_lifetime = 60,
            .ticket_age_add = 0x11223344,
            .ticket_nonce = "\x01\x02",
            .ticket = "clone-owned-ticket",
            .max_early_data_size = 32,
        },
        allocationSweepContext(),
        &rms,
        1234,
        session.Limits.default,
    )).?;
    defer source.deinit();

    var clone: session.ClientTicketState = .{};
    try source.cloneInto(allocator, &clone);
    defer clone.deinit();
    try std.testing.expectEqualSlices(u8, source.ticket.slice(), clone.ticket.slice());
    try std.testing.expectEqualSlices(u8, source.ticket_nonce.slice(), clone.ticket_nonce.slice());
    try std.testing.expectEqualSlices(u8, source.common.resumption_psk.slice(), clone.common.resumption_psk.slice());
}

fn appendBaseTicketPrefix(
    list: *std.ArrayList(u8),
    lifetime: u32,
    age_add: u32,
    nonce: []const u8,
    ticket: []const u8,
) !void {
    const allocator = std.testing.allocator;
    var fixed: [4]u8 = undefined;
    std.mem.writeInt(u32, &fixed, lifetime, .big);
    try list.appendSlice(allocator, &fixed);
    std.mem.writeInt(u32, &fixed, age_add, .big);
    try list.appendSlice(allocator, &fixed);
    try list.append(allocator, @intCast(nonce.len));
    try list.appendSlice(allocator, nonce);
    var len: [2]u8 = undefined;
    std.mem.writeInt(u16, &len, @intCast(ticket.len), .big);
    try list.appendSlice(allocator, &len);
    try list.appendSlice(allocator, ticket);
}

fn appendExtension(list: *std.ArrayList(u8), ext_type: u16, payload: []const u8) !void {
    const allocator = std.testing.allocator;
    var encoded: [2]u8 = undefined;
    std.mem.writeInt(u16, &encoded, ext_type, .big);
    try list.appendSlice(allocator, &encoded);
    std.mem.writeInt(u16, &encoded, @intCast(payload.len), .big);
    try list.appendSlice(allocator, &encoded);
    try list.appendSlice(allocator, payload);
}

// -----------------------------------------------------------------------
// Fuzz target (#494): NewSessionTicket wire codec and owned-state
// construction.
//
// This complements the deterministic truncation/extension/limit coverage
// above (not duplicated here) with continuous mutation of the raw wire
// body plus control-derived owned-state construction through the real
// `buildClientTicketState`/`buildServerRecoverableStateNoIdentity` APIs.
// `std.testing.checkAllAllocationFailures` in
// "ticket owned state builders and clone are allocation-failure clean"
// above already sweeps `FailingAllocator` over a fixed representative
// shape; this target drives fuzzer-chosen shapes through the same APIs at
// `std.testing.allocator` rather than re-adding a second sweep.
// -----------------------------------------------------------------------

const fuzz_cipher_suites = [_]algorithms.CipherSuite{
    .tls_aes_128_gcm_sha256,
    .tls_aes_256_gcm_sha384,
    .tls_chacha20_poly1305_sha256,
};

/// True when `inner` is empty or is wholly contained within `outer`'s
/// backing bytes (pointer-range containment, not content equality) — the
/// #494 borrowed-slice-safety property for `decode`'s `ticket_nonce`/
/// `ticket` fields.
fn withinBounds(outer: []const u8, inner: []const u8) bool {
    if (inner.len == 0) return true;
    const outer_start = @intFromPtr(outer.ptr);
    const outer_end = outer_start + outer.len;
    const inner_start = @intFromPtr(inner.ptr);
    const inner_end = inner_start + inner.len;
    return inner_start >= outer_start and inner_end <= outer_end and inner_end >= inner_start;
}

fn fuzzLimits(control: u8) session.Limits {
    return switch (control % 4) {
        0 => .default,
        1 => .{ .max_ticket_len = 1 },
        2 => .{ .max_ticket_len = absolute_ticket_wire_max },
        else => .{ .max_ticket_len = @as(usize, control) + 1 },
    };
}

pub fn fuzzNewSessionTicket(allocator: std.mem.Allocator, smith: *std.testing.Smith) !void {
    // 1. Raw wire decode: bounded stack buffer, no allocator, matching the
    // real allocation-free `decode` contract.
    var wire_buf: [4096]u8 = undefined;
    const wire_len = smith.slice(&wire_buf);
    const wire = wire_buf[0..wire_len];

    if (decode(wire)) |parsed| {
        try std.testing.expect(withinBounds(wire, parsed.ticket_nonce));
        try std.testing.expect(withinBounds(wire, parsed.ticket));
    } else |_| {}

    // 2. Control-derived valid `EmitParams`, driving encode -> decode
    // structural round trips and owned-state construction. Fields are
    // bounded by construction (buffer sizes / modulo) rather than
    // allowing arbitrary unbounded values, per the #376 contract.
    // `ticket_buf` reaches exactly `session.Limits.default.max_ticket_len`
    // so generated cases exercise the configured default boundary, not
    // only small tickets; the absolute wire maximum
    // (`absolute_ticket_wire_max`) is already deterministically covered
    // by "server recoverable state honors caller ticket limits" above.
    const direction = smith.index(2);
    const suite = fuzz_cipher_suites[smith.index(fuzz_cipher_suites.len)];
    const digest_len = algorithms.transcriptHash(suite).digestLength();

    var nonce_buf: [max_ticket_nonce_len]u8 = undefined;
    const nonce_len = smith.index(nonce_buf.len + 1);
    smith.bytes(nonce_buf[0..nonce_len]);

    var ticket_buf: [session.Limits.default.max_ticket_len]u8 = undefined;
    const ticket_len = 1 + smith.index(ticket_buf.len);
    smith.bytes(ticket_buf[0..ticket_len]);

    const has_early_data = smith.index(2) == 1;
    var early_data_bytes: [4]u8 = undefined;
    smith.bytes(&early_data_bytes);
    const max_early_data_size: ?u32 = if (has_early_data) std.mem.readInt(u32, &early_data_bytes, .big) else null;

    var lifetime_bytes: [4]u8 = undefined;
    smith.bytes(&lifetime_bytes);
    const ticket_lifetime = std.mem.readInt(u32, &lifetime_bytes, .big) % (max_lifetime_seconds + 1);

    var age_add_bytes: [4]u8 = undefined;
    smith.bytes(&age_add_bytes);
    const ticket_age_add = std.mem.readInt(u32, &age_add_bytes, .big);

    const params = EmitParams{
        .ticket_lifetime = ticket_lifetime,
        .ticket_age_add = ticket_age_add,
        .ticket_nonce = nonce_buf[0..nonce_len],
        .ticket = ticket_buf[0..ticket_len],
        .max_early_data_size = max_early_data_size,
    };

    // Comfortably above the worst-case encoded length for the generated
    // shapes above (up to 4096-byte ticket + 255-byte nonce + extension +
    // fixed fields), so a non-trivial `encode_cap` routinely succeeds
    // instead of `OutputTooSmall` dominating every large-ticket case.
    var encode_buf: [8192]u8 = undefined;
    const encode_cap = smith.index(encode_buf.len + 1);
    const scratch = encode_buf[0..encode_cap];
    @memset(scratch, 0xa5);
    var before_buf: [8192]u8 = undefined;
    @memcpy(before_buf[0..encode_cap], scratch);

    const encoded = encode(params, scratch) catch {
        // `OutputTooSmall`/`IllegalParameter`/`LengthOverflow` must never
        // partially write the destination buffer.
        try std.testing.expectEqualSlices(u8, before_buf[0..encode_cap], scratch);
        return;
    };
    try std.testing.expectEqual(try encodedLen(params), encoded.len);
    const round = try decode(encoded);
    try std.testing.expectEqual(params.ticket_lifetime, round.ticket_lifetime);
    try std.testing.expectEqual(params.ticket_age_add, round.ticket_age_add);
    try std.testing.expectEqualSlices(u8, params.ticket_nonce, round.ticket_nonce);
    try std.testing.expectEqualSlices(u8, params.ticket, round.ticket);
    try std.testing.expectEqual(params.max_early_data_size, round.max_early_data_size);

    // 3. Owned-state construction from the round-tripped `Parsed` value,
    // exercising both client and server construction directions. `rms` is
    // sized to exactly the selected suite's transcript-hash digest length
    // (`KeySchedule.resumptionPsk` requires an exact match); a fixed
    // 48-byte slice would make both SHA-256 suites always fail with
    // `InvalidSecretLength`, silently skipping owned-state construction
    // for two of the three suites.
    var rms: [session.max_psk_len]u8 = undefined;
    smith.bytes(rms[0..digest_len]);
    var limits_control: [1]u8 = undefined;
    smith.bytes(&limits_control);
    const limits = fuzzLimits(limits_control[0]);

    const context = ConnectionResumptionContext{
        .cipher_suite = suite,
        .auth_binding = session.AuthBinding.fromLeafCertificateDer("fuzz-leaf"),
    };

    var received_at_bytes: [8]u8 = undefined;
    smith.bytes(&received_at_bytes);
    const received_at_unix_ms: i64 = @bitCast(std.mem.readInt(u64, &received_at_bytes, .big));

    // Fresh per-case deterministic entropy/provider pair, on this call's
    // own stack frame: the #376 contract forbids sharing one
    // process-global entropy stream across cases (unlike
    // `testCryptoProvider()` above, which this file's *deterministic*
    // tests intentionally share).
    const pure_zig = @import("crypto").pure_zig;
    var fuzz_entropy = pure_zig.DeterministicEntropy.init(0x1cec_5);
    var fuzz_provider = pure_zig.Provider.init(fuzz_entropy.entropy());
    const crypto_provider = fuzz_provider.cryptoProvider();

    if (direction == 0) {
        const build_result = buildClientTicketState(
            allocator,
            crypto_provider,
            round,
            context,
            rms[0..digest_len],
            received_at_unix_ms,
            limits,
        );
        if (round.ticket_lifetime == 0) {
            // `buildClientTicketState` returns `null` (not an error) for a
            // zero lifetime, before the ticket-size check below ever runs.
            try std.testing.expectEqual(@as(?session.ClientTicketState, null), try build_result);
            return;
        }
        if (round.ticket.len > limits.max_ticket_len) {
            try std.testing.expectError(error.TicketTooLarge, build_result);
            return;
        }
        var state = (try build_result).?;
        defer state.deinit();
        // The state must own its ticket/nonce bytes, not borrow `round`'s
        // view into `scratch`: poison `scratch` after construction and
        // confirm the state's content survives.
        @memset(scratch, 0xee);
        try std.testing.expectEqualSlices(u8, params.ticket, state.ticket.slice());
        try std.testing.expectEqualSlices(u8, params.ticket_nonce, state.ticket_nonce.slice());
    } else {
        const build_result = buildServerRecoverableStateNoIdentity(
            allocator,
            crypto_provider,
            .{
                .ticket_lifetime = round.ticket_lifetime,
                .ticket_age_add = round.ticket_age_add,
                .ticket_nonce = round.ticket_nonce,
                .max_early_data_size = round.max_early_data_size,
            },
            context,
            rms[0..digest_len],
            received_at_unix_ms,
            limits,
        );
        if (round.ticket_lifetime == 0) {
            // Unlike the client path, a zero lifetime is a hard error here
            // (no opaque bearer identity yet to fall back to `null` for).
            try std.testing.expectError(error.InvalidLifetime, build_result);
            return;
        }
        var state = try build_result;
        defer state.deinit();
        @memset(scratch, 0xee);
        try std.testing.expectEqual(round.ticket_age_add, state.ticket_age_add);
    }
}

test "fuzz: TLS resumption: NewSessionTicket wire decode and owned-state construction never panic or corrupt output" {
    try std.testing.fuzz({}, fuzzNewSessionTicketInput, .{ .corpus = &.{
        "",
        &[_]u8{ 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'x', 0, 0 },
        &[_]u8{ 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'x', 0, 8, 0, 42, 0, 4, 0, 0, 0, 0x20 },
        &[_]u8{ 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 1, 'x', 0, 4, 0x12, 0x34, 0, 0 },
        &[_]u8{ 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'x', 0, 8, 0x12, 0x34, 0, 0, 0x12, 0x34, 0, 0 },
        &[_]u8{ 0, 0, 0, 1, 0, 0, 0, 0 },
        &([_]u8{ 0, 0, 0, 1, 0, 0, 0, 0, 255 } ++ ([_]u8{1} ** 255) ++ [_]u8{ 0, 1, 'x', 0, 0 }),
        &[_]u8{ 0x00, 0x09, 0x3a, 0x80, 0, 0, 0, 0, 0, 0, 1, 'x', 0, 0 },
        &[_]u8{ 0x00, 0x09, 0x3a, 0x81, 0, 0, 0, 0, 0, 0, 1, 'x', 0, 0 },
        &([_]u8{0xff} ** 128),
    } });
}

fn fuzzNewSessionTicketInput(_: void, smith: *std.testing.Smith) !void {
    try fuzzNewSessionTicket(std.testing.allocator, smith);
}
