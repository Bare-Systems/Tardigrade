const std = @import("std");

const ParsedClaims = struct {
    issuer: ?[]const u8,
    audience: ?[]const u8,
    subject: ?[]const u8,
    expires_at: ?i64,
    scope: ?[]const u8,
    device_id: ?[]const u8,
};

pub const Claims = struct {
    subject_present: bool,
    expires_at: ?i64,
};

pub const OwnedClaims = struct {
    subject: ?[]u8,
    expires_at: ?i64,
    scope: ?[]u8,
    device_id: ?[]u8,

    pub fn deinit(self: *OwnedClaims, allocator: std.mem.Allocator) void {
        if (self.subject) |value| allocator.free(value);
        if (self.scope) |value| allocator.free(value);
        if (self.device_id) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub const Options = struct {
    secret: []const u8,
    required_issuer: ?[]const u8 = null,
    required_audience: ?[]const u8 = null,
    now_unix: i64 = 0,
};

pub fn validateHs256(allocator: std.mem.Allocator, token: []const u8, opts: Options) !Claims {
    const parsed = try parseAndValidateHs256(allocator, token, opts);
    return .{ .subject_present = parsed.subject != null, .expires_at = parsed.expires_at };
}

pub fn validateHs256Owned(allocator: std.mem.Allocator, token: []const u8, opts: Options) !OwnedClaims {
    _ = try validateHs256(allocator, token, opts);

    var parts = std.mem.splitScalar(u8, token, '.');
    _ = parts.next() orelse return error.InvalidTokenFormat;
    const payload_b64 = parts.next() orelse return error.InvalidTokenFormat;
    _ = parts.next() orelse return error.InvalidTokenFormat;
    if (parts.next() != null) return error.InvalidTokenFormat;

    const dec = std.base64.url_safe_no_pad.Decoder;
    const payload_len = try dec.calcSizeForSlice(payload_b64);
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    _ = try dec.decode(payload, payload_b64);

    var parsed_payload = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
    defer parsed_payload.deinit();
    const obj = parsed_payload.value.object;

    return .{
        .subject = if (obj.get("sub")) |value|
            if (value == .string) try allocator.dupe(u8, value.string) else return error.InvalidClaim
        else
            null,
        .expires_at = if (obj.get("exp")) |value|
            if (value == .integer) @as(i64, @intCast(value.integer)) else return error.InvalidClaim
        else
            null,
        .scope = if (obj.get("scope")) |value|
            if (value == .string) try allocator.dupe(u8, value.string) else return error.InvalidClaim
        else
            null,
        .device_id = if (obj.get("device_id")) |value|
            if (value == .string) try allocator.dupe(u8, value.string) else return error.InvalidClaim
        else
            null,
    };
}

fn parseAndValidateHs256(allocator: std.mem.Allocator, token: []const u8, opts: Options) !ParsedClaims {
    if (opts.secret.len == 0) return error.MissingSecret;
    var parts = std.mem.splitScalar(u8, token, '.');
    const header_b64 = parts.next() orelse return error.InvalidTokenFormat;
    const payload_b64 = parts.next() orelse return error.InvalidTokenFormat;
    const sig_b64 = parts.next() orelse return error.InvalidTokenFormat;
    if (parts.next() != null) return error.InvalidTokenFormat;

    const dot1 = std.mem.indexOfScalar(u8, token, '.') orelse return error.InvalidTokenFormat;
    const dot2_rel = std.mem.indexOfScalar(u8, token[dot1 + 1 ..], '.') orelse return error.InvalidTokenFormat;
    const dot2 = dot1 + 1 + dot2_rel;
    const signing_input = token[0..dot2];

    const dec = std.base64.url_safe_no_pad.Decoder;
    const header_len = try dec.calcSizeForSlice(header_b64);
    const payload_len = try dec.calcSizeForSlice(payload_b64);
    const sig_len = try dec.calcSizeForSlice(sig_b64);
    const header = try allocator.alloc(u8, header_len);
    defer allocator.free(header);
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    const sig = try allocator.alloc(u8, sig_len);
    defer allocator.free(sig);
    _ = try dec.decode(header, header_b64);
    _ = try dec.decode(payload, payload_b64);
    _ = try dec.decode(sig, sig_b64);

    var parsed_header = try std.json.parseFromSlice(std.json.Value, allocator, header, .{});
    defer parsed_header.deinit();
    const alg = parsed_header.value.object.get("alg") orelse return error.InvalidAlgorithm;
    if (alg != .string or !std.mem.eql(u8, alg.string, "HS256")) return error.InvalidAlgorithm;

    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, signing_input, opts.secret);
    if (sig.len != 32) return error.InvalidSignature;
    if (!std.crypto.utils.timingSafeEql([32]u8, sig[0..32].*, mac)) return error.InvalidSignature;

    var parsed_payload = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{});
    defer parsed_payload.deinit();
    const obj = parsed_payload.value.object;

    const issuer = if (obj.get("iss")) |iss| blk: {
        if (iss != .string) return error.InvalidClaim;
        break :blk iss.string;
    } else null;
    const audience = if (obj.get("aud")) |aud| blk: {
        if (aud == .string) break :blk aud.string;
        if (aud == .array and aud.array.items.len > 0 and aud.array.items[0] == .string) break :blk aud.array.items[0].string;
        return error.InvalidClaim;
    } else null;
    const subject = if (obj.get("sub")) |sub| blk: {
        if (sub != .string) return error.InvalidClaim;
        break :blk sub.string;
    } else null;
    const expires_at = if (obj.get("exp")) |exp| blk: {
        if (exp != .integer) return error.InvalidClaim;
        break :blk @as(i64, @intCast(exp.integer));
    } else null;

    if (opts.required_issuer) |iss| {
        if (issuer == null or !std.mem.eql(u8, issuer.?, iss)) return error.IssuerMismatch;
    }
    if (opts.required_audience) |aud| {
        if (audience == null or !std.mem.eql(u8, audience.?, aud)) return error.AudienceMismatch;
    }
    const now_unix = if (opts.now_unix == 0) std.time.timestamp() else opts.now_unix;
    if (expires_at) |exp| {
        if (now_unix >= exp) return error.TokenExpired;
    }

    const scope = if (obj.get("scope")) |value| blk: {
        if (value != .string) return error.InvalidClaim;
        break :blk value.string;
    } else null;
    const device_id = if (obj.get("device_id")) |value| blk: {
        if (value != .string) return error.InvalidClaim;
        break :blk value.string;
    } else null;

    return .{
        .issuer = issuer,
        .audience = audience,
        .subject = subject,
        .expires_at = expires_at,
        .scope = scope,
        .device_id = device_id,
    };
}

test "validateHs256 accepts valid signed token" {
    const allocator = std.testing.allocator;
    const header_json = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    const payload_json = "{\"sub\":\"user-1\",\"iss\":\"issuer-a\",\"aud\":\"aud-a\",\"exp\":4102444800}";

    var header_buf: [128]u8 = undefined;
    var payload_buf: [256]u8 = undefined;
    const enc = std.base64.url_safe_no_pad.Encoder;
    const header_b64 = enc.encode(header_buf[0..enc.calcSize(header_json.len)], header_json);
    const payload_b64 = enc.encode(payload_buf[0..enc.calcSize(payload_json.len)], payload_json);
    const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ header_b64, payload_b64 });
    defer allocator.free(signing_input);

    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, signing_input, "secret");
    var sig_buf: [128]u8 = undefined;
    const sig_b64 = enc.encode(sig_buf[0..enc.calcSize(mac.len)], mac[0..]);
    const token = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ signing_input, sig_b64 });
    defer allocator.free(token);

    const claims = try validateHs256(allocator, token, .{
        .secret = "secret",
        .required_issuer = "issuer-a",
        .required_audience = "aud-a",
        .now_unix = 1_700_000_000,
    });
    try std.testing.expect(claims.subject_present);
}

test "validateHs256 rejects invalid signature" {
    const allocator = std.testing.allocator;
    const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1In0.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    try std.testing.expectError(error.InvalidSignature, validateHs256(allocator, token, .{ .secret = "secret" }));
}

test "validateHs256Owned exposes subject scope and device_id" {
    const allocator = std.testing.allocator;
    const header_json = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    const payload_json = "{\"sub\":\"user-42\",\"iss\":\"issuer-a\",\"aud\":\"aud-a\",\"scope\":\"bearclaw.operator\",\"device_id\":\"bearclaw-web\",\"exp\":4102444800}";

    var header_buf: [128]u8 = undefined;
    var payload_buf: [256]u8 = undefined;
    const enc = std.base64.url_safe_no_pad.Encoder;
    const header_b64 = enc.encode(header_buf[0..enc.calcSize(header_json.len)], header_json);
    const payload_b64 = enc.encode(payload_buf[0..enc.calcSize(payload_json.len)], payload_json);
    const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ header_b64, payload_b64 });
    defer allocator.free(signing_input);

    var mac: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, signing_input, "secret");
    var sig_buf: [128]u8 = undefined;
    const sig_b64 = enc.encode(sig_buf[0..enc.calcSize(mac.len)], mac[0..]);
    const token = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ signing_input, sig_b64 });
    defer allocator.free(token);

    var claims = try validateHs256Owned(allocator, token, .{
        .secret = "secret",
        .required_issuer = "issuer-a",
        .required_audience = "aud-a",
        .now_unix = 1_700_000_000,
    });
    defer claims.deinit(allocator);

    try std.testing.expectEqualStrings("user-42", claims.subject.?);
    try std.testing.expectEqualStrings("bearclaw.operator", claims.scope.?);
    try std.testing.expectEqualStrings("bearclaw-web", claims.device_id.?);
}
