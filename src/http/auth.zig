const std = @import("std");
const Headers = @import("headers.zig").Headers;

pub const AUTHORIZATION_HEADER = "authorization";
pub const BEARER_SCHEME = "Bearer";
pub const MAX_BEARER_TOKEN_LEN: usize = 4096;

pub const ValidationHook = *const fn (token: []const u8) bool;

pub const AuthorizationError = error{
    MissingAuthorization,
    InvalidAuthorizationScheme,
    MissingBearerToken,
    InvalidBearerToken,
    Unauthorized,
};

/// RFC 6750 `b64token` style characters.
fn isBearerTokenChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == '_' or c == '~' or c == '+' or c == '/' or c == '=';
}

pub fn isValidBearerToken(token: []const u8) bool {
    if (token.len == 0 or token.len > MAX_BEARER_TOKEN_LEN) return false;
    for (token) |c| {
        if (!isBearerTokenChar(c)) return false;
    }
    return true;
}

/// Parse an Authorization header and return the bearer token slice.
pub fn parseBearerToken(header_value: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, header_value, " \t");
    if (trimmed.len < BEARER_SCHEME.len + 1) return null;

    const scheme = trimmed[0..BEARER_SCHEME.len];
    if (!std.ascii.eqlIgnoreCase(scheme, BEARER_SCHEME)) return null;
    if (trimmed[BEARER_SCHEME.len] != ' ') return null;

    const token = std.mem.trim(u8, trimmed[BEARER_SCHEME.len + 1 ..], " \t");
    if (token.len == 0) return null;
    if (std.mem.findAny(u8, token, " \t")) |_| return null;
    return token;
}

pub fn bearerTokenFromHeaders(headers: *const Headers) ?[]const u8 {
    const auth = headers.get(AUTHORIZATION_HEADER) orelse return null;
    return parseBearerToken(auth);
}

pub fn validateBearerToken(token: []const u8, hook: ?ValidationHook) bool {
    if (!isValidBearerToken(token)) return false;
    if (hook) |validator| {
        return validator(token);
    }
    return true;
}

pub fn authorize(headers: *const Headers, hook: ?ValidationHook) AuthorizationError![]const u8 {
    const auth = headers.get(AUTHORIZATION_HEADER) orelse return error.MissingAuthorization;
    const token = parseBearerToken(auth) orelse {
        const trimmed = std.mem.trim(u8, auth, " \t");
        if (trimmed.len < BEARER_SCHEME.len or !std.ascii.eqlIgnoreCase(trimmed[0..@min(trimmed.len, BEARER_SCHEME.len)], BEARER_SCHEME)) {
            return error.InvalidAuthorizationScheme;
        }
        if (trimmed.len == BEARER_SCHEME.len) return error.MissingBearerToken;
        return error.InvalidBearerToken;
    };

    if (!validateBearerToken(token, hook)) {
        return error.Unauthorized;
    }
    return token;
}

test "parseBearerToken extracts bearer token with mixed case scheme" {
    const token = parseBearerToken("bEaReR abc.DEF_123~+/=") orelse unreachable;
    try std.testing.expectEqualStrings("abc.DEF_123~+/=", token);
}

test "parseBearerToken rejects non-bearer and malformed formats" {
    try std.testing.expect(parseBearerToken("Basic abc") == null);
    try std.testing.expect(parseBearerToken("Bearer") == null);
    try std.testing.expect(parseBearerToken("Bearer   ") == null);
    try std.testing.expect(parseBearerToken("Bearer two parts") == null);
}

test "validateBearerToken enforces character set and optional hook" {
    const local = struct {
        fn onlyAllowTrusted(token: []const u8) bool {
            return std.mem.eql(u8, token, "trusted-token");
        }
    };

    try std.testing.expect(validateBearerToken("abc.DEF_123", null));
    try std.testing.expect(!validateBearerToken("bad token", null));
    try std.testing.expect(validateBearerToken("trusted-token", local.onlyAllowTrusted));
    try std.testing.expect(!validateBearerToken("other-token", local.onlyAllowTrusted));
}

test "authorize returns parsed token and expected errors" {
    const allocator = std.testing.allocator;
    var headers = Headers.init(allocator);
    defer headers.deinit();

    try std.testing.expectError(error.MissingAuthorization, authorize(&headers, null));

    try headers.append("Authorization", "Basic abc");
    try std.testing.expectError(error.InvalidAuthorizationScheme, authorize(&headers, null));

    headers.deinit();
    headers = Headers.init(allocator);
    try headers.append("Authorization", "Bearer bad token");
    try std.testing.expectError(error.InvalidBearerToken, authorize(&headers, null));

    headers.deinit();
    headers = Headers.init(allocator);
    try headers.append("Authorization", "Bearer okay-token");
    const local = struct {
        fn denyAll(_: []const u8) bool {
            return false;
        }
    };
    try std.testing.expectError(error.Unauthorized, authorize(&headers, local.denyAll));

    const token = try authorize(&headers, null);
    try std.testing.expectEqualStrings("okay-token", token);
}
