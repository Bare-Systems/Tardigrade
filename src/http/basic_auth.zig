const std = @import("std");
const Headers = @import("headers.zig").Headers;

pub const AUTHORIZATION_HEADER = "authorization";
pub const BASIC_SCHEME = "Basic";

pub const BasicAuthError = error{
    MissingAuthorization,
    InvalidAuthorizationScheme,
    MissingCredentials,
    InvalidBase64,
    MalformedCredentials,
    Unauthorized,
};

/// Decoded Basic auth credentials.
pub const Credentials = struct {
    username: []const u8,
    password: []const u8,
};

/// Parse an `Authorization: Basic <base64>` header value and return
/// the decoded username and password.
///
/// The returned slices point into `out_buf`, which must be large enough
/// to hold the decoded credentials (at most `base64_len * 3 / 4` bytes).
pub fn parseBasicCredentials(header_value: []const u8, out_buf: []u8) BasicAuthError!Credentials {
    const trimmed = std.mem.trim(u8, header_value, " \t");
    if (trimmed.len < BASIC_SCHEME.len + 1) return error.InvalidAuthorizationScheme;

    const scheme = trimmed[0..BASIC_SCHEME.len];
    if (!std.ascii.eqlIgnoreCase(scheme, BASIC_SCHEME)) return error.InvalidAuthorizationScheme;
    if (trimmed[BASIC_SCHEME.len] != ' ') return error.InvalidAuthorizationScheme;

    const encoded = std.mem.trim(u8, trimmed[BASIC_SCHEME.len + 1 ..], " \t");
    if (encoded.len == 0) return error.MissingCredentials;

    // Decode base64
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(encoded) catch return error.InvalidBase64;
    if (decoded_len > out_buf.len) return error.InvalidBase64;

    std.base64.standard.Decoder.decode(out_buf[0..decoded_len], encoded) catch return error.InvalidBase64;
    const decoded = out_buf[0..decoded_len];

    // Split on first ':'
    const colon = std.mem.indexOfScalar(u8, decoded, ':') orelse return error.MalformedCredentials;
    if (colon == 0) return error.MalformedCredentials;

    return .{
        .username = decoded[0..colon],
        .password = decoded[colon + 1 ..],
    };
}

/// Extract Basic credentials from request headers.
pub fn fromHeaders(headers: *const Headers, out_buf: []u8) BasicAuthError!Credentials {
    const auth = headers.get(AUTHORIZATION_HEADER) orelse return error.MissingAuthorization;
    return parseBasicCredentials(auth, out_buf);
}

/// Verify credentials against a SHA-256 hash of "user:password".
/// `allowed_hashes` contains lowercase hex SHA-256 hashes of "user:password" strings.
pub fn verifyCredentials(creds: Credentials, allowed_hashes: []const []const u8) bool {
    if (allowed_hashes.len == 0) return false;

    // Build "user:password" in a stack buffer
    var cred_buf: [512]u8 = undefined;
    if (creds.username.len + 1 + creds.password.len > cred_buf.len) return false;

    @memcpy(cred_buf[0..creds.username.len], creds.username);
    cred_buf[creds.username.len] = ':';
    @memcpy(cred_buf[creds.username.len + 1 ..][0..creds.password.len], creds.password);
    const cred_str = cred_buf[0 .. creds.username.len + 1 + creds.password.len];

    // SHA-256 hash
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(cred_str, &digest, .{});

    // Hex encode for comparison
    var hex_buf: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex_buf, "{s}", .{std.fmt.fmtSliceHexLower(&digest)}) catch return false;

    for (allowed_hashes) |allowed| {
        if (allowed.len == 64 and std.crypto.utils.timingSafeEql([64]u8, allowed[0..64].*, hex_buf)) {
            return true;
        }
    }
    return false;
}

// Tests

test "parseBasicCredentials decodes valid credentials" {
    // "admin:password" -> base64 "YWRtaW46cGFzc3dvcmQ="
    var buf: [256]u8 = undefined;
    const creds = try parseBasicCredentials("Basic YWRtaW46cGFzc3dvcmQ=", &buf);
    try std.testing.expectEqualStrings("admin", creds.username);
    try std.testing.expectEqualStrings("password", creds.password);
}

test "parseBasicCredentials handles empty password" {
    // "admin:" -> base64 "YWRtaW46"
    var buf: [256]u8 = undefined;
    const creds = try parseBasicCredentials("Basic YWRtaW46", &buf);
    try std.testing.expectEqualStrings("admin", creds.username);
    try std.testing.expectEqualStrings("", creds.password);
}

test "parseBasicCredentials case insensitive scheme" {
    var buf: [256]u8 = undefined;
    const creds = try parseBasicCredentials("bAsIc YWRtaW46cGFzc3dvcmQ=", &buf);
    try std.testing.expectEqualStrings("admin", creds.username);
    try std.testing.expectEqualStrings("password", creds.password);
}

test "parseBasicCredentials rejects bearer scheme" {
    var buf: [256]u8 = undefined;
    try std.testing.expectError(error.InvalidAuthorizationScheme, parseBasicCredentials("Bearer token123", &buf));
}

test "parseBasicCredentials rejects missing credentials" {
    var buf: [256]u8 = undefined;
    // "Basic " with only whitespace after the scheme
    try std.testing.expectError(error.InvalidAuthorizationScheme, parseBasicCredentials("Basic ", &buf));
    try std.testing.expectError(error.InvalidAuthorizationScheme, parseBasicCredentials("Basic    ", &buf));
}

test "parseBasicCredentials rejects invalid base64" {
    var buf: [256]u8 = undefined;
    try std.testing.expectError(error.InvalidBase64, parseBasicCredentials("Basic !!!invalid!!!", &buf));
}

test "parseBasicCredentials rejects missing colon" {
    // "nocolon" -> base64 "bm9jb2xvbg=="
    var buf: [256]u8 = undefined;
    try std.testing.expectError(error.MalformedCredentials, parseBasicCredentials("Basic bm9jb2xvbg==", &buf));
}

test "parseBasicCredentials rejects empty username" {
    // ":password" -> base64 "OnBhc3N3b3Jk"
    var buf: [256]u8 = undefined;
    try std.testing.expectError(error.MalformedCredentials, parseBasicCredentials("Basic OnBhc3N3b3Jk", &buf));
}

test "fromHeaders extracts credentials" {
    const allocator = std.testing.allocator;
    var headers = Headers.init(allocator);
    defer headers.deinit();
    try headers.append("Authorization", "Basic YWRtaW46cGFzc3dvcmQ=");

    var buf: [256]u8 = undefined;
    const creds = try fromHeaders(&headers, &buf);
    try std.testing.expectEqualStrings("admin", creds.username);
    try std.testing.expectEqualStrings("password", creds.password);
}

test "fromHeaders returns error when no auth header" {
    const allocator = std.testing.allocator;
    var headers = Headers.init(allocator);
    defer headers.deinit();

    var buf: [256]u8 = undefined;
    try std.testing.expectError(error.MissingAuthorization, fromHeaders(&headers, &buf));
}

test "verifyCredentials accepts valid hash" {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("admin:password", &digest, .{});
    var expected: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&expected, "{s}", .{std.fmt.fmtSliceHexLower(&digest)}) catch unreachable;

    const hashes = &[_][]const u8{expected[0..]};
    const creds = Credentials{ .username = "admin", .password = "password" };
    try std.testing.expect(verifyCredentials(creds, hashes));
}

test "verifyCredentials rejects wrong credentials" {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("admin:password", &digest, .{});
    var expected: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&expected, "{s}", .{std.fmt.fmtSliceHexLower(&digest)}) catch unreachable;

    const hashes = &[_][]const u8{expected[0..]};
    const creds = Credentials{ .username = "admin", .password = "wrong" };
    try std.testing.expect(!verifyCredentials(creds, hashes));
}

test "verifyCredentials rejects empty hash list" {
    const creds = Credentials{ .username = "admin", .password = "password" };
    try std.testing.expect(!verifyCredentials(creds, &[_][]const u8{}));
}
