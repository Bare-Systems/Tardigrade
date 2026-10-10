//! CA URL rules (#832, design §4.3 and §6.3).
//!
//! Every URL that reaches the transport — the operator's directory URL and
//! every URL the CA hands back (`newAccount`, `Location`, ...) — passes
//! through `parse`. CA-supplied URLs additionally pass `requireCaOrigin`,
//! which pins them to the directory's host and port unless the operator opted
//! into cross-host URLs. That is the SSRF boundary: a malicious or
//! compromised directory cannot steer signed requests at internal hosts.
//!
//! Deliberately narrow grammar: `https://` only, ASCII only, a DNS-style or
//! IPv4 host (no IPv6 literals, no userinfo, no fragment), an optional port,
//! and a path/query of printable ASCII. Anything outside it is rejected, not
//! normalized, so the validated string is exactly what is sent and logged.

const std = @import("std");

pub const max_url_len = 2048;
pub const max_host_len = 253;

pub const Error = error{
    InvalidUrl,
    NotHttps,
    UrlTooLong,
    UserInfo,
    Fragment,
    InvalidHost,
    InvalidPort,
    /// Not the directory's host and port (and cross-host URLs are off).
    CrossHostUrl,
};

/// Borrowed view into the validated URL string.
pub const Url = struct {
    host: []const u8,
    port: u16,
    /// Always begins with `/`; includes any query.
    target: []const u8,

    pub fn sameOrigin(self: Url, other: Url) bool {
        return self.port == other.port and std.ascii.eqlIgnoreCase(self.host, other.host);
    }

    /// `Host` header value: the port is omitted when it is the https default.
    pub fn writeHostHeader(self: Url, out: []u8) ?[]const u8 {
        if (self.port == 443) {
            if (self.host.len > out.len) return null;
            @memcpy(out[0..self.host.len], self.host);
            return out[0..self.host.len];
        }
        return std.fmt.bufPrint(out, "{s}:{d}", .{ self.host, self.port }) catch null;
    }
};

pub fn parse(url: []const u8) Error!Url {
    if (url.len > max_url_len) return error.UrlTooLong;
    const scheme = "https://";
    if (url.len < scheme.len or !std.ascii.eqlIgnoreCase(url[0..scheme.len], scheme)) {
        // Make the common mistake legible; everything else is just invalid.
        if (url.len >= 7 and std.ascii.eqlIgnoreCase(url[0..7], "http://")) return error.NotHttps;
        return error.InvalidUrl;
    }
    for (url) |byte| {
        if (byte < 0x21 or byte > 0x7e or byte == '\\') return error.InvalidUrl;
    }
    const rest = url[scheme.len..];
    if (std.mem.indexOfScalar(u8, rest, '#') != null) return error.Fragment;

    const authority_end = std.mem.indexOfAny(u8, rest, "/?") orelse rest.len;
    const authority = rest[0..authority_end];
    if (std.mem.indexOfScalar(u8, authority, '@') != null) return error.UserInfo;

    var host = authority;
    var port: u16 = 443;
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| {
        host = authority[0..colon];
        const digits = authority[colon + 1 ..];
        if (digits.len == 0 or digits.len > 5) return error.InvalidPort;
        for (digits) |d| if (d < '0' or d > '9') return error.InvalidPort;
        const value = std.fmt.parseInt(u32, digits, 10) catch return error.InvalidPort;
        if (value == 0 or value > 65535) return error.InvalidPort;
        port = @intCast(value);
    }
    try validateHost(host);

    // An empty path is "/"; a query without a path would need a synthesized
    // "/", so require the explicit form instead.
    const target = rest[authority_end..];
    if (target.len == 0) return .{ .host = host, .port = port, .target = "/" };
    if (target[0] != '/') return error.InvalidUrl;
    return .{ .host = host, .port = port, .target = target };
}

fn validateHost(host: []const u8) Error!void {
    if (host.len == 0 or host.len > max_host_len) return error.InvalidHost;
    var label_len: usize = 0;
    var prev: u8 = '.';
    for (host) |c| {
        const alnum = (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9');
        if (alnum) {
            label_len += 1;
        } else if (c == '-') {
            if (prev == '.') return error.InvalidHost; // label cannot start with '-'
            label_len += 1;
        } else if (c == '.') {
            if (label_len == 0) return error.InvalidHost; // empty label / leading dot
            if (prev == '-') return error.InvalidHost;
            label_len = 0;
        } else {
            return error.InvalidHost;
        }
        if (label_len > 63) return error.InvalidHost;
        prev = c;
    }
    if (label_len == 0 or prev == '-') return error.InvalidHost; // trailing dot or dash
}

/// Parse a CA-supplied URL and require it to share the directory's origin.
pub fn requireCaOrigin(url: []const u8, directory: Url, allow_cross_host: bool) Error!Url {
    const parsed = try parse(url);
    if (!allow_cross_host and !parsed.sameOrigin(directory)) return error.CrossHostUrl;
    return parsed;
}

// ---------------------------------------------------------------------------

const testing = std.testing;

test "ACME url: accepts https URLs and extracts host, port and target" {
    const a = try parse("https://acme-v02.api.letsencrypt.org/directory");
    try testing.expectEqualStrings("acme-v02.api.letsencrypt.org", a.host);
    try testing.expectEqual(@as(u16, 443), a.port);
    try testing.expectEqualStrings("/directory", a.target);

    const b = try parse("https://localhost:14000/dir?x=1");
    try testing.expectEqualStrings("localhost", b.host);
    try testing.expectEqual(@as(u16, 14000), b.port);
    try testing.expectEqualStrings("/dir?x=1", b.target);

    const c = try parse("HTTPS://CA.Test");
    try testing.expectEqualStrings("/", c.target);
    const d = try parse("https://127.0.0.1:8443/x");
    try testing.expectEqualStrings("127.0.0.1", d.host);
}

test "ACME url: rejects every unsafe or malformed shape" {
    const cases = [_]struct { url: []const u8, err: Error }{
        .{ .url = "", .err = error.InvalidUrl },
        .{ .url = "http://ca.test/dir", .err = error.NotHttps },
        .{ .url = "ftp://ca.test/dir", .err = error.InvalidUrl },
        .{ .url = "file:///etc/passwd", .err = error.InvalidUrl },
        .{ .url = "//ca.test/dir", .err = error.InvalidUrl },
        .{ .url = "https:/ca.test", .err = error.InvalidUrl },
        .{ .url = "https://user@ca.test/dir", .err = error.UserInfo },
        .{ .url = "https://user:pw@ca.test/dir", .err = error.UserInfo },
        .{ .url = "https://ca.test/dir#frag", .err = error.Fragment },
        .{ .url = "https://ca.test:0/dir", .err = error.InvalidPort },
        .{ .url = "https://ca.test:65536/dir", .err = error.InvalidPort },
        .{ .url = "https://ca.test:abc/dir", .err = error.InvalidPort },
        .{ .url = "https://ca.test:/dir", .err = error.InvalidPort },
        .{ .url = "https://[::1]/dir", .err = error.InvalidPort },
        .{ .url = "https:///dir", .err = error.InvalidHost },
        .{ .url = "https://.ca.test/dir", .err = error.InvalidHost },
        .{ .url = "https://ca..test/dir", .err = error.InvalidHost },
        .{ .url = "https://ca.test./dir", .err = error.InvalidHost },
        .{ .url = "https://-ca.test/dir", .err = error.InvalidHost },
        .{ .url = "https://ca-.test/dir", .err = error.InvalidHost },
        .{ .url = "https://ca_test/dir", .err = error.InvalidHost },
        .{ .url = "https://ca.test?x=1", .err = error.InvalidUrl },
        .{ .url = "https://ca.test/di r", .err = error.InvalidUrl },
        .{ .url = "https://ca.test/di\tr", .err = error.InvalidUrl },
        .{ .url = "https://ca.test/dir\r\nHost: evil", .err = error.InvalidUrl },
        .{ .url = "https://ca.test/\\evil", .err = error.InvalidUrl },
        .{ .url = "https://ca.t\xc3\xa9st/dir", .err = error.InvalidUrl },
        .{ .url = "https://" ++ ("a" ** 64) ++ ".test/", .err = error.InvalidHost },
    };
    for (cases) |case| {
        try testing.expectError(case.err, parse(case.url));
    }
    try testing.expectError(error.UrlTooLong, parse("https://ca.test/" ++ ("a" ** max_url_len)));
}

test "ACME url: CA-supplied URLs are pinned to the directory origin" {
    const dir = try parse("https://ca.test/directory");
    _ = try requireCaOrigin("https://ca.test/new-acct", dir, false);
    _ = try requireCaOrigin("https://CA.TEST/new-acct", dir, false);
    _ = try requireCaOrigin("https://ca.test:443/new-acct", dir, false);

    try testing.expectError(error.CrossHostUrl, requireCaOrigin("https://other.test/new-acct", dir, false));
    try testing.expectError(error.CrossHostUrl, requireCaOrigin("https://ca.test:8443/new-acct", dir, false));
    try testing.expectError(error.CrossHostUrl, requireCaOrigin("https://127.0.0.1/", dir, false));
    try testing.expectError(error.CrossHostUrl, requireCaOrigin("https://169.254.169.254/latest/meta-data", dir, false));
    try testing.expectError(error.CrossHostUrl, requireCaOrigin("https://ca.test.evil.test/x", dir, false));
    try testing.expectError(error.CrossHostUrl, requireCaOrigin("https://xca.test/x", dir, false));
    // Syntax is still enforced when cross-host URLs are allowed.
    _ = try requireCaOrigin("https://other.test/x", dir, true);
    try testing.expectError(error.NotHttps, requireCaOrigin("http://other.test/x", dir, true));
    try testing.expectError(error.UserInfo, requireCaOrigin("https://u@other.test/x", dir, true));
}

test "ACME url: host header omits only the default port" {
    var buf: [300]u8 = undefined;
    try testing.expectEqualStrings("ca.test", (try parse("https://ca.test/x")).writeHostHeader(&buf).?);
    try testing.expectEqualStrings("ca.test:8443", (try parse("https://ca.test:8443/x")).writeHostHeader(&buf).?);
}

fn fuzzUrl(_: void, smith: *testing.Smith) !void {
    var buf: [256]u8 = undefined;
    const len = smith.slice(&buf);
    const parsed = parse(buf[0..len]) catch return;
    // Anything admitted is printable ASCII, https, and re-parses identically.
    try testing.expect(parsed.port != 0);
    try testing.expect(parsed.target[0] == '/');
    try testing.expect(parsed.host.len > 0 and parsed.host.len <= max_host_len);
    for (buf[0..len]) |byte| try testing.expect(byte > 0x20 and byte < 0x7f);
}

test "fuzz: ACME: CA URL grammar admits only printable-ASCII https origins" {
    try testing.fuzz({}, fuzzUrl, .{ .corpus = &.{
        "https://ca.test/dir",
        "https://ca.test:443/dir?x=1",
        "http://ca.test",
        "https://u@ca.test",
        "https://ca.test#x",
        "https://[::1]:80/",
        "https://" ++ ("a." ** 40),
        "https://ca.test/\x00",
    } });
}
