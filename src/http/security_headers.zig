const std = @import("std");
const Response = @import("response.zig").Response;

/// A response header scoped to the request currently being handled on this
/// thread (#761: `forward_auth_client_headers` on an allowed request).
pub const ScopedHeader = struct {
    name: []const u8,
    value: []const u8,
};

/// Shared-cache policy for a response to a request that passed
/// `forward_auth` (#761). A protected response must never be stored by a
/// shared cache: the next request would be answered without the auth check.
pub const ProtectedCachePolicy = enum {
    /// Not a forward_auth-protected response.
    none,
    /// Protected: keep the origin's directives but make them `private`,
    /// dropping `public`, `s-maxage` and `proxy-revalidate`.
    private,
    /// Protected and carrying auth-issued headers such as a session cookie:
    /// `no-store` outright.
    no_store,
};

/// HTTP/1.1 handles one request at a time per worker thread, and every H1
/// response head passes through `SecurityHeaders.apply` or the raw
/// security-header writer. Scoping extra headers and the cache policy here
/// lets them reach proxied (buffered and streamed), static, local and upgrade
/// responses without threading them through each writer. Callers must pair
/// `set` with `clear`.
threadlocal var request_scoped_headers: []const ScopedHeader = &.{};
threadlocal var request_cache_policy: ProtectedCachePolicy = .none;

pub fn setRequestScope(headers: []const ScopedHeader, cache_policy: ProtectedCachePolicy) void {
    request_scoped_headers = headers;
    request_cache_policy = cache_policy;
}

pub fn clearRequestScope() void {
    request_scoped_headers = &.{};
    request_cache_policy = .none;
}

pub fn requestScopedHeaders() []const ScopedHeader {
    return request_scoped_headers;
}

pub fn requestCachePolicy() ProtectedCachePolicy {
    return request_cache_policy;
}

/// True for response fields a cache in front of Tardigrade may use to decide
/// whether and how long to store a response. `Cache-Control` plus the
/// vendor fields that CDNs and reverse proxies honor *over* it: Cloudflare's
/// `CDN-Cache-Control`/`Cloudflare-CDN-Cache-Control`, Fastly and others'
/// `Surrogate-Control`, Akamai's `Edge-Control`, and nginx's
/// `X-Accel-Expires`. A protected response must carry none of the origin's.
pub fn isProtectedCacheField(name: []const u8) bool {
    const fields = [_][]const u8{
        "cache-control",     "cdn-cache-control", "cloudflare-cdn-cache-control",
        "surrogate-control", "edge-control",      "x-accel-expires",
    };
    for (fields) |field| {
        if (std.ascii.eqlIgnoreCase(name, field)) return true;
    }
    return false;
}

/// True when a raw writer must not forward the origin's value of `name`
/// because the request scope replaces it.
pub fn requestScopeReplacesHeader(name: []const u8) bool {
    return request_cache_policy != .none and isProtectedCacheField(name);
}

/// Folds every origin `Cache-Control` field into the one protected value.
/// `no-store` in any field dominates. Otherwise the result is unqualified
/// `private` plus the origin's remaining directives, first occurrence of each
/// name winning, with shared-cache permissions dropped. Falls back to
/// `no-store` if the rewritten directives would not fit `buf`.
pub const CacheControlFold = struct {
    policy: ProtectedCachePolicy,
    out: std.ArrayList(u8),
    names: [16][]const u8 = undefined,
    name_count: usize = 0,
    no_store: bool = false,

    pub fn init(buf: []u8, policy: ProtectedCachePolicy) CacheControlFold {
        std.debug.assert(policy != .none);
        var fold = CacheControlFold{ .policy = policy, .out = .initBuffer(buf) };
        fold.out.appendSliceBounded("private") catch unreachable; // buf >= 7 bytes
        fold.no_store = policy == .no_store;
        return fold;
    }

    pub fn add(self: *CacheControlFold, field_value: []const u8) void {
        if (self.no_store) return;
        var directives = std.mem.splitScalar(u8, field_value, ',');
        while (directives.next()) |raw| {
            const directive = std.mem.trim(u8, raw, " \t");
            if (directive.len == 0) continue;
            const name_end = std.mem.findScalar(u8, directive, '=') orelse directive.len;
            const name = std.mem.trim(u8, directive[0..name_end], " \t");
            if (std.ascii.eqlIgnoreCase(name, "no-store")) {
                self.no_store = true;
                return;
            }
            // Shared-cache permissions, and qualified `private="field"` (which
            // still lets a shared cache store the rest), are replaced by the
            // unqualified `private` already emitted.
            if (std.ascii.eqlIgnoreCase(name, "public") or
                std.ascii.eqlIgnoreCase(name, "s-maxage") or
                std.ascii.eqlIgnoreCase(name, "proxy-revalidate") or
                std.ascii.eqlIgnoreCase(name, "private")) continue;
            if (self.seen(name)) continue;
            if (self.name_count == self.names.len) {
                self.no_store = true;
                return;
            }
            const name_start = self.out.items.len + 2;
            self.out.appendSliceBounded(", ") catch return self.overflow();
            self.out.appendSliceBounded(directive) catch return self.overflow();
            self.names[self.name_count] = self.out.items[name_start .. name_start + name.len];
            self.name_count += 1;
        }
    }

    pub fn value(self: *const CacheControlFold) []const u8 {
        return if (self.no_store) "no-store" else self.out.items;
    }

    fn seen(self: *const CacheControlFold, name: []const u8) bool {
        for (self.names[0..self.name_count]) |existing| {
            if (std.ascii.eqlIgnoreCase(existing, name)) return true;
        }
        return false;
    }

    fn overflow(self: *CacheControlFold) void {
        self.no_store = true;
    }
};

/// The protected `Cache-Control` value for a single origin field (or none).
pub fn protectedCacheControl(buf: []u8, origin: ?[]const u8, policy: ProtectedCachePolicy) []const u8 {
    var fold = CacheControlFold.init(buf, policy);
    if (origin) |value| fold.add(value);
    return fold.value();
}

/// Make `response` non-shared-cacheable: fold every origin `Cache-Control`
/// field, drop all cache-controlling fields (including CDN/surrogate ones),
/// and install exactly one protected `Cache-Control`. The field is mandatory:
/// it is exempt from the header-count cap, and if it still cannot be added
/// the response is replaced by an empty 503 rather than sent unprotected.
pub fn applyProtectedCachePolicy(response: *Response, policy: ProtectedCachePolicy) void {
    if (policy == .none) return;
    // Computed into `buf` (or a literal) before any origin field is freed.
    var buf: [256]u8 = undefined;
    var fold = CacheControlFold.init(&buf, policy);
    for (response.headers.iterator()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "cache-control")) fold.add(header.value);
    }
    const value = fold.value();
    removeProtectedCacheFields(&response.headers);
    response.headers.appendRequired("Cache-Control", value) catch failClosed(response);
}

fn removeProtectedCacheFields(headers: anytype) void {
    var write_idx: usize = 0;
    for (headers.items.items) |header| {
        if (isProtectedCacheField(header.name)) {
            headers.allocator.free(header.name);
            headers.allocator.free(header.value);
            continue;
        }
        headers.items.items[write_idx] = header;
        write_idx += 1;
    }
    headers.items.shrinkRetainingCapacity(write_idx);
}

/// Without allocating, turn `response` into an empty 503: a protected
/// response that cannot carry its cache policy must not be sent at all.
fn failClosed(response: *Response) void {
    _ = response.setStatus(.service_unavailable);
    if (response.body_owned) {
        if (response.body) |body| response.allocator.free(body);
    }
    response.body = null;
    response.body_owned = false;
    response.headers.remove("content-length");
    response.headers.remove("content-type");
}

/// Standard security headers applied to all responses.
///
/// - X-Frame-Options
/// - X-Content-Type-Options
/// - Content-Security-Policy
/// - Strict-Transport-Security
/// - Referrer-Policy
/// - Permissions-Policy
/// - Cross-Origin-Opener-Policy
/// - Cross-Origin-Resource-Policy
pub const SecurityHeaders = struct {
    x_frame_options: []const u8 = "DENY",
    x_content_type_options: []const u8 = "nosniff",
    content_security_policy: []const u8 = "default-src 'self'",
    /// HSTS value is intentionally empty by default. The gateway populates this
    /// field only when TLS is active and HSTS is explicitly enabled in config.
    strict_transport_security: []const u8 = "",
    referrer_policy: []const u8 = "strict-origin-when-cross-origin",
    permissions_policy: []const u8 = "camera=(), microphone=(), geolocation=()",
    x_xss_protection: []const u8 = "0", // Disabled per modern best practice (CSP preferred)
    /// Isolates the browsing context from cross-origin documents, preventing
    /// Spectre-style attacks that exploit shared browsing context groups.
    cross_origin_opener_policy: []const u8 = "same-origin",
    /// Controls which origins may embed this resource cross-origin, preventing
    /// cross-origin information leaks via <img>, <video>, fetch, etc.
    cross_origin_resource_policy: []const u8 = "same-origin",

    /// Apply all configured security headers to a response.
    /// Each header is only set if the response does not already carry a header
    /// with that name — this prevents duplicate or conflicting headers when the
    /// upstream (e.g. a Rails app) already supplies its own security policy.
    pub fn apply(self: *const SecurityHeaders, response: *Response) void {
        if (self.x_frame_options.len > 0)
            _ = response.setHeaderIfAbsent("X-Frame-Options", self.x_frame_options);
        if (self.x_content_type_options.len > 0)
            _ = response.setHeaderIfAbsent("X-Content-Type-Options", self.x_content_type_options);
        if (self.content_security_policy.len > 0)
            _ = response.setHeaderIfAbsent("Content-Security-Policy", self.content_security_policy);
        if (self.strict_transport_security.len > 0)
            _ = response.setHeaderIfAbsent("Strict-Transport-Security", self.strict_transport_security);
        if (self.referrer_policy.len > 0)
            _ = response.setHeaderIfAbsent("Referrer-Policy", self.referrer_policy);
        if (self.permissions_policy.len > 0)
            _ = response.setHeaderIfAbsent("Permissions-Policy", self.permissions_policy);
        if (self.x_xss_protection.len > 0)
            _ = response.setHeaderIfAbsent("X-XSS-Protection", self.x_xss_protection);
        if (self.cross_origin_opener_policy.len > 0)
            _ = response.setHeaderIfAbsent("Cross-Origin-Opener-Policy", self.cross_origin_opener_policy);
        if (self.cross_origin_resource_policy.len > 0)
            _ = response.setHeaderIfAbsent("Cross-Origin-Resource-Policy", self.cross_origin_resource_policy);
        appendRequestScopedHeaders(response);
        applyProtectedCachePolicy(response, request_cache_policy);
    }

    /// Default secure configuration.
    pub const default: SecurityHeaders = .{};

    /// API-oriented configuration. Includes the full default security header
    /// set: CSP (`default-src 'self'`), X-Frame-Options (`DENY`), COOP, CORP,
    /// and all other standard headers. Operators can override individual fields
    /// in config if a looser policy is required for their application.
    pub const api: SecurityHeaders = .{};
};

/// Append the request-scoped headers, skipping any exact name/value pair the
/// response already carries so a response decorated twice stays correct.
fn appendRequestScopedHeaders(response: *Response) void {
    outer: for (request_scoped_headers) |scoped| {
        for (response.headers.iterator()) |existing| {
            if (std.ascii.eqlIgnoreCase(existing.name, scoped.name) and std.mem.eql(u8, existing.value, scoped.value)) continue :outer;
        }
        response.headers.append(scoped.name, scoped.value) catch {};
    }
}

// Tests

test "protectedCacheControl never leaves a protected response shared-cacheable" {
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("private, max-age=600", protectedCacheControl(&buf, "public, max-age=600, s-maxage=3600", .private));
    try std.testing.expectEqualStrings("private", protectedCacheControl(&buf, null, .private));
    try std.testing.expectEqualStrings("private, no-cache", protectedCacheControl(&buf, "private=\"Set-Cookie\", no-cache, proxy-revalidate", .private));
    try std.testing.expectEqualStrings("no-store", protectedCacheControl(&buf, "public, NO-STORE", .private));
    try std.testing.expectEqualStrings("no-store", protectedCacheControl(&buf, "public, max-age=600", .no_store));
}

test "CacheControlFold folds split fields with no-store dominating and first directive winning" {
    var buf: [256]u8 = undefined;
    var later_no_store = CacheControlFold.init(&buf, .private);
    later_no_store.add("public, max-age=600");
    later_no_store.add("no-store");
    try std.testing.expectEqualStrings("no-store", later_no_store.value());

    var buf2: [256]u8 = undefined;
    var earlier_no_store = CacheControlFold.init(&buf2, .private);
    earlier_no_store.add("no-store");
    earlier_no_store.add("public, max-age=600");
    try std.testing.expectEqualStrings("no-store", earlier_no_store.value());

    var buf3: [256]u8 = undefined;
    var dedupe = CacheControlFold.init(&buf3, .private);
    dedupe.add("private, max-age=600, must-revalidate");
    dedupe.add("public, MAX-AGE=3600, s-maxage=86400");
    try std.testing.expectEqualStrings("private, max-age=600, must-revalidate", dedupe.value());
}

test "applyProtectedCachePolicy drops CDN and surrogate cache fields" {
    const allocator = std.testing.allocator;
    var response = Response.init(allocator);
    defer response.deinit();
    _ = response
        .setHeader("Cache-Control", "public, max-age=600")
        .setHeader("CDN-Cache-Control", "public, max-age=3600")
        .setHeader("Cloudflare-CDN-Cache-Control", "public, max-age=3600")
        .setHeader("Surrogate-Control", "max-age=3600")
        .setHeader("Edge-Control", "cache-maxage=1h")
        .setHeader("X-Accel-Expires", "3600")
        .setHeader("Cache-Control", "no-store");
    applyProtectedCachePolicy(&response, .private);
    try std.testing.expectEqual(@as(usize, 1), response.headers.countByName("cache-control"));
    try std.testing.expectEqualStrings("no-store", response.headers.get("cache-control").?);
    inline for (.{ "cdn-cache-control", "cloudflare-cdn-cache-control", "surrogate-control", "edge-control", "x-accel-expires" }) |name| {
        try std.testing.expect(response.headers.get(name) == null);
    }
}

test "the protected cache field is added even to a response at the header cap" {
    const allocator = std.testing.allocator;
    var response = Response.init(allocator);
    defer response.deinit();
    const headers_mod = @import("headers.zig");
    var name_buf: [16]u8 = undefined;
    for (0..headers_mod.MAX_HEADERS) |i| {
        const name = try std.fmt.bufPrint(&name_buf, "x-fill-{d}", .{i});
        try response.headers.append(name, "v");
    }
    try std.testing.expectError(error.TooManyHeaders, response.headers.append("x-over", "v"));
    applyProtectedCachePolicy(&response, .private);
    try std.testing.expectEqualStrings("private", response.headers.get("cache-control").?);
}

test "a protected response that cannot carry its cache policy fails closed" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = failing.allocator();
    var response = Response.init(allocator);
    defer response.deinit();
    _ = response.setStatus(.ok).setBodyOwned(try allocator.dupe(u8, "protected-body"));
    try response.headers.append("Content-Length", "14");
    // Every further allocation fails, so the mandatory field cannot be added.
    failing.fail_index = failing.alloc_index;
    applyProtectedCachePolicy(&response, .private);
    try std.testing.expectEqual(@as(u16, 503), @intFromEnum(response.status));
    try std.testing.expect(response.body == null);
    try std.testing.expect(response.headers.get("content-length") == null);
}

test "apply rewrites Cache-Control under a protected request scope" {
    const allocator = std.testing.allocator;
    var response = Response.init(allocator);
    defer response.deinit();
    _ = response.setHeader("Cache-Control", "public, max-age=600");
    setRequestScope(&.{}, .private);
    defer clearRequestScope();
    const sec = SecurityHeaders{};
    sec.apply(&response);
    try std.testing.expectEqual(@as(usize, 1), response.headers.countByName("cache-control"));
    try std.testing.expectEqualStrings("private, max-age=600", response.headers.get("cache-control").?);
}

test "apply adds request-scoped headers once, keeping repeated names" {
    const allocator = std.testing.allocator;
    var response = Response.init(allocator);
    defer response.deinit();
    const scoped = [_]ScopedHeader{
        .{ .name = "Set-Cookie", .value = "a=1" },
        .{ .name = "Set-Cookie", .value = "b=2" },
    };
    setRequestScope(&scoped, .none);
    defer clearRequestScope();
    const sec = SecurityHeaders{};
    sec.apply(&response);
    sec.apply(&response);
    try std.testing.expectEqual(@as(usize, 2), response.headers.countByName("set-cookie"));
}

test "apply sets all default security headers" {
    const allocator = std.testing.allocator;
    var response = Response.init(allocator);
    defer response.deinit();

    const headers = SecurityHeaders.default;
    headers.apply(&response);

    try std.testing.expectEqualStrings("DENY", response.headers.get("X-Frame-Options").?);
    try std.testing.expectEqualStrings("nosniff", response.headers.get("X-Content-Type-Options").?);
    try std.testing.expectEqualStrings("default-src 'self'", response.headers.get("Content-Security-Policy").?);
    try std.testing.expect(response.headers.get("Strict-Transport-Security") == null);
    try std.testing.expectEqualStrings("strict-origin-when-cross-origin", response.headers.get("Referrer-Policy").?);
    try std.testing.expectEqualStrings("0", response.headers.get("X-XSS-Protection").?);
    try std.testing.expectEqualStrings("same-origin", response.headers.get("Cross-Origin-Opener-Policy").?);
    try std.testing.expectEqualStrings("same-origin", response.headers.get("Cross-Origin-Resource-Policy").?);
}

test "api preset includes csp and x-frame-options alongside coop and corp" {
    const allocator = std.testing.allocator;
    var response = Response.init(allocator);
    defer response.deinit();

    const headers = SecurityHeaders.api;
    headers.apply(&response);

    try std.testing.expectEqualStrings("DENY", response.headers.get("X-Frame-Options").?);
    try std.testing.expectEqualStrings("default-src 'self'", response.headers.get("Content-Security-Policy").?);
    try std.testing.expectEqualStrings("nosniff", response.headers.get("X-Content-Type-Options").?);
    try std.testing.expectEqualStrings("same-origin", response.headers.get("Cross-Origin-Opener-Policy").?);
    try std.testing.expectEqualStrings("same-origin", response.headers.get("Cross-Origin-Resource-Policy").?);
}

test "hsts is emitted when strict_transport_security is set" {
    const allocator = std.testing.allocator;
    var response = Response.init(allocator);
    defer response.deinit();

    var headers = SecurityHeaders.default;
    headers.strict_transport_security = "max-age=31536000; includeSubDomains";
    headers.apply(&response);

    try std.testing.expectEqualStrings(
        "max-age=31536000; includeSubDomains",
        response.headers.get("Strict-Transport-Security").?,
    );
}

test "hsts is absent when strict_transport_security is empty" {
    const allocator = std.testing.allocator;
    var response = Response.init(allocator);
    defer response.deinit();

    const headers = SecurityHeaders.default;
    headers.apply(&response);

    try std.testing.expect(response.headers.get("Strict-Transport-Security") == null);
}
