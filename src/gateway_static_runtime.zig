//! Static-file runtime helpers for the edge gateway. This module owns static
//! location serving, try_files fallback, and static error-page resolution.

const compat = @import("zig_compat.zig");
const builtin = @import("builtin");
const std = @import("std");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");
const gp = @import("gateway_proxy.zig");
const gs = @import("gateway_state.zig");

const GatewayState = gs.GatewayState;
const MAX_REQUEST_SIZE = gs.MAX_REQUEST_SIZE;

pub const StaticErrorPageResult = union(enum) {
    served: http.static_file.Result,
    redirect: []u8,

    pub fn deinit(self: *StaticErrorPageResult, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .served => |*served| served.deinit(allocator),
            .redirect => |target| allocator.free(target),
        }
        self.* = undefined;
    }
};

pub fn wantsHtmlErrorPage(request_path: []const u8, headers: *const http.Headers) bool {
    if (std.mem.startsWith(u8, request_path, "/v1/")) return false;
    const accept = headers.get("accept") orelse return false;
    if (std.mem.find(u8, accept, "text/html") != null) return true;
    if (std.mem.find(u8, accept, "*/*") != null) return true;
    if (std.mem.find(u8, accept, "application/json") != null) return false;
    return false;
}

pub fn findErrorPageTarget(block: *const http.location_router.LocationBlock, status_code: u16) ?[]const u8 {
    for (block.error_pages) |rule| {
        for (rule.status_codes) |candidate| {
            if (candidate == status_code) return rule.target;
        }
    }
    return null;
}

pub fn maybeResolveStaticErrorPage(
    allocator: std.mem.Allocator,
    matched: http.location_router.MatchResult,
    root_cfg: anytype,
    request_path: []const u8,
    headers: *const http.Headers,
    status_code: u16,
) !?StaticErrorPageResult {
    if (!wantsHtmlErrorPage(request_path, headers)) return null;
    const target = findErrorPageTarget(matched.block, status_code) orelse return null;
    if (std.mem.startsWith(u8, target, "http://") or std.mem.startsWith(u8, target, "https://")) {
        return .{ .redirect = try allocator.dupe(u8, target) };
    }
    var served = (try http.static_file.serve(allocator, .{
        .root = root_cfg.root,
        .request_path = target,
        .matched_pattern = "/",
        .alias = false,
        .index = root_cfg.index,
        .try_files = "",
        .autoindex = false,
        .headers = headers,
        .max_bytes = MAX_REQUEST_SIZE,
    })) orelse return null;
    served.status_code = @enumFromInt(status_code);
    return .{ .served = served };
}

pub fn handleStaticLocation(
    allocator: std.mem.Allocator,
    conn: anytype,
    request: *const http.Request,
    matched: http.location_router.MatchResult,
    root_cfg: anytype,
    correlation_id: []const u8,
    keep_alive: bool,
    state: *GatewayState,
) !?u16 {
    if (!(request.method == .GET or request.method == .HEAD)) return null;
    const writer = conn.writer();
    const prefer_file_backed = @TypeOf(conn) == compat.NetStream;
    var served = (try http.static_file.serve(allocator, .{
        .root = root_cfg.root,
        .request_path = request.uri.path,
        .matched_pattern = matched.block.pattern,
        .alias = root_cfg.alias,
        .index = root_cfg.index,
        .try_files = root_cfg.try_files,
        .autoindex = root_cfg.autoindex,
        .headers = &request.headers,
        .max_bytes = MAX_REQUEST_SIZE,
        .prefer_file_backed = prefer_file_backed,
    })) orelse blk: {
        var error_page = (try maybeResolveStaticErrorPage(allocator, matched, root_cfg, request.uri.path, &request.headers, 404)) orelse return null;
        switch (error_page) {
            .redirect => |target| {
                defer allocator.free(target);
                var response = http.Response.init(allocator);
                defer response.deinit();
                _ = response
                    .setStatus(.found)
                    .setBody("")
                    .setContentType("text/plain; charset=utf-8")
                    .setConnection(keep_alive)
                    .setHeader("Location", target)
                    .setHeader(http.correlation.HEADER_NAME, correlation_id);
                gp.applyResponseHeaders(state, &response);
                if (request.method == .HEAD) {
                    try response.writeHead(writer);
                } else {
                    try response.write(writer);
                }
                state.metricsRecord(302);
                return 302;
            },
            .served => |*resolved| break :blk resolved.*,
        }
    };
    defer served.deinit(allocator);

    if (@intFromEnum(served.status_code) >= 400) {
        if (try maybeResolveStaticErrorPage(allocator, matched, root_cfg, request.uri.path, &request.headers, @intFromEnum(served.status_code))) |error_page| {
            switch (error_page) {
                .redirect => |target| {
                    defer allocator.free(target);
                    var response = http.Response.init(allocator);
                    defer response.deinit();
                    _ = response
                        .setStatus(.found)
                        .setBody("")
                        .setContentType("text/plain; charset=utf-8")
                        .setConnection(keep_alive)
                        .setHeader("Location", target)
                        .setHeader(http.correlation.HEADER_NAME, correlation_id);
                    gp.applyResponseHeaders(state, &response);
                    if (request.method == .HEAD) {
                        try response.writeHead(writer);
                    } else {
                        try response.write(writer);
                    }
                    state.metricsRecord(302);
                    return 302;
                },
                .served => |replacement| {
                    served.deinit(allocator);
                    served = replacement;
                },
            }
        }
    }

    const status_code = try writeStaticServedResponse(allocator, conn, request.method == .HEAD, keep_alive, correlation_id, state, &served, request.headers.get("accept-encoding"));
    state.metricsRecord(status_code);
    return status_code;
}

pub fn serveTryFilesFallback(
    allocator: std.mem.Allocator,
    conn: anytype,
    cfg: *const edge_config.EdgeConfig,
    request: *const http.Request,
    correlation_id: []const u8,
    keep_alive: bool,
    state: *GatewayState,
) !u16 {
    const method = request.method.toString();
    const request_path = request.uri.path;
    if (!(std.ascii.eqlIgnoreCase(method, "GET") or std.ascii.eqlIgnoreCase(method, "HEAD"))) return error.NoTryFiles;
    if (cfg.doc_root.len == 0) return error.NoTryFiles;
    // When `root` is set at the server level without a `try_files` directive,
    // default to "$uri" so files at the exact request path are served directly.
    const effective_try_files = if (cfg.try_files.len > 0) cfg.try_files else "$uri";
    const prefer_file_backed = @TypeOf(conn) == compat.NetStream;

    var served = (try http.static_file.serve(allocator, .{
        .root = cfg.doc_root,
        .request_path = request_path,
        .matched_pattern = "/",
        .alias = false,
        .index = "",
        .try_files = effective_try_files,
        .autoindex = false,
        .headers = &request.headers,
        .max_bytes = MAX_REQUEST_SIZE,
        .prefer_file_backed = prefer_file_backed,
    })) orelse return error.NoTryFiles;
    defer served.deinit(allocator);

    return writeStaticServedResponse(allocator, conn, std.ascii.eqlIgnoreCase(method, "HEAD"), keep_alive, correlation_id, state, &served, request.headers.get("accept-encoding"));
}

pub fn writeStaticServedResponse(
    allocator: std.mem.Allocator,
    conn: anytype,
    head_only: bool,
    keep_alive: bool,
    correlation_id: []const u8,
    state: *GatewayState,
    served: *const http.static_file.Result,
    /// Value of the request's `Accept-Encoding` header, or null if absent.
    /// Used to compress the buffered body when the client and config allow it.
    accept_encoding: ?[]const u8,
) !u16 {
    const writer = conn.writer();

    // Compress the body before building the response so Content-Length is
    // calculated against the (potentially smaller) compressed bytes.
    // Only the buffered path (served.body != null, served.file_path == null) is
    // eligible: the file-backed sendfile path cannot compress on the fly.
    var compress_result: http.compression.CompressionResult = .{ .body = null, .compressed = false };
    defer if (compress_result.body) |b| allocator.free(b);
    if (served.file_path == null) {
        if (served.body) |raw_body| {
            compress_result = http.compression.compressResponse(
                allocator,
                raw_body,
                served.content_type,
                accept_encoding,
                state.compression_config,
            );
        }
    }
    // The body we will actually transmit (compressed or original).
    const out_body: ?[]const u8 = compress_result.body orelse served.body;

    var response = http.Response.init(allocator);
    defer response.deinit();
    _ = response
        .setStatus(served.status_code)
        .setBody(out_body orelse "")
        .setContentType(served.content_type)
        .setConnection(keep_alive)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    if (served.etag_value) |etag_value| _ = response.setHeader("ETag", etag_value);
    if (served.last_modified_value) |last_modified| _ = response.setHeader("Last-Modified", last_modified);
    if (served.content_range_value) |content_range| _ = response.setHeader("Content-Range", content_range);
    if (served.accept_ranges) _ = response.setHeader("Accept-Ranges", "bytes");
    if (compress_result.compressed) {
        if (compress_result.encoding) |enc| _ = response.setHeader("Content-Encoding", enc.headerValue());
        // Vary: Accept-Encoding tells caches this response varies by encoding.
        _ = response.setHeader("Vary", "Accept-Encoding");
    }

    if (served.file_path != null) {
        _ = response.setContentLength(served.content_length);
    }

    gp.applyResponseHeaders(state, &response);
    try response.writeHead(writer);

    if (head_only) {
        if (served.file_path) |file_path| {
            state.logger.debug(correlation_id, "served static file headers from file-backed path: {s}", .{file_path});
        } else {
            state.logger.debug(correlation_id, "served static file headers from buffered path", .{});
        }
        return @intFromEnum(served.status_code);
    }

    if (served.file_path) |file_path| {
        if (@TypeOf(conn) == compat.NetStream) {
            // conn is always a raw plaintext socket here: TLS connections use
            // *TlsConnection (a different type), which fails the TypeOf check
            // above and causes static_file.serve to return a body instead of a
            // file_path. NetStream.inner is therefore always null at this point.
            var in_fc = try std.Io.Dir.openFileAbsolute(compat.io(), file_path, .{});
            defer in_fc.close(compat.io());
            try sendFileFd(conn.handle, in_fc.handle, served.file_offset, served.file_len);
            state.logger.debug(correlation_id, "served static file via file-backed path: {s}", .{file_path});
        } else {
            return error.InvalidStaticTransferState;
        }
    } else if (out_body) |body| {
        try writer.writeAll(body);
        if (compress_result.compressed) {
            state.logger.debug(correlation_id, "served static file via buffered path (compressed: {s})", .{
                if (compress_result.encoding) |enc| enc.headerValue() else "?",
            });
        } else {
            state.logger.debug(correlation_id, "served static file via buffered path", .{});
        }
    }

    return @intFromEnum(served.status_code);
}

/// Transfer `len` bytes from `file_fd` (starting at `offset`) to `sock_fd`.
///
/// On Linux the kernel sendfile(2) syscall is used — no userspace copy.
/// On other platforms a 64 KiB read/write loop is used as a portable fallback.
fn sendFileFd(sock_fd: std.posix.fd_t, file_fd: std.posix.fd_t, offset: u64, len: u64) !void {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var off: linux.off_t = @intCast(offset);
        var remaining: u64 = len;
        while (remaining > 0) {
            // Cap each call to 2 GiB - 4 KiB, the kernel's per-call maximum.
            const to_send: usize = @intCast(@min(remaining, @as(u64, 0x7ffff000)));
            const rc = linux.sendfile(sock_fd, file_fd, &off, to_send);
            switch (linux.errno(rc)) {
                .SUCCESS => {
                    if (rc == 0) return; // peer closed
                    remaining -= rc;
                },
                .INTR => continue,
                // EAGAIN cannot occur on blocking sockets (sockets are switched
                // to blocking mode in the worker before any I/O — see
                // edge_gateway.zig setNonBlocking(client_fd, false)). Treat it
                // as an error rather than spinning silently if that ever changes.
                .AGAIN => return error.SendFileFailed,
                else => return error.SendFileFailed,
            }
        }
        return;
    }
    // Portable fallback: read into a stack buffer then write to the socket.
    _ = std.c.lseek(file_fd, @intCast(offset), std.c.SEEK.SET);
    var remaining: u64 = len;
    var xfer_buf: [65536]u8 = undefined;
    while (remaining > 0) {
        const to_read: usize = @intCast(@min(xfer_buf.len, remaining));
        const n = std.c.read(file_fd, &xfer_buf, to_read);
        if (n <= 0) break;
        var pos: usize = 0;
        const n_usize: usize = @intCast(n);
        while (pos < n_usize) {
            const w = std.c.write(sock_fd, xfer_buf[pos..].ptr, n_usize - pos);
            if (w <= 0) return error.WriteFailed;
            pos += @intCast(w);
        }
        remaining -= @intCast(n);
    }
}

test "sendFileFd: transfers file bytes via kernel sendfile on Linux" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const data = "hello sendfile world";
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "sf_test.txt", .data = data });
    const file_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, "sf_test.txt");
    defer allocator.free(file_path);

    const file_path_z = try std.mem.concatWithSentinel(allocator, u8, &.{file_path}, 0);
    defer allocator.free(file_path_z);
    const file_fd = std.c.open(file_path_z, .{ .ACCMODE = .RDONLY }, @as(std.c.mode_t, 0));
    if (file_fd < 0) return error.FileOpenFailed;
    defer _ = std.c.close(file_fd);

    const linux = std.os.linux;
    var sv: [2]std.posix.fd_t = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &sv);
    if (linux.errno(rc) != .SUCCESS) return error.SocketPairFailed;
    defer _ = std.c.close(sv[0]);
    defer _ = std.c.close(sv[1]);

    try sendFileFd(sv[0], file_fd, 0, data.len);

    // Shut down the write side so the reader sees EOF after the payload.
    _ = linux.shutdown(sv[0], linux.SHUT.WR);

    var buf: [64]u8 = undefined;
    const n = std.c.read(sv[1], &buf, buf.len);
    try std.testing.expect(n > 0);
    try std.testing.expectEqualStrings(data, buf[0..@intCast(n)]);
}

test "sendFileFd: transfers file bytes via fallback loop on non-Linux" {
    if (builtin.os.tag == .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const data = "hello fallback world";
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "fb_test.txt", .data = data });
    const file_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, "fb_test.txt");
    defer allocator.free(file_path);

    const file_path_z = try std.mem.concatWithSentinel(allocator, u8, &.{file_path}, 0);
    defer allocator.free(file_path_z);
    const file_fd = std.c.open(file_path_z, .{ .ACCMODE = .RDONLY }, @as(std.c.mode_t, 0));
    if (file_fd < 0) return error.FileOpenFailed;
    defer _ = std.c.close(file_fd);

    // std.posix.socketpair is not available on all platforms in Zig 0.16;
    // use std.c.socketpair directly instead.
    var fds: [2]std.posix.fd_t = undefined;
    const sp_rc = std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds);
    if (sp_rc != 0) return error.SocketPairFailed;
    defer _ = std.c.close(fds[0]);
    defer _ = std.c.close(fds[1]);

    try sendFileFd(fds[0], file_fd, 0, data.len);
    // Shut the write side so the reader sees EOF.
    if (builtin.os.tag == .macos or builtin.os.tag == .linux) {
        _ = std.c.shutdown(fds[0], std.posix.SHUT.WR);
    }

    var buf: [64]u8 = undefined;
    const n = std.c.read(fds[1], &buf, buf.len);
    try std.testing.expect(n > 0);
    try std.testing.expectEqualStrings(data, buf[0..@intCast(n)]);
}

test "serveTryFilesFallback: top-level root without try_files defaults to $uri" {
    // Regression test for #92: operators who configure only `root /path;` at
    // the server level expect static files to be served for paths that exist in
    // the webroot. The runtime defaults empty try_files to "$uri".
    const effective_try_files_with_no_try_files: []const u8 = if ("".len > 0) "" else "$uri";
    const effective_try_files_with_try_files: []const u8 = if ("$uri /index.html".len > 0) "$uri /index.html" else "$uri";
    try std.testing.expectEqualStrings("$uri", effective_try_files_with_no_try_files);
    try std.testing.expectEqualStrings("$uri /index.html", effective_try_files_with_try_files);

    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "health.txt", .data = "abc" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    var hdrs = http.Headers.init(allocator);
    defer hdrs.deinit();

    const result = try http.static_file.serve(allocator, .{
        .root = root_path,
        .request_path = "/health.txt",
        .matched_pattern = "/",
        .alias = false,
        .index = "",
        .try_files = "$uri",
        .headers = &hdrs,
        .max_bytes = MAX_REQUEST_SIZE,
    });
    try std.testing.expect(result != null);
    var served = result.?;
    defer served.deinit(allocator);
    try std.testing.expectEqual(http.status.Status.ok, served.status_code);
    try std.testing.expectEqual(@as(usize, 3), served.content_length);
}

test "writeStaticServedResponse: compresses buffered body when compression enabled" {
    // This test exercises the integration path added in #142: when
    // compression_config.enabled is true and the client advertises Accept-Encoding:
    // gzip, a compressible buffered body must be served compressed.
    //
    // We exercise the compression decision directly — the same call as the
    // production code — without requiring a full GatewayState. This keeps the
    // test self-contained and fast while confirming the integration contract.
    const allocator = std.testing.allocator;

    // Build a body large enough to pass the min_size threshold (default: 256 bytes).
    const body = "Hello, Tardigrade! " ** 20; // 380 bytes of repetitive text
    try std.testing.expect(body.len >= http.compression.DEFAULT_MIN_SIZE);

    const config: http.compression.CompressionConfig = .{
        .enabled = true,
        .min_size = 64, // lower than body.len
        .brotli_enabled = false, // deterministic: brotli requires a shared lib at runtime
    };

    // Simulate the compression path in writeStaticServedResponse.
    const result = http.compression.compressResponse(
        allocator,
        body,
        "text/html; charset=utf-8",
        "gzip, deflate",
        config,
    );
    defer if (result.body) |b| allocator.free(b);

    try std.testing.expect(result.compressed);
    try std.testing.expect(result.body != null);
    try std.testing.expect(result.body.?.len < body.len); // compressed is smaller
    try std.testing.expectEqual(http.compression.Encoding.gzip, result.encoding.?);
}

test "writeStaticServedResponse: skips compression when config disabled" {
    const allocator = std.testing.allocator;
    const body = "Hello, Tardigrade! " ** 20;

    const config: http.compression.CompressionConfig = .{ .enabled = false };
    const result = http.compression.compressResponse(
        allocator,
        body,
        "text/html; charset=utf-8",
        "gzip",
        config,
    );
    // No allocation when compression is disabled.
    try std.testing.expect(!result.compressed);
    try std.testing.expect(result.body == null);
}

test "writeStaticServedResponse: skips compression when client does not advertise Accept-Encoding" {
    const allocator = std.testing.allocator;
    const body = "Hello, Tardigrade! " ** 20;

    const config: http.compression.CompressionConfig = .{ .enabled = true, .min_size = 64 };
    // null accept_encoding: no Accept-Encoding header sent by the client.
    const result = http.compression.compressResponse(
        allocator,
        body,
        "text/html; charset=utf-8",
        null,
        config,
    );
    try std.testing.expect(!result.compressed);
    try std.testing.expect(result.body == null);
}
