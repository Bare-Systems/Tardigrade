//! Static-file runtime helpers for the edge gateway. This module owns static
//! location serving, try_files fallback, and static error-page resolution.

const compat = @import("zig_compat.zig");
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

    const status_code = try writeStaticServedResponse(allocator, conn, request.method == .HEAD, keep_alive, correlation_id, state, &served);
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

    return writeStaticServedResponse(allocator, conn, std.ascii.eqlIgnoreCase(method, "HEAD"), keep_alive, correlation_id, state, &served);
}

pub fn writeStaticServedResponse(
    allocator: std.mem.Allocator,
    conn: anytype,
    head_only: bool,
    keep_alive: bool,
    correlation_id: []const u8,
    state: *GatewayState,
    served: *const http.static_file.Result,
) !u16 {
    const writer = conn.writer();
    var response = http.Response.init(allocator);
    defer response.deinit();
    _ = response
        .setStatus(served.status_code)
        .setBody(served.body orelse "")
        .setContentType(served.content_type)
        .setConnection(keep_alive)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    if (served.etag_value) |etag_value| _ = response.setHeader("ETag", etag_value);
    if (served.last_modified_value) |last_modified| _ = response.setHeader("Last-Modified", last_modified);
    if (served.content_range_value) |content_range| _ = response.setHeader("Content-Range", content_range);
    if (served.accept_ranges) _ = response.setHeader("Accept-Ranges", "bytes");

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
            var in_fc = try std.Io.Dir.openFileAbsolute(compat.io(), file_path, .{});
            defer in_fc.close(compat.io());
            _ = std.c.lseek(in_fc.handle, @intCast(served.file_offset), std.c.SEEK.SET);
            var remaining: u64 = served.file_len;
            var xfer_buf: [65536]u8 = undefined;
            while (remaining > 0) {
                const to_read: usize = @intCast(@min(xfer_buf.len, remaining));
                const n = std.c.read(in_fc.handle, &xfer_buf, to_read);
                if (n <= 0) break;
                try conn.writeAll(xfer_buf[0..@intCast(n)]);
                remaining -= @intCast(n);
            }
            state.logger.debug(correlation_id, "served static file via file-backed path: {s}", .{file_path});
        } else {
            return error.InvalidStaticTransferState;
        }
    } else if (served.body) |body| {
        try writer.writeAll(body);
        state.logger.debug(correlation_id, "served static file via buffered path", .{});
    }

    return @intFromEnum(served.status_code);
}
