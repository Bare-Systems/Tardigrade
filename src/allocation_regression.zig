const std = @import("std");
const compat = @import("zig_compat");
const http = @import("http.zig");
const gp = @import("gateway_proxy.zig");
const gpr = @import("gateway_proxy_response.zig");

const default_requests: usize = 32;

const Budget = struct {
    max_allocations_per_request: usize,
    max_bytes_per_request: usize,
    rationale: []const u8,
};

const Scenario = enum {
    static_tiny_file_warm,
    static_304_conditional,
    proxy_keepalive_warm,
    proxy_header_heavy_response,
    mixed_route_selection,
    rejected_overload,

    fn name(self: Scenario) []const u8 {
        return switch (self) {
            .static_tiny_file_warm => "static-tiny-file-warm",
            .static_304_conditional => "static-304-conditional",
            .proxy_keepalive_warm => "proxy-keepalive-warm",
            .proxy_header_heavy_response => "proxy-header-heavy-response",
            .mixed_route_selection => "mixed-route-selection",
            .rejected_overload => "rejected-overload",
        };
    }

    fn budget(self: Scenario) Budget {
        return switch (self) {
            // File-backed static responses intentionally allocate for safe path
            // normalization, realpath ownership, ETag, and Last-Modified headers.
            .static_tiny_file_warm => .{
                .max_allocations_per_request = 14,
                .max_bytes_per_request = 1024,
                .rationale = "file-backed static path allocates owned normalized paths plus cache validators; file body stays out of heap",
            },
            // 304 follows the same path-resolution/header-validator shape as a
            // 200 static hit but avoids response-body allocation.
            .static_304_conditional => .{
                .max_allocations_per_request = 14,
                .max_bytes_per_request = 1024,
                .rationale = "conditional static hit allocates path metadata and validators, not response body bytes",
            },
            // Warm proxy keepalive owns resolved target strings through the same
            // allocPrint helpers used by runtime proxy dispatch. Header vectors
            // stay on stackFallback for this path.
            .proxy_keepalive_warm => .{
                .max_allocations_per_request = 6,
                .max_bytes_per_request = 512,
                .rationale = "warm keepalive proxy helper work owns resolved target strings; forwarded headers remain stack-backed",
            },
            // Header-heavy buffered responses allocate filtered upstream
            // metadata in the same arena-backed production parser used by the
            // proxy path; response serialization then writes through
            // caller-owned output.
            .proxy_header_heavy_response => .{
                .max_allocations_per_request = 16,
                .max_bytes_per_request = 2048,
                .rationale = "header-heavy buffered proxy response parsing owns filtered metadata in an arena; serialization writes through caller-owned buffers",
            },
            // Location matching reads process/config-owned route metadata and
            // returns borrowed route slices. Regex matching now routes Zig
            // scratch through the request allocator so this budget can observe
            // the allocation boundary; POSIX regcomp may still allocate
            // internally through libc.
            .mixed_route_selection => .{
                .max_allocations_per_request = 12,
                .max_bytes_per_request = 1024,
                .rationale = "mixed route selection borrows config-owned locations; regex scratch is request-allocator-owned while libc regcomp remains external",
            },
            // Rejections are not the steady-state success path; JSON payload and
            // response headers are intentionally allocated for clear client errors.
            .rejected_overload => .{
                .max_allocations_per_request = 12,
                .max_bytes_per_request = 1024,
                .rationale = "overload rejection allocates structured JSON and response header copies before closing the request",
            },
        };
    }
};

const AllocationStats = struct {
    allocations: usize = 0,
    frees: usize = 0,
    resize_calls: usize = 0,
    remap_calls: usize = 0,
    bytes_allocated: usize = 0,
    live_bytes: usize = 0,
    peak_live_bytes: usize = 0,
};

const CountingAllocator = struct {
    child: std.mem.Allocator,
    stats: AllocationStats = .{},

    pub fn init(child: std.mem.Allocator) CountingAllocator {
        return .{ .child = child };
    }

    pub fn allocator(self: *CountingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn noteGrowth(self: *CountingAllocator, old_len: usize, new_len: usize) void {
        if (new_len > old_len) {
            const delta = new_len - old_len;
            self.stats.bytes_allocated += delta;
            self.stats.live_bytes += delta;
        } else {
            self.stats.live_bytes -= @min(self.stats.live_bytes, old_len - new_len);
        }
        self.stats.peak_live_bytes = @max(self.stats.peak_live_bytes, self.stats.live_bytes);
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const ptr = self.child.rawAlloc(len, alignment, ret_addr) orelse return null;
        self.stats.allocations += 1;
        self.stats.bytes_allocated += len;
        self.stats.live_bytes += len;
        self.stats.peak_live_bytes = @max(self.stats.peak_live_bytes, self.stats.live_bytes);
        return ptr;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        if (!self.child.rawResize(memory, alignment, new_len, ret_addr)) return false;
        self.stats.resize_calls += 1;
        self.noteGrowth(memory.len, new_len);
        return true;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const ptr = self.child.rawRemap(memory, alignment, new_len, ret_addr) orelse return null;
        self.stats.remap_calls += 1;
        self.noteGrowth(memory.len, new_len);
        return ptr;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        self.stats.frees += 1;
        self.stats.live_bytes -= @min(self.stats.live_bytes, memory.len);
        self.child.rawFree(memory, alignment, ret_addr);
    }

    const vtable = std.mem.Allocator.VTable{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };
};

const ScenarioResult = struct {
    scenario: Scenario,
    requests: usize,
    stats: AllocationStats,

    fn budget(self: ScenarioResult) Budget {
        return self.scenario.budget();
    }
};

const StaticFixture = struct {
    temp_dir: []u8,
    root_path: []u8,
    empty_headers: http.Headers,
    not_modified_headers: http.Headers,

    fn init(allocator: std.mem.Allocator) !StaticFixture {
        const temp_dir = try std.fmt.allocPrint(allocator, "/tmp/tardigrade-allocation-regression-{d}", .{compat.nanoTimestamp()});
        errdefer allocator.free(temp_dir);

        compat.cwd().deleteTree(temp_dir) catch {}; // best-effort cleanup for a stale benchmark temp directory
        try compat.cwd().makePath(temp_dir);
        errdefer compat.cwd().deleteTree(temp_dir) catch {}; // best-effort cleanup if fixture setup fails

        const fixture_file = try std.Io.Dir.path.join(allocator, &.{ temp_dir, "health.txt" });
        defer allocator.free(fixture_file);
        try compat.cwd().writeFile(.{ .sub_path = fixture_file, .data = "ok\n" });

        const root_path = try compat.cwd().realpathAlloc(allocator, temp_dir);
        errdefer allocator.free(root_path);

        var empty_headers = http.Headers.init(allocator);
        errdefer empty_headers.deinit();
        var not_modified_headers = http.Headers.init(allocator);
        errdefer not_modified_headers.deinit();

        var warm = (try http.static_file.serve(allocator, .{
            .root = root_path,
            .request_path = "/health.txt",
            .matched_pattern = "/",
            .alias = false,
            .index = "",
            .try_files = "$uri",
            .headers = &empty_headers,
            .max_bytes = 1024,
            .prefer_file_backed = true,
        })) orelse return error.StaticFixtureMissing;
        defer warm.deinit(allocator);
        try not_modified_headers.append("If-None-Match", warm.etag_value orelse return error.StaticFixtureMissingEtag);

        return .{
            .temp_dir = temp_dir,
            .root_path = root_path,
            .empty_headers = empty_headers,
            .not_modified_headers = not_modified_headers,
        };
    }

    fn deinit(self: *StaticFixture, allocator: std.mem.Allocator) void {
        self.empty_headers.deinit();
        self.not_modified_headers.deinit();
        compat.cwd().deleteTree(self.temp_dir) catch {}; // best-effort benchmark fixture cleanup
        allocator.free(self.root_path);
        allocator.free(self.temp_dir);
        self.* = undefined;
    }
};

pub fn main() !void {
    var debug: std.heap.DebugAllocator(.{}) = .init;
    defer std.debug.assert(debug.deinit() == .ok);
    const allocator = debug.allocator();

    const results = try collectResults(allocator, default_requests);
    try assertBudgets(results[0..]);

    var stdout_buf: [8192]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(compat.io(), &stdout_buf);
    try writeJsonReport(&stdout.interface, results[0..]);
    try stdout.flush();
}

fn collectResults(allocator: std.mem.Allocator, requests: usize) ![6]ScenarioResult {
    var fixture = try StaticFixture.init(allocator);
    defer fixture.deinit(allocator);

    // Warm the filesystem path before measured loops so the budgets describe
    // steady-state allocator churn rather than first-touch setup.
    try runStaticTiny(&fixture, allocator);
    try runStaticNotModified(&fixture, allocator);

    return .{
        try measureScenario(allocator, requests, .static_tiny_file_warm, &fixture),
        try measureScenario(allocator, requests, .static_304_conditional, &fixture),
        try measureScenario(allocator, requests, .proxy_keepalive_warm, &fixture),
        try measureScenario(allocator, requests, .proxy_header_heavy_response, &fixture),
        try measureScenario(allocator, requests, .mixed_route_selection, &fixture),
        try measureScenario(allocator, requests, .rejected_overload, &fixture),
    };
}

fn measureScenario(allocator: std.mem.Allocator, requests: usize, scenario: Scenario, fixture: *StaticFixture) !ScenarioResult {
    var counter = CountingAllocator.init(allocator);
    const measured_allocator = counter.allocator();
    var i: usize = 0;
    while (i < requests) : (i += 1) {
        switch (scenario) {
            .static_tiny_file_warm => try runStaticTiny(fixture, measured_allocator),
            .static_304_conditional => try runStaticNotModified(fixture, measured_allocator),
            .proxy_keepalive_warm => try runProxyKeepaliveWarm(measured_allocator),
            .proxy_header_heavy_response => try runProxyHeaderHeavyResponse(measured_allocator),
            .mixed_route_selection => try runMixedRouteSelection(measured_allocator),
            .rejected_overload => try runRejectedOverload(measured_allocator),
        }
    }
    return .{ .scenario = scenario, .requests = requests, .stats = counter.stats };
}

fn runStaticTiny(fixture: *StaticFixture, allocator: std.mem.Allocator) !void {
    const maybe_served = try http.static_file.serve(allocator, .{
        .root = fixture.root_path,
        .request_path = "/health.txt",
        .matched_pattern = "/",
        .alias = false,
        .index = "",
        .try_files = "$uri",
        .headers = &fixture.empty_headers,
        .max_bytes = 1024,
        .prefer_file_backed = true,
    });
    var served = maybe_served orelse return error.StaticWarmPathMiss;
    defer served.deinit(allocator);
    if (served.status_code != .ok) return error.StaticWarmPathWrongStatus;
    if (served.file_path == null) return error.StaticWarmPathNotFileBacked;
    if (served.body != null) return error.StaticWarmPathBufferedBody;
}

fn runStaticNotModified(fixture: *StaticFixture, allocator: std.mem.Allocator) !void {
    const maybe_served = try http.static_file.serve(allocator, .{
        .root = fixture.root_path,
        .request_path = "/health.txt",
        .matched_pattern = "/",
        .alias = false,
        .index = "",
        .try_files = "$uri",
        .headers = &fixture.not_modified_headers,
        .max_bytes = 1024,
        .prefer_file_backed = true,
    });
    var served = maybe_served orelse return error.StaticConditionalPathMiss;
    defer served.deinit(allocator);
    if (served.status_code != .not_modified) return error.StaticConditionalWrongStatus;
    if (served.content_length != 0) return error.StaticConditionalUnexpectedBody;
}

fn runProxyKeepaliveWarm(allocator: std.mem.Allocator) !void {
    const resolved = try gp.resolveProxyTarget(
        allocator,
        "http://127.0.0.1:8080",
        "/proxy",
        "health",
    );
    defer allocator.free(resolved.url);

    var query = try gp.appendProxyQueryString(allocator, resolved.url, null);
    defer query.deinit(allocator);
    var forwarded = try gp.buildForwardedFor(allocator, null, "127.0.0.1");
    defer forwarded.deinit(allocator);

    var extra_headers_stack = std.heap.stackFallback(2048, allocator);
    var extra_headers = std.array_list.Managed(std.http.Header).init(extra_headers_stack.get());
    defer extra_headers.deinit();
    try extra_headers.ensureUnusedCapacity(6);
    try gp.appendRequestIdHeaders(&extra_headers, "tg-1778460305668-bfebecb410803023");
    try extra_headers.append(.{ .name = "X-Forwarded-For", .value = forwarded.value });
    try extra_headers.append(.{ .name = "X-Real-IP", .value = "127.0.0.1" });

    if (query.owned != null) return error.ProxyKeepaliveQueryAllocated;
    if (forwarded.owned != null) return error.ProxyKeepaliveForwardedForAllocated;
    if (extra_headers.items.len != 4) return error.ProxyKeepaliveHeaderAssemblyFailed;
}

fn runProxyHeaderHeavyResponse(allocator: std.mem.Allocator) !void {
    var parsed = try gp.parseBufferedUpstreamResponse(allocator, "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: application/json\r\n" ++
        "Cache-Control: private, max-age=60\r\n" ++
        "ETag: \"allocation-regression-143\"\r\n" ++
        "X-App-Version: 2026.08.21\r\n" ++
        "X-Trace-Region: iad\r\n" ++
        "Connection: keep-alive\r\n" ++
        "Server: origin-test\r\n" ++
        "X-Powered-By: origin-framework\r\n" ++
        "Set-Cookie: sid=abc; HttpOnly; SameSite=Lax\r\n" ++
        "Vary: Accept-Encoding\r\n" ++
        "\r\n" ++
        "{\"ok\":true}\n");
    defer parsed.deinit(allocator);
    if (parsed.headerValue("Connection") != null) return error.ProxyHeaderHeavyLeakedHopByHopHeader;
    if (parsed.headerValue("Server") != null) return error.ProxyHeaderHeavyLeakedDisclosureHeader;
    if (parsed.headerValue("X-Powered-By") != null) return error.ProxyHeaderHeavyLeakedDisclosureHeader;

    const security = http.security_headers.SecurityHeaders.default;
    var buf: [4096]u8 = undefined;
    var stream = compat.fixedBufferStream(&buf);
    try gpr.writeBufferedUpstreamResponse(
        stream.writer(),
        parsed,
        true,
        "tg-1778460305668-bfebecb410803023",
        &security,
        null,
        "tg_sticky=proxy; Path=/; HttpOnly",
    );
    const out = stream.getWritten();
    if (std.mem.find(u8, out, "X-App-Version: 2026.08.21\r\n") == null) return error.ProxyHeaderHeavyMissingForwardedHeader;
    if (std.mem.find(u8, out, "X-Powered-By: origin-framework\r\n") != null) return error.ProxyHeaderHeavyLeakedDisclosureHeader;
    if (std.mem.find(u8, out, "Set-Cookie: tg_sticky=proxy; Path=/; HttpOnly\r\n") == null) return error.ProxyHeaderHeavyMissingStickyCookie;
    if (std.mem.find(u8, out, "{\"ok\":true}\n") == null) return error.ProxyHeaderHeavyMissingBody;
}

fn runMixedRouteSelection(allocator: std.mem.Allocator) !void {
    const blocks = [_]http.location_router.LocationBlock{
        .{
            .match_type = .prefix,
            .pattern = "/",
            .priority = 10,
            .action = .{ .static_root = .{ .root = "/srv/www", .alias = false, .autoindex = false, .index = "index.html", .try_files = "$uri" } },
        },
        .{
            .match_type = .prefix,
            .pattern = "/api/",
            .priority = 4,
            .action = .{ .proxy_pass = "http://127.0.0.1:3000" },
        },
        .{
            .match_type = .prefix_priority,
            .pattern = "/api/private/",
            .priority = 1,
            .action = .{ .return_response = .{ .status = 403, .body = "forbidden" } },
        },
        .{
            .match_type = .exact,
            .pattern = "/status/metrics",
            .priority = 0,
            .action = .{ .return_response = .{ .status = 200, .body = "metrics" } },
        },
        .{
            .match_type = .regex,
            .pattern = "^/assets/.+\\.css$",
            .priority = 8,
            .action = .{ .static_root = .{ .root = "/srv/assets", .alias = false, .autoindex = false, .index = "", .try_files = "$uri" } },
        },
    };

    const exact = http.location_router.matchLocation(allocator, "/status/metrics?format=prom", &blocks) orelse return error.MixedRouteSelectionMissedExact;
    if (exact.index != 3) return error.MixedRouteSelectionWrongExact;

    const priority = http.location_router.matchLocation(allocator, "/api/private/users", &blocks) orelse return error.MixedRouteSelectionMissedPriority;
    if (priority.index != 2) return error.MixedRouteSelectionWrongPriority;

    const regex = http.location_router.matchLocation(allocator, "/assets/site.css?v=1", &blocks) orelse return error.MixedRouteSelectionMissedRegex;
    if (regex.index != 4) return error.MixedRouteSelectionWrongRegex;

    const prefix = http.location_router.matchLocation(allocator, "/api/users", &blocks) orelse return error.MixedRouteSelectionMissedPrefix;
    if (prefix.index != 1) return error.MixedRouteSelectionWrongPrefix;
}

fn runProxyStreamedHeaderSerializer() !void {
    const upstream_headers = [_]std.http.Header{
        .{ .name = "Content-Type", .value = "application/json" },
        .{ .name = "Connection", .value = "keep-alive" },
        .{ .name = "X-App-Version", .value = "2026.08.21" },
    };

    const security = http.security_headers.SecurityHeaders.default;
    var buf: [2048]u8 = undefined;
    var stream = compat.fixedBufferStream(&buf);
    try gpr.writeStreamedUpstreamResponseHeadFromHeaders(
        stream.writer(),
        200,
        "OK",
        &upstream_headers,
        true,
        "tg-1778460305668-bfebecb410803023",
        &security,
        null,
        "tg_sticky=proxy; Path=/; HttpOnly",
    );
    const out = stream.getWritten();
    if (std.mem.find(u8, out, "X-App-Version: 2026.08.21\r\n") == null) return error.ProxyHeaderHeavyMissingForwardedHeader;
    if (std.mem.find(u8, out, "Connection: keep-alive\r\n") != null) return error.ProxyHeaderHeavyLeakedHopByHopHeader;
}

fn runRejectedOverload(allocator: std.mem.Allocator) !void {
    const request_id = "tg-1778460305668-bfebecb410803023";
    const payload = try gp.buildApiErrorJson(allocator, "overloaded", "Too many in-flight requests", request_id);
    defer allocator.free(payload);

    var response = http.Response.json(allocator, payload);
    defer response.deinit();
    _ = response.setStatus(.service_unavailable).setConnection(false);
    gp.setRequestIdHeaders(&response, request_id);

    var buf: [2048]u8 = undefined;
    var stream = compat.fixedBufferStream(&buf);
    try response.write(stream.writer());
    const out = stream.getWritten();
    if (std.mem.find(u8, out, "503 Service Unavailable") == null) return error.RejectedOverloadWrongStatus;
    if (std.mem.find(u8, out, "\"code\":\"overloaded\"") == null) return error.RejectedOverloadMissingCode;
}

fn assertBudgets(results: []const ScenarioResult) !void {
    for (results) |result| {
        const budget = result.budget();
        const max_allocations = budget.max_allocations_per_request * result.requests;
        const max_bytes = budget.max_bytes_per_request * result.requests;
        if (result.stats.allocations > max_allocations) {
            std.debug.print(
                "allocation regression in {s}: allocations/request {d}.{d:0>2} exceeds budget {d}\n",
                .{
                    result.scenario.name(),
                    result.stats.allocations / result.requests,
                    ((result.stats.allocations % result.requests) * 100) / result.requests,
                    budget.max_allocations_per_request,
                },
            );
            return error.AllocationBudgetExceeded;
        }
        if (result.stats.bytes_allocated > max_bytes) {
            std.debug.print(
                "allocation regression in {s}: bytes/request {d}.{d:0>2} exceeds budget {d}\n",
                .{
                    result.scenario.name(),
                    result.stats.bytes_allocated / result.requests,
                    ((result.stats.bytes_allocated % result.requests) * 100) / result.requests,
                    budget.max_bytes_per_request,
                },
            );
            return error.AllocationByteBudgetExceeded;
        }
    }
}

fn writeJsonReport(writer: anytype, results: []const ScenarioResult) !void {
    try writer.writeAll("{\n");
    try writer.print("  \"_meta\": {{\"benchmark\":\"allocation-regression\",\"requests_per_scenario\":{d},\"note\":\"counts are deterministic allocator calls around in-process hot-path helpers\"}}", .{results[0].requests});
    for (results) |result| {
        const budget = result.budget();
        try writer.print(
            ",\n  \"{s}\": {{\"requests\":{d},\"allocations_total\":{d},\"bytes_allocated_total\":{d},\"allocations_per_request\":",
            .{ result.scenario.name(), result.requests, result.stats.allocations, result.stats.bytes_allocated },
        );
        try writeRatio(writer, result.stats.allocations, result.requests);
        try writer.writeAll(",\"bytes_allocated_per_request\":");
        try writeRatio(writer, result.stats.bytes_allocated, result.requests);
        try writer.print(
            ",\"peak_live_bytes\":{d},\"frees_total\":{d},\"resize_calls_total\":{d},\"remap_calls_total\":{d},\"allocation_budget_per_request\":{d},\"byte_budget_per_request\":{d},\"budget_rationale\":\"{s}\"}}",
            .{
                result.stats.peak_live_bytes,
                result.stats.frees,
                result.stats.resize_calls,
                result.stats.remap_calls,
                budget.max_allocations_per_request,
                budget.max_bytes_per_request,
                budget.rationale,
            },
        );
    }
    try writer.writeAll("\n}\n");
}

fn writeRatio(writer: anytype, numerator: usize, denominator: usize) !void {
    try writer.print("{d}.{d:0>2}", .{
        numerator / denominator,
        ((numerator % denominator) * 100) / denominator,
    });
}

test "hot path allocation budgets are enforced" {
    const results = try collectResults(std.testing.allocator, default_requests);
    try assertBudgets(results[0..]);
}

test "allocation benchmark report exposes per-request counters" {
    const results = try collectResults(std.testing.allocator, 2);
    try assertBudgets(results[0..]);

    var buf: [8192]u8 = undefined;
    var stream = compat.fixedBufferStream(&buf);
    try writeJsonReport(stream.writer(), results[0..]);
    const out = stream.getWritten();
    try std.testing.expect(std.mem.find(u8, out, "\"allocations_per_request\"") != null);
    try std.testing.expect(std.mem.find(u8, out, "\"bytes_allocated_per_request\"") != null);
    try std.testing.expect(std.mem.find(u8, out, "\"static-tiny-file-warm\"") != null);
    try std.testing.expect(std.mem.find(u8, out, "\"proxy-keepalive-warm\"") != null);
    try std.testing.expect(std.mem.find(u8, out, "\"proxy-header-heavy-response\"") != null);
    try std.testing.expect(std.mem.find(u8, out, "\"mixed-route-selection\"") != null);
}

test "streamed proxy response header serializer filters borrowed headers without allocation" {
    try runProxyStreamedHeaderSerializer();
}
