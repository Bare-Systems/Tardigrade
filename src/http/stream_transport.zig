//! Protocol-agnostic upstream stream transport contract (#241).
//!
//! This is the target shape that the existing h1 buffered/streaming paths,
//! `upstream_h2.H2Conn`, and future h3 transports map to. It is intentionally
//! a small data contract first: no current proxy path is rewritten here.

const std = @import("std");

pub const Protocol = enum {
    h1,
    h2,
    h3,
};

pub const TimeoutPhase = enum {
    connect,
    request_write,
    response_head,
    response_body,
};

pub const TransportMeta = struct {
    protocol: Protocol,
    reused_connection: bool = false,
    stream_id: ?u64 = null,
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const RequestHead = struct {
    method: []const u8,
    scheme: []const u8,
    authority: []const u8,
    path: []const u8,
    headers: []const Header = &.{},
};

pub const BodySource = struct {
    ctx: *anyopaque,
    readFn: *const fn (*anyopaque, []u8) anyerror!usize,

    pub fn read(self: BodySource, out: []u8) !usize {
        return self.readFn(self.ctx, out);
    }
};

pub const RequestBody = union(enum) {
    none,
    buffered: []const u8,
    streaming: BodySource,
};

pub const ResponseHead = struct {
    status: u16,
    reason: []const u8 = "",
    headers: []const Header = &.{},
    meta: TransportMeta,
};

pub const ResponseBody = struct {
    ctx: *anyopaque,
    readFn: *const fn (*anyopaque, []u8) anyerror!usize,
    finishFn: *const fn (*anyopaque) void,

    pub fn read(self: ResponseBody, out: []u8) !usize {
        return self.readFn(self.ctx, out);
    }

    pub fn finish(self: ResponseBody) void {
        self.finishFn(self.ctx);
    }
};

pub const DeliveryState = enum {
    /// The request has not reached the origin. A retry on a fresh connection is
    /// always safe and does not consume the normal attempt budget.
    before_delivery,
    /// The request may have reached the origin, but no response bytes were
    /// written downstream. Retry only when the method and policy allow it.
    sent_no_downstream_response,
    /// Response headers or body bytes have been written downstream. Retrying
    /// would duplicate or fabricate a response and is forbidden.
    response_started_downstream,
};

pub const RetryBoundary = enum {
    safe_before_delivery,
    maybe_safe_before_response,
    unsafe_after_downstream_started,
};

pub fn retryBoundary(state: DeliveryState) RetryBoundary {
    return switch (state) {
        .before_delivery => .safe_before_delivery,
        .sent_no_downstream_response => .maybe_safe_before_response,
        .response_started_downstream => .unsafe_after_downstream_started,
    };
}

pub const Exchange = struct {
    request: RequestHead,
    body: RequestBody,
    connect_timeout_ms: u32 = 0,
    response_timeout_ms: u32 = 0,
};

pub const OpenedResponse = struct {
    head: ResponseHead,
    body: ResponseBody,
    delivery_state: DeliveryState,
};

const SliceReader = struct {
    data: []const u8,
    off: usize = 0,
    finished: bool = false,

    fn read(ctx: *anyopaque, out: []u8) !usize {
        const self: *SliceReader = @ptrCast(@alignCast(ctx));
        const remaining = self.data[self.off..];
        if (remaining.len == 0) return 0;
        const n = @min(out.len, remaining.len);
        @memcpy(out[0..n], remaining[0..n]);
        self.off += n;
        return n;
    }

    fn finish(ctx: *anyopaque) void {
        const self: *SliceReader = @ptrCast(@alignCast(ctx));
        self.finished = true;
    }
};

test "BodySource drains a streaming request body" {
    var reader = SliceReader{ .data = "request-body" };
    const source = BodySource{ .ctx = &reader, .readFn = SliceReader.read };

    var buf: [7]u8 = undefined;
    const first = try source.read(&buf);
    try std.testing.expectEqualSlices(u8, "request", buf[0..first]);
    const second = try source.read(&buf);
    try std.testing.expectEqualSlices(u8, "-body", buf[0..second]);
    try std.testing.expectEqual(@as(usize, 0), try source.read(&buf));
}

test "ResponseBody exposes headers-first pull drain and explicit finish" {
    var reader = SliceReader{ .data = "part1part2" };
    const response = OpenedResponse{
        .head = .{
            .status = 200,
            .reason = "OK",
            .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
            .meta = .{ .protocol = .h2, .reused_connection = true, .stream_id = 5 },
        },
        .body = .{
            .ctx = &reader,
            .readFn = SliceReader.read,
            .finishFn = SliceReader.finish,
        },
        .delivery_state = .sent_no_downstream_response,
    };

    try std.testing.expectEqual(@as(u16, 200), response.head.status);
    try std.testing.expectEqual(Protocol.h2, response.head.meta.protocol);
    try std.testing.expectEqual(@as(?u64, 5), response.head.meta.stream_id);

    var buf: [5]u8 = undefined;
    const n = try response.body.read(&buf);
    try std.testing.expectEqualSlices(u8, "part1", buf[0..n]);
    response.body.finish();
    try std.testing.expect(reader.finished);
}

test "retryBoundary pins the shared retry policy states" {
    try std.testing.expectEqual(RetryBoundary.safe_before_delivery, retryBoundary(.before_delivery));
    try std.testing.expectEqual(RetryBoundary.maybe_safe_before_response, retryBoundary(.sent_no_downstream_response));
    try std.testing.expectEqual(RetryBoundary.unsafe_after_downstream_started, retryBoundary(.response_started_downstream));
}
