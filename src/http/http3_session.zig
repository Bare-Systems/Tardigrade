const std = @import("std");
const build_options = @import("build_options");
const Headers = @import("headers.zig").Headers;
const qpack = @import("qpack.zig");
const Response = @import("response.zig").Response;

const nghttp3_enabled = build_options.enable_http3_ngtcp2;

pub const Http3SessionError = error{
    DependencyUnavailable,
    NotYetImplemented,
    InvalidStreamHeaders,
};

pub const StreamRequest = struct {
    allocator: std.mem.Allocator,
    method: []u8,
    path: []u8,
    authority: ?[]u8,
    headers: Headers,
    body: []u8,

    pub fn deinit(self: *StreamRequest) void {
        self.allocator.free(self.method);
        self.allocator.free(self.path);
        if (self.authority) |authority| self.allocator.free(authority);
        self.headers.deinit();
        self.allocator.free(self.body);
        self.* = undefined;
    }
};

pub const StreamAssembler = struct {
    allocator: std.mem.Allocator,
    method: ?[]u8 = null,
    path: ?[]u8 = null,
    authority: ?[]u8 = null,
    headers: Headers,
    body: std.ArrayList(u8),

    pub fn init(allocator: std.mem.Allocator) StreamAssembler {
        return .{
            .allocator = allocator,
            .headers = Headers.init(allocator),
            .body = std.ArrayList(u8).init(allocator),
        };
    }

    pub fn deinit(self: *StreamAssembler) void {
        if (self.method) |value| self.allocator.free(value);
        if (self.path) |value| self.allocator.free(value);
        if (self.authority) |value| self.allocator.free(value);
        self.headers.deinit();
        self.body.deinit();
        self.* = undefined;
    }

    pub fn appendHeaderBlock(self: *StreamAssembler, fields: []const qpack.HeaderField) !void {
        for (fields) |field| {
            if (std.mem.eql(u8, field.name, ":method")) {
                try replaceOwnedString(self.allocator, &self.method, field.value);
                continue;
            }
            if (std.mem.eql(u8, field.name, ":path")) {
                try replaceOwnedString(self.allocator, &self.path, field.value);
                continue;
            }
            if (std.mem.eql(u8, field.name, ":authority")) {
                try replaceOwnedString(self.allocator, &self.authority, field.value);
                continue;
            }
            if (field.name.len > 0 and field.name[0] == ':') continue;
            try self.headers.append(field.name, field.value);
        }
    }

    pub fn appendBody(self: *StreamAssembler, chunk: []const u8) !void {
        try self.body.appendSlice(chunk);
    }

    pub fn finish(self: *StreamAssembler) !StreamRequest {
        const method = self.method orelse return error.InvalidStreamHeaders;
        const path = self.path orelse return error.InvalidStreamHeaders;

        var headers = Headers.init(self.allocator);
        errdefer headers.deinit();
        for (self.headers.iterator()) |header| {
            try headers.append(header.name, header.value);
        }
        if (self.authority) |authority| {
            if (headers.get("host") == null) try headers.append("Host", authority);
        }

        return .{
            .allocator = self.allocator,
            .method = try self.allocator.dupe(u8, method),
            .path = try self.allocator.dupe(u8, path),
            .authority = if (self.authority) |authority| try self.allocator.dupe(u8, authority) else null,
            .headers = headers,
            .body = try self.body.toOwnedSlice(),
        };
    }
};

pub const ServerSession = if (nghttp3_enabled) struct {
    const c = @cImport({
        @cInclude("ngtcp2/ngtcp2.h");
        @cInclude("nghttp3/nghttp3.h");
    });

    const StreamEntry = struct {
        assembler: StreamAssembler,
        complete_request: ?StreamRequest = null,
        response_body: ?[]u8 = null,
        response_sent: usize = 0,

        fn deinit(self: *StreamEntry) void {
            if (self.complete_request) |*req| req.deinit();
            if (self.response_body) |body| self.assembler.allocator.free(body);
            self.assembler.deinit();
            self.* = undefined;
        }
    };

    const SessionState = struct {
        allocator: std.mem.Allocator,
        streams: std.AutoHashMap(i64, StreamEntry),
        quic_conn_ptr: ?*anyopaque = null,

        fn init(allocator: std.mem.Allocator) SessionState {
            return .{
                .allocator = allocator,
                .streams = std.AutoHashMap(i64, StreamEntry).init(allocator),
            };
        }

        fn deinit(self: *SessionState) void {
            var it = self.streams.valueIterator();
            while (it.next()) |entry| entry.deinit();
            self.streams.deinit();
            self.* = undefined;
        }
    };

    allocator: std.mem.Allocator,
    conn: *c.nghttp3_conn,
    state: *SessionState,
    activated: bool = false,

    pub fn init(allocator: std.mem.Allocator) !@This() {
        var callbacks = std.mem.zeroes(c.nghttp3_callbacks);
        callbacks.acked_stream_data = ackedStreamDataCb;
        callbacks.deferred_consume = deferredConsumeCb;
        callbacks.begin_headers = beginHeadersCb;
        callbacks.recv_header = recvHeaderCb;
        callbacks.end_headers = endHeadersCb;
        callbacks.recv_data = recvDataCb;
        callbacks.stop_sending = stopSendingCb;
        callbacks.end_stream = endStreamCb;
        callbacks.reset_stream = resetStreamCb;
        callbacks.rand = randCb;
        callbacks.recv_settings2 = recvSettingsCb;
        callbacks.stream_close = streamCloseCb;

        var settings: c.nghttp3_settings = undefined;
        c.nghttp3_settings_default(&settings);
        settings.qpack_max_dtable_capacity = 4096;
        settings.qpack_blocked_streams = 100;

        const state = try allocator.create(SessionState);
        errdefer allocator.destroy(state);
        state.* = SessionState.init(allocator);
        errdefer state.deinit();

        var conn: ?*c.nghttp3_conn = null;
        if (c.nghttp3_conn_server_new(&conn, &callbacks, &settings, c.nghttp3_mem_default(), state) != 0 or conn == null) {
            return error.DependencyUnavailable;
        }
        errdefer c.nghttp3_conn_del(conn);

        return .{
            .allocator = allocator,
            .conn = conn.?,
            .state = state,
        };
    }

    pub fn deinit(self: *@This()) void {
        c.nghttp3_conn_del(self.conn);
        self.state.deinit();
        self.allocator.destroy(self.state);
        self.* = undefined;
    }

    pub fn activate(self: *@This(), quic_conn_ptr: *anyopaque) !void {
        if (self.activated) return;
        self.state.quic_conn_ptr = quic_conn_ptr;
        const quic_conn: *c.ngtcp2_conn = @ptrCast(@alignCast(quic_conn_ptr));

        const params = c.ngtcp2_conn_get_local_transport_params(quic_conn);
        c.nghttp3_conn_set_max_client_streams_bidi(self.conn, params.*.initial_max_streams_bidi);

        var control_stream_id: i64 = 0;
        if (c.ngtcp2_conn_open_uni_stream(quic_conn, &control_stream_id, null) != 0) return error.NotYetImplemented;
        if (c.nghttp3_conn_bind_control_stream(self.conn, control_stream_id) != 0) return error.NotYetImplemented;

        var qpack_encoder_stream_id: i64 = 0;
        if (c.ngtcp2_conn_open_uni_stream(quic_conn, &qpack_encoder_stream_id, null) != 0) return error.NotYetImplemented;

        var qpack_decoder_stream_id: i64 = 0;
        if (c.ngtcp2_conn_open_uni_stream(quic_conn, &qpack_decoder_stream_id, null) != 0) return error.NotYetImplemented;

        if (c.nghttp3_conn_bind_qpack_streams(self.conn, qpack_encoder_stream_id, qpack_decoder_stream_id) != 0) {
            return error.NotYetImplemented;
        }

        self.activated = true;
    }

    pub fn ingestRequestBytes(self: *@This(), stream_id: i64, src: []const u8, fin: bool) !usize {
        const consumed = c.nghttp3_conn_read_stream2(
            self.conn,
            stream_id,
            src.ptr,
            src.len,
            if (fin) 1 else 0,
            @intCast(std.time.nanoTimestamp()),
        );
        if (consumed < 0) return error.NotYetImplemented;
        return @intCast(consumed);
    }

    pub fn addAckOffset(self: *@This(), stream_id: i64, datalen: usize) !void {
        if (c.nghttp3_conn_add_ack_offset(self.conn, stream_id, datalen) != 0) return error.NotYetImplemented;
    }

    pub fn unblockStream(self: *@This(), stream_id: i64) !void {
        if (c.nghttp3_conn_unblock_stream(self.conn, stream_id) != 0) return error.NotYetImplemented;
    }

    pub fn setMaxClientStreamsBidi(self: *@This(), max_streams: u64) void {
        c.nghttp3_conn_set_max_client_streams_bidi(self.conn, max_streams);
    }

    pub fn isActivated(self: *const @This()) bool {
        return self.activated;
    }

    pub fn rawConn(self: *const @This()) *anyopaque {
        return @ptrCast(self.conn);
    }

    pub fn takeCompletedRequest(self: *@This(), stream_id: i64) ?StreamRequest {
        if (self.state.streams.getPtr(stream_id)) |entry| {
            if (entry.complete_request) |req| {
                const out = req;
                entry.complete_request = null;
                return out;
            }
        }
        return null;
    }

    pub fn closeStream(self: *@This(), stream_id: i64) void {
        _ = c.nghttp3_conn_close_stream(self.conn, stream_id, 0);
        if (self.state.streams.fetchRemove(stream_id)) |entry| {
            var removed = entry.value;
            removed.deinit();
        }
    }

    pub fn addWriteOffset(self: *@This(), stream_id: i64, datalen: usize) void {
        if (self.state.streams.getPtr(stream_id)) |entry| {
            if (entry.response_body != null) {
                entry.response_sent = @min(entry.response_sent + datalen, entry.response_body.?.len);
            }
        }
    }

    pub fn submitResponse(self: *@This(), allocator: std.mem.Allocator, stream_id: i64, response: *const Response) !void {
        if (!self.activated) return error.NotYetImplemented;
        const entry = getOrCreateStreamFromState(self.state, stream_id) catch return error.NotYetImplemented;
        if (entry.response_body) |body| allocator.free(body);
        entry.response_body = null;
        entry.response_sent = 0;

        var owned_nva = try allocNghttp3Nva(allocator, response);
        defer owned_nva.deinit(allocator);

        var data_reader = c.nghttp3_data_reader{ .read_data = readDataCb };
        const reader_ptr = if (response.body) |body|
            blk: {
                entry.response_body = try allocator.dupe(u8, body);
                break :blk if (body.len > 0) &data_reader else null;
            }
        else
            null;

        if (c.nghttp3_conn_submit_response(self.conn, stream_id, owned_nva.nva.ptr, owned_nva.nva.len, reader_ptr) != 0) {
            return error.NotYetImplemented;
        }
    }

    fn getSelf(conn_user_data: ?*anyopaque) *SessionState {
        return @ptrCast(@alignCast(conn_user_data.?));
    }

    fn getOrCreateStreamFromState(state: *SessionState, stream_id: i64) !*StreamEntry {
        if (state.streams.getPtr(stream_id)) |entry| return entry;
        try state.streams.put(stream_id, .{ .assembler = StreamAssembler.init(state.allocator) });
        return state.streams.getPtr(stream_id).?;
    }

    fn beginHeadersCb(_: ?*c.nghttp3_conn, stream_id: i64, conn_user_data: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
        const state = getSelf(conn_user_data);
        _ = getOrCreateStreamFromState(state, stream_id) catch return c.NGHTTP3_ERR_CALLBACK_FAILURE;
        return 0;
    }

    fn recvHeaderCb(_: ?*c.nghttp3_conn, stream_id: i64, _: i32, name: ?*c.nghttp3_rcbuf, value: ?*c.nghttp3_rcbuf, _: u8, conn_user_data: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
        const state = getSelf(conn_user_data);
        const entry = getOrCreateStreamFromState(state, stream_id) catch return c.NGHTTP3_ERR_CALLBACK_FAILURE;
        const name_buf = c.nghttp3_rcbuf_get_buf(name);
        const value_buf = c.nghttp3_rcbuf_get_buf(value);
        entry.assembler.appendHeaderBlock(&.{.{
            .name = name_buf.base[0..name_buf.len],
            .value = value_buf.base[0..value_buf.len],
        }}) catch return c.NGHTTP3_ERR_CALLBACK_FAILURE;
        return 0;
    }

    fn endHeadersCb(_: ?*c.nghttp3_conn, _: i64, _: c_int, _: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
        return 0;
    }

    fn recvDataCb(_: ?*c.nghttp3_conn, stream_id: i64, data: [*c]const u8, datalen: usize, conn_user_data: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
        const state = getSelf(conn_user_data);
        const entry = getOrCreateStreamFromState(state, stream_id) catch return c.NGHTTP3_ERR_CALLBACK_FAILURE;
        entry.assembler.appendBody(data[0..datalen]) catch return c.NGHTTP3_ERR_CALLBACK_FAILURE;
        return 0;
    }

    fn ackedStreamDataCb(_: ?*c.nghttp3_conn, _: i64, _: u64, _: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
        return 0;
    }

    fn deferredConsumeCb(_: ?*c.nghttp3_conn, _: i64, _: usize, _: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
        return 0;
    }

    fn endStreamCb(_: ?*c.nghttp3_conn, stream_id: i64, conn_user_data: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
        const state = getSelf(conn_user_data);
        const entry = getOrCreateStreamFromState(state, stream_id) catch return c.NGHTTP3_ERR_CALLBACK_FAILURE;
        if (entry.complete_request == null) {
            entry.complete_request = entry.assembler.finish() catch return c.NGHTTP3_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    fn streamCloseCb(_: ?*c.nghttp3_conn, stream_id: i64, _: u64, conn_user_data: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
        const state = getSelf(conn_user_data);
        if (state.streams.fetchRemove(stream_id)) |entry| {
            var removed = entry.value;
            removed.deinit();
        }
        return 0;
    }

    fn stopSendingCb(_: ?*c.nghttp3_conn, stream_id: i64, app_error_code: u64, conn_user_data: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
        const state = getSelf(conn_user_data);
        const quic_conn_ptr = state.quic_conn_ptr orelse return 0;
        const quic_conn: *c.ngtcp2_conn = @ptrCast(@alignCast(quic_conn_ptr));
        if (c.ngtcp2_conn_shutdown_stream_read(quic_conn, 0, stream_id, app_error_code) != 0) return c.NGHTTP3_ERR_CALLBACK_FAILURE;
        return 0;
    }

    fn resetStreamCb(_: ?*c.nghttp3_conn, stream_id: i64, app_error_code: u64, conn_user_data: ?*anyopaque, _: ?*anyopaque) callconv(.c) c_int {
        const state = getSelf(conn_user_data);
        const quic_conn_ptr = state.quic_conn_ptr orelse return 0;
        const quic_conn: *c.ngtcp2_conn = @ptrCast(@alignCast(quic_conn_ptr));
        if (c.ngtcp2_conn_shutdown_stream_write(quic_conn, 0, stream_id, app_error_code) != 0) return c.NGHTTP3_ERR_CALLBACK_FAILURE;
        return 0;
    }

    fn randCb(dest: [*c]u8, destlen: usize) callconv(.c) void {
        std.crypto.random.bytes(dest[0..destlen]);
    }

    fn recvSettingsCb(_: ?*c.nghttp3_conn, _: ?*const c.nghttp3_proto_settings, _: ?*anyopaque) callconv(.c) c_int {
        return 0;
    }

    fn readDataCb(_: ?*c.nghttp3_conn, stream_id: i64, vec: [*c]c.nghttp3_vec, veccnt: usize, pflags: [*c]u32, conn_user_data: ?*anyopaque, _: ?*anyopaque) callconv(.c) c.nghttp3_ssize {
        const state = getSelf(conn_user_data);
        const entry = state.streams.getPtr(stream_id) orelse return c.NGHTTP3_ERR_CALLBACK_FAILURE;
        const body = entry.response_body orelse {
            pflags.* = c.NGHTTP3_DATA_FLAG_EOF;
            return 0;
        };
        if (entry.response_sent >= body.len) {
            pflags.* = c.NGHTTP3_DATA_FLAG_EOF;
            return 0;
        }
        if (veccnt == 0) return c.NGHTTP3_ERR_CALLBACK_FAILURE;

        const remaining = body[entry.response_sent..];
        vec[0].base = remaining.ptr;
        vec[0].len = remaining.len;
        pflags.* = c.NGHTTP3_DATA_FLAG_EOF;
        return 1;
    }

    const OwnedNva = struct {
        nva: []c.nghttp3_nv,
        status_buf: []u8,

        fn deinit(self: *OwnedNva, allocator: std.mem.Allocator) void {
            allocator.free(self.status_buf);
            allocator.free(self.nva);
            self.* = undefined;
        }
    };

    fn allocNghttp3Nva(allocator: std.mem.Allocator, response: *const Response) !OwnedNva {
        const header_count = response.headers.iterator().len + 1;
        var nva = try allocator.alloc(c.nghttp3_nv, header_count);
        const status_buf = try allocator.alloc(u8, 3);
        errdefer allocator.free(status_buf);
        const status_text = try std.fmt.bufPrint(status_buf, "{d}", .{response.status.code()});
        nva[0] = .{
            .name = ":status".ptr,
            .value = status_buf.ptr,
            .namelen = 7,
            .valuelen = status_text.len,
            .flags = 0,
        };
        var i: usize = 1;
        for (response.headers.iterator()) |header| {
            nva[i] = .{
                .name = header.name.ptr,
                .value = header.value.ptr,
                .namelen = header.name.len,
                .valuelen = header.value.len,
                .flags = 0,
            };
            i += 1;
        }
        return .{ .nva = nva, .status_buf = status_buf };
    }
} else struct {
    pub fn init(_: std.mem.Allocator) !@This() {
        return error.DependencyUnavailable;
    }

    pub fn deinit(self: *@This()) void {
        self.* = undefined;
    }

    pub fn ingestRequestBytes(_: *@This(), _: i64, _: []const u8, _: bool) !usize {
        return error.DependencyUnavailable;
    }

    pub fn takeCompletedRequest(_: *@This(), _: i64) ?StreamRequest {
        return null;
    }

    pub fn closeStream(_: *@This(), _: i64) void {}

    pub fn submitResponse(_: *@This(), _: std.mem.Allocator, _: i64, _: *const Response) !void {
        return error.DependencyUnavailable;
    }
};

pub fn encodeResponseHeaderBlock(allocator: std.mem.Allocator, response: *const Response) !qpack.Encoded {
    var fields = std.ArrayList(qpack.HeaderField).init(allocator);
    defer fields.deinit();

    var status_buf: [3]u8 = undefined;
    const status_text = try std.fmt.bufPrint(&status_buf, "{d}", .{response.status.code()});
    try fields.append(.{ .name = ":status", .value = status_text });
    for (response.headers.iterator()) |header| {
        try fields.append(.{ .name = header.name, .value = header.value });
    }
    return qpack.encodeLiteralHeaderBlock(allocator, fields.items);
}

fn replaceOwnedString(allocator: std.mem.Allocator, slot: *?[]u8, value: []const u8) !void {
    if (slot.*) |existing| allocator.free(existing);
    slot.* = try allocator.dupe(u8, value);
}

fn appendH3Frame(out: *std.ArrayList(u8), frame_type: u8, payload: []const u8) !void {
    try appendQuicVarInt(out, frame_type);
    try appendQuicVarInt(out, payload.len);
    try out.appendSlice(payload);
}

fn appendQuicVarInt(out: *std.ArrayList(u8), value: usize) !void {
    if (value < 64) {
        try out.append(@intCast(value));
        return;
    }
    if (value < 16_384) {
        const encoded: u16 = @intCast(0x4000 | value);
        try out.append(@intCast(encoded >> 8));
        try out.append(@intCast(encoded & 0xff));
        return;
    }
    return error.NotYetImplemented;
}

test "http3 stream assembler builds request parts from split header and body frames" {
    const allocator = std.testing.allocator;
    var assembler = StreamAssembler.init(allocator);
    defer assembler.deinit();

    try assembler.appendHeaderBlock(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/v1/chat?mode=test" },
    });
    try assembler.appendHeaderBlock(&.{
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "content-type", .value = "application/json" },
    });
    try assembler.appendBody("{\"hello\":");
    try assembler.appendBody("\"world\"}");

    var request = try assembler.finish();
    defer request.deinit();

    try std.testing.expectEqualStrings("POST", request.method);
    try std.testing.expectEqualStrings("/v1/chat?mode=test", request.path);
    try std.testing.expectEqualStrings("example.com", request.authority.?);
    try std.testing.expectEqualStrings("example.com", request.headers.get("Host").?);
    try std.testing.expectEqualStrings("application/json", request.headers.get("content-type").?);
    try std.testing.expectEqualStrings("{\"hello\":\"world\"}", request.body);
}

test "http3 response header encoding includes status pseudo header" {
    const allocator = std.testing.allocator;
    var response = Response.init(allocator);
    defer response.deinit();
    _ = response.setStatus(.accepted).setHeader("content-type", "application/json");

    const encoded = try encodeResponseHeaderBlock(allocator, &response);
    defer allocator.free(encoded.data);
    const decoded = try qpack.decodeLiteralHeaderBlock(allocator, encoded.data);
    defer qpack.deinitDecoded(allocator, decoded);

    try std.testing.expectEqual(@as(usize, 2), decoded.len);
    try std.testing.expectEqualStrings(":status", decoded[0].name);
    try std.testing.expectEqualStrings("202", decoded[0].value);
    try std.testing.expectEqualStrings("content-type", decoded[1].name);
}

test "enabled nghttp3 session initializes and rejects unopened response streams cleanly" {
    if (!nghttp3_enabled) return;

    const allocator = std.testing.allocator;
    var session = try ServerSession.init(allocator);
    defer session.deinit();

    var response = Response.init(allocator);
    defer response.deinit();
    _ = response.setStatus(.ok).setHeader("content-type", "application/json");
    try std.testing.expectError(error.NotYetImplemented, session.submitResponse(allocator, 0, &response));
}
