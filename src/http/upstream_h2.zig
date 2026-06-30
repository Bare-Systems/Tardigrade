//! Single-stream HTTP/2 upstream client (#145, Phase 4b — PR 1).
//!
//! Speaks HTTP/2 to an upstream over an already-connected, ALPN-negotiated TLS
//! transport, **one request/response per connection** — no stream multiplexing
//! yet (that is PR 2, which adds a per-connection reader/demux so many worker
//! threads can share one h2 socket). This module proves the frame + HPACK
//! round-trip end-to-end against a real h2 origin and gives the proxy path an
//! h2 code path to opt into.
//!
//! Scope / limitations (PR 1):
//! - TLS only in production. h2 is negotiated via ALPN, which requires TLS;
//!   cleartext h2c (prior-knowledge) is intentionally not supported here.
//! - Sequential: the connection carries exactly one stream (id 1) and is not
//!   pooled for concurrent reuse.
//! - Flow control is honoured (connection + stream windows, WINDOW_UPDATE) so
//!   bodies larger than the initial 64 KiB window transfer correctly.
//!
//! Built on `http2_frame.zig` (frame codec) and `hpack.zig` (literal encoder +
//! stateful decoder). `exchange` is generic over the transport: it requires
//! `read([]u8) !usize`, `writeAll([]const u8) !void`, and `pending() usize`
//! (`SSL_pending`, so poll-bounded reads do not miss data already buffered in
//! OpenSSL). Reads are bounded with `poll(2)` so a hung origin cannot block a
//! worker indefinitely (the #196 guarantee).

const std = @import("std");
const frame = @import("http2_frame.zig");
const hpack = @import("hpack.zig");

/// HTTP/2 client connection preface (RFC 7540 §3.5).
pub const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const DEFAULT_MAX_FRAME: usize = 16_384;
/// Receive window we advertise per stream (SETTINGS_INITIAL_WINDOW_SIZE).
const OUR_INITIAL_WINDOW: u31 = 1 << 20;
/// HTTP/2 default initial flow-control window for a peer that sent no SETTINGS.
const PROTOCOL_DEFAULT_WINDOW: i64 = 65_535;
const STREAM_ID: u31 = 1;

pub const H2Error = error{
    Http2Timeout,
    Http2GoAway,
    Http2StreamReset,
    Http2ConnectionClosed,
    Http2FrameTooLarge,
    Http2MissingStatus,
};

pub const Request = struct {
    method: []const u8,
    scheme: []const u8 = "https",
    /// `:authority` pseudo-header (host[:port]).
    authority: []const u8,
    path: []const u8,
    /// Extra request headers. Names are lowercased and connection-specific
    /// headers (and Host) are dropped before sending.
    headers: []const std.http.Header = &.{},
    body: []const u8 = "",
};

pub const Response = struct {
    status: u16,
    headers: []hpack.HeaderField,
    body: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Response) void {
        for (self.headers) |h| {
            self.allocator.free(@constCast(h.name));
            self.allocator.free(@constCast(h.value));
        }
        self.allocator.free(self.headers);
        self.allocator.free(self.body);
        self.* = undefined;
    }

    pub fn headerValue(self: *const Response, name: []const u8) ?[]const u8 {
        for (self.headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }
};

const SendState = struct {
    conn_window: i64,
    stream_window: i64,
};

/// Headers an HTTP/2 request must not carry (RFC 7540 §8.1.2.2) plus Host
/// (replaced by `:authority`).
fn isConnectionSpecific(name: []const u8) bool {
    const banned = [_][]const u8{
        "connection",        "keep-alive", "proxy-connection",
        "transfer-encoding", "upgrade",    "host",
    };
    for (banned) |b| if (std.ascii.eqlIgnoreCase(name, b)) return true;
    return false;
}

/// Wait until the transport has readable data, bounded by `deadline_ms`. Checks
/// `pending()` first (decrypted bytes already in the TLS buffer that `poll`
/// cannot see), otherwise polls the fd.
fn pollReadable(transport: anytype, fd: std.posix.fd_t, deadline_ms: u32) H2Error!void {
    if (transport.pending() > 0) return;
    var pfd = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    const n = std.posix.poll(&pfd, @intCast(deadline_ms)) catch return error.Http2ConnectionClosed;
    if (n == 0) return error.Http2Timeout;
}

fn readExact(transport: anytype, fd: std.posix.fd_t, out: []u8, deadline_ms: u32) H2Error!void {
    var off: usize = 0;
    while (off < out.len) {
        try pollReadable(transport, fd, deadline_ms);
        const n = transport.read(out[off..]) catch return error.Http2ConnectionClosed;
        if (n == 0) return error.Http2ConnectionClosed;
        off += n;
    }
}

/// Read one frame, bounding every underlying read with the deadline.
fn readFrameBounded(transport: anytype, fd: std.posix.fd_t, allocator: std.mem.Allocator, deadline_ms: u32) !frame.Frame {
    var header: [frame.HEADER_LEN]u8 = undefined;
    try readExact(transport, fd, header[0..], deadline_ms);
    const len = (@as(usize, header[0]) << 16) | (@as(usize, header[1]) << 8) | @as(usize, header[2]);
    if (len > DEFAULT_MAX_FRAME) return error.Http2FrameTooLarge;
    const typ: frame.Type = @enumFromInt(header[3]);
    const flags = header[4];
    const sid = std.mem.readInt(u32, header[5..9], .big) & 0x7FFF_FFFF;
    const payload = try allocator.alloc(u8, len);
    errdefer allocator.free(payload);
    try readExact(transport, fd, payload, deadline_ms);
    return .{ .typ = typ, .flags = flags, .stream_id = @intCast(sid), .payload = payload };
}

/// Perform one HTTP/2 request/response over `transport`. The connection is
/// consumed for a single stream; the caller closes it afterwards (no pooling in
/// PR 1). `transport` must provide `read`, `writeAll`, and `pending`.
pub fn exchange(
    allocator: std.mem.Allocator,
    transport: anytype,
    fd: std.posix.fd_t,
    req: Request,
    deadline_ms: u32,
) !Response {
    // 1. Client preface + our SETTINGS (disable push; advertise a roomy window).
    try transport.writeAll(PREFACE);
    try frame.writeSettings(allocator, transport, &[_][2]u32{
        .{ 0x2, 0 }, // SETTINGS_ENABLE_PUSH = 0
        .{ 0x4, @as(u32, OUR_INITIAL_WINDOW) }, // SETTINGS_INITIAL_WINDOW_SIZE
    });

    // 2. Request HEADERS (pseudo-headers first), then DATA.
    var fields: std.ArrayList(hpack.HeaderField) = .empty;
    defer fields.deinit(allocator);
    try fields.append(allocator, .{ .name = ":method", .value = req.method });
    try fields.append(allocator, .{ .name = ":scheme", .value = req.scheme });
    try fields.append(allocator, .{ .name = ":authority", .value = req.authority });
    try fields.append(allocator, .{ .name = ":path", .value = req.path });

    var lowered: std.ArrayList([]u8) = .empty;
    defer {
        for (lowered.items) |buf| allocator.free(buf);
        lowered.deinit(allocator);
    }
    for (req.headers) |h| {
        if (isConnectionSpecific(h.name)) continue;
        const lname = try std.ascii.allocLowerString(allocator, h.name);
        try lowered.append(allocator, lname);
        try fields.append(allocator, .{ .name = lname, .value = h.value });
    }

    const header_block = try hpack.encodeLiteralHeaderBlock(allocator, fields.items);
    defer allocator.free(header_block);

    const end_stream_on_headers = req.body.len == 0;
    var hflags: u8 = frame.Flags.END_HEADERS;
    if (end_stream_on_headers) hflags |= frame.Flags.END_STREAM;
    try frame.writeFrame(transport, .headers, hflags, STREAM_ID, header_block);

    // 3. Flow-controlled request body.
    var send_state = SendState{ .conn_window = PROTOCOL_DEFAULT_WINDOW, .stream_window = PROTOCOL_DEFAULT_WINDOW };
    if (req.body.len > 0) {
        try sendBody(allocator, transport, fd, req.body, &send_state, deadline_ms);
    }

    // 4. Read frames until the response stream ends.
    var decoder = hpack.Decoder.init();
    defer decoder.deinit(allocator);

    var header_accum: std.ArrayList(u8) = .empty;
    defer header_accum.deinit(allocator);
    var awaiting_continuation = false;

    var status: ?u16 = null;
    var resp_headers: std.ArrayList(hpack.HeaderField) = .empty;
    errdefer freeHeaderList(allocator, &resp_headers);
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);

    while (true) {
        var fr = try readFrameBounded(transport, fd, allocator, deadline_ms);
        defer frame.deinitFrame(allocator, &fr);

        switch (fr.typ) {
            .settings => {
                if ((fr.flags & frame.Flags.ACK) == 0) {
                    applyPeerSettings(fr.payload, &send_state);
                    try frame.writeSettingsAck(transport);
                }
            },
            .ping => {
                if ((fr.flags & frame.Flags.ACK) == 0) try frame.writePingAck(transport, fr.payload);
            },
            .window_update => {
                const inc = frame.parseWindowUpdateIncrement(fr.payload) catch continue;
                if (fr.stream_id == 0) {
                    send_state.conn_window += @as(i64, inc);
                } else if (fr.stream_id == STREAM_ID) {
                    send_state.stream_window += @as(i64, inc);
                }
            },
            .goaway => return error.Http2GoAway,
            .rst_stream => {
                if (fr.stream_id == STREAM_ID) return error.Http2StreamReset;
            },
            .headers, .continuation => {
                if (fr.stream_id != STREAM_ID and fr.stream_id != 0) continue;
                const block = headerBlockFragment(fr);
                try header_accum.appendSlice(allocator, block);
                awaiting_continuation = (fr.flags & frame.Flags.END_HEADERS) == 0;
                if (!awaiting_continuation) {
                    try decodeHeaderBlock(allocator, &decoder, header_accum.items, &status, &resp_headers);
                    header_accum.clearRetainingCapacity();
                }
                if ((fr.flags & frame.Flags.END_STREAM) != 0 and !awaiting_continuation) break;
            },
            .data => {
                if (fr.stream_id == STREAM_ID and fr.payload.len > 0) {
                    try body.appendSlice(allocator, fr.payload);
                    // Replenish both windows so the origin keeps sending.
                    frame.writeWindowUpdate(transport, 0, @intCast(fr.payload.len)) catch {};
                    frame.writeWindowUpdate(transport, STREAM_ID, @intCast(fr.payload.len)) catch {};
                }
                if ((fr.flags & frame.Flags.END_STREAM) != 0) break;
            },
            else => {},
        }
    }

    const final_status = status orelse return error.Http2MissingStatus;
    return .{
        .status = final_status,
        .headers = try resp_headers.toOwnedSlice(allocator),
        .body = try body.toOwnedSlice(allocator),
        .allocator = allocator,
    };
}

fn applyPeerSettings(payload: []const u8, state: *SendState) void {
    var i: usize = 0;
    while (i + 6 <= payload.len) : (i += 6) {
        const id = std.mem.readInt(u16, payload[i..][0..2], .big);
        const val = std.mem.readInt(u32, payload[i + 2 ..][0..4], .big);
        if (id == 0x4) state.stream_window = @as(i64, val); // SETTINGS_INITIAL_WINDOW_SIZE
    }
}

/// Send the request body as DATA frames, respecting connection + stream flow
/// control. Blocks reading WINDOW_UPDATE/SETTINGS frames when a window is
/// exhausted.
fn sendBody(
    allocator: std.mem.Allocator,
    transport: anytype,
    fd: std.posix.fd_t,
    full_body: []const u8,
    state: *SendState,
    deadline_ms: u32,
) !void {
    var off: usize = 0;
    while (off < full_body.len) {
        while (state.conn_window <= 0 or state.stream_window <= 0) {
            try pumpForWindow(allocator, transport, fd, state, deadline_ms);
        }
        const budget = @min(state.conn_window, state.stream_window);
        const chunk = @min(@min(full_body.len - off, DEFAULT_MAX_FRAME), @as(usize, @intCast(budget)));
        const is_last = (off + chunk) == full_body.len;
        const flags: u8 = if (is_last) frame.Flags.END_STREAM else 0;
        try frame.writeFrame(transport, .data, flags, STREAM_ID, full_body[off .. off + chunk]);
        state.conn_window -= @as(i64, @intCast(chunk));
        state.stream_window -= @as(i64, @intCast(chunk));
        off += chunk;
    }
}

/// Read one frame while blocked on flow control, applying WINDOW_UPDATE/SETTINGS
/// so the send loop can make progress.
fn pumpForWindow(
    allocator: std.mem.Allocator,
    transport: anytype,
    fd: std.posix.fd_t,
    state: *SendState,
    deadline_ms: u32,
) !void {
    var fr = try readFrameBounded(transport, fd, allocator, deadline_ms);
    defer frame.deinitFrame(allocator, &fr);
    switch (fr.typ) {
        .window_update => {
            const inc = frame.parseWindowUpdateIncrement(fr.payload) catch return;
            if (fr.stream_id == 0) {
                state.conn_window += @as(i64, inc);
            } else if (fr.stream_id == STREAM_ID) {
                state.stream_window += @as(i64, inc);
            }
        },
        .settings => {
            if ((fr.flags & frame.Flags.ACK) == 0) {
                applyPeerSettings(fr.payload, state);
                try frame.writeSettingsAck(transport);
            }
        },
        .ping => {
            if ((fr.flags & frame.Flags.ACK) == 0) try frame.writePingAck(transport, fr.payload);
        },
        .goaway => return error.Http2GoAway,
        .rst_stream => if (fr.stream_id == STREAM_ID) return error.Http2StreamReset,
        else => {},
    }
}

/// Extract the header-block fragment from a HEADERS frame, skipping the PADDED
/// pad length and any PRIORITY exclusivity/dependency/weight fields.
fn headerBlockFragment(fr: frame.Frame) []const u8 {
    if (fr.typ == .continuation) return fr.payload;
    var p = fr.payload;
    var pad_len: usize = 0;
    if ((fr.flags & frame.Flags.PADDED) != 0 and p.len >= 1) {
        pad_len = p[0];
        p = p[1..];
    }
    if ((fr.flags & frame.Flags.PRIORITY) != 0 and p.len >= 5) {
        p = p[5..];
    }
    if (pad_len <= p.len) p = p[0 .. p.len - pad_len];
    return p;
}

fn decodeHeaderBlock(
    allocator: std.mem.Allocator,
    decoder: *hpack.Decoder,
    block: []const u8,
    status: *?u16,
    out: *std.ArrayList(hpack.HeaderField),
) !void {
    var decoded = try decoder.decode(allocator, block);
    defer hpack.deinitDecoded(allocator, &decoded);
    for (decoded.headers) |h| {
        if (std.mem.eql(u8, h.name, ":status")) {
            if (status.* == null) status.* = std.fmt.parseInt(u16, h.value, 10) catch null;
            continue;
        }
        if (h.name.len > 0 and h.name[0] == ':') continue; // skip other pseudo-headers
        try out.append(allocator, .{
            .name = try allocator.dupe(u8, h.name),
            .value = try allocator.dupe(u8, h.value),
        });
    }
}

fn freeHeaderList(allocator: std.mem.Allocator, list: *std.ArrayList(hpack.HeaderField)) void {
    for (list.items) |h| {
        allocator.free(@constCast(h.name));
        allocator.free(@constCast(h.value));
    }
    list.deinit(allocator);
}

const testing = std.testing;

test "isConnectionSpecific filters hop-by-hop and Host headers" {
    try testing.expect(isConnectionSpecific("Connection"));
    try testing.expect(isConnectionSpecific("transfer-encoding"));
    try testing.expect(isConnectionSpecific("Host"));
    try testing.expect(!isConnectionSpecific("content-type"));
    try testing.expect(!isConnectionSpecific("x-custom"));
}

test "headerBlockFragment strips padding and priority" {
    // PADDED+PRIORITY: [pad_len=2][5 priority bytes][block "AB"][2 pad bytes]
    var payload = [_]u8{ 2, 0, 0, 0, 0, 0, 'A', 'B', 0, 0 };
    const fr = frame.Frame{
        .typ = .headers,
        .flags = frame.Flags.PADDED | frame.Flags.PRIORITY,
        .stream_id = 1,
        .payload = payload[0..],
    };
    try testing.expectEqualStrings("AB", headerBlockFragment(fr));
}

test "applyPeerSettings updates the stream send window" {
    var state = SendState{ .conn_window = 65535, .stream_window = 65535 };
    const payload = [_]u8{ 0x00, 0x04, 0x00, 0x00, 0x03, 0xE8 }; // INITIAL_WINDOW_SIZE = 1000
    applyPeerSettings(payload[0..], &state);
    try testing.expectEqual(@as(i64, 1000), state.stream_window);
}

/// A plain (non-TLS) fd transport for tests. `pending()` is always 0.
const PlainTransport = struct {
    fd: std.posix.fd_t,
    pub fn read(self: *PlainTransport, buf: []u8) !usize {
        const n = std.c.read(self.fd, buf.ptr, buf.len);
        if (n < 0) return error.ReadFailed;
        return @intCast(n);
    }
    pub fn writeAll(self: *PlainTransport, data: []const u8) !void {
        var off: usize = 0;
        while (off < data.len) {
            const n = std.c.write(self.fd, data.ptr + off, data.len - off);
            if (n <= 0) return error.WriteFailed;
            off += @intCast(n);
        }
    }
    pub fn pending(_: *const PlainTransport) usize {
        return 0;
    }
};

fn makeSocketpair() ![2]std.posix.fd_t {
    var fds: [2]std.posix.fd_t = undefined;
    try testing.expect(std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) == 0);
    return fds;
}

/// Minimal canned h2 server: consume the client's preface + frames up to the
/// request HEADERS, then answer with SETTINGS + response HEADERS + DATA.
fn cannedH2Server(peer_fd: std.posix.fd_t, body: []const u8) void {
    const a = std.heap.page_allocator;
    var srv = PlainTransport{ .fd = peer_fd };

    var preface: [PREFACE.len]u8 = undefined;
    readExact(&srv, peer_fd, preface[0..], 1000) catch return;

    // Consume frames until we see the request HEADERS.
    while (true) {
        var fr = readFrameBounded(&srv, peer_fd, a, 1000) catch return;
        const is_headers = fr.typ == .headers;
        frame.deinitFrame(a, &fr);
        if (is_headers) break;
    }

    frame.writeSettings(a, &srv, &[_][2]u32{}) catch return;
    const block = hpack.encodeLiteralHeaderBlock(a, &[_]hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    }) catch return;
    defer a.free(block);
    frame.writeFrame(&srv, .headers, frame.Flags.END_HEADERS, STREAM_ID, block) catch return;
    frame.writeFrame(&srv, .data, frame.Flags.END_STREAM, STREAM_ID, body) catch return;
}

test "h2 exchange round-trips a request and response over a socketpair" {
    const fds = try makeSocketpair();
    defer _ = std.c.close(fds[0]);

    const server = try std.Thread.spawn(.{}, cannedH2Server, .{ fds[1], @as([]const u8, "hello h2") });

    var transport = PlainTransport{ .fd = fds[0] };
    var resp = try exchange(testing.allocator, &transport, fds[0], .{
        .method = "GET",
        .authority = "example.test",
        .path = "/",
        .headers = &.{.{ .name = "x-custom", .value = "1" }},
    }, 1000);
    defer resp.deinit();

    server.join();
    _ = std.c.close(fds[1]);

    try testing.expectEqual(@as(u16, 200), resp.status);
    try testing.expectEqualStrings("hello h2", resp.body);
    try testing.expectEqualStrings("text/plain", resp.headerValue("content-type").?);
}
