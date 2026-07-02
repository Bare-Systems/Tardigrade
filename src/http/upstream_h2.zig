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
const compat = @import("../zig_compat.zig");
const frame = @import("http2_frame.zig");
const hpack = @import("hpack.zig");
const tls_termination = @import("tls_termination.zig");

/// HTTP/2 client connection preface (RFC 7540 §3.5).
pub const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// SHUT_RDWR (`std.posix.shutdown` is unavailable in this std; use `std.c`).
const SHUT_RDWR: c_int = 2;

/// Monotonic-ish wall clock in milliseconds for connection age bookkeeping.
/// Mirrors `event_loop.monotonicMs` without importing it (avoids a cycle).
fn nowMs() u64 {
    const t = compat.milliTimestamp();
    return if (t <= 0) 0 else @intCast(t);
}

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
pub fn readFrameBounded(transport: anytype, fd: std.posix.fd_t, allocator: std.mem.Allocator, deadline_ms: u32) !frame.Frame {
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

// ---------------------------------------------------------------------------
// Multiplexing connection actor (#145, Phase 4b — PR 2).
//
// `H2Conn` carries many concurrent streams over one upstream h2 socket so
// multiple worker threads can share a single origin connection. A dedicated
// reader thread owns all socket reads and HPACK decoding (the dynamic table is
// connection-wide, so exactly one decoder, no lock). Worker threads call the
// blocking `request()`; it allocates a stream, writes HEADERS/DATA under the
// write mutex, and waits on a condition until the reader marks the stream done
// or errored.
//
// Locking: `write_mutex` serializes socket writes; `state_mutex` (+ `cond`)
// guards the streams map, flow-control windows, and connection flags. The two
// mutexes are never held simultaneously — update state, release, then write —
// so there is no lock-ordering deadlock. `deinit` shuts the fd down to wake the
// blocked reader.
// ---------------------------------------------------------------------------

/// One in-flight request/response on an `H2Conn`. Heap-owned by the connection
/// until `request()` reclaims it.
const Stream = struct {
    id: u31,
    send_window: i64,
    /// Per-stream completion signal — the reader signals only the waiter for
    /// this stream, avoiding a thundering herd across all in-flight requests.
    cond: compat.Condition = .{},
    header_block: std.ArrayList(u8) = .empty,
    awaiting_continuation: bool = false,
    status: ?u16 = null,
    headers: std.ArrayList(hpack.HeaderField) = .empty,
    body: std.ArrayList(u8) = .empty,
    done: bool = false,
    err: ?anyerror = null,

    fn destroy(self: *Stream, allocator: std.mem.Allocator) void {
        self.header_block.deinit(allocator);
        freeHeaderList(allocator, &self.headers);
        self.body.deinit(allocator);
        allocator.destroy(self);
    }
};

pub fn H2Conn(comptime Transport: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        transport: Transport,
        /// When set, `deinit` frees the heap-allocated `transport` pointer with
        /// this allocator after closing it. Null for borrowed transports (e.g.
        /// a stack pointer in tests).
        transport_allocator: ?std.mem.Allocator,
        fd: std.posix.fd_t,
        deadline_ms: u32,

        write_mutex: compat.Mutex = .{},
        state_mutex: compat.Mutex = .{},
        cond: compat.Condition = .{},
        decoder: hpack.Decoder, // reader-thread only

        /// Age bookkeeping for the idle/lifetime reaper (#145, PR 3). `created_ms`
        /// is fixed at init; `last_activity_ms` is stamped whenever a stream
        /// starts or finishes. Both are monotonic-ms (see `nowMs`). Read
        /// lock-free by the reaper so it need not take `state_mutex` per conn.
        created_ms: u64 = 0,
        last_activity_ms: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

        /// Pool-level monotonic counters the reader bumps when it sees an
        /// RST_STREAM / GOAWAY, so the totals survive connection teardown (a
        /// live-conn snapshot would lose them). Null for pool-less test conns.
        pool_rst_counter: ?*std.atomic.Value(u64) = null,
        pool_goaway_counter: ?*std.atomic.Value(u64) = null,

        streams: std.AutoHashMap(u31, *Stream),
        next_stream_id: u31 = 1,
        conn_send_window: i64 = PROTOCOL_DEFAULT_WINDOW,
        peer_initial_window: i64 = PROTOCOL_DEFAULT_WINDOW,
        max_concurrent: u32 = 100,
        active_streams: u32 = 0,
        goaway: bool = false,
        conn_err: ?anyerror = null,
        closing: bool = false,
        reader: ?std.Thread = null,

        /// Connect-level error counters (read under `state_mutex`).
        rst_received: u64 = 0,
        goaway_received: u64 = 0,

        /// Reference count: the pool map holds one ref per entry and each
        /// in-flight `request()` holds one. The connection is torn down when the
        /// count reaches zero, so an evicted connection survives until its last
        /// in-flight request completes.
        refs: std.atomic.Value(u32) = std.atomic.Value(u32).init(1),

        /// Create the actor (heap-owned so the reader thread has a stable
        /// pointer), send the preface + SETTINGS, and spawn the reader. The
        /// actor takes ownership of `transport`/`fd` and closes them in `deinit`.
        pub fn init(
            allocator: std.mem.Allocator,
            transport: Transport,
            fd: std.posix.fd_t,
            deadline_ms: u32,
            transport_allocator: ?std.mem.Allocator,
            rst_counter: ?*std.atomic.Value(u64),
            goaway_counter: ?*std.atomic.Value(u64),
        ) !*Self {
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);
            const now = nowMs();
            self.* = .{
                .allocator = allocator,
                .transport = transport,
                .transport_allocator = transport_allocator,
                .fd = fd,
                .deadline_ms = deadline_ms,
                .decoder = hpack.Decoder.init(),
                .streams = std.AutoHashMap(u31, *Stream).init(allocator),
                .created_ms = now,
                .last_activity_ms = std.atomic.Value(u64).init(now),
                .pool_rst_counter = rst_counter,
                .pool_goaway_counter = goaway_counter,
            };

            try self.transport.writeAll(PREFACE);
            try frame.writeSettings(allocator, self.transport, &[_][2]u32{
                .{ 0x2, 0 }, // ENABLE_PUSH = 0
                .{ 0x4, @as(u32, OUR_INITIAL_WINDOW) },
            });

            self.reader = try std.Thread.spawn(.{}, readerLoop, .{self});
            return self;
        }

        pub fn retain(self: *Self) void {
            _ = self.refs.fetchAdd(1, .monotonic);
        }

        /// Drop a reference; tear down when the last one is released.
        pub fn release(self: *Self) void {
            if (self.refs.fetchSub(1, .acq_rel) == 1) self.deinit();
        }

        pub fn deinit(self: *Self) void {
            // Wake the blocked reader, then join it.
            {
                self.state_mutex.lock();
                self.closing = true;
                self.state_mutex.unlock();
            }
            _ = std.c.shutdown(self.fd, SHUT_RDWR);
            if (self.reader) |t| t.join();

            var it = self.streams.iterator();
            while (it.next()) |e| e.value_ptr.*.destroy(self.allocator);
            self.streams.deinit();
            self.decoder.deinit(self.allocator);
            self.transport.close();
            if (self.transport_allocator) |ta| ta.destroy(self.transport);
            const a = self.allocator;
            a.destroy(self);
        }

        /// True if the connection can still accept a new stream.
        pub fn healthy(self: *Self) bool {
            self.state_mutex.lock();
            defer self.state_mutex.unlock();
            return self.conn_err == null and !self.goaway;
        }

        pub fn activeStreamCount(self: *Self) u32 {
            self.state_mutex.lock();
            defer self.state_mutex.unlock();
            return self.active_streams;
        }

        /// Issue one request and block until its response completes. Safe to
        /// call concurrently from many threads on the same connection.
        pub fn request(self: *Self, req: Request) !Response {
            const stream = try self.beginStream();
            var detached = false;
            errdefer if (!detached) self.dropStream(stream);

            try self.sendRequest(stream, req);

            // Wait for the reader to complete or error the stream, then detach
            // it from the map *under the lock* so the reader can no longer touch
            // its header/body buffers before we move them out.
            self.state_mutex.lock();
            while (!stream.done and stream.err == null and self.conn_err == null) {
                stream.cond.wait(&self.state_mutex);
            }
            const stream_err: ?anyerror = if (stream.err != null) stream.err else self.conn_err;
            _ = self.streams.remove(stream.id);
            if (self.active_streams > 0) self.active_streams -= 1;
            detached = true;
            self.state_mutex.unlock();
            self.last_activity_ms.store(nowMs(), .monotonic); // stamp idle-since
            self.cond.broadcast(); // free a concurrency slot

            if (stream_err) |e| {
                stream.destroy(self.allocator);
                return e;
            }
            const status = stream.status orelse {
                stream.destroy(self.allocator);
                return error.Http2MissingStatus;
            };
            // Move header/body ownership out (the stream is no longer in the map).
            const headers = try stream.headers.toOwnedSlice(self.allocator);
            const body = try stream.body.toOwnedSlice(self.allocator);
            stream.destroy(self.allocator);
            return .{ .status = status, .headers = headers, .body = body, .allocator = self.allocator };
        }

        fn beginStream(self: *Self) !*Stream {
            self.state_mutex.lock();
            defer self.state_mutex.unlock();
            while (self.active_streams >= self.max_concurrent and self.conn_err == null and !self.goaway) {
                self.cond.wait(&self.state_mutex);
            }
            if (self.conn_err) |e| return e;
            if (self.goaway) return error.Http2GoAway;

            const id = self.next_stream_id;
            self.next_stream_id +%= 2;
            const stream = try self.allocator.create(Stream);
            stream.* = .{ .id = id, .send_window = self.peer_initial_window };
            try self.streams.put(id, stream);
            self.active_streams += 1;
            self.last_activity_ms.store(nowMs(), .monotonic);
            return stream;
        }

        /// Remove a stream from the map and free it. Used only on the error path
        /// before the stream has been detached.
        fn dropStream(self: *Self, stream: *Stream) void {
            self.state_mutex.lock();
            const removed = self.streams.remove(stream.id);
            if (removed and self.active_streams > 0) self.active_streams -= 1;
            self.state_mutex.unlock();
            self.cond.broadcast();
            stream.destroy(self.allocator);
        }

        fn sendRequest(self: *Self, stream: *Stream, req: Request) !void {
            var fields: std.ArrayList(hpack.HeaderField) = .empty;
            defer fields.deinit(self.allocator);
            try fields.append(self.allocator, .{ .name = ":method", .value = req.method });
            try fields.append(self.allocator, .{ .name = ":scheme", .value = req.scheme });
            try fields.append(self.allocator, .{ .name = ":authority", .value = req.authority });
            try fields.append(self.allocator, .{ .name = ":path", .value = req.path });

            var lowered: std.ArrayList([]u8) = .empty;
            defer {
                for (lowered.items) |b| self.allocator.free(b);
                lowered.deinit(self.allocator);
            }
            for (req.headers) |h| {
                if (isConnectionSpecific(h.name)) continue;
                const lname = try std.ascii.allocLowerString(self.allocator, h.name);
                try lowered.append(self.allocator, lname);
                try fields.append(self.allocator, .{ .name = lname, .value = h.value });
            }

            const block = try hpack.encodeLiteralHeaderBlock(self.allocator, fields.items);
            defer self.allocator.free(block);

            const end_stream = req.body.len == 0;
            // HEADERS, splitting into CONTINUATION if the block exceeds a frame.
            self.write_mutex.lock();
            defer self.write_mutex.unlock();
            try self.writeHeaderBlockLocked(stream.id, block, end_stream);
            if (req.body.len > 0) try self.sendBodyLocked(stream, req.body);
        }

        /// Write a header block as HEADERS (+CONTINUATION) frames. Caller holds
        /// the write mutex.
        fn writeHeaderBlockLocked(self: *Self, id: u31, block: []const u8, end_stream: bool) !void {
            if (block.len <= DEFAULT_MAX_FRAME) {
                var flags: u8 = frame.Flags.END_HEADERS;
                if (end_stream) flags |= frame.Flags.END_STREAM;
                try frame.writeFrame(self.transport, .headers, flags, id, block);
                return;
            }
            var off: usize = 0;
            var first = true;
            while (off < block.len) {
                const chunk = @min(DEFAULT_MAX_FRAME, block.len - off);
                const last = (off + chunk) == block.len;
                const typ: frame.Type = if (first) .headers else .continuation;
                var flags: u8 = 0;
                if (last) flags |= frame.Flags.END_HEADERS;
                if (first and end_stream) flags |= frame.Flags.END_STREAM;
                try frame.writeFrame(self.transport, typ, flags, id, block[off .. off + chunk]);
                off += chunk;
                first = false;
            }
        }

        /// Send the request body as flow-controlled DATA frames. Caller holds
        /// the write mutex; we briefly drop it while waiting for window so the
        /// reader can apply peer WINDOW_UPDATEs.
        fn sendBodyLocked(self: *Self, stream: *Stream, full_body: []const u8) !void {
            var off: usize = 0;
            while (off < full_body.len) {
                const budget = self.reserveSendWindow(stream, full_body.len - off) catch |e| return e;
                const is_last = (off + budget) == full_body.len;
                const flags: u8 = if (is_last) frame.Flags.END_STREAM else 0;
                try frame.writeFrame(self.transport, .data, flags, stream.id, full_body[off .. off + budget]);
                off += budget;
            }
        }

        /// Reserve up to `want` bytes of send window (connection + stream),
        /// waiting if both are exhausted. Returns the granted byte count.
        fn reserveSendWindow(self: *Self, stream: *Stream, want: usize) !usize {
            self.state_mutex.lock();
            defer self.state_mutex.unlock();
            while (true) {
                if (self.conn_err) |e| return e;
                if (stream.err) |e| return e;
                const avail = @min(self.conn_send_window, stream.send_window);
                if (avail > 0) {
                    const grant = @min(@as(i64, @intCast(@min(want, DEFAULT_MAX_FRAME))), avail);
                    self.conn_send_window -= grant;
                    stream.send_window -= grant;
                    return @intCast(grant);
                }
                self.cond.wait(&self.state_mutex);
            }
        }

        // ---- reader thread ----

        fn readerLoop(self: *Self) void {
            while (true) {
                {
                    self.state_mutex.lock();
                    const stop = self.closing;
                    self.state_mutex.unlock();
                    if (stop) break;
                }
                var fr = readFrameBounded(self.transport, self.fd, self.allocator, self.deadline_ms) catch |e| {
                    self.failConnection(e);
                    return;
                };
                self.handleFrame(&fr) catch |e| {
                    frame.deinitFrame(self.allocator, &fr);
                    self.failConnection(e);
                    return;
                };
                frame.deinitFrame(self.allocator, &fr);
            }
        }

        fn handleFrame(self: *Self, fr: *frame.Frame) !void {
            switch (fr.typ) {
                .settings => {
                    if ((fr.flags & frame.Flags.ACK) == 0) {
                        self.applySettings(fr.payload);
                        self.writeControl(.settings, frame.Flags.ACK, 0, &[_]u8{});
                    }
                },
                .ping => {
                    if ((fr.flags & frame.Flags.ACK) == 0) self.writeControl(.ping, frame.Flags.ACK, 0, fr.payload);
                },
                .window_update => {
                    const inc = frame.parseWindowUpdateIncrement(fr.payload) catch return;
                    self.state_mutex.lock();
                    if (fr.stream_id == 0) {
                        self.conn_send_window += @as(i64, inc);
                    } else if (self.streams.get(fr.stream_id)) |s| {
                        s.send_window += @as(i64, inc);
                    }
                    self.state_mutex.unlock();
                    self.cond.broadcast();
                },
                .goaway => {
                    // Bump the pool counter *before* publishing the state
                    // change: an observer that sees `goaway` set (under the
                    // mutex) must also see the incremented counter.
                    if (self.pool_goaway_counter) |c| _ = c.fetchAdd(1, .monotonic);
                    self.state_mutex.lock();
                    self.goaway = true;
                    self.goaway_received += 1;
                    self.state_mutex.unlock();
                    self.cond.broadcast();
                },
                .rst_stream => {
                    // Counted per frame received (protocol-level), matching the
                    // metric help text — including late resets for streams that
                    // already completed and were removed from the map. Bumped
                    // *before* the stream is errored so an observer that sees
                    // the failed stream also sees the incremented counter.
                    if (self.pool_rst_counter) |c| _ = c.fetchAdd(1, .monotonic);
                    self.state_mutex.lock();
                    self.rst_received += 1;
                    const maybe = self.streams.get(fr.stream_id);
                    if (maybe) |s| s.err = error.Http2StreamReset;
                    self.state_mutex.unlock();
                    if (maybe) |s| s.cond.signal();
                },
                .headers, .continuation => try self.handleHeaders(fr),
                .data => try self.handleData(fr),
                else => {},
            }
        }

        fn handleHeaders(self: *Self, fr: *frame.Frame) !void {
            const block = headerBlockFragment(fr.*);
            const end_headers = (fr.flags & frame.Flags.END_HEADERS) != 0;
            const end_stream = (fr.flags & frame.Flags.END_STREAM) != 0;

            // Accumulate the fragment on the stream (under state lock).
            self.state_mutex.lock();
            const maybe_stream = self.streams.get(fr.stream_id);
            if (maybe_stream) |s| {
                s.header_block.appendSlice(self.allocator, block) catch {
                    self.state_mutex.unlock();
                    return error.OutOfMemory;
                };
                s.awaiting_continuation = !end_headers;
            }
            self.state_mutex.unlock();
            if (maybe_stream == null) return; // unknown/closed stream — ignore

            if (!end_headers) return; // wait for CONTINUATION

            // Decode the complete block with the connection-wide decoder (this
            // thread is the only decoder user). Copy out the block first so we
            // do not hold the state lock across decode.
            const s = maybe_stream.?;
            self.state_mutex.lock();
            const owned_block = self.allocator.dupe(u8, s.header_block.items) catch {
                self.state_mutex.unlock();
                return error.OutOfMemory;
            };
            s.header_block.clearRetainingCapacity();
            self.state_mutex.unlock();
            defer self.allocator.free(owned_block);

            var decoded = try self.decoder.decode(self.allocator, owned_block);
            defer hpack.deinitDecoded(self.allocator, &decoded);

            self.state_mutex.lock();
            defer {
                self.state_mutex.unlock();
                s.cond.signal();
            }
            for (decoded.headers) |h| {
                if (std.mem.eql(u8, h.name, ":status")) {
                    if (s.status == null) s.status = std.fmt.parseInt(u16, h.value, 10) catch null;
                    continue;
                }
                if (h.name.len > 0 and h.name[0] == ':') continue;
                s.headers.append(self.allocator, .{
                    .name = try self.allocator.dupe(u8, h.name),
                    .value = try self.allocator.dupe(u8, h.value),
                }) catch return error.OutOfMemory;
            }
            if (end_stream) s.done = true;
        }

        fn handleData(self: *Self, fr: *frame.Frame) !void {
            const end_stream = (fr.flags & frame.Flags.END_STREAM) != 0;
            self.state_mutex.lock();
            const maybe_stream = self.streams.get(fr.stream_id);
            if (maybe_stream) |s| {
                if (fr.payload.len > 0) s.body.appendSlice(self.allocator, fr.payload) catch {
                    self.state_mutex.unlock();
                    return error.OutOfMemory;
                };
                if (end_stream) s.done = true;
            }
            self.state_mutex.unlock();

            if (fr.payload.len > 0) {
                // Replenish our receive window so the origin keeps sending.
                const inc = windowIncrement(fr.payload.len);
                self.writeControl(.window_update, 0, 0, &inc);
                self.writeControl(.window_update, 0, fr.stream_id, &inc);
            }
            if (maybe_stream) |s| s.cond.signal();
        }

        fn applySettings(self: *Self, payload: []const u8) void {
            self.state_mutex.lock();
            defer self.state_mutex.unlock();
            var i: usize = 0;
            while (i + 6 <= payload.len) : (i += 6) {
                const id = std.mem.readInt(u16, payload[i..][0..2], .big);
                const val = std.mem.readInt(u32, payload[i + 2 ..][0..4], .big);
                switch (id) {
                    0x3 => self.max_concurrent = if (val == 0) 1 else val, // MAX_CONCURRENT_STREAMS
                    0x4 => { // INITIAL_WINDOW_SIZE: delta applies to all open streams
                        const new_win = @as(i64, val);
                        const delta = new_win - self.peer_initial_window;
                        self.peer_initial_window = new_win;
                        var it = self.streams.valueIterator();
                        while (it.next()) |sp| sp.*.send_window += delta;
                    },
                    else => {},
                }
            }
        }

        /// Write a control frame under the write mutex (best-effort; errors mark
        /// the connection failed on the next read).
        fn writeControl(self: *Self, typ: frame.Type, flags: u8, stream_id: u31, payload: []const u8) void {
            self.write_mutex.lock();
            defer self.write_mutex.unlock();
            frame.writeFrame(self.transport, typ, flags, stream_id, payload) catch {};
        }

        fn failConnection(self: *Self, e: anyerror) void {
            self.state_mutex.lock();
            if (self.conn_err == null) self.conn_err = e;
            var it = self.streams.valueIterator();
            while (it.next()) |sp| {
                if (sp.*.err == null) sp.*.err = e;
                sp.*.cond.signal(); // wake each response waiter
            }
            self.state_mutex.unlock();
            self.cond.broadcast(); // wake beginStream / window waiters
        }
    };
}

/// Concrete actor type for production (TLS upstream).
pub const TlsH2Conn = H2Conn(*tls_termination.UpstreamTlsConn);

pub const H2PoolStats = struct {
    connections_active: u64 = 0,
    streams_active: u64 = 0,
    /// Monotonic since process start (see `H2ConnPool` counters).
    stream_resets_total: u64 = 0,
    goaway_total: u64 = 0,
};

/// Result of acquiring a connection for an origin: either a multiplexing h2
/// actor (the caller holds one ref and must `release` it), or — when the origin
/// negotiated HTTP/1.1 over ALPN — the raw TLS connection for the caller to run
/// an HTTP/1.1 exchange on and then `close`/free.
pub const H2AcquireResult = union(enum) {
    h2: *TlsH2Conn,
    h1: *tls_termination.UpstreamTlsConn,
};

/// Per-origin pool of multiplexing h2 connections (#145, PR 2). One connection
/// per origin carries many concurrent streams; connection lifetime is
/// refcounted so an evicted (dead) connection survives until its last in-flight
/// request finishes. Keyed by the scheme-qualified origin (e.g. `h2:host:443`).
pub const H2ConnPool = struct {
    /// Idle / lifetime eviction policy for the maintenance-tick reaper (#145,
    /// PR 3). Mirrors `upstream_pool.Config`'s idle/lifetime knobs.
    pub const Config = struct {
        /// Evict a connection with no in-flight streams unused this long.
        idle_timeout_ms: u64 = 90_000,
        /// Hard cap on total connection age (0 = unlimited).
        max_lifetime_ms: u64 = 0,
    };

    allocator: std.mem.Allocator,
    mutex: compat.Mutex = .{},
    conns: std.StringHashMap(*TlsH2Conn),
    config: Config = .{},

    /// Pool-wide monotonic counters bumped by each connection's reader thread
    /// (via a pointer handed to `H2Conn.init`) so RST_STREAM / GOAWAY totals
    /// persist across connection teardown. Surfaced by `snapshot`.
    stream_resets_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    goaway_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn init(allocator: std.mem.Allocator, config: Config) H2ConnPool {
        return .{
            .allocator = allocator,
            .conns = std.StringHashMap(*TlsH2Conn).init(allocator),
            .config = config,
        };
    }

    pub fn deinit(self: *H2ConnPool) void {
        self.mutex.lock();
        var it = self.conns.iterator();
        while (it.next()) |e| {
            self.allocator.free(e.key_ptr.*);
            e.value_ptr.*.release(); // drop the map ref
        }
        self.conns.deinit();
        self.mutex.unlock();
    }

    /// Get a healthy h2 connection for `key`, creating one if needed. On the h2
    /// path the returned actor carries one ref for the caller (release with
    /// `release`). On ALPN h1 the raw TLS conn is returned for the caller to own.
    pub fn acquire(
        self: *H2ConnPool,
        key: []const u8,
        host: []const u8,
        port: u16,
        tls_options: tls_termination.UpstreamTlsOptions,
        deadline_ms: u32,
    ) !H2AcquireResult {
        // Fast path: an existing healthy connection.
        self.mutex.lock();
        if (self.conns.get(key)) |c| {
            if (c.healthy()) {
                c.retain();
                self.mutex.unlock();
                return .{ .h2 = c };
            }
        }
        self.mutex.unlock();

        // Slow path: connect + handshake (no lock held).
        const fd = try compat.connectBlockingTcp(host, port);
        // Disable Nagle: h2 multiplexing issues many small frame writes
        // (HEADERS / WINDOW_UPDATE) whose interaction with the peer's delayed
        // ACK otherwise stalls each exchange ~40 ms and trips response timeouts
        // under concurrency.
        compat.setTcpNoDelay(fd);
        const tls_ptr = self.allocator.create(tls_termination.UpstreamTlsConn) catch {
            _ = std.c.close(fd);
            return error.OutOfMemory;
        };
        var opts = tls_options;
        opts.offer_h2 = true;
        tls_ptr.* = tls_termination.UpstreamTlsConn.connect(fd, host, opts) catch |e| {
            self.allocator.destroy(tls_ptr);
            _ = std.c.close(fd);
            return e;
        };
        // tls_ptr now owns the fd (its close() closes the socket).

        if (tls_ptr.negotiatedProtocol() != .http2) {
            return .{ .h1 = tls_ptr }; // caller owns: close() + destroy()
        }

        const conn = TlsH2Conn.init(self.allocator, tls_ptr, fd, deadline_ms, self.allocator, &self.stream_resets_total, &self.goaway_total) catch |e| {
            tls_ptr.close();
            self.allocator.destroy(tls_ptr);
            return e;
        };
        // conn.refs == 1 (the caller's ref).

        // Publish into the map, resolving a creation race. A displaced stale
        // entry's map ref may be its last (release can join the reader thread
        // in deinit), so it is dropped via this defer — after the unlock on
        // every return path below — never under the pool mutex.
        var stale: ?*TlsH2Conn = null;
        defer if (stale) |s| s.release();
        self.mutex.lock();
        if (self.conns.get(key)) |c2| {
            if (c2.healthy()) {
                c2.retain();
                self.mutex.unlock();
                conn.release(); // tear down our redundant connection
                return .{ .h2 = c2 };
            }
            // Stale entry — evict it (released via the defer above).
            if (self.conns.fetchRemove(key)) |old| {
                self.allocator.free(old.key);
                stale = old.value;
            }
        }
        const owned_key = self.allocator.dupe(u8, key) catch {
            self.mutex.unlock();
            return .{ .h2 = conn }; // unpooled, but usable; caller still holds its ref
        };
        conn.retain(); // map ref (refs == 2)
        self.conns.put(owned_key, conn) catch {
            self.allocator.free(owned_key);
            conn.release(); // undo map ref
            self.mutex.unlock();
            return .{ .h2 = conn };
        };
        self.mutex.unlock();
        return .{ .h2 = conn };
    }

    /// Drop the caller's ref on an h2 connection.
    pub fn release(_: *H2ConnPool, conn: *TlsH2Conn) void {
        conn.release();
    }

    /// Remove a (presumably dead) connection from the map if it is still the
    /// mapped entry for `key`, dropping the map ref. In-flight requests keep it
    /// alive via their own refs until they finish.
    pub fn evict(self: *H2ConnPool, key: []const u8, conn: *TlsH2Conn) void {
        self.mutex.lock();
        var removed = false;
        if (self.conns.getEntry(key)) |e| {
            if (e.value_ptr.* == conn) {
                self.allocator.free(e.key_ptr.*);
                _ = self.conns.remove(key);
                removed = true;
            }
        }
        self.mutex.unlock();
        // Drop the map ref outside the lock (release can join the reader thread
        // in deinit; see reapIdle). Callers hold their own ref, so in practice
        // this is not the last one — but the invariant is kept unconditionally.
        if (removed) conn.release();
    }

    pub fn snapshot(self: *H2ConnPool) H2PoolStats {
        self.mutex.lock();
        defer self.mutex.unlock();
        var s = H2PoolStats{
            .connections_active = self.conns.count(),
            .stream_resets_total = self.stream_resets_total.load(.monotonic),
            .goaway_total = self.goaway_total.load(.monotonic),
        };
        var it = self.conns.valueIterator();
        while (it.next()) |cp| s.streams_active += cp.*.activeStreamCount();
        return s;
    }

    /// True if `conn` should be dropped from the pool: it must have **no
    /// in-flight streams** (refcount-safe eviction — an in-flight request keeps
    /// the conn alive via its own ref regardless, but idle policy must not race
    /// active work), and then either be unhealthy (dead / GOAWAY), idle past the
    /// idle timeout, or past the max lifetime. Called under the pool mutex.
    fn shouldEvict(self: *H2ConnPool, conn: *TlsH2Conn, now_ms: u64) bool {
        return evictionDecision(self.config, .{
            .active_streams = conn.activeStreamCount(),
            .healthy = conn.healthy(),
            .last_activity_ms = conn.last_activity_ms.load(.monotonic),
            .created_ms = conn.created_ms,
        }, now_ms);
    }

    /// Evict idle / aged-out / dead h2 connections. Mirrors
    /// `upstream_pool.reapIdle`; intended to run from the gateway maintenance
    /// tick. Removal happens under the pool mutex (so no `acquire` can retain a
    /// victim mid-reap), but the final `release` — which may join the reader
    /// thread in `deinit` — runs *after* unlocking so we never block the pool on
    /// a teardown. Refcount-safe: only the map ref is dropped; any late in-flight
    /// request that grabbed a ref before reap keeps the conn alive until it
    /// finishes.
    pub fn reapIdle(self: *H2ConnPool, now_ms: u64) void {
        self.mutex.lock();

        var victims: std.ArrayList(*TlsH2Conn) = .empty;
        defer victims.deinit(self.allocator);
        var victim_keys: std.ArrayList([]const u8) = .empty;
        defer victim_keys.deinit(self.allocator);

        // Reserve up front so eviction never allocates after a removal. On OOM
        // skip the whole round (the conns are reaped on a later tick) — we must
        // never fall back to releasing under the pool mutex.
        const cap = self.conns.count();
        victims.ensureTotalCapacity(self.allocator, cap) catch {
            self.mutex.unlock();
            return;
        };
        victim_keys.ensureTotalCapacity(self.allocator, cap) catch {
            self.mutex.unlock();
            return;
        };

        var it = self.conns.iterator();
        while (it.next()) |e| {
            if (self.shouldEvict(e.value_ptr.*, now_ms)) {
                victim_keys.appendAssumeCapacity(e.key_ptr.*);
            }
        }
        for (victim_keys.items) |k| {
            if (self.conns.fetchRemove(k)) |kv| {
                self.allocator.free(kv.key);
                victims.appendAssumeCapacity(kv.value);
            }
        }
        self.mutex.unlock();

        for (victims.items) |c| c.release(); // drop the map ref (may tear down)
    }
};

/// A connection's reap-relevant state, sampled under the pool mutex. Split out
/// so the eviction policy can be unit-tested without a live TLS connection.
const ConnReapState = struct {
    active_streams: u32,
    healthy: bool,
    last_activity_ms: u64,
    created_ms: u64,
};

/// Pure eviction policy shared by the reaper. A connection is evictable only
/// when it has no in-flight streams, and then if it is unhealthy (dead /
/// GOAWAY), idle past the idle timeout, or past the max lifetime. Saturating
/// subtraction (`-|`) keeps clock skew from wrapping.
fn evictionDecision(cfg: H2ConnPool.Config, s: ConnReapState, now_ms: u64) bool {
    if (s.active_streams != 0) return false;
    if (!s.healthy) return true;
    if (cfg.idle_timeout_ms > 0 and now_ms -| s.last_activity_ms >= cfg.idle_timeout_ms) return true;
    if (cfg.max_lifetime_ms > 0 and now_ms -| s.created_ms >= cfg.max_lifetime_ms) return true;
    return false;
}

/// Encode a u31 window increment into a 4-byte big-endian buffer (thread-local
/// scratch is unsafe here, so build per-call). Returned slice is a comptime
/// array copied by value into the frame writer.
fn windowIncrement(n: usize) [4]u8 {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, @as(u32, @intCast(@min(n, 0x7FFF_FFFF))) & 0x7FFF_FFFF, .big);
    return buf;
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
    pub fn close(self: *PlainTransport) void {
        _ = std.c.close(self.fd);
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

/// A multi-stream canned h2 server: for each request HEADERS it decodes `:path`
/// and replies on that stream with `:status 200` + a DATA body echoing the path,
/// so each client can verify it received *its own* response (correct demux).
fn cannedMuxServer(peer_fd: std.posix.fd_t, n_requests: usize) void {
    const a = std.heap.page_allocator;
    var srv = PlainTransport{ .fd = peer_fd };

    var preface: [PREFACE.len]u8 = undefined;
    readExact(&srv, peer_fd, preface[0..], 2000) catch return;
    frame.writeSettings(a, &srv, &[_][2]u32{}) catch return;

    var served: usize = 0;
    while (served < n_requests) {
        var fr = readFrameBounded(&srv, peer_fd, a, 2000) catch return;
        defer frame.deinitFrame(a, &fr);
        if (fr.typ != .headers) continue;

        var decoded = hpack.decode(a, headerBlockFragment(fr)) catch continue;
        defer hpack.deinitDecoded(a, &decoded);
        var path: []const u8 = "/";
        for (decoded.headers) |h| {
            if (std.mem.eql(u8, h.name, ":path")) path = h.value;
        }
        const block = hpack.encodeLiteralHeaderBlock(a, &[_]hpack.HeaderField{
            .{ .name = ":status", .value = "200" },
        }) catch return;
        defer a.free(block);
        frame.writeFrame(&srv, .headers, frame.Flags.END_HEADERS, fr.stream_id, block) catch return;
        frame.writeFrame(&srv, .data, frame.Flags.END_STREAM, fr.stream_id, path) catch return;
        served += 1;
    }
}

const MuxClientCtx = struct {
    conn: *H2Conn(*PlainTransport),
    idx: usize,
    ok: bool = false,
};

fn muxClientThread(ctx: *MuxClientCtx) void {
    var path_buf: [32]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/req{d}", .{ctx.idx}) catch return;
    var resp = ctx.conn.request(.{
        .method = "GET",
        .authority = "mux.test",
        .path = path,
    }) catch return;
    defer resp.deinit();
    ctx.ok = resp.status == 200 and std.mem.eql(u8, resp.body, path);
}

test "h2 actor multiplexes concurrent requests over one connection" {
    const N = 8;
    const fds = try makeSocketpair();
    const server = try std.Thread.spawn(.{}, cannedMuxServer, .{ fds[1], @as(usize, N) });

    var transport = PlainTransport{ .fd = fds[0] };
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 2000, null, null, null);

    var ctxs: [N]MuxClientCtx = undefined;
    var threads: [N]std.Thread = undefined;
    for (0..N) |i| {
        ctxs[i] = .{ .conn = conn, .idx = i };
        threads[i] = try std.Thread.spawn(.{}, muxClientThread, .{&ctxs[i]});
    }
    for (0..N) |i| threads[i].join();

    var all_ok = true;
    for (0..N) |i| {
        if (!ctxs[i].ok) all_ok = false;
    }
    conn.deinit(); // shuts the fd down, joins the reader
    server.join();
    _ = std.c.close(fds[1]);

    try testing.expect(all_ok);
}

test "evictionDecision honours active-stream, health, idle, and lifetime gates" {
    const cfg = H2ConnPool.Config{ .idle_timeout_ms = 1000, .max_lifetime_ms = 5000 };

    // In-flight streams pin the connection regardless of age/health.
    try testing.expect(!evictionDecision(cfg, .{
        .active_streams = 1,
        .healthy = false,
        .last_activity_ms = 0,
        .created_ms = 0,
    }, 1_000_000));

    // Idle but fresh, healthy → keep.
    try testing.expect(!evictionDecision(cfg, .{
        .active_streams = 0,
        .healthy = true,
        .last_activity_ms = 900,
        .created_ms = 900,
    }, 1500));

    // Idle past the idle timeout → evict.
    try testing.expect(evictionDecision(cfg, .{
        .active_streams = 0,
        .healthy = true,
        .last_activity_ms = 100,
        .created_ms = 100,
    }, 1200));

    // Recently active but past max lifetime → evict.
    try testing.expect(evictionDecision(cfg, .{
        .active_streams = 0,
        .healthy = true,
        .last_activity_ms = 5900,
        .created_ms = 0,
    }, 6000));

    // Unhealthy (dead / GOAWAY) with no streams → evict even if fresh.
    try testing.expect(evictionDecision(cfg, .{
        .active_streams = 0,
        .healthy = false,
        .last_activity_ms = 1_000_000,
        .created_ms = 1_000_000,
    }, 1_000_000));

    // Both caps disabled → an idle, healthy conn is never evicted on age.
    const off = H2ConnPool.Config{ .idle_timeout_ms = 0, .max_lifetime_ms = 0 };
    try testing.expect(!evictionDecision(off, .{
        .active_streams = 0,
        .healthy = true,
        .last_activity_ms = 0,
        .created_ms = 0,
    }, 1_000_000_000));
}

/// Canned server: SETTINGS, wait for the request HEADERS, then RST an unknown
/// stream (late/stray reset) followed by the request's stream. Both frames must
/// count — the metric is per RST_STREAM frame received, not per known stream.
fn cannedRstServer(peer_fd: std.posix.fd_t) void {
    const a = std.heap.page_allocator;
    var srv = PlainTransport{ .fd = peer_fd };
    var preface: [PREFACE.len]u8 = undefined;
    readExact(&srv, peer_fd, preface[0..], 2000) catch return;
    frame.writeSettings(a, &srv, &[_][2]u32{}) catch return;
    while (true) {
        var fr = readFrameBounded(&srv, peer_fd, a, 2000) catch return;
        const sid = fr.stream_id;
        const is_headers = fr.typ == .headers;
        frame.deinitFrame(a, &fr);
        if (is_headers) {
            const code = [_]u8{ 0, 0, 0, 8 }; // CANCEL
            frame.writeFrame(&srv, .rst_stream, 0, 99, code[0..]) catch return; // unknown stream
            frame.writeFrame(&srv, .rst_stream, 0, sid, code[0..]) catch return;
            return;
        }
    }
}

test "reader bumps the pool RST_STREAM counter per frame received" {
    const fds = try makeSocketpair();
    const server = try std.Thread.spawn(.{}, cannedRstServer, .{fds[1]});

    var rst = std.atomic.Value(u64).init(0);
    var goaway = std.atomic.Value(u64).init(0);
    var transport = PlainTransport{ .fd = fds[0] };
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 2000, null, &rst, &goaway);

    const res = conn.request(.{ .method = "GET", .authority = "rst.test", .path = "/" });
    try testing.expectError(error.Http2StreamReset, res);

    conn.deinit(); // joins the reader — the counter bumps have happened by now
    server.join();
    _ = std.c.close(fds[1]);

    // The single reader processes frames in order, so once the request observed
    // its reset both RST frames (unknown stream 99 + the real one) are counted.
    try testing.expectEqual(@as(u64, 2), rst.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), goaway.load(.monotonic));
}

/// Canned server: SETTINGS, then an immediate connection-level GOAWAY.
fn cannedGoawayServer(peer_fd: std.posix.fd_t) void {
    const a = std.heap.page_allocator;
    var srv = PlainTransport{ .fd = peer_fd };
    var preface: [PREFACE.len]u8 = undefined;
    readExact(&srv, peer_fd, preface[0..], 2000) catch return;
    frame.writeSettings(a, &srv, &[_][2]u32{}) catch return;
    const payload = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }; // last_stream_id=0, error=NO_ERROR
    frame.writeFrame(&srv, .goaway, 0, 0, payload[0..]) catch return;
    // Hold the socket so the reader observes the GOAWAY, not a peer close.
    var scratch: [1]u8 = undefined;
    _ = srv.read(scratch[0..]) catch {};
}

test "reader bumps the pool GOAWAY counter on a connection GOAWAY" {
    const fds = try makeSocketpair();
    const server = try std.Thread.spawn(.{}, cannedGoawayServer, .{fds[1]});

    var rst = std.atomic.Value(u64).init(0);
    var goaway = std.atomic.Value(u64).init(0);
    var transport = PlainTransport{ .fd = fds[0] };
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 2000, null, &rst, &goaway);

    // Wait (bounded spin, no sleep-dependent assertion) until the reader has
    // processed the GOAWAY — otherwise deinit's shutdown could win the race and
    // the frame would legitimately never be counted.
    var spins: usize = 0;
    while (conn.healthy() and spins < 1_000_000) : (spins += 1) std.Thread.yield() catch {};
    const saw_goaway = !conn.healthy();

    conn.deinit(); // joins the reader — all counter bumps have happened by now
    server.join();
    _ = std.c.close(fds[1]);

    try testing.expect(saw_goaway);
    try testing.expectEqual(@as(u64, 1), goaway.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), rst.load(.monotonic));
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
