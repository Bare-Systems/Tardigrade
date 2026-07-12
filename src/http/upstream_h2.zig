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
const tls_termination = @import("tls_backend.zig");

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
/// Receive window we advertise per stream (SETTINGS_INITIAL_WINDOW_SIZE). For
/// streaming streams this doubles as the bounded per-stream buffer: the reader
/// stops replenishing it, so a well-behaved peer can have at most this many
/// unconsumed bytes buffered per stream.
const OUR_INITIAL_WINDOW: u31 = 1 << 20;
/// HTTP/2 default initial flow-control window for a peer that sent no SETTINGS.
const PROTOCOL_DEFAULT_WINDOW: i64 = 65_535;
/// Grow the connection-level receive window to this at connection start so the
/// default 64 KiB aggregate window does not throttle multiplexed transfers.
/// The reader replenishes the connection window promptly per DATA frame
/// regardless of consumers, so a slow downstream client never starves other
/// streams on the shared connection; per-stream memory stays bounded by the
/// (unreplenished) stream windows.
const CONN_RECV_WINDOW: i64 = 8 << 20;
/// How often the reader sweeps for workers blocked past their wait deadline
/// while frames keep flowing for other streams (see `Stream.wait_deadline_ms`).
const WAIT_SWEEP_INTERVAL_MS: u64 = 1_000;
const STREAM_ID: u31 = 1;

pub const H2Error = error{
    Http2Timeout,
    Http2GoAway,
    Http2StreamReset,
    Http2ConnectionClosed,
    Http2FrameTooLarge,
    Http2MissingStatus,
    Http2FlowControlError,
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
    /// Whether `body` is the complete outbound request body or the first bytes
    /// of a request body that will continue through streaming DATA writes.
    body_mode: BodyMode = .complete,
};

pub const BodyMode = enum {
    complete,
    streaming,
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
/// until `request()` (buffered) or `finishStreaming()` (streaming) reclaims it.
/// Public so the streaming proxy path can read `status`/`headers` off the
/// handle returned by `requestStreaming`; all other fields are actor-internal.
pub const Stream = struct {
    id: u31,
    send_window: i64,
    /// Per-stream completion signal — the reader signals only the waiter for
    /// this stream, avoiding a thundering herd across all in-flight requests.
    cond: compat.Condition = .{},
    status: ?u16 = null,
    headers: std.ArrayList(hpack.HeaderField) = .empty,
    body: std.ArrayList(u8) = .empty,
    done: bool = false,
    err: ?anyerror = null,
    /// Streaming mode (#145 PR 4): the reader parks DATA in `body` as a bounded
    /// buffer and does NOT replenish the stream-level flow-control window; the
    /// consumer replenishes as it drains via `readStreamingBody`. Buffered
    /// streams keep the replenish-immediately behaviour.
    streaming: bool = false,
    /// Response headers fully decoded (streaming: the head can be relayed; any
    /// later HEADERS block is a trailer section, which the proxy drops).
    headers_done: bool = false,
    /// Consumer read offset into `body` (streaming only).
    body_read_off: usize = 0,
    /// Our advertised-but-unreplenished receive window (streaming only). The
    /// peer overrunning it is a flow-control violation and errors the stream.
    recv_window: i64 = 0,
    /// When non-zero, a worker is blocked waiting on this stream and the reader
    /// must fail the stream with `Http2Timeout` once `nowMs()` passes it (the
    /// reader extends it on progress). Bounds every wait even when the shared
    /// connection stays busy with other streams (#196 guarantee).
    wait_deadline_ms: u64 = 0,
    /// True once the stream's HEADERS frame reached the wire. Guards
    /// `finishStreaming`'s RST_STREAM: resetting a stream the peer never saw
    /// (idle state) would be a connection-level PROTOCOL_ERROR. Written and
    /// read only by the owning worker thread.
    wire_opened: bool = false,

    fn destroy(self: *Stream, allocator: std.mem.Allocator) void {
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

        /// In-flight header-block accumulator (reader-thread only). Blocks
        /// never interleave across streams, so one buffer serves the whole
        /// connection; `accum_stream_id`/`accum_end_stream` identify the block.
        header_accum: std.ArrayList(u8) = .empty,
        accum_stream_id: u31 = 0,
        accum_end_stream: bool = false,

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
            // Grow the connection-level receive window once up front; the
            // reader keeps it topped up per DATA frame afterwards.
            const conn_win_inc = windowIncrement(@intCast(CONN_RECV_WINDOW - PROTOCOL_DEFAULT_WINDOW));
            try frame.writeFrame(self.transport, .window_update, 0, 0, &conn_win_inc);

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
            self.header_accum.deinit(self.allocator);
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
            const stream = try self.beginStream(false);
            var detached = false;
            errdefer if (!detached) self.dropStream(stream);

            try self.sendRequest(stream, req);

            // Wait for the reader to complete or error the stream, then detach
            // it from the map *under the lock* so the reader can no longer touch
            // its header/body buffers before we move them out. The wait deadline
            // bounds a stalled stream even while the shared connection stays
            // busy with other streams (the reader extends it on progress).
            self.state_mutex.lock();
            stream.wait_deadline_ms = nowMs() + self.deadline_ms;
            while (!stream.done and stream.err == null and self.conn_err == null) {
                stream.cond.wait(&self.state_mutex);
            }
            stream.wait_deadline_ms = 0;
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

        /// Begin a streaming request (#145 PR 4): send HEADERS(+body) and block
        /// until the response headers are decoded, then return the stream
        /// handle. The caller reads `stream.status.?`/`stream.headers.items`
        /// (stable once this returns — trailers are discarded), drains the body
        /// with `readStreamingBody`, and MUST call `finishStreaming` exactly
        /// once when done (on every path, including errors after this returns).
        ///
        /// Unlike `request()`, DATA is not buffered without bound: the reader
        /// parks frames in a per-stream buffer capped by the stream receive
        /// window, which is only replenished as the caller drains — a slow
        /// downstream client backpressures its own stream while the connection
        /// window keeps other streams on the shared connection flowing.
        pub fn requestStreaming(self: *Self, req: Request) !*Stream {
            const stream = try self.openStreaming(req);
            errdefer self.finishStreaming(stream);
            try self.waitStreamingResponseHead(stream);
            return stream;
        }

        /// Start a streaming request and return immediately after the request
        /// HEADERS and any initial `req.body` DATA have reached the wire. This
        /// is the entry point for streaming uploads: the caller can then send
        /// request-body DATA incrementally before waiting for response headers.
        pub fn openStreaming(self: *Self, req: Request) !*Stream {
            const stream = try self.beginStream(true);
            errdefer self.finishStreaming(stream);
            try self.sendRequest(stream, req);
            return stream;
        }

        /// Wait until response headers for an opened streaming request have
        /// been decoded. Once this returns, `stream.status.?` and
        /// `stream.headers.items` are stable for response-head relay.
        pub fn waitStreamingResponseHead(self: *Self, stream: *Stream) !void {
            self.state_mutex.lock();
            stream.wait_deadline_ms = nowMs() + self.deadline_ms;
            while (!stream.headers_done and !stream.done and stream.err == null and self.conn_err == null) {
                stream.cond.wait(&self.state_mutex);
            }
            stream.wait_deadline_ms = 0;
            const stream_err: ?anyerror = if (stream.err != null) stream.err else self.conn_err;
            const status = stream.status;
            self.state_mutex.unlock();

            if (stream_err) |e| return e;
            if (status == null) return error.Http2MissingStatus;
        }

        /// Send one chunk of a streaming request body. `end_stream` marks the
        /// final body chunk; when the final chunk is empty an empty DATA frame
        /// carrying END_STREAM is sent. The method waits for connection and
        /// stream send window with no write mutex held, preserving the actor's
        /// lock-order invariant while backpressuring slow/flow-controlled
        /// uploads.
        pub fn writeStreamingRequestBody(self: *Self, stream: *Stream, chunk: []const u8, end_stream: bool) !void {
            if (chunk.len > 0) {
                try self.sendBody(stream, chunk, end_stream);
                return;
            }
            if (!end_stream) return;
            try self.ensureStreamWritable(stream);
            var write_result: anyerror!void = {};
            self.write_mutex.lock();
            write_result = frame.writeFrame(self.transport, .data, frame.Flags.END_STREAM, stream.id, &[_]u8{});
            self.write_mutex.unlock();
            if (write_result) |_| {} else |err| return self.markWriteFailure(err);
        }

        /// Copy the next chunk of a streaming response body into `out`,
        /// blocking (deadline-bounded) until data, end-of-stream, or an error.
        /// Returns 0 at end of stream. Consuming bytes replenishes the
        /// stream-level flow-control window so the origin may send more.
        pub fn readStreamingBody(self: *Self, stream: *Stream, out: []u8) !usize {
            self.state_mutex.lock();
            while (true) {
                const avail = stream.body.items.len - stream.body_read_off;
                if (avail > 0) {
                    const n = @min(avail, out.len);
                    @memcpy(out[0..n], stream.body.items[stream.body_read_off..][0..n]);
                    stream.body_read_off += n;
                    if (stream.body_read_off == stream.body.items.len) {
                        stream.body.clearRetainingCapacity();
                        stream.body_read_off = 0;
                    }
                    stream.recv_window += @as(i64, @intCast(n));
                    // No more data will arrive once END_STREAM was seen, so the
                    // window only needs replenishing while the stream is open.
                    const replenish = !stream.done;
                    self.state_mutex.unlock();
                    if (replenish) {
                        const inc = windowIncrement(n);
                        self.writeControl(.window_update, 0, stream.id, &inc);
                    }
                    return n;
                }
                if (stream.err) |e| {
                    self.state_mutex.unlock();
                    return e;
                }
                if (self.conn_err) |e| {
                    self.state_mutex.unlock();
                    return e;
                }
                if (stream.done) {
                    self.state_mutex.unlock();
                    return 0;
                }
                stream.wait_deadline_ms = nowMs() + self.deadline_ms;
                stream.cond.wait(&self.state_mutex);
                stream.wait_deadline_ms = 0;
            }
        }

        /// Finish a streaming request: detach the stream from the connection,
        /// reset it upstream if the response had not completed (so the origin
        /// stops sending on an abandoned stream), free the concurrency slot,
        /// and destroy the handle. Must be called exactly once per successful
        /// `requestStreaming`.
        pub fn finishStreaming(self: *Self, stream: *Stream) void {
            self.state_mutex.lock();
            const removed = self.streams.remove(stream.id);
            if (removed and self.active_streams > 0) self.active_streams -= 1;
            const need_rst = stream.wire_opened and stream.err == null and !stream.done and self.conn_err == null;
            const id = stream.id;
            self.state_mutex.unlock();
            self.last_activity_ms.store(nowMs(), .monotonic);
            self.cond.broadcast(); // free a concurrency slot
            if (need_rst) {
                const cancel_code = [4]u8{ 0, 0, 0, 8 }; // CANCEL
                self.writeControl(.rst_stream, 0, id, &cancel_code);
            }
            stream.destroy(self.allocator);
        }

        fn beginStream(self: *Self, streaming: bool) !*Stream {
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
            stream.* = .{
                .id = id,
                .send_window = self.peer_initial_window,
                .streaming = streaming,
                .recv_window = if (streaming) @as(i64, OUR_INITIAL_WINDOW) else 0,
            };
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

            const request_body_complete = req.body_mode == .complete;
            const end_stream = request_body_complete and req.body.len == 0;
            // HEADERS (+CONTINUATION) must be contiguous on the wire, so the
            // whole block goes out under one write_mutex hold. DATA frames may
            // interleave with other streams, so the body sender takes the lock
            // per frame — and, crucially, never holds it while waiting on
            // state_mutex for flow-control window (the reader needs write_mutex
            // for PING/SETTINGS acks; holding both would deadlock it).
            self.write_mutex.lock();
            const write_result = self.writeHeaderBlockLocked(stream.id, block, end_stream);
            self.write_mutex.unlock();
            if (write_result) |_| {} else |err| return self.markWriteFailure(err);
            stream.wire_opened = true;
            if (req.body.len > 0) try self.sendBody(stream, req.body, request_body_complete);
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

        /// Send the request body as flow-controlled DATA frames. Waits for send
        /// window with no lock held, then takes the write mutex per frame so
        /// concurrent streams' DATA may interleave and the reader is never
        /// blocked on write_mutex behind a window wait.
        fn sendBody(self: *Self, stream: *Stream, full_body: []const u8, end_stream: bool) !void {
            var off: usize = 0;
            while (off < full_body.len) {
                const budget = try self.reserveSendWindow(stream, full_body.len - off);
                const is_last = end_stream and (off + budget) == full_body.len;
                const flags: u8 = if (is_last) frame.Flags.END_STREAM else 0;
                self.write_mutex.lock();
                const write_result = frame.writeFrame(self.transport, .data, flags, stream.id, full_body[off .. off + budget]);
                self.write_mutex.unlock();
                if (write_result) |_| {} else |err| return self.markWriteFailure(err);
                off += budget;
            }
        }

        fn ensureStreamWritable(self: *Self, stream: *Stream) !void {
            self.state_mutex.lock();
            defer self.state_mutex.unlock();
            if (self.conn_err) |e| return e;
            if (stream.err) |e| return e;
        }

        fn markWriteFailure(self: *Self, err: anyerror) anyerror {
            self.failConnection(err);
            return err;
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
                    stream.wait_deadline_ms = 0;
                    const grant = @min(@as(i64, @intCast(@min(want, DEFAULT_MAX_FRAME))), avail);
                    self.conn_send_window -= grant;
                    stream.send_window -= grant;
                    return @intCast(grant);
                }
                // Bound the window wait: the reader's sweep fails this stream
                // (and broadcasts) if the peer withholds window past the
                // deadline while other frames keep the connection busy.
                if (stream.wait_deadline_ms == 0) stream.wait_deadline_ms = nowMs() + self.deadline_ms;
                self.cond.wait(&self.state_mutex);
            }
        }

        // ---- reader thread ----

        fn readerLoop(self: *Self) void {
            var next_sweep_ms: u64 = nowMs() + WAIT_SWEEP_INTERVAL_MS;
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

                // Periodically fail streams whose waiter has been blocked past
                // its deadline. This bounds every worker wait even when frames
                // keep flowing for *other* streams on the shared connection (a
                // totally silent connection is already bounded by the frame
                // read deadline above).
                const now = nowMs();
                if (now >= next_sweep_ms) {
                    next_sweep_ms = now + WAIT_SWEEP_INTERVAL_MS;
                    self.sweepStalledWaiters(now);
                }
            }
        }

        /// Fail (with `Http2Timeout`) every stream whose waiter registered a
        /// deadline that has passed without progress. Skips streams that have
        /// already completed or errored — their waiter is about to wake anyway.
        fn sweepStalledWaiters(self: *Self, now_ms: u64) void {
            var timed_out = false;
            self.state_mutex.lock();
            var it = self.streams.valueIterator();
            while (it.next()) |sp| {
                const s = sp.*;
                if (s.wait_deadline_ms == 0 or now_ms < s.wait_deadline_ms) continue;
                if (s.done or s.err != null) continue;
                s.err = error.Http2Timeout;
                s.cond.signal();
                timed_out = true;
            }
            self.state_mutex.unlock();
            // Send-window waiters block on the connection cond, not the stream
            // cond — wake them so they observe the stream error.
            if (timed_out) self.cond.broadcast();
        }

        fn handleFrame(self: *Self, fr: *frame.Frame) !void {
            switch (fr.typ) {
                .settings => {
                    if ((fr.flags & frame.Flags.ACK) == 0) {
                        self.applySettings(fr.payload);
                        self.writeControl(.settings, frame.Flags.ACK, 0, &[_]u8{});
                        // INITIAL_WINDOW_SIZE may have grown stream send
                        // windows — wake any send-window waiters.
                        self.cond.broadcast();
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
                    if (self.streams.get(fr.stream_id)) |s| {
                        s.err = error.Http2StreamReset;
                        // Signal under the lock: once we unlock, the waiter may
                        // detach and destroy the stream, so a signal after the
                        // unlock could touch freed memory.
                        s.cond.signal();
                    }
                    self.state_mutex.unlock();
                    self.cond.broadcast(); // wake send-window waiters on this stream
                },
                .headers, .continuation => try self.handleHeaders(fr),
                .data => try self.handleData(fr),
                else => {},
            }
        }

        fn handleHeaders(self: *Self, fr: *frame.Frame) !void {
            const block = headerBlockFragment(fr.*);
            const end_headers = (fr.flags & frame.Flags.END_HEADERS) != 0;

            // Header blocks never interleave on a connection (HEADERS and its
            // CONTINUATIONs are contiguous, RFC 7540 §4.3), so one reader-owned
            // accumulator serves all streams — no state lock needed for it.
            // END_STREAM is only meaningful on the HEADERS frame, so capture it
            // there (a CONTINUATION-terminated block must not lose it).
            if (fr.typ == .headers) {
                self.header_accum.clearRetainingCapacity();
                self.accum_stream_id = fr.stream_id;
                self.accum_end_stream = (fr.flags & frame.Flags.END_STREAM) != 0;
            } else if (fr.stream_id != self.accum_stream_id) {
                return; // stray CONTINUATION for a block we are not assembling
            }
            try self.header_accum.appendSlice(self.allocator, block);
            if (!end_headers) return; // wait for CONTINUATION

            // Decode with the connection-wide decoder even when the stream is
            // gone (completed/abandoned): skipping a block would desynchronize
            // the HPACK dynamic table for every later response on this
            // connection. This thread is the only decoder user.
            var decoded = try self.decoder.decode(self.allocator, self.header_accum.items);
            defer hpack.deinitDecoded(self.allocator, &decoded);
            self.header_accum.clearRetainingCapacity();
            const stream_end = self.accum_end_stream;

            self.state_mutex.lock();
            defer self.state_mutex.unlock();
            const s = self.streams.get(self.accum_stream_id) orelse return;
            if (!s.headers_done) {
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
                if (s.status != null) s.headers_done = true;
            }
            // else: a trailer section — dropped (the proxy does not forward
            // trailers), but decoded above for HPACK table consistency.
            if (stream_end) s.done = true;
            if (s.wait_deadline_ms != 0) s.wait_deadline_ms = nowMs() + self.deadline_ms;
            // Signal under the lock: after unlock the waiter may detach and
            // destroy the stream.
            s.cond.signal();
        }

        fn handleData(self: *Self, fr: *frame.Frame) !void {
            const end_stream = (fr.flags & frame.Flags.END_STREAM) != 0;
            self.state_mutex.lock();
            const maybe_stream = self.streams.get(fr.stream_id);
            var replenish_stream = true;
            var flow_violation = false;
            if (maybe_stream) |s| {
                var deliver = fr.payload.len > 0;
                if (deliver and s.streaming) {
                    // Bounded-buffer backpressure: account the bytes against
                    // the advertised stream window; the consumer replenishes
                    // it as it drains (`readStreamingBody`). A peer that
                    // overruns the window is violating flow control — fail
                    // the stream rather than buffer without bound.
                    replenish_stream = false;
                    s.recv_window -= @as(i64, @intCast(fr.payload.len));
                    if (s.recv_window < 0) {
                        if (s.err == null) s.err = error.Http2FlowControlError;
                        flow_violation = true;
                        deliver = false;
                    }
                }
                if (deliver) {
                    s.body.appendSlice(self.allocator, fr.payload) catch {
                        self.state_mutex.unlock();
                        return error.OutOfMemory;
                    };
                }
                if (end_stream) s.done = true;
                if (s.wait_deadline_ms != 0) s.wait_deadline_ms = nowMs() + self.deadline_ms;
                // Signal under the lock: after unlock the waiter may detach and
                // destroy the stream.
                s.cond.signal();
            }
            self.state_mutex.unlock();
            // Send-window waiters block on the connection cond.
            if (flow_violation) self.cond.broadcast();

            if (fr.payload.len > 0) {
                // Always replenish the connection window promptly — one slow
                // consumer must never stall other streams on the shared
                // connection. The stream window is replenished here only for
                // buffered streams (and unknown/completed streams, harmless);
                // streaming streams replenish on consumer drain.
                const inc = windowIncrement(fr.payload.len);
                self.writeControl(.window_update, 0, 0, &inc);
                if (replenish_stream) self.writeControl(.window_update, 0, fr.stream_id, &inc);
            }
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

/// Production transport for pooled h2 connections: TLS (ALPN-negotiated h2)
/// or a plain cleartext socket (prior-knowledge h2c, #237). Heap-allocated by
/// the pool and owned by the `H2Conn` (its `transport_allocator` destroys the
/// union after `close`). One runtime union — rather than two `H2Conn`
/// instantiations — keeps a single pool, lifecycle, and metrics path for both.
pub const UpstreamH2Transport = union(enum) {
    tls: struct {
        conn: *tls_termination.UpstreamTlsConn,
        /// Frees the `UpstreamTlsConn` allocation in `close` (the pool
        /// allocated it before ALPN was known).
        allocator: std.mem.Allocator,
    },
    plain: std.posix.fd_t,

    pub fn read(self: *UpstreamH2Transport, buf: []u8) !usize {
        switch (self.*) {
            .tls => |t| return t.conn.read(buf),
            // std.posix.read/write (not std.c) so EINTR is retried internally,
            // mirroring compat.NetStream: on macOS, thread machinery delivers
            // signals that interrupt blocking socket syscalls (the same class
            // of failure the kevent EINTR fix addressed), and a surfaced EINTR
            // here would falsely kill the shared connection.
            .plain => |fd| return std.posix.read(fd, buf) catch error.ReadFailed,
        }
    }

    pub fn writeAll(self: *UpstreamH2Transport, data: []const u8) !void {
        switch (self.*) {
            .tls => |t| return t.conn.writeAll(data),
            .plain => |fd| {
                var off: usize = 0;
                while (off < data.len) {
                    // std.posix has no write in this std; retry EINTR manually.
                    const n = std.c.write(fd, data.ptr + off, data.len - off);
                    if (n < 0) {
                        if (std.posix.errno(n) == .INTR) continue;
                        return error.WriteFailed;
                    }
                    if (n == 0) return error.WriteFailed;
                    off += @intCast(n);
                }
            },
        }
    }

    /// Decrypted bytes already buffered inside the transport that `poll(2)`
    /// cannot see. Only TLS buffers; a plain socket has nothing hidden.
    pub fn pending(self: *const UpstreamH2Transport) usize {
        return switch (self.*) {
            .tls => |t| t.conn.pending(),
            .plain => 0,
        };
    }

    pub fn close(self: *UpstreamH2Transport) void {
        switch (self.*) {
            .tls => |t| {
                t.conn.close();
                t.allocator.destroy(t.conn);
            },
            .plain => |fd| _ = std.c.close(fd),
        }
    }
};

/// Concrete actor type for production (TLS h2 and cleartext h2c upstreams).
pub const PooledH2Conn = H2Conn(*UpstreamH2Transport);

pub const H2PoolStats = struct {
    connections_active: u64 = 0,
    streams_active: u64 = 0,
    /// Monotonic since process start: sums of the per-origin counters (origin
    /// entries are never removed while the pool lives, so the sums are
    /// monotonic too — the exported global series stay backward-compatible).
    stream_resets_total: u64 = 0,
    goaway_total: u64 = 0,
};

/// Per-origin monotonic counters bumped by that origin's reader thread (#238).
/// Heap-allocated for a stable address — readers hold pointers across
/// connection teardown and map growth — and kept until pool `deinit`, so the
/// totals survive eviction exactly like the former pool-level counters.
/// Cardinality is bounded by the number of distinct configured origins, same
/// as the h1 pool's per-host stats.
pub const H2OriginCounters = struct {
    stream_resets_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    goaway_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
};

/// A copy of one origin's identity + h2 metrics for rendering. `origin` is the
/// pool key (`h2:host:port`), owned by the caller and freed via
/// `freeH2OriginSnapshots`.
pub const H2OriginSnapshot = struct {
    origin: []u8,
    connections_active: u64,
    streams_active: u64,
    stream_resets_total: u64,
    goaway_total: u64,
};

pub fn freeH2OriginSnapshots(allocator: std.mem.Allocator, snaps: []H2OriginSnapshot) void {
    for (snaps) |snap| allocator.free(snap.origin);
    allocator.free(snaps);
}

/// Result of acquiring a connection for an origin: either a multiplexing h2
/// actor (the caller holds one ref and must `release` it), or — when the origin
/// negotiated HTTP/1.1 over ALPN — the raw TLS connection for the caller to run
/// an HTTP/1.1 exchange on and then `close`/free.
pub const H2AcquireResult = union(enum) {
    h2: *PooledH2Conn,
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
    conns: std.StringHashMap(*PooledH2Conn),
    config: Config = .{},

    /// Per-origin monotonic RST_STREAM/GOAWAY counters (#238), keyed like
    /// `conns` (`h2:host:port`). Each origin's reader thread bumps its own
    /// entry (via pointers handed to `H2Conn.init`), still *before* publishing
    /// the state change the frame causes. Entries are created on first h2
    /// connection to an origin and live until pool `deinit` — never removed —
    /// so both the labelled series and the summed globals stay monotonic
    /// across connection teardown.
    origin_counters: std.StringHashMap(*H2OriginCounters),

    pub fn init(allocator: std.mem.Allocator, config: Config) H2ConnPool {
        return .{
            .allocator = allocator,
            .conns = std.StringHashMap(*PooledH2Conn).init(allocator),
            .origin_counters = std.StringHashMap(*H2OriginCounters).init(allocator),
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
        // Freed only after every connection's reader has been joined above —
        // readers hold pointers into these counter structs.
        var cit = self.origin_counters.iterator();
        while (cit.next()) |e| {
            self.allocator.free(e.key_ptr.*);
            self.allocator.destroy(e.value_ptr.*);
        }
        self.origin_counters.deinit();
        self.mutex.unlock();
    }

    /// Get (or create) the persistent counter struct for `key`. The returned
    /// pointer is stable for the pool's lifetime.
    fn originCounters(self: *H2ConnPool, key: []const u8) !*H2OriginCounters {
        self.mutex.lock();
        defer self.mutex.unlock();
        const gop = try self.origin_counters.getOrPut(key);
        if (!gop.found_existing) {
            errdefer _ = self.origin_counters.remove(key);
            const counters = try self.allocator.create(H2OriginCounters);
            errdefer self.allocator.destroy(counters);
            counters.* = .{};
            gop.key_ptr.* = try self.allocator.dupe(u8, key);
            gop.value_ptr.* = counters;
        }
        return gop.value_ptr.*;
    }

    /// Get a healthy h2 connection for `key`, creating one if needed. On the h2
    /// path the returned actor carries one ref for the caller (release with
    /// `release`). On ALPN h1 the raw TLS conn is returned for the caller to own.
    ///
    /// Two distinct deadlines (#171): `connect_timeout_ms` bounds **only** the
    /// TCP connect (`TARDIGRADE_UPSTREAM_CONNECT_TIMEOUT_MS`), while `deadline_ms`
    /// (the response/read timeout) bounds the TLS handshake and every subsequent
    /// h2 read/write/stream. Passing the read deadline to the connect (as an
    /// earlier revision did) meant pooled h2/h2c connects were bounded by the
    /// response timeout instead of the connect timeout.
    ///
    /// `tls_options == null` selects **prior-knowledge cleartext h2c** (#237):
    /// the connection speaks HTTP/2 immediately on the plain socket, no ALPN
    /// and no HTTP/1.1 Upgrade — so it never returns `.h1` and must only be
    /// used for origins explicitly configured to speak h2c.
    pub fn acquire(
        self: *H2ConnPool,
        key: []const u8,
        host: []const u8,
        port: u16,
        tls_options: ?tls_termination.UpstreamTlsOptions,
        connect_timeout_ms: u32,
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

        // Slow path: connect (+ TLS handshake when configured), no lock held.
        // The TCP connect is poll-bounded by the connect timeout (#171) — a
        // blocking connect() is not interruptible by SO_SNDTIMEO, so a
        // SYN-blackholed origin would otherwise stall the worker for the
        // kernel's own limit.
        const fd = try compat.connectBoundedTcp(host, port, connect_timeout_ms);
        // Bound the TLS handshake (and any later OpenSSL-internal writes) with
        // the response deadline before handing the fd to the transport (#171):
        // the reader's poll deadline only starts once the connection exists, so
        // without these a TCP-accepting-but-silent origin hangs the worker in
        // SSL_connect indefinitely.
        compat.setSocketTimeoutsMs(fd, deadline_ms, deadline_ms);
        // Disable Nagle: h2 multiplexing issues many small frame writes
        // (HEADERS / WINDOW_UPDATE) whose interaction with the peer's delayed
        // ACK otherwise stalls each exchange ~40 ms and trips response timeouts
        // under concurrency.
        compat.setTcpNoDelay(fd);

        const transport = self.allocator.create(UpstreamH2Transport) catch {
            _ = std.c.close(fd);
            return error.OutOfMemory;
        };
        if (tls_options) |base_opts| {
            const tls_ptr = self.allocator.create(tls_termination.UpstreamTlsConn) catch {
                self.allocator.destroy(transport);
                _ = std.c.close(fd);
                return error.OutOfMemory;
            };
            var opts = base_opts;
            opts.offer_h2 = true;
            tls_ptr.* = tls_termination.UpstreamTlsConn.connect(fd, host, opts) catch |e| {
                self.allocator.destroy(tls_ptr);
                self.allocator.destroy(transport);
                _ = std.c.close(fd);
                return e;
            };
            // tls_ptr now owns the fd (its close() closes the socket).

            if (tls_ptr.negotiatedProtocol() != .http2) {
                self.allocator.destroy(transport);
                return .{ .h1 = tls_ptr }; // caller owns: close() + destroy()
            }
            transport.* = .{ .tls = .{ .conn = tls_ptr, .allocator = self.allocator } };
        } else {
            // Prior-knowledge h2c: the plain socket speaks h2 immediately.
            transport.* = .{ .plain = fd };
        }
        // transport now owns the fd (its close() tears down TLS and/or socket).

        // Per-origin counters (#238): the reader bumps its origin's entry, and
        // the entry is only created once the origin is actually speaking h2.
        const counters = self.originCounters(key) catch |e| {
            transport.close();
            self.allocator.destroy(transport);
            return e;
        };

        const conn = PooledH2Conn.init(self.allocator, transport, fd, deadline_ms, self.allocator, &counters.stream_resets_total, &counters.goaway_total) catch |e| {
            transport.close();
            self.allocator.destroy(transport);
            return e;
        };
        // conn.refs == 1 (the caller's ref).

        // Publish into the map, resolving a creation race. A displaced stale
        // entry's map ref may be its last (release can join the reader thread
        // in deinit), so it is dropped via this defer — after the unlock on
        // every return path below — never under the pool mutex.
        var stale: ?*PooledH2Conn = null;
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
    pub fn release(_: *H2ConnPool, conn: *PooledH2Conn) void {
        conn.release();
    }

    /// Remove a (presumably dead) connection from the map if it is still the
    /// mapped entry for `key`, dropping the map ref. In-flight requests keep it
    /// alive via their own refs until they finish.
    pub fn evict(self: *H2ConnPool, key: []const u8, conn: *PooledH2Conn) void {
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
        };
        var it = self.conns.valueIterator();
        while (it.next()) |cp| s.streams_active += cp.*.activeStreamCount();
        // The global totals are sums of the per-origin counters; origin
        // entries are never removed, so the sums stay monotonic.
        var cit = self.origin_counters.valueIterator();
        while (cit.next()) |cp| {
            s.stream_resets_total += cp.*.stream_resets_total.load(.monotonic);
            s.goaway_total += cp.*.goaway_total.load(.monotonic);
        }
        return s;
    }

    /// Snapshot per-origin h2 metrics for rendering (#238): monotonic
    /// reset/GOAWAY counters plus live connection/stream gauges. Origins whose
    /// connection has been evicted keep reporting their counters (with zeroed
    /// gauges). Caller frees with `freeH2OriginSnapshots`.
    pub fn snapshotOrigins(self: *H2ConnPool, allocator: std.mem.Allocator) ![]H2OriginSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        var out = std.array_list.Managed(H2OriginSnapshot).init(allocator);
        errdefer {
            for (out.items) |snap| allocator.free(snap.origin);
            out.deinit();
        }
        var it = self.origin_counters.iterator();
        while (it.next()) |e| {
            var snap = H2OriginSnapshot{
                .origin = try allocator.dupe(u8, e.key_ptr.*),
                .connections_active = 0,
                .streams_active = 0,
                .stream_resets_total = e.value_ptr.*.stream_resets_total.load(.monotonic),
                .goaway_total = e.value_ptr.*.goaway_total.load(.monotonic),
            };
            errdefer allocator.free(snap.origin);
            if (self.conns.get(e.key_ptr.*)) |conn| {
                snap.connections_active = 1;
                snap.streams_active = conn.activeStreamCount();
            }
            try out.append(snap);
        }
        return out.toOwnedSlice();
    }

    /// True if `conn` should be dropped from the pool: it must have **no
    /// in-flight streams** (refcount-safe eviction — an in-flight request keeps
    /// the conn alive via its own ref regardless, but idle policy must not race
    /// active work), and then either be unhealthy (dead / GOAWAY), idle past the
    /// idle timeout, or past the max lifetime. Called under the pool mutex.
    fn shouldEvict(self: *H2ConnPool, conn: *PooledH2Conn, now_ms: u64) bool {
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

        var victims: std.ArrayList(*PooledH2Conn) = .empty;
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
        // std.posix retries EINTR (see UpstreamH2Transport.plain).
        return std.posix.read(self.fd, buf) catch error.ReadFailed;
    }
    pub fn writeAll(self: *PlainTransport, data: []const u8) !void {
        var off: usize = 0;
        while (off < data.len) {
            const n = std.c.write(self.fd, data.ptr + off, data.len - off);
            if (n < 0) {
                if (std.posix.errno(n) == .INTR) continue;
                return error.WriteFailed;
            }
            if (n == 0) return error.WriteFailed;
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

const FailingDataTransport = struct {
    fd: std.posix.fd_t,
    fail_next_data_payload: bool = false,

    pub fn read(self: *FailingDataTransport, buf: []u8) !usize {
        return std.posix.read(self.fd, buf) catch error.ReadFailed;
    }

    pub fn writeAll(self: *FailingDataTransport, data: []const u8) !void {
        if (self.fail_next_data_payload) {
            self.fail_next_data_payload = false;
            return error.WriteFailed;
        }
        if (data.len == frame.HEADER_LEN and data[3] == @intFromEnum(frame.Type.data)) {
            self.fail_next_data_payload = true;
        }
        var off: usize = 0;
        while (off < data.len) {
            const n = std.c.write(self.fd, data.ptr + off, data.len - off);
            if (n < 0) {
                if (std.posix.errno(n) == .INTR) continue;
                return error.WriteFailed;
            }
            if (n == 0) return error.WriteFailed;
            off += @intCast(n);
        }
    }

    pub fn pending(_: *const FailingDataTransport) usize {
        return 0;
    }

    pub fn close(self: *FailingDataTransport) void {
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

/// Accept one connection on `listen_fd` and serve `n` canned h2 requests on it
/// (prior-knowledge: the server speaks h2 immediately, no Upgrade). After
/// serving, drain the socket until the client closes: closing a TCP socket
/// with unread data in its receive queue (the client's SETTINGS-ACK and
/// WINDOW_UPDATEs, which the canned server never reads) sends an RST that can
/// discard the in-flight response — a race the AF_UNIX socketpair servers
/// never see because unix-socket close has clean EOF delivery semantics.
fn h2cListenerServe(listen_fd: std.posix.fd_t, n: usize) void {
    const conn = std.c.accept(listen_fd, null, null);
    if (conn < 0) return;
    cannedMuxServer(conn, n);
    var drain: [512]u8 = undefined;
    while (true) {
        const got = std.posix.read(conn, drain[0..]) catch break;
        if (got == 0) break; // client closed — safe to close without RST
    }
    _ = std.c.close(conn);
}

/// Accept connections and hold them silently (never handshake, never write) —
/// a TCP-accepting-but-dead TLS origin. Gated by `poll()` with a short tick so
/// the loop re-checks `stop` and exits deterministically: `accept()` is only
/// called once poll reports the listener readable, so it never blocks and
/// shutdown does not depend on the unreliable "close the listening fd from
/// another thread to wake a blocking accept()" behavior. Accepted connections
/// are held open until the acceptor exits so the client's `SSL_connect` sees an
/// open-but-silent peer (closing them would let the handshake fail fast on EOF,
/// defeating the timeout test).
fn silentAcceptor(listen_fd: std.posix.fd_t, stop: *std.atomic.Value(bool)) void {
    var held: [4]std.posix.fd_t = undefined;
    var n: usize = 0;
    while (!stop.load(.acquire) and n < held.len) {
        var pfd = [_]std.posix.pollfd{.{ .fd = listen_fd, .events = std.posix.POLL.IN, .revents = 0 }};
        const ready = std.posix.poll(&pfd, 50) catch break; // 50ms tick → re-check stop
        if (ready == 0) continue;
        const conn = std.c.accept(listen_fd, null, null);
        if (conn < 0) continue;
        held[n] = conn;
        n += 1;
    }
    for (held[0..n]) |fd| _ = std.c.close(fd);
}

test "h2 pool acquire is deadline-bounded against a TCP-accepting but silent TLS origin (#171)" {
    const listen_fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    try testing.expect(listen_fd >= 0);
    const sin: std.c.sockaddr.in = .{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 0),
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
        .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    try testing.expect(std.c.bind(listen_fd, @ptrCast(&sin), @sizeOf(std.c.sockaddr.in)) == 0);
    try testing.expect(std.c.listen(listen_fd, 4) == 0);
    var bound: std.c.sockaddr.in = undefined;
    var bound_len: std.posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    try testing.expect(std.c.getsockname(listen_fd, @ptrCast(&bound), &bound_len) == 0);
    const port = std.mem.bigToNative(u16, bound.port);

    var stop = std.atomic.Value(bool).init(false);
    const server = try std.Thread.spawn(.{}, silentAcceptor, .{ listen_fd, &stop });

    var pool = H2ConnPool.init(testing.allocator, .{});
    defer pool.deinit();
    var key_buf: [64]u8 = undefined;
    const key = try std.fmt.bufPrint(&key_buf, "h2:127.0.0.1:{d}", .{port});

    // The origin accepts TCP but never speaks TLS: SSL_connect would block
    // forever without the pre-handshake socket timeouts. The acquire must
    // fail within the deadline, not the OS default.
    const start_ms = nowMs();
    const res = pool.acquire(key, "127.0.0.1", port, .{ .skip_verify = true }, 500, 500);
    const elapsed_ms = nowMs() - start_ms;
    try testing.expect(std.meta.isError(res));
    try testing.expect(elapsed_ms < 5_000);

    // Deterministic shutdown: the acceptor polls with a 50ms tick, so setting
    // the flag makes it exit on its own — no cross-thread accept() wake needed.
    stop.store(true, .release);
    server.join();
    _ = std.c.close(listen_fd);
}

test "h2c pool acquires a prior-knowledge cleartext connection and round-trips" {
    // Raw blocking listener (no event loop), mirroring the gateway_proxy
    // TCP-origin test setup.
    const listen_fd = std.c.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    try testing.expect(listen_fd >= 0);
    defer _ = std.c.close(listen_fd);
    _ = std.c.setsockopt(listen_fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, std.mem.asBytes(&@as(c_int, 1)), @sizeOf(c_int));
    const sin: std.c.sockaddr.in = .{
        .family = std.posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 0),
        .addr = @bitCast([4]u8{ 127, 0, 0, 1 }),
        .zero = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    try testing.expect(std.c.bind(listen_fd, @ptrCast(&sin), @sizeOf(std.c.sockaddr.in)) == 0);
    try testing.expect(std.c.listen(listen_fd, 8) == 0);
    var bound: std.c.sockaddr.in = undefined;
    var bound_len: std.posix.socklen_t = @sizeOf(std.c.sockaddr.in);
    try testing.expect(std.c.getsockname(listen_fd, @ptrCast(&bound), &bound_len) == 0);
    const port = std.mem.bigToNative(u16, bound.port);

    // Cleanup is all defers (LIFO) so a failing assertion cannot leak the
    // pool/connection or leave threads unjoined: release conn -> pool.deinit
    // (drops the map ref, joining the reader; the server then sees EOF or its
    // own read deadline) -> server.join.
    const server = try std.Thread.spawn(.{}, h2cListenerServe, .{ listen_fd, @as(usize, 1) });
    defer server.join();

    var pool = H2ConnPool.init(testing.allocator, .{});
    defer pool.deinit();
    var key_buf: [64]u8 = undefined;
    const key = try std.fmt.bufPrint(&key_buf, "h2c:127.0.0.1:{d}", .{port});

    // tls_options == null => prior-knowledge cleartext h2; never `.h1`.
    const acq = try pool.acquire(key, "127.0.0.1", port, null, 2000, 5000);
    const conn = switch (acq) {
        .h2 => |c| c,
        .h1 => return error.TestUnexpectedResult,
    };
    defer pool.release(conn);
    var resp = try conn.request(.{ .method = "GET", .authority = "h2c.test", .path = "/req0" });
    defer resp.deinit();
    try testing.expectEqual(@as(u16, 200), resp.status);
    try testing.expectEqualStrings("/req0", resp.body);

    // The h2c origin appears in the per-origin snapshot under its `h2c:` key.
    const snaps = try pool.snapshotOrigins(testing.allocator);
    defer freeH2OriginSnapshots(testing.allocator, snaps);
    try testing.expectEqual(@as(usize, 1), snaps.len);
    try testing.expectEqualStrings(key, snaps[0].origin);
    try testing.expectEqual(@as(u64, 1), snaps[0].connections_active);
}

test "h2 pool per-origin counters persist and feed both labelled and global snapshots" {
    var pool = H2ConnPool.init(testing.allocator, .{});
    defer pool.deinit();

    // Two origins; the same key returns the same persistent entry.
    const a = try pool.originCounters("h2:origin-a:443");
    const b = try pool.originCounters("h2:origin-b:8443");
    try testing.expect(a == try pool.originCounters("h2:origin-a:443"));

    // Simulate reader bumps (the reader holds exactly these pointers).
    _ = a.stream_resets_total.fetchAdd(2, .monotonic);
    _ = b.goaway_total.fetchAdd(1, .monotonic);

    // Global snapshot = sums across origins (backward-compatible series).
    const global = pool.snapshot();
    try testing.expectEqual(@as(u64, 2), global.stream_resets_total);
    try testing.expectEqual(@as(u64, 1), global.goaway_total);
    try testing.expectEqual(@as(u64, 0), global.connections_active);

    // Labelled snapshot: per-origin counters, zero gauges without a live conn.
    const snaps = try pool.snapshotOrigins(testing.allocator);
    defer freeH2OriginSnapshots(testing.allocator, snaps);
    try testing.expectEqual(@as(usize, 2), snaps.len);
    for (snaps) |snap| {
        if (std.mem.eql(u8, snap.origin, "h2:origin-a:443")) {
            try testing.expectEqual(@as(u64, 2), snap.stream_resets_total);
            try testing.expectEqual(@as(u64, 0), snap.goaway_total);
        } else {
            try testing.expectEqualStrings("h2:origin-b:8443", snap.origin);
            try testing.expectEqual(@as(u64, 1), snap.goaway_total);
        }
        try testing.expectEqual(@as(u64, 0), snap.connections_active);
        try testing.expectEqual(@as(u64, 0), snap.streams_active);
    }
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

/// Canned server for the streaming round-trip test: answers the first request
/// HEADERS with response HEADERS + DATA("part1"), then *waits for a
/// stream-level WINDOW_UPDATE* — which only the draining consumer sends on a
/// streaming stream — before finishing with DATA("part2", END_STREAM). The
/// client making progress past part1 therefore proves consumer-driven
/// stream-window replenishment.
fn cannedStreamingServer(peer_fd: std.posix.fd_t) void {
    const a = std.heap.page_allocator;
    var srv = PlainTransport{ .fd = peer_fd };
    var preface: [PREFACE.len]u8 = undefined;
    readExact(&srv, peer_fd, preface[0..], 2000) catch return;
    frame.writeSettings(a, &srv, &[_][2]u32{}) catch return;

    var req_stream: u31 = 0;
    while (req_stream == 0) {
        var fr = readFrameBounded(&srv, peer_fd, a, 2000) catch return;
        if (fr.typ == .headers) req_stream = fr.stream_id;
        frame.deinitFrame(a, &fr);
    }

    const block = hpack.encodeLiteralHeaderBlock(a, &[_]hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/plain" },
    }) catch return;
    defer a.free(block);
    frame.writeFrame(&srv, .headers, frame.Flags.END_HEADERS, req_stream, block) catch return;
    frame.writeFrame(&srv, .data, 0, req_stream, "part1") catch return;

    // Block until the consumer's drain replenishes the stream window.
    while (true) {
        var fr = readFrameBounded(&srv, peer_fd, a, 5000) catch return;
        const is_stream_wu = fr.typ == .window_update and fr.stream_id == req_stream;
        frame.deinitFrame(a, &fr);
        if (is_stream_wu) break;
    }
    frame.writeFrame(&srv, .data, frame.Flags.END_STREAM, req_stream, "part2") catch return;
}

test "streaming request relays a multi-frame body with consumer-driven window replenishment" {
    const fds = try makeSocketpair();
    const server = try std.Thread.spawn(.{}, cannedStreamingServer, .{fds[1]});

    var transport = PlainTransport{ .fd = fds[0] };
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 3000, null, null, null);

    const stream = try conn.requestStreaming(.{ .method = "GET", .authority = "stream.test", .path = "/" });
    try testing.expectEqual(@as(u16, 200), stream.status.?);
    var saw_content_type = false;
    for (stream.headers.items) |h| {
        if (std.mem.eql(u8, h.name, "content-type")) saw_content_type = true;
    }

    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(testing.allocator);
    var buf: [4]u8 = undefined; // deliberately tiny: multiple reads per frame
    while (true) {
        const n = try conn.readStreamingBody(stream, buf[0..]);
        if (n == 0) break;
        try got.appendSlice(testing.allocator, buf[0..n]);
    }
    conn.finishStreaming(stream);

    try testing.expect(saw_content_type);
    try testing.expectEqualStrings("part1part2", got.items);
    try testing.expectEqual(@as(u32, 0), conn.activeStreamCount());
    try testing.expect(conn.healthy());

    conn.deinit();
    server.join();
    _ = std.c.close(fds[1]);
}

/// Canned server: HEADERS + DATA + a trailer HEADERS block (END_STREAM). The
/// trailer fields must be decoded (HPACK table consistency) but discarded.
fn cannedTrailerServer(peer_fd: std.posix.fd_t) void {
    const a = std.heap.page_allocator;
    var srv = PlainTransport{ .fd = peer_fd };
    var preface: [PREFACE.len]u8 = undefined;
    readExact(&srv, peer_fd, preface[0..], 2000) catch return;
    frame.writeSettings(a, &srv, &[_][2]u32{}) catch return;

    var req_stream: u31 = 0;
    while (req_stream == 0) {
        var fr = readFrameBounded(&srv, peer_fd, a, 2000) catch return;
        if (fr.typ == .headers) req_stream = fr.stream_id;
        frame.deinitFrame(a, &fr);
    }

    const head = hpack.encodeLiteralHeaderBlock(a, &[_]hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
    }) catch return;
    defer a.free(head);
    frame.writeFrame(&srv, .headers, frame.Flags.END_HEADERS, req_stream, head) catch return;
    frame.writeFrame(&srv, .data, 0, req_stream, "payload") catch return;
    const trailers = hpack.encodeLiteralHeaderBlock(a, &[_]hpack.HeaderField{
        .{ .name = "x-checksum", .value = "abc123" },
    }) catch return;
    defer a.free(trailers);
    frame.writeFrame(&srv, .headers, frame.Flags.END_HEADERS | frame.Flags.END_STREAM, req_stream, trailers) catch return;
}

test "streaming response trailers end the stream and are discarded" {
    const fds = try makeSocketpair();
    const server = try std.Thread.spawn(.{}, cannedTrailerServer, .{fds[1]});

    var transport = PlainTransport{ .fd = fds[0] };
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 3000, null, null, null);

    const stream = try conn.requestStreaming(.{ .method = "GET", .authority = "trailer.test", .path = "/" });
    try testing.expectEqual(@as(u16, 200), stream.status.?);

    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(testing.allocator);
    var buf: [64]u8 = undefined;
    while (true) {
        const n = try conn.readStreamingBody(stream, buf[0..]);
        if (n == 0) break;
        try got.appendSlice(testing.allocator, buf[0..n]);
    }
    try testing.expectEqualStrings("payload", got.items);
    for (stream.headers.items) |h| {
        try testing.expect(!std.mem.eql(u8, h.name, "x-checksum"));
    }
    conn.finishStreaming(stream);
    conn.deinit();
    server.join();
    _ = std.c.close(fds[1]);
}

/// Canned server that violates flow control: sends OUR_INITIAL_WINDOW bytes of
/// DATA (filling the advertised stream window exactly) plus one more frame
/// beyond it without waiting for replenishment, then a PING whose ACK proves
/// the client's reader has processed every prior frame. `saw_ack` is set once
/// the ACK arrives so the test can start consuming deterministically.
fn cannedFlowViolationServer(peer_fd: std.posix.fd_t, saw_ack: *std.atomic.Value(bool)) void {
    const a = std.heap.page_allocator;
    var srv = PlainTransport{ .fd = peer_fd };
    var preface: [PREFACE.len]u8 = undefined;
    readExact(&srv, peer_fd, preface[0..], 2000) catch return;
    frame.writeSettings(a, &srv, &[_][2]u32{}) catch return;

    var req_stream: u31 = 0;
    while (req_stream == 0) {
        var fr = readFrameBounded(&srv, peer_fd, a, 2000) catch return;
        if (fr.typ == .headers) req_stream = fr.stream_id;
        frame.deinitFrame(a, &fr);
    }

    const head = hpack.encodeLiteralHeaderBlock(a, &[_]hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
    }) catch return;
    defer a.free(head);
    frame.writeFrame(&srv, .headers, frame.Flags.END_HEADERS, req_stream, head) catch return;

    const chunk = [_]u8{'x'} ** DEFAULT_MAX_FRAME;
    var sent: usize = 0;
    while (sent < OUR_INITIAL_WINDOW) : (sent += chunk.len) {
        frame.writeFrame(&srv, .data, 0, req_stream, chunk[0..]) catch return;
    }
    // One frame past the advertised window: a flow-control violation.
    frame.writeFrame(&srv, .data, 0, req_stream, chunk[0..]) catch return;

    const ping_payload = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    frame.writeFrame(&srv, .ping, 0, 0, ping_payload[0..]) catch return;
    while (true) {
        var fr = readFrameBounded(&srv, peer_fd, a, 5000) catch return;
        const is_ack = fr.typ == .ping and (fr.flags & frame.Flags.ACK) != 0;
        frame.deinitFrame(a, &fr);
        if (is_ack) {
            saw_ack.store(true, .release);
            return;
        }
    }
}

test "streaming stream fails when the peer overruns the advertised window" {
    const fds = try makeSocketpair();
    var saw_ack = std.atomic.Value(bool).init(false);
    const server = try std.Thread.spawn(.{}, cannedFlowViolationServer, .{ fds[1], &saw_ack });

    var transport = PlainTransport{ .fd = fds[0] };
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 5000, null, null, null);

    const stream = try conn.requestStreaming(.{ .method = "GET", .authority = "flood.test", .path = "/" });

    // Wait (bounded spin) until the reader has processed every frame the
    // server sent — including the over-window one — so the violation is
    // recorded before we start draining (draining replenishes the window).
    var spins: usize = 0;
    while (!saw_ack.load(.acquire) and spins < 100_000_000) : (spins += 1) std.Thread.yield() catch {};
    try testing.expect(saw_ack.load(.acquire));

    // The in-window megabyte drains fine; the overrun then surfaces as a
    // flow-control error rather than unbounded buffering.
    var total: usize = 0;
    var buf: [32 * 1024]u8 = undefined;
    const read_err = while (true) {
        const n = conn.readStreamingBody(stream, buf[0..]) catch |e| break e;
        try testing.expect(n != 0); // stream must not end cleanly
        total += n;
    };
    try testing.expectEqual(@as(usize, OUR_INITIAL_WINDOW), total);
    try testing.expectError(error.Http2FlowControlError, @as(anyerror!void, read_err));

    conn.finishStreaming(stream);
    conn.deinit();
    server.join();
    _ = std.c.close(fds[1]);
}

/// Canned server: response HEADERS then silence on the stream while PING
/// frames keep the connection's reader busy — the stalled stream must be
/// failed by the wait-deadline sweep, not the whole-connection read timeout.
fn cannedStallServer(peer_fd: std.posix.fd_t, stop: *std.atomic.Value(bool)) void {
    const a = std.heap.page_allocator;
    var srv = PlainTransport{ .fd = peer_fd };
    var preface: [PREFACE.len]u8 = undefined;
    readExact(&srv, peer_fd, preface[0..], 2000) catch return;
    frame.writeSettings(a, &srv, &[_][2]u32{}) catch return;

    var req_stream: u31 = 0;
    while (req_stream == 0) {
        var fr = readFrameBounded(&srv, peer_fd, a, 2000) catch return;
        if (fr.typ == .headers) req_stream = fr.stream_id;
        frame.deinitFrame(a, &fr);
    }
    const head = hpack.encodeLiteralHeaderBlock(a, &[_]hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
    }) catch return;
    defer a.free(head);
    frame.writeFrame(&srv, .headers, frame.Flags.END_HEADERS, req_stream, head) catch return;

    // Keep frames flowing (but never DATA for the stream) until told to stop.
    const ping_payload = [_]u8{0} ** 8;
    var i: usize = 0;
    while (!stop.load(.acquire) and i < 10_000) : (i += 1) {
        frame.writeFrame(&srv, .ping, 0, 0, ping_payload[0..]) catch return;
        std.Io.sleep(compat.io(), .fromMilliseconds(20), .awake) catch {}; // pacing only, not asserted on
    }
}

test "stalled streaming stream times out via the reader sweep while other frames flow" {
    const fds = try makeSocketpair();
    var stop = std.atomic.Value(bool).init(false);
    const server = try std.Thread.spawn(.{}, cannedStallServer, .{ fds[1], &stop });

    var transport = PlainTransport{ .fd = fds[0] };
    // Short stream deadline; PINGs every 20ms keep the reader's frame reads
    // alive, so only the sweep can bound the body wait.
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 300, null, null, null);

    const stream = try conn.requestStreaming(.{ .method = "GET", .authority = "stall.test", .path = "/" });
    var buf: [64]u8 = undefined;
    const res = conn.readStreamingBody(stream, buf[0..]);
    try testing.expectError(error.Http2Timeout, res);
    // The stream timed out — the connection itself must still be healthy.
    try testing.expect(conn.healthy());

    conn.finishStreaming(stream);
    stop.store(true, .release);
    conn.deinit();
    server.join();
    _ = std.c.close(fds[1]);
}

const MuxStreamingClientCtx = struct {
    conn: *H2Conn(*PlainTransport),
    idx: usize,
    ok: bool = false,
};

fn muxStreamingClientThread(ctx: *MuxStreamingClientCtx) void {
    var path_buf: [32]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/sreq{d}", .{ctx.idx}) catch return;
    const stream = ctx.conn.requestStreaming(.{
        .method = "GET",
        .authority = "mux.test",
        .path = path,
    }) catch return;
    defer ctx.conn.finishStreaming(stream);
    if (stream.status != 200) return;

    var got_buf: [64]u8 = undefined;
    var got_len: usize = 0;
    while (true) {
        const n = ctx.conn.readStreamingBody(stream, got_buf[got_len..]) catch return;
        if (n == 0) break;
        got_len += n;
    }
    ctx.ok = std.mem.eql(u8, got_buf[0..got_len], path);
}

test "streaming and buffered requests multiplex together on one connection" {
    const N_BUF = 4;
    const N_STREAM = 4;
    const fds = try makeSocketpair();
    const server = try std.Thread.spawn(.{}, cannedMuxServer, .{ fds[1], @as(usize, N_BUF + N_STREAM) });

    var transport = PlainTransport{ .fd = fds[0] };
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 3000, null, null, null);

    var bctxs: [N_BUF]MuxClientCtx = undefined;
    var sctxs: [N_STREAM]MuxStreamingClientCtx = undefined;
    var threads: [N_BUF + N_STREAM]std.Thread = undefined;
    for (0..N_BUF) |i| {
        bctxs[i] = .{ .conn = conn, .idx = i };
        threads[i] = try std.Thread.spawn(.{}, muxClientThread, .{&bctxs[i]});
    }
    for (0..N_STREAM) |i| {
        sctxs[i] = .{ .conn = conn, .idx = i };
        threads[N_BUF + i] = try std.Thread.spawn(.{}, muxStreamingClientThread, .{&sctxs[i]});
    }
    for (threads) |t| t.join();

    var all_ok = true;
    for (bctxs) |c| {
        if (!c.ok) all_ok = false;
    }
    for (sctxs) |c| {
        if (!c.ok) all_ok = false;
    }
    conn.deinit();
    server.join();
    _ = std.c.close(fds[1]);
    try testing.expect(all_ok);
}

const UploadWriterCtx = struct {
    conn: *H2Conn(*PlainTransport),
    stream: *Stream,
    body: []const u8,
    done: *std.atomic.Value(bool),
    ok: bool = false,
};

fn uploadWriterThread(ctx: *UploadWriterCtx) void {
    ctx.conn.writeStreamingRequestBody(ctx.stream, ctx.body, true) catch return;
    ctx.ok = true;
    ctx.done.store(true, .release);
}

fn cannedStreamingUploadServer(peer_fd: std.posix.fd_t, writer_done: *std.atomic.Value(bool), blocked_observed: *std.atomic.Value(bool), expected_len: usize) void {
    const a = std.heap.page_allocator;
    var srv = PlainTransport{ .fd = peer_fd };
    var preface: [PREFACE.len]u8 = undefined;
    readExact(&srv, peer_fd, preface[0..], 2000) catch return;
    frame.writeSettings(a, &srv, &[_][2]u32{}) catch return;

    var req_stream: u31 = 0;
    while (req_stream == 0) {
        var fr = readFrameBounded(&srv, peer_fd, a, 2000) catch return;
        if (fr.typ == .headers) req_stream = fr.stream_id;
        frame.deinitFrame(a, &fr);
    }

    var received: usize = 0;
    while (received < @as(usize, @intCast(PROTOCOL_DEFAULT_WINDOW))) {
        var fr = readFrameBounded(&srv, peer_fd, a, 2000) catch return;
        if (fr.typ == .data and fr.stream_id == req_stream) {
            received += fr.payload.len;
        }
        frame.deinitFrame(a, &fr);
    }

    if (!writer_done.load(.acquire)) blocked_observed.store(true, .release);
    const inc = windowIncrement(expected_len - received);
    frame.writeFrame(&srv, .window_update, 0, 0, &inc) catch return;
    frame.writeFrame(&srv, .window_update, 0, req_stream, &inc) catch return;

    var saw_end = false;
    while (!saw_end) {
        var fr = readFrameBounded(&srv, peer_fd, a, 2000) catch return;
        if (fr.typ == .data and fr.stream_id == req_stream) {
            received += fr.payload.len;
            saw_end = (fr.flags & frame.Flags.END_STREAM) != 0;
        }
        frame.deinitFrame(a, &fr);
    }
    if (received != expected_len) return;

    const head = hpack.encodeLiteralHeaderBlock(a, &[_]hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "x-uploaded-bytes", .value = "69631" },
    }) catch return;
    defer a.free(head);
    frame.writeFrame(&srv, .headers, frame.Flags.END_HEADERS, req_stream, head) catch return;
    frame.writeFrame(&srv, .data, frame.Flags.END_STREAM, req_stream, "upload-ok") catch return;
}

test "streaming request upload sends DATA incrementally and waits for flow-control window" {
    const upload_len: usize = @as(usize, @intCast(PROTOCOL_DEFAULT_WINDOW)) + 4096;
    const body = try testing.allocator.alloc(u8, upload_len);
    defer testing.allocator.free(body);
    @memset(body, 'u');

    const fds = try makeSocketpair();
    var writer_done = std.atomic.Value(bool).init(false);
    var blocked_observed = std.atomic.Value(bool).init(false);
    const server = try std.Thread.spawn(.{}, cannedStreamingUploadServer, .{ fds[1], &writer_done, &blocked_observed, upload_len });

    var transport = PlainTransport{ .fd = fds[0] };
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 3000, null, null, null);

    const stream = try conn.openStreaming(.{
        .method = "POST",
        .scheme = "http",
        .authority = "upload.test",
        .path = "/upload",
        .body_mode = .streaming,
    });

    var writer_ctx = UploadWriterCtx{
        .conn = conn,
        .stream = stream,
        .body = body,
        .done = &writer_done,
    };
    const writer = try std.Thread.spawn(.{}, uploadWriterThread, .{&writer_ctx});

    try conn.waitStreamingResponseHead(stream);
    try testing.expectEqual(@as(u16, 200), stream.status.?);

    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(testing.allocator);
    var buf: [32]u8 = undefined;
    while (true) {
        const n = try conn.readStreamingBody(stream, buf[0..]);
        if (n == 0) break;
        try got.appendSlice(testing.allocator, buf[0..n]);
    }

    conn.finishStreaming(stream);
    writer.join();
    conn.deinit();
    server.join();
    _ = std.c.close(fds[1]);

    try testing.expect(writer_ctx.ok);
    try testing.expect(blocked_observed.load(.acquire));
    try testing.expectEqualStrings("upload-ok", got.items);
}

test "streaming request upload DATA write failure poisons the h2 connection" {
    const fds = try makeSocketpair();
    defer _ = std.c.close(fds[1]);

    var transport = FailingDataTransport{ .fd = fds[0] };
    const conn = try H2Conn(*FailingDataTransport).init(testing.allocator, &transport, fds[0], 3000, null, null, null);

    const stream = try conn.openStreaming(.{
        .method = "POST",
        .scheme = "http",
        .authority = "upload.test",
        .path = "/upload",
        .body_mode = .streaming,
    });

    try testing.expectError(error.WriteFailed, conn.writeStreamingRequestBody(stream, "payload", true));
    try testing.expect(!conn.healthy());

    conn.finishStreaming(stream);
    try testing.expectEqual(@as(u32, 0), conn.activeStreamCount());

    conn.deinit();
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
