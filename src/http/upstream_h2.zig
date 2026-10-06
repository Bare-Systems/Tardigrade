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
//! `read([]u8) !usize`, `writeAll([]const u8) !void`, and `pending() usize`.
//! `pending()` reports already-decrypted plaintext buffered by the transport,
//! so poll-bounded reads do not miss bytes already available above the socket.
//! Reads are bounded with `poll(2)` so a hung origin cannot block a worker
//! indefinitely (the #196 guarantee).

const std = @import("std");
const compat = @import("zig_compat");
const frame = @import("http2_frame.zig");
const hpack = @import("hpack.zig");
const upstream_tls = @import("upstream_tls.zig");
const proxy_buffer_account = @import("proxy_buffer_account.zig");

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
/// Receive window we advertise per stream (SETTINGS_INITIAL_WINDOW_SIZE) when
/// no per-stream buffer policy is configured. For streaming streams this
/// doubles as the bounded per-stream buffer: the reader stops replenishing it,
/// so a well-behaved peer can have at most this many unconsumed bytes buffered
/// per stream. Production connections derive the window from
/// `proxy_buffer_account.streamReceiveWindow` instead (#140).
pub const DEFAULT_STREAM_RECV_WINDOW: u31 = 1 << 20;
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

/// RST_STREAM error codes we emit (RFC 9113 §7).
const RST_FLOW_CONTROL_ERROR: u32 = 0x3;
const RST_CANCEL: u32 = 0x8;

fn rstStreamPayload(code: u32) [4]u8 {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, code, .big);
    return buf;
}

pub const H2Error = error{
    Http2Timeout,
    /// A caller using `readStreamingBodyInterruptible` reached its short
    /// lifecycle polling slice without receiving a body event. This is not an
    /// upstream failure and leaves both the stream and connection usable; the
    /// caller decides whether a higher-level deadline now requires a reset.
    Http2ReadWaitElapsed,
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
    /// Account this stream's queued response body against the connection's
    /// pinned buffer policy. The policy itself is never supplied per request:
    /// it must match the receive window the connection already advertised.
    proxy_buffer_accounting: bool = false,
    proxy_buffer_observer: ?proxy_buffer_account.Observer = null,
    /// Aggregate (origin/global) scopes this stream's queued response bytes are
    /// reserved against, so many concurrent slow streams cannot multiply the
    /// per-stream bound. Only consulted alongside `proxy_buffer_accounting`.
    proxy_buffer_capacity: proxy_buffer_account.AggregateCapacity = .{},
    /// Bytes the caller's response relay buffer will own at the same time as
    /// this stream's queue, held back from the queue's own per-stream hard
    /// limit so the two together cannot exceed it.
    ///
    /// The queue and that buffer are genuinely simultaneous — the queue's
    /// reservation is not released until after the downstream write — so
    /// letting each have the full hard limit meant one stream could own two
    /// limits' worth with neither reporting an exceedance. Subtracting here
    /// rather than sharing a budget object is deliberate: a shared object
    /// would have to outlive both a worker's relay and a stream the reader
    /// thread can still be inside, and `finishStreaming` destroys streams
    /// outside the state lock. Reserved headroom needs no shared lifetime at
    /// all.
    ///
    /// Config validation guarantees `hard >= high + relay`, so the queue is
    /// still left room for a full receive window.
    proxy_relay_reserved_bytes: usize = 0,
};

pub const BodyMode = enum {
    complete,
    streaming,
};

/// Why a stream was aborted. `local_capacity` means *this proxy* ran out of
/// buffer room, which is never evidence about the origin — the distinction has
/// to survive all the way out to status selection and upstream health.
pub const AbortCause = enum {
    none,
    upstream,
    local_capacity,
};

/// How far the downstream response has got. The transition to `committing` is
/// the linearization point for the commitment boundary: taken under
/// `state_mutex`, it makes "did the reader reject DATA before or after we
/// started writing the head?" a decided question rather than a race.
pub const DownstreamCommitState = enum {
    precommit,
    committing,
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
        .{ 0x4, @as(u32, DEFAULT_STREAM_RECV_WINDOW) }, // SETTINGS_INITIAL_WINDOW_SIZE
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
    /// True once the stream's HEADERS frame is being put on the wire. Guards
    /// every RST_STREAM: resetting a stream the peer never saw (idle state)
    /// would be a connection-level PROTOCOL_ERROR. Set by the owning worker and
    /// read by the reader thread, so it lives under `state_mutex` like the rest
    /// of the stream state machine.
    wire_opened: bool = false,
    local_abort: bool = false,
    /// Set once the reader has emitted RST_STREAM for this stream, so
    /// `finishStreaming` does not send a second one.
    rst_sent: bool = false,
    abort_cause: AbortCause = .none,
    downstream_state: DownstreamCommitState = .precommit,
    /// Per-stream logical queue length: the bytes a downstream consumer has not
    /// taken yet. Drives the high/low watermark hysteresis.
    proxy_body_account: ?proxy_buffer_account.Account = null,
    proxy_buffer_observer: ?proxy_buffer_account.Observer = null,
    /// Aggregate scopes backing this stream's queue.
    proxy_buffer_capacity: proxy_buffer_account.AggregateCapacity = .{},
    /// Bytes currently reserved at the aggregate scopes. This tracks `body`'s
    /// **retained allocation**, not its logical length: an ArrayList that has
    /// been drained still owns its backing memory, and retained memory is what
    /// an aggregate limit is meant to bound. The queue's storage is freed (and
    /// this reservation returned in full) as soon as it drains empty.
    proxy_capacity_reserved: usize = 0,
    /// Downstream-consumed bytes not yet credited back to the peer as stream
    /// flow control. While the queue sits above its high watermark, credit is
    /// withheld and accumulates here; it is released as one WINDOW_UPDATE when
    /// the queue drains below the low watermark. This is the pause/resume
    /// hysteresis — crediting every consumed chunk would let the peer refill
    /// immediately and the band would never do anything.
    pending_window_credit: usize = 0,

    fn destroy(self: *Stream, allocator: std.mem.Allocator) void {
        self.releaseQueuedBodyAccounting();
        self.releaseRetainedStorage();
        freeHeaderList(allocator, &self.headers);
        self.body.deinit(allocator);
        allocator.destroy(self);
    }

    /// True while the queue is in the pause band: it reached the high watermark
    /// and has not yet drained back below the low one. Streams with no
    /// accounting policy never pause.
    fn aboveHighWatermark(self: *const Stream) bool {
        const account = self.proxy_body_account orelse return false;
        return account.snapshot().above_high_watermark;
    }

    fn accountDirection(self: *const Stream) proxy_buffer_account.Direction {
        return if (self.proxy_body_account) |account| account.direction else .upstream_to_downstream;
    }

    /// Take ownership of `payload` on this stream's queue, reserving at every
    /// scope *before* any memory is committed. Aggregate scopes are charged for
    /// the queue's retained allocation, so the reservation only grows when the
    /// queue's storage does; the per-stream account tracks the logical length
    /// that drives the watermarks. Either reservation failing leaves the stream
    /// exactly as it was — no bytes queued, no scope charged.
    fn enqueueBody(self: *Stream, allocator: std.mem.Allocator, payload: []const u8) !void {
        const account = if (self.proxy_body_account) |*a| a else {
            try self.body.appendSlice(allocator, payload);
            return;
        };
        const direction = account.direction;

        // Grow the aggregate reservation to cover the storage this append will
        // retain. Allocating precisely keeps `capacity == reserved`, so the
        // aggregates never undercount an ArrayList's amortised over-allocation.
        const needed_capacity = std.math.add(usize, self.body.items.len, payload.len) catch return error.BufferLimitExceeded;
        var capacity_delta: usize = 0;
        if (needed_capacity > self.proxy_capacity_reserved) {
            capacity_delta = needed_capacity - self.proxy_capacity_reserved;
            self.proxy_buffer_capacity.reserve(direction, capacity_delta) catch |err| {
                if (self.proxy_buffer_observer) |observer| {
                    observer.recordAggregateLimitExceeded(direction, proxy_buffer_account.aggregateFailureScope(err));
                }
                return error.BufferLimitExceeded;
            };
        }
        errdefer if (capacity_delta > 0) {
            self.proxy_buffer_capacity.release(direction, capacity_delta);
        };

        const before = account.snapshot();
        account.reserve(payload.len) catch |err| {
            const after = account.snapshot();
            if (self.proxy_buffer_observer) |observer| {
                if (after.limit_exceeded_events > before.limit_exceeded_events) {
                    observer.recordReservation(direction, 0, false, true);
                }
            }
            return err;
        };
        errdefer account.release(payload.len) catch unreachable;

        try self.body.ensureTotalCapacityPrecise(allocator, needed_capacity);
        self.body.appendSliceAssumeCapacity(payload);
        self.proxy_capacity_reserved += capacity_delta;
        if (self.proxy_buffer_observer) |observer| {
            observer.recordRetainedBytes(direction, capacity_delta);
        }

        const after = account.snapshot();
        const crossed_high = after.high_watermark_events > before.high_watermark_events;
        if (self.proxy_buffer_observer) |observer| {
            observer.recordReservation(
                direction,
                payload.len,
                crossed_high,
                after.limit_exceeded_events > before.limit_exceeded_events,
            );
            // Reaching the high watermark is the moment stream credit stops
            // flowing, so the pause belongs here rather than at the drain that
            // eventually clears it.
            if (crossed_high) observer.recordReadPause(.upstream);
        }
    }

    fn releaseQueuedBody(self: *Stream, bytes: usize) void {
        if (bytes == 0) return;
        if (self.proxy_body_account) |*account| {
            account.release(bytes) catch unreachable;
            if (self.proxy_buffer_observer) |observer| {
                observer.releaseReservation(account.direction, bytes);
            }
        }
    }

    /// Give the queue's backing allocation back once it drains empty, and with
    /// it the aggregate reservation that covered it. Without this the queue
    /// would keep its peak allocation for the stream's whole life while the
    /// aggregate counters read zero — the concurrency multiplication the
    /// aggregate limits exist to prevent.
    fn releaseRetainedStorage(self: *Stream) void {
        if (self.proxy_capacity_reserved == 0) return;
        const direction = self.accountDirection();
        self.proxy_buffer_capacity.release(direction, self.proxy_capacity_reserved);
        if (self.proxy_buffer_observer) |observer| {
            observer.releaseRetainedBytes(direction, self.proxy_capacity_reserved);
        }
        self.proxy_capacity_reserved = 0;
    }

    fn compactAcknowledgedBody(self: *Stream, allocator: std.mem.Allocator, bytes: usize) void {
        if (bytes == 0) return;
        std.debug.assert(bytes <= self.body_read_off);
        std.debug.assert(bytes <= self.body.items.len);
        const remaining = self.body.items.len - bytes;
        if (remaining > 0) {
            std.mem.copyForwards(u8, self.body.items[0..remaining], self.body.items[bytes..]);
        }
        self.body.shrinkRetainingCapacity(remaining);
        self.body_read_off -= bytes;
        if (self.body.items.len == 0) {
            self.body_read_off = 0;
            // Drained: hand the storage back rather than sitting on the peak
            // allocation until the stream ends.
            self.body.clearAndFree(allocator);
            self.releaseRetainedStorage();
        }
    }

    fn releaseQueuedBodyAccounting(self: *Stream) void {
        if (self.proxy_body_account) |*account| {
            const current = account.snapshot().current;
            if (current > 0) self.releaseQueuedBody(current);
        }
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
        /// The per-stream buffer policy pinned at connect time, and the source
        /// of the SETTINGS_INITIAL_WINDOW_SIZE this connection advertised.
        /// Pinned rather than read per request because the advertised window is
        /// a promise: a reload that lowered the hard limit under a peer already
        /// holding credit would abort a stream that never exceeded what it was
        /// granted. A reloaded policy therefore applies to connections opened
        /// afterwards, and every stream here is judged by what was advertised.
        buffer_limits: proxy_buffer_account.Limits,
        stream_recv_window: u31,

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
            buffer_limits: proxy_buffer_account.Limits,
        ) !*Self {
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);
            const now = nowMs();
            const stream_recv_window = proxy_buffer_account.streamReceiveWindow(buffer_limits);
            self.* = .{
                .allocator = allocator,
                .transport = transport,
                .transport_allocator = transport_allocator,
                .fd = fd,
                .deadline_ms = deadline_ms,
                .buffer_limits = buffer_limits,
                .stream_recv_window = stream_recv_window,
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
                .{ 0x4, @as(u32, stream_recv_window) },
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

        /// The proxy buffer policy this connection pinned when it was opened.
        ///
        /// Every per-stream decision for a stream on this connection must come
        /// from here rather than from the caller's config snapshot. A pooled
        /// connection outlives reloads, so a caller snapshot would judge one
        /// stream by two generations of policy at once: the queue by what the
        /// connection advertised, and anything the caller sized by whatever the
        /// config says now. On a raise that lets a stream own more than the
        /// hard limit it is documented to be measured against; on a shrink it
        /// refuses a stream that is still operating inside the window this
        /// connection granted it.
        pub fn proxyBufferLimits(self: *const Self) proxy_buffer_account.Limits {
            return self.buffer_limits;
        }

        /// Start a streaming request and return immediately after the request
        /// HEADERS and any initial `req.body` DATA have reached the wire. This
        /// is the entry point for streaming uploads: the caller can then send
        /// request-body DATA incrementally before waiting for response headers.
        pub fn openStreaming(self: *Self, req: Request) !*Stream {
            const stream = try self.beginStream(true);
            errdefer self.finishStreaming(stream);
            if (req.proxy_buffer_accounting) {
                // The connection's pinned policy, not a caller snapshot: the
                // stream is judged by exactly the window it advertised, less
                // whatever the caller's relay buffer will hold alongside the
                // queue (see `Request.proxy_relay_reserved_bytes`).
                var queue_limits = self.buffer_limits;
                queue_limits.per_stream_hard_limit -|= req.proxy_relay_reserved_bytes;
                stream.proxy_body_account = proxy_buffer_account.Account.init(.upstream_to_downstream, .stream, queue_limits);
                stream.proxy_buffer_observer = req.proxy_buffer_observer;
                stream.proxy_buffer_capacity = req.proxy_buffer_capacity;
            }
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
            // The reader can decode HEADERS and then reject DATA before this
            // worker ever writes the head downstream. Reporting success there
            // would commit the origin's status and force a truncation, when
            // nothing has reached the client yet and the caller can still
            // choose a clean pre-commitment status.
            const aborted_locally = stream.local_abort;
            self.state_mutex.unlock();

            if (aborted_locally) {
                if (stream_err) |e| return e;
            }
            if (status != null) return;
            if (stream_err) |e| return e;
            return error.Http2MissingStatus;
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

        /// Claim the commitment boundary for this stream's downstream response.
        /// Call immediately before writing the response head; it fails when the
        /// stream was already aborted for local buffer capacity, so a refusal
        /// that physically happened before the head reached the client is
        /// reported as one instead of becoming a truncated origin status.
        ///
        /// Once this returns, the reader knows the head is going out and later
        /// capacity failures are handled as post-commitment truncations.
        pub fn beginDownstreamCommit(self: *Self, stream: *Stream) error{BufferLimitExceeded}!void {
            self.state_mutex.lock();
            defer self.state_mutex.unlock();
            if (stream.abort_cause == .local_capacity) return error.BufferLimitExceeded;
            stream.downstream_state = .committing;
        }

        /// Why this stream aborted, if it did.
        pub fn abortCause(self: *Self, stream: *Stream) AbortCause {
            self.state_mutex.lock();
            defer self.state_mutex.unlock();
            return stream.abort_cause;
        }

        /// The buffer policy this stream is being judged by — the connection's
        /// pinned policy when accounting is on. Locked because the reader
        /// mutates the account it lives in.
        pub fn streamBufferLimits(self: *Self, stream: *Stream) ?proxy_buffer_account.Limits {
            self.state_mutex.lock();
            defer self.state_mutex.unlock();
            const account = stream.proxy_body_account orelse return null;
            return account.limits;
        }

        /// Copy the next chunk of a streaming response body into `out`,
        /// blocking (deadline-bounded) until data, end-of-stream, or an error.
        /// Returns 0 at end of stream. The caller must acknowledge each
        /// non-zero read with `acknowledgeStreamingBody` only after the copied
        /// bytes have been durably consumed downstream.
        pub fn readStreamingBody(self: *Self, stream: *Stream, out: []u8) !usize {
            self.state_mutex.lock();
            while (true) {
                const avail = stream.body.items.len - stream.body_read_off;
                if (avail > 0) {
                    const n = @min(avail, out.len);
                    @memcpy(out[0..n], stream.body.items[stream.body_read_off..][0..n]);
                    stream.body_read_off += n;
                    self.state_mutex.unlock();
                    return n;
                }
                if (stream.err) |e| {
                    self.state_mutex.unlock();
                    return e;
                }
                // END_STREAM makes this response complete even if the peer
                // closes the shared connection immediately afterward.
                if (stream.done) {
                    self.state_mutex.unlock();
                    return 0;
                }
                if (self.conn_err) |e| {
                    self.state_mutex.unlock();
                    return e;
                }
                stream.wait_deadline_ms = nowMs() + self.deadline_ms;
                stream.cond.wait(&self.state_mutex);
                stream.wait_deadline_ms = 0;
            }
        }

        /// Like `readStreamingBody`, but returns `Http2ReadWaitElapsed` after
        /// a short caller-selected interval rather than waiting indefinitely
        /// on the stream condition. Long-lived response relays use this to
        /// observe reload/shutdown drain deadlines while an upstream is quiet.
        ///
        /// This deliberately does not shorten the actor's connection read
        /// deadline. A quiet stream is polled under its own lock while the
        /// reader continues serving every other stream, so one lifecycle drain
        /// never turns into a connection-wide `Http2Timeout`.
        pub fn readStreamingBodyInterruptible(self: *Self, stream: *Stream, out: []u8, wait_ms: u32) !usize {
            const deadline_ms = nowMs() + @as(u64, wait_ms);
            while (true) {
                self.state_mutex.lock();
                const avail = stream.body.items.len - stream.body_read_off;
                if (avail > 0) {
                    const n = @min(avail, out.len);
                    @memcpy(out[0..n], stream.body.items[stream.body_read_off..][0..n]);
                    stream.body_read_off += n;
                    self.state_mutex.unlock();
                    return n;
                }
                if (stream.err) |e| {
                    self.state_mutex.unlock();
                    return e;
                }
                if (stream.done) {
                    self.state_mutex.unlock();
                    return 0;
                }
                if (self.conn_err) |e| {
                    self.state_mutex.unlock();
                    return e;
                }
                self.state_mutex.unlock();

                const now_ms = nowMs();
                if (now_ms >= deadline_ms) return error.Http2ReadWaitElapsed;
                // Keep the granularity small enough for lifecycle drains while
                // avoiding a busy wait for a quiet SSE stream. The reader
                // signals the regular blocking API; this polling variant must
                // also wake for a deadline that is external to the H2 actor.
                const sleep_ms = @min(@as(u64, 5), deadline_ms - now_ms);
                compat.sleepNs(@as(u64, sleep_ms) * std.time.ns_per_ms);
            }
        }

        /// Acknowledge bytes returned by `readStreamingBody` after the caller
        /// has written them downstream. This is the ownership transfer point:
        /// accounting is released, consumed queue prefixes are compacted, and
        /// stream credit is replenished only after downstream consumption.
        pub fn acknowledgeStreamingBody(self: *Self, stream: *Stream, bytes: usize) void {
            if (bytes == 0) return;
            self.state_mutex.lock();
            const was_above_high = stream.aboveHighWatermark();
            stream.releaseQueuedBody(bytes);
            stream.compactAcknowledgedBody(self.allocator, bytes);
            const still_above_high = stream.aboveHighWatermark();

            // Hysteresis (#140): while the queue sits above its high watermark
            // the peer gets no new credit, so it stops sending instead of
            // refilling whatever the consumer just drained. Credit accumulates
            // and is released as a single WINDOW_UPDATE when the queue falls
            // below the low watermark.
            stream.pending_window_credit += bytes;
            var credit: usize = 0;
            if (!still_above_high) {
                credit = stream.pending_window_credit;
                stream.pending_window_credit = 0;
                stream.recv_window += @as(i64, @intCast(credit));
            }
            const resumed = was_above_high and !still_above_high;
            const observer = stream.proxy_buffer_observer;
            const replenish = !stream.done and credit > 0;
            const id = stream.id;
            self.state_mutex.unlock();

            // The pause is recorded where credit stops (`enqueueBody`); this is
            // where it starts flowing again.
            if (resumed) {
                if (observer) |obs| obs.recordReadResume(.upstream);
            }
            if (replenish) {
                const inc = windowIncrement(credit);
                self.writeControl(.window_update, 0, id, &inc);
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
            // `rst_sent` means the reader already cancelled this stream when it
            // hit a hard limit; a second RST would be redundant.
            const need_rst = stream.wire_opened and !stream.rst_sent and
                (stream.err == null or stream.local_abort) and !stream.done and self.conn_err == null;
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
                .recv_window = if (streaming) @as(i64, self.stream_recv_window) else 0,
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
            //
            // Publish `wire_opened` under `state_mutex` *before* the write: a
            // fast origin can respond the instant the HEADERS syscall lands, so
            // the reader may need to reset this stream while this thread is
            // still inside the write. Setting it afterwards left the reader
            // racing a plain store and potentially skipping a reset for a
            // stream the peer had already seen. A failed write poisons
            // `conn_err`, which keeps `finishStreaming` from emitting a reset
            // for a request that never reached the peer.
            {
                self.state_mutex.lock();
                stream.wire_opened = true;
                self.state_mutex.unlock();
            }
            self.write_mutex.lock();
            const write_result = self.writeHeaderBlockLocked(stream.id, block, end_stream);
            self.write_mutex.unlock();
            if (write_result) |_| {} else |err| return self.markWriteFailure(err);
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
            var replenish_stream = false;
            var flow_violation = false;
            // RST_STREAM error code to emit for this stream once the lock is
            // dropped, if any (RFC 9113 §7).
            var reset_code: ?u32 = null;
            if (maybe_stream) |s| {
                var deliver = fr.payload.len > 0;
                // A stream we already gave up on is discard-only. Without this,
                // later DATA could reserve again once another stream drained
                // capacity free, re-queue bytes behind an error the consumer
                // has not observed yet, and re-count the limit event on every
                // frame while the worker is blocked on a slow downstream write.
                if (s.local_abort or s.err != null) deliver = false;
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
                        // Tell the peer to stop. Without this the origin keeps
                        // sending on a stream we have already failed — the
                        // connection window is replenished per frame, so
                        // nothing else would slow it down — until the worker
                        // eventually finishes the stream. `finishStreaming`
                        // will not cover this either: its predicate skips
                        // streams carrying a non-local error.
                        if (!s.rst_sent and s.wire_opened) {
                            s.rst_sent = true;
                            reset_code = RST_FLOW_CONTROL_ERROR;
                        }
                        flow_violation = true;
                        deliver = false;
                    }
                } else if (deliver) {
                    replenish_stream = true;
                }
                if (deliver) {
                    s.enqueueBody(self.allocator, fr.payload) catch |err| switch (err) {
                        // Local capacity is exhausted at some scope. Make the
                        // stream terminal here and now: reset it upstream so
                        // the origin stops sending, and leave it discard-only
                        // for any DATA already in flight.
                        error.BufferLimitExceeded => {
                            if (s.err == null) s.err = err;
                            s.local_abort = true;
                            s.abort_cause = .local_capacity;
                            if (!s.rst_sent and s.wire_opened) {
                                s.rst_sent = true;
                                reset_code = RST_CANCEL;
                            }
                            deliver = false;
                        },
                        else => {
                            self.state_mutex.unlock();
                            return err;
                        },
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
            if (reset_code) |code| {
                const payload = rstStreamPayload(code);
                self.writeControl(.rst_stream, 0, fr.stream_id, &payload);
            }

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
                // A connection failure cannot retroactively invalidate a
                // response whose END_STREAM was already processed.
                if (!sp.*.done and sp.*.err == null) sp.*.err = e;
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
        conn: *upstream_tls.UpstreamTlsConn,
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
    /// Origin-scope proxy buffer reservations (#140). Shared by every stream on
    /// every connection to this origin, so the origin's queued response bytes
    /// are bounded no matter how many slow streams it fans out to. Lives as
    /// long as the entry, which outlives every reader holding a pointer to it.
    buffer: proxy_buffer_account.Aggregate = proxy_buffer_account.Aggregate.init(.origin, 0),
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
    /// Bytes this origin's streams currently hold, by direction. Response
    /// queues and request-direction upload relay buffers are enforced against
    /// the *same* per-origin limit (#140), so reporting only responses would
    /// let the gauge read zero while the limit was being enforced against
    /// uploads.
    buffered_bytes: [2]usize,
    buffer_limit_exceeded_total: [2]u64,

    pub fn bufferedBytes(self: *const H2OriginSnapshot, direction: proxy_buffer_account.Direction) usize {
        return self.buffered_bytes[@intFromEnum(direction)];
    }

    pub fn bufferLimitExceeded(self: *const H2OriginSnapshot, direction: proxy_buffer_account.Direction) u64 {
        return self.buffer_limit_exceeded_total[@intFromEnum(direction)];
    }
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
    h1: *upstream_tls.UpstreamTlsConn,
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
        /// Proxy buffer policy for connections this pool opens (#140). The
        /// per-stream high watermark becomes each connection's advertised
        /// SETTINGS_INITIAL_WINDOW_SIZE; the aggregate hard limits are applied
        /// to the per-origin accounts. Update through
        /// `H2ConnPool.setProxyBufferLimits`, never by writing this field, so
        /// existing origins pick the change up too.
        proxy_buffer_limits: proxy_buffer_account.Limits = proxy_buffer_account.Limits.defaults(),
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
            // A new origin starts under the policy in force right now, not the
            // aggregate type's unlimited default.
            counters.buffer.setHardLimit(self.config.proxy_buffer_limits.per_origin_hard_limit);
            gop.key_ptr.* = try self.allocator.dupe(u8, key);
            gop.value_ptr.* = counters;
        }
        return gop.value_ptr.*;
    }

    /// The origin-scope buffer aggregate for `key`. Read-only with respect to
    /// policy: the limit comes from `config.proxy_buffer_limits`, which only
    /// `setProxyBufferLimits` writes. A request must never push its own config
    /// snapshot into shared state — a request that started before a reload
    /// would otherwise land here afterwards and restore the superseded limit.
    /// The returned pointer is stable for the pool's lifetime.
    pub fn originBufferAccount(self: *H2ConnPool, key: []const u8) !*proxy_buffer_account.Aggregate {
        const counters = try self.originCounters(key);
        return &counters.buffer;
    }

    /// Apply a reloaded proxy buffer policy. Aggregate hard limits take effect
    /// immediately for every origin, including ones already carrying
    /// reservations; the per-stream policy (and the receive window derived from
    /// it) applies to connections opened after this call, because
    /// SETTINGS_INITIAL_WINDOW_SIZE is negotiated once per connection and
    /// existing peers already hold credit under the previous advertisement.
    pub fn currentProxyBufferLimits(self: *H2ConnPool) proxy_buffer_account.Limits {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.config.proxy_buffer_limits;
    }

    pub fn setProxyBufferLimits(self: *H2ConnPool, limits: proxy_buffer_account.Limits) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.config.proxy_buffer_limits = limits;
        var it = self.origin_counters.valueIterator();
        while (it.next()) |counters| {
            counters.*.buffer.setHardLimit(limits.per_origin_hard_limit);
        }
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
        tls_options: ?upstream_tls.UpstreamTlsOptions,
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
            const tls_ptr = self.allocator.create(upstream_tls.UpstreamTlsConn) catch {
                self.allocator.destroy(transport);
                _ = std.c.close(fd);
                return error.OutOfMemory;
            };
            const opts = base_opts;
            tls_ptr.* = upstream_tls.UpstreamTlsConn.connect(fd, host, opts) catch |e| {
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

        // Snapshot the policy under the lock: a reload can rewrite it, and this
        // connection pins whatever it advertises for its whole life.
        const buffer_limits = self.currentProxyBufferLimits();
        const conn = PooledH2Conn.init(self.allocator, transport, fd, deadline_ms, self.allocator, &counters.stream_resets_total, &counters.goaway_total, buffer_limits) catch |e| {
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
        if (self.conns.get(key)) |existing| {
            if (existing == conn) {
                // Remove first, then free the key the map owned. Freeing it
                // while the entry is still present left `remove` probing a
                // dangling key: on a hash collision it compares stored key
                // bytes, so it could read freed memory and fail to remove the
                // entry at all — leaving a map entry whose key was already
                // freed, which `deinit` would then free a second time and
                // whose connection it would release after teardown. Matches
                // the fetch-then-free order `acquire` and `reapIdle` use.
                if (self.conns.fetchRemove(key)) |old| {
                    self.allocator.free(old.key);
                    removed = true;
                }
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
                .buffered_bytes = .{
                    e.value_ptr.*.buffer.currentBytes(.downstream_to_upstream),
                    e.value_ptr.*.buffer.currentBytes(.upstream_to_downstream),
                },
                .buffer_limit_exceeded_total = .{
                    e.value_ptr.*.buffer.limitExceededEvents(.downstream_to_upstream),
                    e.value_ptr.*.buffer.limitExceededEvents(.upstream_to_downstream),
                },
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

const TestProxyBufferObserver = struct {
    current: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    limit_exceeded: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    origin_limit_exceeded: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    global_limit_exceeded: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    read_pauses: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    read_resumes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Mirrors what the `scope="global"` gauge would report: retained
    /// allocation, which moves on a different schedule from `current`.
    retained: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    fn observer(self: *TestProxyBufferObserver) proxy_buffer_account.Observer {
        return .{
            .context = self,
            .recordReservationFn = record,
            .releaseReservationFn = release,
            .recordAggregateLimitExceededFn = recordAggregateLimitExceeded,
            .recordReadPauseFn = recordReadPause,
            .recordReadResumeFn = recordReadResume,
            .recordRetainedBytesFn = recordRetained,
            .releaseRetainedBytesFn = releaseRetained,
        };
    }

    fn recordRetained(context: *anyopaque, _: proxy_buffer_account.Direction, bytes: usize) void {
        const self: *TestProxyBufferObserver = @ptrCast(@alignCast(context));
        _ = self.retained.fetchAdd(bytes, .monotonic);
    }

    fn releaseRetained(context: *anyopaque, _: proxy_buffer_account.Direction, bytes: usize) void {
        const self: *TestProxyBufferObserver = @ptrCast(@alignCast(context));
        _ = self.retained.fetchSub(bytes, .monotonic);
    }

    fn recordReadPause(context: *anyopaque, _: proxy_buffer_account.Side) void {
        const self: *TestProxyBufferObserver = @ptrCast(@alignCast(context));
        _ = self.read_pauses.fetchAdd(1, .monotonic);
    }

    fn recordReadResume(context: *anyopaque, _: proxy_buffer_account.Side) void {
        const self: *TestProxyBufferObserver = @ptrCast(@alignCast(context));
        _ = self.read_resumes.fetchAdd(1, .monotonic);
    }

    fn recordAggregateLimitExceeded(
        context: *anyopaque,
        _: proxy_buffer_account.Direction,
        scope: proxy_buffer_account.Scope,
    ) void {
        const self: *TestProxyBufferObserver = @ptrCast(@alignCast(context));
        switch (scope) {
            .origin => _ = self.origin_limit_exceeded.fetchAdd(1, .monotonic),
            .global => _ = self.global_limit_exceeded.fetchAdd(1, .monotonic),
            else => {},
        }
    }

    fn record(context: *anyopaque, _: proxy_buffer_account.Direction, bytes: usize, _: bool, limit_exceeded: bool) void {
        const self: *TestProxyBufferObserver = @ptrCast(@alignCast(context));
        if (bytes > 0) _ = self.current.fetchAdd(bytes, .monotonic);
        if (limit_exceeded) _ = self.limit_exceeded.fetchAdd(1, .monotonic);
    }

    fn release(context: *anyopaque, _: proxy_buffer_account.Direction, bytes: usize) void {
        const self: *TestProxyBufferObserver = @ptrCast(@alignCast(context));
        if (bytes > 0) _ = self.current.fetchSub(bytes, .monotonic);
    }
};

/// A per-stream policy whose advertised receive window is exactly `window`,
/// with the low watermark half way down so the pause/resume band is testable.
/// `hard == high` because the window already caps what a compliant peer can
/// queue: anything beyond it is a flow-control violation, not a buffer overrun.
fn windowLimits(window: usize) proxy_buffer_account.Limits {
    return .{
        .per_stream_low_watermark = @max(1, window / 2),
        .per_stream_high_watermark = window,
        .per_stream_hard_limit = window,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    };
}

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
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 2000, null, null, null, windowLimits(DEFAULT_STREAM_RECV_WINDOW));

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

test "per-origin buffer snapshot reports the request direction, not only responses" {
    var pool = H2ConnPool.init(testing.allocator, .{});
    defer pool.deinit();

    const key = "h2:origin-uploads:443";
    const account = try pool.originBufferAccount(key);
    account.setHardLimit(4096);

    // An upload relay holding this origin's buffer capacity, with no response
    // queue anywhere. Reporting only `upstream_to_downstream` made this read as
    // zero while the same limit was actively bounding the upload (#140).
    try account.reserve(.downstream_to_upstream, 3072);
    try testing.expectError(
        error.BufferLimitExceeded,
        account.reserve(.downstream_to_upstream, 2048),
    );

    const snaps = try pool.snapshotOrigins(testing.allocator);
    defer freeH2OriginSnapshots(testing.allocator, snaps);
    try testing.expectEqual(@as(usize, 1), snaps.len);
    try testing.expectEqualStrings(key, snaps[0].origin);
    try testing.expectEqual(@as(usize, 3072), snaps[0].bufferedBytes(.downstream_to_upstream));
    try testing.expectEqual(@as(u64, 1), snaps[0].bufferLimitExceeded(.downstream_to_upstream));
    // The response direction is accounted separately and stays untouched.
    try testing.expectEqual(@as(usize, 0), snaps[0].bufferedBytes(.upstream_to_downstream));
    try testing.expectEqual(@as(u64, 0), snaps[0].bufferLimitExceeded(.upstream_to_downstream));

    account.release(.downstream_to_upstream, 3072);
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

test "reloaded proxy buffer limits reach existing origins but not open connections" {
    const before = proxy_buffer_account.Limits{
        .per_stream_low_watermark = 32 * 1024,
        .per_stream_high_watermark = 64 * 1024,
        .per_stream_hard_limit = 64 * 1024,
        .per_origin_hard_limit = 256 * 1024,
        .global_hard_limit = 0,
    };
    const after = proxy_buffer_account.Limits{
        .per_stream_low_watermark = 8 * 1024,
        .per_stream_high_watermark = 16 * 1024,
        .per_stream_hard_limit = 16 * 1024,
        .per_origin_hard_limit = 32 * 1024,
        .global_hard_limit = 0,
    };
    try before.validate();
    try after.validate();

    var pool = H2ConnPool.init(testing.allocator, .{ .proxy_buffer_limits = before });
    defer pool.deinit();

    const existing = try pool.originBufferAccount("h2:origin-a:443");
    try testing.expectEqual(before.per_origin_hard_limit, existing.hardLimit());
    // Reserve against the pre-reload limit so the reload lands on a scope that
    // is already carrying bytes.
    try existing.reserve(.upstream_to_downstream, 24 * 1024);

    pool.setProxyBufferLimits(after);

    // Aggregate limits change immediately, in place: the stable pointer the
    // readers hold now enforces the reloaded cap.
    try testing.expectEqual(after.per_origin_hard_limit, existing.hardLimit());
    try testing.expectEqual(@as(usize, 24 * 1024), existing.currentBytes(.upstream_to_downstream));
    try testing.expectError(
        error.BufferLimitExceeded,
        existing.reserve(.upstream_to_downstream, 16 * 1024),
    );
    existing.release(.upstream_to_downstream, 24 * 1024);

    // An origin first seen after the reload starts under the new policy, not
    // the aggregate type's unlimited default.
    const fresh = try pool.originBufferAccount("h2:origin-b:443");
    try testing.expectEqual(after.per_origin_hard_limit, fresh.hardLimit());

    // Connections opened from here on advertise the reloaded window.
    try testing.expectEqual(after, pool.currentProxyBufferLimits());
}

test "an open connection keeps the per-stream policy it advertised" {
    // SETTINGS_INITIAL_WINDOW_SIZE is negotiated once, so a connection must
    // judge its streams by what it granted them. A stream therefore takes its
    // policy from the connection, and no caller can supply a different one.
    const fds = try makeSocketpair();
    const server = try std.Thread.spawn(.{}, cannedSingleDataStreamingServer, .{ fds[1], "payload", true });

    const pinned = windowLimits(64 * 1024);
    var transport = PlainTransport{ .fd = fds[0] };
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 3000, null, null, null, pinned);
    try testing.expectEqual(@as(u31, 64 * 1024), conn.stream_recv_window);

    const stream = try conn.requestStreaming(.{
        .method = "GET",
        .authority = "pinned.test",
        .path = "/",
        .proxy_buffer_accounting = true,
    });
    try testing.expectEqual(pinned, conn.streamBufferLimits(stream).?);
    // Deliberately no assertion on `stream.recv_window` here: the reader
    // decrements it as response DATA lands, so any value read from this thread
    // is a race with the origin. The window's actual size is pinned down
    // deterministically by "configured per-stream window replaces the default
    // streaming receive window", which cuts the peer off at exactly the
    // advertised byte count.

    conn.finishStreaming(stream);
    conn.deinit();
    server.join();
    _ = std.c.close(fds[1]);
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
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 2000, null, &rst, &goaway, windowLimits(DEFAULT_STREAM_RECV_WINDOW));

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
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 2000, null, &rst, &goaway, windowLimits(DEFAULT_STREAM_RECV_WINDOW));

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
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 3000, null, null, null, windowLimits(DEFAULT_STREAM_RECV_WINDOW));

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
        conn.acknowledgeStreamingBody(stream, n);
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

fn cannedSingleDataStreamingServer(peer_fd: std.posix.fd_t, body: []const u8, end_stream: bool) void {
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
    }) catch return;
    defer a.free(block);
    frame.writeFrame(&srv, .headers, frame.Flags.END_HEADERS, req_stream, block) catch return;
    frame.writeFrame(&srv, .data, if (end_stream) frame.Flags.END_STREAM else 0, req_stream, body) catch return;

    var scratch: [1]u8 = undefined;
    _ = srv.read(scratch[0..]) catch {};
}

test "streaming body accounting releases only after consumer acknowledgement and compacts queue" {
    const fds = try makeSocketpair();
    const server = try std.Thread.spawn(.{}, cannedSingleDataStreamingServer, .{ fds[1], "payload", false });

    var observer = TestProxyBufferObserver{};
    var transport = PlainTransport{ .fd = fds[0] };
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 3000, null, null, null, windowLimits(DEFAULT_STREAM_RECV_WINDOW));

    const stream = try conn.requestStreaming(.{
        .method = "GET",
        .authority = "account.test",
        .path = "/",
        .proxy_buffer_accounting = true,
        .proxy_buffer_observer = observer.observer(),
    });
    var buf: [16]u8 = undefined;
    const n = try conn.readStreamingBody(stream, buf[0..]);
    try testing.expectEqualStrings("payload", buf[0..n]);
    try testing.expectEqual(@as(usize, 7), observer.current.load(.monotonic));
    try testing.expectEqual(@as(usize, 7), stream.body.items.len);
    try testing.expectEqual(@as(usize, 7), stream.body_read_off);

    conn.acknowledgeStreamingBody(stream, n);
    try testing.expectEqual(@as(usize, 0), observer.current.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), stream.body.items.len);
    try testing.expectEqual(@as(usize, 0), stream.body_read_off);

    conn.finishStreaming(stream);
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
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 3000, null, null, null, windowLimits(DEFAULT_STREAM_RECV_WINDOW));

    const stream = try conn.requestStreaming(.{ .method = "GET", .authority = "trailer.test", .path = "/" });
    try testing.expectEqual(@as(u16, 200), stream.status.?);

    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(testing.allocator);
    var buf: [64]u8 = undefined;
    while (true) {
        const n = try conn.readStreamingBody(stream, buf[0..]);
        if (n == 0) break;
        try got.appendSlice(testing.allocator, buf[0..n]);
        conn.acknowledgeStreamingBody(stream, n);
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

/// What the flow-violation server observed coming back from the client.
const FlowViolationObservation = struct {
    /// Set once the client's PING ACK arrives, proving its reader has processed
    /// every frame the server sent — including the over-window one.
    saw_ack: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    rst_stream_id: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    rst_code: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
};

/// Canned server that violates flow control: sends `window` bytes of DATA
/// (filling the advertised stream window exactly) plus one more frame beyond it
/// without waiting for replenishment, then a PING whose ACK proves the client's
/// reader has processed every prior frame. `window` must be a multiple of
/// `DEFAULT_MAX_FRAME`. Any RST_STREAM the client sends before that ACK is
/// recorded, which is how the overrun reset is asserted.
fn cannedFlowViolationServer(peer_fd: std.posix.fd_t, window: usize, obs: *FlowViolationObservation) void {
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
    while (sent < window) : (sent += chunk.len) {
        frame.writeFrame(&srv, .data, 0, req_stream, chunk[0..]) catch return;
    }
    // One frame past the advertised window: a flow-control violation.
    frame.writeFrame(&srv, .data, 0, req_stream, chunk[0..]) catch return;

    const ping_payload = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    frame.writeFrame(&srv, .ping, 0, 0, ping_payload[0..]) catch return;
    while (true) {
        var fr = readFrameBounded(&srv, peer_fd, a, 5000) catch return;
        const is_ack = fr.typ == .ping and (fr.flags & frame.Flags.ACK) != 0;
        if (fr.typ == .rst_stream and fr.payload.len >= 4) {
            obs.rst_code.store(std.mem.readInt(u32, fr.payload[0..4], .big), .release);
            obs.rst_stream_id.store(@intCast(fr.stream_id), .release);
        }
        frame.deinitFrame(a, &fr);
        if (is_ack) {
            obs.saw_ack.store(true, .release);
            return;
        }
    }
}

test "streaming stream fails when the peer overruns the advertised window" {
    const fds = try makeSocketpair();
    var obs = FlowViolationObservation{};
    const server = try std.Thread.spawn(.{}, cannedFlowViolationServer, .{ fds[1], DEFAULT_STREAM_RECV_WINDOW, &obs });

    var transport = PlainTransport{ .fd = fds[0] };
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 5000, null, null, null, windowLimits(DEFAULT_STREAM_RECV_WINDOW));

    const stream = try conn.requestStreaming(.{ .method = "GET", .authority = "flood.test", .path = "/" });

    // Wait (bounded spin) until the reader has processed every frame the
    // server sent — including the over-window one — so the violation is
    // recorded before we start draining (draining replenishes the window).
    var spins: usize = 0;
    while (!obs.saw_ack.load(.acquire) and spins < 100_000_000) : (spins += 1) std.Thread.yield() catch {};
    try testing.expect(obs.saw_ack.load(.acquire));

    // The in-window megabyte drains fine; the overrun then surfaces as a
    // flow-control error rather than unbounded buffering.
    var total: usize = 0;
    var buf: [32 * 1024]u8 = undefined;
    const read_err = while (true) {
        const n = conn.readStreamingBody(stream, buf[0..]) catch |e| break e;
        try testing.expect(n != 0); // stream must not end cleanly
        total += n;
        conn.acknowledgeStreamingBody(stream, n);
    };
    try testing.expectEqual(@as(usize, DEFAULT_STREAM_RECV_WINDOW), total);
    try testing.expectError(error.Http2FlowControlError, @as(anyerror!void, read_err));

    // The peer is actually told to stop. Without a reset it could keep sending
    // on a stream we have already failed — the connection window is replenished
    // per frame, so nothing else would slow it down.
    try testing.expectEqual(@as(u32, stream.id), obs.rst_stream_id.load(.acquire));
    try testing.expectEqual(RST_FLOW_CONTROL_ERROR, obs.rst_code.load(.acquire));

    conn.finishStreaming(stream);
    conn.deinit();
    server.join();
    _ = std.c.close(fds[1]);
}

test "configured per-stream window replaces the default streaming receive window" {
    // 64 KiB high watermark: the peer may park exactly that much unconsumed
    // response body per stream, a sixteenth of the built-in default.
    const limits = windowLimits(4 * DEFAULT_MAX_FRAME);
    try limits.validate();
    const window = proxy_buffer_account.streamReceiveWindow(limits);
    try testing.expectEqual(@as(u31, 4 * DEFAULT_MAX_FRAME), window);

    const fds = try makeSocketpair();
    var obs = FlowViolationObservation{};
    const server = try std.Thread.spawn(.{}, cannedFlowViolationServer, .{ fds[1], @as(usize, window), &obs });

    var transport = PlainTransport{ .fd = fds[0] };
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 5000, null, null, null, limits);

    const stream = try conn.requestStreaming(.{ .method = "GET", .authority = "window.test", .path = "/" });

    var spins: usize = 0;
    while (!obs.saw_ack.load(.acquire) and spins < 100_000_000) : (spins += 1) std.Thread.yield() catch {};
    try testing.expect(obs.saw_ack.load(.acquire));

    var total: usize = 0;
    var buf: [8 * 1024]u8 = undefined;
    const read_err = while (true) {
        const n = conn.readStreamingBody(stream, buf[0..]) catch |e| break e;
        try testing.expect(n != 0);
        total += n;
        conn.acknowledgeStreamingBody(stream, n);
    };
    // Exactly the configured window was accepted — not the 1 MiB default.
    try testing.expectEqual(@as(usize, window), total);
    try testing.expectError(error.Http2FlowControlError, @as(anyerror!void, read_err));

    conn.finishStreaming(stream);
    conn.deinit();
    server.join();
    _ = std.c.close(fds[1]);
}

test "streaming response reservations clear every aggregate scope after teardown" {
    const fds = try makeSocketpair();
    const server = try std.Thread.spawn(.{}, cannedSingleDataStreamingServer, .{ fds[1], "payload", false });

    var observer = TestProxyBufferObserver{};
    var origin = proxy_buffer_account.Aggregate.init(.origin, 1024);
    var global = proxy_buffer_account.Aggregate.init(.global, 4096);
    var transport = PlainTransport{ .fd = fds[0] };
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 3000, null, null, null, windowLimits(DEFAULT_STREAM_RECV_WINDOW));

    const stream = try conn.requestStreaming(.{
        .method = "GET",
        .authority = "aggregate.test",
        .path = "/",
        .proxy_buffer_accounting = true,
        .proxy_buffer_observer = observer.observer(),
        .proxy_buffer_capacity = .{ .origin = &origin, .global = &global },
    });
    var buf: [16]u8 = undefined;
    const n = try conn.readStreamingBody(stream, buf[0..]);
    try testing.expectEqualStrings("payload", buf[0..n]);
    // Queued bytes are held at every scope until the consumer acknowledges.
    try testing.expectEqual(@as(usize, 7), origin.currentBytes(.upstream_to_downstream));
    try testing.expectEqual(@as(usize, 7), global.currentBytes(.upstream_to_downstream));

    conn.acknowledgeStreamingBody(stream, n);
    try testing.expectEqual(@as(usize, 0), origin.currentBytes(.upstream_to_downstream));
    try testing.expectEqual(@as(usize, 0), global.currentBytes(.upstream_to_downstream));

    conn.finishStreaming(stream);
    conn.deinit();
    server.join();
    _ = std.c.close(fds[1]);

    try testing.expectEqual(@as(usize, 0), observer.current.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), observer.origin_limit_exceeded.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), observer.global_limit_exceeded.load(.monotonic));
}

/// Canned server for the concurrent-stream aggregate case: answers two
/// streams, completes the first with `first_bytes` of DATA carrying
/// END_STREAM, then sends `second_bytes` on the second. Both bursts stay
/// inside each stream's own advertised window, so anything the client refuses
/// it refuses on aggregate grounds.
///
/// The first stream is completed rather than left open on purpose: a
/// wire-open stream is legitimately reset by `finishStreaming`, and an earlier
/// revision of this test recorded that unrelated CANCEL as "the" reset and
/// failed on CI. The server records *every* reset id so the assertion can be
/// about which stream was reset for the capacity event, not about ordering.
/// Why a canned server thread stopped.
///
/// These helpers used to `catch return` on every read timeout and write error,
/// which made "the client never sent what we were waiting for"
/// indistinguishable from "the socket died under us". On a loaded CI runner
/// that turned a scheduling hiccup into a bare `expected 3, found 0` at the end
/// of a test, with nothing pointing at the cause (#140 follow-up). Publishing
/// the reason lets a test assert on it and fail with the real story.
const CannedServerStatus = enum(u32) {
    /// Still running, or stopped without reaching any labelled point — the
    /// initial value, never stored deliberately.
    running,
    /// Reached the terminal state the test wanted: an RST_STREAM arrived.
    saw_rst,
    preface_read_failed,
    settings_write_failed,
    headers_read_failed,
    response_write_failed,
    body_write_failed,
    /// Gave up waiting for the client's RST_STREAM. This is the one that
    /// used to masquerade as "the client never reset the stream".
    rst_read_failed,
};

/// A canned server's published outcome, shared with the test thread.
///
/// Everything here is written by the server thread and read by the test, so it
/// is all atomic; `rst_stream_id` is published *before* the terminal status, so
/// a test that observes `.saw_rst` is guaranteed to see the id with it.
const CannedServerState = struct {
    status: std.atomic.Value(u32) = std.atomic.Value(u32).init(@intFromEnum(CannedServerStatus.running)),
    rst_stream_id: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    fn finish(self: *CannedServerState, status: CannedServerStatus) void {
        self.status.store(@intFromEnum(status), .release);
    }

    fn noteRst(self: *CannedServerState, id: u32) void {
        self.rst_stream_id.store(id, .monotonic);
        self.finish(.saw_rst);
    }

    fn status_(self: *const CannedServerState) CannedServerStatus {
        return @enumFromInt(self.status.load(.acquire));
    }

    /// Block until the server publishes a terminal status.
    ///
    /// This is the synchronisation point these tests were missing. The client's
    /// capacity RST is written by the *reader thread*, after it has released
    /// the state lock that publishes `abort_cause` — so a test that tears the
    /// connection down as soon as it can see the cause races that write.
    /// `H2Conn.deinit` shuts the socket down (`SHUT_RDWR`) before joining the
    /// reader, and `writeControl` swallows the resulting write error, so losing
    /// that race means the RST never reaches the peer at all.
    ///
    /// Bounded so a genuinely stuck test still fails rather than hanging, but
    /// the bound is not the thing being waited on: it is generous, and the wait
    /// returns as soon as the server publishes.
    fn waitForTerminal(self: *const CannedServerState) CannedServerStatus {
        const deadline = nowMs() + canned_server_wait_timeout_ms;
        while (true) {
            const current = self.status_();
            if (current != .running) return current;
            if (nowMs() >= deadline) return .running;
            std.Thread.yield() catch {};
        }
    }

    /// `waitForTerminal` plus the assertion, so a failure names the status the
    /// server actually reached instead of showing up as a mismatched counter
    /// several lines later.
    fn expectTerminal(self: *const CannedServerState, want: CannedServerStatus) !void {
        const got = self.waitForTerminal();
        if (got != want) {
            std.debug.print("canned server ended as .{s}, expected .{s}\n", .{ @tagName(got), @tagName(want) });
            return error.TestUnexpectedResult;
        }
    }
};

/// Sends a response head then deliberately stays quiet. The client-side test
/// uses it to prove a lifecycle polling wake-up is stream-local: ending the
/// abandoned stream sends one RST_STREAM but leaves the pooled connection
/// healthy instead of converting quiet upstream time into a connection error.
fn cannedIdleStreamingServer(peer_fd: std.posix.fd_t, state: *CannedServerState) void {
    const a = std.heap.page_allocator;
    var srv = PlainTransport{ .fd = peer_fd };
    var preface: [PREFACE.len]u8 = undefined;
    readExact(&srv, peer_fd, preface[0..], canned_server_read_timeout_ms) catch return state.finish(.preface_read_failed);
    frame.writeSettings(a, &srv, &[_][2]u32{}) catch return state.finish(.settings_write_failed);

    var req_stream: u31 = 0;
    while (req_stream == 0) {
        var fr = readFrameBounded(&srv, peer_fd, a, canned_server_read_timeout_ms) catch return state.finish(.headers_read_failed);
        if (fr.typ == .headers) req_stream = fr.stream_id;
        frame.deinitFrame(a, &fr);
    }
    const block = hpack.encodeLiteralHeaderBlock(a, &[_]hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/event-stream" },
    }) catch return state.finish(.response_write_failed);
    defer a.free(block);
    frame.writeFrame(&srv, .headers, frame.Flags.END_HEADERS, req_stream, block) catch return state.finish(.response_write_failed);

    while (true) {
        var fr = readFrameBounded(&srv, peer_fd, a, canned_server_read_timeout_ms) catch return state.finish(.rst_read_failed);
        const is_rst = fr.typ == .rst_stream and fr.stream_id == req_stream;
        const id = fr.stream_id;
        frame.deinitFrame(a, &fr);
        if (is_rst) return state.noteRst(@intCast(id));
    }
}

test "interruptible streaming body waits leave a quiet H2 connection healthy" {
    const fds = try makeSocketpair();
    var server_state = CannedServerState{};
    const server = try std.Thread.spawn(.{}, cannedIdleStreamingServer, .{ fds[1], &server_state });

    var transport = PlainTransport{ .fd = fds[0] };
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 2_000, null, null, null, windowLimits(DEFAULT_STREAM_RECV_WINDOW));
    const stream = try conn.requestStreaming(.{ .method = "GET", .authority = "idle.test", .path = "/events" });
    var buf: [16]u8 = undefined;
    try testing.expectError(error.Http2ReadWaitElapsed, conn.readStreamingBodyInterruptible(stream, buf[0..], 10));
    try testing.expect(conn.healthy());

    const stream_id: u32 = stream.id;
    conn.finishStreaming(stream);
    try server_state.expectTerminal(.saw_rst);
    try testing.expect(conn.healthy());

    conn.deinit();
    server.join();
    _ = std.c.close(fds[1]);
    try testing.expectEqual(stream_id, server_state.rst_stream_id.load(.acquire));
}

/// Read budget for the canned server helpers below.
///
/// Deliberately generous: this bounds a *hung* test, not the expected latency,
/// and the expected latency on a loaded CI runner is not something a small
/// millisecond constant can predict — which is exactly how the previous 2–5 s
/// deadlines turned into flakes. Tests wait on published state rather than on
/// this clock, so a passing run never spends anywhere near it.
const canned_server_read_timeout_ms: u64 = 30_000;

/// How long a test waits for the server to publish a terminal status.
///
/// Deliberately *longer* than the server's own read budget: when something is
/// genuinely stuck, the server should reach its own labelled timeout first so
/// the test reports that cause (`.rst_read_failed`) rather than a bare "still
/// running". A `.running` result therefore means the server thread is wedged
/// somewhere with no label at all, which is itself the useful signal.
const canned_server_wait_timeout_ms: u64 = canned_server_read_timeout_ms + 5_000;

fn cannedTwoStreamServer(
    peer_fd: std.posix.fd_t,
    first_bytes: usize,
    second_bytes: usize,
    state: *CannedServerState,
) void {
    const a = std.heap.page_allocator;
    var srv = PlainTransport{ .fd = peer_fd };
    var preface: [PREFACE.len]u8 = undefined;
    readExact(&srv, peer_fd, preface[0..], canned_server_read_timeout_ms) catch return state.finish(.preface_read_failed);
    frame.writeSettings(a, &srv, &[_][2]u32{}) catch return state.finish(.settings_write_failed);

    const block = hpack.encodeLiteralHeaderBlock(a, &[_]hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
    }) catch return state.finish(.response_write_failed);
    defer a.free(block);

    // Answer each request as it arrives so the client can open the second
    // stream (its `requestStreaming` blocks on the response head).
    var ids: [2]u31 = .{ 0, 0 };
    var seen: usize = 0;
    while (seen < 2) {
        var fr = readFrameBounded(&srv, peer_fd, a, canned_server_read_timeout_ms) catch return state.finish(.headers_read_failed);
        const is_headers = fr.typ == .headers;
        const id = fr.stream_id;
        frame.deinitFrame(a, &fr);
        if (!is_headers) continue;
        ids[seen] = id;
        seen += 1;
        frame.writeFrame(&srv, .headers, frame.Flags.END_HEADERS, id, block) catch return state.finish(.response_write_failed);
    }

    const payload = [_]u8{'x'} ** 256;
    // END_STREAM: the healthy stream completes, so nothing later has cause to
    // reset it and any reset the client sends is the capacity one.
    frame.writeFrame(&srv, .data, frame.Flags.END_STREAM, ids[0], payload[0..first_bytes]) catch return state.finish(.body_write_failed);
    frame.writeFrame(&srv, .data, 0, ids[1], payload[0..second_bytes]) catch return state.finish(.body_write_failed);

    while (true) {
        var fr = readFrameBounded(&srv, peer_fd, a, canned_server_read_timeout_ms) catch return state.finish(.rst_read_failed);
        const is_rst = fr.typ == .rst_stream;
        const id = fr.stream_id;
        frame.deinitFrame(a, &fr);
        if (is_rst) return state.noteRst(@intCast(id));
    }
}

test "origin capacity bounds concurrent streams and refuses only the overflowing one" {
    // Each stream may hold 64 bytes, and so may the origin as a whole — a
    // valid production shape (`origin_hard >= per_stream_hard`). One slow
    // stream holding its full window therefore leaves the origin with no room
    // for a second, which is the concurrency multiplication the aggregate
    // limit exists to stop.
    const window: usize = 64;
    const limits = windowLimits(window);
    try limits.validate();

    const fds = try makeSocketpair();
    var server_state = CannedServerState{};
    const server = try std.Thread.spawn(.{}, cannedTwoStreamServer, .{ fds[1], window, 16, &server_state });

    var observer = TestProxyBufferObserver{};
    var origin = proxy_buffer_account.Aggregate.init(.origin, window);
    var global = proxy_buffer_account.Aggregate.init(.global, 1024);
    var transport = PlainTransport{ .fd = fds[0] };
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 3000, null, null, null, limits);

    const capacity = proxy_buffer_account.AggregateCapacity{ .origin = &origin, .global = &global };
    const slow = try conn.requestStreaming(.{
        .method = "GET",
        .authority = "aggregate-origin.test",
        .path = "/",
        .proxy_buffer_accounting = true,
        .proxy_buffer_observer = observer.observer(),
        .proxy_buffer_capacity = capacity,
    });
    // `openStreaming` rather than `requestStreaming` so the handle is owned on
    // every path: the refusal can surface from the head wait as well as from
    // the body read, and the error path of `requestStreaming` would have
    // finished the stream itself, leaving nothing to assert against.
    const refused = try conn.openStreaming(.{
        .method = "GET",
        .authority = "aggregate-origin.test",
        .path = "/",
        .proxy_buffer_accounting = true,
        .proxy_buffer_observer = observer.observer(),
        .proxy_buffer_capacity = capacity,
    });

    // The second stream is refused; the first is untouched and still usable.
    //
    // Wait for the reader to actually refuse before asserting. Otherwise the
    // test races it: the refusal legitimately surfaces from the head wait when
    // the reader gets there first and from the body read when it does not, and
    // an earlier revision that assumed the body-read ordering crashed on CI.
    var buf: [128]u8 = undefined;
    var spins: usize = 0;
    while (conn.abortCause(refused) != .local_capacity and spins < 100_000_000) : (spins += 1) {
        std.Thread.yield() catch {};
    }
    try testing.expectEqual(AbortCause.local_capacity, conn.abortCause(refused));
    // Every way the worker could learn about it reports the same thing, and
    // reports it as still pre-commitment.
    try testing.expectError(error.BufferLimitExceeded, conn.waitStreamingResponseHead(refused));
    try testing.expectError(error.BufferLimitExceeded, conn.readStreamingBody(refused, buf[0..]));
    // The refusal landed before any head relay, so claiming the commitment
    // boundary must fail — this is what turns the race into a pre-commit 503
    // instead of a committed origin status followed by a truncation.
    try testing.expectError(error.BufferLimitExceeded, conn.beginDownstreamCommit(refused));
    // The healthy stream can still commit.
    try conn.beginDownstreamCommit(slow);
    try testing.expect(origin.currentBytes(.upstream_to_downstream) <= window);

    const n = try conn.readStreamingBody(slow, buf[0..]);
    try testing.expectEqual(window, n);
    conn.acknowledgeStreamingBody(slow, n);
    // The healthy stream reaches a clean end of stream rather than being
    // collateral damage of the other stream's capacity abort.
    try testing.expectEqual(@as(usize, 0), try conn.readStreamingBody(slow, buf[0..]));
    try testing.expectEqual(AbortCause.none, conn.abortCause(slow));

    const refused_id: u32 = refused.id;
    // Synchronise on the server having *observed* the reset before tearing the
    // connection down. `abort_cause` is published under the state lock, but the
    // RST is written after that lock is released, and `conn.deinit()` shuts the
    // socket down before joining the reader — so going straight to teardown
    // here races the RST into `writeControl`'s swallowed write error and the
    // server sees nothing. See `CannedServerState.waitForTerminal`.
    try server_state.expectTerminal(.saw_rst);

    conn.finishStreaming(refused);
    conn.finishStreaming(slow);
    conn.deinit();
    server.join();
    _ = std.c.close(fds[1]);

    // The refused stream — not the healthy one — was reset upstream.
    try testing.expectEqual(refused_id, server_state.rst_stream_id.load(.acquire));
    try testing.expectEqual(@as(usize, 0), origin.currentBytes(.upstream_to_downstream));
    try testing.expectEqual(@as(usize, 0), global.currentBytes(.upstream_to_downstream));
    try testing.expectEqual(@as(usize, 0), observer.current.load(.monotonic));
    // Exactly one origin-scope refusal: a stream we gave up on is discard-only,
    // so later DATA on it neither reserves again nor re-counts the event.
    try testing.expectEqual(@as(u64, 1), observer.origin_limit_exceeded.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), observer.global_limit_exceeded.load(.monotonic));
    // The global scope had room; its rolled-back reservation must not have
    // been counted as a global refusal either.
    try testing.expectEqual(@as(u64, 0), observer.limit_exceeded.load(.monotonic));
}

/// Canned server that answers before the client has finished uploading: it
/// replies with HEADERS and a DATA burst as soon as the request head arrives,
/// while the client is still writing request body frames.
fn cannedEarlyResponseServer(peer_fd: std.posix.fd_t, body_bytes: usize, state: *CannedServerState) void {
    const a = std.heap.page_allocator;
    var srv = PlainTransport{ .fd = peer_fd };
    var preface: [PREFACE.len]u8 = undefined;
    readExact(&srv, peer_fd, preface[0..], canned_server_read_timeout_ms) catch return state.finish(.preface_read_failed);
    frame.writeSettings(a, &srv, &[_][2]u32{}) catch return state.finish(.settings_write_failed);

    var req_stream: u31 = 0;
    while (req_stream == 0) {
        var fr = readFrameBounded(&srv, peer_fd, a, canned_server_read_timeout_ms) catch return state.finish(.headers_read_failed);
        if (fr.typ == .headers) req_stream = fr.stream_id;
        frame.deinitFrame(a, &fr);
    }

    const block = hpack.encodeLiteralHeaderBlock(a, &[_]hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
    }) catch return state.finish(.response_write_failed);
    defer a.free(block);
    frame.writeFrame(&srv, .headers, frame.Flags.END_HEADERS, req_stream, block) catch return state.finish(.response_write_failed);
    const payload = [_]u8{'x'} ** 256;
    frame.writeFrame(&srv, .data, 0, req_stream, payload[0..body_bytes]) catch return state.finish(.body_write_failed);

    while (true) {
        var fr = readFrameBounded(&srv, peer_fd, a, canned_server_read_timeout_ms) catch return state.finish(.rst_read_failed);
        const is_rst = fr.typ == .rst_stream and fr.stream_id == req_stream;
        const id = fr.stream_id;
        frame.deinitFrame(a, &fr);
        if (is_rst) return state.noteRst(@intCast(id));
    }
}

test "response capacity exhausted during an upload surfaces before commitment" {
    // The response can outrun the request: the origin answers while the client
    // is still writing body frames. If that response exhausts local capacity,
    // the failure reaches the worker through its *next upload write* — and
    // since nothing is committed downstream yet, the cause has to survive as
    // local capacity rather than looking like an upstream write failure.
    const fds = try makeSocketpair();
    var server_state = CannedServerState{};
    const server = try std.Thread.spawn(.{}, cannedEarlyResponseServer, .{ fds[1], 16, &server_state });

    var observer = TestProxyBufferObserver{};
    // No room at the origin at all: the early response is refused on arrival.
    var origin = proxy_buffer_account.Aggregate.init(.origin, 8);
    var transport = PlainTransport{ .fd = fds[0] };
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 3000, null, null, null, windowLimits(64));

    const stream = try conn.openStreaming(.{
        .method = "POST",
        .authority = "early.test",
        .path = "/",
        .body_mode = .streaming,
        .proxy_buffer_accounting = true,
        .proxy_buffer_observer = observer.observer(),
        .proxy_buffer_capacity = .{ .origin = &origin },
    });

    // Wait for the reader to refuse the early response, then prove the refusal
    // reaches the uploading worker through its next body write. Waiting on the
    // cause first keeps this independent of how fast the reader thread runs;
    // racing it with a write loop would make the test timing-dependent.
    var spins: usize = 0;
    while (conn.abortCause(stream) != .local_capacity and spins < 100_000_000) : (spins += 1) {
        std.Thread.yield() catch {};
    }
    try testing.expectEqual(AbortCause.local_capacity, conn.abortCause(stream));

    const chunk = [_]u8{'u'} ** 64;
    const upload_err = conn.writeStreamingRequestBody(stream, chunk[0..], false);
    try testing.expectError(error.BufferLimitExceeded, upload_err);
    try testing.expectEqual(AbortCause.local_capacity, conn.abortCause(stream));
    // Still pre-commitment, so the caller can choose a clean status.
    try testing.expectError(error.BufferLimitExceeded, conn.beginDownstreamCommit(stream));

    // Same synchronisation point as the origin-capacity test above: the RST is
    // written by the reader after it publishes the cause, so teardown must wait
    // for the server to have seen it rather than for the cause alone.
    try server_state.expectTerminal(.saw_rst);

    conn.finishStreaming(stream);
    conn.deinit();
    server.join();
    _ = std.c.close(fds[1]);

    try testing.expectEqual(@as(usize, 0), origin.currentBytes(.upstream_to_downstream));
    try testing.expectEqual(@as(usize, 0), observer.retained.load(.monotonic));
}

/// Canned server that fills a stream's window in one frame and then reports the
/// increment carried by the **first** stream-level WINDOW_UPDATE the client
/// sends back. Connection-level updates (stream 0) are ignored.
fn cannedWindowCreditServer(
    peer_fd: std.posix.fd_t,
    body_bytes: usize,
    first_credit: *std.atomic.Value(u32),
) void {
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
    }) catch return;
    defer a.free(block);
    frame.writeFrame(&srv, .headers, frame.Flags.END_HEADERS, req_stream, block) catch return;

    const payload = [_]u8{'x'} ** 256;
    frame.writeFrame(&srv, .data, 0, req_stream, payload[0..body_bytes]) catch return;

    while (true) {
        var fr = readFrameBounded(&srv, peer_fd, a, 5000) catch return;
        const is_stream_update = fr.typ == .window_update and fr.stream_id == req_stream;
        const increment: u32 = if (is_stream_update and fr.payload.len >= 4)
            std.mem.readInt(u32, fr.payload[0..4], .big) & 0x7FFF_FFFF
        else
            0;
        frame.deinitFrame(a, &fr);
        if (is_stream_update) {
            first_credit.store(increment, .release);
            return;
        }
    }
}

test "stream credit is withheld between the high and low watermarks" {
    // Window (== high) 64, low 32: draining from 64 to 48 stays inside the
    // pause band, so the peer must get no credit until the queue reaches 32.
    const window: usize = 64;
    const limits = windowLimits(window);
    try testing.expectEqual(@as(usize, 32), limits.per_stream_low_watermark);

    const fds = try makeSocketpair();
    var first_credit = std.atomic.Value(u32).init(0);
    const server = try std.Thread.spawn(.{}, cannedWindowCreditServer, .{ fds[1], window, &first_credit });

    var observer = TestProxyBufferObserver{};
    var transport = PlainTransport{ .fd = fds[0] };
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 3000, null, null, null, limits);

    const stream = try conn.requestStreaming(.{
        .method = "GET",
        .authority = "hysteresis.test",
        .path = "/",
        .proxy_buffer_accounting = true,
        .proxy_buffer_observer = observer.observer(),
    });

    // Fill the queue to the high watermark, which pauses the upstream.
    var buf: [16]u8 = undefined;
    const first = try conn.readStreamingBody(stream, buf[0..]);
    try testing.expectEqual(@as(usize, 16), first);
    conn.acknowledgeStreamingBody(stream, first); // queue 48: still above low
    try testing.expectEqual(@as(u64, 1), observer.read_pauses.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), observer.read_resumes.load(.monotonic));

    const second = try conn.readStreamingBody(stream, buf[0..]);
    try testing.expectEqual(@as(usize, 16), second);
    conn.acknowledgeStreamingBody(stream, second); // queue 32: crosses low
    try testing.expectEqual(@as(u64, 1), observer.read_resumes.load(.monotonic));

    var spins: usize = 0;
    while (first_credit.load(.acquire) == 0 and spins < 100_000_000) : (spins += 1) std.Thread.yield() catch {};
    // One coalesced update for everything drained inside the band — crediting
    // each chunk as it drained would have made this 16.
    try testing.expectEqual(@as(u32, 32), first_credit.load(.acquire));

    conn.finishStreaming(stream);
    conn.deinit();
    server.join();
    _ = std.c.close(fds[1]);
}

test "a partial drain keeps the aggregate gauge at the retained allocation" {
    // The distinction the aggregate gauge has to preserve: a queue drained from
    // 16 bytes to 8 still *owns* 16, and the global hard limit is enforced
    // against that 16. Reporting 8 would leave operators unable to compare the
    // gauge with the limit it is measured by.
    const fds = try makeSocketpair();
    const server = try std.Thread.spawn(.{}, cannedSingleDataStreamingServer, .{ fds[1], "0123456789abcdef", false });

    var observer = TestProxyBufferObserver{};
    var origin = proxy_buffer_account.Aggregate.init(.origin, 64);
    var transport = PlainTransport{ .fd = fds[0] };
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 3000, null, null, null, windowLimits(64));

    const stream = try conn.requestStreaming(.{
        .method = "GET",
        .authority = "partial.test",
        .path = "/",
        .proxy_buffer_accounting = true,
        .proxy_buffer_observer = observer.observer(),
        .proxy_buffer_capacity = .{ .origin = &origin },
    });

    var buf: [8]u8 = undefined;
    const first = try conn.readStreamingBody(stream, buf[0..]);
    try testing.expectEqual(@as(usize, 8), first);
    try testing.expectEqual(@as(usize, 16), observer.retained.load(.monotonic));

    conn.acknowledgeStreamingBody(stream, first);
    // Logical occupancy halves; retained allocation — and the origin scope
    // enforcing it — does not, because the buffer is still 16 bytes long.
    try testing.expectEqual(@as(usize, 8), observer.current.load(.monotonic));
    try testing.expectEqual(@as(usize, 16), observer.retained.load(.monotonic));
    try testing.expectEqual(@as(usize, 16), origin.currentBytes(.upstream_to_downstream));
    try testing.expectEqual(@as(usize, 16), stream.body.capacity);

    const second = try conn.readStreamingBody(stream, buf[0..]);
    conn.acknowledgeStreamingBody(stream, second);
    // Now the storage is actually handed back, and both views agree again.
    try testing.expectEqual(@as(usize, 0), observer.current.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), observer.retained.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), origin.currentBytes(.upstream_to_downstream));

    conn.finishStreaming(stream);
    conn.deinit();
    server.join();
    _ = std.c.close(fds[1]);
}

test "a drained queue returns its backing allocation to the aggregate scopes" {
    // A stream that fills and drains repeatedly must not sit on its peak
    // allocation: the aggregate scopes bound retained memory, so a queue whose
    // logical length is zero has to have given its storage back too.
    const window: usize = 64;
    const fds = try makeSocketpair();
    const server = try std.Thread.spawn(.{}, cannedSingleDataStreamingServer, .{ fds[1], "0123456789abcdef", false });

    var origin = proxy_buffer_account.Aggregate.init(.origin, window);
    var global = proxy_buffer_account.Aggregate.init(.global, 1024);
    var transport = PlainTransport{ .fd = fds[0] };
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 3000, null, null, null, windowLimits(window));

    const stream = try conn.requestStreaming(.{
        .method = "GET",
        .authority = "retained.test",
        .path = "/",
        .proxy_buffer_accounting = true,
        .proxy_buffer_capacity = .{ .origin = &origin, .global = &global },
    });

    var buf: [16]u8 = undefined;
    const n = try conn.readStreamingBody(stream, buf[0..]);
    try testing.expectEqual(@as(usize, 16), n);
    try testing.expectEqual(@as(usize, 16), origin.currentBytes(.upstream_to_downstream));

    conn.acknowledgeStreamingBody(stream, n);
    // Logical length *and* retained capacity are both back to zero.
    try testing.expectEqual(@as(usize, 0), stream.body.items.len);
    try testing.expectEqual(@as(usize, 0), stream.body.capacity);
    try testing.expectEqual(@as(usize, 0), origin.currentBytes(.upstream_to_downstream));
    try testing.expectEqual(@as(usize, 0), global.currentBytes(.upstream_to_downstream));

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
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 300, null, null, null, windowLimits(DEFAULT_STREAM_RECV_WINDOW));

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
        ctx.conn.acknowledgeStreamingBody(stream, n);
    }
    ctx.ok = std.mem.eql(u8, got_buf[0..got_len], path);
}

test "streaming and buffered requests multiplex together on one connection" {
    const N_BUF = 4;
    const N_STREAM = 4;
    const fds = try makeSocketpair();
    const server = try std.Thread.spawn(.{}, cannedMuxServer, .{ fds[1], @as(usize, N_BUF + N_STREAM) });

    var transport = PlainTransport{ .fd = fds[0] };
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 3000, null, null, null, windowLimits(DEFAULT_STREAM_RECV_WINDOW));

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
    const conn = try H2Conn(*PlainTransport).init(testing.allocator, &transport, fds[0], 3000, null, null, null, windowLimits(DEFAULT_STREAM_RECV_WINDOW));

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
        conn.acknowledgeStreamingBody(stream, n);
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
    const conn = try H2Conn(*FailingDataTransport).init(testing.allocator, &transport, fds[0], 3000, null, null, null, windowLimits(DEFAULT_STREAM_RECV_WINDOW));

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
