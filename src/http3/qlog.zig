//! HTTP/3- and QPACK-vantage qlog events (#255).
//!
//! The symmetric half of `src/quic/qlog.zig`. It exists here, in `src/http3`,
//! because these events (`http:*`, `qpack:*`) describe the *application*
//! mapping — SETTINGS, control-stream framing, HEADERS/DATA, GOAWAY, and QPACK
//! head-of-line blocking — and must not leak into the transport package. Just
//! like the transport side it emits through an injected `Sink`; the concrete
//! qlog file writer lives at the composition root and interleaves this stream
//! with the transport stream into one trace.
//!
//! Scope note: only the events needed before external interop are modelled
//! here. `qpack_state_updated` (blocked/unblocked) is the load-bearing one for
//! #255 — QPACK head-of-line blocking is otherwise invisible in application
//! logs — with the frame/settings events included so a trace can attribute a
//! stall to the right H3 exchange.

const std = @import("std");

/// qlog application-vantage categories owned by HTTP/3.
pub const Category = enum {
    http,
    qpack,

    pub fn label(self: Category) []const u8 {
        return @tagName(self);
    }
};

/// H3 frame types we surface in traces (RFC 9114 §7.2).
pub const FrameType = enum {
    data,
    headers,
    settings,
    goaway,
    push_promise,
    cancel_push,
    max_push_id,

    pub fn label(self: FrameType) []const u8 {
        return @tagName(self);
    }
};

pub const Direction = enum { created, parsed };

/// QPACK stream state (RFC 9204 §2.1.2): a request stream becomes `blocked`
/// when it references a dynamic-table entry not yet acknowledged by the
/// encoder stream, and `unblocked` once the required insert count arrives.
pub const QpackState = enum { blocked, unblocked };

pub const Event = union(enum) {
    /// http:parameters_set (SETTINGS applied)
    parameters_set: struct {
        max_field_section_size: ?u64 = null,
        qpack_max_table_capacity: ?u64 = null,
        qpack_blocked_streams: ?u64 = null,
    },
    /// http:frame_created / http:frame_parsed
    frame: struct {
        direction: Direction,
        frame_type: FrameType,
        stream_id: u64,
        length: usize = 0,
    },
    /// qpack:stream_state_updated (head-of-line blocking)
    qpack_state_updated: struct {
        state: QpackState,
        stream_id: u64,
    },

    pub fn category(self: Event) Category {
        return switch (self) {
            .parameters_set, .frame => .http,
            .qpack_state_updated => .qpack,
        };
    }

    pub fn name(self: Event) []const u8 {
        return switch (self) {
            .parameters_set => "parameters_set",
            .frame => |f| switch (f.direction) {
                .created => "frame_created",
                .parsed => "frame_parsed",
            },
            .qpack_state_updated => "stream_state_updated",
        };
    }
};

pub const Record = struct {
    time_us: u64,
    event: Event,
};

/// Injected emission seam — same shape as `quic.qlog.Sink`, so a composition
/// root can hold one of each and route both into the same trace file. A default
/// `.{}` is a no-op.
///
/// `emit_fn` returns `void`, so a concrete file sink cannot propagate write
/// errors here. Same contract as the transport sink: retain the first error
/// and/or count dropped records out-of-band so a truncated trace is detectable.
pub const Sink = struct {
    context: ?*anyopaque = null,
    emit_fn: ?*const fn (?*anyopaque, Record) void = null,

    pub fn emit(self: Sink, record: Record) void {
        if (self.emit_fn) |f| f(self.context, record);
    }

    pub fn log(self: Sink, time_us: u64, event: Event) void {
        self.emit(.{ .time_us = time_us, .event = event });
    }
};

/// JSON-SEQ record separator (RFC 7464), identical framing to the transport
/// side so both streams concatenate into one valid qlog JSON-SEQ file.
pub const record_separator: u8 = 0x1e;

const Buf = struct {
    buf: []u8,
    len: usize = 0,

    fn add(self: *Buf, comptime fmt: []const u8, args: anytype) error{NoSpaceLeft}!void {
        const written = try std.fmt.bufPrint(self.buf[self.len..], fmt, args);
        self.len += written.len;
    }

    fn slice(self: *const Buf) []const u8 {
        return self.buf[0..self.len];
    }
};

fn writeData(b: *Buf, event: Event) error{NoSpaceLeft}!void {
    switch (event) {
        .parameters_set => |d| {
            try b.add("{{", .{});
            var need_comma = false;
            if (d.max_field_section_size) |v| {
                try b.add("\"max_field_section_size\":{d}", .{v});
                need_comma = true;
            }
            if (d.qpack_max_table_capacity) |v| {
                if (need_comma) try b.add(",", .{});
                try b.add("\"qpack_max_table_capacity\":{d}", .{v});
                need_comma = true;
            }
            if (d.qpack_blocked_streams) |v| {
                if (need_comma) try b.add(",", .{});
                try b.add("\"qpack_blocked_streams\":{d}", .{v});
            }
            try b.add("}}", .{});
        },
        .frame => |d| try b.add(
            "{{\"stream_id\":{d},\"frame\":{{\"frame_type\":\"{s}\"}},\"length\":{d}}}",
            .{ d.stream_id, d.frame_type.label(), d.length },
        ),
        .qpack_state_updated => |d| try b.add(
            "{{\"stream_id\":{d},\"state\":\"{s}\"}}",
            .{ d.stream_id, @tagName(d.state) },
        ),
    }
}

/// Serialize one `Record` into `out` as a single qlog JSON-SEQ line. Same shape
/// as `quic.qlog.writeJson` so a merged trace is uniform.
pub fn writeJson(record: Record, out: []u8) error{NoSpaceLeft}![]const u8 {
    var b = Buf{ .buf = out };
    try b.add("{c}", .{record_separator});
    try b.add(
        "{{\"time\":{d}.{d:0>3},\"name\":\"{s}:{s}\",\"data\":",
        .{ record.time_us / 1000, record.time_us % 1000, record.event.category().label(), record.event.name() },
    );
    try writeData(&b, record.event);
    try b.add("}}\n", .{});
    return b.slice();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn expectJson(record: Record, needle: []const u8) !void {
    var buf: [512]u8 = undefined;
    const line = try writeJson(record, &buf);
    try testing.expect(line[0] == record_separator);
    try testing.expect(line[line.len - 1] == '\n');
    try testing.expect(std.mem.indexOf(u8, line, needle) != null);
}

test "qpack blocking is a qpack:stream_state_updated event" {
    const ev = Event{ .qpack_state_updated = .{ .state = .blocked, .stream_id = 12 } };
    try testing.expectEqual(Category.qpack, ev.category());
    try expectJson(.{ .time_us = 42, .event = ev }, "\"name\":\"qpack:stream_state_updated\"");
    try expectJson(.{ .time_us = 42, .event = ev }, "\"state\":\"blocked\"");
}

test "frame direction chooses frame_created vs frame_parsed" {
    try expectJson(
        .{ .time_us = 0, .event = .{ .frame = .{ .direction = .created, .frame_type = .headers, .stream_id = 0, .length = 20 } } },
        "\"name\":\"http:frame_created\"",
    );
    try expectJson(
        .{ .time_us = 0, .event = .{ .frame = .{ .direction = .parsed, .frame_type = .goaway, .stream_id = 3 } } },
        "\"name\":\"http:frame_parsed\"",
    );
}

test "parameters_set only emits present settings" {
    try expectJson(
        .{ .time_us = 0, .event = .{ .parameters_set = .{ .qpack_blocked_streams = 16 } } },
        "{\"qpack_blocked_streams\":16}",
    );
}

test "default sink is a no-op" {
    const sink = Sink{};
    sink.log(1, .{ .qpack_state_updated = .{ .state = .unblocked, .stream_id = 0 } });
}
