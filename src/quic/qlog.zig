//! Transport-layer qlog event model and a minimal JSON-SEQ serializer (#255).
//!
//! This is the observability seam the pure-Zig QUIC transport emits through
//! *before* external interop. It defines:
//!
//!   * `Event`     — a closed union of the transport events qvis/qlog tooling
//!                   needs to explain handshake, loss, path, and flow-control
//!                   behaviour (RFC 9000/9002 vantage points).
//!   * `Record`    — an `Event` stamped with a monotonic time.
//!   * `Sink`      — the injected emission seam, mirroring
//!                   `recovery.EventSink`: an opaque context plus a function
//!                   pointer. The transport calls `sink.emit(record)` and never
//!                   learns what the sink does with it.
//!   * `writeJson` — turns one `Record` into a single qlog JSON-SEQ line
//!                   (RFC 7464: 0x1E record separator + JSON + '\n').
//!
//! ## Layering (the #255 "don't leak H3 into src/quic" decision)
//!
//! `src/quic` owns *only* transport-vantage events (qlog categories
//! `connectivity`, `security`, `transport`, `recovery`). HTTP/3- and
//! QPACK-vantage events live in `src/http3/qlog.zig` and are emitted from
//! `src/http3`. Neither package imports the other — the same boundary the
//! build graph already enforces (see build.zig: the smoke harness stitches the
//! two together, "so neither package learns about the other").
//!
//! The *concrete* qlog file writer therefore lives at the composition root
//! (the gateway h3 listener, or the `tests/quic_h3_smoke.zig` harness), which
//! owns both packages. It installs one `quic.qlog.Sink` and one
//! `http3.qlog.Sink`, and interleaves both event streams into a single qlog
//! trace. This keeps `src/quic` free of any HTTP/3 type while still producing a
//! unified trace file.
//!
//! ## Cost when disabled
//!
//! A default `Sink{}` has a null `emit_fn`; `emit` is a single null check and
//! return. Callers should still guard expensive event construction behind
//! `config.Observability.qlog_enabled` so the hot path pays nothing when qlog
//! is off (the default, per the issue's "disabled by default" requirement).

const std = @import("std");

/// qlog top-level event categories this transport emits. Application (`http`,
/// `qpack`) categories are intentionally absent: they belong to `src/http3`.
pub const Category = enum {
    connectivity,
    security,
    transport,
    recovery,

    pub fn label(self: Category) []const u8 {
        return @tagName(self);
    }
};

/// QUIC packet types (RFC 9000 §17), named as qlog expects them.
pub const PacketType = enum {
    initial,
    zero_rtt,
    handshake,
    one_rtt,
    retry,
    version_negotiation,

    pub fn label(self: PacketType) []const u8 {
        return switch (self) {
            .zero_rtt => "0RTT",
            .one_rtt => "1RTT",
            else => @tagName(self),
        };
    }
};

/// Coarse handshake milestones, enough to localize a stalled handshake to a
/// key-installation / transport-parameter / confirmation stage.
pub const HandshakeStage = enum {
    started,
    initial_keys_installed,
    handshake_keys_installed,
    application_keys_installed,
    transport_parameters_authenticated,
    confirmed,
    failed,
};

/// Why a connection closed (drives `connectivity:connection_closed`).
pub const CloseReason = enum {
    idle_timeout,
    application_close,
    transport_error,
    stateless_reset,
    handshake_failure,
};

/// PATH_CHALLENGE / PATH_RESPONSE lifecycle phases (RFC 9000 §8.2).
pub const PathEventKind = enum {
    challenge_sent,
    challenge_received,
    response_sent,
    response_received,
    validated,
    failed,
};

/// Connection-migration classification and policy outcome (RFC 9000 §9).
pub const MigrationKind = enum { nat_rebinding, active };
pub const MigrationOutcome = enum { accepted, blocked };

/// RESET_STREAM / STOP_SENDING direction (RFC 9000 §19.4, §19.5).
pub const StreamResetKind = enum {
    reset_sent,
    reset_received,
    stop_sending_sent,
    stop_sending_received,
};

/// DATA_BLOCKED vs. STREAM_DATA_BLOCKED (RFC 9000 §19.12, §19.13).
pub const BlockedScope = enum { connection, stream };

/// Why an inbound packet was dropped. `payload_decrypt_error` is the qlog
/// canonical trigger for AEAD deprotection failure — the #255 requirement that
/// deprotection failures are reported deterministically.
pub const DropTrigger = enum {
    payload_decrypt_error,
    key_unavailable,
    unknown_connection_id,
    unexpected_packet,
    header_parse_error,
};

/// The closed set of transport-vantage events. Data payloads are kept small and
/// copy-free (scalars/enums only) so emitting is cheap and the union never
/// borrows connection-owned buffers.
pub const Event = union(enum) {
    /// connectivity:connection_started
    connection_started: struct {
        odcid_len: u8 = 0,
        scid_len: u8 = 0,
        dcid_len: u8 = 0,
    },
    /// connectivity:connection_closed
    connection_closed: struct {
        reason: CloseReason,
        error_code: ?u64 = null,
    },
    /// connectivity:handshake (progress milestone; not a base qlog name, kept
    /// under connectivity as a Tardigrade extension for stage visibility)
    handshake_progressed: struct {
        stage: HandshakeStage,
    },
    /// security:key_updated (1-RTT key-phase flip, RFC 9001 §6)
    key_updated: struct {
        phase: u1,
    },
    /// transport:packet_sent
    packet_sent: struct {
        packet_type: PacketType,
        packet_number: u64,
        length: usize,
        ack_eliciting: bool = false,
    },
    /// transport:packet_received
    packet_received: struct {
        packet_type: PacketType,
        packet_number: u64,
        length: usize,
    },
    /// recovery:packet_lost
    packet_lost: struct {
        packet_type: PacketType,
        packet_number: ?u64 = null,
        bytes_in_flight: usize = 0,
        congestion_window: usize = 0,
    },
    /// transport:packet_dropped (deprotection failure and other drops)
    packet_dropped: struct {
        packet_type: ?PacketType = null,
        trigger: DropTrigger,
        length: usize = 0,
    },
    /// transport:path_validation (PATH_CHALLENGE / PATH_RESPONSE)
    path_validation: struct {
        kind: PathEventKind,
        path_id: u8 = 0,
    },
    /// connectivity:connection_migrated
    connection_migrated: struct {
        kind: MigrationKind,
        outcome: MigrationOutcome,
    },
    /// transport:stream_reset (RESET_STREAM / STOP_SENDING)
    stream_reset: struct {
        kind: StreamResetKind,
        stream_id: u64,
        error_code: u64 = 0,
    },
    /// transport:data_blocked (flow-control blocked)
    data_blocked: struct {
        scope: BlockedScope,
        stream_id: ?u64 = null,
        limit: u64 = 0,
    },

    pub fn category(self: Event) Category {
        return switch (self) {
            .connection_started,
            .connection_closed,
            .handshake_progressed,
            .connection_migrated,
            => .connectivity,
            .key_updated => .security,
            .packet_lost => .recovery,
            .packet_sent,
            .packet_received,
            .packet_dropped,
            .path_validation,
            .stream_reset,
            .data_blocked,
            => .transport,
        };
    }

    /// The qlog event name within the category (the part after the `:`).
    pub fn name(self: Event) []const u8 {
        return switch (self) {
            .connection_started => "connection_started",
            .connection_closed => "connection_closed",
            .handshake_progressed => "handshake",
            .key_updated => "key_updated",
            .packet_sent => "packet_sent",
            .packet_received => "packet_received",
            .packet_lost => "packet_lost",
            .packet_dropped => "packet_dropped",
            .path_validation => "path_validation",
            .connection_migrated => "connection_migrated",
            .stream_reset => "stream_reset",
            .data_blocked => "data_blocked",
        };
    }
};

/// An `Event` stamped with a monotonic microsecond time. qlog time is emitted
/// in milliseconds (the qlog default `time_units`), derived from `time_us`.
pub const Record = struct {
    time_us: u64,
    event: Event,
};

/// The injected emission seam. Mirrors `recovery.EventSink`: a default value
/// (`.{}`) is a no-op, so wiring qlog is opt-in and free when absent.
pub const Sink = struct {
    context: ?*anyopaque = null,
    emit_fn: ?*const fn (?*anyopaque, Record) void = null,

    pub fn emit(self: Sink, record: Record) void {
        if (self.emit_fn) |f| f(self.context, record);
    }

    /// Convenience: stamp an event and emit it in one call.
    pub fn log(self: Sink, time_us: u64, event: Event) void {
        self.emit(.{ .time_us = time_us, .event = event });
    }
};

/// JSON-SEQ record separator (RFC 7464 §2.2): each qlog line is 0x1E + JSON.
pub const record_separator: u8 = 0x1e;

/// A bounded, allocation-free JSON accumulator over a caller-owned buffer, in
/// the same spirit as the wire `Writer` in `tls_handshake.zig`.
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

fn boolText(value: bool) []const u8 {
    return if (value) "true" else "false";
}

fn writeData(b: *Buf, event: Event) error{NoSpaceLeft}!void {
    switch (event) {
        .connection_started => |d| try b.add(
            "{{\"odcid_length\":{d},\"scid_length\":{d},\"dcid_length\":{d}}}",
            .{ d.odcid_len, d.scid_len, d.dcid_len },
        ),
        .connection_closed => |d| {
            try b.add("{{\"reason\":\"{s}\"", .{@tagName(d.reason)});
            if (d.error_code) |code| try b.add(",\"error_code\":{d}", .{code});
            try b.add("}}", .{});
        },
        .handshake_progressed => |d| try b.add(
            "{{\"stage\":\"{s}\"}}",
            .{@tagName(d.stage)},
        ),
        .key_updated => |d| try b.add("{{\"key_phase\":{d}}}", .{d.phase}),
        .packet_sent => |d| try b.add(
            "{{\"packet_type\":\"{s}\",\"packet_number\":{d},\"length\":{d},\"ack_eliciting\":{s}}}",
            .{ d.packet_type.label(), d.packet_number, d.length, boolText(d.ack_eliciting) },
        ),
        .packet_received => |d| try b.add(
            "{{\"packet_type\":\"{s}\",\"packet_number\":{d},\"length\":{d}}}",
            .{ d.packet_type.label(), d.packet_number, d.length },
        ),
        .packet_lost => |d| {
            try b.add("{{\"packet_type\":\"{s}\"", .{d.packet_type.label()});
            if (d.packet_number) |pn| try b.add(",\"packet_number\":{d}", .{pn});
            try b.add(
                ",\"bytes_in_flight\":{d},\"congestion_window\":{d}}}",
                .{ d.bytes_in_flight, d.congestion_window },
            );
        },
        .packet_dropped => |d| {
            try b.add("{{\"trigger\":\"{s}\"", .{@tagName(d.trigger)});
            if (d.packet_type) |pt| try b.add(",\"packet_type\":\"{s}\"", .{pt.label()});
            try b.add(",\"length\":{d}}}", .{d.length});
        },
        .path_validation => |d| try b.add(
            "{{\"phase\":\"{s}\",\"path_id\":{d}}}",
            .{ @tagName(d.kind), d.path_id },
        ),
        .connection_migrated => |d| try b.add(
            "{{\"kind\":\"{s}\",\"outcome\":\"{s}\"}}",
            .{ @tagName(d.kind), @tagName(d.outcome) },
        ),
        .stream_reset => |d| try b.add(
            "{{\"direction\":\"{s}\",\"stream_id\":{d},\"error_code\":{d}}}",
            .{ @tagName(d.kind), d.stream_id, d.error_code },
        ),
        .data_blocked => |d| {
            try b.add("{{\"scope\":\"{s}\"", .{@tagName(d.scope)});
            if (d.stream_id) |sid| try b.add(",\"stream_id\":{d}", .{sid});
            try b.add(",\"limit\":{d}}}", .{d.limit});
        },
    }
}

/// Serialize one `Record` into `out` as a single qlog JSON-SEQ line:
///
///     0x1E {"time":<ms>,"name":"<category>:<event>","data":{...}} \n
///
/// Returns the written slice. Errors only if `out` is too small; a 512-byte
/// buffer is comfortably enough for every event above.
pub fn writeJson(record: Record, out: []u8) error{NoSpaceLeft}![]const u8 {
    var b = Buf{ .buf = out };
    try b.add("{c}", .{record_separator});
    // qlog default time unit is milliseconds; keep microsecond precision.
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

test "category and name mapping stays aligned with qlog vantage points" {
    try testing.expectEqual(Category.transport, (Event{ .packet_sent = .{ .packet_type = .one_rtt, .packet_number = 0, .length = 0 } }).category());
    try testing.expectEqual(Category.recovery, (Event{ .packet_lost = .{ .packet_type = .one_rtt } }).category());
    try testing.expectEqual(Category.security, (Event{ .key_updated = .{ .phase = 1 } }).category());
    try testing.expectEqual(Category.connectivity, (Event{ .connection_migrated = .{ .kind = .active, .outcome = .blocked } }).category());
    try testing.expectEqualStrings("packet_dropped", (Event{ .packet_dropped = .{ .trigger = .payload_decrypt_error } }).name());
}

test "packet_sent serializes to a transport JSON-SEQ line" {
    try expectJson(
        .{ .time_us = 1_234_567, .event = .{ .packet_sent = .{ .packet_type = .initial, .packet_number = 7, .length = 1200, .ack_eliciting = true } } },
        "\"name\":\"transport:packet_sent\"",
    );
    try expectJson(
        .{ .time_us = 1_234_567, .event = .{ .packet_sent = .{ .packet_type = .one_rtt, .packet_number = 7, .length = 1200 } } },
        "\"packet_type\":\"1RTT\"",
    );
}

test "deprotection failure is a packet_dropped with payload_decrypt_error" {
    try expectJson(
        .{ .time_us = 0, .event = .{ .packet_dropped = .{ .packet_type = .one_rtt, .trigger = .payload_decrypt_error, .length = 42 } } },
        "\"trigger\":\"payload_decrypt_error\"",
    );
}

test "time is rendered in milliseconds with microsecond precision" {
    var buf: [512]u8 = undefined;
    const line = try writeJson(.{ .time_us = 1_002_003, .event = .{ .key_updated = .{ .phase = 1 } } }, &buf);
    try testing.expect(std.mem.indexOf(u8, line, "\"time\":1002.003") != null);
}

test "path, migration, stream reset and flow-control events serialize" {
    try expectJson(.{ .time_us = 5, .event = .{ .path_validation = .{ .kind = .response_received } } }, "\"phase\":\"response_received\"");
    try expectJson(.{ .time_us = 5, .event = .{ .connection_migrated = .{ .kind = .nat_rebinding, .outcome = .accepted } } }, "connection_migrated");
    try expectJson(.{ .time_us = 5, .event = .{ .stream_reset = .{ .kind = .reset_received, .stream_id = 4, .error_code = 9 } } }, "\"stream_id\":4");
    try expectJson(.{ .time_us = 5, .event = .{ .data_blocked = .{ .scope = .stream, .stream_id = 8, .limit = 4096 } } }, "\"scope\":\"stream\"");
}

test "default sink is a no-op and log() stamps time" {
    const Collector = struct {
        var last: ?Record = null;
        fn emit(_: ?*anyopaque, record: Record) void {
            last = record;
        }
    };
    const noop = Sink{};
    noop.log(1, .{ .key_updated = .{ .phase = 0 } }); // must not crash

    Collector.last = null;
    const sink = Sink{ .emit_fn = Collector.emit };
    sink.log(99, .{ .connection_closed = .{ .reason = .idle_timeout } });
    try testing.expect(Collector.last != null);
    try testing.expectEqual(@as(u64, 99), Collector.last.?.time_us);
}
