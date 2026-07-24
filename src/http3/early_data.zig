//! HTTP/3 0-RTT remembered SETTINGS support (RFC 9114 §7.2.4.2).
//!
//! TLS session tickets carry this module's opaque bytes as
//! `early_data_application_compat`; the TLS layer keeps the blob opaque and
//! H3 owns the directional compatibility rules.

const std = @import("std");
const frame = @import("frame.zig");
const varint = @import("quic_varint");

pub const format_id: u16 = 0x6833; // "h3"
pub const format_version: u16 = 1;

pub const encoded_snapshot_len: usize = 25;
const flag_max_field_section_size_present: u8 = 1 << 0;
const flag_enable_connect_protocol: u8 = 1 << 1;
const flag_h3_datagram: u8 = 1 << 2;
const known_flags: u8 = flag_max_field_section_size_present |
    flag_enable_connect_protocol |
    flag_h3_datagram;

pub const SnapshotError = error{
    OutputTooSmall,
    MalformedSnapshot,
    FormatMismatch,
    InvalidSettingsDomain,
};

pub const Compatibility = enum {
    compatible,
    missing_state,
    malformed_state,
    settings_incompatible,
};

pub const CompatView = struct {
    format_id: u16,
    format_version: u16,
    bytes: []const u8,
};

pub fn encodeSettingsSnapshot(settings: frame.Settings, out: []u8) SnapshotError![]const u8 {
    if (out.len < encoded_snapshot_len) return error.OutputTooSmall;
    if (!settingsDomainValid(settings)) return error.InvalidSettingsDomain;
    var flags: u8 = 0;
    if (settings.max_field_section_size != null) flags |= flag_max_field_section_size_present;
    if (settings.enable_connect_protocol) flags |= flag_enable_connect_protocol;
    if (settings.h3_datagram) flags |= flag_h3_datagram;

    out[0] = flags;
    std.mem.writeInt(u64, out[1..9], settings.qpack_max_table_capacity, .big);
    std.mem.writeInt(u64, out[9..17], settings.qpack_blocked_streams, .big);
    std.mem.writeInt(u64, out[17..25], settings.max_field_section_size orelse 0, .big);
    return out[0..encoded_snapshot_len];
}

pub fn decodeSettingsSnapshot(bytes: []const u8) SnapshotError!frame.Settings {
    if (bytes.len != encoded_snapshot_len) return error.MalformedSnapshot;
    const flags = bytes[0];
    if (flags & ~known_flags != 0) return error.MalformedSnapshot;
    const settings: frame.Settings = .{
        .qpack_max_table_capacity = std.mem.readInt(u64, bytes[1..9], .big),
        .qpack_blocked_streams = std.mem.readInt(u64, bytes[9..17], .big),
        .max_field_section_size = if (flags & flag_max_field_section_size_present != 0)
            std.mem.readInt(u64, bytes[17..25], .big)
        else
            null,
        .enable_connect_protocol = flags & flag_enable_connect_protocol != 0,
        .h3_datagram = flags & flag_h3_datagram != 0,
    };
    if (!settingsDomainValid(settings)) return error.InvalidSettingsDomain;
    return settings;
}

pub fn decodeCompatView(view: CompatView) SnapshotError!frame.Settings {
    if (view.format_id != format_id or view.format_version != format_version) return error.FormatMismatch;
    return decodeSettingsSnapshot(view.bytes);
}

pub fn rememberedSettingsCompatible(remembered: frame.Settings, current: frame.Settings) bool {
    if (!qpackMaxTableCompatible(remembered.qpack_max_table_capacity, current.qpack_max_table_capacity)) return false;
    if (current.qpack_blocked_streams < remembered.qpack_blocked_streams) return false;
    if (!limitCompatible(remembered.max_field_section_size, current.max_field_section_size)) return false;
    if (remembered.enable_connect_protocol and !current.enable_connect_protocol) return false;
    if (remembered.h3_datagram and !current.h3_datagram) return false;
    return true;
}

pub fn compatibility(remembered: ?CompatView, current: frame.Settings) Compatibility {
    const view = remembered orelse return .missing_state;
    const decoded = decodeCompatView(view) catch |err| return switch (err) {
        error.FormatMismatch => .malformed_state,
        error.MalformedSnapshot => .malformed_state,
        error.InvalidSettingsDomain => .malformed_state,
        error.OutputTooSmall => unreachable,
    };
    return if (rememberedSettingsCompatible(decoded, current)) .compatible else .settings_incompatible;
}

pub fn settingsDomainValid(settings: frame.Settings) bool {
    if (settings.qpack_max_table_capacity > varint.max_value) return false;
    if (settings.qpack_blocked_streams > varint.max_value) return false;
    if (settings.max_field_section_size) |v| {
        if (v > varint.max_value) return false;
    }
    return true;
}

fn qpackMaxTableCompatible(remembered: u64, current: u64) bool {
    if (remembered == 0) return true;
    return current == remembered;
}

fn limitCompatible(remembered: ?u64, current: ?u64) bool {
    if (remembered) |old| {
        if (current) |now| return now >= old;
        return true;
    }
    return current == null;
}

const testing = std.testing;

test "H3 early data SETTINGS snapshot round trips defaults and non-defaults" {
    var buf: [encoded_snapshot_len]u8 = undefined;
    const defaults = try encodeSettingsSnapshot(.{}, &buf);
    try testing.expectEqual(frame.Settings{}, try decodeSettingsSnapshot(defaults));

    const settings: frame.Settings = .{
        .qpack_max_table_capacity = 4096,
        .qpack_blocked_streams = 8,
        .max_field_section_size = 16 * 1024,
        .enable_connect_protocol = true,
        .h3_datagram = true,
    };
    const encoded = try encodeSettingsSnapshot(settings, &buf);
    try testing.expectEqual(settings, try decodeSettingsSnapshot(encoded));
}

test "H3 early data SETTINGS snapshot rejects malformed state" {
    var buf: [encoded_snapshot_len]u8 = undefined;
    const encoded = try encodeSettingsSnapshot(.{}, &buf);
    try testing.expectError(error.MalformedSnapshot, decodeSettingsSnapshot(encoded[0 .. encoded.len - 1]));
    buf[0] = 0x80;
    try testing.expectError(error.MalformedSnapshot, decodeSettingsSnapshot(&buf));
    try testing.expectError(error.FormatMismatch, decodeCompatView(.{
        .format_id = format_id + 1,
        .format_version = format_version,
        .bytes = encoded,
    }));
}

test "H3 early data SETTINGS compatibility is directional" {
    const remembered: frame.Settings = .{
        .qpack_max_table_capacity = 32,
        .qpack_blocked_streams = 4,
        .max_field_section_size = 128,
        .enable_connect_protocol = false,
    };
    try testing.expect(rememberedSettingsCompatible(remembered, .{
        .qpack_max_table_capacity = 32,
        .qpack_blocked_streams = 4,
        .max_field_section_size = null,
        .enable_connect_protocol = true,
    }));
    try testing.expect(!rememberedSettingsCompatible(remembered, .{
        .qpack_max_table_capacity = 32,
        .qpack_blocked_streams = 4,
        .max_field_section_size = 127,
    }));
    try testing.expect(!rememberedSettingsCompatible(.{ .max_field_section_size = null }, .{ .max_field_section_size = 1024 }));
    try testing.expect(rememberedSettingsCompatible(.{ .max_field_section_size = 1024 }, .{ .max_field_section_size = null }));
    try testing.expect(!rememberedSettingsCompatible(.{ .enable_connect_protocol = true }, .{ .enable_connect_protocol = false }));
    try testing.expect(rememberedSettingsCompatible(.{ .enable_connect_protocol = false }, .{ .enable_connect_protocol = true }));
}

test "H3 early data SETTINGS snapshot validates QUIC varint domains" {
    var buf: [encoded_snapshot_len]u8 = undefined;
    _ = try encodeSettingsSnapshot(.{
        .qpack_max_table_capacity = varint.max_value,
        .qpack_blocked_streams = varint.max_value,
        .max_field_section_size = varint.max_value,
    }, &buf);
    try testing.expectError(error.InvalidSettingsDomain, encodeSettingsSnapshot(.{
        .qpack_max_table_capacity = varint.max_value + 1,
    }, &buf));
    try testing.expectError(error.InvalidSettingsDomain, encodeSettingsSnapshot(.{
        .qpack_blocked_streams = varint.max_value + 1,
    }, &buf));
    try testing.expectError(error.InvalidSettingsDomain, encodeSettingsSnapshot(.{
        .max_field_section_size = varint.max_value + 1,
    }, &buf));

    std.mem.writeInt(u64, buf[1..9], varint.max_value + 1, .big);
    try testing.expectError(error.InvalidSettingsDomain, decodeSettingsSnapshot(&buf));
    std.mem.writeInt(u64, buf[1..9], 0, .big);
    std.mem.writeInt(u64, buf[9..17], varint.max_value + 1, .big);
    try testing.expectError(error.InvalidSettingsDomain, decodeSettingsSnapshot(&buf));
    std.mem.writeInt(u64, buf[9..17], 0, .big);
    buf[0] = flag_max_field_section_size_present;
    std.mem.writeInt(u64, buf[17..25], varint.max_value + 1, .big);
    try testing.expectError(error.InvalidSettingsDomain, decodeSettingsSnapshot(&buf));
}

test "H3 early data QPACK max table follows RFC 9204 0-RTT rule" {
    try testing.expect(rememberedSettingsCompatible(.{ .qpack_max_table_capacity = 0 }, .{ .qpack_max_table_capacity = 0 }));
    try testing.expect(rememberedSettingsCompatible(.{ .qpack_max_table_capacity = 0 }, .{ .qpack_max_table_capacity = 4096 }));
    try testing.expect(rememberedSettingsCompatible(.{ .qpack_max_table_capacity = 4096 }, .{ .qpack_max_table_capacity = 4096 }));
    try testing.expect(!rememberedSettingsCompatible(.{ .qpack_max_table_capacity = 4096 }, .{ .qpack_max_table_capacity = 2048 }));
    try testing.expect(!rememberedSettingsCompatible(.{ .qpack_max_table_capacity = 4096 }, .{ .qpack_max_table_capacity = 8192 }));
}

test "H3 early data SETTINGS compatibility classifies missing and malformed remembered state" {
    var buf: [encoded_snapshot_len]u8 = undefined;
    const encoded = try encodeSettingsSnapshot(.{ .qpack_blocked_streams = 2 }, &buf);
    try testing.expectEqual(Compatibility.compatible, compatibility(.{
        .format_id = format_id,
        .format_version = format_version,
        .bytes = encoded,
    }, .{ .qpack_blocked_streams = 2 }));
    try testing.expectEqual(Compatibility.settings_incompatible, compatibility(.{
        .format_id = format_id,
        .format_version = format_version,
        .bytes = encoded,
    }, .{ .qpack_blocked_streams = 1 }));
    try testing.expectEqual(Compatibility.missing_state, compatibility(null, .{}));
    try testing.expectEqual(Compatibility.malformed_state, compatibility(.{
        .format_id = format_id,
        .format_version = format_version + 1,
        .bytes = encoded,
    }, .{}));
}
