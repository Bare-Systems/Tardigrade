//! Pure Zig QUIC/H3 configuration model (#248).
//!
//! These structs define the internal transport defaults before the pure Zig
//! implementation exists. Operator-facing env/config wiring should expose only
//! fields that are needed for safe rollout; the remaining values are internal
//! defaults until benchmarks or interop require public knobs.

const std = @import("std");

pub const QuicVersion = enum(u32) {
    v1 = 0x00000001,
    v2 = 0x6b3343cf,
};

pub const VersionSet = struct {
    v1: bool = true,
    v2: bool = false,

    pub fn supports(self: VersionSet, version: QuicVersion) bool {
        return switch (version) {
            .v1 => self.v1,
            .v2 => self.v2,
        };
    }

    pub fn preferred(self: VersionSet) ?QuicVersion {
        if (self.v1) return .v1;
        if (self.v2) return .v2;
        return null;
    }
};

pub const RetryPolicy = enum {
    off,
    address_validation,
};

pub const MigrationPolicy = enum {
    disabled,
    nat_rebinding_only,
    full,
};

pub const QpackMode = enum {
    static_only,
    dynamic,
};

pub const Observability = struct {
    qlog_enabled: bool = false,
    keylog_enabled: bool = false,
};

pub const QpackConfig = struct {
    mode: QpackMode = .static_only,
    dynamic_table_capacity: u64 = 0,
    blocked_streams: u64 = 0,
};

pub const Config = struct {
    enabled: bool = false,
    versions: VersionSet = .{},
    idle_timeout_ms: u64 = 30_000,
    active_connection_id_limit: u64 = 4,
    max_udp_payload_size: u64 = 1200,
    initial_max_data: u64 = 8 * 1024 * 1024,
    initial_max_stream_data_bidi_local: u64 = 1024 * 1024,
    initial_max_stream_data_bidi_remote: u64 = 1024 * 1024,
    initial_max_stream_data_uni: u64 = 256 * 1024,
    initial_max_streams_bidi: u64 = 100,
    initial_max_streams_uni: u64 = 16,
    retry_policy: RetryPolicy = .off,
    migration_policy: MigrationPolicy = .disabled,
    observability: Observability = .{},
    qpack: QpackConfig = .{},

    pub fn validate(self: Config) !void {
        if (self.versions.preferred() == null) return error.UnsupportedQuicVersion;
        if (self.idle_timeout_ms == 0) return error.InvalidIdleTimeout;
        if (self.active_connection_id_limit < 2) return error.InvalidActiveConnectionIdLimit;
        if (self.max_udp_payload_size < 1200 or self.max_udp_payload_size > 65_527) return error.InvalidMaxUdpPayloadSize;
        if (self.initial_max_data == 0) return error.InvalidFlowControlWindow;
        if (self.initial_max_stream_data_bidi_local > self.initial_max_data) return error.InvalidFlowControlWindow;
        if (self.initial_max_stream_data_bidi_remote > self.initial_max_data) return error.InvalidFlowControlWindow;
        if (self.initial_max_stream_data_uni > self.initial_max_data) return error.InvalidFlowControlWindow;
        if (self.initial_max_streams_bidi == 0) return error.InvalidStreamLimit;
        if (self.qpack.mode == .static_only and (self.qpack.dynamic_table_capacity != 0 or self.qpack.blocked_streams != 0)) {
            return error.InvalidQpackConfig;
        }
    }

    pub fn transportParameters(self: Config) !TransportParameters {
        try self.validate();
        return .{
            .max_idle_timeout_ms = self.idle_timeout_ms,
            .active_connection_id_limit = self.active_connection_id_limit,
            .max_udp_payload_size = self.max_udp_payload_size,
            .initial_max_data = self.initial_max_data,
            .initial_max_stream_data_bidi_local = self.initial_max_stream_data_bidi_local,
            .initial_max_stream_data_bidi_remote = self.initial_max_stream_data_bidi_remote,
            .initial_max_stream_data_uni = self.initial_max_stream_data_uni,
            .initial_max_streams_bidi = self.initial_max_streams_bidi,
            .initial_max_streams_uni = self.initial_max_streams_uni,
            .disable_active_migration = self.migration_policy == .disabled,
        };
    }
};

pub const TransportParameters = struct {
    max_idle_timeout_ms: u64,
    active_connection_id_limit: u64,
    max_udp_payload_size: u64,
    initial_max_data: u64,
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_stream_data_uni: u64,
    initial_max_streams_bidi: u64,
    initial_max_streams_uni: u64,
    disable_active_migration: bool,
};

test "default QUIC config maps to conservative transport parameters" {
    const cfg = Config{};
    const params = try cfg.transportParameters();
    try std.testing.expect(!cfg.enabled);
    try std.testing.expect(cfg.versions.supports(.v1));
    try std.testing.expect(!cfg.versions.supports(.v2));
    try std.testing.expectEqual(@as(u64, 30_000), params.max_idle_timeout_ms);
    try std.testing.expectEqual(@as(u64, 4), params.active_connection_id_limit);
    try std.testing.expectEqual(@as(u64, 1200), params.max_udp_payload_size);
    try std.testing.expect(params.disable_active_migration);
    try std.testing.expectEqual(QpackMode.static_only, cfg.qpack.mode);
}

test "QUIC config validation rejects unsafe combinations" {
    try std.testing.expectError(error.UnsupportedQuicVersion, (Config{ .versions = .{ .v1 = false, .v2 = false } }).validate());
    try std.testing.expectError(error.InvalidActiveConnectionIdLimit, (Config{ .active_connection_id_limit = 1 }).validate());
    try std.testing.expectError(error.InvalidMaxUdpPayloadSize, (Config{ .max_udp_payload_size = 1199 }).validate());
    try std.testing.expectError(error.InvalidFlowControlWindow, (Config{
        .initial_max_data = 1024,
        .initial_max_stream_data_bidi_local = 2048,
    }).validate());
    try std.testing.expectError(error.InvalidQpackConfig, (Config{
        .qpack = .{ .mode = .static_only, .dynamic_table_capacity = 4096 },
    }).validate());
}

test "migration policy maps to transport parameter" {
    const disabled = try (Config{ .migration_policy = .disabled }).transportParameters();
    const rebinding = try (Config{ .migration_policy = .nat_rebinding_only }).transportParameters();
    try std.testing.expect(disabled.disable_active_migration);
    try std.testing.expect(!rebinding.disable_active_migration);
}
