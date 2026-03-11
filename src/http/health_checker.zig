const std = @import("std");

pub const ProbeStatus = enum {
    up,
    down,
    half_open,

    pub fn asString(self: ProbeStatus) []const u8 {
        return switch (self) {
            .up => "up",
            .down => "down",
            .half_open => "half_open",
        };
    }
};

pub const Config = struct {
    path: []const u8 = "/",
    interval_ms: u64 = 10_000,
    timeout_ms: u32 = 2_000,
    fail_threshold: u32 = 3,
    success_threshold: u32 = 1,
    success_status_min: u16 = 200,
    success_status_max: u16 = 299,

    pub fn enabled(self: Config) bool {
        return self.interval_ms > 0;
    }

    pub fn statusIsHealthy(self: Config, status_code: u16) bool {
        return status_code >= self.success_status_min and status_code <= self.success_status_max;
    }
};

pub const Transition = enum {
    none,
    marked_down,
    entered_half_open,
    marked_up,
};

pub const State = struct {
    status: ProbeStatus = .up,
    consecutive_failures: u32 = 0,
    consecutive_successes: u32 = 0,

    pub fn isRoutable(self: State) bool {
        return self.status == .up;
    }

    pub fn recordFailure(self: *State, cfg: Config) Transition {
        self.consecutive_successes = 0;
        switch (self.status) {
            .up => {
                self.consecutive_failures +|= 1;
                if (self.consecutive_failures < cfg.fail_threshold) return .none;
                self.status = .down;
                self.consecutive_failures = 0;
                return .marked_down;
            },
            .down => {
                self.consecutive_failures = 0;
                return .none;
            },
            .half_open => {
                self.status = .down;
                self.consecutive_failures = 0;
                return .marked_down;
            },
        }
    }

    pub fn recordSuccess(self: *State, cfg: Config) Transition {
        self.consecutive_failures = 0;
        switch (self.status) {
            .up => {
                self.consecutive_successes = 0;
                return .none;
            },
            .down => {
                self.status = .half_open;
                self.consecutive_successes = 1;
                if (self.consecutive_successes >= cfg.success_threshold) {
                    self.status = .up;
                    self.consecutive_successes = 0;
                    return .marked_up;
                }
                return .entered_half_open;
            },
            .half_open => {
                self.consecutive_successes +|= 1;
                if (self.consecutive_successes < cfg.success_threshold) return .none;
                self.status = .up;
                self.consecutive_successes = 0;
                return .marked_up;
            },
        }
    }
};

pub fn buildProbeUrl(allocator: std.mem.Allocator, base_url: []const u8, probe_path: []const u8) ![]u8 {
    const base_trimmed = std.mem.trimRight(u8, base_url, "/");
    const path_trimmed = std.mem.trimLeft(u8, probe_path, "/");
    if (path_trimmed.len == 0) return std.fmt.allocPrint(allocator, "{s}/", .{base_trimmed});
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ base_trimmed, path_trimmed });
}

test "state transitions from up to down to half-open to up" {
    const cfg = Config{
        .fail_threshold = 2,
        .success_threshold = 2,
    };
    var state = State{};

    try std.testing.expectEqual(Transition.none, state.recordFailure(cfg));
    try std.testing.expectEqual(ProbeStatus.up, state.status);

    try std.testing.expectEqual(Transition.marked_down, state.recordFailure(cfg));
    try std.testing.expectEqual(ProbeStatus.down, state.status);
    try std.testing.expect(!state.isRoutable());

    try std.testing.expectEqual(Transition.entered_half_open, state.recordSuccess(cfg));
    try std.testing.expectEqual(ProbeStatus.half_open, state.status);
    try std.testing.expect(!state.isRoutable());

    try std.testing.expectEqual(Transition.marked_up, state.recordSuccess(cfg));
    try std.testing.expectEqual(ProbeStatus.up, state.status);
    try std.testing.expect(state.isRoutable());
}

test "half-open failure moves state back to down" {
    const cfg = Config{
        .fail_threshold = 1,
        .success_threshold = 2,
    };
    var state = State{};

    try std.testing.expectEqual(Transition.marked_down, state.recordFailure(cfg));
    try std.testing.expectEqual(Transition.entered_half_open, state.recordSuccess(cfg));
    try std.testing.expectEqual(ProbeStatus.half_open, state.status);

    try std.testing.expectEqual(Transition.marked_down, state.recordFailure(cfg));
    try std.testing.expectEqual(ProbeStatus.down, state.status);
}

test "config healthy status defaults to 2xx" {
    const cfg = Config{};
    try std.testing.expect(cfg.statusIsHealthy(200));
    try std.testing.expect(cfg.statusIsHealthy(299));
    try std.testing.expect(!cfg.statusIsHealthy(199));
    try std.testing.expect(!cfg.statusIsHealthy(300));
}

test "buildProbeUrl joins base and path" {
    const allocator = std.testing.allocator;
    const url = try buildProbeUrl(allocator, "http://127.0.0.1:8080/", "/");
    defer allocator.free(url);
    try std.testing.expectEqualStrings("http://127.0.0.1:8080/", url);
}
