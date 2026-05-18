const std = @import("std");

/// One-shot CLI/control-plane commands keep debug allocator diagnostics.
pub const ControlPlaneAllocator = struct {
    debug: std.heap.DebugAllocator(.{}) = .init,

    pub fn allocator(self: *ControlPlaneAllocator) std.mem.Allocator {
        return self.debug.allocator();
    }

    pub fn deinit(self: *ControlPlaneAllocator) std.heap.Check {
        return self.debug.deinit();
    }
};

/// The shared gateway runtime uses Zig 0.16's process-wide SMP allocator.
pub fn runtimeAllocator() std.mem.Allocator {
    return std.heap.smp_allocator;
}

test "control plane allocator reports clean deinit" {
    var state = ControlPlaneAllocator{};
    const allocator = state.allocator();
    const buf = try allocator.alloc(u8, 32);
    allocator.free(buf);

    try std.testing.expect(state.deinit() == .ok);
}

test "runtime allocator allocates and frees" {
    const allocator = runtimeAllocator();
    const buf = try allocator.alloc(u8, 64);
    allocator.free(buf);
}
