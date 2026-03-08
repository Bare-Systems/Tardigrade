const std = @import("std");
const edge_config = @import("edge_config.zig");
const edge_gateway = @import("edge_gateway.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const validate_flag = blk: {
        for (args) |arg| {
            if (std.mem.eql(u8, arg, "--validate-config")) break :blk true;
        }
        const env = std.process.getEnvVarOwned(allocator, "TARDIGRADE_VALIDATE_CONFIG_ONLY") catch "";
        defer if (env.len > 0) allocator.free(env);
        break :blk std.mem.eql(u8, env, "1") or std.ascii.eqlIgnoreCase(env, "true");
    };

    var cfg = try edge_config.loadFromEnv(allocator);
    defer cfg.deinit(allocator);
    if (validate_flag) {
        std.debug.print("configuration valid\\n", .{});
        return;
    }

    try edge_gateway.run(&cfg);
}

test {
    _ = @import("http.zig");
    _ = @import("edge_config.zig");
    _ = @import("edge_gateway.zig");
}
