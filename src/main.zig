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
    try configureErrorLog(&cfg);
    try writePidFile(&cfg);
    defer removePidFile(&cfg);
    if (validate_flag) {
        std.debug.print("configuration valid\\n", .{});
        return;
    }

    try edge_gateway.run(&cfg);
}

fn configureErrorLog(cfg: *const edge_config.EdgeConfig) !void {
    if (cfg.error_log_path.len == 0 or std.ascii.eqlIgnoreCase(cfg.error_log_path, "stderr")) return;
    var file = try std.fs.cwd().createFile(cfg.error_log_path, .{ .truncate = false, .read = false });
    defer file.close();
    try file.seekFromEnd(0);
    try std.posix.dup2(file.handle, std.io.getStdErr().handle);
}

fn writePidFile(cfg: *const edge_config.EdgeConfig) !void {
    if (cfg.pid_file.len == 0) return;
    var file = try std.fs.cwd().createFile(cfg.pid_file, .{ .truncate = true, .read = false });
    defer file.close();
    try file.writer().print("{d}\n", .{std.posix.getpid()});
}

fn removePidFile(cfg: *const edge_config.EdgeConfig) void {
    if (cfg.pid_file.len == 0) return;
    std.fs.cwd().deleteFile(cfg.pid_file) catch {};
}

test {
    _ = @import("http.zig");
    _ = @import("edge_config.zig");
    _ = @import("edge_gateway.zig");
}
