const std = @import("std");
const edge_config = @import("edge_config.zig");
const edge_gateway = @import("edge_gateway.zig");
const http = @import("http.zig");

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
    const worker_mode = hasArg(args, "--worker");
    const worker_id = parseWorkerIdArg(args) orelse 0;

    var cfg = try edge_config.loadFromEnv(allocator);
    defer cfg.deinit(allocator);
    try edge_config.validate(&cfg);
    try configureErrorLog(&cfg);
    try writePidFile(&cfg);
    defer removePidFile(&cfg);
    if (validate_flag) {
        std.debug.print("configuration valid\n", .{});
        return;
    }

    if (cfg.master_process_enabled and !worker_mode) {
        try runMaster(allocator, &cfg);
        return;
    }

    applyWorkerCpuAffinity(&cfg, worker_id) catch {};
    startWorkerRecycleTimer(&cfg);
    try edge_gateway.run(&cfg);
}

fn configureErrorLog(cfg: *const edge_config.EdgeConfig) !void {
    if (cfg.error_log_path.len == 0 or std.ascii.eqlIgnoreCase(cfg.error_log_path, "stderr")) return;
    const rotate_max_bytes = parseIntEnv(usize, "TARDIGRADE_LOG_ROTATE_MAX_BYTES", 0);
    const rotate_max_files = parseIntEnv(usize, "TARDIGRADE_LOG_ROTATE_MAX_FILES", 5);
    if (rotate_max_bytes > 0) {
        const stat = std.fs.cwd().statFile(cfg.error_log_path) catch null;
        if (stat != null and stat.?.size >= rotate_max_bytes) {
            try rotateLogFiles(std.fs.cwd(), cfg.error_log_path, rotate_max_files);
        }
    }
    var file = try std.fs.cwd().createFile(cfg.error_log_path, .{ .truncate = false, .read = false });
    defer file.close();
    try file.seekFromEnd(0);
    try std.posix.dup2(file.handle, std.io.getStdErr().handle);
}

fn reopenErrorLog(cfg: *const edge_config.EdgeConfig) !void {
    if (cfg.error_log_path.len == 0 or std.ascii.eqlIgnoreCase(cfg.error_log_path, "stderr")) return;
    var file = try std.fs.cwd().createFile(cfg.error_log_path, .{ .truncate = false, .read = false });
    defer file.close();
    try file.seekFromEnd(0);
    try std.posix.dup2(file.handle, std.io.getStdErr().handle);
}

fn parseIntEnv(comptime T: type, key: []const u8, default: T) T {
    const raw = std.process.getEnvVarOwned(std.heap.page_allocator, key) catch return default;
    defer std.heap.page_allocator.free(raw);
    return std.fmt.parseInt(T, std.mem.trim(u8, raw, " \t\r\n"), 10) catch default;
}

fn rotateLogFiles(dir: std.fs.Dir, path: []const u8, max_files: usize) !void {
    if (max_files == 0) {
        dir.deleteFile(path) catch {};
        return;
    }
    const oldest = try std.fmt.allocPrint(std.heap.page_allocator, "{s}.{d}", .{ path, max_files });
    defer std.heap.page_allocator.free(oldest);
    dir.deleteFile(oldest) catch {};

    var idx = max_files;
    while (idx > 1) : (idx -= 1) {
        const src = try std.fmt.allocPrint(std.heap.page_allocator, "{s}.{d}", .{ path, idx - 1 });
        defer std.heap.page_allocator.free(src);
        const dst = try std.fmt.allocPrint(std.heap.page_allocator, "{s}.{d}", .{ path, idx });
        defer std.heap.page_allocator.free(dst);
        dir.rename(src, dst) catch {};
    }
    const first = try std.fmt.allocPrint(std.heap.page_allocator, "{s}.1", .{path});
    defer std.heap.page_allocator.free(first);
    try dir.rename(path, first);
}

fn writePidFile(cfg: *const edge_config.EdgeConfig) !void {
    if (cfg.pid_file.len == 0) return;
    var file = try std.fs.cwd().createFile(cfg.pid_file, .{ .truncate = true, .read = false });
    defer file.close();
    try file.writer().print("{d}\n", .{std.c.getpid()});
}

fn removePidFile(cfg: *const edge_config.EdgeConfig) void {
    if (cfg.pid_file.len == 0) return;
    std.fs.cwd().deleteFile(cfg.pid_file) catch {};
}

fn hasArg(args: []const []const u8, target: []const u8) bool {
    for (args) |arg| {
        if (std.mem.eql(u8, arg, target)) return true;
    }
    return false;
}

fn parseWorkerIdArg(args: []const []const u8) ?usize {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--worker-id") and i + 1 < args.len) {
            return std.fmt.parseInt(usize, args[i + 1], 10) catch 0;
        }
        if (std.mem.startsWith(u8, args[i], "--worker-id=")) {
            return std.fmt.parseInt(usize, args[i]["--worker-id=".len..], 10) catch 0;
        }
    }
    return null;
}

fn startWorkerRecycleTimer(cfg: *const edge_config.EdgeConfig) void {
    if (cfg.worker_recycle_seconds == 0) return;
    const secs = cfg.worker_recycle_seconds;
    _ = std.Thread.spawn(.{}, struct {
        fn run(wait_secs: u32) void {
            std.time.sleep(@as(u64, wait_secs) * std.time.ns_per_s);
            http.shutdown.requestShutdown();
        }
    }.run, .{secs}) catch {};
}

fn runMaster(allocator: std.mem.Allocator, cfg: *const edge_config.EdgeConfig) !void {
    http.shutdown.installSignalHandlers();
    const exe_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(exe_path);
    const worker_count: usize = if (cfg.worker_processes == 0)
        (std.Thread.getCpuCount() catch 1)
    else
        @as(usize, @intCast(@max(cfg.worker_processes, 1)));
    var children = try allocator.alloc(std.process.Child, worker_count);
    defer allocator.free(children);

    for (0..worker_count) |i| {
        children[i] = try spawnWorker(allocator, exe_path, i);
    }

    while (!http.shutdown.isShutdownRequested()) {
        if (cfg.binary_upgrade_enabled and http.shutdown.consumeUpgradeRequested()) {
            _ = try spawnMasterUpgrade(allocator, exe_path);
            http.shutdown.requestShutdown();
            break;
        }
        if (http.shutdown.consumeReopenLogsRequested()) {
            reopenErrorLog(cfg) catch {};
        }

        for (0..worker_count) |i| {
            const wait_result = std.posix.waitpid(children[i].id, std.posix.W.NOHANG);
            if (wait_result.pid == children[i].id and !http.shutdown.isShutdownRequested()) {
                children[i] = try spawnWorker(allocator, exe_path, i);
            }
        }
        std.time.sleep(250 * std.time.ns_per_ms);
    }

    for (0..worker_count) |i| {
        _ = children[i].kill() catch {};
        _ = children[i].wait() catch {};
    }
}

fn spawnWorker(allocator: std.mem.Allocator, exe_path: []const u8, worker_id: usize) !std.process.Child {
    const id_str = try std.fmt.allocPrint(allocator, "{d}", .{worker_id});
    var argv = [_][]const u8{ exe_path, "--worker", "--worker-id", id_str };
    var child = std.process.Child.init(&argv, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    errdefer allocator.free(id_str);
    try child.spawn();
    allocator.free(id_str);
    return child;
}

fn spawnMasterUpgrade(allocator: std.mem.Allocator, exe_path: []const u8) !std.process.Child {
    var argv = [_][]const u8{exe_path};
    var child = std.process.Child.init(&argv, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    try child.spawn();
    return child;
}

fn applyWorkerCpuAffinity(cfg: *const edge_config.EdgeConfig, worker_id: usize) !void {
    if (cfg.worker_cpu_affinity.len == 0) return;
    if (@import("builtin").os.tag != .linux) return;
    var cpus_buf: [64]u32 = undefined;
    var count: usize = 0;
    var it = std.mem.splitScalar(u8, cfg.worker_cpu_affinity, ',');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (trimmed.len == 0) continue;
        if (count >= cpus_buf.len) break;
        cpus_buf[count] = std.fmt.parseInt(u32, trimmed, 10) catch continue;
        count += 1;
    }
    if (count == 0) return;
    const cpu = cpus_buf[worker_id % count];
    try setLinuxCpuAffinity(cpu);
}

fn setLinuxCpuAffinity(cpu: u32) !void {
    if (@import("builtin").os.tag != .linux) {
        return error.CpuAffinityUnsupported;
    }
    const linux = struct {
        const cpu_set_bits = 1024;
        const CpuMaskWord = usize;
        const word_bits = @bitSizeOf(CpuMaskWord);
        const word_count = cpu_set_bits / word_bits;

        const CpuSet = extern struct {
            bits: [word_count]CpuMaskWord = [_]CpuMaskWord{0} ** word_count,
        };

        extern "c" fn getpid() std.c.pid_t;
        extern "c" fn sched_setaffinity(pid: std.c.pid_t, cpusetsize: usize, mask: *const CpuSet) c_int;
    };
    if (cpu >= linux.cpu_set_bits) {
        return error.CpuAffinityUnsupported;
    }
    var mask = linux.CpuSet{};
    const word_index: usize = @intCast(cpu / linux.word_bits);
    const bit_index = cpu % linux.word_bits;
    mask.bits[word_index] |= @as(linux.CpuMaskWord, 1) << @intCast(bit_index);
    if (linux.sched_setaffinity(linux.getpid(), @sizeOf(linux.CpuSet), &mask) != 0) {
        return error.CpuAffinityFailed;
    }
}

test {
    _ = @import("http.zig");
    _ = @import("edge_config.zig");
    _ = @import("edge_gateway.zig");
}

test "rotateLogFiles shifts generations" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "error.log", .data = "latest" });
    try tmp.dir.writeFile(.{ .sub_path = "error.log.1", .data = "older" });

    try rotateLogFiles(tmp.dir, "error.log", 3);

    _ = try tmp.dir.statFile("error.log.1");
    _ = try tmp.dir.statFile("error.log.2");
}

test "rotateLogFiles deletes source when max_files is zero" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(.{ .sub_path = "error.log", .data = "latest" });
    try rotateLogFiles(tmp.dir, "error.log", 0);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile("error.log"));
}
