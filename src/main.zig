const std = @import("std");
const edge_config = @import("edge_config.zig");
const edge_gateway = @import("edge_gateway.zig");
const http = @import("http.zig");

const ENV_CONFIG_PATH = "TARDIGRADE_CONFIG_PATH";

const CliCommand = union(enum) {
    run: RunOptions,
    validate: CommonOptions,
    reload: SignalOptions,
    stop: SignalOptions,
    version,
    help,
    config_init: ConfigInitOptions,
};

const CommonOptions = struct {
    config_path: ?[]const u8 = null,
};

const RunOptions = struct {
    common: CommonOptions = .{},
    daemon: bool = false,
    daemonized: bool = false,
};

const SignalOptions = struct {
    common: CommonOptions = .{},
    pid_file: ?[]const u8 = null,
    pid: ?std.posix.pid_t = null,
};

const ConfigInitOptions = struct {
    output_path: []const u8 = "tardigrade.conf",
    force: bool = false,
    stdout: bool = false,
};

const starter_config =
    \\# Tardigrade starter config.
    \\# All HTTP request-path behavior is config-defined.
    \\
    \\pid /var/run/tardigrade.pid;
    \\listen 8069;
    \\server_name localhost;
    \\
    \\root ./public;
    \\try_files $uri /index.html;
    \\
    \\location = / {
    \\    return 302 /index.html;
    \\}
    \\
    \\location / {
    \\    root ./public;
    \\    try_files $uri /index.html;
    \\}
    \\
    \\# Example reverse-proxy route:
    \\# location = /v1/chat {
    \\#     proxy_pass http://127.0.0.1:8080/v1/chat;
    \\# }
    \\
;

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const command = parseCliCommand(args[1..]) catch |err| {
        try printUsage(std.io.getStdErr().writer());
        return err;
    };

    switch (command) {
        .help => try printUsage(std.io.getStdOut().writer()),
        .version => try std.io.getStdOut().writer().print("{s}\n", .{http.SERVER_VERSION}),
        .config_init => |options| try writeStarterConfig(options),
        .reload => |options| try executeSignalCommand(allocator, "reload", std.posix.SIG.HUP, options),
        .stop => |options| try executeSignalCommand(allocator, "stop", std.posix.SIG.TERM, options),
        .validate => |options| try executeValidateCommand(allocator, options),
        .run => |options| {
            if (environmentRequestsValidate()) {
                try executeValidateCommand(allocator, options.common);
                return;
            }
            try executeRunCommand(allocator, args, options);
        },
    }
}

fn parseCliCommand(args: []const []const u8) !CliCommand {
    if (args.len == 0) return .{ .run = .{} };

    const first = args[0];
    if (std.mem.eql(u8, first, "help") or std.mem.eql(u8, first, "-h") or std.mem.eql(u8, first, "--help")) {
        return .help;
    }
    if (std.mem.eql(u8, first, "version")) return .version;
    if (std.mem.eql(u8, first, "run")) return try parseRunCommand(args[1..]);
    if (std.mem.eql(u8, first, "validate")) return try parseValidateCommand(args[1..]);
    if (std.mem.eql(u8, first, "reload")) return try parseSignalCommand(.reload, args[1..]);
    if (std.mem.eql(u8, first, "stop")) return try parseSignalCommand(.stop, args[1..]);
    if (std.mem.eql(u8, first, "config")) {
        if (args.len >= 2 and std.mem.eql(u8, args[1], "init")) return try parseConfigInitCommand(args[2..]);
        return error.InvalidCommand;
    }

    return try parseRunCommand(args);
}

fn parseRunCommand(args: []const []const u8) !CliCommand {
    var options = RunOptions{};
    var validate_only = false;
    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) return .help;
        if (std.mem.eql(u8, arg, "--validate-config")) {
            validate_only = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--daemon")) {
            options.daemon = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--daemonized")) {
            options.daemonized = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--worker")) continue;
        if (std.mem.eql(u8, arg, "--worker-id")) {
            if (idx + 1 >= args.len) return error.MissingOptionValue;
            idx += 1;
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--worker-id=")) continue;
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            if (idx + 1 >= args.len) return error.MissingOptionValue;
            options.common.config_path = args[idx + 1];
            idx += 1;
            continue;
        }
        return error.UnknownOption;
    }

    if (validate_only) return .{ .validate = options.common };
    return .{ .run = options };
}

fn parseValidateCommand(args: []const []const u8) !CliCommand {
    var options = CommonOptions{};
    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) return .help;
        if (std.mem.eql(u8, arg, "--validate-config")) continue;
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            if (idx + 1 >= args.len) return error.MissingOptionValue;
            options.config_path = args[idx + 1];
            idx += 1;
            continue;
        }
        return error.UnknownOption;
    }
    return .{ .validate = options };
}

fn parseSignalCommand(comptime kind: enum { reload, stop }, args: []const []const u8) !CliCommand {
    var options = SignalOptions{};
    var idx: usize = 0;
    while (idx < args.len) : (idx += 1) {
        const arg = args[idx];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) return .help;
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            if (idx + 1 >= args.len) return error.MissingOptionValue;
            options.common.config_path = args[idx + 1];
            idx += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--pid-file")) {
            if (idx + 1 >= args.len) return error.MissingOptionValue;
            options.pid_file = args[idx + 1];
            idx += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--pid")) {
            if (idx + 1 >= args.len) return error.MissingOptionValue;
            options.pid = try parsePid(args[idx + 1]);
            idx += 1;
            continue;
        }
        return error.UnknownOption;
    }

    return switch (kind) {
        .reload => .{ .reload = options },
        .stop => .{ .stop = options },
    };
}

fn parseConfigInitCommand(args: []const []const u8) !CliCommand {
    var options = ConfigInitOptions{};
    var saw_output = false;
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) return .help;
        if (std.mem.eql(u8, arg, "--force")) {
            options.force = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--stdout")) {
            options.stdout = true;
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-")) return error.UnknownOption;
        if (saw_output) return error.TooManyArguments;
        options.output_path = arg;
        saw_output = true;
    }
    return .{ .config_init = options };
}

fn printUsage(writer: anytype) !void {
    try writer.writeAll(
        \\Usage:
        \\  tardigrade run [-c <path>] [--daemon]
        \\  tardigrade validate [-c <path>]
        \\  tardigrade reload [-c <path>] [--pid-file <path> | --pid <pid>]
        \\  tardigrade stop [-c <path>] [--pid-file <path> | --pid <pid>]
        \\  tardigrade version
        \\  tardigrade config init [<path>] [--force | --stdout]
        \\
        \\Notes:
        \\  - Legacy `--validate-config` remains supported.
        \\  - Config discovery checks `-c/--config`, `TARDIGRADE_CONFIG_PATH`,
        \\    `./tardigrade.conf`, `./config/tardigrade.conf`,
        \\    `/etc/tardigrade/tardigrade.conf`, and
        \\    `$HOME/.config/tardigrade/tardigrade.conf`.
        \\
    );
}

fn environmentRequestsValidate() bool {
    const env = std.process.getEnvVarOwned(std.heap.page_allocator, "TARDIGRADE_VALIDATE_CONFIG_ONLY") catch return false;
    defer std.heap.page_allocator.free(env);
    return std.mem.eql(u8, env, "1") or std.ascii.eqlIgnoreCase(env, "true");
}

fn executeValidateCommand(allocator: std.mem.Allocator, options: CommonOptions) !void {
    const resolved_config_path = try resolveRuntimeConfigPath(allocator, options.config_path);
    defer if (resolved_config_path) |path| allocator.free(path);
    if (resolved_config_path) |path| try setProcessEnv(allocator, ENV_CONFIG_PATH, path);

    var cfg = try edge_config.loadFromEnv(allocator);
    defer cfg.deinit(allocator);
    try edge_config.validate(&cfg);
    std.debug.print("configuration valid\n", .{});
}

fn executeRunCommand(allocator: std.mem.Allocator, args: []const []const u8, options: RunOptions) !void {
    const resolved_config_path = try resolveRuntimeConfigPath(allocator, options.common.config_path);
    defer if (resolved_config_path) |path| allocator.free(path);
    if (resolved_config_path) |path| try setProcessEnv(allocator, ENV_CONFIG_PATH, path);

    const worker_mode = hasArg(args, "--worker");
    const worker_id = parseWorkerIdArg(args) orelse 0;

    if (options.daemon and !options.daemonized and !worker_mode) {
        try spawnDaemonizedProcess(allocator, resolved_config_path);
        return;
    }

    var cfg = try edge_config.loadFromEnv(allocator);
    defer cfg.deinit(allocator);
    try edge_config.validate(&cfg);
    try configureErrorLog(&cfg);
    try writePidFile(&cfg);
    defer removePidFile(&cfg);

    if (cfg.master_process_enabled and !worker_mode) {
        try runMaster(allocator, &cfg);
        return;
    }

    applyWorkerCpuAffinity(&cfg, worker_id) catch {};
    startWorkerRecycleTimer(&cfg);
    try edge_gateway.run(&cfg);
}

fn executeSignalCommand(
    allocator: std.mem.Allocator,
    label: []const u8,
    signal: u8,
    options: SignalOptions,
) !void {
    const pid = try resolveCommandPid(allocator, options);
    try std.posix.kill(pid, signal);
    try std.io.getStdOut().writer().print("{s} signal sent to pid {d}\n", .{ label, pid });
}

fn resolveCommandPid(allocator: std.mem.Allocator, options: SignalOptions) !std.posix.pid_t {
    if (options.pid) |pid| return pid;
    if (options.pid_file) |pid_file| return try readPidFromFile(allocator, pid_file);

    const resolved_config_path = try resolveRuntimeConfigPath(allocator, options.common.config_path);
    defer if (resolved_config_path) |path| allocator.free(path);
    if (resolved_config_path) |path| try setProcessEnv(allocator, ENV_CONFIG_PATH, path);

    var cfg = try edge_config.loadFromEnv(allocator);
    defer cfg.deinit(allocator);
    if (cfg.pid_file.len == 0) return error.MissingPidTarget;
    return try readPidFromFile(allocator, cfg.pid_file);
}

fn parsePid(value: []const u8) !std.posix.pid_t {
    const pid = try std.fmt.parseInt(std.posix.pid_t, value, 10);
    if (pid <= 0) return error.InvalidPid;
    return pid;
}

fn readPidFromFile(allocator: std.mem.Allocator, path: []const u8) !std.posix.pid_t {
    var file = try openFileAtPath(path, .{});
    defer file.close();
    const raw = try file.readToEndAlloc(allocator, 128);
    defer allocator.free(raw);
    return try parsePid(std.mem.trim(u8, raw, " \t\r\n"));
}

fn writeStarterConfig(options: ConfigInitOptions) !void {
    if (options.stdout) {
        try std.io.getStdOut().writer().writeAll(starter_config);
        return;
    }

    if (!options.force and pathExists(options.output_path)) return error.PathAlreadyExists;
    try ensureParentPath(options.output_path);
    var file = try createFileAtPath(options.output_path, .{ .truncate = true, .read = false });
    defer file.close();
    try file.writeAll(starter_config);
    try std.io.getStdOut().writer().print("wrote starter config to {s}\n", .{options.output_path});
}

fn resolveRuntimeConfigPath(allocator: std.mem.Allocator, cli_path: ?[]const u8) !?[]u8 {
    if (cli_path) |path| return try requireConfigPath(allocator, path);

    const env_path = std.process.getEnvVarOwned(allocator, ENV_CONFIG_PATH) catch "";
    defer if (env_path.len > 0) allocator.free(env_path);
    if (env_path.len > 0) return try requireConfigPath(allocator, env_path);

    const search_paths = [_][]const u8{
        "tardigrade.conf",
        "config/tardigrade.conf",
        "/etc/tardigrade/tardigrade.conf",
    };
    for (search_paths) |candidate| {
        if (pathExists(candidate)) return try allocator.dupe(u8, candidate);
    }

    const home = std.process.getEnvVarOwned(allocator, "HOME") catch "";
    defer if (home.len > 0) allocator.free(home);
    if (home.len > 0) {
        const home_candidate = try std.fmt.allocPrint(allocator, "{s}/.config/tardigrade/tardigrade.conf", .{home});
        defer allocator.free(home_candidate);
        if (pathExists(home_candidate)) return try allocator.dupe(u8, home_candidate);
    }

    return null;
}

fn requireConfigPath(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    if (path.len == 0) return error.MissingConfigPath;
    if (!pathExists(path)) return error.ConfigPathNotFound;
    return try allocator.dupe(u8, path);
}

fn setProcessEnv(allocator: std.mem.Allocator, name: []const u8, value: []const u8) !void {
    const name_z = try allocator.dupeZ(u8, name);
    defer allocator.free(name_z);
    const value_z = try allocator.dupeZ(u8, value);
    defer allocator.free(value_z);
    if (setenv(name_z.ptr, value_z.ptr, 1) != 0) return error.SetEnvFailed;
}

fn spawnDaemonizedProcess(allocator: std.mem.Allocator, config_path: ?[]const u8) !void {
    const exe_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(exe_path);

    var argv = std.ArrayList([]const u8).init(allocator);
    defer argv.deinit();
    try argv.append(exe_path);
    try argv.append("run");
    if (config_path) |path| {
        try argv.append("-c");
        try argv.append(path);
    }
    try argv.append("--daemonized");

    var child = std.process.Child.init(argv.items, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    try child.spawn();
    try std.io.getStdOut().writer().print("started tardigrade in background (pid {d})\n", .{child.id});
}

fn pathExists(path: []const u8) bool {
    if (std.fs.path.isAbsolute(path)) {
        std.fs.accessAbsolute(path, .{}) catch return false;
        return true;
    }
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

fn ensureParentPath(path: []const u8) !void {
    const parent = std.fs.path.dirname(path) orelse return;
    if (parent.len == 0 or std.mem.eql(u8, parent, ".")) return;
    if (std.fs.path.isAbsolute(parent)) {
        if (std.mem.eql(u8, parent, "/")) return;
        var root = try std.fs.openDirAbsolute("/", .{});
        defer root.close();
        try root.makePath(parent[1..]);
        return;
    }
    try std.fs.cwd().makePath(parent);
}

fn createFileAtPath(path: []const u8, flags: std.fs.File.CreateFlags) !std.fs.File {
    if (std.fs.path.isAbsolute(path)) return std.fs.createFileAbsolute(path, flags);
    return std.fs.cwd().createFile(path, flags);
}

fn openFileAtPath(path: []const u8, flags: std.fs.File.OpenFlags) !std.fs.File {
    if (std.fs.path.isAbsolute(path)) return std.fs.openFileAbsolute(path, flags);
    return std.fs.cwd().openFile(path, flags);
}

fn deleteFileAtPath(path: []const u8) !void {
    if (std.fs.path.isAbsolute(path)) return std.fs.deleteFileAbsolute(path);
    return std.fs.cwd().deleteFile(path);
}

fn openParentDirForPath(path: []const u8) !struct { dir: std.fs.Dir, basename: []const u8 } {
    const basename = std.fs.path.basename(path);
    const dirname = std.fs.path.dirname(path) orelse ".";
    const dir = if (std.fs.path.isAbsolute(path))
        try std.fs.openDirAbsolute(dirname, .{})
    else
        try std.fs.cwd().openDir(dirname, .{});
    return .{ .dir = dir, .basename = basename };
}

fn configureErrorLog(cfg: *const edge_config.EdgeConfig) !void {
    if (cfg.error_log_path.len == 0 or std.ascii.eqlIgnoreCase(cfg.error_log_path, "stderr")) return;
    const rotate_max_bytes = parseIntEnv(usize, "TARDIGRADE_LOG_ROTATE_MAX_BYTES", 0);
    const rotate_max_files = parseIntEnv(usize, "TARDIGRADE_LOG_ROTATE_MAX_FILES", 5);
    if (rotate_max_bytes > 0) {
        const stat = blk: {
            var existing = openFileAtPath(cfg.error_log_path, .{}) catch break :blk null;
            defer existing.close();
            break :blk existing.stat() catch null;
        };
        if (stat != null and stat.?.size >= rotate_max_bytes) {
            var dir_info = try openParentDirForPath(cfg.error_log_path);
            defer dir_info.dir.close();
            try rotateLogFiles(dir_info.dir, dir_info.basename, rotate_max_files);
        }
    }
    try ensureParentPath(cfg.error_log_path);
    var file = try createFileAtPath(cfg.error_log_path, .{ .truncate = false, .read = false });
    defer file.close();
    try file.seekFromEnd(0);
    try std.posix.dup2(file.handle, std.io.getStdErr().handle);
}

fn reopenErrorLog(cfg: *const edge_config.EdgeConfig) !void {
    if (cfg.error_log_path.len == 0 or std.ascii.eqlIgnoreCase(cfg.error_log_path, "stderr")) return;
    try ensureParentPath(cfg.error_log_path);
    var file = try createFileAtPath(cfg.error_log_path, .{ .truncate = false, .read = false });
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
    try ensureParentPath(cfg.pid_file);
    var file = try createFileAtPath(cfg.pid_file, .{ .truncate = true, .read = false });
    defer file.close();
    try file.writer().print("{d}\n", .{std.c.getpid()});
}

fn removePidFile(cfg: *const edge_config.EdgeConfig) void {
    if (cfg.pid_file.len == 0) return;
    deleteFileAtPath(cfg.pid_file) catch {};
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

test "parse run command supports legacy validate flag" {
    const cmd = try parseCliCommand(&.{ "--validate-config", "-c", "tardigrade.conf" });
    switch (cmd) {
        .validate => |options| try std.testing.expectEqualStrings("tardigrade.conf", options.config_path.?),
        else => return error.TestUnexpectedResult,
    }
}

test "parse config init command supports stdout" {
    const cmd = try parseCliCommand(&.{ "config", "init", "--stdout" });
    switch (cmd) {
        .config_init => |options| try std.testing.expect(options.stdout),
        else => return error.TestUnexpectedResult,
    }
}
