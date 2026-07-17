const std = @import("std");
const compat = @import("zig_compat");

pub const default_deadline_ms: u32 = 10_000;
pub const extended_deadline_ms: u32 = 30_000;

pub const Outcome = union(enum) {
    normal_exit: u8,
    launch_failure,
    timeout,
    signal: std.posix.SIG,
    unexpected_exit_code: u8,
    stdout_limit_exceeded,
    stderr_limit_exceeded,
    malformed_validator_output,
};

pub const Options = struct {
    argv: []const []const u8,
    stdout_limit: usize,
    stderr_limit: usize,
    deadline_ms: u32 = default_deadline_ms,
    accepted_exit_codes: []const u8 = &.{0},
    cwd: std.process.Child.Cwd = .inherit,
};

pub const Result = struct {
    outcome: Outcome,
    stdout: []u8,
    stderr: []u8,
    diagnostic: []u8,

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
        allocator.free(self.diagnostic);
        self.* = undefined;
    }

    pub fn malformedValidatorOutput(
        allocator: std.mem.Allocator,
        stdout: []const u8,
        stderr: []const u8,
        comptime fmt: []const u8,
        args: anytype,
    ) !Result {
        const owned_stdout = try boundedDupe(allocator, stdout, 2048);
        errdefer allocator.free(owned_stdout);
        const owned_stderr = try boundedDupe(allocator, stderr, 2048);
        errdefer allocator.free(owned_stderr);
        return .{
            .outcome = .malformed_validator_output,
            .stdout = owned_stdout,
            .stderr = owned_stderr,
            .diagnostic = try std.fmt.allocPrint(allocator, fmt, args),
        };
    }
};

pub fn run(allocator: std.mem.Allocator, options: Options) std.mem.Allocator.Error!Result {
    const io = compat.io();
    var child = std.process.spawn(io, .{
        .argv = options.argv,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
        .cwd = options.cwd,
    }) catch |err| {
        return launchFailureResult(allocator, "launch failed: {s}", .{@errorName(err)});
    };
    var reaped = false;
    defer if (!reaped) child.kill(io);

    var multi_reader_buffer: std.Io.File.MultiReader.Buffer(2) = undefined;
    var multi_reader: std.Io.File.MultiReader = undefined;
    multi_reader.init(allocator, io, multi_reader_buffer.toStreams(), &.{ child.stdout.?, child.stderr.? });
    var reader_active = true;
    defer if (reader_active) multi_reader.deinit();

    const stdout_reader = multi_reader.reader(0);
    const stderr_reader = multi_reader.reader(1);
    const deadline = if (options.deadline_ms == 0)
        std.Io.Timeout.none
    else
        (std.Io.Timeout{ .duration = .{ .raw = .fromMilliseconds(options.deadline_ms), .clock = .awake } }).toDeadline(io);

    while (multi_reader.fill(64, deadline)) |_| {
        if (stdout_reader.buffered().len > options.stdout_limit) {
            return killedResult(
                allocator,
                &child,
                &reaped,
                &multi_reader,
                &reader_active,
                .stdout_limit_exceeded,
                options.stdout_limit,
                options.stderr_limit,
            );
        }
        if (stderr_reader.buffered().len > options.stderr_limit) {
            return killedResult(
                allocator,
                &child,
                &reaped,
                &multi_reader,
                &reader_active,
                .stderr_limit_exceeded,
                options.stdout_limit,
                options.stderr_limit,
            );
        }
    } else |err| switch (err) {
        error.EndOfStream => {},
        error.Timeout => return killedResult(
            allocator,
            &child,
            &reaped,
            &multi_reader,
            &reader_active,
            .timeout,
            options.stdout_limit,
            options.stderr_limit,
        ),
        else => return killedResult(
            allocator,
            &child,
            &reaped,
            &multi_reader,
            &reader_active,
            .launch_failure,
            options.stdout_limit,
            options.stderr_limit,
        ),
    }

    multi_reader.checkAnyError() catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return killedResult(
            allocator,
            &child,
            &reaped,
            &multi_reader,
            &reader_active,
            .launch_failure,
            options.stdout_limit,
            options.stderr_limit,
        ),
    };

    const term = child.wait(io) catch |err| {
        return failureFromBuffered(
            allocator,
            &multi_reader,
            options.stdout_limit,
            options.stderr_limit,
            .launch_failure,
            "wait failed: {s}",
            .{@errorName(err)},
        );
    };
    reaped = true;

    const outcome: Outcome = switch (term) {
        .exited => |code| if (isAcceptedExit(code, options.accepted_exit_codes))
            .{ .normal_exit = code }
        else
            .{ .unexpected_exit_code = code },
        .signal => |sig| .{ .signal = sig },
        .stopped => |sig| .{ .signal = sig },
        .unknown => .launch_failure,
    };

    const stdout = try multi_reader.toOwnedSlice(0);
    errdefer allocator.free(stdout);
    const stderr = try multi_reader.toOwnedSlice(1);
    errdefer allocator.free(stderr);
    reader_active = false;
    multi_reader.deinit();

    return .{
        .outcome = outcome,
        .stdout = stdout,
        .stderr = stderr,
        .diagnostic = try diagnosticFor(allocator, outcome, stdout, stderr),
    };
}

fn launchFailureResult(
    allocator: std.mem.Allocator,
    comptime fmt: []const u8,
    args: anytype,
) std.mem.Allocator.Error!Result {
    const stdout = try allocator.dupe(u8, "");
    errdefer allocator.free(stdout);
    const stderr = try allocator.dupe(u8, "");
    errdefer allocator.free(stderr);
    return .{
        .outcome = .launch_failure,
        .stdout = stdout,
        .stderr = stderr,
        .diagnostic = try std.fmt.allocPrint(allocator, fmt, args),
    };
}

fn killedResult(
    allocator: std.mem.Allocator,
    child: *std.process.Child,
    reaped: *bool,
    multi_reader: *std.Io.File.MultiReader,
    reader_active: *bool,
    outcome: Outcome,
    stdout_limit: usize,
    stderr_limit: usize,
) std.mem.Allocator.Error!Result {
    const stdout = try boundedDupe(allocator, multi_reader.reader(0).buffered(), stdout_limit);
    errdefer allocator.free(stdout);
    const stderr = try boundedDupe(allocator, multi_reader.reader(1).buffered(), stderr_limit);
    errdefer allocator.free(stderr);
    reader_active.* = false;
    multi_reader.deinit();
    child.kill(compat.io());
    reaped.* = true;
    return .{
        .outcome = outcome,
        .stdout = stdout,
        .stderr = stderr,
        .diagnostic = try diagnosticFor(allocator, outcome, stdout, stderr),
    };
}

fn failureFromBuffered(
    allocator: std.mem.Allocator,
    multi_reader: *std.Io.File.MultiReader,
    stdout_limit: usize,
    stderr_limit: usize,
    outcome: Outcome,
    comptime fmt: []const u8,
    args: anytype,
) std.mem.Allocator.Error!Result {
    const stdout = try boundedDupe(allocator, multi_reader.reader(0).buffered(), stdout_limit);
    errdefer allocator.free(stdout);
    const stderr = try boundedDupe(allocator, multi_reader.reader(1).buffered(), stderr_limit);
    errdefer allocator.free(stderr);
    return .{
        .outcome = outcome,
        .stdout = stdout,
        .stderr = stderr,
        .diagnostic = try std.fmt.allocPrint(allocator, fmt, args),
    };
}

fn diagnosticFor(allocator: std.mem.Allocator, outcome: Outcome, stdout: []const u8, stderr: []const u8) ![]u8 {
    const preferred = if (stderr.len != 0) stderr else stdout;
    const trimmed = std.mem.trim(u8, preferred, " \t\r\n");
    const detail = if (trimmed.len == 0) "no diagnostic" else trimmed[0..@min(trimmed.len, 2048)];
    return switch (outcome) {
        .normal_exit => allocator.dupe(u8, detail),
        .launch_failure => std.fmt.allocPrint(allocator, "process failure: {s}", .{detail}),
        .timeout => std.fmt.allocPrint(allocator, "process timed out: {s}", .{detail}),
        .signal => |sig| std.fmt.allocPrint(allocator, "process terminated by signal {d}: {s}", .{ @intFromEnum(sig), detail }),
        .unexpected_exit_code => |code| std.fmt.allocPrint(allocator, "unexpected exit code {d}: {s}", .{ code, detail }),
        .stdout_limit_exceeded => std.fmt.allocPrint(allocator, "stdout limit exceeded: {s}", .{detail}),
        .stderr_limit_exceeded => std.fmt.allocPrint(allocator, "stderr limit exceeded: {s}", .{detail}),
        .malformed_validator_output => std.fmt.allocPrint(allocator, "malformed validator output: {s}", .{detail}),
    };
}

fn boundedDupe(allocator: std.mem.Allocator, bytes: []const u8, limit: usize) ![]u8 {
    return allocator.dupe(u8, bytes[0..@min(bytes.len, limit)]);
}

fn isAcceptedExit(code: u8, accepted: []const u8) bool {
    for (accepted) |candidate| {
        if (candidate == code) return true;
    }
    return false;
}
