const std = @import("std");
const compat = @import("zig_compat");

fn parseUrl(url: []const u8) !struct { host: []const u8, port: []const u8 } {
    const prefix = "https://";
    if (!std.mem.startsWith(u8, url, prefix)) return error.InvalidUrl;
    const rest = url[prefix.len..];
    const slash = std.mem.findScalar(u8, rest, '/') orelse return error.InvalidUrl;
    const authority = rest[0..slash];
    const colon = std.mem.findScalarLast(u8, authority, ':') orelse return error.InvalidUrl;
    return .{
        .host = authority[0..colon],
        .port = authority[colon + 1 ..],
    };
}

fn extractStatus(output: []const u8) ?u16 {
    const marker = "[:status: ";
    const start = std.mem.find(u8, output, marker) orelse return null;
    const value_start = start + marker.len;
    const value_end = std.mem.findScalarPos(u8, output, value_start, ']') orelse return null;
    return std.fmt.parseInt(u16, output[value_start..value_end], 10) catch null;
}

fn countOccurrences(haystack: []const u8, needle: []const u8) usize {
    var count: usize = 0;
    var cursor: usize = 0;
    while (std.mem.findPos(u8, haystack, cursor, needle)) |idx| {
        count += 1;
        cursor = idx + needle.len;
    }
    return count;
}

fn runOsslClient(allocator: std.mem.Allocator, timeout_seconds: []const u8, args: []const []const u8) !std.process.RunResult {
    var argv = std.ArrayList([]const u8).empty;
    defer argv.deinit(allocator);
    try argv.appendSlice(allocator, &.{ "perl", "-e", "alarm shift; exec @ARGV", timeout_seconds });
    try argv.appendSlice(allocator, args);
    return try std.process.run(allocator, compat.io(), .{
        .argv = argv.items,
    });
}

pub fn main(init: std.process.Init) !u8 {
    var arena_state = std.heap.ArenaAllocator.init(init.gpa);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var arg_it = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.gpa);
    defer arg_it.deinit();

    const argv0 = arg_it.next() orelse "http3_resumption_client";
    const osslclient_bin = arg_it.next() orelse {
        std.debug.print("usage: {s} <osslclient_bin> <request_url> <expected_status>\n", .{argv0});
        return 2;
    };
    const request_url = arg_it.next() orelse {
        std.debug.print("usage: {s} <osslclient_bin> <request_url> <expected_status>\n", .{argv0});
        return 2;
    };
    const expected_status_str = arg_it.next() orelse {
        std.debug.print("usage: {s} <osslclient_bin> <request_url> <expected_status>\n", .{argv0});
        return 2;
    };
    if (arg_it.next() != null) {
        std.debug.print("usage: {s} <osslclient_bin> <request_url> <expected_status>\n", .{argv0});
        return 2;
    }

    const expected_status = try std.fmt.parseInt(u16, expected_status_str, 10);
    const parsed = try parseUrl(request_url);

    var rand_buf: [8]u8 = undefined;
    compat.randomBytes(&rand_buf);
    const run_id = std.fmt.bytesToHex(rand_buf, .lower);
    const base_dir_path = try std.fmt.allocPrint(allocator, ".zig-cache/http3-resumption-{s}", .{run_id});
    try compat.cwd().makePath(base_dir_path);
    defer compat.cwd().deleteTree(base_dir_path) catch {}; // best-effort cleanup; ephemeral test cache directory

    const session_path = try std.fmt.allocPrint(allocator, "{s}/session.pem", .{base_dir_path});
    const tp_path = try std.fmt.allocPrint(allocator, "{s}/transport-params.bin", .{base_dir_path});

    const warm = try runOsslClient(allocator, "20", &.{
        osslclient_bin,
        "--exit-on-all-streams-close",
        "--session-file",
        session_path,
        "--tp-file",
        tp_path,
        "--wait-for-ticket",
        parsed.host,
        parsed.port,
        request_url,
    });
    const resumed = try runOsslClient(allocator, "20", &.{
        osslclient_bin,
        "--exit-on-all-streams-close",
        "--session-file",
        session_path,
        "--tp-file",
        tp_path,
        parsed.host,
        parsed.port,
        request_url,
    });

    const warm_status = extractStatus(warm.stdout) orelse extractStatus(warm.stderr) orelse 0;
    const resumed_status = extractStatus(resumed.stdout) orelse extractStatus(resumed.stderr) orelse 0;
    const zero_rtt_count = countOccurrences(resumed.stdout, "type=0RTT") + countOccurrences(resumed.stderr, "type=0RTT");

    var stdout_buf: [512]u8 = undefined;
    var stdout = compat.stdoutWriter(&stdout_buf);
    try stdout.print(
        "{{\"warm_status\":{d},\"resumed_status\":{d},\"resumed_zero_rtt_count\":{d},\"warm_stdout_bytes\":{d},\"resumed_stdout_bytes\":{d}}}\n",
        .{ warm_status, resumed_status, zero_rtt_count, warm.stdout.len, resumed.stdout.len },
    );
    try stdout.flush();

    if (warm_status == expected_status and resumed_status == expected_status and zero_rtt_count > 0) {
        return 0;
    }

    var stderr_buf: [512]u8 = undefined;
    var stderr = compat.stderrWriter(&stderr_buf);
    try stderr.print(
        "unexpected outcome: warm_term={any} resumed_term={any} warm_status={d} resumed_status={d} resumed_zero_rtt_count={d}\n",
        .{ warm.term, resumed.term, warm_status, resumed_status, zero_rtt_count },
    );
    try stderr.flush();
    return 1;
}
