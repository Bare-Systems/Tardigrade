const std = @import("std");
const io = std.Io.Threaded.global_single_threaded.io();

pub fn main(init: std.process.Init.Minimal) !void {
    var args = init.args.iterate();
    _ = args.next() orelse return error.MissingExecutablePath;
    const mode = args.next() orelse return error.MissingMode;
    if (std.mem.eql(u8, mode, "success")) {
        try writeFd(1, "ok\n");
        return;
    }
    if (std.mem.eql(u8, mode, "exit")) {
        const code = try std.fmt.parseInt(u8, args.next() orelse return error.MissingStatus, 10);
        std.process.exit(code);
    }
    if (std.mem.eql(u8, mode, "stdout")) {
        const len = try std.fmt.parseInt(usize, args.next() orelse return error.MissingLength, 10);
        try writeRepeated(1, 'o', len);
        return;
    }
    if (std.mem.eql(u8, mode, "stderr")) {
        const len = try std.fmt.parseInt(usize, args.next() orelse return error.MissingLength, 10);
        try writeRepeated(2, 'e', len);
        return;
    }
    if (std.mem.eql(u8, mode, "malformed")) {
        try writeFd(1, "{not-json\n");
        return;
    }
    if (std.mem.eql(u8, mode, "hang")) {
        const pid = std.c.getpid();
        var buf: [64]u8 = undefined;
        const line = try std.fmt.bufPrint(&buf, "pid={d}\n", .{pid});
        try writeFd(1, line);
        hangForever();
    }
    if (std.mem.eql(u8, mode, "close-stdio-hang")) {
        const pid = std.c.getpid();
        var buf: [64]u8 = undefined;
        const line = try std.fmt.bufPrint(&buf, "pid={d}\n", .{pid});
        try writeFd(1, line);
        _ = std.c.close(1);
        _ = std.c.close(2);
        hangForever();
    }
    if (std.mem.eql(u8, mode, "spawn-grandchild-and-hang")) {
        const tmp_dir = args.next() orelse return error.MissingTempDir;
        const pid = std.c.getpid();
        var parent_buf: [64]u8 = undefined;
        const parent_line = try std.fmt.bufPrint(&parent_buf, "pid={d}\n", .{pid});
        try writeFd(1, parent_line);
        try touchAndRemoveMarker(tmp_dir, "parent.marker");

        const child_pid = std.c.fork();
        if (child_pid < 0) return error.ForkFailed;
        if (child_pid == 0) {
            const grandchild_pid = std.c.getpid();
            var child_buf: [96]u8 = undefined;
            const child_line = try std.fmt.bufPrint(&child_buf, "grandchild_pid={d}\n", .{grandchild_pid});
            try writeFd(1, child_line);
            hangForever();
        }
        hangForever();
    }
    if (std.mem.eql(u8, mode, "abort")) {
        switch (@import("builtin").os.tag) {
            .windows => @panic("abnormal termination"),
            else => {
                try std.posix.raise(.ABRT);
                unreachable;
            },
        }
    }
    return error.UnknownMode;
}

fn hangForever() noreturn {
    var ts = std.c.timespec{ .sec = 10, .nsec = 0 };
    while (true) {
        _ = std.posix.system.nanosleep(&ts, &ts);
    }
}

fn touchAndRemoveMarker(tmp_dir: []const u8, name: []const u8) !void {
    var dir = try std.Io.Dir.cwd().openDir(io, tmp_dir, .{});
    defer dir.close(io);
    var file = try dir.createFile(io, name, .{});
    file.close(io);
    try dir.deleteFile(io, name);
}

fn writeRepeated(fd: c_int, byte: u8, len: usize) !void {
    var buf: [1024]u8 = undefined;
    @memset(&buf, byte);
    var remaining = len;
    while (remaining > 0) {
        const n = @min(remaining, buf.len);
        try writeFd(fd, buf[0..n]);
        remaining -= n;
    }
}

fn writeFd(fd: c_int, bytes: []const u8) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = std.c.write(fd, bytes.ptr + written, bytes.len - written);
        if (n <= 0) return error.WriteFailed;
        written += @intCast(n);
    }
}
