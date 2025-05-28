const std = @import("std");

pub fn main() !void {
    const address = try std.net.Address.parseIp("0.0.0.0", 8069);

    var server = try std.net.Address.listen(address, .{
        .reuse_address = true,
    });
    defer server.deinit();

    std.debug.print("Listening on 0.0.0.0:8069\n", .{});

    while (true) {
        const conn = try server.accept();
        defer conn.stream.close();
        try handleConnection(&conn.stream);
    }
}

fn handleConnection(stream: *const std.net.Stream) !void {

    var reader = stream.reader();
    var writer = stream.writer();

    var buf: [1024]u8 = undefined;
    const request_line = try reader.readUntilDelimiterOrEof(&buf, '\n');
    if (request_line) |line| {
        const method = line[0..3];
        const path_start = 4;
        const path_end = std.mem.indexOf(u8, line, " HTTP") orelse line.len;
        const path = line[path_start..path_end];

        std.debug.print("Received {s} {s}\n", .{ method, path });

        if (std.mem.eql(u8, method, "GET")) {
            try serveFile(path, writer);
        } else {
            try writer.writeAll("HTTP/1.1 405 Method Not Allowed\r\n\r\n");
        }
    }
}

fn serveFile(path: []const u8, writer: anytype) !void {
    const fs_path = if (std.mem.eql(u8, path, "/")) "public/index.html" else blk: {
        var buffer: [256]u8 = undefined;
        const result = try std.fmt.bufPrint(&buffer, "public{s}", .{path});
        break :blk result;
    };

    var file = std.fs.cwd().openFile(fs_path, .{}) catch {
        try writer.writeAll("HTTP/1.1 404 Not Found\r\n\r\nNot Found");
        return;
    };
    defer file.close();

    try writer.writeAll("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n");

    var file_reader = file.reader();
    var buf: [1024]u8 = undefined;
    while (true) {
        const n = try file_reader.read(&buf);
        if (n == 0) break;
        try writer.writeAll(buf[0..n]);
    }
}
