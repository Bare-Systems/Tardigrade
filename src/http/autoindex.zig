const std = @import("std");

pub const DirItem = struct {
    name: []const u8,
    is_dir: bool,
};

pub fn generateAutoIndex(allocator: std.mem.Allocator, dirPath: []const u8, uriPath: []const u8) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();

    // Build output by appending bytes
    for ("<!doctype html><html><head><meta charset=\"utf-8\">\n") |b| try out.append(b);
    for ("<title>Index of ") |b| try out.append(b);
    for (uriPath) |b| try out.append(b);
    for ("</title></head><body><h1>Index of ") |b| try out.append(b);
    for (uriPath) |b| try out.append(b);
    for ("</h1><hr><pre>\n") |b| try out.append(b);

    const fs = std.fs.cwd();
    var dir = fs.openDir(dirPath, .{}) catch |err| {
        return err;
    };
    defer dir.close();

    var items = std.ArrayList(DirItem).init(allocator);
    defer items.deinit();

    var it = dir.iterate();
    while (true) {
        const entry = try it.next();
        if (entry == null) break;
        const e = entry.?;
        if (e.name.len == 0) continue;
        // Skip dotfiles for now
        if (e.name[0] == '.') continue;

        const name_copy = try allocator.alloc(u8, e.name.len);
        var _k: usize = 0;
        for (e.name) |bb| {
            name_copy[_k] = bb;
            _k += 1;
        }

        try items.append(DirItem{ .name = name_copy, .is_dir = e.kind == .directory });
    }

    // Simple stable sort: directories first, then by name
    var i: usize = 0;
    while (i < items.items.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < items.items.len) : (j += 1) {
            const a = items.items[i];
            const b = items.items[j];
            var name_cmp: i32 = 0;
            const a_name = a.name;
            const b_name = b.name;
            const min_len = if (a_name.len < b_name.len) a_name.len else b_name.len;
            var idx2: usize = 0;
            while (idx2 < min_len) : (idx2 += 1) {
                if (a_name[idx2] != b_name[idx2]) {
                    name_cmp = if (a_name[idx2] < b_name[idx2]) -1 else 1;
                    break;
                }
            }
            if (name_cmp == 0) name_cmp = if (a_name.len == b_name.len) 0 else if (a_name.len < b_name.len) -1 else 1;
            const swap = if (a.is_dir != b.is_dir) a.is_dir == false else name_cmp > 0;
            if (swap) {
                const tmp = items.items[i];
                items.items[i] = items.items[j];
                items.items[j] = tmp;
            }
        }
    }

    // Parent link if not root
    if (!(uriPath.len == 1 and uriPath[0] == '/')) {
        for ("<a href=\"../\">../</a>\n") |b| try out.append(b);
    }

    // Append entries
    for (items.items) |ent| {
        for ("<a href=\"") |b| try out.append(b);

        // Ensure uriPath ends with '/'
        for (uriPath) |b| try out.append(b);
        if (uriPath.len == 0 or uriPath[uriPath.len - 1] != '/') for ("/") |b| try out.append(b);

        for (ent.name) |b| try out.append(b);
        if (ent.is_dir) for ("/") |b| try out.append(b);
        for ("\"") |b| try out.append(b);
        for (">") |b| try out.append(b);
        for (ent.name) |b| try out.append(b);
        if (ent.is_dir) for ("/") |b| try out.append(b);
        for ("</a>\n") |b| try out.append(b);
    }

    for ("</pre><hr><address>tardigrade</address></body></html>\n") |b| try out.append(b);

    const slice = try out.toOwnedSlice();
    // free copied names
    for (items.items) |entry_item| {
        allocator.free(entry_item.name);
    }

    return slice;
}
