const std = @import("std");

pub const Overrides = struct {
    map: std.StringHashMap([]const u8),

    pub fn init(allocator: std.mem.Allocator) Overrides {
        return .{ .map = std.StringHashMap([]const u8).init(allocator) };
    }

    pub fn deinit(self: *Overrides, allocator: std.mem.Allocator) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.map.deinit();
    }
};

pub fn loadOverrides(allocator: std.mem.Allocator) !Overrides {
    const path = std.process.getEnvVarOwned(allocator, "TARDIGRADE_SECRETS_PATH") catch {
        return Overrides.init(allocator);
    };
    defer allocator.free(path);

    const keys_raw = std.process.getEnvVarOwned(allocator, "TARDIGRADE_SECRET_KEYS") catch "";
    defer if (keys_raw.len > 0) allocator.free(keys_raw);
    if (keys_raw.len == 0) return Overrides.init(allocator);

    const key_list = try parseKeyList(allocator, keys_raw);
    defer {
        for (key_list) |k| allocator.free(k);
        allocator.free(key_list);
    }

    var out = Overrides.init(allocator);
    errdefer out.deinit(allocator);

    const raw = try std.fs.cwd().readFileAlloc(allocator, path, 2 * 1024 * 1024);
    defer allocator.free(raw);
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line_raw| {
        const no_comment = line_raw[0 .. std.mem.indexOfScalar(u8, line_raw, '#') orelse line_raw.len];
        const line = std.mem.trim(u8, no_comment, " \t\r\n");
        if (line.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], " \t");
        const value = std.mem.trim(u8, line[eq + 1 ..], " \t");
        if (key.len == 0 or value.len == 0) continue;

        const plain = if (std.mem.startsWith(u8, value, "ENC:"))
            try decryptValue(allocator, value["ENC:".len..], key_list)
        else
            try allocator.dupe(u8, value);
        defer allocator.free(plain);

        try putOverride(allocator, &out.map, key, plain);
    }

    return out;
}

fn putOverride(allocator: std.mem.Allocator, map: *std.StringHashMap([]const u8), key_raw: []const u8, value_raw: []const u8) !void {
    const key = try allocator.dupe(u8, key_raw);
    errdefer allocator.free(key);
    const val = try allocator.dupe(u8, value_raw);
    errdefer allocator.free(val);
    if (map.fetchRemove(key_raw)) |old| {
        allocator.free(old.key);
        allocator.free(old.value);
    }
    try map.put(key, val);
}

fn parseKeyList(allocator: std.mem.Allocator, raw: []const u8) ![][]u8 {
    var out = std.ArrayList([]u8).init(allocator);
    errdefer {
        for (out.items) |k| allocator.free(k);
        out.deinit();
    }

    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (trimmed.len == 0) continue;
        const key = try hexDecode(allocator, trimmed);
        if (key.len == 0) {
            allocator.free(key);
            continue;
        }
        try out.append(key);
    }
    return out.toOwnedSlice();
}

fn hexDecode(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return allocator.alloc(u8, 0);
    var out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        const hi = std.fmt.charToDigit(hex[i * 2], 16) catch return allocator.alloc(u8, 0);
        const lo = std.fmt.charToDigit(hex[i * 2 + 1], 16) catch return allocator.alloc(u8, 0);
        out[i] = @as(u8, @intCast((hi << 4) | lo));
    }
    return out;
}

fn decryptValue(allocator: std.mem.Allocator, encoded: []const u8, keys: [][]u8) ![]u8 {
    // Simple XOR envelope for branch-local encrypted secret storage:
    // ENC:<base64(xor(plaintext,key))>
    const dec_len = try std.base64.standard.Decoder.calcSizeForSlice(encoded);
    const cipher = try allocator.alloc(u8, dec_len);
    defer allocator.free(cipher);
    try std.base64.standard.Decoder.decode(cipher, encoded);
    const decoded = cipher;
    for (keys) |key| {
        if (key.len == 0) continue;
        var plain = try allocator.alloc(u8, decoded.len);
        errdefer allocator.free(plain);
        for (decoded, 0..) |b, i| plain[i] = b ^ key[i % key.len];
        if (plain.len < 4 or !std.mem.eql(u8, plain[0..4], "TG1:")) {
            allocator.free(plain);
            continue;
        }
        const out = try allocator.dupe(u8, plain[4..]);
        allocator.free(plain);
        return out;
    }
    return error.SecretDecryptFailed;
}

test "decrypt xor envelope with key rotation list" {
    const allocator = std.testing.allocator;
    const plain = "TG1:supersecret";
    const key = "aabbccddeeff00112233445566778899";
    const key_bytes = try hexDecode(allocator, key);
    defer allocator.free(key_bytes);

    var cipher = try allocator.alloc(u8, plain.len);
    defer allocator.free(cipher);
    for (plain, 0..) |c, i| cipher[i] = c ^ key_bytes[i % key_bytes.len];
    const enc_len = std.base64.standard.Encoder.calcSize(cipher.len);
    const enc = try allocator.alloc(u8, enc_len);
    defer allocator.free(enc);
    _ = std.base64.standard.Encoder.encode(enc, cipher);

    var keys = std.ArrayList([]u8).init(allocator);
    defer keys.deinit();
    try keys.append(try hexDecode(allocator, "0000000000000000"));
    try keys.append(try hexDecode(allocator, key));
    defer {
        for (keys.items) |k| allocator.free(k);
    }

    const out = try decryptValue(allocator, enc, keys.items);
    defer allocator.free(out);
    try std.testing.expectEqualStrings("supersecret", out);
}
