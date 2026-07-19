const std = @import("std");
const credentials = @import("credentials.zig");

pub const LoadedIdentity = struct {
    allocator: std.mem.Allocator,
    cert_der: []u8,
    key_der: []u8,
    identity: credentials.Identity,

    pub fn deinit(self: *LoadedIdentity) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.identity.key));
        if (self.cert_der.len > 0) self.allocator.free(self.cert_der);
        if (self.key_der.len > 0) self.allocator.free(self.key_der);
        self.* = undefined;
    }
};

pub fn loadIdentity(
    allocator: std.mem.Allocator,
    cert_path: []const u8,
    key_path: []const u8,
) !LoadedIdentity {
    const cert_raw = try readSmallFile(allocator, cert_path);
    defer allocator.free(cert_raw);
    const key_raw = try readSmallFile(allocator, key_path);
    defer allocator.free(key_raw);

    const cert_der = try derFromPemOrDer(allocator, cert_raw, "CERTIFICATE");
    errdefer allocator.free(cert_der);
    const key_der = try keyDerFromPemOrDer(allocator, key_raw);
    errdefer allocator.free(key_der);

    const identity = try credentials.Identity.initPkcs8(cert_der, key_der);
    return .{
        .allocator = allocator,
        .cert_der = cert_der,
        .key_der = key_der,
        .identity = identity,
    };
}

pub fn readSmallFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const fd = try std.posix.openat(std.posix.AT.FDCWD, path, .{}, 0);
    defer _ = std.c.close(fd);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = try std.posix.read(fd, &buf);
        if (n == 0) break;
        if (out.items.len + n > 256 * 1024) return error.FileTooBig;
        try out.appendSlice(allocator, buf[0..n]);
    }
    return out.toOwnedSlice(allocator);
}

pub fn derFromPemOrDer(allocator: std.mem.Allocator, raw: []const u8, block_name: []const u8) ![]u8 {
    if (raw.len > 0 and raw[0] == 0x30) return allocator.dupe(u8, raw);
    return pemBlockToDer(allocator, raw, block_name);
}

pub fn keyDerFromPemOrDer(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    if (raw.len > 0 and raw[0] == 0x30) return allocator.dupe(u8, raw);
    if (pemBlockToDer(allocator, raw, "PRIVATE KEY")) |der| return der else |_| {}
    return pemBlockToDer(allocator, raw, "EC PRIVATE KEY");
}

pub fn pemBlockToDer(allocator: std.mem.Allocator, pem: []const u8, block_name: []const u8) ![]u8 {
    var begin_buf: [64]u8 = undefined;
    var end_buf: [64]u8 = undefined;
    const begin = try std.fmt.bufPrint(&begin_buf, "-----BEGIN {s}-----", .{block_name});
    const end = try std.fmt.bufPrint(&end_buf, "-----END {s}-----", .{block_name});
    const begin_at = std.mem.find(u8, pem, begin) orelse return error.PemBlockNotFound;
    const body_start = begin_at + begin.len;
    const end_at = std.mem.findPos(u8, pem, body_start, end) orelse return error.PemBlockNotFound;
    const body = pem[body_start..end_at];

    var compact = try allocator.alloc(u8, body.len);
    defer allocator.free(compact);
    var len: usize = 0;
    for (body) |char| {
        if (char == '\n' or char == '\r' or char == ' ' or char == '\t') continue;
        compact[len] = char;
        len += 1;
    }
    const decoder = std.base64.standard.Decoder;
    const der_len = try decoder.calcSizeForSlice(compact[0..len]);
    const der = try allocator.alloc(u8, der_len);
    errdefer allocator.free(der);
    try decoder.decode(der, compact[0..len]);
    return der;
}

test "PEM block decoding extracts DER bytes" {
    const allocator = std.testing.allocator;
    const pem = "junk\n-----BEGIN CERTIFICATE-----\nMAMCAQA=\n-----END CERTIFICATE-----\n";
    const der = try pemBlockToDer(allocator, pem, "CERTIFICATE");
    defer allocator.free(der);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x30, 0x03, 0x02, 0x01, 0x00 }, der);
    try std.testing.expectError(error.PemBlockNotFound, pemBlockToDer(allocator, pem, "PRIVATE KEY"));
}
