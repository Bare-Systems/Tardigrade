const std = @import("std");
const builtin = @import("builtin");
const crypto = @import("crypto");
const tls13_backend = @import("tls13_backend.zig");

pub const Provider = crypto.pure_zig.Provider;

pub const OsEntropy = struct {
    pub fn entropy(self: *OsEntropy) crypto.provider.Entropy {
        return .{ .context = self, .fillFn = fill };
    }

    fn fill(_: *anyopaque, buffer: []u8) crypto.provider.EntropyError!void {
        fillSecure(buffer) catch return error.EntropyFailure;
    }
};

pub fn freshHandshakeEntropy() crypto.provider.EntropyError!tls13_backend.Entropy {
    var entropy: tls13_backend.Entropy = undefined;
    try fillSecure(&entropy.hello_random);
    try fillSecure(&entropy.key_share_seed);
    return entropy;
}

test "fresh handshake entropy fills both backend inputs" {
    const entropy = try freshHandshakeEntropy();
    try std.testing.expect(!allZero(&entropy.hello_random));
    try std.testing.expect(!allZero(&entropy.key_share_seed));
}

fn fillSecure(buffer: []u8) crypto.provider.EntropyError!void {
    if (buffer.len == 0) return;
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var offset: usize = 0;
        while (offset < buffer.len) {
            const rc = linux.getrandom(buffer[offset..].ptr, buffer.len - offset, 0);
            switch (linux.errno(rc)) {
                .SUCCESS => {
                    if (rc == 0) return error.EntropyFailure;
                    offset += rc;
                },
                .INTR => {},
                else => return error.EntropyFailure,
            }
        }
        return;
    }
    if (@TypeOf(std.c.arc4random_buf) != void) {
        std.c.arc4random_buf(buffer.ptr, buffer.len);
        return;
    }
    return error.EntropyFailure;
}

fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| {
        if (byte != 0) return false;
    }
    return true;
}
