//! Pure Zig QUIC foundation modules.

pub const config = @import("config.zig");
pub const udp = @import("udp.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
