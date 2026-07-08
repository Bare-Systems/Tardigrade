//! Pure Zig QUIC foundation modules (#240). Transport core only — no HTTP or
//! gateway types. HTTP/3 application mapping lives in `src/http3/`.

pub const config = @import("config.zig");
pub const udp = @import("udp.zig");
pub const varint = @import("varint.zig");
pub const packet = @import("packet.zig");
pub const connection = @import("connection.zig");
pub const tls_adapter = @import("tls_adapter.zig");
pub const recovery = @import("recovery.zig");
pub const cid = @import("cid.zig");
pub const path = @import("path.zig");
pub const stream = @import("stream.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
