//! Pure Zig QUIC foundation modules (#240). Transport core only — no HTTP or
//! gateway types. HTTP/3 application mapping lives in `src/http3/`.

pub const config = @import("config.zig");
pub const udp = @import("udp.zig");
pub const varint = @import("quic_varint");
pub const packet = @import("packet.zig");
pub const frame = @import("frame.zig");
pub const connection = @import("connection.zig");
pub const tls_adapter = @import("tls_adapter.zig");
pub const tls_handshake = @import("tls_handshake.zig");
pub const tls_backend = @import("tls_backend.zig");
pub const record_mode_handshake_test = @import("record_mode_handshake_test.zig");
pub const recovery = @import("recovery.zig");
pub const cid = @import("cid.zig");
pub const path = @import("path.zig");
pub const stream = @import("stream.zig");
pub const qlog = @import("qlog.zig");
pub const keylog = @import("keylog.zig");
pub const tls_core = @import("tls_core");

test {
    @import("std").testing.refAllDecls(@This());
}
