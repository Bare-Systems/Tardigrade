//! Pure Zig HTTP/3 application layer (#240): frames, QPACK, request/response
//! session mapping, and the backend-agnostic `Http3Transport` boundary. Sits
//! above the QUIC transport core in `src/quic/` and maps each request onto the
//! shared `stream_transport` contract used by h1/h2/h3.

pub const transport = @import("transport.zig");
pub const frame = @import("frame.zig");
pub const qpack = @import("qpack.zig");
pub const session = @import("session.zig");
pub const qlog = @import("qlog.zig");
pub const priority = @import("priority.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
