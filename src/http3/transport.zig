//! `Http3Transport` — the C-backend replacement boundary (#242).
//!
//! Both HTTP/3 backends implement this vtable, selected at build time:
//!   * `-Denable-http3-ngtcp2` — the current ngtcp2/nghttp3 C-backed path.
//!   * `-Denable-http3-zig`    — the pure-Zig `src/quic` + `src/http3` path.
//!
//! The boundary sits *at the transport*: above the QUIC/ngtcp2 machinery and
//! below `http3_handler` / `handleHttp3Request`, so pseudo-header mapping,
//! response encoding, and the gateway bridge are reused by both backends. No
//! backend-specific type (ngtcp2 handle, `src/quic` connection) escapes this
//! interface. The gateway itself drives h1/h2/h3 through the shared
//! `stream_transport` contract; this seam is only the h3 listener lifecycle.
//!
//! Status: interface defined (#242). Retrofitting the existing ngtcp2 runtime
//! onto this vtable, and implementing the pure-Zig backend, are tracked
//! follow-ups (#246 and the QUIC implementation issues).

const std = @import("std");
const stream_transport = @import("stream_transport");

/// The request/response shape an h3 backend maps each stream onto — shared with
/// h1/h2 so the gateway proxy path stays protocol-agnostic.
pub const Exchange = stream_transport.Exchange;

/// Backend-agnostic HTTP/3 listener lifecycle.
pub const Http3Transport = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Serve on the already-bound UDP endpoint until `stop` is requested.
        start: *const fn (ctx: *anyopaque) anyerror!void,
        /// Request a graceful stop of the listener.
        stop: *const fn (ctx: *anyopaque) void,
        /// Release all resources.
        deinit: *const fn (ctx: *anyopaque) void,
    };

    pub fn start(self: Http3Transport) anyerror!void {
        return self.vtable.start(self.ptr);
    }
    pub fn stop(self: Http3Transport) void {
        self.vtable.stop(self.ptr);
    }
    pub fn deinit(self: Http3Transport) void {
        self.vtable.deinit(self.ptr);
    }
};

test {
    std.testing.refAllDecls(@This());
}

test "Http3Transport dispatches lifecycle through the vtable" {
    const Fake = struct {
        started: bool = false,
        stopped: bool = false,
        deinitialized: bool = false,

        fn start(ctx: *anyopaque) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.started = true;
        }
        fn stop(ctx: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.stopped = true;
        }
        fn deinit(ctx: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.deinitialized = true;
        }
    };

    var fake = Fake{};
    const vt = Http3Transport.VTable{ .start = Fake.start, .stop = Fake.stop, .deinit = Fake.deinit };
    const transport = Http3Transport{ .ptr = &fake, .vtable = &vt };
    try transport.start();
    transport.stop();
    transport.deinit();
    try std.testing.expect(fake.started and fake.stopped and fake.deinitialized);
}

test "Http3Transport.Exchange is the shared stream-transport Exchange" {
    // Lock the boundary so #243/#246 build on the shared contract, not a copy.
    try std.testing.expect(Exchange == stream_transport.Exchange);
}
