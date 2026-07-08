//! HTTP/3 request/response mapping (#246): turns a QUIC request stream into the
//! shared `stream_transport` request/response shape the gateway proxy path
//! consumes for h1/h2/h3 alike.
//!
//! Decodes HEADERS (via `qpack.zig`) into pseudo-headers + headers, exposes the
//! request body as a pull `BodySource`, and writes the response headers-first
//! then a pull-drained body — preserving the bounded-buffer / explicit-cancel /
//! no-hidden-full-body model. This is the module a pure-Zig `Http3Transport`
//! (`transport.zig`) hands each accepted stream to.
//!
//! Status: skeleton — implemented in #246 once frames/QPACK/streams exist.

const std = @import("std");
const stream_transport = @import("stream_transport");

/// The protocol tag reported to the gateway/metrics for streams served here.
pub const protocol: stream_transport.Protocol = .h3;

// TODO(#246): map a QUIC request stream onto stream_transport.Exchange
// (RequestHead + pull RequestBody in, ResponseHead + pull ResponseBody out).

test {
    std.testing.refAllDecls(@This());
}
