//! Transport-neutral contract for the shared TLS 1.3 handshake engine.
//!
//! Record and QUIC profiles adapt this contract at their respective transport
//! boundaries. Keeping the engine on this lower-level contract prevents it
//! from depending on either encrypted byte streams or QUIC framing.

const events = @import("events.zig");
const messages = @import("messages.zig");
const transport = @import("transport.zig");

pub const Error = events.HandshakeError || messages.ReadError || messages.WriteError || error{
    TransportBufferOverflow,
    UnexpectedTransportEpoch,
    MissingTransportExtension,
    InvalidTransportProfile,
};

pub const Contract = transport.Contract(void, events.EncryptionEpoch, Error);
pub const Backend = Contract.Backend;
pub const EventSink = Contract.EventSink;

test {
    @import("std").testing.refAllDecls(@This());
}
