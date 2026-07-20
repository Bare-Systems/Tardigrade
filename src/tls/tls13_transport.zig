//! Transport-neutral contract for the shared TLS 1.3 handshake engine.
//!
//! Record and QUIC profiles adapt this contract at their respective transport
//! boundaries. Keeping the engine on this lower-level contract prevents it
//! from depending on either encrypted byte streams or QUIC framing.

const std = @import("std");
const events = @import("events.zig");
const messages = @import("messages.zig");
const session = @import("session.zig");
const transport = @import("transport.zig");

pub const Error = events.HandshakeError || messages.ReadError || messages.WriteError || error{
    TransportBufferOverflow,
    UnexpectedTransportEpoch,
    MissingTransportExtension,
    InvalidTransportProfile,
};

pub const max_new_session_ticket_message_len =
    4 + 4 + 4 + 1 + session.max_ticket_nonce_len + 2 + session.absolute_ticket_wire_max + 2 + (std.math.maxInt(u16) - 1);

pub const Contract = transport.ContractWithOptions(
    void,
    events.EncryptionEpoch,
    Error,
    16,
    max_new_session_ticket_message_len,
    error.TransportBufferOverflow,
);
pub const Backend = Contract.Backend;
pub const EventSink = Contract.EventSink;

test {
    @import("std").testing.refAllDecls(@This());
}
