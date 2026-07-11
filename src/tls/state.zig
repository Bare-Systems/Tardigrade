//! Protocol-neutral TLS engine state vocabulary.

pub const Role = enum { client, server };

pub const TransportMode = enum {
    /// TLS handshake messages are carried directly by a QUIC CRYPTO transport.
    quic,
    /// TLS owns record framing over a reliable byte stream; the record layer is
    /// a future module and is deliberately not imported here.
    record,
};

pub const HandshakeState = enum {
    idle,
    client_hello,
    server_hello,
    encrypted_extensions,
    certificate,
    certificate_verify,
    finished,
    complete,
};

pub const DriverState = enum {
    idle,
    in_progress,
    complete,
    failed,
};
