# TLS record transport contract

`src/tls/record_transport.zig` defines the protocol-neutral contract that the
future TLS-over-TCP record layer consumes. It does not import TCP sockets,
pollers, ciphertext buffers, or record-codec types.

The record layer supplies already-decrypted handshake bytes by epoch:
`plaintext`, `handshake_protected`, or `application_protected`. The TLS
handshake backend emits events for handshake output tagged with the required
protection epoch, asymmetric read/write traffic-key activation, negotiated ALPN,
peer certificate state, fatal alerts, and completion.

Event byte slices are copied into the driver-owned sink. They remain valid only
until the next `start` or `receive` call on the driver. Resetting or
deinitializing the sink securely zeroes the used scratch range, including copied
traffic secrets.

`Driver.receive` returns the sink even for terminal TLS handshake failures so a
caller can serialize the fatal alert before shutting the connection down. The
terminal error is reported alongside the sink.
