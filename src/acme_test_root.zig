//! Root of the dedicated `zig build test-acme` gate (#832). Lives in `src/`
//! so the module can reach both `acme/` and the native TLS dialer in `http/`.

test {
    _ = @import("acme/root.zig");
    _ = @import("http/acme_tls_dialer.zig");
}
