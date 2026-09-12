//! Native upstream HTTPS/TLS client for every shipping profile
//! (#379, epic #327, #634, retirement #649).
//!
//! `UpstreamTlsConn` is the native upstream HTTPS/TLS client used for
//! `proxy_pass https://…` in every profile (#634): a small adapter over the
//! same TLS engine, record layer, and PKI trust/identity machinery the
//! native downstream listener (`native_tls_connection.zig`) and `src/pki/`
//! already provide — `src/tls/webpki_verifier.zig` for
//! certificate-chain/hostname verification, `identity_loader.zig` for an
//! optional client (mTLS) credential. It presents a synchronous,
//! blocking-socket contract at the API boundary (`connect` takes a
//! caller-owned, already-connected fd and blocks until the handshake
//! completes or fails; `read`/`writeAll` block similarly) — but internally
//! puts that fd in nonblocking mode and drives the record layer's carrier
//! itself with a bounded `poll()` between `drive()` calls, because the
//! shared record engine drains its carrier in a loop until
//! `error.WouldBlock` (see `driveUntilHandshakeComplete`'s doc comment): a
//! literally blocking fd would make that loop's second read of a batch
//! block for the full configured socket timeout even when the first read
//! already delivered everything needed. `waitForFd`'s deadline is read back
//! from whatever `SO_RCVTIMEO`/`SO_SNDTIMEO` the caller already configured
//! on the fd. No `@cImport`, no OpenSSL types, no C linkage, and no
//! runtime fallback to a foreign implementation — see
//! docs/TLS_DEPENDENCY_POLICY.md.
//!
//! Downstream TLS termination is served entirely by
//! `native_tls_connection.zig`, not this file: this file used to also hold
//! a downstream `TlsTerminator`/`TlsConnection` pair (first the retired
//! OpenSSL adapter's implementation, later a permanently-inert stub kept
//! only so old call sites compiled), but #649 removed that model
//! entirely — there is no downstream-terminator surface left here to keep
//! call sites compiling against. This module is named for what it is now
//! (the upstream TLS client), not for migration history; `negotiated_dispatch.zig`
//! is the neutral home for `NegotiatedProtocol` since both this client and
//! the downstream native listener need it.

const std = @import("std");
const builtin = @import("builtin");
const tls_core = @import("tls_core");
const encrypted_stream = tls_core.encrypted_stream;
const negotiated_dispatch = @import("negotiated_dispatch.zig");

/// The error surface actually reachable through this native client's API —
/// no OpenSSL-adapter-only failure modes (init/cipher/CRL/OCSP config,
/// cert/key mismatch) that this implementation never returns.
pub const TlsError = error{
    OutOfMemory,
    ContextInitFailed,
    CertificateLoadFailed,
    PrivateKeyLoadFailed,
    VerifyConfigFailed,
    HandshakeFailed,
    NoApplicationProtocol,
    TlsReadFailed,
    TlsWriteFailed,
};

pub const NegotiatedProtocol = negotiated_dispatch.NegotiatedProtocol;

pub const UpstreamTlsOptions = struct {
    skip_verify: bool = false,
    ca_bundle_path: []const u8 = "",
    sni_override: []const u8 = "",
    client_cert_path: []const u8 = "",
    client_key_path: []const u8 = "",
    alpn_policy: UpstreamAlpnPolicy = .require_http1,
};

pub const UpstreamAlpnPolicy = enum {
    require_http1,
    require_h2,
    prefer_h2_allow_http1,
    /// TLS for protocols such as SMTP and IMAP that do not negotiate an
    /// application protocol with ALPN. The connection is still fully
    /// certificate- and hostname-verified.
    non_http_no_alpn,

    pub fn offersH2(self: UpstreamAlpnPolicy) bool {
        return self == .require_h2 or self == .prefer_h2_allow_http1;
    }

    /// The ALPN protocol names this policy offers in the ClientHello, most
    /// preferred first. Mirrors the OpenSSL adapter's `wire()` ordering.
    fn alpnProtocols(self: UpstreamAlpnPolicy) []const tls_core.algorithms.ProtocolName {
        return switch (self) {
            .require_http1 => &http1_only_alpns,
            .require_h2 => &h2_only_alpns,
            .prefer_h2_allow_http1 => &h2_and_http1_alpns,
            .non_http_no_alpn => &.{},
        };
    }

    /// Validate the peer's actually-negotiated ALPN protocol against this
    /// policy. Absent ALPN is never accepted by any policy — an HTTPS
    /// upstream that does not speak ALPN cannot be trusted to be the
    /// protocol the operator configured. Kept as an explicit
    /// application-level check after the handshake completes (not only
    /// engine-internal ALPN policy) so a bug or future engine relaxation in
    /// ALPN enforcement can never silently downgrade a `require_h2`
    /// upstream to HTTP/1.1 or vice versa.
    pub fn select(self: UpstreamAlpnPolicy, selected_alpn: ?[]const u8) TlsError!NegotiatedProtocol {
        if (self == .non_http_no_alpn) {
            if (selected_alpn != null) return error.NoApplicationProtocol;
            // `protocol` is only observed by HTTP callers. Keep the existing
            // storage type while non-HTTP callers deliberately ignore it.
            return .http1_1;
        }
        const selected = selected_alpn orelse return error.NoApplicationProtocol;
        if (std.mem.eql(u8, selected, "h2")) {
            return switch (self) {
                .require_http1 => error.NoApplicationProtocol,
                .require_h2, .prefer_h2_allow_http1 => .http2,
                .non_http_no_alpn => error.NoApplicationProtocol,
            };
        }
        if (std.mem.eql(u8, selected, "http/1.1")) {
            return switch (self) {
                .require_http1, .prefer_h2_allow_http1 => .http1_1,
                .require_h2 => error.NoApplicationProtocol,
                .non_http_no_alpn => error.NoApplicationProtocol,
            };
        }
        return error.NoApplicationProtocol;
    }
};

const http1_only_alpns = [_]tls_core.algorithms.ProtocolName{tls_core.algorithms.alpn.http_1_1};
const h2_only_alpns = [_]tls_core.algorithms.ProtocolName{tls_core.algorithms.alpn.h2};
const h2_and_http1_alpns = [_]tls_core.algorithms.ProtocolName{ tls_core.algorithms.alpn.h2, tls_core.algorithms.alpn.http_1_1 };

test "upstream ALPN policy validates selected protocol strictly" {
    try std.testing.expect(!UpstreamAlpnPolicy.require_http1.offersH2());
    try std.testing.expect(UpstreamAlpnPolicy.require_h2.offersH2());
    try std.testing.expect(UpstreamAlpnPolicy.prefer_h2_allow_http1.offersH2());
    try std.testing.expect(!UpstreamAlpnPolicy.non_http_no_alpn.offersH2());

    try std.testing.expectEqual(NegotiatedProtocol.http1_1, try UpstreamAlpnPolicy.require_http1.select("http/1.1"));
    try std.testing.expectError(error.NoApplicationProtocol, UpstreamAlpnPolicy.require_http1.select("h2"));
    try std.testing.expectError(error.NoApplicationProtocol, UpstreamAlpnPolicy.require_http1.select(null));

    try std.testing.expectEqual(NegotiatedProtocol.http2, try UpstreamAlpnPolicy.require_h2.select("h2"));
    try std.testing.expectError(error.NoApplicationProtocol, UpstreamAlpnPolicy.require_h2.select("http/1.1"));
    try std.testing.expectError(error.NoApplicationProtocol, UpstreamAlpnPolicy.require_h2.select(null));

    try std.testing.expectEqual(NegotiatedProtocol.http2, try UpstreamAlpnPolicy.prefer_h2_allow_http1.select("h2"));
    try std.testing.expectEqual(NegotiatedProtocol.http1_1, try UpstreamAlpnPolicy.prefer_h2_allow_http1.select("http/1.1"));
    try std.testing.expectError(error.NoApplicationProtocol, UpstreamAlpnPolicy.prefer_h2_allow_http1.select("spdy/3"));
    try std.testing.expectError(error.NoApplicationProtocol, UpstreamAlpnPolicy.prefer_h2_allow_http1.select(null));
    try std.testing.expectEqual(NegotiatedProtocol.http1_1, try UpstreamAlpnPolicy.non_http_no_alpn.select(null));
    try std.testing.expectError(error.NoApplicationProtocol, UpstreamAlpnPolicy.non_http_no_alpn.select("http/1.1"));
}

/// A native (pure-Zig) TLS client connection to a TCP stream, used for
/// upstream HTTPS connections (#634). `fd` must already be a connected
/// socket; `connect` immediately puts it in nonblocking mode internally
/// (see the module doc comment above), but presents the OpenSSL adapter's
/// synchronous, *blocking-socket-shaped* contract at the API boundary —
/// callers still configure bounded connect/read/write behavior via
/// `SO_RCVTIMEO`/`SO_SNDTIMEO` on the fd before/around calling
/// `connect`/`read`/`writeAll`, exactly as the OpenSSL adapter's
/// `SSL_connect`/`SSL_read`/`SSL_write` rely on for their own blocking
/// timeout behavior; that configured timeout becomes `waitForFd`'s bounded
/// `poll()` deadline instead of a per-syscall kernel timeout.
/// The heap-stable connection state `UpstreamTlsConn` points to. Allocated
/// once and never moved for the life of the connection: the record layer's
/// handshake driver captures a permanent pointer to `backend`
/// (`backend.backend()`), the crypto provider captures a permanent pointer to
/// `crypto_provider_state`, and the blocking `Carrier` captures a permanent
/// pointer to this whole struct for `fd` access — none of that is safe to
/// move once construction starts. `UpstreamTlsConn` itself stays a small,
/// freely copyable value (a pointer to this plus the negotiated protocol),
/// matching the OpenSSL adapter's `ssl: *SSL, ctx: *SSL_CTX` shape and the
/// existing by-value `UpstreamTlsConn.connect(...) TlsError!UpstreamTlsConn`
/// call sites in `upstream_pool.zig`/`gateway_proxy.zig`.
const UpstreamTlsState = struct {
    allocator: std.mem.Allocator,
    fd: std.posix.fd_t,
    entropy_source: tls_core.production_crypto.OsEntropy = .{},
    crypto_provider_state: tls_core.production_crypto.Provider = undefined,
    backend: tls_core.tls13_backend.Tls13Backend = undefined,
    record: encrypted_stream.PureZigRecordStream = undefined,
};

pub const TestHooks = if (builtin.is_test) struct {
    pub const State = UpstreamTlsState;
} else struct {};

pub const UpstreamTlsConn = struct {
    state: *UpstreamTlsState,
    /// Copy of the connected fd, for callers that need it directly (e.g. to
    /// bound reads/writes with `SO_RCVTIMEO`/`SO_SNDTIMEO`) without going
    /// through `state`. Never used by this type's own I/O, which always goes
    /// through `state.record`'s carrier.
    fd: std.posix.fd_t = -1,
    protocol: NegotiatedProtocol = .http1_1,

    /// Bounds the handshake pump loop (`driveUntilHandshakeComplete`)
    /// against a stuck/misbehaving peer independent of the socket-level
    /// timeout: each iteration is either genuine forward progress or one
    /// bounded `poll()` wait, and a real TLS 1.3 handshake completes in a
    /// small, fixed number of round trips, so this is a generous upper bound
    /// on iterations, not a time budget.
    const max_handshake_drive_iterations = 64;

    pub fn connect(
        fd: std.posix.fd_t,
        host: []const u8,
        opts: UpstreamTlsOptions,
    ) TlsError!UpstreamTlsConn {
        const allocator = std.heap.c_allocator;
        const sni_host = if (opts.sni_override.len > 0) opts.sni_override else host;
        // The record layer's `drive()` drains a nonblocking carrier in a
        // tight loop until it sees `error.WouldBlock` (see the module doc
        // comment): on a genuinely *blocking* fd, a second read call inside
        // that same loop — with nothing left for the peer to say right now —
        // would itself block for the full configured socket timeout instead
        // of returning immediately, even though the first read already
        // delivered everything needed for this round. So this fd is put in
        // nonblocking mode, matching the native downstream listener
        // (`native_tls_connection.zig`); the caller-configured
        // `SO_RCVTIMEO`/`SO_SNDTIMEO` (still read back by `waitForFd` below)
        // becomes this function's own bounded `poll()` deadline instead of a
        // per-syscall kernel timeout.
        setNonBlocking(fd) catch return error.ContextInitFailed;

        const state = allocator.create(UpstreamTlsState) catch return error.ContextInitFailed;
        errdefer allocator.destroy(state);
        state.* = .{ .allocator = allocator, .fd = fd };
        state.entropy_source = .{};
        state.crypto_provider_state = tls_core.production_crypto.Provider.init(state.entropy_source.entropy());
        const crypto_provider = state.crypto_provider_state.cryptoProvider();
        const handshake_entropy = tls_core.production_crypto.freshHandshakeEntropy() catch return error.ContextInitFailed;

        const config = tls_core.tls13_backend.BackendConfig{
            .transport = .record,
            .policy = .{
                .transport_mode = .record,
                .protocol_versions = tls_core.tls13_backend.native_capabilities.protocol_versions,
                .cipher_suites = tls_core.tls13_backend.native_capabilities.cipher_suites,
                .named_groups = tls_core.tls13_backend.native_capabilities.named_groups,
                .signature_schemes = tls_core.tls13_backend.native_capabilities.signature_schemes,
                .alpn_protocols = opts.alpn_policy.alpnProtocols(),
                .allow_absent_alpn = opts.alpn_policy == .non_http_no_alpn,
            },
        };
        const client_options = tls_core.tls13_backend.Tls13Backend.ClientOptions{
            .server_name = sni_host,
            .policy = .{ .require_peer_authentication = !opts.skip_verify },
        };

        // Verification state (trust anchors, the Web-PKI verifier adapter)
        // and an optional client (mTLS) credential are only ever consulted
        // synchronously while this function's own `driveUntilHandshakeComplete`
        // call below is on the stack — `WebPkiVerifier.verifyPeer` always
        // completes synchronously (never `.pending`) and TLS 1.3 has no
        // post-handshake re-authentication — so both may safely be ordinary
        // locals, unlike `state` above.
        var trust_anchors: ?tls_core.webpki_verifier.TrustAnchors = null;
        defer if (trust_anchors) |*anchors| anchors.deinit(allocator);
        var verifier_storage: tls_core.webpki_verifier.WebPkiVerifier = undefined;

        if (opts.skip_verify) {
            state.backend = tls_core.tls13_backend.Tls13Backend.initClientConfigured(
                handshake_entropy,
                crypto_provider,
                .insecure_no_verification,
                config,
                client_options,
            );
        } else {
            trust_anchors = tls_core.webpki_verifier.loadTrustAnchors(allocator, opts.ca_bundle_path) catch return error.VerifyConfigFailed;
            verifier_storage = tls_core.webpki_verifier.WebPkiVerifier.init(allocator, trust_anchors.?.anchors(), crypto_provider);
            state.backend = tls_core.tls13_backend.Tls13Backend.initClientWithVerifierConfigured(
                handshake_entropy,
                crypto_provider,
                verifier_storage.verifier(),
                config,
                client_options,
            );
        }

        // `state.backend` is definitely initialized from here on and owns
        // handshake secrets that must be wiped on every failure path below.
        // Ownership transfers to `state.record` once it is constructed
        // (mirroring `native_tls_connection.zig`'s `backend_owned_by_record`
        // pattern): `record.deinit()` tears the backend down transitively,
        // so exactly one of the two guards below is ever live at a time.
        var backend_owned_by_record = false;
        errdefer if (!backend_owned_by_record) state.backend.deinit();

        var loaded_client_identity: ?tls_core.identity_loader.LoadedIdentity = null;
        defer if (loaded_client_identity) |*loaded| loaded.deinit();
        var client_credential: tls_core.credentials.FixedCredentialProvider = undefined;
        if (opts.client_cert_path.len > 0 or opts.client_key_path.len > 0) {
            if (opts.client_cert_path.len == 0) return error.CertificateLoadFailed;
            if (opts.client_key_path.len == 0) return error.PrivateKeyLoadFailed;
            loaded_client_identity = tls_core.identity_loader.loadIdentity(
                allocator,
                opts.client_cert_path,
                opts.client_key_path,
                state.entropy_source.entropy(),
            ) catch return error.CertificateLoadFailed;
            client_credential = tls_core.credentials.FixedCredentialProvider.init(
                loaded_client_identity.?.identity,
                state.entropy_source.entropy(),
            );
            state.backend.setLocalCredentialProvider(client_credential.provider());
        }

        state.record = encrypted_stream.PureZigRecordStream.initWithCarrierAndBackend(
            allocator,
            .client,
            crypto_provider,
            .tls_aes_128_gcm_sha256,
            .{
                .ptr = state,
                .readFn = carrierRead,
                .writeFn = carrierWrite,
                .closeFn = carrierCloseNoop,
                .owns_handle = false,
            },
            state.backend.backend(),
        ) catch return error.ContextInitFailed;
        backend_owned_by_record = true;
        errdefer state.record.deinit();
        // The backend's `Trust`/`auth_policy` alone is not sufficient to open
        // an unverified connection: the record layer requires this separate,
        // explicit opt-in (mirroring the QUIC driver's own policy) so
        // `.certificate(.not_checked)` can never silently open a client
        // stream just because a backend happened to be configured without
        // verification. Skipping this when `opts.skip_verify` is set would
        // make the handshake fail closed even in the deliberately-insecure
        // case, not silently succeed — but it must still be set explicitly
        // to actually deliver the "verification disabled" contract.
        state.record.allow_unverified_certificate = opts.skip_verify;

        try driveUntilHandshakeComplete(&state.record, fd);

        const protocol = try opts.alpn_policy.select(state.record.negotiatedAlpn());
        return .{ .state = state, .fd = fd, .protocol = protocol };
    }

    pub fn deinit(self: *UpstreamTlsConn) void {
        self.state.record.deinit();
        self.state.allocator.destroy(self.state);
        self.* = undefined;
    }

    pub fn close(self: *UpstreamTlsConn) void {
        const fd = self.state.fd;
        self.deinit();
        if (fd >= 0) _ = std.c.close(fd);
    }

    /// `error.EndOfStream` from `readPlaintext` is a *clean* shutdown (the
    /// peer's `close_notify` was received, `peer_closed = true`) — mapped to
    /// `0`, matching the OpenSSL adapter's `SSL_ERROR_ZERO_RETURN -> 0`. An
    /// abrupt close without `close_notify` never sets `peer_closed`; it
    /// surfaces through `drive()`'s own failure path instead (truncation is
    /// not silently treated as a clean end of body).
    ///
    /// Checking `record.peer_closed` before calling `drive()` again (rather
    /// than after) is safe, not merely a shortcut: once `handleAlert`
    /// processes `close_notify` and sets `peer_closed`,
    /// `canProcessCarrierInput()` and `feedCiphertextInternal()` both
    /// short-circuit on it (`encrypted_stream.zig`), so nothing past that
    /// point ever gets parsed — every byte the peer sent is necessarily
    /// already in `inbound_plaintext` by the time `peer_closed` is observed,
    /// since TLS records (including the alert itself) are only ever
    /// consumed in wire order.
    pub fn read(self: *UpstreamTlsConn, buf: []u8) TlsError!usize {
        const record = &self.state.record;
        const fd = self.state.fd;
        while (true) {
            if (record.inbound_plaintext.len > 0) {
                return record.readPlaintext(buf) catch return error.TlsReadFailed;
            }
            if (record.peer_closed) {
                return record.readPlaintext(buf) catch |err| switch (err) {
                    error.EndOfStream => return 0,
                    else => return error.TlsReadFailed,
                };
            }
            const result = record.drive() catch return error.TlsReadFailed;
            if (record.inbound_plaintext.len > 0 or record.peer_closed) continue;
            if (result.made_progress) continue;
            try waitForFd(fd, record.readiness(), error.TlsReadFailed);
        }
    }

    pub fn writeAll(self: *UpstreamTlsConn, data: []const u8) TlsError!void {
        const record = &self.state.record;
        const fd = self.state.fd;
        var offset: usize = 0;
        while (offset < data.len) {
            // `writePlaintext` can report `WouldBlock` (record-layer
            // backpressure, e.g. a still-full outbound queue) rather than a
            // hard failure; treat it as "wrote nothing this attempt" and let
            // the drive/wait loop below flush or advance before retrying the
            // same offset, instead of failing the write outright.
            const written = record.writePlaintext(data[offset..]) catch |err| switch (err) {
                error.WouldBlock => 0,
                else => return error.TlsWriteFailed,
            };
            offset += written;
            while (record.queuedCiphertextLen() > 0) {
                const result = record.drive() catch return error.TlsWriteFailed;
                if (record.queuedCiphertextLen() == 0) break;
                if (result.made_progress) continue;
                try waitForFd(fd, record.readiness(), error.TlsWriteFailed);
            }
            if (written == 0 and offset < data.len) {
                const result = record.drive() catch return error.TlsWriteFailed;
                if (!result.made_progress) try waitForFd(fd, record.readiness(), error.TlsWriteFailed);
            }
        }
    }

    /// Bytes already decrypted and buffered by the record layer, not yet
    /// consumed by `read` — the native analogue of OpenSSL's `SSL_pending`.
    pub fn pending(self: *const UpstreamTlsConn) usize {
        return self.state.record.inbound_plaintext.len;
    }

    /// Whether the next `read()` call is guaranteed to return without
    /// needing the raw fd to become readable first: either there is already
    /// buffered plaintext (`pending() > 0`), or the peer has already sent a
    /// clean TLS shutdown (`close_notify`), in which case `read()` returns
    /// `0` immediately regardless of the fd.
    ///
    /// This second case matters because `close_notify` is a *half-close*
    /// signal (RFC 8446 §6.1): the peer's raw TCP socket often stays open
    /// afterward, e.g. waiting for this side to send its own `close_notify`
    /// back — which this client does not currently do. A caller that
    /// `poll()`s the raw fd for readability before calling `read()` (as
    /// `gateway_proxy.zig`'s close-delimited-body relay does, to avoid
    /// starving its own deadline against buffered-but-unpolled bytes) would
    /// otherwise wait out its *entire* deadline on every such connection,
    /// even though `read()` itself would not block at all. Observed as a
    /// streamed close-delimited response hanging for the full upstream
    /// response timeout instead of completing immediately (#634).
    pub fn readReady(self: *const UpstreamTlsConn) bool {
        return self.state.record.inbound_plaintext.len > 0 or self.state.record.peer_closed;
    }

    /// Bounds `drainQueuedRecordsAndCheckReady`'s drive loop against a
    /// pathologically fragmented record stream. A real TLS post-handshake
    /// message (e.g. a `NewSessionTicket`) is a handful of records at most;
    /// this is a generous upper bound on iterations, not a time budget --
    /// `drive()` never blocks, so exceeding it can only mean an unexpectedly
    /// long run of already-arrived records, not a slow peer.
    const max_drain_iterations = 256;

    /// Drains any TLS records already sitting on the raw fd (a
    /// `NewSessionTicket`, key update, or other post-handshake,
    /// record-layer-only traffic) without blocking, then reports whether
    /// genuine application data or a clean shutdown emerged. Unlike
    /// `readReady()`, which only reflects what a PRIOR `read()` call
    /// already decrypted, this proactively drives newly-arrived-but-undriven
    /// ciphertext through the record layer -- closing the gap where a
    /// hostile origin's ghost application-data record has arrived on the
    /// wire but has not yet been fed through it (#673 review round 8: a
    /// pooled connection is only safe to reuse if nothing at all -- decrypted
    /// or still-queued -- is waiting on it).
    ///
    /// Safe to call with nothing pending: the underlying fd is nonblocking
    /// (see the module doc comment), so `drive()` never blocks waiting for
    /// more bytes -- it either makes progress on what is already queued or
    /// reports no progress immediately, the same primitive `read()` itself
    /// uses before ever calling `waitForFd()`. Fails closed (reports
    /// "ready", i.e. do not reuse) on a drive error or on hitting the
    /// iteration bound, rather than risking a false "clean" result.
    ///
    /// A stalled drive (`made_progress == false`) is not by itself proof of
    /// "nothing pending": `drive()` can consume a prefix of a record into
    /// the parser without ever producing plaintext, if the record is only
    /// partially present. A hostile origin can trickle a ghost response's
    /// first few ciphertext bytes before release and complete it only after
    /// the connection is checked out again, and a check that only looks at
    /// `inbound_plaintext`/`peer_closed` would call that "clean" the moment
    /// the drive stalls waiting for the rest (#673 review round 10). So a
    /// stall is only treated as clean if the record layer isn't still
    /// holding onto anything -- raw carrier bytes not yet parsed, or a
    /// parser mid-record -- via the same three buffers
    /// `inboundCiphertextOwned()` sums internally.
    pub const CheckoutReadiness = union(enum) {
        clean,
        application_plaintext: usize,
        peer_closed,
        drive_error,
        incomplete_ciphertext: struct {
            inbound_carrier: usize,
            initial_parser: usize,
            ciphertext_parser: usize,
        },
        drain_budget_exhausted,
    };

    pub fn drainQueuedRecordsAndCheckReady(self: *UpstreamTlsConn) CheckoutReadiness {
        const record = &self.state.record;
        var iterations: usize = 0;
        while (true) {
            if (record.inbound_plaintext.len > 0) return .{ .application_plaintext = record.inbound_plaintext.len };
            if (record.peer_closed) return .peer_closed;
            if (iterations >= max_drain_iterations) return .drain_budget_exhausted;
            iterations += 1;
            const result = record.drive() catch return .drive_error;
            if (record.inbound_plaintext.len > 0) return .{ .application_plaintext = record.inbound_plaintext.len };
            if (record.peer_closed) return .peer_closed;
            if (!result.made_progress) {
                const inbound_carrier = record.inbound_carrier.len;
                const initial_parser = record.initial_parser.len;
                const ciphertext_parser = record.ciphertext_parser.len;
                const owned_ciphertext = inbound_carrier + initial_parser + ciphertext_parser;
                if (owned_ciphertext > 0) {
                    return .{ .incomplete_ciphertext = .{
                        .inbound_carrier = inbound_carrier,
                        .initial_parser = initial_parser,
                        .ciphertext_parser = ciphertext_parser,
                    } };
                }
                return .clean;
            }
        }
    }

    /// The ALPN protocol validated immediately after the handshake completed.
    pub fn negotiatedProtocol(self: *const UpstreamTlsConn) NegotiatedProtocol {
        return self.protocol;
    }
};

/// Drive the handshake to completion over the nonblocking carrier, waiting
/// (bounded) between `drive()` calls whenever a call makes no progress. Each
/// iteration is either genuine progress or one bounded `waitForFd` — never a
/// busy spin — so a call that reports no progress and for which `waitForFd`
/// times out means the peer genuinely went quiet past the caller's
/// configured socket timeout; that is a bounded failure.
fn driveUntilHandshakeComplete(record: *encrypted_stream.PureZigRecordStream, fd: std.posix.fd_t) TlsError!void {
    var iterations: usize = 0;
    while (!record.applicationDataOpen()) {
        iterations += 1;
        if (iterations > UpstreamTlsConn.max_handshake_drive_iterations) return error.HandshakeFailed;
        const result = record.drive() catch return error.HandshakeFailed;
        if (record.applicationDataOpen()) return;
        if (result.made_progress) continue;
        try waitForFd(fd, record.readiness(), error.HandshakeFailed);
    }
}

/// Block (via `poll`) until `fd` is ready for whatever `readiness` wants, up
/// to the caller's currently-configured `SO_RCVTIMEO`/`SO_SNDTIMEO` on `fd`
/// (0/unset means wait indefinitely, matching blocking-socket convention).
/// Returns `timeout_err` if `readiness` wants nothing (nothing to wait for —
/// a stuck record-layer state, not a socket condition), the poll itself
/// fails, or it times out.
fn waitForFd(fd: std.posix.fd_t, readiness: encrypted_stream.Readiness, timeout_err: TlsError) TlsError!void {
    if (!readiness.wants_read and !readiness.wants_write) return timeout_err;
    var events: i16 = 0;
    if (readiness.wants_read) events |= std.posix.POLL.IN;
    if (readiness.wants_write) events |= std.posix.POLL.OUT;
    var pfd = [1]std.posix.pollfd{.{ .fd = fd, .events = events, .revents = 0 }};
    const timeout_ms = currentSocketTimeoutMs(fd);
    const timeout: i32 = if (timeout_ms == 0) -1 else @intCast(@min(timeout_ms, @as(u32, @intCast(std.math.maxInt(i32)))));
    const ready = std.posix.poll(&pfd, timeout) catch return timeout_err;
    if (ready == 0) return timeout_err;
}

/// Read back whatever `SO_RCVTIMEO` is currently set on `fd`, in
/// milliseconds (0 if unset/disabled or unreadable) — the same value a
/// caller configures via `setSocketTimeoutMs` before calling `connect`,
/// `read`, or `writeAll`, reused here as this function's `poll()` deadline
/// instead of a per-syscall kernel timeout (see `connect`'s doc comment).
fn currentSocketTimeoutMs(fd: std.posix.fd_t) u32 {
    var tv: std.posix.timeval = undefined;
    var tv_len: std.posix.socklen_t = @sizeOf(std.posix.timeval);
    if (std.c.getsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, @ptrCast(&tv), &tv_len) != 0) return 0;
    if (tv.sec < 0) return 0;
    const ms: i64 = @as(i64, tv.sec) * 1000 + @divTrunc(@as(i64, tv.usec), 1000);
    if (ms <= 0) return 0;
    return @intCast(@min(ms, @as(i64, std.math.maxInt(u32))));
}

fn carrierRead(ptr: *anyopaque, out: []u8) encrypted_stream.Error!usize {
    const state: *UpstreamTlsState = @ptrCast(@alignCast(ptr));
    if (state.fd < 0) return error.StreamClosed;
    return readFd(state.fd, out);
}

fn carrierWrite(ptr: *anyopaque, bytes: []const u8) encrypted_stream.Error!usize {
    const state: *UpstreamTlsState = @ptrCast(@alignCast(ptr));
    if (state.fd < 0) return error.StreamClosed;
    return writeFd(state.fd, bytes);
}

fn carrierCloseNoop(_: *anyopaque) void {
    // `UpstreamTlsConn` does not let the record layer own fd lifecycle:
    // `close`/`deinit` (matching the OpenSSL adapter's split between them)
    // decide separately whether the caller or this type owns the fd.
}

/// Nonblocking read/write helpers for the upstream fd, structurally
/// identical to `native_tls_connection.zig`'s `readFd`/`writeFd` (same
/// errno mapping) and duplicated here rather than shared for the same reason
/// this file duplicates other small pieces of that module (see the file doc
/// comment): a self-contained client-side adapter, not a dependency on the
/// downstream listener's internals.
fn setNonBlocking(fd: std.posix.fd_t) !void {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const status_flags = linux.fcntl(fd, linux.F.GETFL, 0);
        if (linux.errno(status_flags) != .SUCCESS) return error.FcntlFailed;
        const nonblock: usize = @intCast(@as(u32, @bitCast(linux.O{ .NONBLOCK = true })));
        const rc = linux.fcntl(fd, linux.F.SETFL, status_flags | nonblock);
        if (linux.errno(rc) != .SUCCESS) return error.FcntlFailed;
    } else {
        const status_flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
        if (status_flags < 0) return error.FcntlFailed;
        const nonblock = @as(c_int, @bitCast(std.posix.O{ .NONBLOCK = true }));
        if (std.c.fcntl(fd, std.c.F.SETFL, status_flags | nonblock) < 0) return error.FcntlFailed;
    }
}

fn readFd(fd: std.posix.fd_t, out: []u8) encrypted_stream.Error!usize {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.read(fd, out.ptr, out.len);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            else => error.SocketReadFailed,
        };
    }
    const rc = std.c.read(fd, out.ptr, out.len);
    if (rc < 0) {
        if (std.posix.errno(rc) == .AGAIN) return error.WouldBlock;
        return error.SocketReadFailed;
    }
    return @intCast(rc);
}

fn writeFd(fd: std.posix.fd_t, bytes: []const u8) encrypted_stream.Error!usize {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.write(fd, bytes.ptr, bytes.len);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            else => error.SocketWriteFailed,
        };
    }
    const rc = std.c.write(fd, bytes.ptr, bytes.len);
    if (rc < 0) {
        if (std.posix.errno(rc) == .AGAIN) return error.WouldBlock;
        return error.SocketWriteFailed;
    }
    return @intCast(rc);
}

// #634: a bad fd must fail bounded rather than close-fail with a fixed
// sentinel error. An invalid fd fails immediately at `setNonBlocking` (an
// `fcntl` on -1 cannot succeed), before any handshake I/O is attempted,
// hence `ContextInitFailed` rather than `HandshakeFailed` here.
// `skip_verify = true` isolates this to the fd path, independent of
// whether the test environment happens to have a system CA bundle
// installed.
test "native upstream TLS connect fails closed on an unusable fd" {
    try std.testing.expectError(error.ContextInitFailed, UpstreamTlsConn.connect(-1, "example.com", .{ .skip_verify = true }));
}

// A staged-ownership regression test: `state.backend` is fully initialized by
// this point (it happens before client-mTLS-credential setup), so a failure
// here must deinitialize it rather than only freeing the raw `state`
// allocation via the outer `errdefer allocator.destroy(state)` — a bug fixed
// alongside the equivalent post-`state.record`-init case (both previously
// leaked handshake state on every error exit after their respective
// initialization point). `client_key_path` empty with `client_cert_path` set
// is the cheapest deterministic way to reach this exact failure point: it
// needs no filesystem access and no live peer, since it is rejected before
// `identity_loader.loadIdentity` ever runs. A valid-but-unconnected socket
// (one end of a socketpair) is enough — `setNonBlocking` needs a real fd, but
// this failure path returns before any handshake I/O is attempted on it.
test "native upstream TLS connect deinitializes the backend when client mTLS credential setup fails" {
    var fds: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    defer _ = std.c.close(fds[0]);
    defer _ = std.c.close(fds[1]);

    try std.testing.expectError(error.PrivateKeyLoadFailed, UpstreamTlsConn.connect(fds[1], "example.com", .{
        .skip_verify = true,
        .client_cert_path = "unused.crt",
        .client_key_path = "",
    }));
}
