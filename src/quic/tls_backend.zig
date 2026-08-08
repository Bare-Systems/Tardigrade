//! Thin QUIC profile for the TLS-owned TLS 1.3 engine.
//!
//! TLS handshake processing, key schedule, certificate verification, Finished
//! handling, and zeroization live in `tls_core.tls13_backend`. This module owns
//! only RFC 9000 transport-parameter/CID binding, QUIC epoch translation, and
//! construction of the shared engine with the QUIC extension profile.

const std = @import("std");
const config = @import("config.zig");
const varint = @import("quic_varint");
const tls_adapter = @import("tls_adapter.zig");
const tls_core = @import("tls_core");
const tls_handshake = @import("tls_handshake.zig");
const test_quic_crypto = @import("test_quic_crypto");
const crypto_pkg = @import("crypto");

const crypto_provider = crypto_pkg.provider;
const shared = tls_core.tls13_backend;
const RecordSink = tls_core.tls13_transport.EventSink;
const HandshakeError = tls_handshake.HandshakeError;
const EventSink = tls_handshake.EventSink;
const EncryptionLevel = tls_adapter.EncryptionLevel;

pub const Identity = shared.Identity;
pub const Trust = shared.Trust;
pub const Entropy = shared.Entropy;
pub const ClientOptions = shared.Tls13Backend.ClientOptions;
pub const CredentialProvider = tls_core.credentials.CredentialProvider;
pub const KeySchedule = shared.KeySchedule;
pub const hash_len = shared.hash_len;
pub const max_message_len = shared.max_message_len;
pub const max_certificate_len = shared.max_certificate_len;
pub const testdata = shared.testdata;
pub const EarlyDataCompatibilityCandidate = shared.EarlyDataCompatibilityCandidate;
pub const EarlyDataCompatibilityDecision = shared.EarlyDataCompatibilityDecision;
pub const EarlyDataCompatibilityGate = shared.EarlyDataCompatibilityGate;
pub const EarlyDataReplayCandidate = shared.EarlyDataReplayCandidate;
pub const EarlyDataReplayDecision = shared.EarlyDataReplayDecision;
pub const EarlyDataReplayGate = shared.EarlyDataReplayGate;
pub const ServerEarlyDataPolicy = shared.ServerEarlyDataPolicy;
pub const ClientEarlyDataIntent = shared.ClientEarlyDataIntent;

const ext_quic_transport_parameters: u16 = @intFromEnum(tls_core.algorithms.ExtensionType.quic_transport_parameters);
const tp_max_idle_timeout: u64 = 0x01;
const tp_max_udp_payload_size: u64 = 0x03;
const tp_initial_max_data: u64 = 0x04;
const tp_initial_max_stream_data_bidi_local: u64 = 0x05;
const tp_initial_max_stream_data_bidi_remote: u64 = 0x06;
const tp_initial_max_stream_data_uni: u64 = 0x07;
const tp_initial_max_streams_bidi: u64 = 0x08;
const tp_initial_max_streams_uni: u64 = 0x09;
const tp_disable_active_migration: u64 = 0x0c;
const tp_active_connection_id_limit: u64 = 0x0e;
const tp_original_destination_connection_id: u64 = 0x00;
const tp_stateless_reset_token: u64 = 0x02;
const tp_ack_delay_exponent: u64 = 0x0a;
const tp_max_ack_delay: u64 = 0x0b;
const tp_initial_source_connection_id: u64 = 0x0f;
const tp_retry_source_connection_id: u64 = 0x10;

pub const max_transport_parameters_len = 11 * (2 + 1 + 8) + 3 + 3 * (2 + 1 + config.max_cid_len) + (2 + 1 + 16);

pub fn encodeTransportParameters(params: config.TransportParameters, buf: []u8) HandshakeError![]const u8 {
    return encodeTransportParametersBound(params, &.{}, buf);
}

pub fn encodeTransportParametersBound(
    params: config.TransportParameters,
    binding: *const config.CidBinding,
    buf: []u8,
) HandshakeError![]const u8 {
    if (params.initial_max_streams_bidi > config.max_initial_streams_transport_parameter or
        params.initial_max_streams_uni > config.max_initial_streams_transport_parameter)
    {
        return error.InvalidTransportParameters;
    }

    var len: usize = 0;
    const entries = [_]struct { id: u64, value: u64 }{
        .{ .id = tp_max_idle_timeout, .value = params.max_idle_timeout_ms },
        .{ .id = tp_max_udp_payload_size, .value = params.max_udp_payload_size },
        .{ .id = tp_initial_max_data, .value = params.initial_max_data },
        .{ .id = tp_initial_max_stream_data_bidi_local, .value = params.initial_max_stream_data_bidi_local },
        .{ .id = tp_initial_max_stream_data_bidi_remote, .value = params.initial_max_stream_data_bidi_remote },
        .{ .id = tp_initial_max_stream_data_uni, .value = params.initial_max_stream_data_uni },
        .{ .id = tp_initial_max_streams_bidi, .value = params.initial_max_streams_bidi },
        .{ .id = tp_initial_max_streams_uni, .value = params.initial_max_streams_uni },
        .{ .id = tp_active_connection_id_limit, .value = params.active_connection_id_limit },
        .{ .id = tp_ack_delay_exponent, .value = params.ack_delay_exponent },
        .{ .id = tp_max_ack_delay, .value = params.max_ack_delay_ms },
    };
    for (entries) |entry| {
        len += varint.encode(entry.id, buf[len..]) catch return error.HandshakeBufferOverflow;
        const value_len = varint.encodedLen(entry.value) catch return error.HandshakeBufferOverflow;
        len += varint.encode(value_len, buf[len..]) catch return error.HandshakeBufferOverflow;
        len += varint.encode(entry.value, buf[len..]) catch return error.HandshakeBufferOverflow;
    }
    if (params.disable_active_migration) {
        len += varint.encode(tp_disable_active_migration, buf[len..]) catch return error.HandshakeBufferOverflow;
        len += varint.encode(0, buf[len..]) catch return error.HandshakeBufferOverflow;
    }
    const cid_entries = [_]struct { id: u64, value: ?config.CidValue }{
        .{ .id = tp_initial_source_connection_id, .value = binding.initial_source_connection_id },
        .{ .id = tp_original_destination_connection_id, .value = binding.original_destination_connection_id },
        .{ .id = tp_retry_source_connection_id, .value = binding.retry_source_connection_id },
    };
    for (cid_entries) |entry| {
        const value = entry.value orelse continue;
        len += varint.encode(entry.id, buf[len..]) catch return error.HandshakeBufferOverflow;
        len += varint.encode(value.len, buf[len..]) catch return error.HandshakeBufferOverflow;
        if (value.len > buf.len - len) return error.HandshakeBufferOverflow;
        @memcpy(buf[len..][0..value.len], value.slice());
        len += value.len;
    }
    if (binding.stateless_reset_token) |*token| {
        len += varint.encode(tp_stateless_reset_token, buf[len..]) catch return error.HandshakeBufferOverflow;
        len += varint.encode(token.len, buf[len..]) catch return error.HandshakeBufferOverflow;
        if (token.len > buf.len - len) return error.HandshakeBufferOverflow;
        @memcpy(buf[len..][0..token.len], token);
        len += token.len;
    }
    return buf[0..len];
}

pub const max_tracked_unknown_transport_parameters = 64;

pub fn decodeTransportParameters(bytes: []const u8) HandshakeError!config.TransportParameters {
    var binding = config.CidBinding{};
    defer binding.deinit();
    return decodeTransportParametersBound(bytes, &binding);
}

pub fn decodeTransportParametersBound(
    bytes: []const u8,
    binding: *config.CidBinding,
) HandshakeError!config.TransportParameters {
    var params = config.TransportParameters{
        .max_idle_timeout_ms = 0,
        .active_connection_id_limit = 2,
        .max_udp_payload_size = 65_527,
        .initial_max_data = 0,
        .initial_max_stream_data_bidi_local = 0,
        .initial_max_stream_data_bidi_remote = 0,
        .initial_max_stream_data_uni = 0,
        .initial_max_streams_bidi = 0,
        .initial_max_streams_uni = 0,
        .disable_active_migration = false,
    };
    var seen_known: u32 = 0;
    var seen_unknown: [max_tracked_unknown_transport_parameters]u64 = undefined;
    var seen_unknown_count: usize = 0;
    var offset: usize = 0;
    while (offset < bytes.len) {
        const id = varint.decode(bytes[offset..]) catch return error.InvalidTransportParameters;
        offset += id.len;
        const value_len = varint.decode(bytes[offset..]) catch return error.InvalidTransportParameters;
        offset += value_len.len;
        if (value_len.value > bytes.len - offset) return error.InvalidTransportParameters;
        const value_bytes = bytes[offset..][0..@intCast(value_len.value)];
        offset += value_bytes.len;

        if (knownTransportParameterBit(id.value)) |bit| {
            if (seen_known & bit != 0) return error.InvalidTransportParameters;
            seen_known |= bit;
        } else {
            for (seen_unknown[0..seen_unknown_count]) |seen_id| {
                if (seen_id == id.value) return error.InvalidTransportParameters;
            }
            // Unknown parameters must remain skippable. Once this bounded
            // duplicate cache fills, keep ignoring further distinct unknown IDs.
            if (seen_unknown_count < seen_unknown.len) {
                seen_unknown[seen_unknown_count] = id.value;
                seen_unknown_count += 1;
            }
        }

        switch (id.value) {
            tp_max_idle_timeout => params.max_idle_timeout_ms = try integerParameter(value_bytes),
            tp_max_udp_payload_size => params.max_udp_payload_size = try integerParameter(value_bytes),
            tp_initial_max_data => params.initial_max_data = try integerParameter(value_bytes),
            tp_initial_max_stream_data_bidi_local => params.initial_max_stream_data_bidi_local = try integerParameter(value_bytes),
            tp_initial_max_stream_data_bidi_remote => params.initial_max_stream_data_bidi_remote = try integerParameter(value_bytes),
            tp_initial_max_stream_data_uni => params.initial_max_stream_data_uni = try integerParameter(value_bytes),
            tp_initial_max_streams_bidi => {
                const value = try integerParameter(value_bytes);
                if (value > config.max_initial_streams_transport_parameter) return error.InvalidTransportParameters;
                params.initial_max_streams_bidi = value;
            },
            tp_initial_max_streams_uni => {
                const value = try integerParameter(value_bytes);
                if (value > config.max_initial_streams_transport_parameter) return error.InvalidTransportParameters;
                params.initial_max_streams_uni = value;
            },
            tp_disable_active_migration => {
                if (value_bytes.len != 0) return error.InvalidTransportParameters;
                params.disable_active_migration = true;
            },
            tp_active_connection_id_limit => params.active_connection_id_limit = try integerParameter(value_bytes),
            tp_ack_delay_exponent => {
                const value = try integerParameter(value_bytes);
                if (value > 20) return error.InvalidTransportParameters;
                params.ack_delay_exponent = @intCast(value);
            },
            tp_max_ack_delay => {
                const value = try integerParameter(value_bytes);
                if (value >= 1 << 14) return error.InvalidTransportParameters;
                params.max_ack_delay_ms = value;
            },
            tp_initial_source_connection_id => binding.initial_source_connection_id = config.CidValue.init(value_bytes) catch return error.InvalidTransportParameters,
            tp_original_destination_connection_id => binding.original_destination_connection_id = config.CidValue.init(value_bytes) catch return error.InvalidTransportParameters,
            tp_retry_source_connection_id => binding.retry_source_connection_id = config.CidValue.init(value_bytes) catch return error.InvalidTransportParameters,
            tp_stateless_reset_token => {
                if (value_bytes.len != 16) return error.InvalidTransportParameters;
                binding.stateless_reset_token = value_bytes[0..16].*;
            },
            else => {},
        }
    }
    if (params.max_udp_payload_size < 1200 or params.max_udp_payload_size > 65_527) return error.InvalidTransportParameters;
    if (params.active_connection_id_limit < 2) return error.InvalidTransportParameters;
    return params;
}

fn integerParameter(value_bytes: []const u8) HandshakeError!u64 {
    const decoded = varint.decode(value_bytes) catch return error.InvalidTransportParameters;
    if (decoded.len != value_bytes.len) return error.InvalidTransportParameters;
    return decoded.value;
}

fn knownTransportParameterBit(id: u64) ?u32 {
    const index: u5 = switch (id) {
        tp_original_destination_connection_id => 0,
        tp_max_idle_timeout => 1,
        tp_stateless_reset_token => 2,
        tp_max_udp_payload_size => 3,
        tp_initial_max_data => 4,
        tp_initial_max_stream_data_bidi_local => 5,
        tp_initial_max_stream_data_bidi_remote => 6,
        tp_initial_max_stream_data_uni => 7,
        tp_initial_max_streams_bidi => 8,
        tp_initial_max_streams_uni => 9,
        tp_ack_delay_exponent => 10,
        tp_max_ack_delay => 11,
        tp_disable_active_migration => 12,
        tp_active_connection_id_limit => 13,
        tp_initial_source_connection_id => 14,
        tp_retry_source_connection_id => 15,
        else => return null,
    };
    return @as(u32, 1) << index;
}

pub const Tls13Backend = struct {
    allocator: ?std.mem.Allocator = null,
    engine: shared.Tls13Backend,
    alpn: []const u8 = "h3",
    cid_binding: config.CidBinding = .{},
    peer_cid_binding: config.CidBinding = .{},
    local_transport_parameters: [max_transport_parameters_len]u8 = undefined,
    scratch: RecordSink = .{},

    pub fn initClient(entropy: Entropy, tls_crypto_provider: crypto_provider.CryptoProvider, trust: Trust) Tls13Backend {
        return initClientWithOptions(entropy, tls_crypto_provider, trust, .{});
    }

    pub fn initClientWithOptions(entropy: Entropy, tls_crypto_provider: crypto_provider.CryptoProvider, trust: Trust, options: ClientOptions) Tls13Backend {
        return initClientWithPolicyAndOptions(entropy, tls_crypto_provider, trust, tls_core.policy.Policy.quicDefault(), options);
    }

    /// QUIC's transport-parameters extension profile, with an explicitly
    /// supplied negotiation policy instead of `quicDefault()` (#338). The
    /// external conformance matrix needs to pin one cipher-suite/group/
    /// signature tuple per row and run it over *both* transports; without
    /// this, a QUIC row could only ever exercise the default policy while the
    /// record transport walked the whole matrix.
    ///
    /// `policy.transport_mode` must be `.quic`: the mode is what selects
    /// QUIC's own extension handling inside the engine, and a record-mode
    /// policy here would silently produce a handshake that is neither.
    pub fn initClientWithPolicyAndOptions(
        entropy: Entropy,
        tls_crypto_provider: crypto_provider.CryptoProvider,
        trust: Trust,
        policy: tls_core.policy.Policy,
        options: ClientOptions,
    ) Tls13Backend {
        std.debug.assert(policy.transport_mode == .quic);
        return .{ .engine = shared.Tls13Backend.initClientConfigured(entropy, tls_crypto_provider, trust, .{
            .policy = policy,
            .transport = .{ .extension = .{
                .extension_type = ext_quic_transport_parameters,
                .local = "",
            } },
        }, options) };
    }

    pub fn initClientWithAllocator(
        allocator: std.mem.Allocator,
        entropy: Entropy,
        tls_crypto_provider: crypto_provider.CryptoProvider,
        trust: Trust,
    ) HandshakeError!Tls13Backend {
        return initClientWithAllocatorAndOptions(allocator, entropy, tls_crypto_provider, trust, .{});
    }

    pub fn initClientWithAllocatorAndOptions(
        allocator: std.mem.Allocator,
        entropy: Entropy,
        tls_crypto_provider: crypto_provider.CryptoProvider,
        trust: Trust,
        options: ClientOptions,
    ) HandshakeError!Tls13Backend {
        var self = initClientWithOptions(entropy, tls_crypto_provider, trust, options);
        self.allocator = allocator;
        self.engine.setPostHandshakeAllocator(allocator) catch |err| return mapError(err);
        return self;
    }

    pub fn initServer(entropy: Entropy, tls_crypto_provider: crypto_provider.CryptoProvider, identity: Identity) Tls13Backend {
        return initServerWithPolicy(entropy, tls_crypto_provider, identity, tls_core.policy.Policy.quicDefault());
    }

    /// The server counterpart to `initClientWithPolicyAndOptions` (#338):
    /// QUIC's extension profile with an explicitly supplied negotiation
    /// policy, so a conformance row can pin the same tuple on both roles.
    /// `policy.transport_mode` must be `.quic`.
    pub fn initServerWithPolicy(
        entropy: Entropy,
        tls_crypto_provider: crypto_provider.CryptoProvider,
        identity: Identity,
        policy: tls_core.policy.Policy,
    ) Tls13Backend {
        std.debug.assert(policy.transport_mode == .quic);
        return .{ .engine = shared.Tls13Backend.initServerConfigured(entropy, tls_crypto_provider, identity, .{
            .policy = policy,
            .transport = .{ .extension = .{
                .extension_type = ext_quic_transport_parameters,
                .local = "",
            } },
        }) };
    }

    pub fn initServerWithAllocator(
        allocator: std.mem.Allocator,
        entropy: Entropy,
        tls_crypto_provider: crypto_provider.CryptoProvider,
        identity: Identity,
    ) Tls13Backend {
        var self = initServer(entropy, tls_crypto_provider, identity);
        self.allocator = allocator;
        return self;
    }

    pub fn initServerWithProvider(entropy: Entropy, tls_crypto_provider: crypto_provider.CryptoProvider, provider: CredentialProvider) Tls13Backend {
        return .{ .engine = shared.Tls13Backend.initServerWithProviderConfigured(entropy, tls_crypto_provider, provider, .{
            .policy = tls_core.policy.Policy.quicDefault(),
            .transport = .{ .extension = .{
                .extension_type = ext_quic_transport_parameters,
                .local = "",
            } },
        }) };
    }

    pub fn initServerWithAllocatorAndProvider(
        allocator: std.mem.Allocator,
        entropy: Entropy,
        tls_crypto_provider: crypto_provider.CryptoProvider,
        provider: CredentialProvider,
    ) Tls13Backend {
        var self = initServerWithProvider(entropy, tls_crypto_provider, provider);
        self.allocator = allocator;
        return self;
    }

    pub fn backend(self: *Tls13Backend) tls_handshake.TlsBackend {
        return .{
            .transport = .{
                .ptr = self,
                .startFn = start,
                .receiveFn = receive,
                .deinitFn = deinitImpl,
                // Forward asynchronous authentication progression (#334) to the
                // inner engine so a QUIC connection can drive a parked signer,
                // verifier, or selector without another inbound CRYPTO frame.
                .authPendingFn = authPending,
                .resumeFn = resumeAuth,
                .earlyDataAttemptedFn = earlyDataAttempted,
                .earlyDataMaxBytesFn = earlyDataMaxBytes,
                .earlyDataDiscardLimitFn = earlyDataDiscardLimit,
            },
            .setCidBindingFn = setCidBinding,
            .peerCidBindingFn = peerCidBinding,
            .setPostHandshakeAllocatorFn = setPostHandshakeAllocator,
            .setEarlyDataApplicationCompatFn = setEarlyDataApplicationCompatVtable,
            .emitNewSessionTicketFn = emitNewSessionTicket,
            .setServerPskResolverFn = setServerPskResolverVtable,
            .prepareNewSessionTicketFn = prepareNewSessionTicket,
            .emitPreparedNewSessionTicketFn = emitPreparedNewSessionTicket,
            .earlyDataAcceptedFn = earlyDataAcceptedVtable,
            .earlyDataDecisionFn = earlyDataDecisionVtable,
        };
    }

    fn earlyDataAcceptedVtable(ptr: *anyopaque) bool {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        return self.engine.earlyDataAccepted();
    }

    fn earlyDataDecisionVtable(ptr: *anyopaque) shared.EarlyDataDecision {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        return self.engine.earlyDataDecision();
    }

    fn earlyDataAttempted(ptr: *anyopaque) bool {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        return self.engine.earlyDataAttempted();
    }

    fn earlyDataMaxBytes(ptr: *anyopaque) u32 {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        return self.engine.earlyDataMaxBytes();
    }

    fn earlyDataDiscardLimit(ptr: *anyopaque) u32 {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        return self.engine.earlyDataDiscardLimit();
    }

    fn authPending(ptr: *anyopaque) bool {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        return self.engine.authPending();
    }

    fn resumeAuth(ptr: *anyopaque, sink: *EventSink) HandshakeError!void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        self.scratch.reset();
        const result = self.engine.resumeAuth(&self.scratch);
        try self.forwardPeerTransportParameters(sink);
        try translate(self.allocator, &self.scratch, sink);
        result catch |err| return mapError(err);
    }

    pub fn deinit(self: *Tls13Backend) void {
        self.scratch.deinit();
        self.engine.deinit();
        std.crypto.secureZero(u8, &self.local_transport_parameters);
        self.cid_binding.deinit();
        self.peer_cid_binding.deinit();
    }

    fn deinitImpl(ptr: *anyopaque) void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        self.deinit();
    }

    fn setCidBinding(ptr: *anyopaque, binding: *const config.CidBinding) void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        // Wipe the prior owner before replacing it: if this hook is ever
        // called more than once, assigning straight over a binding whose
        // token is `Some` would otherwise leave the old payload bytes
        // resident until final teardown instead of only until replacement.
        self.cid_binding.deinit();
        self.cid_binding = binding.*;
    }

    fn peerCidBinding(ptr: *anyopaque) *const config.CidBinding {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        return &self.peer_cid_binding;
    }

    fn setPostHandshakeAllocator(ptr: *anyopaque, allocator: std.mem.Allocator) HandshakeError!void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        if (self.engine.role != .client) return;
        if (self.allocator) |existing| {
            if (existing.ptr == allocator.ptr and existing.vtable == allocator.vtable) return;
        }
        self.allocator = allocator;
        self.engine.setPostHandshakeAllocator(allocator) catch |err| return mapError(err);
    }

    fn emitNewSessionTicket(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        sink: *EventSink,
        params: tls_handshake.EmitNewSessionTicketParams,
        limits: tls_core.session.Limits,
    ) HandshakeError!tls_core.session.ServerRecoverableState {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        self.scratch.reset();
        var state = self.engine.emitNewSessionTicket(allocator, &self.scratch, params, limits) catch |err| return mapError(err);
        errdefer state.deinit();
        try translate(self.allocator, &self.scratch, sink);
        return state;
    }

    /// #488: forwarding seam only — resolver selection, binder verification,
    /// and the PSK+DHE key schedule all stay in the shared engine. Must be
    /// called before the handshake starts (before `Connection.init`, which
    /// arms the responder), matching the shared engine's own precondition.
    pub fn setServerPskResolver(self: *Tls13Backend, resolver: tls_core.pre_shared_key.ServerPskResolver) HandshakeError!void {
        self.engine.setServerPskResolver(resolver) catch |err| return mapError(err);
    }

    pub fn setResumeCompatibilityPolicy(self: *Tls13Backend, policy: shared.Tls13Backend.ResumeCompatibilityPolicy) HandshakeError!void {
        self.engine.setResumeCompatibilityPolicy(policy) catch |err| return mapError(err);
    }

    pub fn setApplicationCompat(self: *Tls13Backend, blob: ?tls_core.new_session_ticket.CompatBlob) HandshakeError!void {
        self.engine.setApplicationCompat(blob) catch |err| return mapError(err);
    }

    pub fn setEarlyDataApplicationCompat(self: *Tls13Backend, blob: ?tls_core.new_session_ticket.CompatBlob) HandshakeError!void {
        self.engine.setEarlyDataApplicationCompat(blob) catch |err| return mapError(err);
    }

    fn setEarlyDataApplicationCompatVtable(ptr: *anyopaque, blob: ?tls_core.new_session_ticket.CompatBlob) HandshakeError!void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        try self.setEarlyDataApplicationCompat(blob);
    }

    pub fn setEarlyDataCompatibilityGate(self: *Tls13Backend, gate: EarlyDataCompatibilityGate) HandshakeError!void {
        self.engine.setEarlyDataCompatibilityGate(gate) catch |err| return mapError(err);
    }

    /// #368 Slice 2: installs the process-shared anti-replay gate on the
    /// shared engine — the same seam native TCP uses — so QUIC/H3 can never
    /// fall back to worker-local replay bookkeeping.
    pub fn setEarlyDataReplayGate(self: *Tls13Backend, gate: EarlyDataReplayGate) HandshakeError!void {
        self.engine.setEarlyDataReplayGate(gate) catch |err| return mapError(err);
    }

    /// #523: forwarding seam only — the accept/reject decision (PSK identity,
    /// replay, compatibility, age skew) stays entirely in the shared engine.
    /// Must be called before the handshake starts, matching every other
    /// early-data setter here.
    pub fn setServerEarlyDataPolicy(self: *Tls13Backend, policy: ServerEarlyDataPolicy) HandshakeError!void {
        self.engine.setServerEarlyDataPolicy(policy) catch |err| return mapError(err);
    }

    /// #523: forwarding seam only — offer/binder selection and the resulting
    /// early-traffic-secret export stay entirely in the shared engine. Must
    /// be called before the handshake starts.
    pub fn setClientEarlyDataIntent(self: *Tls13Backend, intent: ClientEarlyDataIntent) HandshakeError!void {
        self.engine.setClientEarlyDataIntent(intent) catch |err| return mapError(err);
    }

    pub fn setResumptionDecisionObserver(self: *Tls13Backend, observer: shared.Tls13Backend.ResumptionDecisionObserver) HandshakeError!void {
        self.engine.setResumptionDecisionObserver(observer) catch |err| return mapError(err);
    }

    fn setServerPskResolverVtable(ptr: *anyopaque, resolver: tls_core.pre_shared_key.ServerPskResolver) HandshakeError!void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        try self.setServerPskResolver(resolver);
    }

    fn prepareNewSessionTicket(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        params: tls_handshake.PrepareNewSessionTicketParams,
        limits: tls_core.session.Limits,
    ) HandshakeError!tls_handshake.PreparedNewSessionTicket {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        return self.engine.prepareNewSessionTicket(allocator, params, limits) catch |err| return mapError(err);
    }

    fn emitPreparedNewSessionTicket(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        sink: *EventSink,
        prepared: *const tls_handshake.PreparedNewSessionTicket,
        identity: []const u8,
        limits: tls_core.session.Limits,
    ) HandshakeError!void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        self.scratch.reset();
        self.engine.emitPreparedNewSessionTicket(allocator, &self.scratch, prepared, identity, limits) catch |err| return mapError(err);
        try translate(self.allocator, &self.scratch, sink);
    }

    fn start(ptr: *anyopaque, role: tls_handshake.Role, params: config.TransportParameters, sink: *EventSink) HandshakeError!void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        const encoded = try encodeTransportParametersBound(params, &self.cid_binding, &self.local_transport_parameters);
        self.engine.profile = .{ .extension = .{
            .extension_type = ext_quic_transport_parameters,
            .local = encoded,
        } };
        self.scratch.reset();
        const result = self.engine.backend().start(role, {}, &self.scratch);
        try self.forwardPeerTransportParameters(sink);
        try translate(self.allocator, &self.scratch, sink);
        result catch |err| return mapError(err);
    }

    fn receive(ptr: *anyopaque, level: EncryptionLevel, bytes: []const u8, sink: *EventSink) HandshakeError!void {
        const self: *Tls13Backend = @ptrCast(@alignCast(ptr));
        self.scratch.reset();
        const result = self.engine.backend().receive(toEpoch(level), bytes, &self.scratch);
        try self.forwardPeerTransportParameters(sink);
        try translate(self.allocator, &self.scratch, sink);
        result catch |err| return mapError(err);
    }

    fn forwardPeerTransportParameters(self: *Tls13Backend, sink: *EventSink) HandshakeError!void {
        const bytes = self.engine.takePeerTransportExtension() orelse return;
        try sink.emitPeerTransportParameters(try decodeTransportParametersBound(bytes, &self.peer_cid_binding));
    }
};

fn translate(allocator: ?std.mem.Allocator, source: *RecordSink, destination: *EventSink) HandshakeError!void {
    var index: usize = 0;
    while (index < source.len) : (index += 1) {
        const event = source.items[index];
        switch (event) {
            .handshake_bytes => |item| {
                if (item.data.len <= EventSink.max_bytes) {
                    try destination.emitHandshakeBytes(toLevel(item.epoch), item.data);
                } else if (source.takeOwnedHandshakePayload(index)) |payload| {
                    destination.emitOwnedHandshakeBytes(payload.allocator, toLevel(item.epoch), payload.bytes) catch |err| {
                        crypto_pkg.secrets.secureZeroAndFree(payload.allocator, payload.bytes);
                        return err;
                    };
                } else {
                    const explicit_allocator = allocator orelse return error.InvalidHandshakeState;
                    try destination.emitOwnedHandshakeBytesCopy(explicit_allocator, toLevel(item.epoch), item.data);
                }
            },
            .negotiated_parameters => |params| try destination.emitNegotiatedParameters(params),
            .early_data_parameters => |params| try destination.emitEarlyDataParameters(params),
            .traffic_secret => |item| try destination.emitSecret(toLevel(item.epoch), item.direction, item.data),
            .peer_transport_parameters => {},
            .alpn => |protocol| try destination.emitAlpn(protocol),
            .certificate => |state| try destination.emitCertificate(state),
            .discard_epoch => |epoch| try destination.emitDiscardEpoch(toLevel(epoch)),
            .handshake_complete => try destination.emitHandshakeComplete(),
            .fatal_alert => |alert| try destination.emitFatalAlert(alert),
        }
    }
}

fn mapError(err: tls_core.tls13_transport.Error) HandshakeError {
    return switch (err) {
        error.UnexpectedTransportEpoch => error.UnexpectedCryptoLevel,
        error.MissingTransportExtension => error.MissingTransportParameters,
        error.TransportBufferOverflow => error.HandshakeBufferOverflow,
        error.InvalidTransportProfile => error.InvalidHandshakeState,
        else => @errorCast(err),
    };
}

fn toEpoch(level: EncryptionLevel) tls_core.events.EncryptionEpoch {
    return switch (level) {
        .initial => .initial,
        .zero_rtt => .zero_rtt,
        .handshake => .handshake,
        .application => .application,
    };
}

fn toLevel(epoch: tls_core.events.EncryptionEpoch) EncryptionLevel {
    return switch (epoch) {
        .initial => .initial,
        .zero_rtt => .zero_rtt,
        .handshake => .handshake,
        .application => .application,
    };
}

test "QUIC transport parameters remain owned by the QUIC adapter" {
    const params = (config.Config{}).transportParameters() catch unreachable;
    var buf: [max_transport_parameters_len]u8 = undefined;
    const encoded = try encodeTransportParameters(params, &buf);
    const decoded = try decodeTransportParameters(encoded);
    try std.testing.expectEqualDeep(params, decoded);
}

test "QUIC transport parameter decoding preserves defaults and unknown values" {
    const bytes = [_]u8{ 0x21, 0x03, 0xaa, 0xbb, 0xcc, 0x03, 0x02, 0x45, 0xac };
    const decoded = try decodeTransportParameters(&bytes);
    try std.testing.expectEqual(@as(u64, 1452), decoded.max_udp_payload_size);
    try std.testing.expectEqual(@as(u64, 2), decoded.active_connection_id_limit);
    try std.testing.expectEqual(@as(u64, 0), decoded.initial_max_data);
    try std.testing.expect(!decoded.disable_active_migration);
}

test "QUIC transport parameter decoding rejects duplicates and illegal values" {
    const duplicated = [_]u8{ 0x03, 0x02, 0x45, 0xac, 0x03, 0x02, 0x45, 0xac };
    try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&duplicated));
    const duplicated_unknown = [_]u8{ 0x2a, 0x01, 0xaa, 0x2a, 0x01, 0xbb };
    try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&duplicated_unknown));
    const truncated = [_]u8{ 0x04, 0x08, 0x00 };
    try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&truncated));
    const overlong = [_]u8{ 0x04, 0x02, 0x01, 0xff };
    try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&overlong));
    const illegal = [_]u8{ 0x03, 0x02, 0x40, 0x64 };
    try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&illegal));
    const flag_with_value = [_]u8{ 0x0c, 0x01, 0x01 };
    try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&flag_with_value));
}

test "QUIC adapter owns CID binding round trip" {
    const params = (config.Config{}).transportParameters() catch unreachable;
    const scid = try config.CidValue.init(&.{ 0x01, 0x02, 0x03, 0x04 });
    const odcid = try config.CidValue.init(&.{ 0x10, 0x11, 0x12 });
    const local = config.CidBinding{
        .initial_source_connection_id = scid,
        .original_destination_connection_id = odcid,
        .stateless_reset_token = [_]u8{0xa5} ** 16,
    };
    var buf: [max_transport_parameters_len]u8 = undefined;
    const encoded = try encodeTransportParametersBound(params, &local, &buf);
    var peer = config.CidBinding{};
    _ = try decodeTransportParametersBound(encoded, &peer);
    try std.testing.expectEqualDeep(local, peer);
}

test "transport parameter encoder rejects outbound stream count violations" {
    var params = (config.Config{
        .initial_max_streams_bidi = config.max_initial_streams_transport_parameter,
        .initial_max_streams_uni = config.max_initial_streams_transport_parameter,
    }).transportParameters() catch unreachable;
    var buf: [max_transport_parameters_len]u8 = undefined;
    _ = try encodeTransportParameters(params, &buf);

    params.initial_max_streams_bidi = config.max_initial_streams_transport_parameter + 1;
    try std.testing.expectError(error.InvalidTransportParameters, encodeTransportParameters(params, &buf));
    params.initial_max_streams_bidi = config.max_initial_streams_transport_parameter;
    params.initial_max_streams_uni = config.max_initial_streams_transport_parameter + 1;
    try std.testing.expectError(error.InvalidTransportParameters, encodeTransportParameters(params, &buf));
}

test "transport parameter structural fuzz seeds preserve typed boundaries" {
    try std.testing.expectEqualDeep(config.TransportParameters{
        .max_idle_timeout_ms = 0,
        .active_connection_id_limit = 2,
        .max_udp_payload_size = 65_527,
        .initial_max_data = 0,
        .initial_max_stream_data_bidi_local = 0,
        .initial_max_stream_data_bidi_remote = 0,
        .initial_max_stream_data_uni = 0,
        .initial_max_streams_bidi = 0,
        .initial_max_streams_uni = 0,
        .disable_active_migration = false,
    }, try decodeTransportParameters(&.{}));

    try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&.{0xff}));
    try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&.{ tp_initial_max_data, 0xff }));
    try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&.{ tp_initial_max_data, 0x02, 0x00 }));
    try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&.{ tp_initial_max_data, 0x01, 0x40 }));
    try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&.{ tp_initial_max_data, 0x02, 0x01, 0xff }));

    const unknown = [_]u8{ 0x21, 0x03, 0xaa, 0xbb, 0xcc };
    _ = try decodeTransportParameters(&unknown);
    const duplicate_unknown = [_]u8{ 0x21, 0x00, 0x21, 0x00 };
    try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(&duplicate_unknown));

    var many: [512]u8 = undefined;
    var pos: usize = 0;
    var id: u64 = 0x21;
    while (id < 0x21 + max_tracked_unknown_transport_parameters + 8) : (id += 1) {
        try appendTpRaw(&many, &pos, id, &.{});
    }
    _ = try decodeTransportParameters(many[0..pos]);
}

test "transport parameter semantic boundary regressions" {
    try expectTpIntRejected(tp_max_udp_payload_size, 1199);
    try std.testing.expectEqual(@as(u64, 1200), (try decodeOneTpInt(tp_max_udp_payload_size, 1200)).max_udp_payload_size);
    try std.testing.expectEqual(@as(u64, 65_527), (try decodeOneTpInt(tp_max_udp_payload_size, 65_527)).max_udp_payload_size);
    try expectTpIntRejected(tp_max_udp_payload_size, 65_528);

    try expectTpIntRejected(tp_active_connection_id_limit, 0);
    try expectTpIntRejected(tp_active_connection_id_limit, 1);
    try std.testing.expectEqual(@as(u64, 2), (try decodeOneTpInt(tp_active_connection_id_limit, 2)).active_connection_id_limit);
    try std.testing.expectEqual(@as(u64, max_quic_varint), (try decodeOneTpInt(tp_active_connection_id_limit, max_quic_varint)).active_connection_id_limit);

    try std.testing.expectEqual(@as(u8, 20), (try decodeOneTpInt(tp_ack_delay_exponent, 20)).ack_delay_exponent);
    try expectTpIntRejected(tp_ack_delay_exponent, 21);
    try std.testing.expectEqual(@as(u64, (1 << 14) - 1), (try decodeOneTpInt(tp_max_ack_delay, (1 << 14) - 1)).max_ack_delay_ms);
    try expectTpIntRejected(tp_max_ack_delay, 1 << 14);

    try std.testing.expectEqual(@as(u64, 0), (try decodeOneTpInt(tp_initial_max_data, 0)).initial_max_data);
    try std.testing.expectEqual(@as(u64, 7), (try decodeOneTpInt(tp_initial_max_stream_data_bidi_local, 7)).initial_max_stream_data_bidi_local);
    try std.testing.expectEqual(max_quic_varint, (try decodeOneTpInt(tp_initial_max_stream_data_bidi_remote, max_quic_varint)).initial_max_stream_data_bidi_remote);
    try std.testing.expectEqual(@as(u64, 0), (try decodeOneTpInt(tp_initial_max_stream_data_uni, 0)).initial_max_stream_data_uni);
    try std.testing.expectEqual(@as(u64, 3), (try decodeOneTpInt(tp_initial_max_streams_bidi, 3)).initial_max_streams_bidi);
    try std.testing.expectEqual(config.max_initial_streams_transport_parameter, (try decodeOneTpInt(tp_initial_max_streams_bidi, config.max_initial_streams_transport_parameter)).initial_max_streams_bidi);
    try expectTpIntRejected(tp_initial_max_streams_bidi, config.max_initial_streams_transport_parameter + 1);
    try std.testing.expectEqual(config.max_initial_streams_transport_parameter, (try decodeOneTpInt(tp_initial_max_streams_uni, config.max_initial_streams_transport_parameter)).initial_max_streams_uni);
    try expectTpIntRejected(tp_initial_max_streams_uni, config.max_initial_streams_transport_parameter + 1);

    var flag: [8]u8 = undefined;
    var pos: usize = 0;
    try appendTpRaw(&flag, &pos, tp_disable_active_migration, &.{});
    try std.testing.expect((try decodeTransportParameters(flag[0..pos])).disable_active_migration);
    pos = 0;
    try appendTpRaw(&flag, &pos, tp_disable_active_migration, &.{0});
    try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(flag[0..pos]));
}

test "transport parameter CID binding boundary regressions" {
    const max_cid = [_]u8{0xcd} ** config.max_cid_len;
    const cid_ids = [_]u64{
        tp_initial_source_connection_id,
        tp_original_destination_connection_id,
        tp_retry_source_connection_id,
    };
    inline for (cid_ids) |id| {
        var zero: [8]u8 = undefined;
        var pos: usize = 0;
        try appendTpRaw(&zero, &pos, id, &.{});
        var zero_binding = config.CidBinding{};
        _ = try decodeTransportParametersBound(zero[0..pos], &zero_binding);
        try expectBindingCidLen(zero_binding, id, 0);

        var exact: [64]u8 = undefined;
        pos = 0;
        try appendTpRaw(&exact, &pos, id, &max_cid);
        var exact_binding = config.CidBinding{};
        _ = try decodeTransportParametersBound(exact[0..pos], &exact_binding);
        try expectBindingCidLen(exact_binding, id, config.max_cid_len);

        var one_over: [64]u8 = undefined;
        pos = 0;
        try appendTpRaw(&one_over, &pos, id, &([_]u8{0xee} ** (config.max_cid_len + 1)));
        var rejected_binding = config.CidBinding{};
        try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParametersBound(one_over[0..pos], &rejected_binding));
    }

    var reset: [64]u8 = undefined;
    var pos: usize = 0;
    try appendTpRaw(&reset, &pos, tp_stateless_reset_token, &([_]u8{0xa5} ** 16));
    var binding = config.CidBinding{};
    _ = try decodeTransportParametersBound(reset[0..pos], &binding);
    try std.testing.expectEqualSlices(u8, &([_]u8{0xa5} ** 16), &binding.stateless_reset_token.?);
    pos = 0;
    try appendTpRaw(&reset, &pos, tp_stateless_reset_token, &([_]u8{0xa5} ** 15));
    try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParametersBound(reset[0..pos], &binding));
    pos = 0;
    try appendTpRaw(&reset, &pos, tp_stateless_reset_token, &([_]u8{0xa5} ** 17));
    try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParametersBound(reset[0..pos], &binding));
}

test "fuzz: transport parameter decoder preserves bounded structural contract" {
    try std.testing.fuzz({}, fuzzTransportParameterDecode, .{ .corpus = &.{
        "",
        "\xff",
        "\x04\xff",
        "\x04\x02\x00",
        "\x04\x01\x40",
        "\x04\x02\x01\xff",
        "\x21\x03\xaa\xbb\xcc",
        "\x21\x00\x21\x00",
        "\x03\x02\x44\xb0",
        "\x0e\x01\x02",
        "\x0c\x00",
        "\x0c\x01\x00",
        "\x0f\x00",
        "\x02\x10abcdefghijklmnop",
    } });
}

test "fuzz: transport parameters canonical encode and binding round-trip" {
    try std.testing.fuzz({}, fuzzTransportParameterRoundTrip, .{ .corpus = &.{
        "\x00",
        "\x01\x02\x03\x04",
        "\x14\x00\x10\x08",
        "\xff\x00\x7f\x40",
    } });
}

const max_quic_varint = (1 << 62) - 1;

fn appendTpRaw(out: []u8, pos: *usize, id: u64, value: []const u8) !void {
    pos.* += varint.encode(id, out[pos.*..]) catch return error.TestUnexpectedResult;
    pos.* += varint.encode(value.len, out[pos.*..]) catch return error.TestUnexpectedResult;
    if (value.len > out.len - pos.*) return error.TestUnexpectedResult;
    @memcpy(out[pos.*..][0..value.len], value);
    pos.* += value.len;
}

fn appendTpInt(out: []u8, pos: *usize, id: u64, value: u64) !void {
    var encoded: [8]u8 = undefined;
    const value_len = varint.encode(value, &encoded) catch return error.TestUnexpectedResult;
    try appendTpRaw(out, pos, id, encoded[0..value_len]);
}

fn decodeOneTpInt(id: u64, value: u64) !config.TransportParameters {
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    try appendTpInt(&buf, &pos, id, value);
    return try decodeTransportParameters(buf[0..pos]);
}

fn expectTpIntRejected(id: u64, value: u64) !void {
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    try appendTpInt(&buf, &pos, id, value);
    try std.testing.expectError(error.InvalidTransportParameters, decodeTransportParameters(buf[0..pos]));
}

fn expectBindingCidLen(binding: config.CidBinding, id: u64, expected_len: usize) !void {
    const value = switch (id) {
        tp_initial_source_connection_id => binding.initial_source_connection_id,
        tp_original_destination_connection_id => binding.original_destination_connection_id,
        tp_retry_source_connection_id => binding.retry_source_connection_id,
        else => unreachable,
    } orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(expected_len, value.slice().len);
}

fn fuzzTransportParameterDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len = smith.slice(&buf);
    var binding = config.CidBinding{};
    const decoded = decodeTransportParametersBound(buf[0..len], &binding) catch return;
    try std.testing.expect(decoded.max_udp_payload_size >= 1200);
    try std.testing.expect(decoded.max_udp_payload_size <= 65_527);
    try std.testing.expect(decoded.active_connection_id_limit >= 2);
    try std.testing.expect(decoded.ack_delay_exponent <= 20);
    try std.testing.expect(decoded.max_ack_delay_ms < 1 << 14);
    if (binding.initial_source_connection_id) |value| try std.testing.expect(value.slice().len <= config.max_cid_len);
    if (binding.original_destination_connection_id) |value| try std.testing.expect(value.slice().len <= config.max_cid_len);
    if (binding.retry_source_connection_id) |value| try std.testing.expect(value.slice().len <= config.max_cid_len);
}

fn fuzzTransportParameterRoundTrip(_: void, smith: *std.testing.Smith) !void {
    var cid_bytes: [config.max_cid_len]u8 = undefined;
    var odcid_bytes: [config.max_cid_len]u8 = undefined;
    var retry_bytes: [config.max_cid_len]u8 = undefined;
    @memset(&cid_bytes, 0);
    @memset(&odcid_bytes, 0);
    @memset(&retry_bytes, 0);
    _ = smith.slice(&cid_bytes);
    _ = smith.slice(&odcid_bytes);
    _ = smith.slice(&retry_bytes);
    const cid_len = @as(usize, smith.value(u8)) % (config.max_cid_len + 1);
    const odcid_len = @as(usize, smith.value(u8)) % (config.max_cid_len + 1);
    const retry_len = @as(usize, smith.value(u8)) % (config.max_cid_len + 1);

    const params = config.TransportParameters{
        .max_idle_timeout_ms = @as(u64, smith.value(u32)),
        .active_connection_id_limit = 2 + @as(u64, smith.value(u16)),
        .max_udp_payload_size = 1200 + (@as(u64, smith.value(u16)) % (65_527 - 1200 + 1)),
        .initial_max_data = smith.value(u64) & max_quic_varint,
        .initial_max_stream_data_bidi_local = smith.value(u64) & max_quic_varint,
        .initial_max_stream_data_bidi_remote = smith.value(u64) & max_quic_varint,
        .initial_max_stream_data_uni = smith.value(u64) & max_quic_varint,
        .initial_max_streams_bidi = smith.value(u64) % (config.max_initial_streams_transport_parameter + 1),
        .initial_max_streams_uni = smith.value(u64) % (config.max_initial_streams_transport_parameter + 1),
        .disable_active_migration = smith.value(u1) == 1,
        .ack_delay_exponent = @as(u8, smith.value(u5)) % 21,
        .max_ack_delay_ms = @as(u64, smith.value(u16)) % (1 << 14),
    };
    const binding = config.CidBinding{
        .initial_source_connection_id = try config.CidValue.init(cid_bytes[0..cid_len]),
        .original_destination_connection_id = try config.CidValue.init(odcid_bytes[0..odcid_len]),
        .retry_source_connection_id = try config.CidValue.init(retry_bytes[0..retry_len]),
        .stateless_reset_token = [_]u8{smith.value(u8)} ** 16,
    };

    var encoded: [max_transport_parameters_len]u8 = undefined;
    const bytes = try encodeTransportParametersBound(params, &binding, &encoded);
    var decoded_binding = config.CidBinding{};
    const decoded = try decodeTransportParametersBound(bytes, &decoded_binding);
    try std.testing.expectEqualDeep(params, decoded);
    try std.testing.expectEqualDeep(binding, decoded_binding);
}

test "QUIC TLS backend does not embed maximum ticket storage" {
    try std.testing.expect(@sizeOf(Tls13Backend) < 128 * 1024);
    try std.testing.expect(@sizeOf(Tls13Backend) < tls_core.tls13_transport.max_new_session_ticket_message_len);
}

test "QUIC adapter teardown wipes private scratch, parameters, and shared engine ownership" {
    const entropy = Entropy{ .hello_random = [_]u8{0x31} ** 32 };
    var backend = Tls13Backend.initServer(
        entropy,
        test_quic_crypto.testDefaultProvider(),
        try Identity.initPkcs8(testdata.certificate_der, testdata.private_key_pkcs8_der),
    );
    @memset(&backend.local_transport_parameters, 0xa5);
    const secret = [_]u8{0x5a} ** hash_len;
    try backend.scratch.emitSecret(.handshake, .write, &secret);
    const used = backend.scratch.used;
    try std.testing.expect(used > 0);

    backend.deinit();

    try std.testing.expectEqual(@as(usize, 0), backend.scratch.used);
    try std.testing.expect(std.mem.allEqual(u8, backend.scratch.scratch[0..used], 0));
    try std.testing.expect(std.mem.allEqual(u8, &backend.local_transport_parameters, 0));
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&backend.engine.identity), 0));
    try std.testing.expect(!backend.engine.identity_present);
    try std.testing.expect(std.mem.allEqual(u8, &backend.engine.peer_transport_extension, 0));
}

const RealHandshakeHarness = struct {
    client_adapter: tls_adapter.QuicTlsAdapter = .{ .provider = test_quic_crypto.testDefaultProvider() },
    server_adapter: tls_adapter.QuicTlsAdapter = .{ .provider = test_quic_crypto.testDefaultProvider() },
    // Owned, per-instance deterministic TLS-engine provider storage (#490
    // review), not the shared `test_quic_crypto.testHandshakeProvider()`
    // stream: every harness instance gets its own independent entropy.
    // `undefined` until `init`/`initWithSniProvider` seed it in place —
    // never read before then.
    client_provider_storage: test_quic_crypto.HandshakeProviderStorage = undefined,
    server_provider_storage: test_quic_crypto.HandshakeProviderStorage = undefined,
    client_backend: Tls13Backend = undefined,
    server_backend: Tls13Backend = undefined,
    client: tls_handshake.Handshake = undefined,
    server: tls_handshake.Handshake = undefined,
    wired: bool = false,
    deinitialized: bool = false,

    /// Out-parameter style rather than `fn init() !RealHandshakeHarness`
    /// (#490 review): `self.client_provider_storage`/`.server_provider_
    /// storage` must be seeded at their *final* address before the
    /// `CryptoProvider` values borrowing that storage are constructed, which
    /// a `return .{...}` struct literal cannot guarantee — the literal is
    /// not necessarily built in place at the eventual call site's storage.
    /// Callers declare `var harness: RealHandshakeHarness = undefined;`
    /// then `try harness.init();`.
    fn init(self: *RealHandshakeHarness) !void {
        const client_crypto_provider = self.client_provider_storage.init(0x442_c);
        const server_crypto_provider = self.server_provider_storage.init(0x442_5);
        self.client_adapter = .{ .provider = test_quic_crypto.testDefaultProvider() };
        self.server_adapter = .{ .provider = test_quic_crypto.testDefaultProvider() };
        self.client_backend = try Tls13Backend.initClientWithAllocator(
            std.testing.allocator,
            .{ .hello_random = [_]u8{0xc1} ** 32 },
            client_crypto_provider,
            .{ .pinned_certificate = testdata.certificate_der },
        );
        self.server_backend = Tls13Backend.initServerWithAllocator(
            std.testing.allocator,
            .{ .hello_random = [_]u8{0x51} ** 32 },
            server_crypto_provider,
            try Identity.initPkcs8(testdata.certificate_der, testdata.private_key_pkcs8_der),
        );
        self.client = undefined;
        self.server = undefined;
        self.wired = false;
        self.deinitialized = false;
    }

    fn initWithSniProvider(self: *RealHandshakeHarness, server_name: []const u8, provider: tls_core.credentials.CredentialProvider) !void {
        const client_crypto_provider = self.client_provider_storage.init(0x442_c);
        const server_crypto_provider = self.server_provider_storage.init(0x442_5);
        self.client_adapter = .{ .provider = test_quic_crypto.testDefaultProvider() };
        self.server_adapter = .{ .provider = test_quic_crypto.testDefaultProvider() };
        self.client_backend = try Tls13Backend.initClientWithAllocatorAndOptions(
            std.testing.allocator,
            .{ .hello_random = [_]u8{0xc1} ** 32 },
            client_crypto_provider,
            .{ .pinned_certificate = testdata.certificate_der },
            .{ .server_name = server_name },
        );
        self.server_backend = Tls13Backend.initServerWithAllocatorAndProvider(
            std.testing.allocator,
            .{ .hello_random = [_]u8{0x51} ** 32 },
            server_crypto_provider,
            provider,
        );
        self.client = undefined;
        self.server = undefined;
        self.wired = false;
        self.deinitialized = false;
    }

    fn wire(self: *RealHandshakeHarness) !void {
        self.client = tls_handshake.Handshake.initClient(&self.client_adapter, self.client_backend.backend());
        self.server = tls_handshake.Handshake.initServer(&self.server_adapter, self.server_backend.backend());
        self.wired = true;
        try self.server.start((config.Config{}).transportParameters() catch unreachable);
    }

    fn run(self: *RealHandshakeHarness) HandshakeError!void {
        if (self.client.driver.state == .idle) {
            try self.client.start((config.Config{}).transportParameters() catch unreachable);
        }
        var rounds: usize = 0;
        while (rounds < 64) : (rounds += 1) {
            var progressed = false;
            inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |level| {
                var buf: [2048]u8 = undefined;
                while (try self.client.pollOutput(level, &buf)) |out| {
                    try self.server.onCrypto(level, out.offset, out.bytes);
                    progressed = true;
                }
                while (try self.server.pollOutput(level, &buf)) |out| {
                    try self.client.onCrypto(level, out.offset, out.bytes);
                    progressed = true;
                }
            }
            if (!progressed) return;
        }
        return error.InvalidHandshakeState;
    }

    fn deinit(self: *RealHandshakeHarness) void {
        if (self.deinitialized) return;
        self.deinitialized = true;
        if (self.wired) {
            self.client.deinit();
            self.server.deinit();
        } else {
            self.client_backend.deinit();
            self.server_backend.deinit();
        }
    }
};

fn expectQuicBackendWiped(backend: *const Tls13Backend) !void {
    try std.testing.expectEqual(@as(usize, 0), backend.scratch.used);
    try std.testing.expect(std.mem.allEqual(u8, &backend.local_transport_parameters, 0));
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&backend.engine.key_pair), 0));
    try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&backend.engine.identity), 0));
    try std.testing.expect(!backend.engine.key_pair_present);
    try std.testing.expect(!backend.engine.identity_present);
    try std.testing.expect(std.mem.allEqual(u8, &backend.engine.peer_transport_extension, 0));
}

test "QUIC handshake owner tears down shared and adapter storage on success" {
    var harness: RealHandshakeHarness = undefined;
    try harness.init();
    defer harness.deinit();
    try harness.wire();
    try harness.run();
    try std.testing.expect(harness.client.isComplete());
    try std.testing.expect(harness.server.isComplete());
    harness.deinit();
    try expectQuicBackendWiped(&harness.client_backend);
    try expectQuicBackendWiped(&harness.server_backend);
}

test "QUIC TLS backend delivers large post-handshake tickets through application CRYPTO chunks" {
    const Capture = struct {
        count: usize = 0,
        psk: [hash_len]u8 = undefined,
        ticket_len: usize = 0,

        fn now(_: *anyopaque) i64 {
            return 10;
        }

        fn onTicket(ctx: *anyopaque, ticket: *const tls_core.session.ClientTicketState) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.count += 1;
            @memcpy(&self.psk, ticket.common.resumption_psk.slice());
            self.ticket_len = ticket.ticket.slice().len;
        }
    };

    var harness: RealHandshakeHarness = undefined;
    try harness.init();
    defer harness.deinit();
    var capture = Capture{};
    const limits = tls_core.session.Limits{ .max_ticket_len = tls_core.session.absolute_ticket_wire_max, .max_serialized_len = 128 * 1024 };
    try harness.client_backend.engine.setSessionTicketConsumer(std.testing.allocator, limits, .{
        .ctx = &capture,
        .nowUnixMsFn = Capture.now,
        .onTicketFn = Capture.onTicket,
    });
    try harness.wire();
    try harness.run();

    const opaque_ticket = try std.testing.allocator.alloc(u8, tls_core.session.absolute_ticket_wire_max);
    defer std.testing.allocator.free(opaque_ticket);
    @memset(opaque_ticket, 0xa5);

    var shared_sink = RecordSink{};
    defer shared_sink.deinit();
    var server_state = try harness.server_backend.engine.emitNewSessionTicket(std.testing.allocator, &shared_sink, .{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .opaque_ticket = opaque_ticket,
        .issued_at_unix_ms = 10,
    }, limits);
    defer server_state.deinit();
    try std.testing.expect(shared_sink.items[0].handshake_bytes.data.len > 16 * 1024);

    var quic_sink = EventSink{};
    defer quic_sink.deinit();
    try translate(std.testing.allocator, &shared_sink, &quic_sink);
    try std.testing.expectEqual(@as(usize, 1), quic_sink.len);
    try harness.server_adapter.queueHandshakeOutput(
        quic_sink.items[0].handshake_bytes.epoch,
        quic_sink.items[0].handshake_bytes.data,
    );

    var chunks: usize = 0;
    var buf: [4096]u8 = undefined;
    while (try harness.server.pollOutput(.application, &buf)) |out| {
        chunks += 1;
        try harness.client.onCrypto(.application, out.offset, out.bytes);
    }
    try std.testing.expect(chunks > 1);
    try std.testing.expectEqual(@as(usize, 1), capture.count);
    try std.testing.expectEqual(opaque_ticket.len, capture.ticket_len);
    try std.testing.expectEqualSlices(u8, server_state.common.resumption_psk.slice(), &capture.psk);
}

test "QUIC TLS backend drops valid post-handshake ticket with no consumer" {
    var harness: RealHandshakeHarness = undefined;
    try harness.init();
    defer harness.deinit();
    try harness.wire();
    try harness.run();

    var shared_sink = RecordSink{};
    defer shared_sink.deinit();
    var server_state = try harness.server_backend.engine.emitNewSessionTicket(std.testing.allocator, &shared_sink, .{
        .ticket_lifetime = 60,
        .ticket_age_add = 1,
        .ticket_nonce = "\x01",
        .opaque_ticket = "drop-ticket",
        .issued_at_unix_ms = 10,
    }, tls_core.session.Limits.default);
    defer server_state.deinit();

    var quic_sink = EventSink{};
    defer quic_sink.deinit();
    try translate(std.testing.allocator, &shared_sink, &quic_sink);
    try harness.server_adapter.queueHandshakeOutput(
        quic_sink.items[0].handshake_bytes.epoch,
        quic_sink.items[0].handshake_bytes.data,
    );

    var chunks: usize = 0;
    var buf: [4]u8 = undefined;
    while (try harness.server.pollOutput(.application, &buf)) |out| {
        chunks += 1;
        try harness.client.onCrypto(.application, out.offset, out.bytes);
    }
    try std.testing.expect(chunks > 1);
    try std.testing.expect(harness.client.isComplete());
    try std.testing.expect(harness.server.isComplete());
}

fn quicSniConfig(patterns: []const []const u8, chain: []const []const u8) tls_core.sni_provider.CredentialBundleConfig {
    return .{
        .chain = chain,
        .patterns = patterns,
        .signer = tls_core.sni_provider.SignAdapter.fromIdentity(Identity.initPkcs8(testdata.certificate_der, testdata.private_key_pkcs8_der) catch unreachable, tls_core.credentials.testdata.ignoredEntropy()),
        .key_kind = .ed25519,
        .is_default = true,
    };
}

test "QUIC handshake uses the shared reloadable SNI provider" {
    var provider = tls_core.sni_provider.ReloadableProvider.init(std.testing.allocator);
    defer provider.deinit();

    const chain = [_][]const u8{testdata.certificate_der};
    const first_patterns = [_][]const u8{"quic-one.example.test"};
    try provider.reload(&.{quicSniConfig(first_patterns[0..], chain[0..])}, .{ .unknown_sni_policy = .fail_handshake });
    {
        var harness: RealHandshakeHarness = undefined;
        try harness.initWithSniProvider("quic-one.example.test", provider.provider());
        defer harness.deinit();
        try harness.wire();
        try harness.run();
        try std.testing.expect(harness.client.isComplete());
        try std.testing.expect(harness.server.isComplete());
    }

    const second_patterns = [_][]const u8{"quic-two.example.test"};
    try provider.reload(&.{quicSniConfig(second_patterns[0..], chain[0..])}, .{ .unknown_sni_policy = .fail_handshake });
    {
        var harness: RealHandshakeHarness = undefined;
        try harness.initWithSniProvider("quic-two.example.test", provider.provider());
        defer harness.deinit();
        try harness.wire();
        try harness.run();
        try std.testing.expect(harness.client.isComplete());
        try std.testing.expect(harness.server.isComplete());
    }
}

test "QUIC handshake owner tears down shared and adapter storage on failure" {
    var harness: RealHandshakeHarness = undefined;
    try harness.init();
    defer harness.deinit();
    harness.client_backend.engine.trust = .{ .pinned_certificate = "not the server certificate" };
    try harness.wire();
    try std.testing.expectError(error.CertificateInvalid, harness.run());
    harness.deinit();
    try expectQuicBackendWiped(&harness.client_backend);
    try expectQuicBackendWiped(&harness.server_backend);
}

test "QUIC handshake owner tears down shared and adapter storage when abandoned" {
    var harness: RealHandshakeHarness = undefined;
    try harness.init();
    defer harness.deinit();
    try harness.wire();
    harness.deinit();
    try expectQuicBackendWiped(&harness.client_backend);
    try expectQuicBackendWiped(&harness.server_backend);
}

test "the QUIC production driver resumes an async server signature without another peer CRYPTO frame (#334)" {
    // A genuinely asynchronous server signer parks after ClientHello. No further
    // client CRYPTO will arrive until the server sends its Finished, so progress
    // must come from resumeAuth alone — the QUIC backend forwards pending/resume
    // to the inner engine, and the driver exposes it.
    var mock = tls_core.credentials.MockCredentialProvider.init(
        try Identity.initPkcs8(testdata.certificate_der, testdata.private_key_pkcs8_der),
    );
    mock.async_sign = true;
    mock.pending_polls = 2;

    var client_adapter = tls_adapter.QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
    var server_adapter = tls_adapter.QuicTlsAdapter{ .provider = test_quic_crypto.testDefaultProvider() };
    var client_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
    var server_provider_storage: test_quic_crypto.HandshakeProviderStorage = .{};
    var client_backend = Tls13Backend.initClient(
        .{ .hello_random = [_]u8{0xc1} ** 32 },
        client_provider_storage.init(0x442_c),
        .{ .pinned_certificate = testdata.certificate_der },
    );
    var server_backend = Tls13Backend.initServer(
        .{ .hello_random = [_]u8{0x51} ** 32 },
        server_provider_storage.init(0x442_5),
        try Identity.initPkcs8(testdata.certificate_der, testdata.private_key_pkcs8_der),
    );
    // Serve the server credential through the async mock rather than the fixed
    // identity's synchronous signer.
    server_backend.engine.external_provider = mock.provider();

    var client = tls_handshake.Handshake.initClient(&client_adapter, client_backend.backend());
    var server = tls_handshake.Handshake.initServer(&server_adapter, server_backend.backend());
    defer client.deinit();
    defer server.deinit();

    const params = (config.Config{}).transportParameters() catch unreachable;
    try server.start(params);
    try client.start(params);

    // Deliver the ClientHello; the server emits ServerHello/EncryptedExtensions/
    // Certificate and then parks awaiting the asynchronous signature.
    var buf: [2048]u8 = undefined;
    while (try client.pollOutput(.initial, &buf)) |out| {
        try server.onCrypto(.initial, out.offset, out.bytes);
    }
    try std.testing.expect(server.authPending());

    // Advance the signature purely through resumeAuth — no further peer CRYPTO.
    var guard: usize = 0;
    while (server.authPending()) : (guard += 1) {
        if (guard > 16) return error.TestResumeStuck;
        try server.resumeAuth();
    }
    try std.testing.expect(!server.authPending());

    // With the flight now produced, the remaining exchange completes both sides.
    var rounds: usize = 0;
    while (rounds < 64) : (rounds += 1) {
        var progressed = false;
        inline for (.{ EncryptionLevel.initial, EncryptionLevel.handshake }) |level| {
            while (try server.pollOutput(level, &buf)) |out| {
                try client.onCrypto(level, out.offset, out.bytes);
                progressed = true;
            }
            while (try client.pollOutput(level, &buf)) |out| {
                try server.onCrypto(level, out.offset, out.bytes);
                progressed = true;
            }
        }
        if (!progressed) break;
    }
    try std.testing.expect(client.isComplete());
    try std.testing.expect(server.isComplete());
}
