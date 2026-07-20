//! Transport-neutral resumable TLS 1.3 session and ticket model (#360).
//!
//! This module defines the owned value types for TLS 1.3 session resumption
//! shared by record-mode TLS and QUIC/H3: common resumable-session metadata,
//! client-held ticket state, server-recoverable state, a bounded internal
//! serialization codec for that state, and typed compatibility decisions.
//!
//! It intentionally does not implement the RFC 8446 `NewSessionTicket`
//! handshake-message codec or resumed-handshake behavior (see
//! `messages.zig` / `tls13_backend.zig` for the existing framing check, and
//! issue #361), `pre_shared_key` / binder handling (#362), ticket encryption
//! (#363), session-cache storage (#364), or transport integration (#365). It
//! also does not import QUIC transport-parameter or HTTP/3 SETTINGS types:
//! transport/application compatibility is represented as bounded opaque
//! blobs so those adapters can be built on top without this module knowing
//! about them.
//!
//! The internal serialization defined here (`encodeClient`/`decode`/etc.) is
//! a caller-facing persistence format, not the wire format. Encoded state
//! contains bearer secrets (the resumption PSK and the raw ticket) and must
//! be treated as sensitive plaintext: it must be encrypted and authenticated
//! (#363) before leaving a trusted process or persistence boundary.
//!
//! ## Ownership
//!
//! Every owning aggregate (`ResumableSessionCommon`, `ClientTicketState`,
//! `ServerRecoverableState`, `CompatSnapshot`) is initialized in place via a
//! pointer-based `init`, released via `deinit`, deep-copied via `cloneInto`,
//! and transferred via `moveFrom`/`moveInto`. A move leaves the source
//! zero-valued (safe to `deinit` again or reuse); an ordinary `a = b;`
//! bitwise copy of one of these types aliases heap-backed secret storage
//! and must never be relied on as a public API.

const std = @import("std");
const crypto = @import("crypto");
const algorithms = @import("algorithms.zig");
const dns_name = @import("dns_name.zig");
const sni_provider = @import("sni_provider.zig");

const secrets = crypto.secrets;

pub const max_sni_len = dns_name.max_name_len;
pub const max_alpn_len = 255;
pub const max_ticket_nonce_len = 255;
pub const auth_binding_len = 32;
pub const max_psk_len = 48;

/// RFC 8446 §4.6.1: ticket_lifetime is a uint32 number of seconds, and
/// SHOULD NOT exceed seven days.
pub const max_lifetime_seconds: u32 = 604_800;

/// RFC 8446 §4.6.1: `ticket<1..2^16-1>`. This is the absolute wire maximum,
/// not a default: `Limits.max_ticket_len` is the caller-tightenable default
/// every internal decoder/cache should actually accept.
pub const absolute_ticket_wire_max: usize = 65535;

/// Hard ceiling on `Limits.max_fields`. Comfortably above the ~14 fields the
/// current format ever emits, while still bounding the fixed-size
/// duplicate/count tracking used during decode.
pub const hard_max_fields: usize = 64;

/// Hard ceiling on `Limits.max_transport_compat_len` /
/// `Limits.max_application_compat_len`.
pub const hard_max_compat_len: usize = 8192;

/// Hard ceiling on `Limits.max_serialized_len`.
pub const hard_max_serialized_len: usize = 128 * 1024;

/// Caller-tightenable bounds for the internal state codec. Defaults are
/// deliberately small; callers that need to accept larger tickets or
/// compatibility blobs must opt in explicitly, and `validate` rejects any
/// attempt to exceed the hard module/protocol caps above.
pub const Limits = struct {
    max_fields: usize = 32,
    max_ticket_len: usize = 4096,
    max_transport_compat_len: usize = 1024,
    max_application_compat_len: usize = 1024,
    max_serialized_len: usize = 4096,

    pub const default: Limits = .{};

    pub fn validate(self: Limits) error{InvalidLimits}!void {
        if (self.max_fields == 0 or self.max_fields > hard_max_fields) return error.InvalidLimits;
        if (self.max_ticket_len == 0 or self.max_ticket_len > absolute_ticket_wire_max) return error.InvalidLimits;
        if (self.max_transport_compat_len > hard_max_compat_len) return error.InvalidLimits;
        if (self.max_application_compat_len > hard_max_compat_len) return error.InvalidLimits;
        if (self.max_serialized_len == 0 or self.max_serialized_len > hard_max_serialized_len) return error.InvalidLimits;
    }
};

pub const ResumptionPsk = secrets.FixedSecret(max_psk_len);

/// Resume-only vs early-data-capable policy for a resumable session.
pub const EarlyDataPolicy = union(enum) {
    resume_only,
    /// Maximum early-data byte count the server is willing to accept; must
    /// be non-zero (a zero-byte allowance is expressed as `.resume_only`).
    early_data_capable: u32,

    pub fn maxEarlyData(self: EarlyDataPolicy) u32 {
        return switch (self) {
            .resume_only => 0,
            .early_data_capable => |max| max,
        };
    }
};

/// A bounded, opaque compatibility snapshot for a transport or application
/// layer, identified by a caller-defined format id/version. Equality is
/// exact: any byte difference is a mismatch.
///
/// The blob is allocator-backed (`crypto.secrets.BoundedSecret`) so its
/// capacity is caller-tunable via `Limits` rather than a fixed comptime
/// array embedded in every session, and so it carries the same
/// no-ordinary-formatting guarantee as other owned state here even though it
/// is not cryptographic key material.
pub const CompatSnapshot = struct {
    format_id: u16 = 0,
    format_version: u16 = 0,
    blob: secrets.BoundedSecret = .{},

    pub const InitError = error{ OutOfMemory, CompatSnapshotTooLarge, InvalidLimits };

    /// `self` must be zero-valued (`.{}`) or a previously-initialized,
    /// live `CompatSnapshot` — never `undefined` memory: on entry this
    /// safely releases whatever `self` currently owns (a no-op if `self`
    /// is already zero-valued) before installing the new blob, so calling
    /// `init` again on an already-live snapshot cannot leak the prior
    /// allocation.
    ///
    /// `limit` is still checked against the absolute module cap
    /// (`hard_max_compat_len`) here, not just against `data.len`: this
    /// constructor must not trust a caller-supplied `limit` that itself
    /// exceeds what `Limits.validate` would ever allow, since the encode
    /// path's fixed scratch buffer is sized to `hard_max_compat_len`.
    pub fn init(
        self: *CompatSnapshot,
        allocator: std.mem.Allocator,
        format_id: u16,
        snapshot_version: u16,
        data: []const u8,
        limit: usize,
    ) InitError!void {
        if (limit > hard_max_compat_len) return error.InvalidLimits;
        if (data.len > limit) return error.CompatSnapshotTooLarge;
        self.deinit();
        self.format_id = format_id;
        self.format_version = snapshot_version;
        self.blob.init(allocator, data.len, data) catch |err| switch (err) {
            error.SecretTooLarge => return error.CompatSnapshotTooLarge,
            else => return error.OutOfMemory,
        };
    }

    pub fn deinit(self: *CompatSnapshot) void {
        self.blob.deinit();
    }

    pub fn slice(self: *const CompatSnapshot) []const u8 {
        return self.blob.slice();
    }

    pub fn eql(self: *const CompatSnapshot, other: *const CompatSnapshot) bool {
        return self.format_id == other.format_id and
            self.format_version == other.format_version and
            std.mem.eql(u8, self.slice(), other.slice());
    }

    /// `out` must be zero-valued or a previously-initialized, live
    /// `CompatSnapshot` — never `undefined` memory (see `init`).
    pub fn cloneInto(self: *const CompatSnapshot, allocator: std.mem.Allocator, out: *CompatSnapshot) error{OutOfMemory}!void {
        out.deinit();
        out.format_id = self.format_id;
        out.format_version = self.format_version;
        out.blob.init(allocator, self.blob.slice().len, self.blob.slice()) catch return error.OutOfMemory;
    }

    /// Transfers ownership of `source`'s allocation into `self`. `source`
    /// becomes zero-valued and safe to `deinit` or reinitialize. `self`
    /// must be zero-valued or a previously-initialized, live
    /// `CompatSnapshot` — never `undefined` memory (see `init`); any
    /// storage `self` already owns is released first. Moving a value into
    /// itself (`self == source`) is a safe no-op rather than an
    /// accidental self-wipe.
    pub fn moveFrom(self: *CompatSnapshot, source: *CompatSnapshot) void {
        if (self == source) return;
        self.deinit();
        self.* = source.*;
        source.* = .{};
    }

    pub fn moveInto(self: *CompatSnapshot, dest: *CompatSnapshot) void {
        dest.moveFrom(self);
    }

    pub fn format(
        _: CompatSnapshot,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        _: anytype,
    ) !void {
        @compileError("compatibility snapshots must not be formatted or logged");
    }
};

/// Canonical ASCII-lowercase SNI, validated with the shared TLS DNS-name
/// rules at construction time. A `null` `ResumableSessionCommon.server_name`
/// means the original handshake had no SNI; an empty *present* value is
/// invalid and rejected at construction.
pub const SniName = struct {
    len: u8 = 0,
    bytes: [max_sni_len]u8 = undefined,

    pub fn init(raw: []const u8) dns_name.Error!SniName {
        try dns_name.validateHostName(raw);
        var self = SniName{};
        for (raw, 0..) |ch, i| self.bytes[i] = sni_provider.asciiLower(ch);
        self.len = @intCast(raw.len);
        return self;
    }

    pub fn slice(self: *const SniName) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn eqlIgnoreCase(self: *const SniName, candidate: []const u8) bool {
        return sni_provider.asciiEqlIgnoreCase(self.slice(), candidate);
    }
};

/// Owned, bounded ALPN protocol name (RFC 7301 protocol names are
/// length-prefixed by a single byte, so 255 bytes is the wire maximum). A
/// `null` `ResumableSessionCommon.application_protocol` means ALPN was
/// absent or negotiated outside TLS; an empty *present* value is invalid.
pub const AlpnProtocol = struct {
    len: u8 = 0,
    bytes: [max_alpn_len]u8 = undefined,

    pub const Error = error{AlpnProtocolTooLarge};

    pub fn init(raw: []const u8) Error!AlpnProtocol {
        if (raw.len == 0 or raw.len > max_alpn_len) return error.AlpnProtocolTooLarge;
        var self = AlpnProtocol{};
        @memcpy(self.bytes[0..raw.len], raw);
        self.len = @intCast(raw.len);
        return self;
    }

    pub fn slice(self: *const AlpnProtocol) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn eql(self: *const AlpnProtocol, other: []const u8) bool {
        return std.mem.eql(u8, self.slice(), other);
    }
};

/// Stable authentication binding for the peer identity a session was
/// negotiated with. For format version 1 this is a SHA-256 digest of the
/// leaf certificate DER (not `sni_provider.Snapshot.generation`, which is
/// process-local reload-ordering state, not a portable identity).
pub const AuthBinding = struct {
    bytes: [auth_binding_len]u8,

    pub fn fromLeafCertificateDer(der: []const u8) AuthBinding {
        var digest: [auth_binding_len]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(der, &digest, .{});
        return .{ .bytes = digest };
    }

    pub fn eql(self: AuthBinding, other: AuthBinding) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }
};

/// Common resumable-session metadata shared by client-ticket state and
/// server-recoverable state.
///
/// Owns a resumption PSK and, optionally, transport/application
/// compatibility snapshots (both allocator-backed). See the module-level
/// ownership note: use `init`/`deinit`/`cloneInto`/`moveFrom` rather than
/// constructing or copying this value directly.
pub const ResumableSessionCommon = struct {
    resumption_psk: ResumptionPsk = .{},
    cipher_suite: algorithms.CipherSuite = .tls_aes_128_gcm_sha256,
    /// `null` means the original handshake had no SNI.
    server_name: ?SniName = null,
    /// `null` means ALPN was absent or negotiated outside TLS.
    application_protocol: ?AlpnProtocol = null,
    auth_binding: AuthBinding = .{ .bytes = [_]u8{0} ** auth_binding_len },
    issued_at_unix_ms: i64 = 0,
    lifetime_seconds: u32 = 0,
    early_data: EarlyDataPolicy = .resume_only,
    transport_compat: ?CompatSnapshot = null,
    application_compat: ?CompatSnapshot = null,

    pub const CompatBlobParams = struct {
        format_id: u16,
        format_version: u16,
        bytes: []const u8,
    };

    pub const InitParams = struct {
        cipher_suite: algorithms.CipherSuite,
        resumption_psk: []const u8,
        server_name: ?[]const u8 = null,
        application_protocol: ?[]const u8 = null,
        auth_binding: AuthBinding,
        issued_at_unix_ms: i64,
        lifetime_seconds: u32,
        early_data: EarlyDataPolicy = .resume_only,
        transport_compat: ?CompatBlobParams = null,
        application_compat: ?CompatBlobParams = null,
    };

    pub const InitError = error{
        OutOfMemory,
        InvalidLimits,
        InvalidDnsName,
        EmptyServerName,
        AlpnProtocolTooLarge,
        EmptyApplicationProtocol,
        InvalidPskLength,
        InvalidLifetime,
        InvalidEarlyDataPolicy,
        CompatSnapshotTooLarge,
    };

    pub fn init(
        self: *ResumableSessionCommon,
        allocator: std.mem.Allocator,
        limits: Limits,
        params: InitParams,
    ) InitError!void {
        try limits.validate();

        const expected_psk_len = algorithms.transcriptHash(params.cipher_suite).digestLength();
        if (params.resumption_psk.len != expected_psk_len) return error.InvalidPskLength;
        if (params.lifetime_seconds == 0 or params.lifetime_seconds > max_lifetime_seconds)
            return error.InvalidLifetime;
        switch (params.early_data) {
            .resume_only => {},
            .early_data_capable => |max| if (max == 0) return error.InvalidEarlyDataPolicy,
        }

        // `self` must be zero-valued or a previously-initialized, live
        // value — never `undefined` memory. `deinit` safely releases
        // whatever `self` currently owns (a no-op if already zero-valued)
        // before this reinitializes it, so calling `init` again on an
        // already-live value cannot leak the prior PSK/compat allocations.
        self.deinit();
        self.* = .{};
        errdefer self.deinit();

        self.cipher_suite = params.cipher_suite;
        self.auth_binding = params.auth_binding;
        self.issued_at_unix_ms = params.issued_at_unix_ms;
        self.lifetime_seconds = params.lifetime_seconds;
        self.early_data = params.early_data;

        if (params.server_name) |raw| {
            if (raw.len == 0) return error.EmptyServerName;
            self.server_name = try SniName.init(raw);
        }
        if (params.application_protocol) |raw| {
            if (raw.len == 0) return error.EmptyApplicationProtocol;
            self.application_protocol = try AlpnProtocol.init(raw);
        }

        self.resumption_psk.replace(params.resumption_psk) catch unreachable;

        if (params.transport_compat) |blob| {
            var snap = CompatSnapshot{};
            try snap.init(allocator, blob.format_id, blob.format_version, blob.bytes, limits.max_transport_compat_len);
            self.transport_compat = snap;
        }
        if (params.application_compat) |blob| {
            var snap = CompatSnapshot{};
            try snap.init(allocator, blob.format_id, blob.format_version, blob.bytes, limits.max_application_compat_len);
            self.application_compat = snap;
        }
    }

    pub fn deinit(self: *ResumableSessionCommon) void {
        self.resumption_psk.deinit();
        if (self.transport_compat) |*snap| snap.deinit();
        if (self.application_compat) |*snap| snap.deinit();
        self.transport_compat = null;
        self.application_compat = null;
    }

    /// `out` must be zero-valued or a previously-initialized, live value —
    /// never `undefined` memory (see `init`).
    pub fn cloneInto(
        self: *const ResumableSessionCommon,
        allocator: std.mem.Allocator,
        out: *ResumableSessionCommon,
    ) error{OutOfMemory}!void {
        out.deinit();
        out.* = .{};
        errdefer out.deinit();

        out.cipher_suite = self.cipher_suite;
        out.server_name = self.server_name;
        out.application_protocol = self.application_protocol;
        out.auth_binding = self.auth_binding;
        out.issued_at_unix_ms = self.issued_at_unix_ms;
        out.lifetime_seconds = self.lifetime_seconds;
        out.early_data = self.early_data;
        out.resumption_psk = self.resumption_psk.copy();

        if (self.transport_compat) |*snap| {
            var cloned = CompatSnapshot{};
            try snap.cloneInto(allocator, &cloned);
            out.transport_compat = cloned;
        }
        if (self.application_compat) |*snap| {
            var cloned = CompatSnapshot{};
            try snap.cloneInto(allocator, &cloned);
            out.application_compat = cloned;
        }
    }

    /// Transfers ownership of `source`'s secret/blob storage into `self`.
    /// `source` becomes zero-valued and safe to `deinit` or reinitialize.
    /// `self` must be zero-valued or a previously-initialized, live value
    /// — never `undefined` memory (see `init`); any storage `self` already
    /// owns is released first. Moving a value into itself (`self ==
    /// source`) is a safe no-op rather than an accidental self-wipe.
    pub fn moveFrom(self: *ResumableSessionCommon, source: *ResumableSessionCommon) void {
        if (self == source) return;
        self.deinit();
        self.* = source.*;
        source.* = .{};
    }

    pub fn moveInto(self: *ResumableSessionCommon, dest: *ResumableSessionCommon) void {
        dest.moveFrom(self);
    }

    pub fn isNotYetValid(self: *const ResumableSessionCommon, now_unix_ms: i64) bool {
        return now_unix_ms < self.issued_at_unix_ms;
    }

    /// Overflow-safe: computed in `i128` regardless of how close
    /// `issued_at_unix_ms`/`now_unix_ms` are to the `i64` extremes.
    pub fn isExpired(self: *const ResumableSessionCommon, now_unix_ms: i64) bool {
        const age_ms: i128 = @as(i128, now_unix_ms) - @as(i128, self.issued_at_unix_ms);
        if (age_ms < 0) return false;
        const lifetime_ms: i128 = @as(i128, self.lifetime_seconds) * 1000;
        return age_ms >= lifetime_ms;
    }

    pub fn format(
        _: ResumableSessionCommon,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        _: anytype,
    ) !void {
        @compileError("resumable session state must not be formatted or logged");
    }
};

/// Client-owned ticket state: the common session metadata plus the opaque
/// ticket identity and timing needed to offer resumption. The ticket bytes
/// are a bearer credential transmitted on the wire, but are held under the
/// same secret ownership/redaction rules as the PSK.
pub const ClientTicketState = struct {
    common: ResumableSessionCommon = .{},
    ticket: secrets.BoundedSecret = .{},
    ticket_age_add: u32 = 0,
    ticket_nonce: secrets.FixedSecret(max_ticket_nonce_len) = .{},
    received_at_unix_ms: i64 = 0,

    pub const InitParams = struct {
        ticket: []const u8,
        ticket_age_add: u32,
        ticket_nonce: []const u8,
        received_at_unix_ms: i64,
    };

    pub const InitError = error{ OutOfMemory, InvalidLimits, TicketTooLarge, NonceTooLarge };

    /// Initializes `self` in place and takes ownership of `common` by
    /// moving it out of the caller's variable: on every path (success or
    /// failure) `common.*` becomes zero-valued and safe to `deinit` or
    /// reinitialize, and it is never left duplicated between caller and
    /// callee.
    pub fn init(
        self: *ClientTicketState,
        allocator: std.mem.Allocator,
        limits: Limits,
        common: *ResumableSessionCommon,
        params: InitParams,
    ) InitError!void {
        try limits.validate();

        // `self` must be zero-valued or a previously-initialized, live
        // value — never `undefined` memory (see
        // `ResumableSessionCommon.init`).
        self.deinit();
        self.* = .{};
        self.common.moveFrom(common);
        errdefer self.deinit();

        if (params.ticket.len == 0 or params.ticket.len > limits.max_ticket_len) return error.TicketTooLarge;
        if (params.ticket_nonce.len > max_ticket_nonce_len) return error.NonceTooLarge;

        self.ticket.init(allocator, params.ticket.len, params.ticket) catch |err| switch (err) {
            error.SecretTooLarge => return error.TicketTooLarge,
            else => return error.OutOfMemory,
        };
        self.ticket_nonce.replace(params.ticket_nonce) catch return error.NonceTooLarge;
        self.ticket_age_add = params.ticket_age_add;
        self.received_at_unix_ms = params.received_at_unix_ms;
    }

    pub fn deinit(self: *ClientTicketState) void {
        self.common.deinit();
        self.ticket.deinit();
        self.ticket_nonce.deinit();
    }

    /// `out` must be zero-valued or a previously-initialized, live value —
    /// never `undefined` memory (see `init`).
    pub fn cloneInto(
        self: *const ClientTicketState,
        allocator: std.mem.Allocator,
        out: *ClientTicketState,
    ) error{OutOfMemory}!void {
        out.deinit();
        out.* = .{};
        errdefer out.deinit();

        try self.common.cloneInto(allocator, &out.common);
        out.ticket.init(allocator, self.ticket.slice().len, self.ticket.slice()) catch return error.OutOfMemory;
        out.ticket_nonce = self.ticket_nonce.copy();
        out.ticket_age_add = self.ticket_age_add;
        out.received_at_unix_ms = self.received_at_unix_ms;
    }

    /// `self` must be zero-valued or a previously-initialized, live value
    /// — never `undefined` memory (see `init`); any storage `self` already
    /// owns is released first. Moving a value into itself (`self ==
    /// source`) is a safe no-op rather than an accidental self-wipe.
    pub fn moveFrom(self: *ClientTicketState, source: *ClientTicketState) void {
        if (self == source) return;
        self.deinit();
        self.* = source.*;
        source.* = .{};
    }

    pub fn moveInto(self: *ClientTicketState, dest: *ClientTicketState) void {
        dest.moveFrom(self);
    }

    /// Overflow-safe elapsed time since receipt, saturating to zero if
    /// `now_unix_ms` predates `received_at_unix_ms` (e.g. clock skew), and
    /// computed in `i128` so the subtraction itself can never trap or wrap
    /// even at the `i64` extremes.
    pub fn ageMillis(self: *const ClientTicketState, now_unix_ms: i64) u64 {
        const age: i128 = @as(i128, now_unix_ms) - @as(i128, self.received_at_unix_ms);
        if (age <= 0) return 0;
        return @intCast(@min(age, @as(i128, std.math.maxInt(u64))));
    }

    pub fn format(
        _: ClientTicketState,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        _: anytype,
    ) !void {
        @compileError("resumable session state must not be formatted or logged");
    }
};

/// Server-owned recoverable state: only the common session metadata needed
/// after a stateful cache lookup or stateless-ticket decryption. Contains no
/// client-only bookkeeping and no provider/runtime handles.
pub const ServerRecoverableState = struct {
    common: ResumableSessionCommon = .{},

    /// Initializes `self` in place and takes ownership of `common` by
    /// moving it out of the caller's variable (see `ClientTicketState.init`).
    /// `self` must be zero-valued or a previously-initialized, live value
    /// — never `undefined` memory.
    pub fn init(self: *ServerRecoverableState, common: *ResumableSessionCommon) void {
        self.deinit();
        self.* = .{};
        self.common.moveFrom(common);
    }

    pub fn deinit(self: *ServerRecoverableState) void {
        self.common.deinit();
    }

    /// `out` must be zero-valued or a previously-initialized, live value —
    /// never `undefined` memory (see `init`).
    pub fn cloneInto(
        self: *const ServerRecoverableState,
        allocator: std.mem.Allocator,
        out: *ServerRecoverableState,
    ) error{OutOfMemory}!void {
        out.deinit();
        out.* = .{};
        errdefer out.deinit();
        try self.common.cloneInto(allocator, &out.common);
    }

    /// `self` must be zero-valued or a previously-initialized, live value
    /// — never `undefined` memory (see `init`); any storage `self` already
    /// owns is released first. Moving a value into itself (`self ==
    /// source`) is a safe no-op rather than an accidental self-wipe.
    pub fn moveFrom(self: *ServerRecoverableState, source: *ServerRecoverableState) void {
        if (self == source) return;
        self.deinit();
        self.* = source.*;
        source.* = .{};
    }

    pub fn moveInto(self: *ServerRecoverableState, dest: *ServerRecoverableState) void {
        dest.moveFrom(self);
    }

    pub fn format(
        _: ServerRecoverableState,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        _: anytype,
    ) !void {
        @compileError("resumable session state must not be formatted or logged");
    }
};

// -----------------------------------------------------------------------
// Compatibility decisions
// -----------------------------------------------------------------------

/// A candidate transport/application compatibility value to check against a
/// stored `CompatSnapshot`. Borrowed, not owned: no allocation is needed to
/// evaluate compatibility.
pub const CandidateCompat = struct {
    format_id: u16,
    format_version: u16,
    bytes: []const u8,
};

/// The candidate connection context a stored session is checked against.
pub const CandidateContext = struct {
    cipher_suite: algorithms.CipherSuite,
    server_name: ?[]const u8 = null,
    application_protocol: ?[]const u8 = null,
    auth_binding: AuthBinding,
    transport_compat: ?CandidateCompat = null,
    application_compat: ?CandidateCompat = null,
    want_early_data: bool = false,
};

pub const ResumeMismatch = enum {
    expired,
    not_yet_valid,
    cipher_suite_mismatch,
    sni_mismatch,
    alpn_mismatch,
    auth_binding_mismatch,
    transport_mismatch,
    application_mismatch,
};

pub const ResumeEligibility = union(enum) {
    eligible,
    rejected: ResumeMismatch,
};

pub const EarlyDataEligibility = union(enum) {
    /// Early data was not requested, or the session policy is resume-only.
    disabled,
    /// Early data was requested but the session itself is not resumable.
    incompatible,
    allowed: u32,
};

pub const CompatibilityDecision = struct {
    resumption: ResumeEligibility,
    early_data: EarlyDataEligibility,
};

pub fn evaluateCompatibility(
    common: *const ResumableSessionCommon,
    candidate: CandidateContext,
    now_unix_ms: i64,
) CompatibilityDecision {
    const resume_result = checkResumeEligibility(common, candidate, now_unix_ms);
    const early_data = checkEarlyDataEligibility(common, candidate, resume_result);
    return .{ .resumption = resume_result, .early_data = early_data };
}

fn checkResumeEligibility(
    common: *const ResumableSessionCommon,
    candidate: CandidateContext,
    now_unix_ms: i64,
) ResumeEligibility {
    if (common.isExpired(now_unix_ms)) return .{ .rejected = .expired };
    if (common.isNotYetValid(now_unix_ms)) return .{ .rejected = .not_yet_valid };
    if (common.cipher_suite != candidate.cipher_suite) return .{ .rejected = .cipher_suite_mismatch };
    if (!sniMatches(common.server_name, candidate.server_name)) return .{ .rejected = .sni_mismatch };
    if (!alpnMatches(common.application_protocol, candidate.application_protocol))
        return .{ .rejected = .alpn_mismatch };
    if (!common.auth_binding.eql(candidate.auth_binding)) return .{ .rejected = .auth_binding_mismatch };
    if (!compatSnapshotMatches(common.transport_compat, candidate.transport_compat))
        return .{ .rejected = .transport_mismatch };
    if (!compatSnapshotMatches(common.application_compat, candidate.application_compat))
        return .{ .rejected = .application_mismatch };
    return .eligible;
}

fn sniMatches(stored: ?SniName, candidate: ?[]const u8) bool {
    if (stored) |*s| {
        const c = candidate orelse return false;
        return s.eqlIgnoreCase(c);
    }
    return candidate == null;
}

fn alpnMatches(stored: ?AlpnProtocol, candidate: ?[]const u8) bool {
    if (stored) |*s| {
        const c = candidate orelse return false;
        return s.eql(c);
    }
    return candidate == null;
}

/// Symmetric optional equality: a session with no recorded snapshot only
/// matches a candidate that also supplies none, and vice versa. An absent
/// stored snapshot is never a wildcard that accepts any candidate.
fn compatSnapshotMatches(stored: ?CompatSnapshot, candidate: ?CandidateCompat) bool {
    if (stored) |*s| {
        const c = candidate orelse return false;
        return s.format_id == c.format_id and s.format_version == c.format_version and
            std.mem.eql(u8, s.slice(), c.bytes);
    }
    return candidate == null;
}

fn checkEarlyDataEligibility(
    common: *const ResumableSessionCommon,
    candidate: CandidateContext,
    resume_result: ResumeEligibility,
) EarlyDataEligibility {
    if (!candidate.want_early_data) return .disabled;
    if (resume_result != .eligible) return .incompatible;
    return switch (common.early_data) {
        .resume_only => .disabled,
        .early_data_capable => |max| .{ .allowed = max },
    };
}

// -----------------------------------------------------------------------
// Internal state codec (not the RFC 8446 NewSessionTicket wire format)
// -----------------------------------------------------------------------

pub const RecordType = enum(u8) {
    client = 1,
    server = 2,
};

pub const format_version: u8 = 1;

/// 4-byte magic identifying this internal-state format, distinct from any
/// TLS wire format: "TRS1" (Tardigrade Resumable Session, format 1).
pub const magic: [4]u8 = .{ 'T', 'R', 'S', '1' };

/// `magic(4) | major(1) | kind(1) | field_section_len(4)`.
const header_len: usize = magic.len + 1 + 1 + 4;

const optional_field_mask: u16 = 0x8000;

const field_cipher_suite: u16 = 0x0001;
const field_resumption_psk: u16 = 0x0002;
const field_server_name: u16 = 0x0003;
const field_application_protocol: u16 = 0x0004;
const field_auth_binding: u16 = 0x0005;
const field_issued_at: u16 = 0x0006;
const field_lifetime_seconds: u16 = 0x0007;
const field_early_data: u16 = 0x0008;
const field_transport_compat: u16 = 0x8001;
const field_application_compat: u16 = 0x8002;

const field_ticket: u16 = 0x0010;
const field_ticket_age_add: u16 = 0x0011;
const field_ticket_nonce: u16 = 0x0012;
const field_received_at: u16 = 0x0013;

pub const EncodeError = error{ BufferTooSmall, StateTooLarge, InvalidLimits, TooManyFields, FieldTooLarge };

pub const DecodeError = error{
    InvalidLimits,
    StateTooLarge,
    Truncated,
    UnsupportedVersion,
    UnknownRecordType,
    BadMagic,
    SectionLengthMismatch,
    TooManyFields,
    DuplicateField,
    UnknownCriticalField,
    MissingField,
    MalformedLength,
    FieldTooLarge,
    InvalidCipherSuite,
    InvalidSni,
    EmptyServerName,
    EmptyApplicationProtocol,
    InvalidPskLength,
    InvalidLifetime,
    InvalidEarlyDataPolicy,
    OutOfMemory,
};

pub const DecodedRecord = union(enum) {
    client: ClientTicketState,
    server: ServerRecoverableState,

    pub fn deinit(self: *DecodedRecord) void {
        switch (self.*) {
            .client => |*c| c.deinit(),
            .server => |*s| s.deinit(),
        }
    }
};

fn tlvLen(value_len: usize) usize {
    return 4 + value_len;
}

fn earlyDataFieldLen(policy: EarlyDataPolicy) usize {
    return switch (policy) {
        .resume_only => 1,
        .early_data_capable => 5,
    };
}

fn commonEncodedLen(common: *const ResumableSessionCommon) usize {
    var total: usize = 0;
    total += tlvLen(2);
    total += tlvLen(common.resumption_psk.slice().len);
    if (common.server_name) |*s| total += tlvLen(s.slice().len);
    if (common.application_protocol) |*a| total += tlvLen(a.slice().len);
    total += tlvLen(auth_binding_len);
    total += tlvLen(8);
    total += tlvLen(4);
    total += tlvLen(earlyDataFieldLen(common.early_data));
    if (common.transport_compat) |*snap| total += tlvLen(4 + snap.slice().len);
    if (common.application_compat) |*snap| total += tlvLen(4 + snap.slice().len);
    return total;
}

pub fn clientEncodedLen(state: *const ClientTicketState) usize {
    var total: usize = header_len;
    total += commonEncodedLen(&state.common);
    total += tlvLen(state.ticket.slice().len);
    total += tlvLen(4);
    total += tlvLen(state.ticket_nonce.slice().len);
    total += tlvLen(8);
    return total;
}

pub fn serverEncodedLen(state: *const ServerRecoverableState) usize {
    return header_len + commonEncodedLen(&state.common);
}

fn commonFieldCount(common: *const ResumableSessionCommon) usize {
    // cipher_suite, resumption_psk, auth_binding, issued_at, lifetime_seconds, early_data
    var count: usize = 6;
    if (common.server_name != null) count += 1;
    if (common.application_protocol != null) count += 1;
    if (common.transport_compat != null) count += 1;
    if (common.application_compat != null) count += 1;
    return count;
}

/// Validates transport/application compatibility blob sizes against
/// `limits`. Ticket size and total field count are checked by the callers
/// below (they differ between client and server records).
fn checkCommonAgainstLimits(common: *const ResumableSessionCommon, limits: Limits) EncodeError!void {
    if (common.transport_compat) |*snap| {
        if (snap.slice().len > limits.max_transport_compat_len) return error.FieldTooLarge;
    }
    if (common.application_compat) |*snap| {
        if (snap.slice().len > limits.max_application_compat_len) return error.FieldTooLarge;
    }
}

/// Computes the exact encoded length for `state`, but first validates every
/// field against `limits` (ticket length, compatibility blob lengths, and
/// total field count) rather than only checking the final byte total. This
/// is what prevents encoding a state built under wider limits into a record
/// a matching decoder using tighter limits would reject.
pub fn clientEncodedLenWithLimits(state: *const ClientTicketState, limits: Limits) EncodeError!usize {
    try checkCommonAgainstLimits(&state.common, limits);
    if (state.ticket.slice().len > limits.max_ticket_len) return error.FieldTooLarge;
    const field_count = commonFieldCount(&state.common) + 4; // ticket, ticket_age_add, ticket_nonce, received_at
    if (field_count > limits.max_fields) return error.TooManyFields;
    return clientEncodedLen(state);
}

pub fn serverEncodedLenWithLimits(state: *const ServerRecoverableState, limits: Limits) EncodeError!usize {
    try checkCommonAgainstLimits(&state.common, limits);
    const field_count = commonFieldCount(&state.common);
    if (field_count > limits.max_fields) return error.TooManyFields;
    return serverEncodedLen(state);
}

fn writeTlv(out: []u8, pos: *usize, field_id: u16, value: []const u8) void {
    std.debug.assert(out.len - pos.* >= tlvLen(value.len));
    std.mem.writeInt(u16, out[pos.*..][0..2], field_id, .big);
    std.mem.writeInt(u16, out[pos.* + 2 ..][0..2], @intCast(value.len), .big);
    @memcpy(out[pos.* + 4 ..][0..value.len], value);
    pos.* += tlvLen(value.len);
}

fn writeCompatSnapshot(out: []u8, pos: *usize, field_id: u16, snap: *const CompatSnapshot, scratch: []u8) void {
    std.mem.writeInt(u16, scratch[0..2], snap.format_id, .big);
    std.mem.writeInt(u16, scratch[2..4], snap.format_version, .big);
    const blob = snap.slice();
    @memcpy(scratch[4..][0..blob.len], blob);
    writeTlv(out, pos, field_id, scratch[0 .. 4 + blob.len]);
}

fn writeCommon(out: []u8, pos: *usize, common: *const ResumableSessionCommon, compat_scratch: []u8) void {
    var cs_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &cs_bytes, @intFromEnum(common.cipher_suite), .big);
    writeTlv(out, pos, field_cipher_suite, &cs_bytes);

    writeTlv(out, pos, field_resumption_psk, common.resumption_psk.slice());
    if (common.server_name) |*s| writeTlv(out, pos, field_server_name, s.slice());
    if (common.application_protocol) |*a| writeTlv(out, pos, field_application_protocol, a.slice());
    writeTlv(out, pos, field_auth_binding, &common.auth_binding.bytes);

    var issued_bytes: [8]u8 = undefined;
    std.mem.writeInt(i64, &issued_bytes, common.issued_at_unix_ms, .big);
    writeTlv(out, pos, field_issued_at, &issued_bytes);

    var lifetime_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &lifetime_bytes, common.lifetime_seconds, .big);
    writeTlv(out, pos, field_lifetime_seconds, &lifetime_bytes);

    var early_bytes: [5]u8 = undefined;
    const early_slice: []const u8 = switch (common.early_data) {
        .resume_only => blk: {
            early_bytes[0] = 0;
            break :blk early_bytes[0..1];
        },
        .early_data_capable => |max| blk: {
            early_bytes[0] = 1;
            std.mem.writeInt(u32, early_bytes[1..5], max, .big);
            break :blk early_bytes[0..5];
        },
    };
    writeTlv(out, pos, field_early_data, early_slice);

    if (common.transport_compat) |*snap| writeCompatSnapshot(out, pos, field_transport_compat, snap, compat_scratch);
    if (common.application_compat) |*snap|
        writeCompatSnapshot(out, pos, field_application_compat, snap, compat_scratch);
}

fn writeHeader(out: []u8, kind: RecordType, field_section_len: u32) void {
    @memcpy(out[0..4], &magic);
    out[4] = format_version;
    out[5] = @intFromEnum(kind);
    std.mem.writeInt(u32, out[6..10], field_section_len, .big);
}

/// Encodes `state` into `out`. The complete required length is computed and
/// validated against `limits.max_serialized_len` and `out.len` before any
/// byte is written, so an undersized buffer or over-limit state fails
/// without ever leaving partial plaintext secret state in `out`.
pub fn encodeClient(state: *const ClientTicketState, limits: Limits, out: []u8) EncodeError![]const u8 {
    try limits.validate();
    const needed = try clientEncodedLenWithLimits(state, limits);
    if (needed > limits.max_serialized_len) return error.StateTooLarge;
    if (out.len < needed) return error.BufferTooSmall;

    const field_section_len = needed - header_len;
    writeHeader(out, .client, @intCast(field_section_len));
    var pos: usize = header_len;

    var compat_scratch: [4 + hard_max_compat_len]u8 = undefined;
    writeCommon(out, &pos, &state.common, &compat_scratch);
    writeTlv(out, &pos, field_ticket, state.ticket.slice());

    var age_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &age_bytes, state.ticket_age_add, .big);
    writeTlv(out, &pos, field_ticket_age_add, &age_bytes);

    writeTlv(out, &pos, field_ticket_nonce, state.ticket_nonce.slice());

    var received_bytes: [8]u8 = undefined;
    std.mem.writeInt(i64, &received_bytes, state.received_at_unix_ms, .big);
    writeTlv(out, &pos, field_received_at, &received_bytes);

    std.debug.assert(pos == needed);
    return out[0..pos];
}

pub fn encodeServer(state: *const ServerRecoverableState, limits: Limits, out: []u8) EncodeError![]const u8 {
    try limits.validate();
    const needed = try serverEncodedLenWithLimits(state, limits);
    if (needed > limits.max_serialized_len) return error.StateTooLarge;
    if (out.len < needed) return error.BufferTooSmall;

    const field_section_len = needed - header_len;
    writeHeader(out, .server, @intCast(field_section_len));
    var pos: usize = header_len;

    var compat_scratch: [4 + hard_max_compat_len]u8 = undefined;
    writeCommon(out, &pos, &state.common, &compat_scratch);

    std.debug.assert(pos == needed);
    return out[0..pos];
}

const Tlv = struct { field_id: u16, value: []const u8 };

fn nextTlv(bytes: []const u8, offset: *usize) DecodeError!?Tlv {
    if (offset.* >= bytes.len) return null;
    if (bytes.len - offset.* < 4) return error.Truncated;
    const field_id = std.mem.readInt(u16, bytes[offset.*..][0..2], .big);
    const length: usize = std.mem.readInt(u16, bytes[offset.* + 2 ..][0..2], .big);
    offset.* += 4;
    if (bytes.len - offset.* < length) return error.Truncated;
    const value = bytes[offset.*..][0..length];
    offset.* += length;
    return Tlv{ .field_id = field_id, .value = value };
}

const CommonFields = struct {
    cipher_suite: ?algorithms.CipherSuite = null,
    psk: ?[]const u8 = null,
    server_name: ?[]const u8 = null,
    application_protocol: ?[]const u8 = null,
    auth_binding: ?[auth_binding_len]u8 = null,
    issued_at_unix_ms: ?i64 = null,
    lifetime_seconds: ?u32 = null,
    early_data: ?EarlyDataPolicy = null,
    transport_compat: ?RawCompat = null,
    application_compat: ?RawCompat = null,
};

const RawCompat = struct {
    format_id: u16,
    format_version: u16,
    bytes: []const u8,
};

fn decodeEarlyData(value: []const u8) DecodeError!EarlyDataPolicy {
    if (value.len == 1) {
        if (value[0] != 0) return error.InvalidEarlyDataPolicy;
        return .resume_only;
    }
    if (value.len == 5) {
        if (value[0] != 1) return error.InvalidEarlyDataPolicy;
        const max = std.mem.readInt(u32, value[1..5], .big);
        if (max == 0) return error.InvalidEarlyDataPolicy;
        return .{ .early_data_capable = max };
    }
    return error.MalformedLength;
}

fn decodeRawCompat(value: []const u8, limit: usize) DecodeError!RawCompat {
    if (value.len < 4) return error.MalformedLength;
    const cs_format_id = std.mem.readInt(u16, value[0..2], .big);
    const cs_format_version = std.mem.readInt(u16, value[2..4], .big);
    const blob = value[4..];
    if (blob.len > limit) return error.FieldTooLarge;
    return .{ .format_id = cs_format_id, .format_version = cs_format_version, .bytes = blob };
}

/// Tracks every field id seen so far (known or unknown) for global
/// duplicate rejection and enforces `limits.max_fields`.
const FieldTracker = struct {
    seen: [hard_max_fields]u16 = undefined,
    count: usize = 0,
    max_fields: usize,

    fn observe(self: *FieldTracker, field_id: u16) DecodeError!void {
        for (self.seen[0..self.count]) |seen_id| {
            if (seen_id == field_id) return error.DuplicateField;
        }
        if (self.count >= self.max_fields) return error.TooManyFields;
        self.seen[self.count] = field_id;
        self.count += 1;
    }
};

fn parseSharedField(builder: *CommonFields, limits: Limits, field_id: u16, value: []const u8) DecodeError!bool {
    switch (field_id) {
        field_cipher_suite => {
            if (value.len != 2) return error.MalformedLength;
            const raw = std.mem.readInt(u16, value[0..2], .big);
            builder.cipher_suite = algorithms.fromInt(algorithms.CipherSuite, raw) orelse return error.InvalidCipherSuite;
            return true;
        },
        field_resumption_psk => {
            if (value.len == 0 or value.len > max_psk_len) return error.FieldTooLarge;
            builder.psk = value;
            return true;
        },
        field_server_name => {
            if (value.len == 0) return error.EmptyServerName;
            if (value.len > max_sni_len) return error.FieldTooLarge;
            builder.server_name = value;
            return true;
        },
        field_application_protocol => {
            if (value.len == 0) return error.EmptyApplicationProtocol;
            if (value.len > max_alpn_len) return error.FieldTooLarge;
            builder.application_protocol = value;
            return true;
        },
        field_auth_binding => {
            if (value.len != auth_binding_len) return error.MalformedLength;
            var binding: [auth_binding_len]u8 = undefined;
            @memcpy(&binding, value);
            builder.auth_binding = binding;
            return true;
        },
        field_issued_at => {
            if (value.len != 8) return error.MalformedLength;
            builder.issued_at_unix_ms = std.mem.readInt(i64, value[0..8], .big);
            return true;
        },
        field_lifetime_seconds => {
            if (value.len != 4) return error.MalformedLength;
            const lifetime = std.mem.readInt(u32, value[0..4], .big);
            if (lifetime == 0 or lifetime > max_lifetime_seconds) return error.InvalidLifetime;
            builder.lifetime_seconds = lifetime;
            return true;
        },
        field_early_data => {
            builder.early_data = try decodeEarlyData(value);
            return true;
        },
        field_transport_compat => {
            builder.transport_compat = try decodeRawCompat(value, limits.max_transport_compat_len);
            return true;
        },
        field_application_compat => {
            builder.application_compat = try decodeRawCompat(value, limits.max_application_compat_len);
            return true;
        },
        else => return false,
    }
}

fn buildCommon(
    allocator: std.mem.Allocator,
    limits: Limits,
    fields: CommonFields,
    out: *ResumableSessionCommon,
) DecodeError!void {
    const cipher_suite = fields.cipher_suite orelse return error.MissingField;
    const psk = fields.psk orelse return error.MissingField;
    const auth_binding_bytes = fields.auth_binding orelse return error.MissingField;
    const issued_at_unix_ms = fields.issued_at_unix_ms orelse return error.MissingField;
    const lifetime_seconds = fields.lifetime_seconds orelse return error.MissingField;
    const early_data = fields.early_data orelse return error.MissingField;

    var transport_compat: ?ResumableSessionCommon.CompatBlobParams = null;
    if (fields.transport_compat) |raw|
        transport_compat = .{ .format_id = raw.format_id, .format_version = raw.format_version, .bytes = raw.bytes };
    var application_compat: ?ResumableSessionCommon.CompatBlobParams = null;
    if (fields.application_compat) |raw|
        application_compat = .{ .format_id = raw.format_id, .format_version = raw.format_version, .bytes = raw.bytes };

    out.init(allocator, limits, .{
        .cipher_suite = cipher_suite,
        .resumption_psk = psk,
        .server_name = fields.server_name,
        .application_protocol = fields.application_protocol,
        .auth_binding = .{ .bytes = auth_binding_bytes },
        .issued_at_unix_ms = issued_at_unix_ms,
        .lifetime_seconds = lifetime_seconds,
        .early_data = early_data,
        .transport_compat = transport_compat,
        .application_compat = application_compat,
    }) catch |err| switch (err) {
        error.InvalidDnsName => return error.InvalidSni,
        error.EmptyServerName => return error.EmptyServerName,
        error.AlpnProtocolTooLarge => return error.FieldTooLarge,
        error.EmptyApplicationProtocol => return error.EmptyApplicationProtocol,
        error.InvalidPskLength => return error.InvalidPskLength,
        error.InvalidLifetime => return error.InvalidLifetime,
        error.InvalidEarlyDataPolicy => return error.InvalidEarlyDataPolicy,
        error.CompatSnapshotTooLarge => return error.FieldTooLarge,
        error.InvalidLimits => return error.InvalidLimits,
        error.OutOfMemory => return error.OutOfMemory,
    };
}

fn decodeClient(allocator: std.mem.Allocator, limits: Limits, bytes: []const u8) DecodeError!ClientTicketState {
    var common_fields = CommonFields{};
    var ticket: ?[]const u8 = null;
    var ticket_age_add: ?u32 = null;
    var ticket_nonce: ?[]const u8 = null;
    var received_at_unix_ms: ?i64 = null;

    var tracker = FieldTracker{ .max_fields = limits.max_fields };
    var offset: usize = 0;
    while (try nextTlv(bytes, &offset)) |tlv| {
        try tracker.observe(tlv.field_id);

        if (try parseSharedField(&common_fields, limits, tlv.field_id, tlv.value)) continue;
        switch (tlv.field_id) {
            field_ticket => {
                if (tlv.value.len == 0 or tlv.value.len > limits.max_ticket_len) return error.FieldTooLarge;
                ticket = tlv.value;
            },
            field_ticket_age_add => {
                if (tlv.value.len != 4) return error.MalformedLength;
                ticket_age_add = std.mem.readInt(u32, tlv.value[0..4], .big);
            },
            field_ticket_nonce => {
                if (tlv.value.len > max_ticket_nonce_len) return error.FieldTooLarge;
                ticket_nonce = tlv.value;
            },
            field_received_at => {
                if (tlv.value.len != 8) return error.MalformedLength;
                received_at_unix_ms = std.mem.readInt(i64, tlv.value[0..8], .big);
            },
            else => {
                if (tlv.field_id & optional_field_mask != 0) continue;
                return error.UnknownCriticalField;
            },
        }
    }

    var common: ResumableSessionCommon = .{};
    try buildCommon(allocator, limits, common_fields, &common);
    errdefer common.deinit();

    var state: ClientTicketState = .{};
    state.init(allocator, limits, &common, .{
        .ticket = ticket orelse return error.MissingField,
        .ticket_age_add = ticket_age_add orelse return error.MissingField,
        .ticket_nonce = ticket_nonce orelse return error.MissingField,
        .received_at_unix_ms = received_at_unix_ms orelse return error.MissingField,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidLimits => return error.InvalidLimits,
        error.TicketTooLarge, error.NonceTooLarge => return error.FieldTooLarge,
    };
    return state;
}

fn decodeServer(allocator: std.mem.Allocator, limits: Limits, bytes: []const u8) DecodeError!ServerRecoverableState {
    var common_fields = CommonFields{};

    var tracker = FieldTracker{ .max_fields = limits.max_fields };
    var offset: usize = 0;
    while (try nextTlv(bytes, &offset)) |tlv| {
        try tracker.observe(tlv.field_id);
        if (try parseSharedField(&common_fields, limits, tlv.field_id, tlv.value)) continue;
        if (tlv.field_id & optional_field_mask != 0) continue;
        return error.UnknownCriticalField;
    }

    var common: ResumableSessionCommon = .{};
    try buildCommon(allocator, limits, common_fields, &common);

    var state: ServerRecoverableState = .{};
    state.init(&common);
    return state;
}

/// Decode a versioned internal-state record. `bytes` must be exactly one
/// encoded record with no leading/trailing framing; returns a completely
/// owned value on success, or an error after fully clearing any partial
/// secret state.
pub fn decode(allocator: std.mem.Allocator, limits: Limits, bytes: []const u8) DecodeError!DecodedRecord {
    try limits.validate();
    if (bytes.len > limits.max_serialized_len) return error.StateTooLarge;
    if (bytes.len < header_len) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..4], &magic)) return error.BadMagic;
    if (bytes[4] != format_version) return error.UnsupportedVersion;
    const record_type = std.enums.fromInt(RecordType, bytes[5]) orelse return error.UnknownRecordType;
    const field_section_len: usize = std.mem.readInt(u32, bytes[6..10], .big);
    if (field_section_len != bytes.len - header_len) return error.SectionLengthMismatch;

    const section = bytes[header_len..];
    return switch (record_type) {
        .client => .{ .client = try decodeClient(allocator, limits, section) },
        .server => .{ .server = try decodeServer(allocator, limits, section) },
    };
}

/// Convenience wrapper decoding with `Limits.default`.
pub fn decodeDefault(allocator: std.mem.Allocator, bytes: []const u8) DecodeError!DecodedRecord {
    return decode(allocator, Limits.default, bytes);
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

const testing = std.testing;

fn sampleCommon(allocator: std.mem.Allocator, resumption_psk: []const u8) !ResumableSessionCommon {
    var common: ResumableSessionCommon = .{};
    try common.init(allocator, Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = resumption_psk,
        .server_name = "Example.TEST",
        .application_protocol = "h3",
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf-der-bytes"),
        .issued_at_unix_ms = 1_000_000,
        .lifetime_seconds = 3_600,
        .early_data = .resume_only,
    });
    return common;
}

fn sampleClient(allocator: std.mem.Allocator) !ClientTicketState {
    var common = try sampleCommon(allocator, &([_]u8{0xab} ** 32));
    var state: ClientTicketState = .{};
    try state.init(allocator, Limits.default, &common, .{
        .ticket = "opaque-ticket-bytes",
        .ticket_age_add = 12345,
        .ticket_nonce = "nonce",
        .received_at_unix_ms = 1_500_000,
    });
    return state;
}

test "SHA-256 and SHA-384 suites require matching PSK length" {
    var sha256_psk = [_]u8{0x11} ** 32;
    var common256: ResumableSessionCommon = .{};
    try common256.init(testing.allocator, Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &sha256_psk,
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf"),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 100,
    });
    defer common256.deinit();
    try testing.expectEqual(@as(usize, 32), common256.resumption_psk.slice().len);

    var sha384_psk = [_]u8{0x22} ** 48;
    var common384: ResumableSessionCommon = .{};
    try common384.init(testing.allocator, Limits.default, .{
        .cipher_suite = .tls_aes_256_gcm_sha384,
        .resumption_psk = &sha384_psk,
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf"),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 100,
    });
    defer common384.deinit();
    try testing.expectEqual(@as(usize, 48), common384.resumption_psk.slice().len);

    var mismatched: ResumableSessionCommon = .{};
    try testing.expectError(error.InvalidPskLength, mismatched.init(testing.allocator, Limits.default, .{
        .cipher_suite = .tls_aes_256_gcm_sha384,
        .resumption_psk = &sha256_psk,
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf"),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 100,
    }));
}

test "SNI is optional, canonicalized to ASCII-lowercase, and compares case-insensitively" {
    var common = try sampleCommon(testing.allocator, &([_]u8{0xab} ** 32));
    defer common.deinit();

    try testing.expectEqualStrings("example.test", common.server_name.?.slice());
    try testing.expect(common.server_name.?.eqlIgnoreCase("EXAMPLE.test"));
    try testing.expect(!common.server_name.?.eqlIgnoreCase("other.test"));

    var no_sni: ResumableSessionCommon = .{};
    try no_sni.init(testing.allocator, Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &([_]u8{0xcd} ** 32),
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf"),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 100,
    });
    defer no_sni.deinit();
    try testing.expect(no_sni.server_name == null);
    try testing.expect(no_sni.application_protocol == null);
}

test "a present but empty SNI or ALPN is rejected" {
    var common: ResumableSessionCommon = .{};
    try testing.expectError(error.EmptyServerName, common.init(testing.allocator, Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &([_]u8{0xcd} ** 32),
        .server_name = "",
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf"),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 100,
    }));
    try testing.expectError(error.EmptyApplicationProtocol, common.init(testing.allocator, Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &([_]u8{0xcd} ** 32),
        .application_protocol = "",
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf"),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 100,
    }));
}

test "lifetime_seconds must be within (0, 604800]" {
    var common: ResumableSessionCommon = .{};
    try testing.expectError(error.InvalidLifetime, common.init(testing.allocator, Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &([_]u8{0xcd} ** 32),
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf"),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 0,
    }));
    try testing.expectError(error.InvalidLifetime, common.init(testing.allocator, Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &([_]u8{0xcd} ** 32),
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf"),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = max_lifetime_seconds + 1,
    }));

    var ok: ResumableSessionCommon = .{};
    try ok.init(testing.allocator, Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &([_]u8{0xcd} ** 32),
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf"),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = max_lifetime_seconds,
    });
    ok.deinit();
}

test "expiry boundaries are exact millisecond-precise and overflow-safe" {
    var common = try sampleCommon(testing.allocator, &([_]u8{0xab} ** 32));
    defer common.deinit();
    common.issued_at_unix_ms = 1_000_000;
    common.lifetime_seconds = 100; // 100_000 ms

    try testing.expect(!common.isExpired(1_099_999));
    try testing.expect(common.isExpired(1_100_000));
    try testing.expect(!common.isNotYetValid(1_000_000));
    try testing.expect(common.isNotYetValid(999_999));

    // issued_at + lifetime overflows i64; the i128 comparison must neither
    // panic nor wrap.
    common.issued_at_unix_ms = std.math.maxInt(i64) - 10;
    common.lifetime_seconds = 1; // 1000 ms
    try testing.expect(!common.isExpired(std.math.maxInt(i64)));

    // Extreme past issue time / far-future `now` must not panic.
    common.issued_at_unix_ms = std.math.minInt(i64);
    common.lifetime_seconds = max_lifetime_seconds;
    try testing.expect(common.isExpired(std.math.maxInt(i64)));
    try testing.expect(!common.isExpired(std.math.minInt(i64)));
}

test "ClientTicketState.ageMillis is overflow-safe at the i64 extremes" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    client.received_at_unix_ms = std.math.minInt(i64);
    // now - received_at overflows i64; must not trap or wrap, and must
    // saturate to the largest representable u64 age rather than panic.
    try testing.expectEqual(
        @as(u64, std.math.maxInt(u64)),
        client.ageMillis(std.math.maxInt(i64)),
    );

    client.received_at_unix_ms = std.math.maxInt(i64);
    // now - received_at underflows i64; a future receipt time (clock skew)
    // must saturate to zero, not go negative or trap.
    try testing.expectEqual(@as(u64, 0), client.ageMillis(std.math.minInt(i64)));
    try testing.expectEqual(@as(u64, 0), client.ageMillis(std.math.maxInt(i64) - 1));

    client.received_at_unix_ms = 1_000;
    try testing.expectEqual(@as(u64, 0), client.ageMillis(1_000));
    try testing.expectEqual(@as(u64, 500), client.ageMillis(1_500));
    try testing.expectEqual(@as(u64, 0), client.ageMillis(999)); // future receipt vs. now
}

test "compatibility distinguishes each mismatch reason" {
    var common = try sampleCommon(testing.allocator, &([_]u8{0xab} ** 32));
    defer common.deinit();
    var transport_snap: CompatSnapshot = .{};
    try transport_snap.init(testing.allocator, 1, 1, "quic-params", Limits.default.max_transport_compat_len);
    common.transport_compat = transport_snap;
    var application_snap: CompatSnapshot = .{};
    try application_snap.init(testing.allocator, 2, 1, "h3-settings", Limits.default.max_application_compat_len);
    common.application_compat = application_snap;

    const base = CandidateContext{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .server_name = "example.test",
        .application_protocol = "h3",
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf-der-bytes"),
        .transport_compat = .{ .format_id = 1, .format_version = 1, .bytes = "quic-params" },
        .application_compat = .{ .format_id = 2, .format_version = 1, .bytes = "h3-settings" },
    };

    try testing.expectEqual(ResumeEligibility.eligible, evaluateCompatibility(&common, base, 1_000_000).resumption);

    try testing.expectEqual(ResumeMismatch.expired, evaluateCompatibility(&common, base, 10_000_000).resumption.rejected);
    try testing.expectEqual(ResumeMismatch.not_yet_valid, evaluateCompatibility(&common, base, 0).resumption.rejected);

    var cipher_mismatch = base;
    cipher_mismatch.cipher_suite = .tls_aes_256_gcm_sha384;
    try testing.expectEqual(ResumeMismatch.cipher_suite_mismatch, evaluateCompatibility(&common, cipher_mismatch, 1_000_000).resumption.rejected);

    var sni_mismatch = base;
    sni_mismatch.server_name = "other.test";
    try testing.expectEqual(ResumeMismatch.sni_mismatch, evaluateCompatibility(&common, sni_mismatch, 1_000_000).resumption.rejected);

    var sni_absent = base;
    sni_absent.server_name = null;
    try testing.expectEqual(ResumeMismatch.sni_mismatch, evaluateCompatibility(&common, sni_absent, 1_000_000).resumption.rejected);

    var alpn_mismatch = base;
    alpn_mismatch.application_protocol = "h2";
    try testing.expectEqual(ResumeMismatch.alpn_mismatch, evaluateCompatibility(&common, alpn_mismatch, 1_000_000).resumption.rejected);

    var auth_mismatch = base;
    auth_mismatch.auth_binding = AuthBinding.fromLeafCertificateDer("different-leaf");
    try testing.expectEqual(ResumeMismatch.auth_binding_mismatch, evaluateCompatibility(&common, auth_mismatch, 1_000_000).resumption.rejected);

    var transport_mismatch = base;
    transport_mismatch.transport_compat = .{ .format_id = 1, .format_version = 2, .bytes = "quic-params" };
    try testing.expectEqual(ResumeMismatch.transport_mismatch, evaluateCompatibility(&common, transport_mismatch, 1_000_000).resumption.rejected);

    var application_mismatch = base;
    application_mismatch.application_compat = null;
    try testing.expectEqual(ResumeMismatch.application_mismatch, evaluateCompatibility(&common, application_mismatch, 1_000_000).resumption.rejected);
}

test "compatibility snapshots require symmetric presence, absent is not a wildcard" {
    var common = try sampleCommon(testing.allocator, &([_]u8{0xab} ** 32));
    defer common.deinit();
    // common.transport_compat / application_compat are null (absent).

    const candidate_with_transport = CandidateContext{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .server_name = "example.test",
        .application_protocol = "h3",
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf-der-bytes"),
        .transport_compat = .{ .format_id = 1, .format_version = 1, .bytes = "quic-params" },
    };
    try testing.expectEqual(
        ResumeMismatch.transport_mismatch,
        evaluateCompatibility(&common, candidate_with_transport, 1_000_000).resumption.rejected,
    );

    var stored_transport: CompatSnapshot = .{};
    try stored_transport.init(testing.allocator, 1, 1, "quic-params", Limits.default.max_transport_compat_len);
    common.transport_compat = stored_transport;

    const candidate_without_transport = CandidateContext{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .server_name = "example.test",
        .application_protocol = "h3",
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf-der-bytes"),
    };
    try testing.expectEqual(
        ResumeMismatch.transport_mismatch,
        evaluateCompatibility(&common, candidate_without_transport, 1_000_000).resumption.rejected,
    );
}

test "resumption may succeed while early data remains disabled" {
    var common = try sampleCommon(testing.allocator, &([_]u8{0xab} ** 32));
    defer common.deinit();
    // common.early_data defaults to .resume_only

    const candidate = CandidateContext{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .server_name = "example.test",
        .application_protocol = "h3",
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf-der-bytes"),
        .want_early_data = true,
    };

    const decision = evaluateCompatibility(&common, candidate, 1_000_000);
    try testing.expectEqual(ResumeEligibility.eligible, decision.resumption);
    try testing.expectEqual(EarlyDataEligibility.disabled, decision.early_data);
}

test "early data is allowed only when the session is resumable and policy permits it" {
    var common = try sampleCommon(testing.allocator, &([_]u8{0xab} ** 32));
    defer common.deinit();
    common.early_data = .{ .early_data_capable = 16384 };

    const good_candidate = CandidateContext{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .server_name = "example.test",
        .application_protocol = "h3",
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf-der-bytes"),
        .want_early_data = true,
    };
    const good_decision = evaluateCompatibility(&common, good_candidate, 1_000_000);
    try testing.expectEqual(ResumeEligibility.eligible, good_decision.resumption);
    try testing.expectEqual(@as(u32, 16384), good_decision.early_data.allowed);

    var bad_candidate = good_candidate;
    bad_candidate.server_name = "other.test";
    const bad_decision = evaluateCompatibility(&common, bad_candidate, 1_000_000);
    try testing.expectEqual(ResumeMismatch.sni_mismatch, bad_decision.resumption.rejected);
    try testing.expectEqual(EarlyDataEligibility.incompatible, bad_decision.early_data);
}

test "invalid early data policy is rejected" {
    var common: ResumableSessionCommon = .{};
    try testing.expectError(error.InvalidEarlyDataPolicy, common.init(testing.allocator, Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &([_]u8{0} ** 32),
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf"),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 100,
        .early_data = .{ .early_data_capable = 0 },
    }));
}

test "client and server internal state round-trips deterministically" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    var buf: [Limits.default.max_serialized_len]u8 = undefined;
    const encoded_len = clientEncodedLen(&client);
    const encoded = try encodeClient(&client, Limits.default, &buf);
    try testing.expectEqual(encoded_len, encoded.len);

    var decoded = try decodeDefault(testing.allocator, encoded);
    defer decoded.deinit();
    try testing.expect(decoded == .client);
    try testing.expectEqual(client.common.cipher_suite, decoded.client.common.cipher_suite);
    try testing.expectEqualStrings(client.common.server_name.?.slice(), decoded.client.common.server_name.?.slice());
    try testing.expectEqualStrings(
        client.common.application_protocol.?.slice(),
        decoded.client.common.application_protocol.?.slice(),
    );
    try testing.expect(client.common.resumption_psk.eql(&decoded.client.common.resumption_psk));
    try testing.expectEqualStrings(client.ticket.slice(), decoded.client.ticket.slice());
    try testing.expectEqual(client.ticket_age_add, decoded.client.ticket_age_add);
    try testing.expectEqualStrings(client.ticket_nonce.slice(), decoded.client.ticket_nonce.slice());
    try testing.expectEqual(client.received_at_unix_ms, decoded.client.received_at_unix_ms);

    // Re-encoding the decoded value must reproduce the exact same bytes
    // (canonical field order is deterministic regardless of decode path).
    var buf2: [Limits.default.max_serialized_len]u8 = undefined;
    const re_encoded = try encodeClient(&decoded.client, Limits.default, &buf2);
    try testing.expectEqualSlices(u8, encoded, re_encoded);

    var server_common = try sampleCommon(testing.allocator, &([_]u8{0xcd} ** 32));
    var server: ServerRecoverableState = .{};
    server.init(&server_common);
    defer server.deinit();

    var server_buf: [Limits.default.max_serialized_len]u8 = undefined;
    const server_encoded = try encodeServer(&server, Limits.default, &server_buf);
    try testing.expectEqual(serverEncodedLen(&server), server_encoded.len);

    var decoded_server = try decodeDefault(testing.allocator, server_encoded);
    defer decoded_server.deinit();
    try testing.expect(decoded_server == .server);
    try testing.expectEqualStrings(
        server.common.server_name.?.slice(),
        decoded_server.server.common.server_name.?.slice(),
    );
}

test "absent SNI/ALPN round-trip without emitting a TLV" {
    var common: ResumableSessionCommon = .{};
    try common.init(testing.allocator, Limits.default, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &([_]u8{0xab} ** 32),
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf"),
        .issued_at_unix_ms = 1_000,
        .lifetime_seconds = 100,
    });
    var server: ServerRecoverableState = .{};
    server.init(&common);
    defer server.deinit();

    var buf: [Limits.default.max_serialized_len]u8 = undefined;
    const encoded = try encodeServer(&server, Limits.default, &buf);

    // No server_name/application_protocol TLV was ever written.
    var offset: usize = header_len;
    while (try nextTlv(encoded, &offset)) |tlv| {
        try testing.expect(tlv.field_id != field_server_name);
        try testing.expect(tlv.field_id != field_application_protocol);
    }

    var decoded = try decodeDefault(testing.allocator, encoded);
    defer decoded.deinit();
    try testing.expect(decoded.server.common.server_name == null);
    try testing.expect(decoded.server.common.application_protocol == null);
}

test "decode is order-independent across shuffled fields" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    var buf: [Limits.default.max_serialized_len]u8 = undefined;
    const encoded = try encodeClient(&client, Limits.default, &buf);

    var tlvs = std.ArrayList(Tlv).empty;
    defer tlvs.deinit(testing.allocator);
    var offset: usize = header_len;
    while (try nextTlv(encoded, &offset)) |tlv| {
        try tlvs.append(testing.allocator, tlv);
    }
    std.mem.reverse(Tlv, tlvs.items);

    var shuffled: [Limits.default.max_serialized_len]u8 = undefined;
    const field_section_len: usize = encoded.len - header_len;
    writeHeader(&shuffled, .client, @intCast(field_section_len));
    var pos: usize = header_len;
    for (tlvs.items) |tlv| {
        writeTlv(&shuffled, &pos, tlv.field_id, tlv.value);
    }

    var decoded = try decodeDefault(testing.allocator, shuffled[0..pos]);
    defer decoded.deinit();
    try testing.expect(decoded == .client);
    try testing.expectEqualStrings(client.ticket.slice(), decoded.client.ticket.slice());
}

test "unknown optional fields are skipped, unknown critical fields are rejected" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    var buf: [Limits.default.max_serialized_len]u8 = undefined;
    const encoded = try encodeClient(&client, Limits.default, &buf);

    var with_optional: [Limits.default.max_serialized_len]u8 = undefined;
    @memcpy(with_optional[0..encoded.len], encoded);
    var pos: usize = encoded.len;
    writeTlv(&with_optional, &pos, 0x9abc, "future-extension-data");
    patchSectionLen(&with_optional, pos);

    var decoded = try decodeDefault(testing.allocator, with_optional[0..pos]);
    defer decoded.deinit();
    try testing.expect(decoded == .client);

    var with_critical: [Limits.default.max_serialized_len]u8 = undefined;
    @memcpy(with_critical[0..encoded.len], encoded);
    var pos2: usize = encoded.len;
    writeTlv(&with_critical, &pos2, 0x00ff, "unrecognized-critical-data");
    patchSectionLen(&with_critical, pos2);

    try testing.expectError(error.UnknownCriticalField, decodeDefault(testing.allocator, with_critical[0..pos2]));
}

fn patchSectionLen(buf: []u8, total_len: usize) void {
    std.mem.writeInt(u32, buf[6..10], @intCast(total_len - header_len), .big);
}

test "decode rejects unsupported major versions, bad magic, and unknown record types" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    var buf: [Limits.default.max_serialized_len]u8 = undefined;
    const encoded = try encodeClient(&client, Limits.default, &buf);

    var bad_version: [Limits.default.max_serialized_len]u8 = undefined;
    @memcpy(bad_version[0..encoded.len], encoded);
    bad_version[4] = 2;
    try testing.expectError(error.UnsupportedVersion, decodeDefault(testing.allocator, bad_version[0..encoded.len]));

    var bad_magic: [Limits.default.max_serialized_len]u8 = undefined;
    @memcpy(bad_magic[0..encoded.len], encoded);
    bad_magic[0] = 'X';
    try testing.expectError(error.BadMagic, decodeDefault(testing.allocator, bad_magic[0..encoded.len]));

    var bad_kind: [Limits.default.max_serialized_len]u8 = undefined;
    @memcpy(bad_kind[0..encoded.len], encoded);
    bad_kind[5] = 99;
    try testing.expectError(error.UnknownRecordType, decodeDefault(testing.allocator, bad_kind[0..encoded.len]));
}

test "decode rejects a field section length that under- or overruns the buffer" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    var buf: [Limits.default.max_serialized_len]u8 = undefined;
    const encoded = try encodeClient(&client, Limits.default, &buf);

    var under: [Limits.default.max_serialized_len]u8 = undefined;
    @memcpy(under[0..encoded.len], encoded);
    std.mem.writeInt(u32, under[6..10], @intCast(encoded.len - header_len - 1), .big);
    try testing.expectError(error.SectionLengthMismatch, decodeDefault(testing.allocator, under[0..encoded.len]));

    var over: [Limits.default.max_serialized_len]u8 = undefined;
    @memcpy(over[0..encoded.len], encoded);
    std.mem.writeInt(u32, over[6..10], @intCast(encoded.len - header_len + 1), .big);
    try testing.expectError(error.SectionLengthMismatch, decodeDefault(testing.allocator, over[0..encoded.len]));
}

test "decode rejects duplicate fields, including repeated unknown-optional ids" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    var buf: [Limits.default.max_serialized_len]u8 = undefined;
    const encoded = try encodeClient(&client, Limits.default, &buf);

    var duplicated: [Limits.default.max_serialized_len]u8 = undefined;
    @memcpy(duplicated[0..encoded.len], encoded);
    var pos: usize = encoded.len;
    writeTlv(&duplicated, &pos, field_server_name, "duplicate.test");
    patchSectionLen(&duplicated, pos);
    try testing.expectError(error.DuplicateField, decodeDefault(testing.allocator, duplicated[0..pos]));

    var duplicated_optional: [Limits.default.max_serialized_len]u8 = undefined;
    @memcpy(duplicated_optional[0..encoded.len], encoded);
    var pos2: usize = encoded.len;
    writeTlv(&duplicated_optional, &pos2, 0x9abc, "first");
    writeTlv(&duplicated_optional, &pos2, 0x9abc, "second");
    patchSectionLen(&duplicated_optional, pos2);
    try testing.expectError(error.DuplicateField, decodeDefault(testing.allocator, duplicated_optional[0..pos2]));
}

test "decode rejects a field section exceeding the configured field-count limit" {
    var tight_limits = Limits.default;
    tight_limits.max_fields = 8; // the client record has more than 8 mandatory fields

    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    var buf: [Limits.default.max_serialized_len]u8 = undefined;
    const encoded = try encodeClient(&client, Limits.default, &buf);

    try testing.expectError(error.TooManyFields, decode(testing.allocator, tight_limits, encoded));
}

test "field-count limit accepts exactly max_fields and rejects one more" {
    // Build a minimal server record (8 common fields), then append unknown
    // optional filler fields up to and past a tight max_fields boundary.
    var common = try sampleCommon(testing.allocator, &([_]u8{0xab} ** 32));
    var server: ServerRecoverableState = .{};
    server.init(&common);
    defer server.deinit();

    var buf: [Limits.default.max_serialized_len]u8 = undefined;
    const encoded = try encodeServer(&server, Limits.default, &buf);

    var offset: usize = header_len;
    var base_field_count: usize = 0;
    while (try nextTlv(encoded, &offset)) |_| base_field_count += 1;

    var exact: [Limits.default.max_serialized_len]u8 = undefined;
    @memcpy(exact[0..encoded.len], encoded);
    var pos: usize = encoded.len;
    var next_id: u16 = 0x9000;
    while (base_field_count < 32) : (base_field_count += 1) {
        writeTlv(&exact, &pos, next_id, "x");
        next_id += 1;
    }
    patchSectionLen(&exact, pos);

    var limits_32 = Limits.default;
    limits_32.max_fields = 32;
    var decoded = try decode(testing.allocator, limits_32, exact[0..pos]);
    defer decoded.deinit();

    // One more field beyond the limit must fail.
    var over: [Limits.default.max_serialized_len]u8 = undefined;
    @memcpy(over[0 .. pos + tlvLen(1)][0..pos], exact[0..pos]);
    var pos2 = pos;
    writeTlv(&over, &pos2, next_id, "x");
    patchSectionLen(&over, pos2);
    try testing.expectError(error.TooManyFields, decode(testing.allocator, limits_32, over[0..pos2]));
}

test "Limits.validate rejects configurations exceeding hard caps" {
    var too_many_fields = Limits.default;
    too_many_fields.max_fields = hard_max_fields + 1;
    try testing.expectError(error.InvalidLimits, too_many_fields.validate());

    var zero_fields = Limits.default;
    zero_fields.max_fields = 0;
    try testing.expectError(error.InvalidLimits, zero_fields.validate());

    var ticket_over_wire_max = Limits.default;
    ticket_over_wire_max.max_ticket_len = absolute_ticket_wire_max + 1;
    try testing.expectError(error.InvalidLimits, ticket_over_wire_max.validate());

    var zero_ticket = Limits.default;
    zero_ticket.max_ticket_len = 0;
    try testing.expectError(error.InvalidLimits, zero_ticket.validate());

    var transport_over = Limits.default;
    transport_over.max_transport_compat_len = hard_max_compat_len + 1;
    try testing.expectError(error.InvalidLimits, transport_over.validate());

    var application_over = Limits.default;
    application_over.max_application_compat_len = hard_max_compat_len + 1;
    try testing.expectError(error.InvalidLimits, application_over.validate());

    var serialized_over = Limits.default;
    serialized_over.max_serialized_len = hard_max_serialized_len + 1;
    try testing.expectError(error.InvalidLimits, serialized_over.validate());

    var zero_serialized = Limits.default;
    zero_serialized.max_serialized_len = 0;
    try testing.expectError(error.InvalidLimits, zero_serialized.validate());

    // Exactly at every hard cap must be accepted.
    var at_caps = Limits{
        .max_fields = hard_max_fields,
        .max_ticket_len = absolute_ticket_wire_max,
        .max_transport_compat_len = hard_max_compat_len,
        .max_application_compat_len = hard_max_compat_len,
        .max_serialized_len = hard_max_serialized_len,
    };
    try at_caps.validate();
}

test "decode rejects state larger than the configured serialized-length limit" {
    var oversized: [Limits.default.max_serialized_len + 1]u8 = [_]u8{0} ** (Limits.default.max_serialized_len + 1);
    try testing.expectError(error.StateTooLarge, decodeDefault(testing.allocator, &oversized));
}

test "constructing a ticket larger than the configured limit is rejected" {
    var common = try sampleCommon(testing.allocator, &([_]u8{0xab} ** 32));
    errdefer common.deinit();

    var oversized_ticket: [Limits.default.max_ticket_len + 1]u8 = undefined;
    @memset(&oversized_ticket, 0x42);

    var state: ClientTicketState = .{};
    try testing.expectError(error.TicketTooLarge, state.init(testing.allocator, Limits.default, &common, .{
        .ticket = &oversized_ticket,
        .ticket_age_add = 0,
        .ticket_nonce = "",
        .received_at_unix_ms = 0,
    }));
    // `common` was moved into `state` regardless of the subsequent failure;
    // it is now zero-valued and safe to deinit.
    common.deinit();
}

test "encoding into an undersized buffer fails before writing any partial state" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    const needed = clientEncodedLen(&client);
    var undersized_buf: [Limits.default.max_serialized_len]u8 = undefined;

    var size: usize = 0;
    while (size < needed) : (size += 1) {
        const sentinel = 0xee;
        @memset(undersized_buf[0..needed], sentinel);
        try testing.expectError(error.BufferTooSmall, encodeClient(&client, Limits.default, undersized_buf[0..size]));
        // The call must never touch the buffer at all when it rejects up
        // front, so every byte remains the sentinel we prefilled.
        for (undersized_buf[0..needed]) |byte| try testing.expectEqual(@as(u8, sentinel), byte);
    }

    // Exactly `needed` bytes must succeed.
    var exact_buf: [Limits.default.max_serialized_len]u8 = undefined;
    const encoded = try encodeClient(&client, Limits.default, exact_buf[0..needed]);
    try testing.expectEqual(needed, encoded.len);
}

test "encoding state above max_serialized_len is rejected" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    var tiny_limits = Limits.default;
    tiny_limits.max_serialized_len = clientEncodedLen(&client) - 1;

    var buf: [Limits.default.max_serialized_len]u8 = undefined;
    try testing.expectError(error.StateTooLarge, encodeClient(&client, tiny_limits, &buf));
}

test "encode enforces max_ticket_len even when the state was built under wider limits" {
    var wide = Limits.default;
    wide.max_ticket_len = 8192;
    wide.max_serialized_len = 16384;

    var common = try sampleCommon(testing.allocator, &([_]u8{0xab} ** 32));
    var wide_ticket: [5000]u8 = undefined;
    @memset(&wide_ticket, 0x5a);
    var state: ClientTicketState = .{};
    try state.init(testing.allocator, wide, &common, .{
        .ticket = &wide_ticket,
        .ticket_age_add = 1,
        .ticket_nonce = "n",
        .received_at_unix_ms = 0,
    });
    defer state.deinit();

    var tight = wide;
    tight.max_ticket_len = 4096;

    var buf: [16384]u8 = undefined;
    // Must fail up front (not just at decode time) because the state's
    // 5000-byte ticket exceeds `tight.max_ticket_len`.
    try testing.expectError(error.FieldTooLarge, encodeClient(&state, tight, &buf));
    try testing.expectError(error.FieldTooLarge, clientEncodedLenWithLimits(&state, tight));

    // Encoding and decoding under the *same* (wide) limits must still
    // round-trip.
    const encoded = try encodeClient(&state, wide, &buf);
    var decoded = try decode(testing.allocator, wide, encoded);
    defer decoded.deinit();
    try testing.expectEqualStrings(state.ticket.slice(), decoded.client.ticket.slice());
}

test "encode enforces max_transport_compat_len and max_application_compat_len symmetrically with decode" {
    var wide = Limits.default;
    wide.max_transport_compat_len = 2048;
    wide.max_application_compat_len = 2048;
    wide.max_serialized_len = 8192;

    var common: ResumableSessionCommon = .{};
    var wide_blob: [1500]u8 = undefined;
    @memset(&wide_blob, 0x11);
    try common.init(testing.allocator, wide, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &([_]u8{0xab} ** 32),
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf"),
        .issued_at_unix_ms = 0,
        .lifetime_seconds = 100,
        .transport_compat = .{ .format_id = 1, .format_version = 1, .bytes = &wide_blob },
    });
    var server: ServerRecoverableState = .{};
    server.init(&common);
    defer server.deinit();

    var tight_transport = wide;
    tight_transport.max_transport_compat_len = 1024;
    var buf: [8192]u8 = undefined;
    try testing.expectError(error.FieldTooLarge, encodeServer(&server, tight_transport, &buf));

    const encoded = try encodeServer(&server, wide, &buf);
    var decoded = try decode(testing.allocator, wide, encoded);
    defer decoded.deinit();
    try testing.expectEqualSlices(u8, &wide_blob, decoded.server.common.transport_compat.?.slice());

    // Decoding the same bytes under the tighter transport-compat limit must
    // also fail, proving encode and decode agree on every limit.
    try testing.expectError(error.FieldTooLarge, decode(testing.allocator, tight_transport, encoded));
}

test "encode enforces max_fields symmetrically with decode" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    var tight_fields = Limits.default;
    tight_fields.max_fields = 8; // fewer than the ~11 fields a client record emits

    var buf: [Limits.default.max_serialized_len]u8 = undefined;
    try testing.expectError(error.TooManyFields, encodeClient(&client, tight_fields, &buf));
    try testing.expectError(error.TooManyFields, clientEncodedLenWithLimits(&client, tight_fields));

    // The same limits must reject the equivalent already-encoded record at
    // decode time too (proven separately above); encode now refuses to
    // produce it in the first place.
    const encoded = try encodeClient(&client, Limits.default, &buf);
    try testing.expectError(error.TooManyFields, decode(testing.allocator, tight_fields, encoded));
}

test "allocation failure during client ticket construction and decode does not leak" {
    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var client = try sampleClient(allocator);
            client.deinit();
        }
    }.run, .{});

    var seed = try sampleClient(testing.allocator);
    defer seed.deinit();
    var buf: [Limits.default.max_serialized_len]u8 = undefined;
    const encoded = try encodeClient(&seed, Limits.default, &buf);

    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var decoded = try decodeDefault(allocator, bytes);
            decoded.deinit();
        }
    }.run, .{encoded});
}

test "allocation failure during compat-snapshot construction does not leak" {
    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var snap: CompatSnapshot = .{};
            try snap.init(allocator, 1, 1, "some-compat-bytes", Limits.default.max_transport_compat_len);
            snap.deinit();
        }
    }.run, .{});
}

test "moveFrom invalidates the source and prevents double-free" {
    var backing = [_]u8{0xcc} ** 4096;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    const allocator = fba.allocator();

    var source: ClientTicketState = try sampleClient(allocator);
    var dest: ClientTicketState = .{};
    dest.moveFrom(&source);

    // The source is now zero-valued: its ticket/psk storage is empty, and
    // deiniting it is a safe no-op rather than a double-free of `dest`'s
    // storage.
    try testing.expectEqual(@as(usize, 0), source.ticket.slice().len);
    try testing.expectEqual(@as(usize, 0), source.common.resumption_psk.slice().len);
    source.deinit();

    try testing.expectEqualStrings("opaque-ticket-bytes", dest.ticket.slice());
    dest.deinit();
}

test "clone produces an independent deep copy" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    var cloned: ClientTicketState = .{};
    try client.cloneInto(testing.allocator, &cloned);
    defer cloned.deinit();

    try testing.expectEqualStrings(client.ticket.slice(), cloned.ticket.slice());
    try testing.expect(client.ticket.bytes.ptr != cloned.ticket.bytes.ptr);

    var server_common = try sampleCommon(testing.allocator, &([_]u8{0xef} ** 32));
    var server: ServerRecoverableState = .{};
    server.init(&server_common);
    defer server.deinit();

    var cloned_server: ServerRecoverableState = .{};
    try server.cloneInto(testing.allocator, &cloned_server);
    defer cloned_server.deinit();
    try testing.expectEqualStrings(
        server.common.server_name.?.slice(),
        cloned_server.common.server_name.?.slice(),
    );
}

test "CompatSnapshot.init rejects a limit exceeding the absolute hard cap" {
    var snap: CompatSnapshot = .{};
    try testing.expectError(
        error.InvalidLimits,
        snap.init(testing.allocator, 1, 1, "data", hard_max_compat_len + 1),
    );
    // Exactly at the hard cap must be accepted.
    try snap.init(testing.allocator, 1, 1, "data", hard_max_compat_len);
    snap.deinit();
}

test "CompatSnapshot.init on an already-live value releases the prior allocation" {
    var snap: CompatSnapshot = .{};
    try snap.init(testing.allocator, 1, 1, "first-value", hard_max_compat_len);
    try testing.expectEqualStrings("first-value", snap.slice());

    // Reinitializing a live snapshot must not leak the first allocation;
    // `testing.allocator` fails the test on any unreleased allocation.
    try snap.init(testing.allocator, 2, 2, "second-value", hard_max_compat_len);
    try testing.expectEqualStrings("second-value", snap.slice());
    snap.deinit();
}

test "CompatSnapshot.cloneInto into an already-live destination releases the prior allocation" {
    var a: CompatSnapshot = .{};
    try a.init(testing.allocator, 1, 1, "a-value", hard_max_compat_len);
    defer a.deinit();

    var b: CompatSnapshot = .{};
    try b.init(testing.allocator, 9, 9, "stale-destination-value", hard_max_compat_len);
    // `b` is live; cloning into it must release its existing allocation
    // rather than leak it.
    try a.cloneInto(testing.allocator, &b);
    defer b.deinit();
    try testing.expectEqualStrings("a-value", b.slice());
}

test "CompatSnapshot.moveFrom into an already-live destination releases the prior allocation" {
    var source: CompatSnapshot = .{};
    try source.init(testing.allocator, 1, 1, "source-value", hard_max_compat_len);

    var dest: CompatSnapshot = .{};
    try dest.init(testing.allocator, 9, 9, "stale-destination-value", hard_max_compat_len);
    dest.moveFrom(&source);
    defer dest.deinit();

    try testing.expectEqualStrings("source-value", dest.slice());
    // `source` is now zero-valued; deiniting it is a safe no-op.
    try testing.expectEqual(@as(usize, 0), source.slice().len);
    source.deinit();
}

test "CompatSnapshot.moveFrom into itself is a safe no-op" {
    var snap: CompatSnapshot = .{};
    try snap.init(testing.allocator, 1, 1, "self-move-value", hard_max_compat_len);
    defer snap.deinit();

    snap.moveFrom(&snap);
    try testing.expectEqualStrings("self-move-value", snap.slice());
}

test "ResumableSessionCommon.moveFrom into itself is a safe no-op" {
    var common = try sampleCommon(testing.allocator, &([_]u8{0xab} ** 32));
    defer common.deinit();

    common.moveFrom(&common);
    try testing.expectEqual(@as(usize, 32), common.resumption_psk.slice().len);
    try testing.expectEqualStrings("example.test", common.server_name.?.slice());
}

test "ClientTicketState.moveFrom into itself is a safe no-op" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    client.moveFrom(&client);
    try testing.expectEqualStrings("opaque-ticket-bytes", client.ticket.slice());
}

test "secret-bearing types expose no ordinary formatting path" {
    try testing.expect(@hasDecl(ResumableSessionCommon, "format"));
    try testing.expect(@hasDecl(ClientTicketState, "format"));
    try testing.expect(@hasDecl(ServerRecoverableState, "format"));
    try testing.expect(@hasDecl(CompatSnapshot, "format"));
}

// Checked-in literal byte fixtures, generated once from `sampleClient`
// (cipher tls_aes_128_gcm_sha256, PSK 0xab*32, sni "example.test", alpn
// "h3", auth_binding = SHA-256("leaf-der-bytes"), issued_at_unix_ms
// 1_000_000, lifetime_seconds 3600, resume_only, ticket
// "opaque-ticket-bytes", ticket_age_add 12345, ticket_nonce "nonce",
// received_at_unix_ms 1_500_000) and the equivalent server-only common
// metadata (PSK 0xcd*32, otherwise identical), both under `Limits.default`.
// Pinned as literal bytes — not re-derived from the encoder under test — so
// an accidental field-id/order/integer-encoding change is caught even if
// the round-trip test above is (incorrectly) also changed to match.
const client_fixture: [187]u8 = .{
    0x54, 0x52, 0x53, 0x31, 0x01, 0x01, 0x00, 0x00, 0x00, 0xb1, 0x00, 0x01,
    0x00, 0x02, 0x13, 0x01, 0x00, 0x02, 0x00, 0x20, 0xab, 0xab, 0xab, 0xab,
    0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
    0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
    0xab, 0xab, 0xab, 0xab, 0x00, 0x03, 0x00, 0x0c, 0x65, 0x78, 0x61, 0x6d,
    0x70, 0x6c, 0x65, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x00, 0x04, 0x00, 0x02,
    0x68, 0x33, 0x00, 0x05, 0x00, 0x20, 0x47, 0x9a, 0xd1, 0xdc, 0x62, 0x45,
    0x1c, 0x82, 0xf1, 0xcb, 0x22, 0x9b, 0xf5, 0xbf, 0x62, 0x9f, 0x1e, 0x2e,
    0xb8, 0x8b, 0x79, 0xd0, 0x30, 0x7b, 0x6d, 0xcf, 0x18, 0x98, 0xa0, 0xcc,
    0xe5, 0xf7, 0x00, 0x06, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
    0x42, 0x40, 0x00, 0x07, 0x00, 0x04, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x08,
    0x00, 0x01, 0x00, 0x00, 0x10, 0x00, 0x13, 0x6f, 0x70, 0x61, 0x71, 0x75,
    0x65, 0x2d, 0x74, 0x69, 0x63, 0x6b, 0x65, 0x74, 0x2d, 0x62, 0x79, 0x74,
    0x65, 0x73, 0x00, 0x11, 0x00, 0x04, 0x00, 0x00, 0x30, 0x39, 0x00, 0x12,
    0x00, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x00, 0x13, 0x00, 0x08, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x16, 0xe3, 0x60,
};

const server_fixture: [135]u8 = .{
    0x54, 0x52, 0x53, 0x31, 0x01, 0x02, 0x00, 0x00, 0x00, 0x7d, 0x00, 0x01,
    0x00, 0x02, 0x13, 0x01, 0x00, 0x02, 0x00, 0x20, 0xcd, 0xcd, 0xcd, 0xcd,
    0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
    0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
    0xcd, 0xcd, 0xcd, 0xcd, 0x00, 0x03, 0x00, 0x0c, 0x65, 0x78, 0x61, 0x6d,
    0x70, 0x6c, 0x65, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x00, 0x04, 0x00, 0x02,
    0x68, 0x33, 0x00, 0x05, 0x00, 0x20, 0x47, 0x9a, 0xd1, 0xdc, 0x62, 0x45,
    0x1c, 0x82, 0xf1, 0xcb, 0x22, 0x9b, 0xf5, 0xbf, 0x62, 0x9f, 0x1e, 0x2e,
    0xb8, 0x8b, 0x79, 0xd0, 0x30, 0x7b, 0x6d, 0xcf, 0x18, 0x98, 0xa0, 0xcc,
    0xe5, 0xf7, 0x00, 0x06, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
    0x42, 0x40, 0x00, 0x07, 0x00, 0x04, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x08,
    0x00, 0x01, 0x00,
};

test "checked-in literal client-record byte fixture decodes to every expected field" {
    var decoded = try decodeDefault(testing.allocator, &client_fixture);
    defer decoded.deinit();
    try testing.expect(decoded == .client);
    const c = &decoded.client;

    try testing.expectEqual(algorithms.CipherSuite.tls_aes_128_gcm_sha256, c.common.cipher_suite);
    try testing.expectEqualSlices(u8, &([_]u8{0xab} ** 32), c.common.resumption_psk.slice());
    try testing.expectEqualStrings("example.test", c.common.server_name.?.slice());
    try testing.expectEqualStrings("h3", c.common.application_protocol.?.slice());
    try testing.expect(c.common.auth_binding.eql(AuthBinding.fromLeafCertificateDer("leaf-der-bytes")));
    try testing.expectEqual(@as(i64, 1_000_000), c.common.issued_at_unix_ms);
    try testing.expectEqual(@as(u32, 3600), c.common.lifetime_seconds);
    try testing.expectEqual(EarlyDataPolicy.resume_only, c.common.early_data);
    try testing.expect(c.common.transport_compat == null);
    try testing.expect(c.common.application_compat == null);
    try testing.expectEqualStrings("opaque-ticket-bytes", c.ticket.slice());
    try testing.expectEqual(@as(u32, 12345), c.ticket_age_add);
    try testing.expectEqualStrings("nonce", c.ticket_nonce.slice());
    try testing.expectEqual(@as(i64, 1_500_000), c.received_at_unix_ms);
}

test "checked-in literal server-record byte fixture decodes to every expected field" {
    var decoded = try decodeDefault(testing.allocator, &server_fixture);
    defer decoded.deinit();
    try testing.expect(decoded == .server);
    const s = &decoded.server;

    try testing.expectEqual(algorithms.CipherSuite.tls_aes_128_gcm_sha256, s.common.cipher_suite);
    try testing.expectEqualSlices(u8, &([_]u8{0xcd} ** 32), s.common.resumption_psk.slice());
    try testing.expectEqualStrings("example.test", s.common.server_name.?.slice());
    try testing.expectEqualStrings("h3", s.common.application_protocol.?.slice());
    try testing.expect(s.common.auth_binding.eql(AuthBinding.fromLeafCertificateDer("leaf-der-bytes")));
    try testing.expectEqual(@as(i64, 1_000_000), s.common.issued_at_unix_ms);
    try testing.expectEqual(@as(u32, 3600), s.common.lifetime_seconds);
    try testing.expectEqual(EarlyDataPolicy.resume_only, s.common.early_data);
}

test "current encoder output exactly equals the checked-in fixtures" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();
    var buf: [Limits.default.max_serialized_len]u8 = undefined;
    const encoded = try encodeClient(&client, Limits.default, &buf);
    try testing.expectEqualSlices(u8, &client_fixture, encoded);

    var server_common = try sampleCommon(testing.allocator, &([_]u8{0xcd} ** 32));
    var server: ServerRecoverableState = .{};
    server.init(&server_common);
    defer server.deinit();
    var buf2: [Limits.default.max_serialized_len]u8 = undefined;
    const encoded2 = try encodeServer(&server, Limits.default, &buf2);
    try testing.expectEqualSlices(u8, &server_fixture, encoded2);
}

/// Rebuilds `fixture` with every TLV whose field id is `field_id_to_remove`
/// dropped, patching the section length to match.
fn fixtureWithFieldRemoved(fixture: []const u8, field_id_to_remove: u16, out: []u8) usize {
    @memcpy(out[0..header_len], fixture[0..header_len]);
    var pos: usize = header_len;
    var offset: usize = header_len;
    while ((nextTlv(fixture, &offset) catch unreachable)) |tlv| {
        if (tlv.field_id == field_id_to_remove) continue;
        writeTlv(out, &pos, tlv.field_id, tlv.value);
    }
    patchSectionLen(out, pos);
    return pos;
}

/// Rebuilds `fixture` with an extra copy of the first TLV whose field id is
/// `field_id_to_duplicate` appended at the end, patching the section length
/// to match.
fn fixtureWithFieldDuplicated(fixture: []const u8, field_id_to_duplicate: u16, out: []u8) usize {
    @memcpy(out[0..fixture.len], fixture);
    var pos: usize = fixture.len;
    var offset: usize = header_len;
    var value_to_duplicate: ?[]const u8 = null;
    while ((nextTlv(fixture, &offset) catch unreachable)) |tlv| {
        if (tlv.field_id == field_id_to_duplicate) value_to_duplicate = tlv.value;
    }
    writeTlv(out, &pos, field_id_to_duplicate, value_to_duplicate.?);
    patchSectionLen(out, pos);
    return pos;
}

test "duplicating any known client field, mandatory or optional, is rejected" {
    const all_client_field_ids = [_]u16{
        field_cipher_suite, field_resumption_psk, field_server_name,      field_application_protocol,
        field_auth_binding, field_issued_at,      field_lifetime_seconds, field_early_data,
        field_ticket,       field_ticket_age_add, field_ticket_nonce,     field_received_at,
    };
    for (all_client_field_ids) |field_id| {
        var buf: [client_fixture.len + 64]u8 = undefined;
        const len = fixtureWithFieldDuplicated(&client_fixture, field_id, &buf);
        try testing.expectError(error.DuplicateField, decodeDefault(testing.allocator, buf[0..len]));
    }
}

test "removing any mandatory client field is rejected as missing" {
    const mandatory_client_field_ids = [_]u16{
        field_cipher_suite,     field_resumption_psk, field_auth_binding, field_issued_at,
        field_lifetime_seconds, field_early_data,     field_ticket,       field_ticket_age_add,
        field_ticket_nonce,     field_received_at,
    };
    for (mandatory_client_field_ids) |field_id| {
        var buf: [client_fixture.len]u8 = undefined;
        const len = fixtureWithFieldRemoved(&client_fixture, field_id, &buf);
        try testing.expectError(error.MissingField, decodeDefault(testing.allocator, buf[0..len]));
    }
}

test "removing an optional-presence client field (server_name/application_protocol) leaves it null, not missing" {
    var without_sni: [client_fixture.len]u8 = undefined;
    const sni_len = fixtureWithFieldRemoved(&client_fixture, field_server_name, &without_sni);
    var decoded_no_sni = try decodeDefault(testing.allocator, without_sni[0..sni_len]);
    defer decoded_no_sni.deinit();
    try testing.expect(decoded_no_sni.client.common.server_name == null);
    // Every other mandatory field is still present and correctly decoded.
    try testing.expectEqualStrings("opaque-ticket-bytes", decoded_no_sni.client.ticket.slice());

    var without_alpn: [client_fixture.len]u8 = undefined;
    const alpn_len = fixtureWithFieldRemoved(&client_fixture, field_application_protocol, &without_alpn);
    var decoded_no_alpn = try decodeDefault(testing.allocator, without_alpn[0..alpn_len]);
    defer decoded_no_alpn.deinit();
    try testing.expect(decoded_no_alpn.client.common.application_protocol == null);
}

test "duplicating any known server field is rejected" {
    const all_server_field_ids = [_]u16{
        field_cipher_suite, field_resumption_psk, field_server_name,      field_application_protocol,
        field_auth_binding, field_issued_at,      field_lifetime_seconds, field_early_data,
    };
    for (all_server_field_ids) |field_id| {
        var buf: [server_fixture.len + 64]u8 = undefined;
        const len = fixtureWithFieldDuplicated(&server_fixture, field_id, &buf);
        try testing.expectError(error.DuplicateField, decodeDefault(testing.allocator, buf[0..len]));
    }
}

test "removing any mandatory server field is rejected as missing" {
    const mandatory_server_field_ids = [_]u16{
        field_cipher_suite, field_resumption_psk,   field_auth_binding,
        field_issued_at,    field_lifetime_seconds, field_early_data,
    };
    for (mandatory_server_field_ids) |field_id| {
        var buf: [server_fixture.len]u8 = undefined;
        const len = fixtureWithFieldRemoved(&server_fixture, field_id, &buf);
        try testing.expectError(error.MissingField, decodeDefault(testing.allocator, buf[0..len]));
    }
}

test "removing an optional-presence server field (server_name/application_protocol) leaves it null, not missing" {
    var without_sni: [server_fixture.len]u8 = undefined;
    const sni_len = fixtureWithFieldRemoved(&server_fixture, field_server_name, &without_sni);
    var decoded_no_sni = try decodeDefault(testing.allocator, without_sni[0..sni_len]);
    defer decoded_no_sni.deinit();
    try testing.expect(decoded_no_sni.server.common.server_name == null);

    var without_alpn: [server_fixture.len]u8 = undefined;
    const alpn_len = fixtureWithFieldRemoved(&server_fixture, field_application_protocol, &without_alpn);
    var decoded_no_alpn = try decodeDefault(testing.allocator, without_alpn[0..alpn_len]);
    defer decoded_no_alpn.deinit();
    try testing.expect(decoded_no_alpn.server.common.application_protocol == null);
}
