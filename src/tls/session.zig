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

const std = @import("std");
const crypto = @import("crypto");
const algorithms = @import("algorithms.zig");
const dns_name = @import("dns_name.zig");
const sni_provider = @import("sni_provider.zig");

const secrets = crypto.secrets;

pub const max_sni_len = dns_name.max_name_len;
pub const max_alpn_len = 255;
pub const max_ticket_len = 65535;
pub const max_ticket_nonce_len = 255;
pub const max_compat_blob_len = 512;
pub const auth_binding_len = 32;
pub const max_psk_len = 48;

/// Overall bound on one encoded internal-state record, chosen generously
/// above the sum of every field's individual maximum so a corrupt or hostile
/// buffer is rejected before any attacker-controlled allocation is made.
pub const max_encoded_state_len: usize = 128 * 1024;

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
pub const CompatSnapshot = struct {
    format_id: u16,
    format_version: u16,
    len: u16 = 0,
    bytes: [max_compat_blob_len]u8 = undefined,

    pub const Error = error{CompatSnapshotTooLarge};

    pub fn init(format_id: u16, snapshot_version: u16, data: []const u8) Error!CompatSnapshot {
        if (data.len > max_compat_blob_len) return error.CompatSnapshotTooLarge;
        var self = CompatSnapshot{ .format_id = format_id, .format_version = snapshot_version };
        @memcpy(self.bytes[0..data.len], data);
        self.len = @intCast(data.len);
        return self;
    }

    pub fn slice(self: *const CompatSnapshot) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn eql(self: *const CompatSnapshot, other: *const CompatSnapshot) bool {
        return self.format_id == other.format_id and
            self.format_version == other.format_version and
            std.mem.eql(u8, self.slice(), other.slice());
    }
};

/// Canonical ASCII-lowercase SNI, validated with the shared TLS DNS-name
/// rules at construction time.
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
/// length-prefixed by a single byte, so 255 bytes is the wire maximum).
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
/// Owns a resumption PSK (a secret). Fields are conceptually private:
/// callers should use `init`/`deinit`/`clone` rather than constructing or
/// copying this value directly, since a bitwise copy of the PSK container is
/// only safe because `FixedSecret` is inline storage — treat that as an
/// implementation detail, not a supported API.
pub const ResumableSessionCommon = struct {
    resumption_psk: ResumptionPsk = .{},
    cipher_suite: algorithms.CipherSuite = .tls_aes_128_gcm_sha256,
    sni: SniName = .{},
    alpn: AlpnProtocol = .{},
    auth_binding: AuthBinding = .{ .bytes = [_]u8{0} ** auth_binding_len },
    issued_at: u64 = 0,
    lifetime_seconds: u32 = 0,
    early_data: EarlyDataPolicy = .resume_only,
    transport_compat: ?CompatSnapshot = null,
    application_compat: ?CompatSnapshot = null,

    pub const InitParams = struct {
        cipher_suite: algorithms.CipherSuite,
        resumption_psk: []const u8,
        sni: []const u8,
        alpn: []const u8,
        auth_binding: AuthBinding,
        issued_at: u64,
        lifetime_seconds: u32,
        early_data: EarlyDataPolicy = .resume_only,
        transport_compat: ?CompatSnapshot = null,
        application_compat: ?CompatSnapshot = null,
    };

    pub const InitError = error{
        InvalidDnsName,
        AlpnProtocolTooLarge,
        InvalidPskLength,
        InvalidEarlyDataPolicy,
    };

    pub fn init(params: InitParams) InitError!ResumableSessionCommon {
        const expected_psk_len = algorithms.transcriptHash(params.cipher_suite).digestLen();
        if (params.resumption_psk.len != expected_psk_len) return error.InvalidPskLength;
        switch (params.early_data) {
            .resume_only => {},
            .early_data_capable => |max| if (max == 0) return error.InvalidEarlyDataPolicy,
        }

        var self = ResumableSessionCommon{
            .cipher_suite = params.cipher_suite,
            .sni = try SniName.init(params.sni),
            .alpn = try AlpnProtocol.init(params.alpn),
            .auth_binding = params.auth_binding,
            .issued_at = params.issued_at,
            .lifetime_seconds = params.lifetime_seconds,
            .early_data = params.early_data,
            .transport_compat = params.transport_compat,
            .application_compat = params.application_compat,
        };
        errdefer self.deinit();
        self.resumption_psk.replace(params.resumption_psk) catch unreachable;
        return self;
    }

    pub fn deinit(self: *ResumableSessionCommon) void {
        self.resumption_psk.deinit();
    }

    /// Explicit deep copy. Does not alias the source's secret storage.
    pub fn clone(self: *const ResumableSessionCommon) ResumableSessionCommon {
        var out = self.*;
        out.resumption_psk = self.resumption_psk.copy();
        return out;
    }

    pub fn isExpired(self: *const ResumableSessionCommon, now: u64) bool {
        const expiry = std.math.add(u64, self.issued_at, self.lifetime_seconds) catch std.math.maxInt(u64);
        return now >= expiry;
    }

    pub fn isNotYetValid(self: *const ResumableSessionCommon, now: u64) bool {
        return now < self.issued_at;
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
    /// Unix seconds when this ticket was received from the server.
    received_at: u64 = 0,

    pub const InitParams = struct {
        /// Ownership of `common` is transferred in; on success it is owned
        /// by the returned `ClientTicketState`, on failure it is deinited.
        common: ResumableSessionCommon,
        ticket: []const u8,
        ticket_age_add: u32,
        ticket_nonce: []const u8,
        received_at: u64,
    };

    pub const InitError = error{ OutOfMemory, TicketTooLarge, NonceTooLarge };

    pub fn init(allocator: std.mem.Allocator, params: InitParams) InitError!ClientTicketState {
        var common = params.common;
        errdefer common.deinit();

        if (params.ticket.len == 0 or params.ticket.len > max_ticket_len) return error.TicketTooLarge;
        if (params.ticket_nonce.len > max_ticket_nonce_len) return error.NonceTooLarge;

        var self = ClientTicketState{
            .common = common,
            .ticket_age_add = params.ticket_age_add,
            .received_at = params.received_at,
        };
        errdefer self.common.deinit();

        self.ticket.init(allocator, params.ticket.len, params.ticket) catch |err| switch (err) {
            error.SecretTooLarge => return error.TicketTooLarge,
            else => return error.OutOfMemory,
        };
        errdefer self.ticket.deinit();

        self.ticket_nonce.replace(params.ticket_nonce) catch return error.NonceTooLarge;

        return self;
    }

    pub fn deinit(self: *ClientTicketState) void {
        self.common.deinit();
        self.ticket.deinit();
        self.ticket_nonce.deinit();
    }

    pub fn clone(self: *const ClientTicketState, allocator: std.mem.Allocator) error{OutOfMemory}!ClientTicketState {
        var out = ClientTicketState{
            .common = self.common.clone(),
            .ticket_age_add = self.ticket_age_add,
            .received_at = self.received_at,
        };
        errdefer out.common.deinit();

        out.ticket.init(allocator, self.ticket.slice().len, self.ticket.slice()) catch return error.OutOfMemory;
        errdefer out.ticket.deinit();

        out.ticket_nonce = self.ticket_nonce.copy();
        return out;
    }

    /// Overflow-safe elapsed time since receipt, saturating to zero if `now`
    /// predates `received_at` (e.g. clock skew).
    pub fn ageSeconds(self: *const ClientTicketState, now: u64) u64 {
        return now -| self.received_at;
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

    pub fn init(common: ResumableSessionCommon) ServerRecoverableState {
        return .{ .common = common };
    }

    pub fn deinit(self: *ServerRecoverableState) void {
        self.common.deinit();
    }

    pub fn clone(self: *const ServerRecoverableState) ServerRecoverableState {
        return .{ .common = self.common.clone() };
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

/// The candidate connection context a stored session is checked against.
pub const CandidateContext = struct {
    cipher_suite: algorithms.CipherSuite,
    sni: []const u8,
    alpn: []const u8,
    auth_binding: AuthBinding,
    transport_compat: ?CompatSnapshot = null,
    application_compat: ?CompatSnapshot = null,
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
    now: u64,
) CompatibilityDecision {
    const resume_result = checkResumeEligibility(common, candidate, now);
    const early_data = checkEarlyDataEligibility(common, candidate, resume_result);
    return .{ .resumption = resume_result, .early_data = early_data };
}

fn checkResumeEligibility(
    common: *const ResumableSessionCommon,
    candidate: CandidateContext,
    now: u64,
) ResumeEligibility {
    if (common.isExpired(now)) return .{ .rejected = .expired };
    if (common.isNotYetValid(now)) return .{ .rejected = .not_yet_valid };
    if (common.cipher_suite != candidate.cipher_suite) return .{ .rejected = .cipher_suite_mismatch };
    if (!common.sni.eqlIgnoreCase(candidate.sni)) return .{ .rejected = .sni_mismatch };
    if (!common.alpn.eql(candidate.alpn)) return .{ .rejected = .alpn_mismatch };
    if (!common.auth_binding.eql(candidate.auth_binding)) return .{ .rejected = .auth_binding_mismatch };
    if (!compatSnapshotMatches(common.transport_compat, candidate.transport_compat))
        return .{ .rejected = .transport_mismatch };
    if (!compatSnapshotMatches(common.application_compat, candidate.application_compat))
        return .{ .rejected = .application_mismatch };
    return .eligible;
}

fn compatSnapshotMatches(session_snapshot: ?CompatSnapshot, candidate_snapshot: ?CompatSnapshot) bool {
    const s = session_snapshot orelse return true;
    const c = candidate_snapshot orelse return false;
    return s.eql(&c);
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

const optional_field_mask: u16 = 0x8000;

const field_cipher_suite: u16 = 0x0001;
const field_resumption_psk: u16 = 0x0002;
const field_sni: u16 = 0x0003;
const field_alpn: u16 = 0x0004;
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

pub const EncodeError = error{BufferTooSmall};

pub const DecodeError = error{
    StateTooLarge,
    Truncated,
    UnsupportedVersion,
    UnknownRecordType,
    DuplicateField,
    UnknownCriticalField,
    MissingField,
    MalformedLength,
    FieldTooLarge,
    InvalidCipherSuite,
    InvalidSni,
    InvalidPskLength,
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
    total += tlvLen(common.sni.slice().len);
    total += tlvLen(common.alpn.slice().len);
    total += tlvLen(auth_binding_len);
    total += tlvLen(8);
    total += tlvLen(4);
    total += tlvLen(earlyDataFieldLen(common.early_data));
    if (common.transport_compat) |*snap| total += tlvLen(4 + snap.slice().len);
    if (common.application_compat) |*snap| total += tlvLen(4 + snap.slice().len);
    return total;
}

pub fn clientEncodedLen(state: *const ClientTicketState) usize {
    var total: usize = 2;
    total += commonEncodedLen(&state.common);
    total += tlvLen(state.ticket.slice().len);
    total += tlvLen(4);
    total += tlvLen(state.ticket_nonce.slice().len);
    total += tlvLen(8);
    return total;
}

pub fn serverEncodedLen(state: *const ServerRecoverableState) usize {
    return 2 + commonEncodedLen(&state.common);
}

fn writeTlv(out: []u8, pos: *usize, field_id: u16, value: []const u8) EncodeError!void {
    if (out.len - pos.* < tlvLen(value.len)) return error.BufferTooSmall;
    std.mem.writeInt(u16, out[pos.*..][0..2], field_id, .big);
    std.mem.writeInt(u16, out[pos.* + 2 ..][0..2], @intCast(value.len), .big);
    @memcpy(out[pos.* + 4 ..][0..value.len], value);
    pos.* += tlvLen(value.len);
}

fn writeCompatSnapshot(out: []u8, pos: *usize, field_id: u16, snap: *const CompatSnapshot) EncodeError!void {
    var combined: [4 + max_compat_blob_len]u8 = undefined;
    std.mem.writeInt(u16, combined[0..2], snap.format_id, .big);
    std.mem.writeInt(u16, combined[2..4], snap.format_version, .big);
    const blob = snap.slice();
    @memcpy(combined[4..][0..blob.len], blob);
    try writeTlv(out, pos, field_id, combined[0 .. 4 + blob.len]);
}

fn writeCommon(out: []u8, pos: *usize, common: *const ResumableSessionCommon) EncodeError!void {
    var cs_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &cs_bytes, @intFromEnum(common.cipher_suite), .big);
    try writeTlv(out, pos, field_cipher_suite, &cs_bytes);

    try writeTlv(out, pos, field_resumption_psk, common.resumption_psk.slice());
    try writeTlv(out, pos, field_sni, common.sni.slice());
    try writeTlv(out, pos, field_alpn, common.alpn.slice());
    try writeTlv(out, pos, field_auth_binding, &common.auth_binding.bytes);

    var issued_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &issued_bytes, common.issued_at, .big);
    try writeTlv(out, pos, field_issued_at, &issued_bytes);

    var lifetime_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &lifetime_bytes, common.lifetime_seconds, .big);
    try writeTlv(out, pos, field_lifetime_seconds, &lifetime_bytes);

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
    try writeTlv(out, pos, field_early_data, early_slice);

    if (common.transport_compat) |*snap| try writeCompatSnapshot(out, pos, field_transport_compat, snap);
    if (common.application_compat) |*snap| try writeCompatSnapshot(out, pos, field_application_compat, snap);
}

pub fn encodeClient(state: *const ClientTicketState, out: []u8) EncodeError![]const u8 {
    if (out.len < 2) return error.BufferTooSmall;
    out[0] = format_version;
    out[1] = @intFromEnum(RecordType.client);
    var pos: usize = 2;

    try writeCommon(out, &pos, &state.common);
    try writeTlv(out, &pos, field_ticket, state.ticket.slice());

    var age_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &age_bytes, state.ticket_age_add, .big);
    try writeTlv(out, &pos, field_ticket_age_add, &age_bytes);

    try writeTlv(out, &pos, field_ticket_nonce, state.ticket_nonce.slice());

    var received_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &received_bytes, state.received_at, .big);
    try writeTlv(out, &pos, field_received_at, &received_bytes);

    return out[0..pos];
}

pub fn encodeServer(state: *const ServerRecoverableState, out: []u8) EncodeError![]const u8 {
    if (out.len < 2) return error.BufferTooSmall;
    out[0] = format_version;
    out[1] = @intFromEnum(RecordType.server);
    var pos: usize = 2;

    try writeCommon(out, &pos, &state.common);
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
    sni: ?[]const u8 = null,
    alpn: ?[]const u8 = null,
    auth_binding: ?[auth_binding_len]u8 = null,
    issued_at: ?u64 = null,
    lifetime_seconds: ?u32 = null,
    early_data: ?EarlyDataPolicy = null,
    transport_compat: ?CompatSnapshot = null,
    application_compat: ?CompatSnapshot = null,
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

fn decodeCompatSnapshot(value: []const u8) DecodeError!CompatSnapshot {
    if (value.len < 4) return error.MalformedLength;
    const cs_format_id = std.mem.readInt(u16, value[0..2], .big);
    const cs_format_version = std.mem.readInt(u16, value[2..4], .big);
    return CompatSnapshot.init(cs_format_id, cs_format_version, value[4..]) catch return error.FieldTooLarge;
}

fn parseSharedField(builder: *CommonFields, field_id: u16, value: []const u8) DecodeError!bool {
    switch (field_id) {
        field_cipher_suite => {
            if (builder.cipher_suite != null) return error.DuplicateField;
            if (value.len != 2) return error.MalformedLength;
            const raw = std.mem.readInt(u16, value[0..2], .big);
            builder.cipher_suite = algorithms.fromInt(algorithms.CipherSuite, raw) orelse return error.InvalidCipherSuite;
            return true;
        },
        field_resumption_psk => {
            if (builder.psk != null) return error.DuplicateField;
            if (value.len == 0 or value.len > max_psk_len) return error.FieldTooLarge;
            builder.psk = value;
            return true;
        },
        field_sni => {
            if (builder.sni != null) return error.DuplicateField;
            if (value.len == 0 or value.len > max_sni_len) return error.FieldTooLarge;
            builder.sni = value;
            return true;
        },
        field_alpn => {
            if (builder.alpn != null) return error.DuplicateField;
            if (value.len == 0 or value.len > max_alpn_len) return error.FieldTooLarge;
            builder.alpn = value;
            return true;
        },
        field_auth_binding => {
            if (builder.auth_binding != null) return error.DuplicateField;
            if (value.len != auth_binding_len) return error.MalformedLength;
            var binding: [auth_binding_len]u8 = undefined;
            @memcpy(&binding, value);
            builder.auth_binding = binding;
            return true;
        },
        field_issued_at => {
            if (builder.issued_at != null) return error.DuplicateField;
            if (value.len != 8) return error.MalformedLength;
            builder.issued_at = std.mem.readInt(u64, value[0..8], .big);
            return true;
        },
        field_lifetime_seconds => {
            if (builder.lifetime_seconds != null) return error.DuplicateField;
            if (value.len != 4) return error.MalformedLength;
            builder.lifetime_seconds = std.mem.readInt(u32, value[0..4], .big);
            return true;
        },
        field_early_data => {
            if (builder.early_data != null) return error.DuplicateField;
            builder.early_data = try decodeEarlyData(value);
            return true;
        },
        field_transport_compat => {
            if (builder.transport_compat != null) return error.DuplicateField;
            builder.transport_compat = try decodeCompatSnapshot(value);
            return true;
        },
        field_application_compat => {
            if (builder.application_compat != null) return error.DuplicateField;
            builder.application_compat = try decodeCompatSnapshot(value);
            return true;
        },
        else => return false,
    }
}

fn buildCommon(fields: CommonFields) DecodeError!ResumableSessionCommon {
    const cipher_suite = fields.cipher_suite orelse return error.MissingField;
    const psk = fields.psk orelse return error.MissingField;
    const sni = fields.sni orelse return error.MissingField;
    const alpn = fields.alpn orelse return error.MissingField;
    const auth_binding_bytes = fields.auth_binding orelse return error.MissingField;
    const issued_at = fields.issued_at orelse return error.MissingField;
    const lifetime_seconds = fields.lifetime_seconds orelse return error.MissingField;
    const early_data = fields.early_data orelse return error.MissingField;

    return ResumableSessionCommon.init(.{
        .cipher_suite = cipher_suite,
        .resumption_psk = psk,
        .sni = sni,
        .alpn = alpn,
        .auth_binding = .{ .bytes = auth_binding_bytes },
        .issued_at = issued_at,
        .lifetime_seconds = lifetime_seconds,
        .early_data = early_data,
        .transport_compat = fields.transport_compat,
        .application_compat = fields.application_compat,
    }) catch |err| switch (err) {
        error.InvalidDnsName => return error.InvalidSni,
        error.AlpnProtocolTooLarge => return error.FieldTooLarge,
        error.InvalidPskLength => return error.InvalidPskLength,
        error.InvalidEarlyDataPolicy => return error.InvalidEarlyDataPolicy,
    };
}

fn decodeClient(allocator: std.mem.Allocator, bytes: []const u8) DecodeError!ClientTicketState {
    var common_fields = CommonFields{};
    var ticket: ?[]const u8 = null;
    var ticket_age_add: ?u32 = null;
    var ticket_nonce: ?[]const u8 = null;
    var received_at: ?u64 = null;

    var offset: usize = 0;
    while (try nextTlv(bytes, &offset)) |tlv| {
        if (try parseSharedField(&common_fields, tlv.field_id, tlv.value)) continue;
        switch (tlv.field_id) {
            field_ticket => {
                if (ticket != null) return error.DuplicateField;
                if (tlv.value.len == 0 or tlv.value.len > max_ticket_len) return error.FieldTooLarge;
                ticket = tlv.value;
            },
            field_ticket_age_add => {
                if (ticket_age_add != null) return error.DuplicateField;
                if (tlv.value.len != 4) return error.MalformedLength;
                ticket_age_add = std.mem.readInt(u32, tlv.value[0..4], .big);
            },
            field_ticket_nonce => {
                if (ticket_nonce != null) return error.DuplicateField;
                if (tlv.value.len > max_ticket_nonce_len) return error.FieldTooLarge;
                ticket_nonce = tlv.value;
            },
            field_received_at => {
                if (received_at != null) return error.DuplicateField;
                if (tlv.value.len != 8) return error.MalformedLength;
                received_at = std.mem.readInt(u64, tlv.value[0..8], .big);
            },
            else => {
                if (tlv.field_id & optional_field_mask != 0) continue;
                return error.UnknownCriticalField;
            },
        }
    }

    var common = try buildCommon(common_fields);
    errdefer common.deinit();

    return ClientTicketState.init(allocator, .{
        .common = common,
        .ticket = ticket orelse return error.MissingField,
        .ticket_age_add = ticket_age_add orelse return error.MissingField,
        .ticket_nonce = ticket_nonce orelse return error.MissingField,
        .received_at = received_at orelse return error.MissingField,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.TicketTooLarge => return error.FieldTooLarge,
        error.NonceTooLarge => return error.FieldTooLarge,
    };
}

fn decodeServer(bytes: []const u8) DecodeError!ServerRecoverableState {
    var common_fields = CommonFields{};

    var offset: usize = 0;
    while (try nextTlv(bytes, &offset)) |tlv| {
        if (try parseSharedField(&common_fields, tlv.field_id, tlv.value)) continue;
        if (tlv.field_id & optional_field_mask != 0) continue;
        return error.UnknownCriticalField;
    }

    const common = try buildCommon(common_fields);
    return ServerRecoverableState.init(common);
}

/// Decode a versioned internal-state record. `bytes` must be exactly one
/// encoded record with no leading/trailing framing; returns a completely
/// owned value on success, or an error after fully clearing any partial
/// secret state.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) DecodeError!DecodedRecord {
    if (bytes.len > max_encoded_state_len) return error.StateTooLarge;
    if (bytes.len < 2) return error.Truncated;
    if (bytes[0] != format_version) return error.UnsupportedVersion;
    const record_type = std.enums.fromInt(RecordType, bytes[1]) orelse return error.UnknownRecordType;
    return switch (record_type) {
        .client => .{ .client = try decodeClient(allocator, bytes[2..]) },
        .server => .{ .server = try decodeServer(bytes[2..]) },
    };
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

const testing = std.testing;

fn sampleCommon(alloc_psk: []const u8) !ResumableSessionCommon {
    return ResumableSessionCommon.init(.{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = alloc_psk,
        .sni = "Example.TEST",
        .alpn = "h3",
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf-der-bytes"),
        .issued_at = 1_000,
        .lifetime_seconds = 3_600,
        .early_data = .resume_only,
    });
}

fn sampleClient(allocator: std.mem.Allocator) !ClientTicketState {
    const common = try sampleCommon(&([_]u8{0xab} ** 32));
    return ClientTicketState.init(allocator, .{
        .common = common,
        .ticket = "opaque-ticket-bytes",
        .ticket_age_add = 12345,
        .ticket_nonce = "nonce",
        .received_at = 1_500,
    });
}

test "SHA-256 and SHA-384 suites require matching PSK length" {
    var sha256_psk = [_]u8{0x11} ** 32;
    var common256 = try ResumableSessionCommon.init(.{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &sha256_psk,
        .sni = "sha256.test",
        .alpn = "h2",
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf"),
        .issued_at = 0,
        .lifetime_seconds = 100,
    });
    defer common256.deinit();
    try testing.expectEqual(@as(usize, 32), common256.resumption_psk.slice().len);

    var sha384_psk = [_]u8{0x22} ** 48;
    var common384 = try ResumableSessionCommon.init(.{
        .cipher_suite = .tls_aes_256_gcm_sha384,
        .resumption_psk = &sha384_psk,
        .sni = "sha384.test",
        .alpn = "h2",
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf"),
        .issued_at = 0,
        .lifetime_seconds = 100,
    });
    defer common384.deinit();
    try testing.expectEqual(@as(usize, 48), common384.resumption_psk.slice().len);

    try testing.expectError(error.InvalidPskLength, ResumableSessionCommon.init(.{
        .cipher_suite = .tls_aes_256_gcm_sha384,
        .resumption_psk = &sha256_psk,
        .sni = "mismatch.test",
        .alpn = "h2",
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf"),
        .issued_at = 0,
        .lifetime_seconds = 100,
    }));
}

test "SNI is canonicalized to ASCII-lowercase and compares case-insensitively" {
    var common = try sampleCommon(&([_]u8{0xab} ** 32));
    defer common.deinit();

    try testing.expectEqualStrings("example.test", common.sni.slice());
    try testing.expect(common.sni.eqlIgnoreCase("EXAMPLE.test"));
    try testing.expect(!common.sni.eqlIgnoreCase("other.test"));
}

test "expiry boundaries are exact and overflow-safe" {
    var common = try sampleCommon(&([_]u8{0xab} ** 32));
    defer common.deinit();
    common.issued_at = 1_000;
    common.lifetime_seconds = 100;

    try testing.expect(!common.isExpired(1_099));
    try testing.expect(common.isExpired(1_100));
    try testing.expect(!common.isNotYetValid(1_000));
    try testing.expect(common.isNotYetValid(999));

    // issued_at + lifetime_seconds overflows u64; the saturating computation
    // must neither panic nor wrap, and must treat the (saturated) expiry as
    // reachable only once `now` itself reaches the maximum representable
    // timestamp.
    common.issued_at = std.math.maxInt(u64) - 10;
    common.lifetime_seconds = 100;
    try testing.expect(!common.isExpired(std.math.maxInt(u64) - 1));
    try testing.expect(common.isExpired(std.math.maxInt(u64)));
}

test "compatibility distinguishes each mismatch reason" {
    var common = try sampleCommon(&([_]u8{0xab} ** 32));
    defer common.deinit();
    common.transport_compat = try CompatSnapshot.init(1, 1, "quic-params");
    common.application_compat = try CompatSnapshot.init(2, 1, "h3-settings");

    const base = CandidateContext{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .sni = "example.test",
        .alpn = "h3",
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf-der-bytes"),
        .transport_compat = try CompatSnapshot.init(1, 1, "quic-params"),
        .application_compat = try CompatSnapshot.init(2, 1, "h3-settings"),
    };

    try testing.expectEqual(ResumeEligibility.eligible, evaluateCompatibility(&common, base, 1_000).resumption);

    var expired_check = base;
    try testing.expectEqual(ResumeMismatch.expired, evaluateCompatibility(&common, expired_check, 10_000).resumption.rejected);

    try testing.expectEqual(ResumeMismatch.not_yet_valid, evaluateCompatibility(&common, base, 0).resumption.rejected);

    var cipher_mismatch = base;
    cipher_mismatch.cipher_suite = .tls_aes_256_gcm_sha384;
    try testing.expectEqual(ResumeMismatch.cipher_suite_mismatch, evaluateCompatibility(&common, cipher_mismatch, 1_000).resumption.rejected);

    var sni_mismatch = base;
    sni_mismatch.sni = "other.test";
    try testing.expectEqual(ResumeMismatch.sni_mismatch, evaluateCompatibility(&common, sni_mismatch, 1_000).resumption.rejected);

    var alpn_mismatch = base;
    alpn_mismatch.alpn = "h2";
    try testing.expectEqual(ResumeMismatch.alpn_mismatch, evaluateCompatibility(&common, alpn_mismatch, 1_000).resumption.rejected);

    var auth_mismatch = base;
    auth_mismatch.auth_binding = AuthBinding.fromLeafCertificateDer("different-leaf");
    try testing.expectEqual(ResumeMismatch.auth_binding_mismatch, evaluateCompatibility(&common, auth_mismatch, 1_000).resumption.rejected);

    var transport_mismatch = base;
    transport_mismatch.transport_compat = try CompatSnapshot.init(1, 2, "quic-params");
    try testing.expectEqual(ResumeMismatch.transport_mismatch, evaluateCompatibility(&common, transport_mismatch, 1_000).resumption.rejected);

    var application_mismatch = base;
    application_mismatch.application_compat = null;
    try testing.expectEqual(ResumeMismatch.application_mismatch, evaluateCompatibility(&common, application_mismatch, 1_000).resumption.rejected);

    _ = &expired_check;
}

test "resumption may succeed while early data remains disabled" {
    var common = try sampleCommon(&([_]u8{0xab} ** 32));
    defer common.deinit();
    // common.early_data defaults to .resume_only

    const candidate = CandidateContext{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .sni = "example.test",
        .alpn = "h3",
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf-der-bytes"),
        .want_early_data = true,
    };

    const decision = evaluateCompatibility(&common, candidate, 1_000);
    try testing.expectEqual(ResumeEligibility.eligible, decision.resumption);
    try testing.expectEqual(EarlyDataEligibility.disabled, decision.early_data);
}

test "early data is allowed only when the session is resumable and policy permits it" {
    var common = try sampleCommon(&([_]u8{0xab} ** 32));
    defer common.deinit();
    common.early_data = .{ .early_data_capable = 16384 };

    const good_candidate = CandidateContext{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .sni = "example.test",
        .alpn = "h3",
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf-der-bytes"),
        .want_early_data = true,
    };
    const good_decision = evaluateCompatibility(&common, good_candidate, 1_000);
    try testing.expectEqual(ResumeEligibility.eligible, good_decision.resumption);
    try testing.expectEqual(@as(u32, 16384), good_decision.early_data.allowed);

    var bad_candidate = good_candidate;
    bad_candidate.sni = "other.test";
    const bad_decision = evaluateCompatibility(&common, bad_candidate, 1_000);
    try testing.expectEqual(ResumeMismatch.sni_mismatch, bad_decision.resumption.rejected);
    try testing.expectEqual(EarlyDataEligibility.incompatible, bad_decision.early_data);
}

test "invalid early data policy is rejected" {
    try testing.expectError(error.InvalidEarlyDataPolicy, ResumableSessionCommon.init(.{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &([_]u8{0} ** 32),
        .sni = "zero.test",
        .alpn = "h2",
        .auth_binding = AuthBinding.fromLeafCertificateDer("leaf"),
        .issued_at = 0,
        .lifetime_seconds = 100,
        .early_data = .{ .early_data_capable = 0 },
    }));
}

test "client and server internal state round-trips deterministically" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    var buf: [max_encoded_state_len]u8 = undefined;
    const encoded_len = clientEncodedLen(&client);
    const encoded = try encodeClient(&client, &buf);
    try testing.expectEqual(encoded_len, encoded.len);

    var decoded = try decode(testing.allocator, encoded);
    defer decoded.deinit();
    try testing.expect(decoded == .client);
    try testing.expectEqual(client.common.cipher_suite, decoded.client.common.cipher_suite);
    try testing.expectEqualStrings(client.common.sni.slice(), decoded.client.common.sni.slice());
    try testing.expectEqualStrings(client.common.alpn.slice(), decoded.client.common.alpn.slice());
    try testing.expect(client.common.resumption_psk.eql(&decoded.client.common.resumption_psk));
    try testing.expectEqualStrings(client.ticket.slice(), decoded.client.ticket.slice());
    try testing.expectEqual(client.ticket_age_add, decoded.client.ticket_age_add);
    try testing.expectEqualStrings(client.ticket_nonce.slice(), decoded.client.ticket_nonce.slice());
    try testing.expectEqual(client.received_at, decoded.client.received_at);

    // Re-encoding the decoded value must reproduce the exact same bytes
    // (canonical field order is deterministic regardless of decode path).
    var buf2: [max_encoded_state_len]u8 = undefined;
    const re_encoded = try encodeClient(&decoded.client, &buf2);
    try testing.expectEqualSlices(u8, encoded, re_encoded);

    var server = ServerRecoverableState.init(try sampleCommon(&([_]u8{0xcd} ** 32)));
    defer server.deinit();

    var server_buf: [max_encoded_state_len]u8 = undefined;
    const server_encoded = try encodeServer(&server, &server_buf);
    try testing.expectEqual(serverEncodedLen(&server), server_encoded.len);

    var decoded_server = try decode(testing.allocator, server_encoded);
    defer decoded_server.deinit();
    try testing.expect(decoded_server == .server);
    try testing.expectEqualStrings(server.common.sni.slice(), decoded_server.server.common.sni.slice());
}

test "decode is order-independent across shuffled fields" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    var buf: [max_encoded_state_len]u8 = undefined;
    const encoded = try encodeClient(&client, &buf);

    // Parse the canonical TLVs, then re-emit them in reverse order.
    var tlvs = std.ArrayList(Tlv).empty;
    defer tlvs.deinit(testing.allocator);
    var offset: usize = 2;
    while (try nextTlv(encoded, &offset)) |tlv| {
        try tlvs.append(testing.allocator, tlv);
    }
    std.mem.reverse(Tlv, tlvs.items);

    var shuffled: [max_encoded_state_len]u8 = undefined;
    shuffled[0] = format_version;
    shuffled[1] = @intFromEnum(RecordType.client);
    var pos: usize = 2;
    for (tlvs.items) |tlv| {
        try writeTlv(&shuffled, &pos, tlv.field_id, tlv.value);
    }

    var decoded = try decode(testing.allocator, shuffled[0..pos]);
    defer decoded.deinit();
    try testing.expect(decoded == .client);
    try testing.expectEqualStrings(client.ticket.slice(), decoded.client.ticket.slice());
}

test "unknown optional fields are skipped, unknown critical fields are rejected" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    var buf: [max_encoded_state_len]u8 = undefined;
    const encoded = try encodeClient(&client, &buf);

    var with_optional: [max_encoded_state_len]u8 = undefined;
    @memcpy(with_optional[0..encoded.len], encoded);
    var pos: usize = encoded.len;
    try writeTlv(&with_optional, &pos, 0x9abc, "future-extension-data");

    var decoded = try decode(testing.allocator, with_optional[0..pos]);
    defer decoded.deinit();
    try testing.expect(decoded == .client);

    var with_critical: [max_encoded_state_len]u8 = undefined;
    @memcpy(with_critical[0..encoded.len], encoded);
    var pos2: usize = encoded.len;
    try writeTlv(&with_critical, &pos2, 0x00ff, "unrecognized-critical-data");

    try testing.expectError(error.UnknownCriticalField, decode(testing.allocator, with_critical[0..pos2]));
}

test "decode rejects unsupported major versions" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    var buf: [max_encoded_state_len]u8 = undefined;
    const encoded = try encodeClient(&client, &buf);

    var mutated: [max_encoded_state_len]u8 = undefined;
    @memcpy(mutated[0..encoded.len], encoded);
    mutated[0] = 2;

    try testing.expectError(error.UnsupportedVersion, decode(testing.allocator, mutated[0..encoded.len]));
}

test "decode rejects unknown record types" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    var buf: [max_encoded_state_len]u8 = undefined;
    const encoded = try encodeClient(&client, &buf);

    var mutated: [max_encoded_state_len]u8 = undefined;
    @memcpy(mutated[0..encoded.len], encoded);
    mutated[1] = 99;

    try testing.expectError(error.UnknownRecordType, decode(testing.allocator, mutated[0..encoded.len]));
}

test "decode rejects duplicate fields" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    var buf: [max_encoded_state_len]u8 = undefined;
    const encoded = try encodeClient(&client, &buf);

    var duplicated: [max_encoded_state_len]u8 = undefined;
    @memcpy(duplicated[0..encoded.len], encoded);
    var pos: usize = encoded.len;
    try writeTlv(&duplicated, &pos, field_sni, "duplicate.test");

    try testing.expectError(error.DuplicateField, decode(testing.allocator, duplicated[0..pos]));
}

test "decode rejects malformed fixed-width field lengths" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    var buf: [max_encoded_state_len]u8 = undefined;
    const encoded = try encodeClient(&client, &buf);

    // The cipher_suite TLV is the first field written: id(2) + len(2) + value(2).
    var mutated: [max_encoded_state_len]u8 = undefined;
    @memcpy(mutated[0..encoded.len], encoded);
    // Shrink the declared length of the cipher_suite field from 2 to 1.
    std.mem.writeInt(u16, mutated[2 + 2 ..][0..2], 1, .big);

    try testing.expectError(error.MalformedLength, decode(testing.allocator, mutated[0 .. encoded.len - 1]));
}

test "decode rejects every truncation prefix" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    var buf: [max_encoded_state_len]u8 = undefined;
    const encoded = try encodeClient(&client, &buf);

    var i: usize = 0;
    while (i < encoded.len) : (i += 1) {
        if (decode(testing.allocator, encoded[0..i])) |*decoded| {
            var mutable_decoded = decoded.*;
            mutable_decoded.deinit();
            try testing.expect(false); // a truncated prefix must never decode successfully
        } else |_| {}
    }
}

test "decode rejects trailing bytes that do not form a valid field" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    var buf: [max_encoded_state_len]u8 = undefined;
    const encoded = try encodeClient(&client, &buf);

    var with_stray_byte: [max_encoded_state_len]u8 = undefined;
    @memcpy(with_stray_byte[0..encoded.len], encoded);
    with_stray_byte[encoded.len] = 0xff;

    try testing.expectError(error.Truncated, decode(testing.allocator, with_stray_byte[0 .. encoded.len + 1]));
}

test "decode rejects state larger than the configured bound" {
    var oversized: [max_encoded_state_len + 1]u8 = [_]u8{0} ** (max_encoded_state_len + 1);
    try testing.expectError(error.StateTooLarge, decode(testing.allocator, &oversized));
}

test "constructing a ticket larger than the maximum is rejected" {
    var common = try sampleCommon(&([_]u8{0xab} ** 32));
    errdefer common.deinit();

    var oversized_ticket: [max_ticket_len + 1]u8 = undefined;
    @memset(&oversized_ticket, 0x42);

    try testing.expectError(error.TicketTooLarge, ClientTicketState.init(testing.allocator, .{
        .common = common,
        .ticket = &oversized_ticket,
        .ticket_age_add = 0,
        .ticket_nonce = "",
        .received_at = 0,
    }));
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
    var buf: [max_encoded_state_len]u8 = undefined;
    const encoded = try encodeClient(&seed, &buf);

    try testing.checkAllAllocationFailures(testing.allocator, struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var decoded = try decode(allocator, bytes);
            decoded.deinit();
        }
    }.run, .{encoded});
}

test "clone produces an independent deep copy" {
    var client = try sampleClient(testing.allocator);
    defer client.deinit();

    var cloned = try client.clone(testing.allocator);
    defer cloned.deinit();

    try testing.expectEqualStrings(client.ticket.slice(), cloned.ticket.slice());
    try testing.expect(client.ticket.bytes.ptr != cloned.ticket.bytes.ptr);

    var server = ServerRecoverableState.init(try sampleCommon(&([_]u8{0xef} ** 32)));
    defer server.deinit();
    var cloned_server = server.clone();
    defer cloned_server.deinit();
    try testing.expectEqualStrings(server.common.sni.slice(), cloned_server.common.sni.slice());
}

test "secret-bearing types expose no ordinary formatting path" {
    try testing.expect(@hasDecl(ResumableSessionCommon, "format"));
    try testing.expect(@hasDecl(ClientTicketState, "format"));
    try testing.expect(@hasDecl(ServerRecoverableState, "format"));
}
