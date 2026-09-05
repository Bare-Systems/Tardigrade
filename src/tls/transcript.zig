//! TLS 1.3 transcript hash helper.
//!
//! The transcript is transport-neutral and hash-agile: it supports SHA-256
//! and SHA-384 (the two transcript/HKDF hashes `algorithms.transcriptHash`
//! maps the negotiated cipher suites to — #564), selected once per
//! connection via `selectFamily`. Callers update it with exact handshake
//! message bytes as emitted by `messages.HandshakeMessage.raw`.
//!
//! ## Why selection is deferred
//!
//! The negotiated cipher suite — and therefore the transcript's hash family
//! — is not known when the very first transcript-affecting bytes arrive:
//!
//!   - The server learns the suite while parsing ClientHello, but `Core`
//!     (`handshake.zig`) already feeds ClientHello's raw bytes to the
//!     transcript before that parse ever runs.
//!   - The client sends its own ClientHello before it knows anything the
//!     server will pick, and then `Core` feeds the ServerHello/
//!     HelloRetryRequest's raw bytes to the transcript (and, for an HRR,
//!     rebinds ClientHello1 into `message_hash` form) *before* the backend
//!     has parsed that message's `cipher_suite` field out of its body.
//!
//! So `update`/`rebindClientHello` transparently buffer bytes (and record a
//! rebind boundary) until `selectFamily` runs, then replay them into the
//! real hash in order — no ClientHello bytes are lost and no message is
//! ever hashed under the wrong family. Once a family is selected every
//! subsequent `update`/`rebindClientHello` call hashes live; `selectFamily`
//! itself becomes a no-op (the negotiated suite is authoritative and is not
//! re-derived here — callers must not call it with a different hash for the
//! same connection).
//!
//! ## Bounding the pre-selection buffer
//!
//! `max_pending_len` holds exactly one framed handshake message, not two:
//! a well-behaved peer only ever requires buffering ClientHello1 (the
//! server resolves the family from it synchronously, before any other
//! message is processed) or, on the client, a single incoming ServerHello/
//! HelloRetryRequest (the transport layer resolves the family from that
//! message's own `cipher_suite` field before handing it to `update`/
//! `rebindClientHello` at all — see `tls13_backend.zig`'s `drainInput`).
//! Buffering more than one message's worth before a family is ever selected
//! is a caller bug (or a peer so malformed the connection was going to fail
//! closed anyway), and `update` reports it as `error.TranscriptOverflow`
//! rather than overrunning `pending` — this type never panics on
//! attacker-controlled input.

const std = @import("std");
const provider = @import("crypto").provider;
const messages = @import("messages.zig");

pub const Hash = provider.Hash;
/// Largest digest this transcript can hold (SHA-384 = 48 bytes).
pub const max_digest_len = provider.max_digest_len;

/// One framed handshake message's worth of pre-selection buffering — see
/// "Bounding the pre-selection buffer" above. Exactly
/// `tls13_backend.max_message_len` (#646: 16 KiB) plus its 4-byte handshake
/// header — the same bound the reassembler already admits a single
/// handshake message up to, so a legitimate ClientHello the engine accepts
/// can never itself overflow this buffer before its suite is known.
///
/// This module cannot import `tls13_backend.zig` to reference that constant
/// directly (that module already imports this one), so the value is
/// duplicated here as a literal; `tls13_backend.zig` asserts at comptime
/// that the two stay in sync, so a future change to one without the other
/// fails the build rather than silently reopening a size bug.
pub const max_pending_len: usize = 16 * 1024 + 4;

pub const Error = error{TranscriptOverflow};

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;

/// A transcript digest: `bytes[0..len]` is the hash under whatever family
/// was selected (or active at capture time); `bytes[len..]` is always zero,
/// never uninitialized — so a caller that mistakenly reads past `len` sees
/// deterministic zero bytes, not stack garbage.
pub const Digest = struct {
    bytes: [max_digest_len]u8 = [_]u8{0} ** max_digest_len,
    len: usize = 0,

    pub fn slice(self: *const Digest) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn eql(self: *const Digest, other: *const Digest) bool {
        return self.len == other.len and std.mem.eql(u8, self.slice(), other.slice());
    }
};

const HashState = union(Hash) {
    sha256: Sha256,
    sha384: Sha384,

    fn init(hash: Hash) HashState {
        return switch (hash) {
            .sha256 => .{ .sha256 = Sha256.init(.{}) },
            .sha384 => .{ .sha384 = Sha384.init(.{}) },
        };
    }

    fn update(self: *HashState, bytes: []const u8) void {
        switch (self.*) {
            inline else => |*h| h.update(bytes),
        }
    }

    fn digest(self: *const HashState) Digest {
        var copy = self.*;
        var out = Digest{};
        switch (copy) {
            inline else => |*h| {
                const n = @TypeOf(h.*).digest_length;
                out.len = n;
                h.final(out.bytes[0..n]);
            },
        }
        return out;
    }

    fn family(self: HashState) Hash {
        return std.meta.activeTag(self);
    }
};

pub const Transcript = struct {
    /// Bytes already hashed into `state`, when a family has been selected;
    /// otherwise unused (everything so far lives in `pending`).
    state: ?HashState = null,
    pending: [max_pending_len]u8 = undefined,
    pending_len: usize = 0,
    /// Set by a `rebindClientHello` that ran before a family was selected:
    /// the offset in `pending` where the HRR `message_hash` synthetic
    /// message must be substituted for everything before it. At most one
    /// HRR may occur per connection (RFC 8446), and only the client can
    /// ever reach a rebind before its own suite is known, so a single
    /// optional offset is sufficient — never a list.
    rebind_at: ?usize = null,

    /// Commit this transcript to `hash`, the negotiated cipher suite's
    /// transcript/HKDF hash (`algorithms.transcriptHash`). Replays any
    /// buffered bytes (and rebind boundary) into a real hash of that
    /// family. A no-op once a family is already active — the negotiated
    /// suite is selected exactly once per connection and every call after
    /// the first is expected to name the same hash.
    pub fn selectFamily(self: *Transcript, hash: Hash) void {
        if (self.state != null) return;
        var h = HashState.init(hash);
        if (self.rebind_at) |at| {
            var pre = HashState.init(hash);
            pre.update(self.pending[0..at]);
            const pre_digest = pre.digest();
            var synthetic: [4 + max_digest_len]u8 = undefined;
            synthetic[0] = @intFromEnum(messages.MessageType.message_hash);
            std.mem.writeInt(u24, synthetic[1..4], @intCast(pre_digest.len), .big);
            @memcpy(synthetic[4..][0..pre_digest.len], pre_digest.slice());
            h.update(synthetic[0 .. 4 + pre_digest.len]);
            h.update(self.pending[at..self.pending_len]);
        } else {
            h.update(self.pending[0..self.pending_len]);
        }
        self.state = h;
        std.crypto.secureZero(u8, self.pending[0..self.pending_len]);
        self.pending_len = 0;
        self.rebind_at = null;
    }

    /// The negotiated hash family, once selected.
    pub fn family(self: *const Transcript) ?Hash {
        if (self.state) |s| return s.family();
        return null;
    }

    pub fn update(self: *Transcript, bytes: []const u8) Error!void {
        if (self.state) |*s| {
            s.update(bytes);
            return;
        }
        // Buffering: the family is not known yet — see "Bounding the
        // pre-selection buffer" above. A caller on attacker-reachable input
        // must be able to fail the connection here rather than crash.
        if (self.pending_len + bytes.len > self.pending.len) return error.TranscriptOverflow;
        @memcpy(self.pending[self.pending_len..][0..bytes.len], bytes);
        self.pending_len += bytes.len;
    }

    pub fn peek(self: *const Transcript) Digest {
        if (self.state) |s| return s.digest();
        return .{};
    }

    pub fn peekWith(self: *const Transcript, bytes: []const u8) Digest {
        if (self.state) |s| {
            var copy = s;
            copy.update(bytes);
            return copy.digest();
        }
        return .{};
    }

    /// RFC 8446 §4.4.1: replace the transcript-so-far with the synthetic
    /// `message_hash(Hash(ClientHello1))` message ahead of a
    /// HelloRetryRequest. When the hash family is already known this hashes
    /// immediately, exactly as before; when it is not yet known (the
    /// client's own HRR-shaped ServerHello, received before its body has
    /// been parsed) this only records where the rebind boundary falls in
    /// the pending buffer — `selectFamily` performs the actual rebind once
    /// the family is learned, still over exactly the same bytes.
    pub fn rebindClientHello(self: *Transcript) void {
        if (self.state != null) {
            self.replace(self.peek());
            return;
        }
        std.debug.assert(self.rebind_at == null);
        self.rebind_at = self.pending_len;
    }

    pub fn replace(self: *Transcript, digest: Digest) void {
        std.debug.assert(self.state != null);
        var synthetic: [4 + max_digest_len]u8 = undefined;
        synthetic[0] = @intFromEnum(messages.MessageType.message_hash);
        std.mem.writeInt(u24, synthetic[1..4], @intCast(digest.len), .big);
        @memcpy(synthetic[4..][0..digest.len], digest.slice());

        const hash = self.state.?.family();
        self.state = HashState.init(hash);
        self.state.?.update(synthetic[0 .. 4 + digest.len]);
    }
};

const testing = std.testing;

test "transcript hash matches direct SHA-256 and supports HRR-style replacement" {
    var transcript = Transcript{};
    transcript.selectFamily(.sha256);
    try transcript.update("client hello");

    var expected: [Sha256.digest_length]u8 = undefined;
    Sha256.hash("client hello", &expected, .{});
    try testing.expectEqualSlices(u8, &expected, transcript.peek().slice());

    transcript.replace(transcript.peek());
    var rebound_expected: [Sha256.digest_length]u8 = undefined;
    const synthetic = [_]u8{ 254, 0, 0, Sha256.digest_length } ++ expected;
    Sha256.hash(&synthetic, &rebound_expected, .{});
    try testing.expectEqualSlices(u8, &rebound_expected, transcript.peek().slice());
}

test "transcript hash matches direct SHA-384" {
    var transcript = Transcript{};
    transcript.selectFamily(.sha384);
    try transcript.update("client hello");

    var expected: [Sha384.digest_length]u8 = undefined;
    Sha384.hash("client hello", &expected, .{});
    const digest = transcript.peek();
    try testing.expectEqual(@as(usize, Sha384.digest_length), digest.len);
    try testing.expectEqualSlices(u8, &expected, digest.slice());
}

test "peekWith does not mutate transcript state" {
    var transcript = Transcript{};
    transcript.selectFamily(.sha256);
    try transcript.update("client hello");
    const before = transcript.peek();

    var expected = Sha256.init(.{});
    expected.update("client hello");
    expected.update("hello retry request");
    var expected_digest: [Sha256.digest_length]u8 = undefined;
    expected.final(&expected_digest);

    try testing.expectEqualSlices(u8, &expected_digest, transcript.peekWith("hello retry request").slice());
    try testing.expectEqualSlices(u8, before.slice(), transcript.peek().slice());
}

test "rebindClientHello produces deterministic HRR transcript fixture when the family is already known" {
    const client_hello_1 = [_]u8{ 1, 0, 0, 3, 0x01, 0x02, 0x03 };
    const hello_retry_request = [_]u8{ 2, 0, 0, 2, 0x04, 0x05 };
    const client_hello_2 = [_]u8{ 1, 0, 0, 4, 0x06, 0x07, 0x08, 0x09 };

    var transcript = Transcript{};
    transcript.selectFamily(.sha256);
    try transcript.update(&client_hello_1);
    transcript.rebindClientHello();
    try transcript.update(&hello_retry_request);
    try transcript.update(&client_hello_2);

    var independent_ch1_hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&client_hello_1, &independent_ch1_hash, .{});

    var synthetic: [4 + Sha256.digest_length]u8 = undefined;
    synthetic[0] = @intFromEnum(messages.MessageType.message_hash);
    std.mem.writeInt(u24, synthetic[1..4], Sha256.digest_length, .big);
    @memcpy(synthetic[4..], &independent_ch1_hash);

    var direct = Sha256.init(.{});
    direct.update(&synthetic);
    direct.update(&hello_retry_request);
    direct.update(&client_hello_2);
    var expected: [Sha256.digest_length]u8 = undefined;
    direct.final(&expected);

    try testing.expectEqualSlices(u8, &expected, transcript.peek().slice());
}

test "rebindClientHello buffers the rebind boundary until selectFamily runs, matching the live-family path byte for byte" {
    const client_hello_1 = [_]u8{ 1, 0, 0, 3, 0x01, 0x02, 0x03 };
    const hello_retry_request = [_]u8{ 2, 0, 0, 2, 0x04, 0x05 };
    const client_hello_2 = [_]u8{ 1, 0, 0, 4, 0x06, 0x07, 0x08, 0x09 };

    // Deferred: the family is only learned after both ClientHello1 and the
    // HelloRetryRequest have already been fed to the transcript — exactly
    // the client-role ordering `drainInput`/`Core.acceptHelloRetryRequest`
    // impose in the real engine.
    var deferred = Transcript{};
    try deferred.update(&client_hello_1);
    deferred.rebindClientHello();
    try deferred.update(&hello_retry_request);
    try testing.expectEqual(@as(?Hash, null), deferred.family());
    deferred.selectFamily(.sha384);
    try deferred.update(&client_hello_2);

    // Live: the family is selected up front, so every call hashes
    // immediately — the baseline this deferred path must reproduce.
    var live = Transcript{};
    live.selectFamily(.sha384);
    try live.update(&client_hello_1);
    live.rebindClientHello();
    try live.update(&hello_retry_request);
    try live.update(&client_hello_2);

    try testing.expect(deferred.peek().eql(&live.peek()));
    try testing.expectEqual(@as(usize, Sha384.digest_length), deferred.peek().len);
}

test "selectFamily keeps the first active family when a later call names the other hash" {
    // Found 2026-09-01 by the #675 campaign (t1-01, test-tls-protocol-fuzz
    // --fuzz=10M): pins the documented sticky-selection contract — the first
    // selected family remains authoritative and a later call naming a
    // different hash neither rebinds the family nor perturbs the digest.
    var transcript = Transcript{};
    transcript.selectFamily(.sha384);
    try transcript.update("client hello");
    const before = transcript.peek();

    transcript.selectFamily(.sha256);
    try testing.expectEqual(@as(?Hash, .sha384), transcript.family());
    try testing.expect(before.eql(&transcript.peek()));
    try testing.expectEqual(@as(usize, Sha384.digest_length), transcript.peek().len);
}

test "selectFamily is idempotent once a family is active" {
    var transcript = Transcript{};
    transcript.selectFamily(.sha256);
    try transcript.update("client hello");
    const before = transcript.peek();

    // A later call (e.g. the final ServerHello after an HRR already
    // selected the family) must not reset or re-hash anything.
    transcript.selectFamily(.sha256);
    try testing.expect(before.eql(&transcript.peek()));
}

test "an unselected transcript reports no family and a zero-length digest with a zeroed tail" {
    const transcript = Transcript{};
    try testing.expectEqual(@as(?Hash, null), transcript.family());
    const digest = transcript.peek();
    try testing.expectEqual(@as(usize, 0), digest.len);
    for (digest.bytes) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "fuzz: TLS protocol: transcript update select and HRR rebind sequences are bounded and deterministic" {
    try testing.fuzz({}, fuzzTranscriptSequences, .{
        .corpus = &.{
            "",
            &[_]u8{ 0, 1, 2, 3, 4 },
            &[_]u8{ 2, 0, 0, 1, 0xaa },
            &([_]u8{0xff} ** 128),
            // Found 2026-09-01, zig build test-tls-protocol-fuzz
            // -Doptimize=ReleaseFast --fuzz=10M (#675 campaign row t1-01):
            // selectFamily on an already-active transcript must keep the first
            // family; the fuzz model previously expected it to adopt the new
            // one. Minimized from the original 528-byte discovery input
            // (was 781e24d2...) to 166 bytes via delta-debugging against the
            // pre-fix model, preserving the exact "expected .sha256, found
            // .sha384" failure.
            @embedFile("vectors/fuzz/transcript/5f01f33d7fdcab9119a62339ac496951e958ba24d7c3a77f3093ba7e8fb66951.bin"),
        },
    });
}

fn fuzzTranscriptSequences(_: void, smith: *testing.Smith) !void {
    var transcript = Transcript{};
    var mirrored = Transcript{};
    var saw_deferred_rebind = false;

    var chunk_storage: [96]u8 = undefined;
    for (0..32) |_| {
        switch (smith.index(5)) {
            0 => {
                const len = smith.index(chunk_storage.len + 1);
                smith.bytes(chunk_storage[0..len]);
                const before_pending_len = transcript.pending_len;
                const update_result = transcript.update(chunk_storage[0..len]);
                const mirror_result = mirrored.update(chunk_storage[0..len]);
                if (update_result) |_| {
                    try mirror_result;
                } else |err| {
                    try testing.expectEqual(error.TranscriptOverflow, err);
                    try testing.expectError(error.TranscriptOverflow, mirror_result);
                    try testing.expectEqual(before_pending_len, transcript.pending_len);
                }
            },
            1 => {
                const family: Hash = if (smith.index(2) == 0) .sha256 else .sha384;
                const active = transcript.family();
                transcript.selectFamily(family);
                mirrored.selectFamily(family);
                // selectFamily is a no-op once a family is active, so the
                // first selected family stays authoritative — a later call
                // naming the other family must not rebind it.
                try testing.expectEqual(active orelse family, transcript.family().?);
                try testing.expect(transcript.peek().eql(&mirrored.peek()));
            },
            2 => {
                if (transcript.family() != null or !saw_deferred_rebind) {
                    transcript.rebindClientHello();
                    mirrored.rebindClientHello();
                    if (transcript.family() == null) saw_deferred_rebind = true;
                    try testing.expect(transcript.peek().eql(&mirrored.peek()));
                }
            },
            3 => {
                const len = smith.index(chunk_storage.len + 1);
                smith.bytes(chunk_storage[0..len]);
                const before = transcript.peek();
                _ = transcript.peekWith(chunk_storage[0..len]);
                try testing.expect(before.eql(&transcript.peek()));
            },
            else => {
                if (transcript.family()) |family| {
                    const before = transcript.peek();
                    transcript.selectFamily(if (family == .sha256) .sha384 else .sha256);
                    try testing.expect(before.eql(&transcript.peek()));
                }
            },
        }
    }
}
