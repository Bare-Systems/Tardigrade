//! Bounded, crash-safe disk tier for the generic `proxy_pass` response cache
//! (#903, extending #901/#902's in-memory-only `gateway_proxy_cache.zig`).
//!
//! Every entry is one file, named by the already-collision-resistant SHA-256
//! hex cache key (`gateway_proxy_cache.buildCacheKey`/`buildVaryVariantKey`)
//! directly -- no separate hashing/sharding layer. Reads, writes and deletes
//! reuse the hardened `http.acme.state.StateDir` primitive (symlink-refusing,
//! ownership/permission-checked, exclusive-create-temp + fsync + rename +
//! fsync-parent atomic replacement, originally built for ACME state). A
//! record is self-contained: a versioned magic, the config fingerprint it
//! was written under, every field needed to replay or classify freshness,
//! and a checksum. Corrupt, truncated, wrong-fingerprint or wrong-key
//! records are treated as a miss and best-effort deleted -- never repaired,
//! never served.
//!
//! All accounting (entry count, aggregate bytes, LRU eviction) lives in one
//! in-memory index guarded by this type's own mutex, deliberately separate
//! from `GatewayState.proxy_response_cache_mutex` so a disk read/write never
//! blocks an in-memory cache hit. The index is seeded once at `init` by a
//! single bounded directory scan (stat-only, no file contents read) so a
//! restart reconciles real on-disk usage and bounded Vary metadata instead of
//! silently leaking bytes a crashed process never got to account for. If the
//! bounded scan cannot reach EOF, the tier disables itself rather than enforce
//! quota against a partial directory view.

const std = @import("std");
const compat = @import("zig_compat");
const http = @import("http.zig");
const gpc = @import("gateway_proxy_cache.zig");

const StateDir = http.acme.state.StateDir;

/// Exactly `buildCacheKey`/`buildVaryVariantKey`'s fixed hex-digest width.
/// Any other length is rejected outright rather than guessed at.
pub const key_len: usize = 64;

pub const Limits = struct {
    max_object_bytes: usize,
    max_entries: usize,
    max_total_bytes: usize,
    max_vary_variants: usize = 8,
};

/// Accounted overhead per record beyond the raw body (headers, reason,
/// fixed-width metadata, framing) -- mirrors `gateway_proxy_cache.zig`'s own
/// `objectBytes` fudge factor. Keeps the disk cap commensurable with the
/// `max_object_bytes` operators already configure for the in-memory tier.
const record_overhead_bytes: usize = 512;

/// Hard ceiling on stored header count/sizes, independent of the in-memory
/// cache's own limits: this module decodes untrusted bytes read back from
/// disk, so every length is validated against a fixed bound before any
/// allocation proportional to it.
const max_headers: usize = 64;
const max_header_name_bytes: usize = 256;
const max_header_value_bytes: usize = 8192;
const max_reason_bytes: usize = 256;

const record_magic = "TPDC2\x00\x00\x00".*;

pub const PutRecord = struct {
    status_code: u16,
    reason: []const u8,
    headers: []const gpc.CacheHeaderView,
    body: []const u8,
    stored_at_ms: u64,
    expires_at_ms: u64,
    swr_until_ms: u64,
    initial_age_seconds: u32,
    vary_primary_key: ?[]const u8 = null,
};

pub const LoadedRecord = struct {
    status_code: u16,
    reason: []const u8,
    headers: []gpc.CacheHeader,
    body: []const u8,
    stored_at_ms: u64,
    expires_at_ms: u64,
    swr_until_ms: u64,
    initial_age_seconds: u32,
    vary_primary_key: ?[]const u8,
};

fn isHexLowerKey(key: []const u8) bool {
    if (key.len != key_len) return false;
    for (key) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        if (!ok) return false;
    }
    return true;
}

const IndexValue = struct {
    bytes: usize,
    last_used_ms: u64,
    vary_primary_key: ?[key_len]u8 = null,
};

const VaryIndexEntry = struct {
    variant_keys: [gpc.hard_max_vary_variants][key_len]u8 = undefined,
    count: usize = 0,

    fn indexOf(self: *const VaryIndexEntry, secondary_key: []const u8) ?usize {
        for (self.variant_keys[0..self.count], 0..) |key, i| {
            if (std.mem.eql(u8, key[0..], secondary_key)) return i;
        }
        return null;
    }

    fn removeAt(self: *VaryIndexEntry, idx: usize) void {
        var i = idx;
        while (i + 1 < self.count) : (i += 1) self.variant_keys[i] = self.variant_keys[i + 1];
        self.count -= 1;
    }
};

/// Bounded, hardened, crash-safe disk-backed companion to
/// `gateway_proxy_cache.ProxyResponseCache`. Every public method is
/// best-effort: a disk fault, corruption, or capacity limit degrades to "as
/// if the entry were absent" rather than ever propagating into the live
/// proxy request path.
pub const DiskCache = struct {
    allocator: std.mem.Allocator,
    state_dir: StateDir,
    limits: Limits,
    /// #903: the config fingerprint this process was started/reloaded with.
    /// A record written under a different fingerprint belongs to a
    /// different route/upstream/cache-policy configuration and is never
    /// served, even though the bytes on disk are otherwise well-formed.
    fingerprint: u64,
    mutex: compat.Mutex = .{},
    index: std.StringHashMap(IndexValue),
    vary_index: std.StringHashMap(VaryIndexEntry),
    total_bytes: usize = 0,
    max_vary_variants: usize,
    disabled: bool = false,

    /// Opens (creating as `0700` if absent) and validates `root_path`,
    /// refusing a symlink, a path owned by another user, or one with
    /// group/other write bits -- the same contract `StateDir.open` already
    /// enforces for ACME state. Then runs one bounded reconciliation scan so
    /// disk usage and Vary metadata from a previous process are restored.
    pub fn init(allocator: std.mem.Allocator, root_path: []const u8, limits: Limits, fingerprint: u64) !DiskCache {
        var state_dir = try StateDir.open(root_path);
        errdefer state_dir.close();
        var self = DiskCache{
            .allocator = allocator,
            .state_dir = state_dir,
            .limits = limits,
            .fingerprint = fingerprint,
            .index = std.StringHashMap(IndexValue).init(allocator),
            .vary_index = std.StringHashMap(VaryIndexEntry).init(allocator),
            .max_vary_variants = @max(1, @min(limits.max_vary_variants, gpc.hard_max_vary_variants)),
        };
        self.reconcileFromDisk(root_path);
        self.evictToFitLocked();
        return self;
    }

    pub fn deinit(self: *DiskCache) void {
        var it = self.index.iterator();
        while (it.next()) |kv| self.allocator.free(kv.key_ptr.*);
        self.index.deinit();
        var vit = self.vary_index.iterator();
        while (vit.next()) |kv| self.allocator.free(kv.key_ptr.*);
        self.vary_index.deinit();
        self.state_dir.close();
        self.* = undefined;
    }

    /// One-time, bounded directory scan opened independently
    /// of `state_dir` (a second read-only handle on the same already-
    /// validated path -- `StateDir.open` above already proved it is a safe,
    /// owned, non-symlinked directory). Bounded to a small multiple of the
    /// configured entry cap rather than the directory's actual size. Reaching
    /// the cap without EOF disables the tier, preventing untracked files from
    /// bypassing quota. Valid records are decoded to rebuild the bounded Vary
    /// primary-to-secondary index required after restart.
    fn reconcileFromDisk(self: *DiskCache, root_path: []const u8) void {
        const dir_fd = compat.openDirNoFollow(root_path) catch return;
        defer compat.closeFd(dir_fd);
        var dir: std.Io.Dir = .{ .handle = dir_fd };
        const io = compat.io();
        var it = dir.iterate();
        const scan_cap = self.limits.max_entries * 4 + 64;
        const now_ms = http.event_loop.monotonicMs();
        var visited: usize = 0;
        while (visited < scan_cap) {
            const entry = (it.next(io) catch {
                self.disableLocked();
                return;
            }) orelse return;
            visited += 1;
            if (entry.kind != .file) continue;
            if (!isHexLowerKey(entry.name)) continue;
            const st = dir.statFile(io, entry.name, .{ .follow_symlinks = false }) catch continue;
            if (st.kind != .file) continue;
            const owned = self.allocator.dupe(u8, entry.name) catch continue;
            const bytes: usize = @intCast(st.size);
            const gop = self.index.getOrPut(owned) catch {
                self.allocator.free(owned);
                continue;
            };
            if (gop.found_existing) {
                self.allocator.free(owned);
                continue;
            }
            gop.value_ptr.* = .{ .bytes = bytes, .last_used_ms = now_ms };
            self.total_bytes += bytes;

            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();
            const raw = self.state_dir.readFileAlloc(arena.allocator(), entry.name, self.limits.max_object_bytes + record_overhead_bytes, false) catch continue;
            const decoded = decodeRecord(arena.allocator(), raw) catch {
                self.disableLocked();
                return;
            } orelse continue;
            if (decoded.fingerprint != self.fingerprint or !std.mem.eql(u8, decoded.key, entry.name)) continue;
            if (decoded.record.vary_primary_key) |primary| {
                var primary_buf: [key_len]u8 = undefined;
                @memcpy(primary_buf[0..], primary);
                gop.value_ptr.vary_primary_key = primary_buf;
                self.trackVariantLocked(primary, entry.name) catch {
                    self.disableLocked();
                    return;
                };
            }
        }

        // Reaching the cap without EOF means there may be unaccounted files.
        // Disable the tier rather than enforcing quota against a partial view.
        if ((it.next(io) catch null) != null) self.disableLocked();
    }

    fn disableLocked(self: *DiskCache) void {
        var it = self.index.iterator();
        while (it.next()) |kv| self.allocator.free(kv.key_ptr.*);
        self.index.clearRetainingCapacity();
        var vit = self.vary_index.iterator();
        while (vit.next()) |kv| self.allocator.free(kv.key_ptr.*);
        self.vary_index.clearRetainingCapacity();
        self.total_bytes = 0;
        self.disabled = true;
    }

    fn trackVariantLocked(self: *DiskCache, primary_key: []const u8, secondary_key: []const u8) !void {
        if (self.vary_index.getPtr(primary_key)) |index| {
            if (index.indexOf(secondary_key) != null) return;
            if (index.count == self.max_vary_variants) return;
            @memcpy(index.variant_keys[index.count][0..], secondary_key);
            index.count += 1;
            return;
        }
        const owned = try self.allocator.dupe(u8, primary_key);
        errdefer self.allocator.free(owned);
        var fresh = VaryIndexEntry{};
        @memcpy(fresh.variant_keys[0][0..], secondary_key);
        fresh.count = 1;
        try self.vary_index.put(owned, fresh);
    }

    fn pruneVariantLocked(self: *DiskCache, primary_key: []const u8, secondary_key: []const u8) void {
        const index = self.vary_index.getPtr(primary_key) orelse return;
        const idx = index.indexOf(secondary_key) orelse return;
        index.removeAt(idx);
        if (index.count == 0) {
            if (self.vary_index.fetchRemove(primary_key)) |removed| self.allocator.free(removed.key);
        }
    }

    /// Deletes the single oldest (`last_used_ms`) tracked entry. Called only
    /// while `self.mutex` is held.
    fn evictOneLocked(self: *DiskCache) void {
        _ = self.evictOneLockedExcept(null);
    }

    fn evictOneLockedExcept(self: *DiskCache, except: ?[]const u8) bool {
        var oldest_key: ?[]const u8 = null;
        var oldest_ms: u64 = std.math.maxInt(u64);
        var it = self.index.iterator();
        while (it.next()) |kv| {
            if (except) |key| if (std.mem.eql(u8, kv.key_ptr.*, key)) continue;
            if (kv.value_ptr.last_used_ms < oldest_ms) {
                oldest_ms = kv.value_ptr.last_used_ms;
                oldest_key = kv.key_ptr.*;
            }
        }
        const victim = oldest_key orelse return false;
        self.removeLocked(victim);
        return true;
    }

    fn evictToFitLocked(self: *DiskCache) void {
        var guard: usize = 0;
        while ((self.index.count() > self.limits.max_entries or self.total_bytes > self.limits.max_total_bytes) and guard < self.limits.max_entries + 1) {
            guard += 1;
            self.evictOneLocked();
        }
    }

    fn removeLocked(self: *DiskCache, key: []const u8) void {
        if (self.index.fetchRemove(key)) |removed| {
            // `key` may alias `removed.key`; unlink before releasing it.
            self.state_dir.removeFile(removed.key);
            self.total_bytes -= removed.value.bytes;
            if (removed.value.vary_primary_key) |primary| self.pruneVariantLocked(primary[0..], removed.key);
            self.allocator.free(removed.key);
        }
    }

    /// Best-effort delete, forgetting the key whether or not it was tracked
    /// (a file can exist on disk without an index entry after a startup
    /// scan truncated by `scan_cap`, or never have been written at all).
    pub fn remove(self: *DiskCache, key: []const u8) void {
        if (!isHexLowerKey(key)) return;
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.disabled) return;
        self.removeLocked(key);
        // Also remove a valid but untracked file (for example, one left by a
        // failed process between rename and index publication).
        if (!self.index.contains(key)) self.state_dir.removeFile(key);
    }

    fn recordBytes(key: []const u8, record: PutRecord) usize {
        var total: usize = key.len + record.reason.len + record.body.len + record_overhead_bytes;
        for (record.headers) |h| total += h.name.len + h.value.len;
        return total;
    }

    /// Encodes and durably persists `record` under `key`. Best-effort: too
    /// large, an encode failure, or an I/O fault all leave any previous
    /// on-disk entry for `key` untouched and simply do not admit the new
    /// one -- callers never see this as distinct from "the disk tier is
    /// unavailable".
    pub fn put(self: *DiskCache, key: []const u8, record: PutRecord, now_ms: u64) void {
        if (!isHexLowerKey(key)) return;
        if (record.reason.len > max_reason_bytes) return;
        if (record.headers.len > max_headers) return;
        for (record.headers) |h| {
            if (h.name.len > max_header_name_bytes or h.value.len > max_header_value_bytes) return;
        }
        const object_bytes = recordBytes(key, record);
        if (object_bytes > self.limits.max_object_bytes) return;

        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.allocator);
        encodeRecord(self.allocator, &buf, key, record, self.fingerprint) catch return;

        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.disabled) return;

        const existing = self.index.get(key);
        const retired_count: usize = if (existing == null) 0 else 1;
        const retired_bytes: usize = if (existing) |value| value.bytes else 0;
        if (existing == null) self.index.ensureUnusedCapacity(1) catch return;
        var owned_key = if (existing == null) self.allocator.dupe(u8, key) catch return else null;
        defer if (owned_key) |owned| self.allocator.free(owned);

        var owned_primary: ?[]u8 = null;
        if (record.vary_primary_key) |primary| {
            if (!isHexLowerKey(primary)) return;
            if (!self.vary_index.contains(primary)) {
                self.vary_index.ensureUnusedCapacity(1) catch return;
                owned_primary = self.allocator.dupe(u8, primary) catch return;
            }
        }
        defer if (owned_primary) |owned| self.allocator.free(owned);

        const candidate_bytes = buf.items.len;
        var guard: usize = 0;
        while (((self.index.count() - retired_count) >= self.limits.max_entries or
            (self.total_bytes - retired_bytes) + candidate_bytes > self.limits.max_total_bytes) and guard < self.limits.max_entries + 1)
        {
            guard += 1;
            if (!self.evictOneLockedExcept(key)) break;
        }
        const refreshed = self.index.get(key);
        const refreshed_count: usize = if (refreshed == null) 0 else 1;
        const refreshed_bytes: usize = if (refreshed) |value| value.bytes else 0;
        if ((self.index.count() - refreshed_count) >= self.limits.max_entries or
            (self.total_bytes - refreshed_bytes) + candidate_bytes > self.limits.max_total_bytes) return;

        self.state_dir.writeFileAtomicLimit(key, buf.items, 0o600, self.limits.max_object_bytes + record_overhead_bytes) catch return;

        var final_key: ?[]const u8 = owned_key;
        if (self.index.fetchRemove(key)) |removed| {
            self.total_bytes -= removed.value.bytes;
            if (removed.value.vary_primary_key) |primary| {
                const same_variant = if (record.vary_primary_key) |next_primary|
                    std.mem.eql(u8, primary[0..], next_primary)
                else
                    false;
                if (!same_variant) self.pruneVariantLocked(primary[0..], removed.key);
            }
            final_key = removed.key;
        }
        var vary_primary: ?[key_len]u8 = null;
        if (record.vary_primary_key) |primary| {
            var primary_buf: [key_len]u8 = undefined;
            @memcpy(primary_buf[0..], primary);
            vary_primary = primary_buf;
        }
        self.index.putAssumeCapacity(final_key.?, .{ .bytes = candidate_bytes, .last_used_ms = now_ms, .vary_primary_key = vary_primary });
        owned_key = null;
        self.total_bytes += candidate_bytes;

        if (record.vary_primary_key) |primary| {
            if (self.vary_index.getPtr(primary)) |index| {
                if (index.indexOf(key) == null) {
                    if (index.count == self.max_vary_variants) {
                        const victim = index.variant_keys[0];
                        index.removeAt(0);
                        self.removeLocked(victim[0..]);
                    }
                    @memcpy(index.variant_keys[index.count][0..], key);
                    index.count += 1;
                }
            } else {
                var fresh = VaryIndexEntry{};
                @memcpy(fresh.variant_keys[0][0..], key);
                fresh.count = 1;
                self.vary_index.putAssumeCapacity(owned_primary.?, fresh);
                owned_primary = null;
            }
        } else if (self.vary_index.fetchRemove(key)) |variants| {
            for (variants.value.variant_keys[0..variants.value.count]) |variant| self.removeLocked(variant[0..]);
            self.allocator.free(variants.key);
        }
    }

    /// Reads, validates and decodes `key`. `scratch` must outlive the
    /// returned `LoadedRecord` (every slice borrows directly from one
    /// allocation made on it) -- callers use the same request-scoped arena
    /// `gateway_proxy_cache.ProxyResponseCache.lookup` already requires.
    /// Any validation failure (missing, corrupt, truncated, wrong
    /// fingerprint, or a key mismatch) is treated as a miss and the on-disk
    /// entry is best-effort removed so a permanently-corrupt file cannot
    /// wedge every future lookup for that key.
    pub fn get(self: *DiskCache, scratch: std.mem.Allocator, key: []const u8, now_ms: u64) ?LoadedRecord {
        if (!isHexLowerKey(key)) return null;
        self.mutex.lock();
        if (self.disabled) {
            self.mutex.unlock();
            return null;
        }
        const tracked = self.index.contains(key);
        self.mutex.unlock();
        if (!tracked) return null;

        const raw = self.state_dir.readFileAlloc(scratch, key, self.limits.max_object_bytes + record_overhead_bytes, false) catch {
            self.remove(key);
            return null;
        };
        const maybe_decoded = decodeRecord(scratch, raw) catch return null;
        const decoded = maybe_decoded orelse {
            self.remove(key);
            return null;
        };
        if (decoded.fingerprint != self.fingerprint or !std.mem.eql(u8, decoded.key, key)) {
            self.remove(key);
            return null;
        }
        if (now_ms >= decoded.record.swr_until_ms) {
            self.remove(key);
            return null;
        }

        self.mutex.lock();
        if (self.index.getPtr(key)) |value| value.last_used_ms = now_ms;
        self.mutex.unlock();
        return decoded.record;
    }

    pub fn isVaryTracked(self: *DiskCache, primary_key: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return !self.disabled and self.vary_index.contains(primary_key);
    }
};

fn writeLenPrefixed(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime LenT: type, bytes: []const u8) !void {
    var len_buf: [@sizeOf(LenT)]u8 = undefined;
    std.mem.writeInt(LenT, &len_buf, @intCast(bytes.len), .little);
    try buf.appendSlice(allocator, &len_buf);
    try buf.appendSlice(allocator, bytes);
}

fn encodeRecord(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), key: []const u8, record: PutRecord, fingerprint: u64) !void {
    try buf.appendSlice(allocator, &record_magic);
    var u64_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &u64_buf, fingerprint, .little);
    try buf.appendSlice(allocator, &u64_buf);
    var u16_buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &u16_buf, record.status_code, .little);
    try buf.appendSlice(allocator, &u16_buf);
    std.mem.writeInt(u64, &u64_buf, record.stored_at_ms, .little);
    try buf.appendSlice(allocator, &u64_buf);
    std.mem.writeInt(u64, &u64_buf, record.expires_at_ms, .little);
    try buf.appendSlice(allocator, &u64_buf);
    std.mem.writeInt(u64, &u64_buf, record.swr_until_ms, .little);
    try buf.appendSlice(allocator, &u64_buf);
    var u32_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &u32_buf, record.initial_age_seconds, .little);
    try buf.appendSlice(allocator, &u32_buf);

    try writeLenPrefixed(buf, allocator, u16, key);
    try writeLenPrefixed(buf, allocator, u16, record.vary_primary_key orelse "");
    try writeLenPrefixed(buf, allocator, u16, record.reason);

    std.mem.writeInt(u16, &u16_buf, @intCast(record.headers.len), .little);
    try buf.appendSlice(allocator, &u16_buf);
    for (record.headers) |h| {
        try writeLenPrefixed(buf, allocator, u16, h.name);
        try writeLenPrefixed(buf, allocator, u32, h.value);
    }
    try writeLenPrefixed(buf, allocator, u32, record.body);

    const checksum = std.hash.Wyhash.hash(0x5054_4443_3155, buf.items);
    std.mem.writeInt(u64, &u64_buf, checksum, .little);
    try buf.appendSlice(allocator, &u64_buf);
}

const Decoded = struct {
    fingerprint: u64,
    key: []const u8,
    record: LoadedRecord,
};

/// Zero-copy decode: every slice in the returned value borrows directly
/// from `raw`. Every length is validated against the fixed module ceilings
/// before use, and the trailing checksum is verified before any field is
/// trusted at all.
fn decodeRecord(scratch: std.mem.Allocator, raw: []const u8) !?Decoded {
    var r = Reader{ .bytes = raw };
    const magic = r.take(record_magic.len) orelse return null;
    if (!std.mem.eql(u8, magic, &record_magic)) return null;
    if (raw.len < 8) return null;
    const checksum_offset = raw.len - 8;
    const claimed_checksum = std.mem.readInt(u64, raw[checksum_offset..][0..8], .little);
    const actual_checksum = std.hash.Wyhash.hash(0x5054_4443_3155, raw[0..checksum_offset]);
    if (claimed_checksum != actual_checksum) return null;
    // Re-derive the reader over just the checksummed prefix so the fields
    // below can never read into (or past) the trailing checksum itself.
    r = Reader{ .bytes = raw[0..checksum_offset] };
    _ = r.take(record_magic.len) orelse return null;

    const fingerprint = r.readU64() orelse return null;
    const status_code = r.readU16() orelse return null;
    const stored_at_ms = r.readU64() orelse return null;
    const expires_at_ms = r.readU64() orelse return null;
    const swr_until_ms = r.readU64() orelse return null;
    const initial_age_seconds = r.readU32() orelse return null;

    const key = r.readLenPrefixed(u16, key_len) orelse return null;
    const vary_primary_raw = r.readLenPrefixed(u16, key_len) orelse return null;
    if (vary_primary_raw.len != 0 and !isHexLowerKey(vary_primary_raw)) return null;
    const vary_primary_key: ?[]const u8 = if (vary_primary_raw.len == 0) null else vary_primary_raw;
    const reason = r.readLenPrefixed(u16, max_reason_bytes) orelse return null;

    const header_count = r.readU16() orelse return null;
    if (header_count > max_headers) return null;
    const headers = try scratch.alloc(gpc.CacheHeader, header_count);
    var i: usize = 0;
    while (i < header_count) : (i += 1) {
        const name = r.readLenPrefixed(u16, max_header_name_bytes) orelse return null;
        const value = r.readLenPrefixed(u32, max_header_value_bytes) orelse return null;
        headers[i] = .{ .name = @constCast(name), .value = @constCast(value) };
    }
    const body = r.readLenPrefixed(u32, std.math.maxInt(u32)) orelse return null;
    if (!r.atEnd()) return null;

    return .{
        .fingerprint = fingerprint,
        .key = key,
        .record = .{
            .status_code = status_code,
            .reason = reason,
            .headers = headers,
            .body = body,
            .stored_at_ms = stored_at_ms,
            .expires_at_ms = expires_at_ms,
            .swr_until_ms = swr_until_ms,
            .initial_age_seconds = initial_age_seconds,
            .vary_primary_key = vary_primary_key,
        },
    };
}

/// Bounds-checked cursor over an immutable byte slice -- every read either
/// returns a validated, in-bounds slice/int or `null`, never a panic or an
/// out-of-bounds access, since `raw` is untrusted on-disk content.
const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn atEnd(self: *const Reader) bool {
        return self.pos == self.bytes.len;
    }

    fn take(self: *Reader, n: usize) ?[]const u8 {
        if (self.pos + n > self.bytes.len) return null;
        const slice = self.bytes[self.pos .. self.pos + n];
        self.pos += n;
        return slice;
    }

    fn readU16(self: *Reader) ?u16 {
        const bytes = self.take(2) orelse return null;
        return std.mem.readInt(u16, bytes[0..2], .little);
    }

    fn readU32(self: *Reader) ?u32 {
        const bytes = self.take(4) orelse return null;
        return std.mem.readInt(u32, bytes[0..4], .little);
    }

    fn readU64(self: *Reader) ?u64 {
        const bytes = self.take(8) orelse return null;
        return std.mem.readInt(u64, bytes[0..8], .little);
    }

    fn readLenPrefixed(self: *Reader, comptime LenT: type, max_len: usize) ?[]const u8 {
        const len_bytes = self.take(@sizeOf(LenT)) orelse return null;
        const len = std.mem.readInt(LenT, len_bytes[0..@sizeOf(LenT)], .little);
        if (len > max_len) return null;
        return self.take(len);
    }
};

test "isHexLowerKey accepts exactly 64 lowercase hex chars" {
    try std.testing.expect(isHexLowerKey("a" ** 64));
    try std.testing.expect(!isHexLowerKey("A" ** 64));
    try std.testing.expect(!isHexLowerKey("a" ** 63));
    try std.testing.expect(!isHexLowerKey("a" ** 65));
    try std.testing.expect(!isHexLowerKey("g" ** 64));
}

test "encodeRecord/decodeRecord round-trips every field and rejects a flipped byte" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const key = "b" ** 64;
    const headers = [_]gpc.CacheHeaderView{
        .{ .name = "Content-Type", .value = "text/plain" },
        .{ .name = "ETag", .value = "\"v1\"" },
    };
    const record = PutRecord{
        .status_code = 200,
        .reason = "OK",
        .headers = &headers,
        .body = "hello disk cache",
        .stored_at_ms = 1_000,
        .expires_at_ms = 61_000,
        .swr_until_ms = 121_000,
        .initial_age_seconds = 3,
    };
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try encodeRecord(allocator, &buf, key, record, 0xABCD);

    const decoded = (try decodeRecord(arena.allocator(), buf.items)).?;
    try std.testing.expectEqual(@as(u64, 0xABCD), decoded.fingerprint);
    try std.testing.expectEqualStrings(key, decoded.key);
    try std.testing.expectEqual(@as(u16, 200), decoded.record.status_code);
    try std.testing.expectEqualStrings("OK", decoded.record.reason);
    try std.testing.expectEqual(@as(usize, 2), decoded.record.headers.len);
    try std.testing.expectEqualStrings("Content-Type", decoded.record.headers[0].name);
    try std.testing.expectEqualStrings("hello disk cache", decoded.record.body);
    try std.testing.expectEqual(@as(u64, 61_000), decoded.record.expires_at_ms);
    try std.testing.expectEqual(@as(u64, 121_000), decoded.record.swr_until_ms);

    // Flipping any single byte must fail the checksum, never silently
    // decode a corrupted field.
    var corrupted = try allocator.dupe(u8, buf.items);
    defer allocator.free(corrupted);
    corrupted[corrupted.len / 2] ^= 0xFF;
    try std.testing.expectEqual(@as(?Decoded, null), try decodeRecord(arena.allocator(), corrupted));

    // Truncation must fail outright rather than decode a partial record.
    try std.testing.expectEqual(@as(?Decoded, null), try decodeRecord(arena.allocator(), buf.items[0 .. buf.items.len - 1]));
}

test "decodeRecord rejects a bad magic and an empty buffer" {
    try std.testing.expectEqual(@as(?Decoded, null), try decodeRecord(std.testing.allocator, ""));
    try std.testing.expectEqual(@as(?Decoded, null), try decodeRecord(std.testing.allocator, "not a cache record at all"));
}

test "DiskCache put/get round-trips, enforces the config fingerprint and evicts past the stale-while-revalidate deadline" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);

    var cache = try DiskCache.init(allocator, root_path, .{ .max_object_bytes = 4096, .max_entries = 4, .max_total_bytes = 1 << 20 }, 111);
    defer cache.deinit();

    const key = "c" ** 64;
    const headers = [_]gpc.CacheHeaderView{.{ .name = "Content-Type", .value = "text/plain" }};
    cache.put(key, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &headers,
        .body = "cached body",
        .stored_at_ms = 0,
        .expires_at_ms = 1_000,
        .swr_until_ms = 2_000,
        .initial_age_seconds = 0,
    }, 0);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const hit = cache.get(arena.allocator(), key, 500) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("cached body", hit.body);

    // Still inside the stale-while-revalidate window (past `expires_at_ms`
    // but before `swr_until_ms`): the disk tier itself does not evict or
    // refuse this -- freshness-vs-staleness classification is the caller's
    // job (`gateway_proxy_cache.zig`/`GatewayState`), same split as the
    // in-memory cache.
    const stale_hit = cache.get(arena.allocator(), key, 1_500) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("cached body", stale_hit.body);

    // Past the stale-while-revalidate deadline: a safe miss, and the file is
    // gone so a fresh process would not find it either.
    try std.testing.expectEqual(@as(?LoadedRecord, null), cache.get(arena.allocator(), key, 2_500));

    // A different config fingerprint never sees a hit, even immediately
    // after a fresh write under the matching one.
    cache.put(key, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &headers,
        .body = "cached body",
        .stored_at_ms = 0,
        .expires_at_ms = 1_000,
        .swr_until_ms = 2_000,
        .initial_age_seconds = 0,
    }, 0);
    cache.deinit();
    cache = try DiskCache.init(allocator, root_path, .{ .max_object_bytes = 4096, .max_entries = 4, .max_total_bytes = 1 << 20 }, 222);
    try std.testing.expectEqual(@as(?LoadedRecord, null), cache.get(arena.allocator(), key, 500));
}

test "DiskCache failed overwrite preserves the prior indexed record" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    var cache = try DiskCache.init(allocator, root_path, .{ .max_object_bytes = 4096, .max_entries = 4, .max_total_bytes = 1 << 20 }, 9);
    defer cache.deinit();
    const key = "9" ** 64;
    const headers = [_]gpc.CacheHeaderView{};
    const base = PutRecord{
        .status_code = 200,
        .reason = "OK",
        .headers = &headers,
        .body = "old",
        .stored_at_ms = 0,
        .expires_at_ms = 100_000,
        .swr_until_ms = 100_000,
        .initial_age_seconds = 0,
    };
    cache.put(key, base, 0);
    cache.state_dir.fault = .write;
    cache.state_dir.fault_file = key;
    var replacement = base;
    replacement.body = "new";
    cache.put(key, replacement, 1);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const hit = cache.get(arena.allocator(), key, 2) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("old", hit.body);
    try std.testing.expectEqual(@as(usize, 1), cache.index.count());
}

test "DiskCache rebuilds bounded Vary metadata across restart" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    const limits = Limits{ .max_object_bytes = 4096, .max_entries = 4, .max_total_bytes = 1 << 20, .max_vary_variants = 2 };
    const primary = "a" ** 64;
    const secondary = "b" ** 64;
    const headers = [_]gpc.CacheHeaderView{.{ .name = "Vary", .value = "Accept-Encoding" }};
    {
        var cache = try DiskCache.init(allocator, root_path, limits, 17);
        defer cache.deinit();
        cache.put(secondary, .{
            .status_code = 200,
            .reason = "OK",
            .headers = &headers,
            .body = "gzip variant",
            .stored_at_ms = 0,
            .expires_at_ms = 100_000,
            .swr_until_ms = 100_000,
            .initial_age_seconds = 0,
            .vary_primary_key = primary,
        }, 0);
        cache.put(secondary, .{
            .status_code = 200,
            .reason = "OK",
            .headers = &headers,
            .body = "updated gzip variant",
            .stored_at_ms = 1,
            .expires_at_ms = 100_000,
            .swr_until_ms = 100_000,
            .initial_age_seconds = 0,
            .vary_primary_key = primary,
        }, 1);
    }

    var cache = try DiskCache.init(allocator, root_path, limits, 17);
    defer cache.deinit();
    try std.testing.expect(cache.isVaryTracked(primary));
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const hit = cache.get(arena.allocator(), secondary, 1) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings(primary, hit.vary_primary_key.?);
    try std.testing.expectEqualStrings("updated gzip variant", hit.body);
}

test "DiskCache disables reconciliation when startup scan reaches its cap" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    const limits = Limits{ .max_object_bytes = 4096, .max_entries = 1, .max_total_bytes = 1 << 20 };
    {
        var writer = try DiskCache.init(allocator, root_path, limits, 3);
        defer writer.deinit();
        var i: usize = 0;
        while (i < 80) : (i += 1) {
            var name = [_]u8{'0'} ** key_len;
            _ = try std.fmt.bufPrint(name[key_len - 8 ..], "{x:0>8}", .{i});
            try writer.state_dir.writeFileAtomic(&name, "untracked", 0o600);
        }
    }

    var cache = try DiskCache.init(allocator, root_path, limits, 3);
    defer cache.deinit();
    try std.testing.expect(cache.disabled);
    try std.testing.expectEqual(@as(usize, 0), cache.index.count());
}

test "DiskCache survives a reopen (restart) and reconciles pre-existing entries" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);

    const limits = Limits{ .max_object_bytes = 4096, .max_entries = 4, .max_total_bytes = 1 << 20 };
    const key = "d" ** 64;
    const headers = [_]gpc.CacheHeaderView{};
    {
        var cache = try DiskCache.init(allocator, root_path, limits, 42);
        defer cache.deinit();
        cache.put(key, .{
            .status_code = 200,
            .reason = "OK",
            .headers = &headers,
            .body = "persisted across restart",
            .stored_at_ms = 0,
            .expires_at_ms = 1_000_000,
            .swr_until_ms = 1_000_000,
            .initial_age_seconds = 0,
        }, 0);
    }

    var cache = try DiskCache.init(allocator, root_path, limits, 42);
    defer cache.deinit();
    try std.testing.expectEqual(@as(usize, 1), cache.index.count());
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const hit = cache.get(arena.allocator(), key, 500) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("persisted across restart", hit.body);
}

test "DiskCache evicts the least-recently-used entry once max_entries is exceeded" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);

    var cache = try DiskCache.init(allocator, root_path, .{ .max_object_bytes = 4096, .max_entries = 2, .max_total_bytes = 1 << 20 }, 7);
    defer cache.deinit();
    const headers = [_]gpc.CacheHeaderView{};
    const base = PutRecord{
        .status_code = 200,
        .reason = "OK",
        .headers = &headers,
        .body = "x",
        .stored_at_ms = 0,
        .expires_at_ms = 1_000_000,
        .swr_until_ms = 1_000_000,
        .initial_age_seconds = 0,
    };
    cache.put("1" ** 64, base, 0);
    cache.put("2" ** 64, base, 1);
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    // Touch "1" so "2" becomes the least-recently-used key.
    _ = cache.get(arena.allocator(), "1" ** 64, 10);
    cache.put("3" ** 64, base, 20);

    try std.testing.expectEqual(@as(usize, 2), cache.index.count());
    try std.testing.expect(cache.get(arena.allocator(), "1" ** 64, 20) != null);
    try std.testing.expect(cache.get(arena.allocator(), "3" ** 64, 20) != null);
    try std.testing.expectEqual(@as(?LoadedRecord, null), cache.get(arena.allocator(), "2" ** 64, 20));
}

test "DiskCache.put refuses an object larger than max_object_bytes" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);

    var cache = try DiskCache.init(allocator, root_path, .{ .max_object_bytes = 32, .max_entries = 4, .max_total_bytes = 1 << 20 }, 1);
    defer cache.deinit();
    const headers = [_]gpc.CacheHeaderView{};
    cache.put("e" ** 64, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &headers,
        .body = "this body is far too long to fit the configured cap",
        .stored_at_ms = 0,
        .expires_at_ms = 1_000,
        .swr_until_ms = 1_000,
        .initial_age_seconds = 0,
    }, 0);
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try std.testing.expectEqual(@as(?LoadedRecord, null), cache.get(arena.allocator(), "e" ** 64, 10));
}
