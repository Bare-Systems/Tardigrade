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
//!
//! Disabling is durable, not just in-process: any disable (a truncated scan,
//! a faulted unlink, a fence write that failed while a sibling's I/O lane was
//! busy) writes a best-effort marker file that the next `init` checks before
//! trusting anything else in the directory. A disable can follow a mutation
//! this process could not fully account for, and bytes left behind can look
//! like a perfectly ordinary, reconcilable directory to a fresh scan -- so
//! once disabled, the namespace requires an operator to purge the directory
//! before the disk tier will serve from it again.

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

const record_magic = "TPDC3\x00\x00\x00".*;
const tombstone_magic = "TPDCTMB3".*;
/// Marks a primary whose Vary family has been superseded by a direct
/// response. Unlike a tombstone (a transient direct->Vary guard), a fence
/// masks every variant of its primary on restart.
const fence_magic = "TPDCFNC3".*;
const tombstone_bytes = tombstone_magic.len + @sizeOf(u64) + key_len + @sizeOf(u64);
const io_lane_count: usize = 64;

/// Fixed, non-hex name: `reconcileFromDisk`'s directory scan already skips
/// every entry that is not exactly `key_len` lowercase hex characters, so
/// this can never collide with a cache record and is never mistaken for one.
/// Its mere presence -- independent of the config fingerprint -- durably
/// marks the whole namespace untrustworthy; see `disableLocked`.
const poison_name = "disk-cache.disabled";
const poison_marker = "TARDIGRADE-DISK-CACHE-POISONED\x00".*;

/// Test-only pause point for proving that unrelated keys remain responsive
/// while one durable write is stalled. The pointer is null in production.
pub const TestIoBarrier = struct {
    key: []const u8,
    mutex: compat.Mutex = .{},
    condition: compat.Condition = .{},
    reached: bool = false,
    released: bool = false,

    pub fn waitUntilReached(self: *TestIoBarrier) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (!self.reached) self.condition.wait(&self.mutex);
    }

    pub fn release(self: *TestIoBarrier) void {
        self.mutex.lock();
        self.released = true;
        self.condition.broadcast();
        self.mutex.unlock();
    }

    fn pauseIfMatched(self: *TestIoBarrier, key: []const u8) void {
        if (!std.mem.eql(u8, self.key, key)) return;
        self.mutex.lock();
        self.reached = true;
        self.condition.broadcast();
        while (!self.released) self.condition.wait(&self.mutex);
        self.mutex.unlock();
    }
};

pub const TestWriteBarrier = TestIoBarrier;

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

const PersistedRecord = struct {
    status_code: u16,
    reason: []const u8,
    headers: []gpc.CacheHeader,
    body: []const u8,
    stored_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    swr_until_unix_ms: u64,
    initial_age_seconds: u32,
    vary_primary_key: ?[]const u8,
};

fn skipListContains(skip: []const [key_len]u8, key: []const u8) bool {
    for (skip) |entry| if (std.mem.eql(u8, entry[0..], key)) return true;
    return false;
}

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
    pending_write: bool = false,
    tombstone: bool = false,
    /// A direct-policy fence (implies `tombstone`): masks the primary's
    /// Vary family in-process and across restart until it is retired.
    fence: bool = false,
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
    /// Fixed striped lanes serialize same-key durable mutations without
    /// carrying the global index mutex across filesystem I/O.
    io_lanes: [io_lane_count]compat.Mutex = @splat(.{}),
    index: std.StringHashMap(IndexValue),
    vary_index: std.StringHashMap(VaryIndexEntry),
    total_bytes: usize = 0,
    reserved_entries: usize = 0,
    reserved_bytes: usize = 0,
    reserved_vary_primaries: usize = 0,
    max_vary_variants: usize,
    disabled: bool = false,
    test_write_barrier: ?*TestWriteBarrier = null,
    test_read_barrier: ?*TestIoBarrier = null,
    /// Test-only wall-clock override for reboot/clock-epoch simulations.
    test_unix_now_ms: ?u64 = null,

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
        // A prior process may have disabled itself mid-mutation (a faulted
        // fence write racing a busy sibling lane, a truncated startup scan,
        // an unprovable unlink) -- states where the bytes left on disk can
        // look like a perfectly ordinary, reconcilable directory. Trusting
        // that appearance would resurrect whatever representation the prior
        // process could no longer account for. The durable marker makes
        // "disabled" permanent until an operator purges the directory,
        // rather than merely in-process.
        if (self.isPoisonedOnDisk()) {
            self.disabled = true;
            return self;
        }
        self.reconcileFromDisk(root_path);
        self.applyFencesAtStartup();
        self.evictToFitLocked();
        return self;
    }

    /// Fail-safe: only a confirmed `NotFound` counts as "not poisoned". Any
    /// other error (unsafe file type, I/O failure, oversized/corrupt marker)
    /// cannot prove the marker is absent, so the namespace is still treated
    /// as untrustworthy.
    fn isPoisonedOnDisk(self: *DiskCache) bool {
        var buf: [poison_marker.len]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&buf);
        _ = self.state_dir.readFileAlloc(fba.allocator(), poison_name, poison_marker.len, false) catch |err| {
            return err != error.NotFound;
        };
        return true;
    }

    /// Best-effort: if even this write fails, a restart falls back to
    /// whatever `reconcileFromDisk` can determine on its own (which already
    /// fails closed on a truncated scan).
    fn poisonDurableBestEffort(self: *DiskCache) void {
        self.state_dir.writeFileAtomicLimit(poison_name, &poison_marker, 0o600, poison_marker.len) catch {};
    }

    const IoGuard = struct {
        cache: *DiskCache,
        first: usize,
        second: ?usize,

        fn unlock(self: IoGuard) void {
            if (self.second) |idx| self.cache.io_lanes[idx].unlock();
            self.cache.io_lanes[self.first].unlock();
        }
    };

    pub fn ioLane(key: []const u8) usize {
        return @intCast(std.hash.Wyhash.hash(0x5444_4349_4f, key) % io_lane_count);
    }

    pub fn keysShareIoLane(a: []const u8, b: []const u8) bool {
        return ioLane(a) == ioLane(b);
    }

    fn lockIo(self: *DiskCache, key: []const u8, related_key: ?[]const u8) IoGuard {
        const key_lane = ioLane(key);
        const related_lane = if (related_key) |related| ioLane(related) else key_lane;
        const first = @min(key_lane, related_lane);
        const second = @max(key_lane, related_lane);
        self.io_lanes[first].lock();
        if (second != first) self.io_lanes[second].lock();
        return .{ .cache = self, .first = first, .second = if (second == first) null else second };
    }

    fn unixNowMs(self: *const DiskCache) ?u64 {
        if (self.test_unix_now_ms) |now| return now;
        const now = compat.milliTimestamp();
        if (now < 0) return null;
        return @intCast(now);
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
        const dir_fd = compat.openDirNoFollow(root_path) catch {
            self.disableLocked();
            return;
        };
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
            if (!isHexLowerKey(entry.name)) continue;
            if (entry.kind != .file) {
                self.disableLocked();
                return;
            }
            const st = dir.statFile(io, entry.name, .{ .follow_symlinks = false }) catch {
                self.disableLocked();
                return;
            };
            if (st.kind != .file) {
                self.disableLocked();
                return;
            }
            const owned = self.allocator.dupe(u8, entry.name) catch {
                self.disableLocked();
                return;
            };
            const bytes: usize = @intCast(st.size);
            const gop = self.index.getOrPut(owned) catch {
                self.allocator.free(owned);
                self.disableLocked();
                return;
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
            if (isTombstone(raw, entry.name, self.fingerprint)) {
                gop.value_ptr.tombstone = true;
                continue;
            }
            if (isFence(raw, entry.name, self.fingerprint)) {
                gop.value_ptr.tombstone = true;
                gop.value_ptr.fence = true;
                continue;
            }
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
        const more = it.next(io) catch {
            self.disableLocked();
            return;
        };
        if (more != null) self.disableLocked();
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
        self.poisonDurableBestEffort();
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

    /// Detaches one tracked entry from the in-memory index. The caller owns
    /// the returned key and must unlink/free it after releasing `self.mutex`.
    fn detachLocked(self: *DiskCache, key: []const u8) ?[]const u8 {
        const removed = self.index.fetchRemove(key) orelse return null;
        self.total_bytes -= removed.value.bytes;
        if (removed.value.vary_primary_key) |primary| self.pruneVariantLocked(primary[0..], removed.key);
        return removed.key;
    }

    fn oldestKeyLocked(self: *DiskCache, except: ?[]const u8, skip: []const [key_len]u8) ?[]const u8 {
        var oldest_key: ?[]const u8 = null;
        var oldest_ms: u64 = std.math.maxInt(u64);
        var it = self.index.iterator();
        while (it.next()) |kv| {
            if (except) |key| if (std.mem.eql(u8, kv.key_ptr.*, key)) continue;
            if (kv.value_ptr.pending_write) continue;
            // A fence is the only thing masking its primary's variants.
            if (kv.value_ptr.fence) continue;
            if (skipListContains(skip, kv.key_ptr.*)) continue;
            if (kv.value_ptr.last_used_ms < oldest_ms or
                (kv.value_ptr.last_used_ms == oldest_ms and (oldest_key == null or std.mem.order(u8, kv.key_ptr.*, oldest_key.?) == .lt)))
            {
                oldest_ms = kv.value_ptr.last_used_ms;
                oldest_key = kv.key_ptr.*;
            }
        }
        return oldest_key;
    }

    /// Startup-only: every durable direct-policy fence masks its primary's
    /// Vary family. Variants are unlinked durably and the fence itself is
    /// then retired; any failure disables the tier rather than serving a
    /// superseded representation.
    fn applyFencesAtStartup(self: *DiskCache) void {
        if (self.disabled) return;
        var fences: std.ArrayList([key_len]u8) = .empty;
        defer fences.deinit(self.allocator);
        var it = self.index.iterator();
        while (it.next()) |kv| {
            if (!kv.value_ptr.fence) continue;
            var buf: [key_len]u8 = undefined;
            @memcpy(buf[0..], kv.key_ptr.*);
            fences.append(self.allocator, buf) catch {
                self.disableLocked();
                return;
            };
        }
        for (fences.items) |*primary| {
            while (self.vary_index.getPtr(primary)) |family| {
                if (family.count == 0) {
                    self.pruneVariantLocked(primary, family.variant_keys[0][0..]);
                    break;
                }
                const sibling = family.variant_keys[0];
                const owned = self.detachLocked(sibling[0..]) orelse {
                    self.pruneVariantLocked(primary, sibling[0..]);
                    continue;
                };
                defer self.allocator.free(owned);
                self.state_dir.removeFileDurable(owned) catch {
                    self.disableLocked();
                    return;
                };
            }
            self.state_dir.removeFileDurable(primary) catch {
                self.disableLocked();
                return;
            };
            if (self.detachLocked(primary)) |owned| self.allocator.free(owned);
        }
    }

    fn isFencedLocked(self: *DiskCache, primary: []const u8) bool {
        return if (self.index.get(primary)) |marker| marker.fence else false;
    }

    /// True when `key` must never be served: missing, a tombstone/fence
    /// itself, or a Vary secondary whose primary now carries a direct-policy
    /// fence. Called both before the durable read and again immediately
    /// before returning a decoded record, so a fence installed by a
    /// concurrent writer in between (the only way a secondary's own index
    /// entry survives a family retirement: its I/O lane was busy) still
    /// masks the stale representation rather than letting it resume serving
    /// under its old key.
    fn isMaskedRecordLocked(self: *DiskCache, key: []const u8) bool {
        const value = self.index.get(key) orelse return true;
        if (value.tombstone) return true;
        if (value.vary_primary_key) |primary| return self.isFencedLocked(primary[0..]);
        return false;
    }

    /// Retires every tracked variant of `primary` once, each under its own
    /// I/O lane. Returns true only when the whole family is gone.
    fn retireFamilyWithIoHeld(self: *DiskCache, guard: IoGuard, primary: []const u8) bool {
        self.mutex.lock();
        if (self.disabled) {
            self.mutex.unlock();
            return false;
        }
        const snapshot: VaryIndexEntry = if (self.vary_index.get(primary)) |family| family else {
            self.mutex.unlock();
            return true;
        };
        self.mutex.unlock();
        var complete = true;
        for (snapshot.variant_keys[0..snapshot.count]) |*sibling| {
            switch (self.retireVictimWithLanes(guard, sibling, primary)) {
                .retired, .gone => {},
                .busy => complete = false,
                .failed => return false,
            }
        }
        return complete;
    }

    /// Vary -> direct. A single durable fence at the primary is written
    /// before any sibling is retired, so a busy lane or a crash between
    /// sibling unlinks can only leave variants that restart masks. Returns
    /// true when the family is fully retired and the direct record may
    /// replace the fence.
    fn fenceAndRetireFamilyWithIoHeld(self: *DiskCache, guard: IoGuard, primary: []const u8, now_ms: u64) bool {
        self.mutex.lock();
        if (self.disabled) {
            self.mutex.unlock();
            return false;
        }
        if (!self.vary_index.contains(primary)) {
            self.mutex.unlock();
            return true;
        }
        const fenced = self.isFencedLocked(primary);
        self.mutex.unlock();

        var fence_failed = false;
        if (!fenced) {
            var marker: [tombstone_bytes]u8 = undefined;
            encodeFence(&marker, primary, self.fingerprint);
            if (self.state_dir.writeFileAtomicLimit(primary, &marker, 0o600, tombstone_bytes)) |_| {
                if (!self.publishFence(primary, now_ms)) return false;
            } else |_| {
                fence_failed = true;
            }
        }
        const complete = self.retireFamilyWithIoHeld(guard, primary);
        if (!complete and fence_failed) {
            // No durable fence and the family could not be fully retired:
            // stop trusting the disk tier rather than risk a stale replay.
            self.mutex.lock();
            self.disableLocked();
            self.mutex.unlock();
        }
        return complete;
    }

    fn publishFence(self: *DiskCache, primary: []const u8, now_ms: u64) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.disabled) return false;
        if (self.index.getPtr(primary)) |existing| {
            self.total_bytes -= existing.bytes;
            existing.* = .{ .bytes = tombstone_bytes, .last_used_ms = now_ms, .tombstone = true, .fence = true };
            self.total_bytes += tombstone_bytes;
            return true;
        }
        const owned = self.allocator.dupe(u8, primary) catch {
            self.disableLocked();
            return false;
        };
        // Same capacity protocol as put(): leave room for every outstanding
        // reservation plus this insertion.
        self.index.ensureUnusedCapacity(@intCast(self.reserved_entries + 1)) catch {
            self.allocator.free(owned);
            self.disableLocked();
            return false;
        };
        self.index.putAssumeCapacity(owned, .{ .bytes = tombstone_bytes, .last_used_ms = now_ms, .tombstone = true, .fence = true });
        self.total_bytes += tombstone_bytes;
        return true;
    }

    const RetireResult = enum { retired, gone, busy, failed };

    /// Retires one tracked victim while the caller already holds the I/O
    /// lanes in `held`. The victim's own lane is acquired with `tryLock`
    /// (never a blocking nested acquire, which could deadlock against a
    /// writer holding the victim's lane and waiting on ours), and the entry
    /// is re-validated under the index mutex once the lane is owned. Because
    /// the lane is held across detach and unlink, a concurrent writer of the
    /// victim cannot publish a newer file that this unlink would then delete.
    fn retireVictimWithLanes(self: *DiskCache, held: IoGuard, victim: *const [key_len]u8, vary_primary: ?[]const u8) RetireResult {
        const lane = ioLane(victim);
        const own_lane = lane == held.first or (held.second != null and lane == held.second.?);
        if (!own_lane and !self.io_lanes[lane].tryLock()) return .busy;
        defer if (!own_lane) self.io_lanes[lane].unlock();

        self.mutex.lock();
        if (self.disabled) {
            self.mutex.unlock();
            return .failed;
        }
        const tracked = self.index.getPtr(victim) orelse {
            if (vary_primary) |primary| self.pruneVariantLocked(primary, victim);
            self.mutex.unlock();
            return .gone;
        };
        if (vary_primary) |primary| {
            // The victim must still be a variant of this primary; a
            // repurposed key (now direct, or under another primary) is not
            // ours to delete. Only the stale reference is dropped.
            const still_ours = if (tracked.vary_primary_key) |stored| std.mem.eql(u8, stored[0..], primary) else false;
            if (!still_ours) {
                self.pruneVariantLocked(primary, victim);
                self.mutex.unlock();
                return .gone;
            }
        }
        if (tracked.pending_write) {
            self.mutex.unlock();
            return .busy;
        }
        const owned = self.detachLocked(victim) orelse {
            self.mutex.unlock();
            return .gone;
        };
        self.mutex.unlock();
        defer self.allocator.free(owned);
        self.state_dir.removeFileDurable(owned) catch {
            self.mutex.lock();
            self.disableLocked();
            self.mutex.unlock();
            return .failed;
        };
        return .retired;
    }

    /// Startup-only quota reconciliation. No other thread can observe this
    /// object yet, so filesystem cleanup does not need the runtime mutex.
    fn evictToFitLocked(self: *DiskCache) void {
        var guard: usize = 0;
        while ((self.index.count() > self.limits.max_entries or self.total_bytes > self.limits.max_total_bytes) and guard < self.limits.max_entries + 1) {
            guard += 1;
            const victim = self.oldestKeyLocked(null, &.{}) orelse break;
            const owned = self.detachLocked(victim) orelse continue;
            defer self.allocator.free(owned);
            // An unverifiable deletion would leave the index smaller than
            // the directory, so fail closed instead of under-reporting.
            self.state_dir.removeFileDurable(owned) catch {
                self.disableLocked();
                return;
            };
        }
    }

    /// Best-effort delete, forgetting the key whether or not it was tracked
    /// (a file can exist on disk without an index entry after a startup
    /// scan truncated by `scan_cap`, or never have been written at all).
    pub fn remove(self: *DiskCache, key: []const u8) void {
        if (!isHexLowerKey(key)) return;
        const io_guard = self.lockIo(key, null);
        defer io_guard.unlock();
        self.removeWithIoHeld(key);
    }

    fn removeWithIoHeld(self: *DiskCache, key: []const u8) void {
        self.mutex.lock();
        if (self.disabled) {
            self.mutex.unlock();
            return;
        }
        const owned = self.detachLocked(key);
        self.mutex.unlock();
        // Also remove a valid but untracked file (for example, one left by a
        // failed process between rename and index publication). No global
        // index mutex is held while touching the filesystem.
        // Explicit invalidation (policy change, corruption) must survive a
        // power loss; on a fault stop serving the disk tier altogether.
        self.state_dir.removeFileDurable(owned orelse key) catch {
            self.mutex.lock();
            self.disableLocked();
            self.mutex.unlock();
        };
        if (owned) |removed_key| self.allocator.free(removed_key);
    }

    /// Replace an obsolete direct representation with a small durable marker
    /// before attempting a Vary variant write. A crash or failed candidate
    /// write can therefore yield only a miss, never resurrect the direct
    /// response under a different Accept-Encoding policy.
    fn installTombstoneWithIoHeld(self: *DiskCache, key: []const u8, now_ms: u64) bool {
        self.mutex.lock();
        if (self.disabled) {
            self.mutex.unlock();
            return false;
        }
        const existing = self.index.getPtr(key) orelse {
            self.mutex.unlock();
            return true;
        };
        if (existing.tombstone or existing.vary_primary_key != null) {
            self.mutex.unlock();
            return true;
        }
        existing.pending_write = true;
        self.mutex.unlock();

        var marker: [tombstone_bytes]u8 = undefined;
        encodeTombstone(&marker, key, self.fingerprint);
        self.state_dir.writeFileAtomicLimit(key, &marker, 0o600, tombstone_bytes) catch {
            // The marker never replaced the old direct file, so a restart
            // would recover it under the stale policy. Retire that file
            // durably instead; only if even that fails is the tier disabled.
            const retired = self.state_dir.removeFileDurable(key);
            self.mutex.lock();
            if (retired) |_| {
                if (self.detachLocked(key)) |owned| self.allocator.free(owned);
            } else |_| {
                self.disableLocked();
            }
            self.mutex.unlock();
            return false;
        };

        self.mutex.lock();
        if (self.disabled) {
            self.mutex.unlock();
            return false;
        }
        if (self.index.fetchRemove(key)) |removed| {
            self.total_bytes -= removed.value.bytes;
            if (removed.value.vary_primary_key) |primary| self.pruneVariantLocked(primary[0..], removed.key);
            self.index.putAssumeCapacity(removed.key, .{
                .bytes = tombstone_bytes,
                .last_used_ms = now_ms,
                .pending_write = true,
                .tombstone = true,
            });
            self.total_bytes += tombstone_bytes;
        }
        self.mutex.unlock();
        return true;
    }

    fn releaseTombstonePendingWithIoHeld(self: *DiskCache, key: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.index.getPtr(key)) |value| {
            if (value.tombstone) value.pending_write = false;
        }
    }

    /// Once at least one replacement variant is durable, the marker is no
    /// longer needed. Its unlink is directory-fsynced before index accounting
    /// is released; on failure the tier disables instead of admitting writes
    /// against an unprovable disk footprint.
    fn retireTombstoneWithIoHeld(self: *DiskCache, key: []const u8) void {
        self.mutex.lock();
        const tracked = if (self.index.get(key)) |value| value.tombstone else false;
        self.mutex.unlock();
        if (!tracked) return;
        self.state_dir.removeFileDurable(key) catch {
            self.mutex.lock();
            self.disableLocked();
            self.mutex.unlock();
            return;
        };
        self.mutex.lock();
        const owned = if (self.index.get(key)) |value| if (value.tombstone) self.detachLocked(key) else null else null;
        self.mutex.unlock();
        if (owned) |removed| self.allocator.free(removed);
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
        if (record.vary_primary_key) |primary| if (!isHexLowerKey(primary)) return;
        const io_guard = self.lockIo(key, record.vary_primary_key);
        defer io_guard.unlock();
        var tombstone_primary: ?[]const u8 = null;
        var retire_tombstone = false;
        defer if (tombstone_primary) |primary| {
            if (retire_tombstone)
                self.retireTombstoneWithIoHeld(primary)
            else
                self.releaseTombstonePendingWithIoHeld(primary);
        };

        // A representation-policy transition retires the incompatible disk
        // shape before attempting the new write. If the write then fails or
        // the process crashes, restart observes a safe miss instead of an
        // old unvaried/varied representation under the new policy.
        if (record.vary_primary_key) |primary| {
            // A fenced family is obsolete: it must be gone before the
            // primary may become varied again.
            self.mutex.lock();
            const fenced = self.isFencedLocked(primary);
            self.mutex.unlock();
            if (fenced and !self.retireFamilyWithIoHeld(io_guard, primary)) return;
            if (!self.installTombstoneWithIoHeld(primary, now_ms)) return;
            tombstone_primary = primary;
        } else if (!self.fenceAndRetireFamilyWithIoHeld(io_guard, key, now_ms)) {
            return;
        }

        // The policy fence above has already run, so every refusal below
        // leaves at worst a safe miss on disk, never the obsolete shape.
        if (record.reason.len > max_reason_bytes) return;
        if (record.headers.len > max_headers) return;
        for (record.headers) |h| {
            if (h.name.len > max_header_name_bytes or h.value.len > max_header_value_bytes) return;
        }
        const object_bytes = recordBytes(key, record);
        if (object_bytes > self.limits.max_object_bytes) return;

        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.allocator);
        const now_unix_ms = self.unixNowMs() orelse return;
        encodeRecord(self.allocator, &buf, key, record, self.fingerprint, now_ms, now_unix_ms) catch return;
        // Keep each primary's variant set bounded before reserving the new
        // record. The primary I/O lane prevents another variant writer from
        // changing this set while the filesystem operation is in flight.
        if (record.vary_primary_key) |primary| {
            while (true) {
                self.mutex.lock();
                if (self.disabled) {
                    self.mutex.unlock();
                    return;
                }
                const victim: ?[key_len]u8 = if (self.vary_index.getPtr(primary)) |index| blk: {
                    if (index.indexOf(key) != null or index.count < self.max_vary_variants) break :blk null;
                    break :blk index.variant_keys[0];
                } else null;
                if (victim == null) {
                    self.mutex.unlock();
                    break;
                }
                self.mutex.unlock();
                // The FIFO victim is a different key with its own I/O lane;
                // retire it under that lane with a durable unlink. If its
                // lane is busy the new variant is simply not persisted.
                switch (self.retireVictimWithLanes(io_guard, &victim.?, primary)) {
                    .retired, .gone => {},
                    .busy, .failed => return,
                }
            }
        }

        const candidate_bytes = buf.items.len;
        var owned_key: ?[]u8 = self.allocator.dupe(u8, key) catch return;
        defer if (owned_key) |owned| self.allocator.free(owned);
        var owned_primary: ?[]u8 = if (record.vary_primary_key) |primary| self.allocator.dupe(u8, primary) catch return else null;
        defer if (owned_primary) |owned| self.allocator.free(owned);

        var reserved_entry: usize = 0;
        var reserved_growth: usize = 0;
        var reserved_vary_primary: usize = 0;
        var skipped: [8][key_len]u8 = undefined;
        var skipped_count: usize = 0;
        while (true) {
            self.mutex.lock();
            if (self.disabled) {
                self.mutex.unlock();
                return;
            }
            const existing = self.index.get(key);
            reserved_entry = if (existing == null) 1 else 0;
            const existing_bytes = if (existing) |value| value.bytes else 0;
            reserved_growth = candidate_bytes -| existing_bytes;
            const entries_fit = self.reserved_entries + reserved_entry <= self.limits.max_entries -| self.index.count();
            const bytes_fit = self.reserved_bytes + reserved_growth <= self.limits.max_total_bytes -| self.total_bytes;
            if (entries_fit and bytes_fit) {
                if (existing == null) self.index.ensureUnusedCapacity(@intCast(self.reserved_entries + reserved_entry)) catch {
                    self.mutex.unlock();
                    return;
                } else if (self.index.getPtr(key)) |value| {
                    value.pending_write = true;
                }
                if (record.vary_primary_key != null) {
                    reserved_vary_primary = 1;
                    self.vary_index.ensureUnusedCapacity(@intCast(self.reserved_vary_primaries + reserved_vary_primary)) catch {
                        if (self.index.getPtr(key)) |value| value.pending_write = false;
                        self.mutex.unlock();
                        return;
                    };
                }
                self.reserved_entries += reserved_entry;
                self.reserved_bytes += reserved_growth;
                self.reserved_vary_primaries += reserved_vary_primary;
                self.mutex.unlock();
                break;
            }

            const victim_ptr = self.oldestKeyLocked(key, skipped[0..skipped_count]) orelse {
                self.mutex.unlock();
                return;
            };
            var victim: [key_len]u8 = undefined;
            @memcpy(victim[0..], victim_ptr);
            self.mutex.unlock();
            switch (self.retireVictimWithLanes(io_guard, &victim, null)) {
                .retired, .gone => continue,
                .busy => {
                    // Another writer owns that victim's lane right now;
                    // look for a different one rather than waiting.
                    if (skipped_count == skipped.len) return;
                    skipped[skipped_count] = victim;
                    skipped_count += 1;
                    continue;
                },
                .failed => return,
            }
        }

        if (self.test_write_barrier) |barrier| barrier.pauseIfMatched(key);
        const write_succeeded = blk: {
            self.state_dir.writeFileAtomicLimit(key, buf.items, 0o600, self.limits.max_object_bytes + record_overhead_bytes) catch break :blk false;
            break :blk true;
        };

        self.mutex.lock();
        self.reserved_entries -= reserved_entry;
        self.reserved_bytes -= reserved_growth;
        self.reserved_vary_primaries -= reserved_vary_primary;
        if (!write_succeeded or self.disabled) {
            if (self.index.getPtr(key)) |value| value.pending_write = false;
            self.mutex.unlock();
            return;
        }

        var final_key: []const u8 = owned_key.?;
        var used_new_key = true;
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
            used_new_key = false;
        }
        var vary_primary: ?[key_len]u8 = null;
        if (record.vary_primary_key) |primary| {
            var primary_buf: [key_len]u8 = undefined;
            @memcpy(primary_buf[0..], primary);
            vary_primary = primary_buf;
        }
        self.index.putAssumeCapacity(final_key, .{ .bytes = candidate_bytes, .last_used_ms = now_ms, .vary_primary_key = vary_primary });
        if (used_new_key) owned_key = null;
        self.total_bytes += candidate_bytes;

        if (record.vary_primary_key) |primary| {
            if (self.vary_index.getPtr(primary)) |index| {
                if (index.indexOf(key) == null) {
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
        }
        self.mutex.unlock();
        retire_tombstone = record.vary_primary_key != null;
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
        const io_guard = self.lockIo(key, null);
        defer io_guard.unlock();
        self.mutex.lock();
        if (self.disabled) {
            self.mutex.unlock();
            return null;
        }
        const masked = self.isMaskedRecordLocked(key);
        self.mutex.unlock();
        if (masked) return null;

        const raw = self.state_dir.readFileAlloc(scratch, key, self.limits.max_object_bytes + record_overhead_bytes, false) catch {
            self.removeWithIoHeld(key);
            return null;
        };
        if (self.test_read_barrier) |barrier| barrier.pauseIfMatched(key);
        const maybe_decoded = decodeRecord(scratch, raw) catch return null;
        const decoded = maybe_decoded orelse {
            self.removeWithIoHeld(key);
            return null;
        };
        if (decoded.fingerprint != self.fingerprint or !std.mem.eql(u8, decoded.key, key)) {
            self.removeWithIoHeld(key);
            return null;
        }
        const now_unix_ms = self.unixNowMs() orelse return null;
        // A backward wall-clock jump is treated as an unprovable age and a
        // safe miss. Forward jumps only expire records sooner. Persisted
        // freshness can therefore never become valid again when the host's
        // monotonic epoch resets across a reboot.
        if (now_unix_ms < decoded.record.stored_at_unix_ms or now_unix_ms >= decoded.record.swr_until_unix_ms) {
            self.removeWithIoHeld(key);
            return null;
        }

        const resident_seconds = (now_unix_ms - decoded.record.stored_at_unix_ms) / 1000;
        const age_seconds: u32 = @intCast(@min(@as(u64, decoded.record.initial_age_seconds) + resident_seconds, std.math.maxInt(u32)));
        const loaded = LoadedRecord{
            .status_code = decoded.record.status_code,
            .reason = decoded.record.reason,
            .headers = decoded.record.headers,
            .body = decoded.record.body,
            .stored_at_ms = now_ms,
            .expires_at_ms = unixToMonotonic(decoded.record.expires_at_unix_ms, now_unix_ms, now_ms),
            .swr_until_ms = unixToMonotonic(decoded.record.swr_until_unix_ms, now_unix_ms, now_ms),
            .initial_age_seconds = age_seconds,
            .vary_primary_key = decoded.record.vary_primary_key,
        };

        // Re-check immediately before returning: a concurrent writer could
        // have installed the primary's fence while this read was in flight
        // (the test read barrier proves this interleaving), and that must
        // still mask an already-decoded, otherwise-valid record.
        self.mutex.lock();
        if (self.disabled or self.isMaskedRecordLocked(key)) {
            self.mutex.unlock();
            return null;
        }
        if (self.index.getPtr(key)) |value| value.last_used_ms = now_ms;
        self.mutex.unlock();
        return loaded;
    }

    pub fn isVaryTracked(self: *DiskCache, primary_key: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.disabled) return false;
        if (self.index.get(primary_key)) |marker| if (marker.fence) return false;
        return self.vary_index.contains(primary_key);
    }
};

fn writeLenPrefixed(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime LenT: type, bytes: []const u8) !void {
    var len_buf: [@sizeOf(LenT)]u8 = undefined;
    std.mem.writeInt(LenT, &len_buf, @intCast(bytes.len), .little);
    try buf.appendSlice(allocator, &len_buf);
    try buf.appendSlice(allocator, bytes);
}

fn monotonicToUnix(monotonic_ms: u64, now_ms: u64, now_unix_ms: u64) u64 {
    return if (monotonic_ms >= now_ms)
        now_unix_ms +| (monotonic_ms - now_ms)
    else
        now_unix_ms -| (now_ms - monotonic_ms);
}

fn unixToMonotonic(unix_ms: u64, now_unix_ms: u64, now_ms: u64) u64 {
    return if (unix_ms >= now_unix_ms)
        now_ms +| (unix_ms - now_unix_ms)
    else
        now_ms -| (now_unix_ms - unix_ms);
}

fn encodeRecord(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    key: []const u8,
    record: PutRecord,
    fingerprint: u64,
    now_ms: u64,
    now_unix_ms: u64,
) !void {
    try buf.appendSlice(allocator, &record_magic);
    var u64_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &u64_buf, fingerprint, .little);
    try buf.appendSlice(allocator, &u64_buf);
    var u16_buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &u16_buf, record.status_code, .little);
    try buf.appendSlice(allocator, &u16_buf);
    std.mem.writeInt(u64, &u64_buf, monotonicToUnix(record.stored_at_ms, now_ms, now_unix_ms), .little);
    try buf.appendSlice(allocator, &u64_buf);
    std.mem.writeInt(u64, &u64_buf, monotonicToUnix(record.expires_at_ms, now_ms, now_unix_ms), .little);
    try buf.appendSlice(allocator, &u64_buf);
    std.mem.writeInt(u64, &u64_buf, monotonicToUnix(record.swr_until_ms, now_ms, now_unix_ms), .little);
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

fn encodeTombstone(out: *[tombstone_bytes]u8, key: []const u8, fingerprint: u64) void {
    encodeMarker(out, tombstone_magic, key, fingerprint);
}

fn encodeFence(out: *[tombstone_bytes]u8, key: []const u8, fingerprint: u64) void {
    encodeMarker(out, fence_magic, key, fingerprint);
}

fn encodeMarker(out: *[tombstone_bytes]u8, magic: [tombstone_magic.len]u8, key: []const u8, fingerprint: u64) void {
    @memcpy(out[0..tombstone_magic.len], &magic);
    std.mem.writeInt(u64, out[tombstone_magic.len..][0..8], fingerprint, .little);
    const key_offset = tombstone_magic.len + 8;
    @memcpy(out[key_offset..][0..key_len], key);
    const checksum_offset = key_offset + key_len;
    const checksum = std.hash.Wyhash.hash(0x544f_4d42_5354, out[0..checksum_offset]);
    std.mem.writeInt(u64, out[checksum_offset..][0..8], checksum, .little);
}

fn isTombstone(raw: []const u8, key: []const u8, fingerprint: u64) bool {
    return isMarker(raw, tombstone_magic, key, fingerprint);
}

fn isFence(raw: []const u8, key: []const u8, fingerprint: u64) bool {
    return isMarker(raw, fence_magic, key, fingerprint);
}

fn isMarker(raw: []const u8, magic: [tombstone_magic.len]u8, key: []const u8, fingerprint: u64) bool {
    if (raw.len != tombstone_bytes) return false;
    if (!std.mem.eql(u8, raw[0..tombstone_magic.len], &magic)) return false;
    const stored_fingerprint = std.mem.readInt(u64, raw[tombstone_magic.len..][0..8], .little);
    if (stored_fingerprint != fingerprint) return false;
    const key_offset = tombstone_magic.len + 8;
    if (!std.mem.eql(u8, raw[key_offset..][0..key_len], key)) return false;
    const checksum_offset = key_offset + key_len;
    const expected = std.mem.readInt(u64, raw[checksum_offset..][0..8], .little);
    return expected == std.hash.Wyhash.hash(0x544f_4d42_5354, raw[0..checksum_offset]);
}

const Decoded = struct {
    fingerprint: u64,
    key: []const u8,
    record: PersistedRecord,
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
    const stored_at_unix_ms = r.readU64() orelse return null;
    const expires_at_unix_ms = r.readU64() orelse return null;
    const swr_until_unix_ms = r.readU64() orelse return null;
    const initial_age_seconds = r.readU32() orelse return null;

    const key = r.readLenPrefixed(u16, key_len) orelse return null;
    const vary_primary_raw = r.readLenPrefixed(u16, key_len) orelse return null;
    if (vary_primary_raw.len != 0 and !isHexLowerKey(vary_primary_raw)) return null;
    const vary_primary_key: ?[]const u8 = if (vary_primary_raw.len == 0) null else vary_primary_raw;
    const reason = r.readLenPrefixed(u16, max_reason_bytes) orelse return null;

    const header_count = r.readU16() orelse return null;
    if (header_count > max_headers) return null;
    var header_buf: [max_headers]gpc.CacheHeader = undefined;
    var i: usize = 0;
    while (i < header_count) : (i += 1) {
        const name = r.readLenPrefixed(u16, max_header_name_bytes) orelse return null;
        const value = r.readLenPrefixed(u32, max_header_value_bytes) orelse return null;
        if (!gpc.isPersistableResponseHeaderName(name)) return null;
        header_buf[i] = .{ .name = @constCast(name), .value = @constCast(value) };
    }
    const body = r.readLenPrefixed(u32, std.math.maxInt(u32)) orelse return null;
    if (!r.atEnd()) return null;
    const headers = try scratch.alloc(gpc.CacheHeader, header_count);
    @memcpy(headers, header_buf[0..header_count]);

    return .{
        .fingerprint = fingerprint,
        .key = key,
        .record = .{
            .status_code = status_code,
            .reason = reason,
            .headers = headers,
            .body = body,
            .stored_at_unix_ms = stored_at_unix_ms,
            .expires_at_unix_ms = expires_at_unix_ms,
            .swr_until_unix_ms = swr_until_unix_ms,
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

fn testHexKey(out: *[key_len]u8, value: u64) []const u8 {
    @memset(out, '0');
    _ = std.fmt.bufPrint(out[key_len - 16 ..], "{x:0>16}", .{value}) catch unreachable;
    return out[0..];
}

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
    try encodeRecord(allocator, &buf, key, record, 0xABCD, 1_000, 1_700_000_000_000);

    const decoded = (try decodeRecord(arena.allocator(), buf.items)).?;
    try std.testing.expectEqual(@as(u64, 0xABCD), decoded.fingerprint);
    try std.testing.expectEqualStrings(key, decoded.key);
    try std.testing.expectEqual(@as(u16, 200), decoded.record.status_code);
    try std.testing.expectEqualStrings("OK", decoded.record.reason);
    try std.testing.expectEqual(@as(usize, 2), decoded.record.headers.len);
    try std.testing.expectEqualStrings("Content-Type", decoded.record.headers[0].name);
    try std.testing.expectEqualStrings("hello disk cache", decoded.record.body);
    try std.testing.expectEqual(@as(u64, 1_700_000_060_000), decoded.record.expires_at_unix_ms);
    try std.testing.expectEqual(@as(u64, 1_700_000_120_000), decoded.record.swr_until_unix_ms);

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

test "decodeRecord rejects a checksummed record containing a forbidden response header" {
    const allocator = std.testing.allocator;
    const key = "f" ** 64;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try encodeRecord(allocator, &buf, key, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{
            .{ .name = "Cache-Control", .value = "public, max-age=60" },
            .{ .name = "X-Auth", .value = "Bearer forbidden-on-disk" },
        },
        .body = "body",
        .stored_at_ms = 1_000,
        .expires_at_ms = 61_000,
        .swr_until_ms = 61_000,
        .initial_age_seconds = 0,
    }, 7, 1_000, 1_700_000_000_000);
    try std.testing.expectEqual(@as(?Decoded, null), try decodeRecord(allocator, buf.items));
}

test "DiskCache put/get round-trips, enforces the config fingerprint and evicts past the stale-while-revalidate deadline" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);

    var cache = try DiskCache.init(allocator, root_path, .{ .max_object_bytes = 4096, .max_entries = 4, .max_total_bytes = 1 << 20 }, 111);
    defer cache.deinit();
    cache.test_unix_now_ms = 10_000;

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
    cache.test_unix_now_ms = 10_500;
    const hit = cache.get(arena.allocator(), key, 500) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("cached body", hit.body);

    // Still inside the stale-while-revalidate window (past `expires_at_ms`
    // but before `swr_until_ms`): the disk tier itself does not evict or
    // refuse this -- freshness-vs-staleness classification is the caller's
    // job (`gateway_proxy_cache.zig`/`GatewayState`), same split as the
    // in-memory cache.
    cache.test_unix_now_ms = 11_500;
    const stale_hit = cache.get(arena.allocator(), key, 1_500) orelse return error.TestExpectedEqual;
    try std.testing.expectEqualStrings("cached body", stale_hit.body);

    // Past the stale-while-revalidate deadline: a safe miss, and the file is
    // gone so a fresh process would not find it either.
    cache.test_unix_now_ms = 12_500;
    try std.testing.expectEqual(@as(?LoadedRecord, null), cache.get(arena.allocator(), key, 2_500));

    // A different config fingerprint never sees a hit, even immediately
    // after a fresh write under the matching one.
    cache.test_unix_now_ms = 20_000;
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

test "DiskCache wall-clock expiry cannot resurrect when the monotonic epoch repeats after reboot" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    const limits = Limits{ .max_object_bytes = 4096, .max_entries = 4, .max_total_bytes = 1 << 20 };
    const key = "0" ** 64;
    const old_uptime_ms: u64 = 10 * 60 * 60 * 1000;
    const old_unix_ms: u64 = 1_700_000_000_000;
    {
        var cache = try DiskCache.init(allocator, root_path, limits, 43);
        defer cache.deinit();
        cache.test_unix_now_ms = old_unix_ms;
        cache.put(key, .{
            .status_code = 200,
            .reason = "OK",
            .headers = &.{.{ .name = "Cache-Control", .value = "max-age=60" }},
            .body = "old-boot-body",
            .stored_at_ms = old_uptime_ms,
            .expires_at_ms = old_uptime_ms + 60_000,
            .swr_until_ms = old_uptime_ms + 60_000,
            .initial_age_seconds = 0,
        }, old_uptime_ms);
    }

    var rebooted = try DiskCache.init(allocator, root_path, limits, 43);
    defer rebooted.deinit();
    // Wall time is well beyond expiry, while the new boot's monotonic clock
    // has reached the exact old uptime that previously made this entry fresh.
    rebooted.test_unix_now_ms = old_unix_ms + 24 * 60 * 60 * 1000;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try std.testing.expect(rebooted.get(arena.allocator(), key, old_uptime_ms + 30_000) == null);
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

test "DiskCache stalled write does not block a disjoint write or Vary metadata lookup" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    var cache = try DiskCache.init(allocator, root_path, .{ .max_object_bytes = 4096, .max_entries = 8, .max_total_bytes = 1 << 20 }, 55);
    defer cache.deinit();
    const key_a = "1" ** 64;
    const candidates = [_][]const u8{ "2" ** 64, "3" ** 64, "4" ** 64, "5" ** 64 };
    var key_b = candidates[0];
    for (candidates) |candidate| {
        if (DiskCache.ioLane(candidate) != DiskCache.ioLane(key_a)) {
            key_b = candidate;
            break;
        }
    }
    try std.testing.expect(DiskCache.ioLane(key_a) != DiskCache.ioLane(key_b));
    const vary_primary = "a" ** 64;
    const vary_secondary = "b" ** 64;
    const headers = [_]gpc.CacheHeaderView{.{ .name = "Cache-Control", .value = "max-age=60" }};
    const record = PutRecord{
        .status_code = 200,
        .reason = "OK",
        .headers = &headers,
        .body = "body",
        .stored_at_ms = 0,
        .expires_at_ms = 60_000,
        .swr_until_ms = 60_000,
        .initial_age_seconds = 0,
    };
    var vary_record = record;
    vary_record.vary_primary_key = vary_primary;
    cache.put(vary_secondary, vary_record, 0);

    var barrier = TestWriteBarrier{ .key = key_a };
    cache.test_write_barrier = &barrier;
    const PutWorker = struct {
        fn run(target: *DiskCache, key: []const u8, value: PutRecord, started: *std.atomic.Value(bool), done: *std.atomic.Value(bool)) void {
            started.store(true, .release);
            target.put(key, value, 1);
            done.store(true, .release);
        }
    };
    var a_started = std.atomic.Value(bool).init(false);
    var a_done = std.atomic.Value(bool).init(false);
    const writer_a = try std.Thread.spawn(.{}, PutWorker.run, .{ &cache, key_a, record, &a_started, &a_done });
    while (!a_started.load(.acquire)) std.atomic.spinLoopHint();
    barrier.waitUntilReached();

    var b_started = std.atomic.Value(bool).init(false);
    var b_done = std.atomic.Value(bool).init(false);
    const writer_b = std.Thread.spawn(.{}, PutWorker.run, .{ &cache, key_b, record, &b_started, &b_done }) catch |err| {
        barrier.release();
        writer_a.join();
        return err;
    };
    while (!b_started.load(.acquire)) std.atomic.spinLoopHint();

    var vary_done = std.atomic.Value(bool).init(false);
    var vary_tracked = false;
    const VaryWorker = struct {
        fn run(target: *DiskCache, primary: []const u8, result: *bool, done: *std.atomic.Value(bool)) void {
            result.* = target.isVaryTracked(primary);
            done.store(true, .release);
        }
    };
    const vary_reader = std.Thread.spawn(.{}, VaryWorker.run, .{ &cache, vary_primary, &vary_tracked, &vary_done }) catch |err| {
        barrier.release();
        writer_a.join();
        writer_b.join();
        return err;
    };
    var attempts: usize = 0;
    while ((!b_done.load(.acquire) or !vary_done.load(.acquire)) and attempts < 100) : (attempts += 1) {
        std.Io.sleep(compat.io(), std.Io.Duration.fromMilliseconds(1), .awake) catch {};
    }
    const disjoint_write_completed = b_done.load(.acquire);
    const vary_lookup_completed = vary_done.load(.acquire);
    barrier.release();
    writer_a.join();
    writer_b.join();
    vary_reader.join();
    cache.test_write_barrier = null;

    try std.testing.expect(disjoint_write_completed);
    try std.testing.expect(vary_lookup_completed);
    try std.testing.expect(vary_tracked);
    try std.testing.expect(a_done.load(.acquire));
}

test "DiskCache reserves hash-map capacity for every concurrent unpublished entry" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    var cache = try DiskCache.init(allocator, root_path, .{ .max_object_bytes = 4096, .max_entries = 256, .max_total_bytes = 1 << 20 }, 56);
    defer cache.deinit();
    const record = PutRecord{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{.{ .name = "Cache-Control", .value = "max-age=60" }},
        .body = "body",
        .stored_at_ms = 0,
        .expires_at_ms = 60_000,
        .swr_until_ms = 60_000,
        .initial_age_seconds = 0,
    };

    var next: u64 = 1;
    while (cache.index.capacity() == 0 or cache.index.count() + 1 < (cache.index.capacity() * std.hash_map.default_max_load_percentage) / 100) : (next += 1) {
        var key_buf: [key_len]u8 = undefined;
        cache.put(testHexKey(&key_buf, next), record, 0);
    }
    const index_load_limit = (cache.index.capacity() * std.hash_map.default_max_load_percentage) / 100;
    try std.testing.expectEqual(index_load_limit - 1, cache.index.count());

    var key_a_buf: [key_len]u8 = undefined;
    const key_a = testHexKey(&key_a_buf, 10_000);
    var key_b_buf: [key_len]u8 = undefined;
    var candidate: u64 = 20_000;
    var key_b = testHexKey(&key_b_buf, candidate);
    while (DiskCache.keysShareIoLane(key_a, key_b)) : (candidate += 1) key_b = testHexKey(&key_b_buf, candidate);

    var barrier = TestWriteBarrier{ .key = key_a };
    cache.test_write_barrier = &barrier;
    const Worker = struct {
        fn run(target: *DiskCache, key: []const u8, value: PutRecord, done: *std.atomic.Value(bool)) void {
            target.put(key, value, 1);
            done.store(true, .release);
        }
    };
    var a_done = std.atomic.Value(bool).init(false);
    const a = try std.Thread.spawn(.{}, Worker.run, .{ &cache, key_a, record, &a_done });
    barrier.waitUntilReached();
    var b_done = std.atomic.Value(bool).init(false);
    const b = std.Thread.spawn(.{}, Worker.run, .{ &cache, key_b, record, &b_done }) catch |err| {
        barrier.release();
        a.join();
        return err;
    };
    var attempts: usize = 0;
    while (!b_done.load(.acquire) and attempts < 100) : (attempts += 1) {
        std.Io.sleep(compat.io(), std.Io.Duration.fromMilliseconds(1), .awake) catch {};
    }
    const b_published_while_a_reserved = b_done.load(.acquire);
    barrier.release();
    a.join();
    b.join();
    cache.test_write_barrier = null;

    try std.testing.expect(b_published_while_a_reserved);
    try std.testing.expect(a_done.load(.acquire));
    try std.testing.expect(cache.index.contains(key_a));
    try std.testing.expect(cache.index.contains(key_b));
}

test "DiskCache reserves Vary-index capacity for every concurrent unpublished primary" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    var cache = try DiskCache.init(allocator, root_path, .{ .max_object_bytes = 4096, .max_entries = 512, .max_total_bytes = 1 << 20 }, 57);
    defer cache.deinit();
    const base = PutRecord{
        .status_code = 200,
        .reason = "OK",
        .headers = &.{
            .{ .name = "Cache-Control", .value = "max-age=60" },
            .{ .name = "Vary", .value = "Accept-Encoding" },
        },
        .body = "variant",
        .stored_at_ms = 0,
        .expires_at_ms = 60_000,
        .swr_until_ms = 60_000,
        .initial_age_seconds = 0,
    };

    var next: u64 = 1;
    while (cache.vary_index.capacity() == 0 or cache.vary_index.count() + 1 < (cache.vary_index.capacity() * std.hash_map.default_max_load_percentage) / 100) : (next += 1) {
        var primary_buf: [key_len]u8 = undefined;
        var secondary_buf: [key_len]u8 = undefined;
        var record = base;
        record.vary_primary_key = testHexKey(&primary_buf, next * 2);
        cache.put(testHexKey(&secondary_buf, next * 2 + 1), record, 0);
    }
    const vary_load_limit = (cache.vary_index.capacity() * std.hash_map.default_max_load_percentage) / 100;
    try std.testing.expectEqual(vary_load_limit - 1, cache.vary_index.count());

    var primary_a_buf: [key_len]u8 = undefined;
    var secondary_a_buf: [key_len]u8 = undefined;
    const primary_a = testHexKey(&primary_a_buf, 50_000);
    const secondary_a = testHexKey(&secondary_a_buf, 50_001);
    var primary_b_buf: [key_len]u8 = undefined;
    var secondary_b_buf: [key_len]u8 = undefined;
    var candidate: u64 = 60_000;
    var primary_b = testHexKey(&primary_b_buf, candidate);
    var secondary_b = testHexKey(&secondary_b_buf, candidate + 1);
    while (DiskCache.keysShareIoLane(primary_a, primary_b) or
        DiskCache.keysShareIoLane(primary_a, secondary_b) or
        DiskCache.keysShareIoLane(secondary_a, primary_b) or
        DiskCache.keysShareIoLane(secondary_a, secondary_b)) : (candidate += 2)
    {
        primary_b = testHexKey(&primary_b_buf, candidate);
        secondary_b = testHexKey(&secondary_b_buf, candidate + 1);
    }

    var barrier = TestWriteBarrier{ .key = secondary_a };
    cache.test_write_barrier = &barrier;
    const Worker = struct {
        fn run(target: *DiskCache, key: []const u8, primary: []const u8, value: PutRecord, done: *std.atomic.Value(bool)) void {
            var variant = value;
            variant.vary_primary_key = primary;
            target.put(key, variant, 1);
            done.store(true, .release);
        }
    };
    var a_done = std.atomic.Value(bool).init(false);
    const a = try std.Thread.spawn(.{}, Worker.run, .{ &cache, secondary_a, primary_a, base, &a_done });
    barrier.waitUntilReached();
    var b_done = std.atomic.Value(bool).init(false);
    const b = std.Thread.spawn(.{}, Worker.run, .{ &cache, secondary_b, primary_b, base, &b_done }) catch |err| {
        barrier.release();
        a.join();
        return err;
    };
    var attempts: usize = 0;
    while (!b_done.load(.acquire) and attempts < 100) : (attempts += 1) {
        std.Io.sleep(compat.io(), std.Io.Duration.fromMilliseconds(1), .awake) catch {};
    }
    const b_published_while_a_reserved = b_done.load(.acquire);
    barrier.release();
    a.join();
    b.join();
    cache.test_write_barrier = null;

    try std.testing.expect(b_published_while_a_reserved);
    try std.testing.expect(a_done.load(.acquire));
    try std.testing.expect(cache.isVaryTracked(primary_a));
    try std.testing.expect(cache.isVaryTracked(primary_b));
}

test "DiskCache failed direct-to-Vary transition cannot revive the direct record after restart" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    const limits = Limits{ .max_object_bytes = 4096, .max_entries = 8, .max_total_bytes = 1 << 20 };
    const primary = "c" ** 64;
    const secondary = "d" ** 64;
    const headers = [_]gpc.CacheHeaderView{.{ .name = "Cache-Control", .value = "max-age=60" }};
    {
        var cache = try DiskCache.init(allocator, root_path, limits, 88);
        defer cache.deinit();
        cache.put(primary, .{
            .status_code = 200,
            .reason = "OK",
            .headers = &headers,
            .body = "old direct",
            .stored_at_ms = 0,
            .expires_at_ms = 60_000,
            .swr_until_ms = 60_000,
            .initial_age_seconds = 0,
        }, 0);
        cache.state_dir.fault = .write;
        cache.state_dir.fault_file = secondary;
        cache.put(secondary, .{
            .status_code = 200,
            .reason = "OK",
            .headers = &headers,
            .body = "new variant",
            .stored_at_ms = 1,
            .expires_at_ms = 60_000,
            .swr_until_ms = 60_000,
            .initial_age_seconds = 0,
            .vary_primary_key = primary,
        }, 1);
        var marker_arena = std.heap.ArenaAllocator.init(allocator);
        defer marker_arena.deinit();
        const marker = try cache.state_dir.readFileAlloc(marker_arena.allocator(), primary, tombstone_bytes, false);
        try std.testing.expect(isTombstone(marker, primary, 88));
    }

    var reopened = try DiskCache.init(allocator, root_path, limits, 88);
    defer reopened.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try std.testing.expect(reopened.get(arena.allocator(), primary, 2) == null);
    try std.testing.expect(reopened.get(arena.allocator(), secondary, 2) == null);
}

test "DiskCache restart quota shrink evicts equal-recency keys deterministically" {
    const allocator = std.testing.allocator;
    var iteration: usize = 0;
    while (iteration < 3) : (iteration += 1) {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
        defer allocator.free(root_path);
        const headers = [_]gpc.CacheHeaderView{};
        const record = PutRecord{
            .status_code = 200,
            .reason = "OK",
            .headers = &headers,
            .body = "same",
            .stored_at_ms = 0,
            .expires_at_ms = 60_000,
            .swr_until_ms = 60_000,
            .initial_age_seconds = 0,
        };
        {
            var writer = try DiskCache.init(allocator, root_path, .{ .max_object_bytes = 4096, .max_entries = 4, .max_total_bytes = 1 << 20 }, 99);
            defer writer.deinit();
            writer.put("1" ** 64, record, 0);
            writer.put("2" ** 64, record, 0);
            writer.put("3" ** 64, record, 0);
        }
        var reopened = try DiskCache.init(allocator, root_path, .{ .max_object_bytes = 4096, .max_entries = 2, .max_total_bytes = 1 << 20 }, 99);
        defer reopened.deinit();
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        try std.testing.expect(reopened.get(arena.allocator(), "1" ** 64, 1) == null);
        try std.testing.expect(reopened.get(arena.allocator(), "2" ** 64, 1) != null);
        try std.testing.expect(reopened.get(arena.allocator(), "3" ** 64, 1) != null);
    }
}

test "DiskCache failed tombstone write retires the direct record so restart cannot revive it" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    const limits = Limits{ .max_object_bytes = 4096, .max_entries = 8, .max_total_bytes = 1 << 20 };
    const primary = "c" ** 64;
    const secondary = "d" ** 64;
    const headers = [_]gpc.CacheHeaderView{.{ .name = "Cache-Control", .value = "max-age=60" }};
    {
        var cache = try DiskCache.init(allocator, root_path, limits, 89);
        defer cache.deinit();
        cache.put(primary, .{
            .status_code = 200,
            .reason = "OK",
            .headers = &headers,
            .body = "old direct",
            .stored_at_ms = 0,
            .expires_at_ms = 60_000,
            .swr_until_ms = 60_000,
            .initial_age_seconds = 0,
        }, 0);
        // The tombstone write itself fails before rename.
        cache.state_dir.fault = .write;
        cache.state_dir.fault_file = primary;
        cache.put(secondary, .{
            .status_code = 200,
            .reason = "OK",
            .headers = &headers,
            .body = "new variant",
            .stored_at_ms = 1,
            .expires_at_ms = 60_000,
            .swr_until_ms = 60_000,
            .initial_age_seconds = 0,
            .vary_primary_key = primary,
        }, 1);
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        try std.testing.expect(cache.get(arena.allocator(), primary, 2) == null);
    }

    var reopened = try DiskCache.init(allocator, root_path, limits, 89);
    defer reopened.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try std.testing.expect(reopened.get(arena.allocator(), primary, 2) == null);
}

test "DiskCache Vary FIFO eviction is durable across restart" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    const limits = Limits{ .max_object_bytes = 4096, .max_entries = 8, .max_total_bytes = 1 << 20, .max_vary_variants = 1 };
    const primary = "c" ** 64;
    const first = "d" ** 64;
    const second = "e" ** 64;
    const headers = [_]gpc.CacheHeaderView{.{ .name = "Cache-Control", .value = "max-age=60" }};
    const record = PutRecord{
        .status_code = 200,
        .reason = "OK",
        .headers = &headers,
        .body = "variant",
        .stored_at_ms = 0,
        .expires_at_ms = 60_000,
        .swr_until_ms = 60_000,
        .initial_age_seconds = 0,
        .vary_primary_key = primary,
    };
    {
        var cache = try DiskCache.init(allocator, root_path, limits, 90);
        defer cache.deinit();
        cache.put(first, record, 0);
        cache.put(second, record, 1);
    }
    var reopened = try DiskCache.init(allocator, root_path, limits, 90);
    defer reopened.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try std.testing.expect(reopened.get(arena.allocator(), first, 2) == null);
    try std.testing.expect(reopened.get(arena.allocator(), second, 2) != null);
}

test "DiskCache quota eviction never unlinks a victim that a concurrent writer is replacing" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    const limits = Limits{ .max_object_bytes = 4096, .max_entries = 2, .max_total_bytes = 1 << 20 };
    const key_b = "1" ** 64;
    const key_c = "2" ** 64;
    const key_a = "3" ** 64;
    const headers = [_]gpc.CacheHeaderView{.{ .name = "Cache-Control", .value = "max-age=60" }};
    var record = PutRecord{
        .status_code = 200,
        .reason = "OK",
        .headers = &headers,
        .body = "old-b",
        .stored_at_ms = 0,
        .expires_at_ms = 60_000,
        .swr_until_ms = 60_000,
        .initial_age_seconds = 0,
    };
    {
        var cache = try DiskCache.init(allocator, root_path, limits, 91);
        defer cache.deinit();
        cache.put(key_b, record, 0);
        record.body = "c";
        cache.put(key_c, record, 5);

        var barrier = TestWriteBarrier{ .key = key_b };
        cache.test_write_barrier = &barrier;
        const PutWorker = struct {
            fn run(target: *DiskCache, key: []const u8, value: PutRecord, now: u64) void {
                target.put(key, value, now);
            }
        };
        var new_b = record;
        new_b.body = "new-b";
        const writer = try std.Thread.spawn(.{}, PutWorker.run, .{ &cache, key_b, new_b, 6 });
        barrier.waitUntilReached();

        // B is the oldest entry but mid-replacement: eviction must skip it
        // and take C, leaving B's lane and file to its writer.
        record.body = "a";
        cache.put(key_a, record, 7);
        barrier.release();
        writer.join();

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const loaded = cache.get(arena.allocator(), key_b, 8) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("new-b", loaded.body);
        try std.testing.expect(cache.get(arena.allocator(), key_c, 8) == null);
    }
    var reopened = try DiskCache.init(allocator, root_path, limits, 91);
    defer reopened.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const loaded = reopened.get(arena.allocator(), key_b, 9) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("new-b", loaded.body);
}

test "DiskCache policy fence runs even when the new candidate fails preflight" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    const limits = Limits{ .max_object_bytes = 1024, .max_entries = 8, .max_total_bytes = 1 << 20 };
    const primary = "c" ** 64;
    const secondary = "d" ** 64;
    const other_primary = "e" ** 64;
    const other_secondary = "f" ** 64;
    const headers = [_]gpc.CacheHeaderView{.{ .name = "Cache-Control", .value = "max-age=60" }};
    const small = PutRecord{
        .status_code = 200,
        .reason = "OK",
        .headers = &headers,
        .body = "small",
        .stored_at_ms = 0,
        .expires_at_ms = 60_000,
        .swr_until_ms = 60_000,
        .initial_age_seconds = 0,
    };
    const oversized_body = [_]u8{'x'} ** 2048;
    var big = small;
    big.body = &oversized_body;
    {
        var cache = try DiskCache.init(allocator, root_path, limits, 92);
        defer cache.deinit();
        // Direct -> Vary with a candidate over the object limit.
        cache.put(primary, small, 0);
        var big_variant = big;
        big_variant.vary_primary_key = primary;
        cache.put(secondary, big_variant, 1);
        // Vary -> direct with a candidate over the object limit.
        var small_variant = small;
        small_variant.vary_primary_key = other_primary;
        cache.put(other_secondary, small_variant, 0);
        cache.put(other_primary, big, 1);
    }
    var reopened = try DiskCache.init(allocator, root_path, limits, 92);
    defer reopened.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try std.testing.expect(reopened.get(arena.allocator(), primary, 2) == null);
    try std.testing.expect(reopened.get(arena.allocator(), other_secondary, 2) == null);
}

test "DiskCache explicit invalidation is durable and disables the tier on an fsync fault" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    const limits = Limits{ .max_object_bytes = 4096, .max_entries = 8, .max_total_bytes = 1 << 20 };
    const key = "c" ** 64;
    const headers = [_]gpc.CacheHeaderView{.{ .name = "Cache-Control", .value = "max-age=60" }};
    var cache = try DiskCache.init(allocator, root_path, limits, 93);
    defer cache.deinit();
    cache.put(key, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &headers,
        .body = "public",
        .stored_at_ms = 0,
        .expires_at_ms = 60_000,
        .swr_until_ms = 60_000,
        .initial_age_seconds = 0,
    }, 0);
    cache.state_dir.fault = .fsync_dir;
    cache.state_dir.fault_file = key;
    cache.remove(key);
    try std.testing.expect(cache.disabled);
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try std.testing.expect(cache.get(arena.allocator(), key, 1) == null);
}

test "DiskCache FIFO retirement refuses a victim no longer associated with the primary" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    const limits = Limits{ .max_object_bytes = 4096, .max_entries = 8, .max_total_bytes = 1 << 20 };
    const primary = "c" ** 64;
    const other_primary = "e" ** 64;
    const victim = "d" ** 64;
    const headers = [_]gpc.CacheHeaderView{.{ .name = "Cache-Control", .value = "max-age=60" }};
    var cache = try DiskCache.init(allocator, root_path, limits, 94);
    defer cache.deinit();
    cache.put(victim, .{
        .status_code = 200,
        .reason = "OK",
        .headers = &headers,
        .body = "repurposed",
        .stored_at_ms = 0,
        .expires_at_ms = 60_000,
        .swr_until_ms = 60_000,
        .initial_age_seconds = 0,
        .vary_primary_key = other_primary,
    }, 0);
    var victim_key: [key_len]u8 = undefined;
    @memcpy(victim_key[0..], victim);
    {
        const guard = cache.lockIo(victim, null);
        defer guard.unlock();
        try std.testing.expectEqual(DiskCache.RetireResult.gone, cache.retireVictimWithLanes(guard, &victim_key, primary));
    }
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try std.testing.expect(cache.get(arena.allocator(), victim, 1) != null);
}

test "DiskCache quota eviction fails closed when the victim cannot be durably unlinked" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    const limits = Limits{ .max_object_bytes = 4096, .max_entries = 1, .max_total_bytes = 1 << 20 };
    const old_key = "1" ** 64;
    const new_key = "2" ** 64;
    const headers = [_]gpc.CacheHeaderView{.{ .name = "Cache-Control", .value = "max-age=60" }};
    const record = PutRecord{
        .status_code = 200,
        .reason = "OK",
        .headers = &headers,
        .body = "body",
        .stored_at_ms = 0,
        .expires_at_ms = 60_000,
        .swr_until_ms = 60_000,
        .initial_age_seconds = 0,
    };
    var cache = try DiskCache.init(allocator, root_path, limits, 95);
    defer cache.deinit();
    cache.put(old_key, record, 0);
    cache.state_dir.fault = .fsync_dir;
    cache.state_dir.fault_file = old_key;
    cache.put(new_key, record, 1);
    try std.testing.expect(cache.disabled);
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try std.testing.expect(cache.get(arena.allocator(), new_key, 2) == null);
}

test "DiskCache Vary-to-direct fences the family durably when a sibling lane is busy" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    const limits = Limits{ .max_object_bytes = 4096, .max_entries = 8, .max_total_bytes = 1 << 20 };
    const primary = "c" ** 64;
    const candidates = [_][]const u8{ "d" ** 64, "e" ** 64, "f" ** 64, "a" ** 64, "b" ** 64, "9" ** 64 };
    var siblings: [2][]const u8 = undefined;
    var found: usize = 0;
    for (candidates) |candidate| {
        if (DiskCache.ioLane(candidate) == DiskCache.ioLane(primary)) continue;
        if (found == 1 and DiskCache.ioLane(candidate) == DiskCache.ioLane(siblings[0])) continue;
        siblings[found] = candidate;
        found += 1;
        if (found == 2) break;
    }
    try std.testing.expectEqual(@as(usize, 2), found);
    const headers = [_]gpc.CacheHeaderView{.{ .name = "Cache-Control", .value = "max-age=60" }};
    const record = PutRecord{
        .status_code = 200,
        .reason = "OK",
        .headers = &headers,
        .body = "variant",
        .stored_at_ms = 0,
        .expires_at_ms = 60_000,
        .swr_until_ms = 60_000,
        .initial_age_seconds = 0,
    };
    {
        var cache = try DiskCache.init(allocator, root_path, limits, 96);
        defer cache.deinit();
        var variant = record;
        variant.vary_primary_key = primary;
        cache.put(siblings[0], variant, 0);
        cache.put(siblings[1], variant, 0);

        // Another operation owns the second sibling's lane: the transition
        // retires the first, cannot retire the second, and must not publish
        // the direct record. The in-process family is masked.
        cache.io_lanes[DiskCache.ioLane(siblings[1])].lock();
        var direct = record;
        direct.body = "direct";
        cache.put(primary, direct, 1);
        cache.io_lanes[DiskCache.ioLane(siblings[1])].unlock();

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        try std.testing.expect(!cache.isVaryTracked(primary));
        try std.testing.expect(cache.get(arena.allocator(), siblings[0], 2) == null);
        // The surviving sibling (its lane was busy during retirement) is
        // still tracked and its file is still on disk -- the regression this
        // test exists for: a fence on the primary must mask it in-process,
        // before any restart gets a chance to durably retire it.
        try std.testing.expect(cache.get(arena.allocator(), siblings[1], 2) == null);
        try std.testing.expect(cache.get(arena.allocator(), primary, 2) == null);
    }
    // Restart: the durable fence masks the surviving sibling.
    var reopened = try DiskCache.init(allocator, root_path, limits, 96);
    defer reopened.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try std.testing.expect(!reopened.isVaryTracked(primary));
    try std.testing.expect(reopened.get(arena.allocator(), siblings[0], 2) == null);
    try std.testing.expect(reopened.get(arena.allocator(), siblings[1], 2) == null);
    try std.testing.expect(reopened.get(arena.allocator(), primary, 2) == null);
}

test "DiskCache get rechecks the primary fence installed while an in-flight secondary read was paused" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    const limits = Limits{ .max_object_bytes = 4096, .max_entries = 8, .max_total_bytes = 1 << 20 };
    const primary = "c" ** 64;
    const candidates = [_][]const u8{ "d" ** 64, "e" ** 64, "f" ** 64, "a" ** 64 };
    var secondary = candidates[0];
    for (candidates) |candidate| {
        if (DiskCache.ioLane(candidate) != DiskCache.ioLane(primary)) {
            secondary = candidate;
            break;
        }
    }
    const headers = [_]gpc.CacheHeaderView{.{ .name = "Cache-Control", .value = "max-age=60" }};
    const record = PutRecord{
        .status_code = 200,
        .reason = "OK",
        .headers = &headers,
        .body = "variant",
        .stored_at_ms = 0,
        .expires_at_ms = 60_000,
        .swr_until_ms = 60_000,
        .initial_age_seconds = 0,
    };
    var cache = try DiskCache.init(allocator, root_path, limits, 98);
    defer cache.deinit();
    var variant = record;
    variant.vary_primary_key = primary;
    cache.put(secondary, variant, 0);

    var read_barrier = TestIoBarrier{ .key = secondary };
    cache.test_read_barrier = &read_barrier;

    const Getter = struct {
        fn run(target: *DiskCache, key: []const u8, saw_hit: *std.atomic.Value(bool)) void {
            var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
            defer arena.deinit();
            const loaded = target.get(arena.allocator(), key, 2);
            saw_hit.store(loaded != null, .release);
        }
    };
    var saw_hit = std.atomic.Value(bool).init(true);
    const getter = try std.Thread.spawn(.{}, Getter.run, .{ &cache, secondary, &saw_hit });
    read_barrier.waitUntilReached();

    // The secondary's own I/O lane is held by the paused read, so its file
    // cannot be retired, but the primary's lane is free: the fence still
    // commits durably while the read sits decoded-but-not-yet-returned.
    var direct = record;
    direct.body = "direct";
    cache.put(primary, direct, 1);
    try std.testing.expect(!cache.isVaryTracked(primary));

    read_barrier.release();
    getter.join();
    cache.test_read_barrier = null;

    try std.testing.expect(!saw_hit.load(.acquire));
}

test "DiskCache failed fence write with a busy sibling disables the tier" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);
    const limits = Limits{ .max_object_bytes = 4096, .max_entries = 8, .max_total_bytes = 1 << 20 };
    const primary = "c" ** 64;
    const candidates = [_][]const u8{ "d" ** 64, "e" ** 64, "f" ** 64, "a" ** 64 };
    var secondary = candidates[0];
    for (candidates) |candidate| {
        if (DiskCache.ioLane(candidate) != DiskCache.ioLane(primary)) {
            secondary = candidate;
            break;
        }
    }
    const headers = [_]gpc.CacheHeaderView{.{ .name = "Cache-Control", .value = "max-age=60" }};
    const record = PutRecord{
        .status_code = 200,
        .reason = "OK",
        .headers = &headers,
        .body = "variant",
        .stored_at_ms = 0,
        .expires_at_ms = 60_000,
        .swr_until_ms = 60_000,
        .initial_age_seconds = 0,
    };
    {
        var cache = try DiskCache.init(allocator, root_path, limits, 97);
        defer cache.deinit();
        var variant = record;
        variant.vary_primary_key = primary;
        cache.put(secondary, variant, 0);
        cache.state_dir.fault = .write;
        cache.state_dir.fault_file = primary;
        cache.io_lanes[DiskCache.ioLane(secondary)].lock();
        cache.put(primary, record, 1);
        cache.io_lanes[DiskCache.ioLane(secondary)].unlock();
        try std.testing.expect(cache.disabled);
    }
    // No durable fence could be written and the busy sibling could not be
    // retired, so the on-disk directory still looks like an ordinary,
    // reconcilable Vary family under the unchanged fingerprint: exactly the
    // state a naive restart would happily replay under the new (direct)
    // representation policy. The durable poison marker must keep the next
    // process from trusting it instead.
    var reopened = try DiskCache.init(allocator, root_path, limits, 97);
    defer reopened.deinit();
    try std.testing.expect(reopened.disabled);
    try std.testing.expect(!reopened.isVaryTracked(primary));
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try std.testing.expect(reopened.get(arena.allocator(), secondary, 2) == null);
    try std.testing.expect(reopened.get(arena.allocator(), primary, 2) == null);
}
