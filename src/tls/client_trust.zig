//! Downstream client-certificate trust anchors for native TLS and QUIC (#763).
//!
//! Shared by the TCP (H1/H2) and QUIC (H3) accept paths so one CA bundle, one
//! reload and one generation counter govern every protocol.

const std = @import("std");
const compat = @import("zig_compat");
const webpki_verifier = @import("webpki_verifier.zig");

/// Client-certificate trust anchors, published as immutable
/// refcounted generations so a reload swaps the whole set atomically: a
/// handshake pins one generation for its whole lifetime (the verifier borrows
/// its anchors) and never observes a half-rotated bundle. A failed
/// `prepare` leaves the serving generation untouched.
pub const ClientTrustStore = struct {
    allocator: std.mem.Allocator,
    mutex: compat.Mutex = .{},
    current: ?*Generation = null,

    pub const Generation = struct {
        allocator: std.mem.Allocator,
        refs: std.atomic.Value(u32),
        anchors: webpki_verifier.TrustAnchors,
        max_path_length: usize,

        pub fn release(self: *Generation) void {
            if (self.refs.fetchSub(1, .acq_rel) == 1) {
                const allocator = self.allocator;
                self.anchors.deinit(allocator);
                allocator.destroy(self);
            }
        }
    };

    pub const Prepared = struct {
        generation: ?*Generation,

        pub fn deinit(self: *Prepared) void {
            if (self.generation) |g| g.release();
            self.* = undefined;
        }
    };

    pub fn init(allocator: std.mem.Allocator) ClientTrustStore {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ClientTrustStore) void {
        if (self.current) |g| g.release();
        self.* = undefined;
    }

    /// Load and parse `ca_bundle_path` without publishing it. `ca_bundle_path`
    /// must be non-empty: client trust never falls back to the system store.
    pub fn prepare(self: *ClientTrustStore, ca_bundle_path: []const u8, max_path_length: usize) !Prepared {
        if (ca_bundle_path.len == 0) return error.ClientTrustPathRequired;
        var anchors = try webpki_verifier.loadTrustAnchors(self.allocator, ca_bundle_path);
        errdefer anchors.deinit(self.allocator);
        if (anchors.anchors().len == 0) return error.NoClientTrustAnchors;
        const generation = try self.allocator.create(Generation);
        generation.* = .{
            .allocator = self.allocator,
            .refs = std.atomic.Value(u32).init(1),
            .anchors = anchors,
            .max_path_length = max_path_length,
        };
        return .{ .generation = generation };
    }

    pub fn commit(self: *ClientTrustStore, prepared: *Prepared) void {
        const generation = prepared.generation orelse return;
        prepared.generation = null;
        self.mutex.lock();
        const previous = self.current;
        self.current = generation;
        self.mutex.unlock();
        if (previous) |g| g.release();
    }

    /// Pin the serving generation; the caller must `release` it.
    pub fn acquire(self: *ClientTrustStore) ?*Generation {
        self.mutex.lock();
        defer self.mutex.unlock();
        const g = self.current orelse return null;
        _ = g.refs.fetchAdd(1, .monotonic);
        return g;
    }
};
