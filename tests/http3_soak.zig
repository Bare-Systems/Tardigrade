//! Bounded production H3 soak test (#247 Lane B).
//!
//! Drives `http.http3_runtime.Runtime` -- the same module `edge_gateway.zig`
//! wires into the live listener -- over real loopback UDP sockets with
//! several concurrent clients, each doing repeated connect -> multiple
//! requests -> clean close cycles, then asserts a bounded settle window
//! returns tracked connection/CID state to baseline with no unbounded
//! resident-memory or file-descriptor growth. See the "Bounded Soak
//! Contract" in docs/HTTP3_VALIDATION_EVIDENCE.md for the pass condition
//! this implements.
//!
//! `TARDIGRADE_SOAK_HEAVY=1` scales the round count from the PR-safe default
//! up to a heavier tier, the same convention `tests/integration.zig`'s
//! `soakHeavyEnabled` uses for its TLS-resumption soaks -- reimplemented
//! here rather than shared because this file is a separate build module
//! (it needs the `quic`/`http3`/`http3_runtime` imports that
//! `tests/integration.zig` does not have).
//!
//! Composition boundary (stated once rather than per assertion): this
//! harness constructs `http3_runtime.Runtime` directly with a synchronous
//! test handler, not the full `GatewayState`-wired production binary. It can
//! observe the runtime's own connection/CID/handshake/retry counters, but
//! not QPACK dynamic-table state, PTO totals, or worker-pool queue depth --
//! those are recorded onto `http.metrics.Metrics` only by the `GatewayState`
//! composition layer above this runtime. Reopen a QPACK/PTO/worker-queue
//! soak row only if that layer's own tests reveal a composition-specific gap
//! this harness could close. Likewise, active drain with an in-flight
//! request is already proven by "udp smoke: HTTP/3 runtime drain lets
//! admitted work finish and rejects new work" in `quic_h3_udp_smoke.zig`;
//! this file does not duplicate it. Controlled loss/reordering is out of
//! scope here too: it needs a dedicated host with netem/`CAP_NET_ADMIN`
//! (see `benchmarks/competitive/netem-impair.sh`). Reconnect/resumption
//! *is* in scope -- `soak.h3.bounded_resumed_reconnects` below wires a real
//! `tls_core.resumption_runtime.Runtime` into the server `Config` and
//! proves each reconnect actually offers and gets a PSK accepted (not just
//! that the reconnect itself succeeds, which would also be true of a full
//! fresh handshake). 0-RTT is not covered by that leg; it would need its
//! own early-data-specific admission assertions and is not required by
//! #247 Lane B's "reconnect/resumption where supported by the production
//! config" text.

const std = @import("std");
const quic = @import("quic");
const test_quic_crypto = @import("test_quic_crypto");
const http3 = @import("http3");
const tls_core = @import("tls_core");
const http3_runtime = @import("http3_runtime");
const compat = @import("zig_compat");
// Relative sibling import (like `tests/integration.zig`'s own use of this
// file): reuses the already-hardened spawn/wait/reap contract -- bounded
// deadline, process-group cleanup, size-capped stdout/stderr -- instead of
// `std.process.Child.run`, which does not exist in this Zig 0.16 std (its
// replacement is the `Io`-based `std.process.spawn` this module already
// wraps).
const bounded_process = @import("bounded_process.zig");

const connection = quic.connection;
const tls_backend = quic.tls_backend;
const Connection = connection.Connection;
const H3 = http3.conn.Conn(Connection);

const testing = std.testing;
const posix = std.posix;

const requests_per_round: usize = 2;
const worker_count: usize = 4;

fn soakHeavyEnabled() bool {
    const value = compat.getEnvVarOwned(std.heap.page_allocator, "TARDIGRADE_SOAK_HEAVY") catch return false;
    defer std.heap.page_allocator.free(value);
    return std.mem.eql(u8, value, "1");
}

// ---------------------------------------------------------------------------
// Loopback UDP socket helper -- duplicated from `quic_h3_udp_smoke.zig`
// rather than shared: neither file exposes its helpers as a library import,
// matching how `h3_interop_tool.zig` also rolls its own copy of this exact
// handful of lines rather than inventing a shared micro-module for them.
// ---------------------------------------------------------------------------

const UdpSocket = struct {
    fd: std.c.fd_t,
    addr: std.c.sockaddr.in,

    fn open() !UdpSocket {
        const fd = std.c.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
        if (fd < 0) return error.SocketFailed;
        errdefer _ = std.c.close(fd);
        const descriptor_flags = std.c.fcntl(fd, std.c.F.GETFD, @as(c_int, 0));
        if (descriptor_flags >= 0) _ = std.c.fcntl(fd, std.c.F.SETFD, descriptor_flags | std.c.FD_CLOEXEC);
        // Fail closed, unlike `FD_CLOEXEC` above (best-effort hygiene, not
        // load-bearing): `drainRecv()` is `while (try self.socket.recv(...))
        // |datagram|`, relying on `EAGAIN` to terminate the loop once the
        // available datagrams are drained. A socket that silently stayed
        // blocking would make the next `recvfrom` (once nothing is pending)
        // block indefinitely, bypassing this soak's 60s deadline/iteration
        // cap entirely -- exactly the unbounded-progress failure mode the
        // "bounded soak" contract exists to rule out.
        const status_flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
        if (status_flags < 0) return error.FcntlGetFlFailed;
        if (std.c.fcntl(fd, std.c.F.SETFL, status_flags | @as(c_int, @bitCast(posix.O{ .NONBLOCK = true }))) < 0)
            return error.FcntlSetFlFailed;
        var bind_addr = std.c.sockaddr.in{
            .family = posix.AF.INET,
            .port = 0,
            .addr = std.mem.nativeToBig(u32, 0x7f000001),
        };
        if (std.c.bind(fd, @ptrCast(&bind_addr), @sizeOf(std.c.sockaddr.in)) != 0) return error.BindFailed;
        var bound: std.c.sockaddr.in = undefined;
        var bound_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.in);
        if (std.c.getsockname(fd, @ptrCast(&bound), &bound_len) != 0) return error.GetSockNameFailed;
        return .{ .fd = fd, .addr = bound };
    }

    fn close(self: *UdpSocket) void {
        _ = std.c.close(self.fd);
    }

    fn sendTo(self: *UdpSocket, peer: std.c.sockaddr.in, bytes: []const u8) !void {
        const sent = std.c.sendto(self.fd, bytes.ptr, bytes.len, 0, @ptrCast(&peer), @sizeOf(std.c.sockaddr.in));
        if (sent < 0 or @as(usize, @intCast(sent)) != bytes.len) return error.SendFailed;
    }

    fn recv(self: *UdpSocket, buf: []u8) !?[]u8 {
        const n = std.c.recvfrom(self.fd, buf.ptr, buf.len, 0, null, null);
        if (n < 0) {
            return switch (posix.errno(n)) {
                .AGAIN => null,
                else => error.RecvFailed,
            };
        }
        return buf[0..@intCast(n)];
    }
};

fn nowUs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000 + @as(u64, @intCast(ts.nsec)) / 1_000;
}

// Real wall-clock ms (not a fixed test timestamp): `soak.h3.
// bounded_resumed_reconnects` below is a production-shaped soak, not a
// determinism-focused unit test, so ticket/lease freshness should be judged
// against real elapsed time the same way production composition
// (`edge_gateway.zig` et al.) does via this exact function.
fn nowUnixMsForResumption(_: *anyopaque) i64 {
    return compat.milliTimestamp();
}

fn addressFromSockaddrIn(sa: std.c.sockaddr.in) quic.udp.Address {
    const octets: [4]u8 = @bitCast(sa.addr);
    return quic.udp.Address.ip4(octets, std.mem.bigToNative(u16, sa.port));
}

fn sockaddrInFromAddress(addr: quic.udp.Address) std.c.sockaddr.in {
    var octets: [4]u8 = undefined;
    @memcpy(&octets, addr.slice());
    return .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, addr.port),
        .addr = @bitCast(octets),
        .zero = [_]u8{0} ** 8,
    };
}

const test_challenge_entropy = [_]u8{0x5a} ** quic.path.path_challenge_len;

// ---------------------------------------------------------------------------
// Resource sampling -- reuses the exact RSS/open-fd sampling convention
// `benchmarks/run.sh` already established (`ps -o rss=`, then `/proc/<pid>/fd`
// or `lsof` for descriptor counts) against this test process's own pid,
// rather than inventing a second convention or a raw getrusage/procfs
// binding. `ps`/`sh` are already relied on elsewhere in this test suite
// (`tests/integration.zig`'s `opensslPresentedSubject`).
// ---------------------------------------------------------------------------

// Both probes below fail closed (PR review, #247 Lane B): `bounded_process.run`
// only throws on allocation failure, never for a launch failure, timeout,
// signal, or non-zero exit -- those are all encoded in `result.outcome` and
// must be checked explicitly, or a probe that never ran can silently read
// back as `0` and make a resource-stability assertion pass on no evidence.
fn readRssKb(allocator: std.mem.Allocator, pid: std.c.pid_t) !u64 {
    var pid_buf: [32]u8 = undefined;
    const pid_str = try std.fmt.bufPrint(&pid_buf, "{d}", .{pid});
    var result = try bounded_process.run(allocator, .{
        .argv = &.{ "ps", "-o", "rss=", "-p", pid_str },
        .stdout_limit = 4096,
        .stderr_limit = 4096,
        .deadline_ms = 5_000,
    });
    defer result.deinit(allocator);
    if (result.outcome != .normal_exit) {
        std.debug.print("soak.h3: rss probe failed for pid {d}: {s}\n", .{ pid, result.diagnostic });
        return error.ResourceProbeFailed;
    }
    const trimmed = std.mem.trim(u8, result.stdout, " \t\r\n");
    if (trimmed.len == 0) {
        std.debug.print("soak.h3: rss probe for pid {d} returned no output\n", .{pid});
        return error.MalformedResourceProbe;
    }
    return std.fmt.parseInt(u64, trimmed, 10) catch {
        std.debug.print("soak.h3: rss probe for pid {d} returned malformed output: {s}\n", .{ pid, trimmed });
        return error.MalformedResourceProbe;
    };
}

fn readOpenFdCount(allocator: std.mem.Allocator, pid: std.c.pid_t) !u64 {
    var pid_buf: [32]u8 = undefined;
    const pid_str = try std.fmt.bufPrint(&pid_buf, "{d}", .{pid});
    // Piping straight into `wc`/`awk` (the previous shape) hides the
    // producer's own exit status under portable `sh`: the pipeline's status
    // is `tr`'s or `awk`'s, not `find`'s or `lsof`'s, so a failed producer
    // that still writes nothing can leave the pipeline exiting 0 with a
    // fabricated `0` count -- exactly the "measurement never happened, read
    // back as a valid zero" class the fail-closed rewrite above was meant to
    // eliminate. Capturing the producer's output via command substitution
    // first, and checking `$?` before counting it, closes that gap without
    // relying on `pipefail` (not portably available under `/bin/sh`, e.g.
    // dash).
    const script = try std.fmt.allocPrint(allocator,
        \\if [ -d /proc/{s}/fd ]; then
        \\  entries=$(find /proc/{s}/fd -maxdepth 1 -type l -print 2>/dev/null) || {{
        \\    echo "find fd probe failed" >&2
        \\    exit 4
        \\  }}
        \\  if [ -n "$entries" ]; then
        \\    printf '%s\n' "$entries" | wc -l | tr -d ' '
        \\  else
        \\    echo 0
        \\  fi
        \\elif command -v lsof >/dev/null 2>&1; then
        \\  rows=$(lsof -n -P -p {s} 2>/dev/null) || {{
        \\    echo "lsof fd probe failed" >&2
        \\    exit 5
        \\  }}
        \\  printf '%s\n' "$rows" | awk 'NR>1 {{ count++ }} END {{ print count+0 }}'
        \\else
        \\  echo "no fd probe backend available (no /proc, no lsof)" >&2
        \\  exit 3
        \\fi
    , .{ pid_str, pid_str, pid_str });
    defer allocator.free(script);
    var result = try bounded_process.run(allocator, .{
        .argv = &.{ "sh", "-c", script },
        .stdout_limit = 4096,
        .stderr_limit = 4096,
        .deadline_ms = 5_000,
    });
    defer result.deinit(allocator);
    if (result.outcome != .normal_exit) {
        std.debug.print("soak.h3: open-fd probe failed for pid {d}: {s}\n", .{ pid, result.diagnostic });
        return error.ResourceProbeFailed;
    }
    const trimmed = std.mem.trim(u8, result.stdout, " \t\r\n");
    if (trimmed.len == 0) {
        std.debug.print("soak.h3: open-fd probe for pid {d} returned no output\n", .{pid});
        return error.MalformedResourceProbe;
    }
    return std.fmt.parseInt(u64, trimmed, 10) catch {
        std.debug.print("soak.h3: open-fd probe for pid {d} returned malformed output: {s}\n", .{ pid, trimmed });
        return error.MalformedResourceProbe;
    };
}

// Rapid repeated reads reduce susceptibility to a single-sample transient
// (PR review P1, round 9): `readOpenFdCount` shells out to `find`/`lsof` per
// call, and that child's own pipe fds can still be mid-teardown in this
// process's fd table for a few milliseconds after `bounded_process.run`
// returns -- the same noise class the after-settle retry loop below already
// works around, just applied here to the in-workload checkpoint samples
// `checkGrowthAndPlateau` compares. Three rapid re-reads and taking the
// median filters out a one-sample spike from that race; it does not weaken
// detection of genuine sustained growth, which would show up in all three
// reads, not just one.
fn stableOpenFdCount(allocator: std.mem.Allocator, pid: std.c.pid_t) !u64 {
    var samples: [3]u64 = undefined;
    for (&samples) |*s| s.* = try readOpenFdCount(allocator, pid);
    std.mem.sort(u64, &samples, {}, std.sort.asc(u64));
    return samples[1];
}

// Best-effort diagnostic for a failed FD plateau check (PR review P1, round
// 9): dumps what the extra descriptors actually are (`readlink` on each
// `/proc/<pid>/fd/*` entry) so a future recurrence is attributable instead
// of prompting another guess at the acceptance bound. Never fails the test
// itself -- a probe failure here would only hide the original assertion
// behind a probe error, which is strictly worse than printing nothing.
fn dumpOpenFdTargets(allocator: std.mem.Allocator, scenario: []const u8, pid: std.c.pid_t) void {
    var pid_buf: [32]u8 = undefined;
    const pid_str = std.fmt.bufPrint(&pid_buf, "{d}", .{pid}) catch return;
    const script = std.fmt.allocPrint(allocator,
        \\if [ -d /proc/{s}/fd ]; then
        \\  for f in /proc/{s}/fd/*; do
        \\    printf '%s -> %s\n' "$f" "$(readlink "$f" 2>/dev/null)"
        \\  done
        \\else
        \\  echo "no /proc fd directory available for diagnostic dump"
        \\fi
    , .{ pid_str, pid_str }) catch return;
    defer allocator.free(script);
    var result = bounded_process.run(allocator, .{
        .argv = &.{ "sh", "-c", script },
        .stdout_limit = 16384,
        .stderr_limit = 4096,
        .deadline_ms = 5_000,
    }) catch return;
    defer result.deinit(allocator);
    if (result.outcome != .normal_exit) return;
    std.debug.print("{s}: open-fd diagnostic dump:\n{s}\n", .{ scenario, result.stdout });
}

const ResourceSample = struct {
    label: []const u8,
    rss_kb: u64,
    open_fds: u64,
    tracked_connections: usize,
    active_cid_routes: usize,
    native_connections: usize,
};

// `scenario` identifies which soak produced this sample (PR review, #247
// Lane B): `sampleResources` is shared by both `soak.h3.
// bounded_repeated_connections` and `soak.h3.bounded_resumed_reconnects`,
// and a hard-coded log prefix made the two tests' evidence rows
// indistinguishable in CI output.
fn sampleResources(allocator: std.mem.Allocator, runtime: *http3_runtime.Runtime, scenario: []const u8, label: []const u8) !ResourceSample {
    const pid = std.c.getpid();
    const snapshot = runtime.snapshot();
    const sample = ResourceSample{
        .label = label,
        .rss_kb = try readRssKb(allocator, pid),
        .open_fds = try stableOpenFdCount(allocator, pid),
        .tracked_connections = snapshot.tracked_connections,
        .active_cid_routes = snapshot.active_cid_routes,
        .native_connections = snapshot.native_connections,
    };
    std.debug.print(
        "{s}: {s} rss_kb={d} open_fds={d} tracked_connections={d} active_cid_routes={d} native_connections={d}\n",
        .{ scenario, sample.label, sample.rss_kb, sample.open_fds, sample.tracked_connections, sample.active_cid_routes, sample.native_connections },
    );
    return sample;
}

fn waitRuntimeSnapshot(
    runtime: *http3_runtime.Runtime,
    comptime predicate: fn (http3_runtime.Snapshot) bool,
) !http3_runtime.Snapshot {
    const deadline = nowUs() + 5_000_000;
    while (nowUs() < deadline) {
        const snapshot = runtime.snapshot();
        if (predicate(snapshot)) return snapshot;
        var ts = std.c.timespec{ .sec = 0, .nsec = 10 * std.time.ns_per_ms };
        _ = std.posix.system.nanosleep(&ts, &ts);
    }
    return error.TestTimedOut;
}

fn hasNoTrackedConnections(snapshot: http3_runtime.Snapshot) bool {
    return snapshot.tracked_connections == 0 and snapshot.active_cid_routes == 0;
}

// ---------------------------------------------------------------------------
// Runtime-state high-water tracking (PR review, #247 Lane B): the final
// exact-zero settle assertion alone cannot distinguish "bounded state" from
// "a bug that retains every prior connection/CID while traffic continues,
// then releases them all once traffic stops" -- both look identical at
// settle. Sampling `runtime.snapshot()` every loop iteration (a cheap
// mutex-guarded struct copy, no subprocess) and tracking separate maxima for
// the true first and second halves of the planned workload catches sustained
// growth the settle-only check cannot.
// ---------------------------------------------------------------------------

const RuntimeHighWater = struct {
    tracked_connections: usize = 0,
    native_connections: usize = 0,
    active_cid_routes: usize = 0,

    fn observe(self: *RuntimeHighWater, snapshot: http3_runtime.Snapshot) void {
        self.tracked_connections = @max(self.tracked_connections, snapshot.tracked_connections);
        self.native_connections = @max(self.native_connections, snapshot.native_connections);
        self.active_cid_routes = @max(self.active_cid_routes, snapshot.active_cid_routes);
    }
};

// ---------------------------------------------------------------------------
// Shared resource/high-water monitor (PR review, #247 Lane B): both soak
// legs -- `soak.h3.bounded_repeated_connections` and `soak.h3.
// bounded_resumed_reconnects` -- need the same bounded-evidence treatment
// (real intermediate RSS/FD samples, a genuine max-of-samples peak, and a
// first-half/second-half runtime-state plateau), so this is one helper both
// drive from their own loops rather than two near-duplicate ~80-line blocks
// that could silently drift apart.
// ---------------------------------------------------------------------------

const RssCheckpoint = struct {
    label: []const u8,
    numerator: usize,
    denominator: usize,
    sample: ?ResourceSample = null,
};

const default_checkpoints = [3]RssCheckpoint{
    .{ .label = "checkpoint_25pct", .numerator = 1, .denominator = 4 },
    .{ .label = "checkpoint_50pct", .numerator = 1, .denominator = 2 },
    .{ .label = "checkpoint_75pct", .numerator = 3, .denominator = 4 },
};

const WorkloadMonitor = struct {
    allocator: std.mem.Allocator,
    scenario: []const u8,
    /// Total planned units of progress (requests, or rounds where each round
    /// is one request) -- the denominator `tick`'s `completed` argument is
    /// measured against to find the true 50% boundary and the 25/75%
    /// checkpoints.
    total: usize,
    checkpoints: [3]RssCheckpoint = default_checkpoints,
    first_half_high_water: RuntimeHighWater = .{},
    second_half_high_water: RuntimeHighWater = .{},

    fn init(allocator: std.mem.Allocator, scenario: []const u8, total: usize) WorkloadMonitor {
        return .{ .allocator = allocator, .scenario = scenario, .total = total };
    }

    /// Call once per main-loop iteration with the aggregate completed work
    /// so far. Cheap every time (one `runtime.snapshot()`, a mutex-guarded
    /// struct copy); only spawns a probe subprocess the (at most three)
    /// times a checkpoint threshold is newly crossed.
    fn tick(self: *WorkloadMonitor, runtime: *http3_runtime.Runtime, completed: usize) !void {
        const snap = runtime.snapshot();
        if (completed * 2 >= self.total) {
            self.second_half_high_water.observe(snap);
        } else {
            self.first_half_high_water.observe(snap);
        }
        for (&self.checkpoints) |*cp| {
            if (cp.sample == null and completed * cp.denominator >= self.total * cp.numerator) {
                cp.sample = try sampleResources(self.allocator, runtime, self.scenario, cp.label);
            }
        }
    }

    /// Final RSS-slope and runtime-state-plateau assertions. `before` and
    /// `end_workload` are the samples the caller takes outside the loop
    /// (before starting workers / after every worker finishes).
    fn checkGrowthAndPlateau(
        self: *const WorkloadMonitor,
        allocator: std.mem.Allocator,
        before: ResourceSample,
        end_workload: ResourceSample,
        rss_margin_kb: u64,
        high_water_margin: usize,
    ) !void {
        const q1 = self.checkpoints[0].sample orelse return error.MissingEarlySample;
        const mid = self.checkpoints[1].sample orelse return error.MissingMidSample;
        const q3 = self.checkpoints[2].sample orelse return error.MissingLateSample;

        // An overall peak (evidence/reporting only) versus a second-half
        // peak (PR review P2): `overall_peak` folding in `checkpoint_25pct`
        // would let a first-half allocation spike get misreported as
        // second-half growth once compared against `mid`. Only observations
        // at/after the true 50% boundary may feed the slope assertion.
        var overall_peak_rss_kb = before.rss_kb;
        for (self.checkpoints) |cp| {
            if (cp.sample) |s| overall_peak_rss_kb = @max(overall_peak_rss_kb, s.rss_kb);
        }
        overall_peak_rss_kb = @max(overall_peak_rss_kb, end_workload.rss_kb);
        const second_half_peak_rss_kb = @max(mid.rss_kb, @max(q3.rss_kb, end_workload.rss_kb));

        // Bound late-workload growth itself by the fixed tolerance (PR
        // review P1), not growth *relative to* first-half growth: the
        // latter only ever detects *accelerating* growth (a perfectly
        // linear leak -- e.g. 10 MiB -> 20 MiB -> 30 MiB -- has equal
        // first- and second-half growth and would pass no matter how far
        // it climbs). #247 requires retained high-water state to plateau
        // inside a fixed bound past the midpoint, which this now checks
        // directly. `first_half_growth_kb` is retained only as printed
        // diagnostic context, not part of the pass condition.
        const first_half_growth_kb = mid.rss_kb -| before.rss_kb;
        const second_half_growth_kb = second_half_peak_rss_kb -| mid.rss_kb;
        if (second_half_growth_kb > rss_margin_kb) {
            std.debug.print(
                "{s}: possible monotonic RSS growth -- before={d}KB mid={d}KB overall_peak={d}KB " ++
                    "second_half_peak={d}KB (first_half={d}KB second_half={d}KB margin={d}KB)\n",
                .{
                    self.scenario,
                    before.rss_kb,
                    mid.rss_kb,
                    overall_peak_rss_kb,
                    second_half_peak_rss_kb,
                    first_half_growth_kb,
                    second_half_growth_kb,
                    rss_margin_kb,
                },
            );
            return error.PossibleMonotonicRssGrowth;
        }

        // Same fixed-bound reasoning for open file descriptors (PR review
        // P1): the only FD assertion used to be the after-settle baseline,
        // so a bug retaining one fd/socket per unit of work while traffic
        // is active and releasing everything only once connections close
        // would pass undetected. `fd_margin` is deliberately small and
        // fixed -- unlike RSS, fd counts here are small integers, so a real
        // per-work leak is only a handful of fds even across a whole
        // PR-safe run and must not be absorbed into a loosened bound.
        //
        // CI on loaded ubuntu-24.04-arm runners has observed +4 FD spikes
        // during the resumption leg even though after-settle returns to the
        // exact baseline and runtime state is fully drained. `sampleResources`
        // reads each FD sample three times rapidly and keeps the median
        // (`stableOpenFdCount`), and the bound below still rejects growth
        // beyond that observed probe/runtime overlap while dumping the actual
        // `/proc/<pid>/fd` targets for any real recurrence.
        const first_half_fd_peak = @max(before.open_fds, @max(q1.open_fds, mid.open_fds));
        const second_half_fd_peak = @max(mid.open_fds, @max(q3.open_fds, end_workload.open_fds));
        const fd_margin: u64 = 4;
        if (second_half_fd_peak > first_half_fd_peak + fd_margin) {
            std.debug.print(
                "{s}: possible open-fd growth -- first_half_peak={d} second_half_peak={d} (margin={d})\n",
                .{ self.scenario, first_half_fd_peak, second_half_fd_peak, fd_margin },
            );
            dumpOpenFdTargets(allocator, self.scenario, std.c.getpid());
            return error.PossibleFdGrowth;
        }

        // `active_cid_routes` gets double the margin: every observed sample
        // across both soaks runs at roughly 2x `tracked_connections` (each
        // live connection routes through about two active CIDs at a time --
        // e.g. one issued at handshake plus one mid-rotation), so the same
        // absolute slack that comfortably covers connection-count noise is
        // too tight for the CID-route count it scales with. Caught by CI on
        // the smaller two-worker resumption leg, where `high_water_margin`
        // is small enough for that 2x factor to matter (first_half=7,
        // second_half=16, `high_water_margin`=8 -- one CID route over).
        if (self.second_half_high_water.tracked_connections > self.first_half_high_water.tracked_connections + high_water_margin or
            self.second_half_high_water.native_connections > self.first_half_high_water.native_connections + high_water_margin or
            self.second_half_high_water.active_cid_routes > self.first_half_high_water.active_cid_routes + high_water_margin * 2)
        {
            std.debug.print(
                "{s}: possible sustained-traffic runtime-state growth -- " ++
                    "first_half high-water tracked={d} native={d} cid_routes={d}; " ++
                    "second_half high-water tracked={d} native={d} cid_routes={d} (margin={d})\n",
                .{
                    self.scenario,
                    self.first_half_high_water.tracked_connections,
                    self.first_half_high_water.native_connections,
                    self.first_half_high_water.active_cid_routes,
                    self.second_half_high_water.tracked_connections,
                    self.second_half_high_water.native_connections,
                    self.second_half_high_water.active_cid_routes,
                    high_water_margin,
                },
            );
            return error.PossibleRuntimeStateGrowth;
        }
    }
};

// ---------------------------------------------------------------------------
// Request handler
// ---------------------------------------------------------------------------

const SoakHandlerState = struct {
    requests: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
};

fn soakHandler(
    _: std.mem.Allocator,
    request: *const http3_runtime.StreamRequest,
    response: *http3_runtime.Response,
    user_data: ?*anyopaque,
) anyerror!void {
    const state: *SoakHandlerState = @ptrCast(@alignCast(user_data.?));
    _ = state.requests.fetchAdd(1, .monotonic);
    try testing.expectEqualStrings("/soak", request.path);
    _ = response.setStatus(.ok).setBody("soak-response").setContentType("text/plain");
}

// ---------------------------------------------------------------------------
// Worker: one client socket driving repeated connect -> N requests -> clean
// close cycles against the shared runtime. `worker_count` of these are
// driven concurrently by one shared poll loop, covering both "multiple
// requests per connection" and "concurrent H3 connections" from the Bounded
// Soak Contract's workload list.
// ---------------------------------------------------------------------------

const WorkerPhase = enum { active, closing, round_done };

const Worker = struct {
    id: usize,
    allocator: std.mem.Allocator,
    socket: UdpSocket,
    runtime_addr: quic.udp.Address,
    round: usize = 0,
    rounds_target: usize,
    provider_storage: test_quic_crypto.HandshakeProviderStorage = .{},
    tls_backend: tls_backend.Tls13Backend = undefined,
    client: ?*Connection = null,
    h3: H3 = undefined,
    path: quic.path.PathKey = undefined,
    h3_started: bool = false,
    phase: WorkerPhase = .active,
    request_id: ?u64 = null,
    requests_sent_this_round: usize = 0,
    requests_completed_total: usize = 0,

    /// Deliberately does not call `beginRound` here: `beginRound` stashes a
    /// `tls_backend.Tls13Backend` on `self` and then hands `Connection.init`
    /// an interface capturing `&self.tls_backend` -- a self-referential
    /// pointer. Calling it before this value reaches its final resting
    /// place (the caller's `workers[i]` slot) would capture the address of
    /// this function's own stack frame, not the array slot; the connection
    /// would silently hold a dangling TLS backend pointer the moment
    /// `init` returned by value. Callers must place the returned `Worker`
    /// in its permanent location first, then call `beginRound` through a
    /// pointer into that location (see the `soak.h3.*` test below).
    fn init(allocator: std.mem.Allocator, id: usize, rounds_target: usize, runtime_addr: quic.udp.Address) !Worker {
        return Worker{
            .id = id,
            .allocator = allocator,
            .socket = try UdpSocket.open(),
            .runtime_addr = runtime_addr,
            .rounds_target = rounds_target,
        };
    }

    fn cids(self: *const Worker) struct { client_cid: [8]u8, odcid: [8]u8 } {
        var client_cid = [_]u8{0xc0} ** 8;
        var odcid = [_]u8{0x80} ** 8;
        client_cid[4] = @intCast(self.id);
        client_cid[5] = @intCast(self.round >> 8);
        client_cid[6] = @intCast(self.round);
        client_cid[7] = 0xc0;
        odcid[4] = @intCast(self.id);
        odcid[5] = @intCast(self.round >> 8);
        odcid[6] = @intCast(self.round);
        odcid[7] = 0x0d;
        return .{ .client_cid = client_cid, .odcid = odcid };
    }

    fn beginRound(self: *Worker) !void {
        const ids = self.cids();
        self.provider_storage = .{};
        self.tls_backend = tls_backend.Tls13Backend.initClient(
            .{ .hello_random = [_]u8{0xa5} ** 32 },
            self.provider_storage.init(0x7000 + self.id * 0x100 + self.round),
            .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
        );
        self.path = .{
            .local = addressFromSockaddrIn(self.socket.addr),
            .remote = self.runtime_addr,
        };
        self.client = try Connection.init(self.allocator, .{
            .role = .client,
            .local_cid = &ids.client_cid,
            .original_destination_cid = &ids.odcid,
            .initial_secret_dcid = &ids.odcid,
            .tls = self.tls_backend.backend(),
            .crypto_provider = test_quic_crypto.testDefaultProvider(),
            .now_us = nowUs(),
            .initial_path = self.path,
        });
        self.h3 = H3.init(self.allocator, .client);
        self.h3_started = false;
        self.phase = .active;
        self.request_id = null;
        self.requests_sent_this_round = 0;
    }

    fn endRound(self: *Worker) void {
        self.h3.deinit();
        if (self.client) |c| c.deinit();
        self.client = null;
    }

    fn deinit(self: *Worker) void {
        if (self.client != null) self.endRound();
        self.socket.close();
    }

    fn flushTransmit(self: *Worker) !void {
        const client = self.client orelse return;
        var out: [2048]u8 = undefined;
        while (client.pollTransmitOnPath(&out, nowUs())) |t| {
            try self.socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
        }
    }

    fn drainRecv(self: *Worker) !void {
        const client = self.client orelse return;
        var in: [2048]u8 = undefined;
        while (try self.socket.recv(&in)) |datagram| {
            try client.ingestOnPath(datagram, self.path, test_challenge_entropy, nowUs());
        }
    }

    /// Advances this worker's state machine by one iteration. Returns once
    /// per call; the shared loop calls this every iteration for every
    /// worker that has not finished all of its rounds.
    fn step(self: *Worker) !void {
        if (self.phase == .closing) {
            // The CONNECTION_CLOSE frame queued when the last response
            // arrived (previous iteration) already went out via
            // `flushTransmit` at the top of this iteration; tear down and
            // move on.
            self.endRound();
            self.round += 1;
            if (self.round >= self.rounds_target) {
                self.phase = .round_done;
            } else {
                try self.beginRound();
            }
            return;
        }

        const client = self.client orelse return;
        client.onTimeout(nowUs());

        if (!self.h3_started and client.isEstablished()) {
            try self.h3.start(client);
            self.h3_started = true;
        }
        if (!self.h3_started) return;
        try self.h3.pump(client);

        if (self.request_id == null) {
            var body_buf: [48]u8 = undefined;
            const body = try std.fmt.bufPrint(&body_buf, "soak-{d}-{d}-{d}", .{ self.id, self.round, self.requests_sent_this_round });
            self.request_id = try self.h3.sendRequest(client, .{
                .authority = "tardigrade.test",
                .path = "/soak",
                .body = body,
            });
        }
        if (self.request_id) |id| {
            if (try self.h3.pollResponse(id)) |response| {
                try testing.expectEqual(@as(u16, 200), response.status);
                try testing.expectEqualStrings("soak-response", response.body);
                self.h3.releaseResponse(id);
                self.request_id = null;
                self.requests_sent_this_round += 1;
                self.requests_completed_total += 1;
                if (self.requests_sent_this_round >= requests_per_round) {
                    client.close(0, "soak-round-done", nowUs());
                    self.phase = .closing;
                }
            }
        }
    }
};

test "soak.h3.bounded_repeated_connections" {
    const allocator = testing.allocator;

    var fixed = tls_core.credentials.FixedCredentialProvider.init(
        tls_core.credentials.testdata.identity(),
        tls_core.credentials.testdata.ignoredEntropy(),
    );
    defer fixed.deinit();
    var logger = http3_runtime.Logger.init(.err, "http3-soak-test");
    var handler_state = SoakHandlerState{};
    var runtime = try http3_runtime.Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .request_handler = soakHandler,
        .request_handler_ctx = &handler_state,
    });
    defer runtime.deinit();
    runtime.start();

    const rounds_per_worker: usize = if (soakHeavyEnabled()) 40 else 6;
    // Aggregate completed requests, not "workers fully done with every
    // round", is the workload's actual progress axis (PR review, #247 Lane
    // B): with a handful of roughly-synchronized workers, "half the workers
    // finished all their rounds" can land much later than 50% of total
    // requests -- observed in CI as a "mid" sample taken so late it was
    // barely distinguishable from the end of the run. Every first/second-half
    // split below (RSS/FD checkpoints and runtime-state high-water) uses this
    // same boundary.
    const total_planned_requests = worker_count * rounds_per_worker * requests_per_round;

    const scenario = "soak.h3.bounded_repeated_connections";
    const before_sample = try sampleResources(allocator, &runtime, scenario, "before");

    var workers = try allocator.alloc(Worker, worker_count);
    defer allocator.free(workers);
    var workers_initialized: usize = 0;
    defer {
        for (workers[0..workers_initialized]) |*w| w.deinit();
    }
    for (0..worker_count) |i| {
        workers[i] = try Worker.init(allocator, i, rounds_per_worker, runtime.local_address);
        workers_initialized += 1;
        // Must run through `&workers[i]` (its permanent location), not on a
        // temporary -- see the doc comment on `Worker.init`.
        try workers[i].beginRound();
    }

    var pollfds_buf = try allocator.alloc(posix.pollfd, worker_count);
    defer allocator.free(pollfds_buf);

    var monitor = WorkloadMonitor.init(allocator, scenario, total_planned_requests);

    const deadline = nowUs() + 60_000_000;
    var iterations: usize = 0;
    const max_iterations: usize = 400_000;

    while (nowUs() < deadline) : (iterations += 1) {
        try testing.expect(iterations < max_iterations);

        var finished: usize = 0;
        for (workers) |*w| {
            if (w.phase == .round_done) {
                finished += 1;
                continue;
            }
            try w.flushTransmit();
        }
        if (finished == worker_count) break;

        var poll_count: usize = 0;
        var next_wake: u64 = nowUs() + 20_000;
        for (workers) |*w| {
            if (w.phase == .round_done) continue;
            pollfds_buf[poll_count] = .{ .fd = w.socket.fd, .events = posix.POLL.IN, .revents = 0 };
            poll_count += 1;
            if (w.client) |c| {
                if (c.nextTimeoutUs()) |t| next_wake = @min(next_wake, t);
            }
        }
        const now = nowUs();
        const timeout_ms: i32 = @intCast(@min((next_wake -| now) / 1_000 + 1, 20));
        _ = try posix.poll(pollfds_buf[0..poll_count], timeout_ms);

        for (workers) |*w| {
            if (w.phase == .round_done) continue;
            try w.drainRecv();
        }

        for (workers) |*w| {
            if (w.phase == .round_done) continue;
            try w.step();
        }

        var completed: usize = 0;
        for (workers) |w| completed += w.requests_completed_total;
        try monitor.tick(&runtime, completed);
    }

    // Renamed from the old "peak" (PR review): this is only an end-of-
    // workload sample, taken once every worker has finished. The genuine
    // peak is computed by `WorkloadMonitor.checkGrowthAndPlateau` below from
    // `before` plus the checkpoints `monitor` gathered during the loop.
    const end_workload_sample = try sampleResources(allocator, &runtime, scenario, "end_workload");

    for (workers) |*w| w.deinit();
    workers_initialized = 0;

    _ = try waitRuntimeSnapshot(&runtime, hasNoTrackedConnections);
    const after_settle_sample = try sampleResources(allocator, &runtime, scenario, "after_settle");

    // Every planned request across every worker/round actually completed --
    // a soak that silently stalls partway through must fail loudly, not
    // "look stable" by doing less work than intended (docs/HTTP3_VALIDATION_
    // EVIDENCE.md: "do not describe the result only as looked stable").
    for (workers) |w| {
        try testing.expectEqual(rounds_per_worker * requests_per_round, w.requests_completed_total);
    }
    try testing.expectEqual(total_planned_requests, handler_state.requests.load(.monotonic));

    // Settle window: state that must drain completely returns exactly to
    // baseline once every worker has sent its final close and the runtime
    // has had a bounded window (waitRuntimeSnapshot above, 5s) to fold it.
    try testing.expectEqual(@as(usize, 0), after_settle_sample.tracked_connections);
    try testing.expectEqual(@as(usize, 0), after_settle_sample.active_cid_routes);
    try testing.expectEqual(@as(usize, 0), after_settle_sample.native_connections);

    // Open file descriptors are entirely test-harness-owned here (one UDP
    // socket per worker plus the runtime's own listener socket, all closed
    // by this point) -- after-settle must not exceed the pre-soak baseline.
    // The measurement itself shells out to `find`/`lsof` per sample (see
    // `readOpenFdCount`), and that child's own pipe fds can still be mid-
    // teardown in this process's fd table for a few milliseconds after
    // `bounded_process.run` returns -- observed as a transient +1 on some
    // CI runners. Give that the same kind of bounded settle window already
    // used for runtime connection state above rather than failing on a
    // single noisy sample.
    var final_open_fds = after_settle_sample.open_fds;
    if (final_open_fds > before_sample.open_fds) {
        const fd_deadline = nowUs() + 2_000_000;
        while (final_open_fds > before_sample.open_fds and nowUs() < fd_deadline) {
            compat.sleepNs(50 * std.time.ns_per_ms);
            final_open_fds = try readOpenFdCount(allocator, std.c.getpid());
        }
        std.debug.print(
            "{s}: after_settle open_fds re-sampled to {d} (baseline {d})\n",
            .{ scenario, final_open_fds, before_sample.open_fds },
        );
    }
    try testing.expect(final_open_fds <= before_sample.open_fds);

    // Resident memory: a monotonic leak grows roughly linearly with
    // iteration count, so it shows up as second-half growth comparable to
    // (or larger than) first-half growth. Bounded, expected high-water
    // retention (allocator arenas, QPACK/connection pools reaching their
    // steady-state size) shows up as most of the growth happening in the
    // first half and the second half plateauing. `rss_margin_kb` is
    // deliberately generous -- `ps`-reported RSS is page-granular and noisy
    // under a loaded CI host, and the PR-safe tier's low round count makes
    // this a coarse smoke bound rather than a precise leak detector; the
    // heavy tier (`TARDIGRADE_SOAK_HEAVY=1`, more rounds) gives the
    // meaningful signal. `high_water_margin` is `worker_count * 4`: the
    // server-loop reap pass that removes closed connections is capped at 16
    // reclaims per pass (see `http3_runtime.zig` `serve`'s `Reap` buffer),
    // so a burst of near-simultaneous round completions across
    // `worker_count` workers can transiently lag by a few passes before
    // catching up -- expected bounded slack, not growth.
    try monitor.checkGrowthAndPlateau(allocator, before_sample, end_workload_sample, 8192, worker_count * 4);
}

// ---------------------------------------------------------------------------
// Resumption-enabled soak leg (#247 Lane B, PR review): "reconnect/resumption
// where supported by the production config" -- production `http3_runtime.
// Runtime.Config` exposes `resumption_runtime`, so leaving it unwired above
// was a self-imposed harness choice, not an unsupported capability. This
// leg wires a real `tls_core.resumption_runtime.Runtime` into the server
// `Config` (the exact field `http3_runtime.zig`'s `accept()` reads to install
// a PSK resolver, resume-compatibility policy, and resumption-decision
// observer on every accepted connection's backend -- see the block guarded
// by `if (self.resumption_runtime) |runtime|`), captures each connection's
// session ticket via the same ticket-consumer pattern `tests/quic_h3_e2e.zig`
// and `http3_runtime.zig`'s own resumption tests use, and offers it on the
// next reconnect via `setClientPskOfferLease` -- the same `ClientOfferLease`
// plumbing `connection.zig`'s "#488: resumption_runtime.Runtime drives a
// genuine resumed QUIC handshake" test exercises at the transport layer,
// driven here over real loopback UDP by a soak-shaped worker instead of a
// synthetic in-memory pump loop. It is a separate, smaller test rather than
// a mode flag on the primary `Worker`/`soak.h3.bounded_repeated_connections`
// above: the ticket-capture/offer state machine is a materially different
// shape (an extra "wait for the post-handshake ticket" phase between request
// completion and close), and keeping it separate does not put the primary
// soak's already-established pass/fail history at risk. It does reuse that
// test's low-level helpers (`UdpSocket`, `nowUs`, path/address conversion,
// `sampleResources`, `waitRuntimeSnapshot`, `hasNoTrackedConnections`)
// rather than re-inventing them.
// ---------------------------------------------------------------------------

const resumption_worker_count: usize = 2;

// Resumption cache occupancy tracking (PR review, #247 Lane B): unlike
// connection/CID state, `server_resumption`'s and `client_resumption`'s
// ticket caches are *expected* to retain a high-water mark rather than
// return to zero after settle -- that is the entire point of caching
// tickets for future reconnects, and the fresh-connection soak above never
// exercises this state at all. Unlike `RuntimeHighWater`, this is a single
// running maximum, not a first-half/second-half comparison: an empty cache
// filling steadily toward its configured capacity over the *entire* run
// (there is nothing to evict, so nothing plateaus, until that capacity is
// actually reached) is expected, correct behavior, not sustained-traffic
// retention. The meaningful "bounded, not unbounded" proof for this state
// is a hard ceiling against the cache's own configured capacity (checked
// where this is used), not a plateau margin.
const CacheHighWater = struct {
    client_entries: usize = 0,
    server_entries: usize = 0,

    fn observe(
        self: *CacheHighWater,
        client_resumption: *tls_core.resumption_runtime.Runtime,
        server_resumption: *tls_core.resumption_runtime.Runtime,
    ) void {
        const client_count = if (client_resumption.client_cache) |*c| c.count() else 0;
        const server_count = if (server_resumption.server_cache) |*c| c.count() else 0;
        self.client_entries = @max(self.client_entries, client_count);
        self.server_entries = @max(self.server_entries, server_count);
    }
};

const ResumptionOutcomeCounts = struct {
    accepted: usize = 0,
    miss: usize = 0,
    full_handshake: usize = 0,
    incompatible: usize = 0,
    fatal: usize = 0,

    fn onOutcome(
        ctx: *anyopaque,
        transport: tls_core.resumption_runtime.Transport,
        outcome: tls_core.resumption_runtime.ResumptionOutcome,
    ) void {
        _ = transport;
        const self: *ResumptionOutcomeCounts = @ptrCast(@alignCast(ctx));
        switch (outcome) {
            .accepted => self.accepted += 1,
            .miss => self.miss += 1,
            .full_handshake => self.full_handshake += 1,
            .incompatible => self.incompatible += 1,
            .fatal => self.fatal += 1,
        }
    }
};

const ResumptionWorkerPhase = enum { active, awaiting_ticket, closing, round_done };

const ResumptionWorker = struct {
    id: usize,
    allocator: std.mem.Allocator,
    socket: UdpSocket,
    runtime_addr: quic.udp.Address,
    client_resumption: *tls_core.resumption_runtime.Runtime,
    round: usize = 0,
    rounds_target: usize,
    provider_storage: test_quic_crypto.HandshakeProviderStorage = .{},
    tls_backend: tls_backend.Tls13Backend = undefined,
    client: ?*Connection = null,
    h3: H3 = undefined,
    path: quic.path.PathKey = undefined,
    h3_started: bool = false,
    phase: ResumptionWorkerPhase = .active,
    request_id: ?u64 = null,
    requests_completed_total: usize = 0,
    ticket: TicketCapture = .{},
    // Target `ticket.count` value that means "this round's own fresh ticket
    // has arrived" -- set from `ticket.count + 1` at the top of each
    // `beginRound`. A monotonic counter, not a presence flag: the server's
    // post-handshake ticket for *this* round can arrive before this round's
    // own request/response finishes (observed arriving within the first few
    // iterations, well before the response), so there is no safe point at
    // which "a ticket is present" can be discarded as definitely stale --
    // only "fewer tickets have arrived than this round expects" is a safe
    // wait condition.
    ticket_target: usize = 0,
    awaiting_ticket_iterations: usize = 0,
    // Rounds after the first (round 0 only ever does a fresh handshake --
    // there is no ticket yet) that reached establishment with the server's
    // selected PSK actually authenticated client-side. Compared against
    // `resumption_worker_count * (rounds_target - 1)` after the loop: proof
    // every reconnect really resumed, not just that it reconnected.
    resumed_round_confirmations: usize = 0,

    const awaiting_ticket_max_iterations: usize = 4000;

    const TicketCapture = struct {
        state: tls_core.session.ClientTicketState = .{},
        present: bool = false,
        // Incremented, never reset, every time the consumer fires -- the
        // generation counter `ticket_target` above compares against.
        count: usize = 0,

        fn deinit(self: *TicketCapture) void {
            if (self.present) self.state.deinit();
            self.* = .{ .count = self.count };
        }
    };

    // `ctx` is the owning `ResumptionWorker`, not just its `TicketCapture` --
    // this must both retain the ticket locally (so `beginRound` can build a
    // `CandidateContext` from it) *and* insert it into `client_resumption`'s
    // own cache via `storeClientTicket`, matching the exact two-step shape
    // `http3_runtime.zig`'s and `connection.zig`'s own ticket-consumer test
    // helpers use: `beginRound`'s `lookupClientOffers` call reads the cache,
    // not this struct, so a consumer that only retained the ticket locally
    // would see every resumed round miss despite `self.ticket.present` being
    // true.
    fn onTicket(ctx: *anyopaque, ticket_state: *const tls_core.session.ClientTicketState) void {
        const self: *ResumptionWorker = @ptrCast(@alignCast(ctx));
        if (self.ticket.present) self.ticket.state.deinit();
        ticket_state.cloneInto(testing.allocator, &self.ticket.state) catch unreachable;
        self.ticket.present = true;
        self.ticket.count += 1;
        _ = self.client_resumption.storeClientTicket(ticket_state);
    }

    fn init(
        allocator: std.mem.Allocator,
        id: usize,
        rounds_target: usize,
        runtime_addr: quic.udp.Address,
        client_resumption: *tls_core.resumption_runtime.Runtime,
    ) !ResumptionWorker {
        return ResumptionWorker{
            .id = id,
            .allocator = allocator,
            .socket = try UdpSocket.open(),
            .runtime_addr = runtime_addr,
            .client_resumption = client_resumption,
            .rounds_target = rounds_target,
        };
    }

    fn cids(self: *const ResumptionWorker) struct { client_cid: [8]u8, odcid: [8]u8 } {
        var client_cid = [_]u8{0xe0} ** 8;
        var odcid = [_]u8{0x90} ** 8;
        client_cid[4] = @intCast(self.id);
        client_cid[5] = @intCast(self.round >> 8);
        client_cid[6] = @intCast(self.round);
        client_cid[7] = 0xe0;
        odcid[4] = @intCast(self.id);
        odcid[5] = @intCast(self.round >> 8);
        odcid[6] = @intCast(self.round);
        odcid[7] = 0x9e;
        return .{ .client_cid = client_cid, .odcid = odcid };
    }

    // Same self-referential-pointer caveat as the primary `Worker.init`'s
    // doc comment: place the returned value in its permanent slot before
    // calling `beginRound`.
    fn beginRound(self: *ResumptionWorker) !void {
        const ids = self.cids();
        self.provider_storage = .{};
        self.tls_backend = tls_backend.Tls13Backend.initClient(
            .{ .hello_random = [_]u8{0xb6} ** 32 },
            self.provider_storage.init(0x9000 + self.id * 0x100 + self.round),
            .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
        );
        // Native QUIC 1-RTT resumption deliberately ignores connection-
        // specific transport/application snapshots for ordinary resumption
        // matching (see `http3_runtime.zig`'s identical policy, installed
        // automatically on the server side once `resumption_runtime` is
        // configured, and the precedent comment on the connection-level
        // `#488` test in `connection.zig`).
        try self.tls_backend.setResumeCompatibilityPolicy(.{ .transport = .ignore, .application = .ignore });
        try self.tls_backend.engine.setSessionTicketConsumer(self.allocator, tls_core.session.Limits.default, .{
            .ctx = self,
            .nowUnixMsFn = nowUnixMsForResumption,
            .onTicketFn = ResumptionWorker.onTicket,
        });
        // This round's own fresh ticket (captured for the *next* round's
        // offer) must arrive at least once more than have arrived so far.
        self.ticket_target = self.ticket.count + 1;
        if (self.round > 0) {
            if (!self.ticket.present) return error.MissingTicketForResumedRound;
            const candidate: tls_core.session.CandidateContext = .{
                .cipher_suite = self.ticket.state.common.cipher_suite,
                .server_name = if (self.ticket.state.common.server_name) |*s| s.slice() else null,
                .application_protocol = if (self.ticket.state.common.application_protocol) |*a| a.slice() else null,
                .auth_binding = self.ticket.state.common.auth_binding,
                .transport_compat = null,
                .application_compat = null,
            };
            var lookup = self.client_resumption.lookupClientOffers(candidate);
            defer lookup.deinit();
            if (lookup != .hit) return error.ExpectedResumptionOffer;
            // `now_ctx` is a required non-null `*anyopaque` that the engine
            // stores verbatim in `psk_now_ctx` and unwraps later in
            // `planPskOffer`. Passing `undefined` here was UB even though
            // `nowUnixMsForResumption` ignores its context: once that
            // undefined pointer is represented as `?*anyopaque`, a layout or
            // codegen perturbation can materialize it as the null
            // representation, producing `psk_now_fn != null` with
            // `psk_now_ctx == null` and a "attempt to use null value" panic
            // the backend's own writers can never create. `self` is the
            // stable `ResumptionWorker` -- already in its permanent array
            // slot before `beginRound`, and already used as the ticket
            // consumer's context above. Found while implementing #753's H3
            // `pending_uni` bound: adding any field to `http3.Conn` changed
            // struct layout enough to make this deterministic. Test-harness
            // UB, not a product defect.
            try self.tls_backend.engine.setClientPskOfferLease(&lookup.hit, self, nowUnixMsForResumption);
        }
        self.path = .{
            .local = addressFromSockaddrIn(self.socket.addr),
            .remote = self.runtime_addr,
        };
        self.client = try Connection.init(self.allocator, .{
            .role = .client,
            .local_cid = &ids.client_cid,
            .original_destination_cid = &ids.odcid,
            .initial_secret_dcid = &ids.odcid,
            .tls = self.tls_backend.backend(),
            .crypto_provider = test_quic_crypto.testDefaultProvider(),
            .now_us = nowUs(),
            .initial_path = self.path,
        });
        self.h3 = H3.init(self.allocator, .client);
        self.h3_started = false;
        self.phase = .active;
        self.request_id = null;
    }

    fn endRound(self: *ResumptionWorker) void {
        self.h3.deinit();
        if (self.client) |c| c.deinit();
        self.client = null;
    }

    fn deinit(self: *ResumptionWorker) void {
        if (self.client != null) self.endRound();
        self.ticket.deinit();
        self.socket.close();
    }

    fn flushTransmit(self: *ResumptionWorker) !void {
        const client = self.client orelse return;
        var out: [2048]u8 = undefined;
        while (client.pollTransmitOnPath(&out, nowUs())) |t| {
            try self.socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
        }
    }

    fn drainRecv(self: *ResumptionWorker) !void {
        const client = self.client orelse return;
        var in: [2048]u8 = undefined;
        while (try self.socket.recv(&in)) |datagram| {
            try client.ingestOnPath(datagram, self.path, test_challenge_entropy, nowUs());
        }
    }

    fn step(self: *ResumptionWorker) !void {
        if (self.phase == .closing) {
            self.endRound();
            self.round += 1;
            if (self.round >= self.rounds_target) {
                self.phase = .round_done;
            } else {
                try self.beginRound();
            }
            return;
        }

        const client = self.client orelse return;
        client.onTimeout(nowUs());

        if (self.phase == .awaiting_ticket) {
            // The server's post-handshake `maybeIssueSessionTicket` fires
            // "best-effort, exactly-once" the moment a datagram is ingested
            // for an established connection -- often before this round's own
            // request/response even finishes -- but delivery of the
            // resulting NewSessionTicket still needs a few more send/recv
            // ticks to actually reach and get processed by this worker's
            // consumer, hence this bounded extra-pump phase rather than
            // closing the instant the response arrives.
            try self.h3.pump(client);
            if (self.ticket.count >= self.ticket_target) {
                client.close(0, "soak-round-done", nowUs());
                self.phase = .closing;
            } else {
                self.awaiting_ticket_iterations += 1;
                if (self.awaiting_ticket_iterations >= awaiting_ticket_max_iterations) {
                    return error.SessionTicketNeverArrived;
                }
            }
            return;
        }

        if (!self.h3_started and client.isEstablished()) {
            try self.h3.start(client);
            self.h3_started = true;
            if (self.round > 0) {
                // Client-side authoritative signal (RFC 8446): set when
                // ServerHello's `selected_identity` confirms the server
                // chose the offered PSK, before EncryptedExtensions even
                // arrives -- not an inference from "the reconnect worked",
                // which would also be true of a full fresh handshake.
                if (!self.tls_backend.engine.core.psk_authenticated) return error.ResumptionNotAccepted;
                self.resumed_round_confirmations += 1;
            }
        }
        if (!self.h3_started) return;
        try self.h3.pump(client);

        if (self.request_id == null) {
            var body_buf: [48]u8 = undefined;
            const body = try std.fmt.bufPrint(&body_buf, "resume-{d}-{d}", .{ self.id, self.round });
            self.request_id = try self.h3.sendRequest(client, .{
                .authority = "tardigrade.test",
                .path = "/soak",
                .body = body,
            });
        }
        if (self.request_id) |id| {
            if (try self.h3.pollResponse(id)) |response| {
                try testing.expectEqual(@as(u16, 200), response.status);
                try testing.expectEqualStrings("soak-response", response.body);
                self.h3.releaseResponse(id);
                self.request_id = null;
                self.requests_completed_total += 1;
                self.awaiting_ticket_iterations = 0;
                self.phase = .awaiting_ticket;
            }
        }
    }
};

test "soak.h3.bounded_resumed_reconnects" {
    const allocator = testing.allocator;

    var server_entropy = tls_core.production_crypto.OsEntropy{};
    var server_crypto_provider_state = tls_core.production_crypto.Provider.init(server_entropy.entropy());
    var server_resumption = try tls_core.resumption_runtime.Runtime.init(
        allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = nowUnixMsForResumption },
        server_crypto_provider_state.cryptoProvider(),
    );
    defer server_resumption.deinit();
    var outcome_counts = ResumptionOutcomeCounts{};
    server_resumption.setObserver(.{ .ctx = &outcome_counts, .onResumptionOutcomeFn = ResumptionOutcomeCounts.onOutcome });

    var client_entropy = tls_core.production_crypto.OsEntropy{};
    var client_crypto_provider_state = tls_core.production_crypto.Provider.init(client_entropy.entropy());
    var client_resumption = try tls_core.resumption_runtime.Runtime.init(
        allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = nowUnixMsForResumption },
        client_crypto_provider_state.cryptoProvider(),
    );
    defer client_resumption.deinit();

    var fixed = tls_core.credentials.FixedCredentialProvider.init(
        tls_core.credentials.testdata.identity(),
        tls_core.credentials.testdata.ignoredEntropy(),
    );
    defer fixed.deinit();
    var logger = http3_runtime.Logger.init(.err, "http3-soak-resume-test");
    var handler_state = SoakHandlerState{};
    var runtime = try http3_runtime.Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        // The one line that actually enables this leg: everything else
        // (PSK resolver, resume-compatibility policy, resumption-decision
        // observer) is wired onto every accepted connection automatically
        // by `accept()` once this is non-null.
        .resumption_runtime = &server_resumption,
        .request_handler = soakHandler,
        .request_handler_ctx = &handler_state,
    });
    defer runtime.deinit();
    runtime.start();

    const rounds_per_worker: usize = if (soakHeavyEnabled()) 10 else 4;
    // One request per round here (unlike the primary soak's
    // `requests_per_round`), so rounds and requests coincide as the
    // progress axis `WorkloadMonitor`/`CacheHighWater` split on.
    const total_work = resumption_worker_count * rounds_per_worker;

    const scenario = "soak.h3.bounded_resumed_reconnects";
    const before_sample = try sampleResources(allocator, &runtime, scenario, "before");

    var workers = try allocator.alloc(ResumptionWorker, resumption_worker_count);
    defer allocator.free(workers);
    var workers_initialized: usize = 0;
    defer {
        for (workers[0..workers_initialized]) |*w| w.deinit();
    }
    for (0..resumption_worker_count) |i| {
        workers[i] = try ResumptionWorker.init(allocator, i, rounds_per_worker, runtime.local_address, &client_resumption);
        workers_initialized += 1;
        try workers[i].beginRound();
    }

    var pollfds_buf = try allocator.alloc(posix.pollfd, resumption_worker_count);
    defer allocator.free(pollfds_buf);

    var monitor = WorkloadMonitor.init(allocator, scenario, total_work);
    var cache_high_water: CacheHighWater = .{};

    const deadline = nowUs() + 60_000_000;
    var iterations: usize = 0;
    const max_iterations: usize = 400_000;

    while (nowUs() < deadline) : (iterations += 1) {
        try testing.expect(iterations < max_iterations);

        var finished: usize = 0;
        for (workers) |*w| {
            if (w.phase == .round_done) {
                finished += 1;
                continue;
            }
            try w.flushTransmit();
        }
        if (finished == resumption_worker_count) break;

        var poll_count: usize = 0;
        var next_wake: u64 = nowUs() + 20_000;
        for (workers) |*w| {
            if (w.phase == .round_done) continue;
            pollfds_buf[poll_count] = .{ .fd = w.socket.fd, .events = posix.POLL.IN, .revents = 0 };
            poll_count += 1;
            if (w.client) |c| {
                if (c.nextTimeoutUs()) |t| next_wake = @min(next_wake, t);
            }
        }
        const now = nowUs();
        const timeout_ms: i32 = @intCast(@min((next_wake -| now) / 1_000 + 1, 20));
        _ = try posix.poll(pollfds_buf[0..poll_count], timeout_ms);

        for (workers) |*w| {
            if (w.phase == .round_done) continue;
            try w.drainRecv();
        }
        for (workers) |*w| {
            if (w.phase == .round_done) continue;
            try w.step();
        }

        var completed: usize = 0;
        for (workers) |w| completed += w.requests_completed_total;
        try monitor.tick(&runtime, completed);
        cache_high_water.observe(&client_resumption, &server_resumption);
    }

    const end_workload_sample = try sampleResources(allocator, &runtime, scenario, "end_workload");

    for (workers) |*w| w.deinit();
    workers_initialized = 0;

    _ = try waitRuntimeSnapshot(&runtime, hasNoTrackedConnections);
    const after_settle_sample = try sampleResources(allocator, &runtime, scenario, "after_settle");

    // Every planned request completed and every reconnect (every round past
    // the first) genuinely resumed -- the primary point of this leg.
    var total_confirmed: usize = 0;
    for (workers) |w| {
        try testing.expectEqual(rounds_per_worker, w.requests_completed_total);
        total_confirmed += w.resumed_round_confirmations;
    }
    const expected_resumed_rounds = resumption_worker_count * (rounds_per_worker - 1);
    try testing.expectEqual(expected_resumed_rounds, total_confirmed);
    try testing.expectEqual(resumption_worker_count * rounds_per_worker, handler_state.requests.load(.monotonic));

    // Independent server-side confirmation via the production resumption
    // runtime's own observer (see the doc comment above `ResumptionWorker`):
    // every resumed round's PSK was actually accepted, never merely offered
    // and missed/rejected, and round 0's plain fresh handshake never even
    // reaches this observer (the server's PSK selection short-circuits
    // before notifying when the ClientHello carries no PSK extension at
    // all), so `full_handshake` staying zero is expected, not incidental.
    try testing.expectEqual(expected_resumed_rounds, outcome_counts.accepted);
    try testing.expectEqual(@as(usize, 0), outcome_counts.miss);
    try testing.expectEqual(@as(usize, 0), outcome_counts.incompatible);
    try testing.expectEqual(@as(usize, 0), outcome_counts.fatal);
    try testing.expectEqual(@as(usize, 0), outcome_counts.full_handshake);

    // Same bounded resource/settle checks as the primary soak, folded into
    // this leg per the PR review rather than only proving resumption in
    // isolation.
    try testing.expectEqual(@as(usize, 0), after_settle_sample.tracked_connections);
    try testing.expectEqual(@as(usize, 0), after_settle_sample.active_cid_routes);
    try testing.expectEqual(@as(usize, 0), after_settle_sample.native_connections);

    var final_open_fds = after_settle_sample.open_fds;
    if (final_open_fds > before_sample.open_fds) {
        const fd_deadline = nowUs() + 2_000_000;
        while (final_open_fds > before_sample.open_fds and nowUs() < fd_deadline) {
            compat.sleepNs(50 * std.time.ns_per_ms);
            final_open_fds = try readOpenFdCount(allocator, std.c.getpid());
        }
        std.debug.print(
            "{s}: after_settle open_fds re-sampled to {d} (baseline {d})\n",
            .{ scenario, final_open_fds, before_sample.open_fds },
        );
    }
    try testing.expect(final_open_fds <= before_sample.open_fds);

    // RSS-slope and connection/CID-state plateau, same shape and margins as
    // the primary soak.
    try monitor.checkGrowthAndPlateau(allocator, before_sample, end_workload_sample, 8192, resumption_worker_count * 4);

    // Bounded resumption-cache occupancy (PR review P1): resumption cache
    // entries are *expected* to retain a high-water mark rather than return
    // to zero -- unlike connection/CID state above, this is state the
    // primary soak never exercises at all, and `server_resumption`/
    // `client_resumption` are intentionally still alive when
    // `after_settle_sample` was taken. Unlike connection/CID state, an empty
    // cache filling steadily toward capacity over the *entire* run (nothing
    // to evict, so nothing plateaus, until capacity is actually reached) is
    // expected, correct behavior -- so the meaningful "bounded, not
    // unbounded" proof is a hard ceiling against the cache's own configured
    // per-origin capacity, not a first-half/second-half plateau margin.
    const client_cache_limit = tls_core.session_cache.Limits.client_default.max_entries_per_origin;
    const server_cache_limit = tls_core.session_cache.Limits.stateful_server_default.max_entries_per_origin;
    if (cache_high_water.client_entries > client_cache_limit or cache_high_water.server_entries > server_cache_limit) {
        std.debug.print(
            "{s}: resumption-cache occupancy exceeded configured capacity -- " ++
                "client={d} (limit {d}) server={d} (limit {d})\n",
            .{ scenario, cache_high_water.client_entries, client_cache_limit, cache_high_water.server_entries, server_cache_limit },
        );
        return error.PossibleResumptionCacheGrowth;
    }

    // Distinct from connection/CID state, which correctly drains to zero
    // above: the whole point of the cache is that it keeps entries after
    // the connections that populated it have closed and settled, ready for
    // a future reconnect this test does not itself make.
    const client_entries_after_settle = client_resumption.client_cache.?.count();
    const server_entries_after_settle = server_resumption.server_cache.?.count();
    try testing.expect(client_entries_after_settle > 0);
    try testing.expect(server_entries_after_settle > 0);
    std.debug.print(
        "{s}: after_settle resumption cache occupancy client={d} server={d} (client_limit={d} server_limit={d})\n",
        .{ scenario, client_entries_after_settle, server_entries_after_settle, client_cache_limit, server_cache_limit },
    );
}

// ---------------------------------------------------------------------------
// Cancellation soak leg (#247 Lane B, PR review): "cancellation/reset
// activity where the existing client/harness can exercise it honestly" -- the
// real client here already can. `H3.sendRequest` returns the actual request
// stream ID, native `Connection.resetStream`/`stopSending` are public, and
// production `http3.conn.Conn.pump()`'s server-side `pumpRequests` already
// handles `error.StreamReset` on a request stream by removing it from the
// tracked request map (`reset_requests`/`finishRequest` in
// `src/http3/conn.zig`). The existing deterministic `quic_h3_e2e` reset test
// proves QUIC-level reset propagation between two directly-pumped
// connections; it does not prove repeated reset ownership/cleanup through
// the full `http3_runtime.Runtime` composition over real UDP -- the
// resource/lifecycle case this soak lane exists for.
//
// #247's matrix row is explicitly full-duplex: "RESET_STREAM / STOP_SENDING
// lifecycle is idempotent and cleans stream accounting". A single
// `resetStream` only abandons the client->server (request) direction; the
// server->client (response) direction needs `stopSending` too, and per
// RFC 9000 SS3.5 a peer that receives STOP_SENDING must answer with its own
// RESET_STREAM -- so both directions closing was also the concrete trigger
// for the `Stream.state()` terminal-precedence fix in `quic/stream.zig`
// (see that file's regression test). Proving that fix under a live
// composition, not just the one-shot-then-teardown shape this leg started
// with, requires *multiple* cancel+follow-up cycles on the *same*
// established connection before it closes -- a single cycle per connection
// can never show whether per-stream accounting keeps working correctly
// while the connection stays alive.
// ---------------------------------------------------------------------------

const reset_worker_count: usize = 2;
// RFC 9114 SS8.1: H3_REQUEST_CANCELLED, the application error code an
// HTTP/3 client uses to abandon a request it no longer wants answered.
const h3_request_cancelled: u64 = 0x010c;

const ResetTransportCapture = struct {
    stream_resets: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    fn onDelta(ctx: *anyopaque, delta: http3_runtime.QuicTransportDelta) void {
        const self: *ResetTransportCapture = @ptrCast(@alignCast(ctx));
        _ = self.stream_resets.fetchAdd(delta.stream_resets, .monotonic);
    }
};

const ResetWorkerPhase = enum { active, closing, done };

const ResetWorker = struct {
    id: usize,
    allocator: std.mem.Allocator,
    socket: UdpSocket,
    runtime_addr: quic.udp.Address,
    // One connection, established once and reused across every cycle --
    // deliberately not per-cycle like the primary/resumption workers, so
    // per-stream accounting (the point of this leg) is observed while the
    // connection stays alive rather than getting reset by teardown.
    cycles_target: usize,
    cycles_completed: usize = 0,
    provider_storage: test_quic_crypto.HandshakeProviderStorage = .{},
    tls_backend: tls_backend.Tls13Backend = undefined,
    client: ?*Connection = null,
    h3: H3 = undefined,
    path: quic.path.PathKey = undefined,
    h3_started: bool = false,
    phase: ResetWorkerPhase = .active,
    // Whether this cycle's cancel-a-request-immediately step already ran.
    // One cancel per cycle, always the first thing this worker does once
    // established/between cycles -- separate from `request_id`, which
    // tracks the *normal* follow-up request that proves the connection
    // still works afterward.
    cancel_done: bool = false,
    request_id: ?u64 = null,
    requests_completed_total: usize = 0,

    fn init(allocator: std.mem.Allocator, id: usize, cycles_target: usize, runtime_addr: quic.udp.Address) !ResetWorker {
        return ResetWorker{
            .id = id,
            .allocator = allocator,
            .socket = try UdpSocket.open(),
            .runtime_addr = runtime_addr,
            .cycles_target = cycles_target,
        };
    }

    fn cids(self: *const ResetWorker) struct { client_cid: [8]u8, odcid: [8]u8 } {
        var client_cid = [_]u8{0xf0} ** 8;
        var odcid = [_]u8{0xa0} ** 8;
        client_cid[4] = @intCast(self.id);
        client_cid[7] = 0xf0;
        odcid[4] = @intCast(self.id);
        odcid[7] = 0xa5;
        return .{ .client_cid = client_cid, .odcid = odcid };
    }

    fn beginConnection(self: *ResetWorker) !void {
        const ids = self.cids();
        self.provider_storage = .{};
        self.tls_backend = tls_backend.Tls13Backend.initClient(
            .{ .hello_random = [_]u8{0xd4} ** 32 },
            self.provider_storage.init(0xa000 + self.id * 0x100),
            .{ .pinned_certificate = tls_core.credentials.testdata.certificate_der },
        );
        self.path = .{
            .local = addressFromSockaddrIn(self.socket.addr),
            .remote = self.runtime_addr,
        };
        self.client = try Connection.init(self.allocator, .{
            .role = .client,
            .local_cid = &ids.client_cid,
            .original_destination_cid = &ids.odcid,
            .initial_secret_dcid = &ids.odcid,
            .tls = self.tls_backend.backend(),
            .crypto_provider = test_quic_crypto.testDefaultProvider(),
            .now_us = nowUs(),
            .initial_path = self.path,
        });
        self.h3 = H3.init(self.allocator, .client);
        self.h3_started = false;
        self.phase = .active;
        self.cancel_done = false;
        self.request_id = null;
    }

    fn closeConnection(self: *ResetWorker) void {
        if (self.client) |c| {
            self.h3.deinit();
            c.deinit();
            self.client = null;
        }
    }

    fn deinit(self: *ResetWorker) void {
        self.closeConnection();
        self.socket.close();
    }

    fn flushTransmit(self: *ResetWorker) !void {
        const client = self.client orelse return;
        var out: [2048]u8 = undefined;
        while (client.pollTransmitOnPath(&out, nowUs())) |t| {
            try self.socket.sendTo(sockaddrInFromAddress(t.path.remote), t.bytes);
        }
    }

    fn drainRecv(self: *ResetWorker) !void {
        const client = self.client orelse return;
        var in: [2048]u8 = undefined;
        while (try self.socket.recv(&in)) |datagram| {
            try client.ingestOnPath(datagram, self.path, test_challenge_entropy, nowUs());
        }
    }

    fn step(self: *ResetWorker) !void {
        if (self.phase == .closing) {
            // `client.close(...)` was queued last iteration and already
            // flushed by this iteration's earlier `flushTransmit` call (the
            // outer loop's per-iteration order is flush, poll/recv, step);
            // safe to tear down the connection now. The socket stays open
            // -- this worker never reconnects, so the final `deinit` in the
            // test's own cleanup closes it exactly once.
            self.closeConnection();
            self.phase = .done;
            return;
        }

        const client = self.client orelse return;
        client.onTimeout(nowUs());

        if (!self.h3_started and client.isEstablished()) {
            try self.h3.start(client);
            self.h3_started = true;
        }
        if (!self.h3_started) return;
        try self.h3.pump(client);

        if (!self.cancel_done) {
            // Cancel a request the instant it opens, before this outer
            // iteration's `flushTransmit` even runs: the request, its
            // RESET_STREAM, and its STOP_SENDING all go out together in the
            // next flush -- the realistic "changed my mind immediately"
            // shape, not a mid-response abort (`H3.sendRequest` here always
            // writes a complete request with `fin=true` in one call; there
            // is no lower-level partial-write API this harness exposes to
            // cancel mid-body instead). Full-duplex: `resetStream`
            // abandons the client->server request direction, `stopSending`
            // abandons the server->client response direction -- per
            // RFC 9000 SS3.5 the server answers `stopSending` with its own
            // RESET_STREAM, which is what actually closes the *send* side
            // of the server's stream and exercises the accounting fix in
            // `quic/stream.zig`.
            const cancelled_id = try self.h3.sendRequest(client, .{
                .authority = "tardigrade.test",
                .path = "/soak",
                .body = "cancel-me",
            });
            try client.resetStream(cancelled_id, h3_request_cancelled);
            try client.stopSending(cancelled_id, h3_request_cancelled);
            // Drop client-side pending-response bookkeeping now: this
            // worker will never poll for it, matching the primary/
            // resumption workers' `releaseResponse` call once a request's
            // outcome (there, a real response; here, an intentional
            // cancellation) is settled.
            self.h3.releaseResponse(cancelled_id);
            self.cancel_done = true;
            return;
        }

        if (self.request_id == null) {
            var body_buf: [64]u8 = undefined;
            const body = try std.fmt.bufPrint(&body_buf, "reset-followup-{d}-{d}", .{ self.id, self.cycles_completed });
            self.request_id = try self.h3.sendRequest(client, .{
                .authority = "tardigrade.test",
                .path = "/soak",
                .body = body,
            });
        }
        if (self.request_id) |id| {
            if (try self.h3.pollResponse(id)) |response| {
                try testing.expectEqual(@as(u16, 200), response.status);
                try testing.expectEqualStrings("soak-response", response.body);
                self.h3.releaseResponse(id);
                self.request_id = null;
                self.requests_completed_total += 1;
                self.cycles_completed += 1;
                if (self.cycles_completed >= self.cycles_target) {
                    client.close(0, "soak-cycles-done", nowUs());
                    self.phase = .closing;
                } else {
                    self.cancel_done = false;
                }
            }
        }
    }
};

test "soak.h3.bounded_cancelled_requests" {
    const allocator = testing.allocator;

    var fixed = tls_core.credentials.FixedCredentialProvider.init(
        tls_core.credentials.testdata.identity(),
        tls_core.credentials.testdata.ignoredEntropy(),
    );
    defer fixed.deinit();
    var logger = http3_runtime.Logger.init(.err, "http3-soak-reset-test");
    var handler_state = SoakHandlerState{};
    var reset_capture = ResetTransportCapture{};
    var runtime = try http3_runtime.Runtime.init(allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .request_handler = soakHandler,
        .request_handler_ctx = &handler_state,
        // Independent server-side confirmation the reset actually reached
        // and was folded by the production runtime, not only that the
        // client called `resetStream` (see the assertion on
        // `reset_capture.stream_resets` below).
        .quic_transport_metrics_ctx = &reset_capture,
        .quic_transport_metrics_cb = ResetTransportCapture.onDelta,
    });
    defer runtime.deinit();
    runtime.start();

    // Heavy tier deliberately exceeds the native transport's default
    // `initial_max_streams_bidi = 100` (60 cycles * 2 streams/cycle = 120
    // request streams on each persistent connection): this leg's whole
    // point is a *persistent* connection surviving many cancel cycles, so
    // it is the natural place to prove `StreamManager.maybeClose`'s
    // RFC 9000 SS4.6 MAX_STREAMS replenishment holds up under a real soak
    // rather than only the deterministic single-connection unit regression
    // in `connection.zig`. Without replenishment this would fail outright
    // once the 51st cycle tried to open its 101st stream.
    const cycles_per_worker: usize = if (soakHeavyEnabled()) 60 else 4;
    const total_work = reset_worker_count * cycles_per_worker;

    const scenario = "soak.h3.bounded_cancelled_requests";
    const before_sample = try sampleResources(allocator, &runtime, scenario, "before");

    var workers = try allocator.alloc(ResetWorker, reset_worker_count);
    defer allocator.free(workers);
    var workers_initialized: usize = 0;
    defer {
        for (workers[0..workers_initialized]) |*w| w.deinit();
    }
    for (0..reset_worker_count) |i| {
        workers[i] = try ResetWorker.init(allocator, i, cycles_per_worker, runtime.local_address);
        workers_initialized += 1;
        try workers[i].beginConnection();
    }

    var pollfds_buf = try allocator.alloc(posix.pollfd, reset_worker_count);
    defer allocator.free(pollfds_buf);

    var monitor = WorkloadMonitor.init(allocator, scenario, total_work);

    const deadline = nowUs() + 60_000_000;
    var iterations: usize = 0;
    const max_iterations: usize = 400_000;

    while (nowUs() < deadline) : (iterations += 1) {
        try testing.expect(iterations < max_iterations);

        var finished: usize = 0;
        for (workers) |*w| {
            if (w.phase == .done) {
                finished += 1;
                continue;
            }
            try w.flushTransmit();
        }
        if (finished == reset_worker_count) break;

        var poll_count: usize = 0;
        var next_wake: u64 = nowUs() + 20_000;
        for (workers) |*w| {
            if (w.phase == .done) continue;
            pollfds_buf[poll_count] = .{ .fd = w.socket.fd, .events = posix.POLL.IN, .revents = 0 };
            poll_count += 1;
            if (w.client) |c| {
                if (c.nextTimeoutUs()) |t| next_wake = @min(next_wake, t);
            }
        }
        const now = nowUs();
        const timeout_ms: i32 = @intCast(@min((next_wake -| now) / 1_000 + 1, 20));
        _ = try posix.poll(pollfds_buf[0..poll_count], timeout_ms);

        for (workers) |*w| {
            if (w.phase == .done) continue;
            try w.drainRecv();
        }
        for (workers) |*w| {
            if (w.phase == .done) continue;
            try w.step();
        }

        var completed: usize = 0;
        for (workers) |w| completed += w.requests_completed_total;
        try monitor.tick(&runtime, completed);
    }

    const end_workload_sample = try sampleResources(allocator, &runtime, scenario, "end_workload");

    for (workers) |*w| w.deinit();
    workers_initialized = 0;

    _ = try waitRuntimeSnapshot(&runtime, hasNoTrackedConnections);
    const after_settle_sample = try sampleResources(allocator, &runtime, scenario, "after_settle");

    // Every cycle's cancelled request was actually reset in both
    // directions at the production runtime -- the accumulated
    // `stream_resets` transport-metrics delta equals exactly twice the
    // planned cycle count, proving both halves reached and were folded by
    // `http3_runtime.Runtime` itself, not only that the client invoked an
    // API: once from the server receiving the client's `RESET_STREAM`
    // (`receiveResetStream`, closing the server's recv side), and once
    // from the server's own RFC 9000 SS3.5 auto-`RESET_STREAM` in response
    // to the client's `STOP_SENDING` (`sendResetStream`, closing the
    // server's send side -- this is the half that exercises the
    // `Stream.state()` terminal-precedence fix). Every cycle's follow-up
    // request on the *same*, still-open connection completed normally:
    // proof the cancellation did not poison the connection, repeatedly,
    // not just once before teardown.
    for (workers) |w| {
        try testing.expectEqual(cycles_per_worker, w.requests_completed_total);
    }
    try testing.expectEqual(total_work * 2, reset_capture.stream_resets.load(.monotonic));
    // And the cancelled requests never escaped into the application
    // handler -- only the normal follow-ups did.
    try testing.expectEqual(total_work, handler_state.requests.load(.monotonic));

    try testing.expectEqual(@as(usize, 0), after_settle_sample.tracked_connections);
    try testing.expectEqual(@as(usize, 0), after_settle_sample.active_cid_routes);
    try testing.expectEqual(@as(usize, 0), after_settle_sample.native_connections);

    var final_open_fds = after_settle_sample.open_fds;
    if (final_open_fds > before_sample.open_fds) {
        const fd_deadline = nowUs() + 2_000_000;
        while (final_open_fds > before_sample.open_fds and nowUs() < fd_deadline) {
            compat.sleepNs(50 * std.time.ns_per_ms);
            final_open_fds = try readOpenFdCount(allocator, std.c.getpid());
        }
        std.debug.print(
            "{s}: after_settle open_fds re-sampled to {d} (baseline {d})\n",
            .{ scenario, final_open_fds, before_sample.open_fds },
        );
    }
    try testing.expect(final_open_fds <= before_sample.open_fds);

    try monitor.checkGrowthAndPlateau(allocator, before_sample, end_workload_sample, 8192, reset_worker_count * 4);
}
