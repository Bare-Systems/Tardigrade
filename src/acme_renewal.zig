//! Native ACME automatic-HTTPS renewal scheduler, bounded backoff and
//! restart recovery (#835, A5 of epic #759, design
//! `docs/ACME_AUTOMATIC_HTTPS.md` §5, §5.4, §5.5, §9.4).
//!
//! `Worker` is the single lifetime-managed owner of every managed group's
//! issuance *and* ongoing renewal, replacing A4's one-shot
//! `acme_activation.runBootstrapOnce`/`BootstrapCtx`. Every pass repeats the
//! same recover-first, issue-what-is-due, publish-the-complete-set sequence
//! A4 already proved at startup (`acme_activation.recoverFromDisk`,
//! `loadManagedBundleSet`, `NativeCredentialStore.commitPreparedReload`),
//! now gated by `acme.renewal_policy.nextAttempt` against the *currently
//! committed* certificate's own validity and a durable per-group
//! `acme.renewal_state` record, instead of running exactly once.
//!
//! ## Scheduling
//!
//! Each pass (`tick`) opens the state directory once, computes a due/sleep
//! decision for every group from `acme.activate.loadCommitted` (so a
//! mismatched name set -- no generation satisfies the exact requested SAN
//! set -- is already "no certificate", i.e. immediately due, with no
//! separate `names_changed` tracking needed) and the durable retry record,
//! then closes the state directory before any network access. Due groups
//! are attempted sequentially against one CA `Session` (design §9.1: "one
//! serialized worker" -- this *is* the bounded concurrency; there is no
//! second worker to coordinate with). A group's own failure never aborts
//! another group's attempt in the same pass.
//!
//! `group_list` is fixed for the life of the worker: the hot-reload path
//! (`gateway_shutdown.acmeHttp01ListenerConfigChanged`) already rejects any
//! config reload that would change `tls_acme_domains_spec`, so this worker
//! never needs to react to a changed managed-name set while running --
//! only to shutdown cancellation, which `stopAndJoin` delivers through the
//! same interruptible `acme.orders.Waiter`/`Cancel` seam `acme.orders.obtain`
//! already uses for its own network waits.
//!
//! ## Failure handling
//!
//! A per-group CA/verification failure is classified with the existing
//! `acme.client.classify` taxonomy (transport/protocol/persistence/
//! resource) and recorded in `acme.renewal_state`, which
//! `acme.renewal_policy.nextAttempt`'s bounded exponential backoff and
//! cross-restart failure floor then consume on the next pass. A setup
//! failure that makes every group's attempt moot (opening the ACME
//! account) is itself classified: `persistence`-class failures (state-dir
//! ownership/permissions, a corrupt or mismatched account record) are
//! design §5.2's "Fatal configuration" and stop the worker for the process
//! lifetime -- serving continues on whatever was last published. Any other
//! class is logged and retried no sooner than the bounded failure floor.
//!
//! ## What this never does
//!
//! Never deletes or replaces a still-valid committed generation on a failed
//! attempt (`acme.activate.verifyAndPersist` already guarantees that).
//! Never writes `acme.renewal_state` while cancelled mid-attempt (a
//! `error.Cancelled` from `acme.orders.obtain` is dropped silently --
//! shutdown is already in progress, and the next process start recomputes
//! the schedule fresh from committed certificate validity alone). Never
//! holds the state-directory lock during CA network I/O.

const std = @import("std");
const compat = @import("zig_compat");
const http = @import("http.zig");
const acme_activation = @import("acme_activation.zig");

const acme = http.acme;

pub const ManagedBundleSpec = acme_activation.ManagedBundleSpec;
pub const NativeCredentialStore = acme_activation.NativeCredentialStore;
pub const SniCertSpec = acme_activation.SniCertSpec;
pub const PublishedHosts = acme_activation.PublishedHosts;
pub const ChallengeStore = http.acme_http01_listener.ChallengeStore;

pub const IssueOptions = struct {
    directory_url: []const u8,
    contact_email: []const u8 = "",
    terms_of_service_agreed: bool = false,
    account_key_path: []const u8 = "",
    /// Borrowed; already loaded by the caller (design §9.3: before any
    /// privilege drop/chroot). `Worker`'s own per-attempt `TlsDialer`
    /// retains its own reference, so the caller may release its copy any
    /// time after `Worker.stopAndJoin()` returns.
    trust_anchors: *acme.transport.TrustAnchorSnapshot,
};

/// Bounded, secret-free per-group snapshot for operators (design §9.4):
/// the same shape `tardigrade_acme_not_after_seconds{group}`,
/// `_next_attempt_timestamp_seconds{group}` and a closed failure-class
/// enum would expose, index-aligned with `Worker.group_list.slice()`
/// rather than carrying a hostname -- a future metrics exporter must label
/// by the group's own `acme.groups.groupId` digest, never a raw hostname
/// or CA URL, to stay low-cardinality.
pub const GroupStatus = struct {
    not_after: ?i64 = null,
    next_attempt_at: i64 = 0,
    consecutive_failures: u32 = 0,
    last_failure_class: ?acme.client.FailureClass = null,
    /// Mirrors `Worker.pending_success[i]`: true once a fresh issuance has
    /// been durably persisted but the live provider has not yet been
    /// republished with it, so `consecutive_failures`/`last_failure_class`
    /// above still reflect whatever failure record predates this attempt
    /// rather than the attempt that is still pending activation.
    activation_pending: bool = false,
};

/// Production randomness is bounded to `acme.renewal_policy`'s accepted
/// `[-10, 10]` jitter range; tests inject a fixed value for determinism.
pub const Jitter = struct {
    ctx: ?*anyopaque = null,
    percentFn: *const fn (ctx: ?*anyopaque) i8 = defaultPercent,

    fn defaultPercent(_: ?*anyopaque) i8 {
        var byte: [1]u8 = undefined;
        compat.randomBytes(&byte);
        return @as(i8, @intCast(@mod(@as(i16, byte[0]), 21))) - 10;
    }

    pub fn percent(self: Jitter) i8 {
        return self.percentFn(self.ctx);
    }
};

pub const Worker = struct {
    allocator: std.mem.Allocator,
    state_dir_path: []const u8,
    default_cert_path: []const u8,
    default_key_path: []const u8,
    sni_certs: []const SniCertSpec,
    issue: IssueOptions,
    store: *NativeCredentialStore,
    challenge_store: *ChallengeStore,
    published: *PublishedHosts,
    /// Builds a publication snapshot from the currently live config rather
    /// than the startup-only manual cert/SNI mapping, so a renewal that
    /// completes after SIGHUP cannot resurrect stale manual credentials.
    /// Kept optional for focused unit tests.
    prepare_current_credentials: ?*const fn (
        ?*anyopaque,
        std.mem.Allocator,
        *NativeCredentialStore,
        []const ManagedBundleSpec,
    ) anyerror!NativeCredentialStore.PreparedReload = null,
    credential_config_ctx: ?*anyopaque = null,
    group_list: acme.groups.GroupList,
    /// Validated elsewhere (`edge_config.validateAcmeConfig`) to 1..60.
    renew_days_before_expiry: u32 = 30,
    logger: http.logger.Logger,

    unix_clock: acme.orders.UnixClock = .{},
    waiter: acme.orders.Waiter = .{},
    jitter: Jitter = .{},
    /// Upper bound on a single sleep, independent of how far away the
    /// furthest group's `next_attempt_at` is (design §5.5: "every 12h ±
    /// jitter"), so a long-lived process keeps re-validating its schedule
    /// against the wall clock instead of trusting one very old computation
    /// for weeks at a time.
    max_wake_interval_seconds: i64 = 12 * 60 * 60,

    cancel: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,

    status_mutex: compat.Mutex = .{},
    statuses: [acme.groups.max_groups]GroupStatus = @splat(.{}),

    /// Set when a group's issuance has been verified and durably persisted
    /// (`acme.activate.verifyAndPersist` committed it as `current`) but the
    /// following republish of the complete managed set has not yet
    /// succeeded -- the live TLS provider may still be serving a stale or
    /// absent credential even though disk already holds a valid one.
    /// Cleared only once a republish actually succeeds. In-memory only: a
    /// restart does not need to remember this, because
    /// `acme_activation.recoverFromDisk` unconditionally republishes
    /// whatever is committed at every startup regardless of this flag's
    /// value in whatever process came before.
    pending_publish: bool = false,
    /// Set, index-aligned with `group_list.slice()`, when a group's issuance
    /// succeeded this process's lifetime but the durable `acme.renewal_state`
    /// success record (`failures=0`) has not yet been written, because the
    /// live-activation half of that success (the following republish) has
    /// not yet succeeded. Resetting the failure record before activation
    /// actually lands would let `tick`'s decision and the operator-facing
    /// status/metrics advertise a clean renewal while the live provider may
    /// still be serving a stale or absent credential. Resolved (the record
    /// written, the flag cleared) only once `republishManagedSet` actually
    /// succeeds -- which may be several passes later than the issuance that
    /// set it, exactly tracking `pending_publish`'s own lifetime.
    pending_success: [acme.groups.max_groups]bool = @splat(false),
    /// Bounded wait before retrying a `.Locked` collision with a short-lived
    /// concurrent writer (a routine SIGHUP reload or another in-flight
    /// durable-state transition), distinct from `acme.renewal_policy`'s
    /// multi-minute CA-failure backoff floor: a lock held by a sibling
    /// in-process action is expected to clear in well under a second, not
    /// minutes, and retrying at the CA-failure floor would make a routine
    /// momentary collision look like a multi-minute outage.
    lock_retry_wait_seconds: i64 = 2,
    /// Per-group stable cooldown anchor for a corrupt `renewal.json`
    /// (`acme.renewal_state.loadOrConservativeDefault`'s `corrupt_since`),
    /// index-aligned with `group_list.slice()`.
    corrupt_anchor: [acme.groups.max_groups]?i64 = @splat(null),
    /// Test-only: substituted for the production TLS dialer in
    /// `attemptDueGroups`, the one call site `runLoop` itself uses. Lets a
    /// test exercise `runLoop`'s own scheduling/backoff decisions against a
    /// fake CA end-to-end instead of only the lower-level
    /// `attemptDueGroupsWithDialer` it wraps.
    dialer_override: ?acme.transport.Dialer = null,

    pub fn start(self: *Worker) !void {
        self.thread = try std.Thread.spawn(.{}, runThread, .{self});
    }

    /// Idempotent; safe to call even if `start` was never called or the
    /// thread already finished on its own. Waits for any in-flight attempt
    /// to notice cancellation and settle (design §5.5: "a cancelled attempt
    /// leaves `pending/` for resumption and publishes nothing") before
    /// returning.
    pub fn stopAndJoin(self: *Worker) void {
        self.cancel.store(true, .release);
        if (self.thread) |t| t.join();
        self.thread = null;
    }

    /// A bounded snapshot for operators/tests, index-aligned with
    /// `group_list.slice()`. `out` may be shorter than `group_list.len`.
    pub fn snapshotStatus(self: *Worker, out: []GroupStatus) void {
        self.status_mutex.lock();
        defer self.status_mutex.unlock();
        const n = @min(out.len, self.group_list.len);
        @memcpy(out[0..n], self.statuses[0..n]);
    }

    fn setStatus(self: *Worker, index: usize, status: GroupStatus) void {
        self.status_mutex.lock();
        defer self.status_mutex.unlock();
        self.statuses[index] = status;
    }
};

fn cancelCheck(ctx: ?*anyopaque) bool {
    const flag: *std.atomic.Value(bool) = @ptrCast(@alignCast(ctx.?));
    return flag.load(.acquire);
}

fn runThread(worker: *Worker) void {
    runLoop(worker) catch |err| {
        worker.logger.err(null, "ACME renewal worker stopped for the process lifetime (class={s}, error={s}); serving continues on existing credentials", .{ @tagName(acme.client.classify(err)), @errorName(err) });
    };
}

/// The one error path out of this loop is a `persistence`-class setup
/// failure (design §5.2 "Fatal configuration"); every other failure --
/// per-group CA/verification errors included -- is handled inside `tick`
/// or `attemptDueGroups` and never propagates here. `error.Locked`
/// specifically is never fatal at either call site: a short-lived
/// collision with another legitimate writer of the same state directory
/// (a routine SIGHUP reload, an overlapping durable-state transition) is
/// not corrupt or unsafe state, just a millisecond-scale race, and must
/// not be mistaken for the "Fatal configuration" case that stops the
/// worker for the rest of the process lifetime.
fn runLoop(worker: *Worker) !void {
    const cancel: acme.orders.Cancel = .{ .ctx = &worker.cancel, .checkFn = cancelCheck };
    while (!worker.cancel.load(.acquire)) {
        var scheduled = tick(worker) catch |err| {
            if (err == error.Locked) {
                worker.logger.warn(null, "ACME renewal: state directory busy (transient lock contention); retrying shortly", .{});
                if (worker.waiter.wait(lockRetryWaitMs(worker), cancel)) return;
                continue;
            }
            return err;
        };

        var any_due = false;
        for (0..worker.group_list.len) |i| {
            if (scheduled.due[i]) any_due = true;
        }
        if (any_due or worker.pending_publish) {
            attemptDueGroups(worker, scheduled) catch |err| handled: {
                if (err == error.Locked) {
                    worker.logger.warn(null, "ACME renewal: state directory busy during an issuance/publish pass (transient lock contention); retrying shortly", .{});
                    scheduled.earliest_next = @min(scheduled.earliest_next, worker.unix_clock.now() + worker.lock_retry_wait_seconds);
                    break :handled;
                }
                if (err == error.RetryStateNotPersisted) {
                    // A per-group failure happened *and* the durable retry
                    // record for it could not be written (disk full,
                    // permissions, a stuck lock): without this floor, the
                    // next pass would recompute the identical unmodified
                    // due record and re-contact the CA immediately, with no
                    // backoff at all. Not escalated to a permanent stop --
                    // unlike a corrupt/mismatched account record, a failed
                    // state write may well be writable again on the very
                    // next pass, and serving continues on the last live
                    // credential either way.
                    worker.logger.err(null, "ACME renewal: a per-group retry record failed to persist; applying a conservative retry floor to avoid hammering the CA", .{});
                    scheduled.earliest_next = @max(scheduled.earliest_next, worker.unix_clock.now() + acme.renewal_policy.retry_floor_seconds);
                    break :handled;
                }
                const class = acme.client.classify(err);
                if (class == .persistence) {
                    worker.logger.err(null, "ACME renewal worker stopped for the process lifetime: durable state is unusable (error={s}); serving continues on existing credentials", .{@errorName(err)});
                    return err;
                }
                worker.logger.warn(null, "ACME renewal: an issuance pass could not complete (class={s}, error={s})", .{ @tagName(class), @errorName(err) });
                // No per-group record was written (the failure was global,
                // before any group-specific attempt), so without this floor
                // the next pass would recompute the identical due time and
                // retry immediately forever.
                scheduled.earliest_next = @max(scheduled.earliest_next, worker.unix_clock.now() + acme.renewal_policy.retry_floor_seconds);
            };
        }
        if (worker.pending_publish) {
            // A pending republish is bounded local disk I/O, never a CA
            // call: retry it far sooner than the schedule a far-future
            // valid certificate would otherwise imply.
            scheduled.earliest_next = @min(scheduled.earliest_next, worker.unix_clock.now() + acme.renewal_policy.retry_floor_seconds);
        }
        if (worker.cancel.load(.acquire)) return;

        const now = worker.unix_clock.now();
        const wait_seconds = std.math.clamp(scheduled.earliest_next - now, 0, worker.max_wake_interval_seconds);
        const wait_ms: u32 = @intCast(@min(wait_seconds * 1000, @as(i64, std.math.maxInt(u32))));
        if (worker.waiter.wait(wait_ms, cancel)) return;
    }
}

fn lockRetryWaitMs(worker: *Worker) u32 {
    return @intCast(@min(worker.lock_retry_wait_seconds * 1000, @as(i64, std.math.maxInt(u32))));
}

const Scheduled = struct {
    due: [acme.groups.max_groups]bool = @splat(false),
    /// Failure count *before* this pass's attempt, captured once here so
    /// `attemptDueGroups` never needs to re-read `acme.renewal_state` (and
    /// risk a different value) between scheduling and recording.
    prior_failures: [acme.groups.max_groups]u32 = @splat(0),
    earliest_next: i64,
};

/// One read-only pass: for every managed group, combine the committed
/// generation's own validity (if any, and if it still matches the exact
/// requested name set) with the durable retry record into a
/// `acme.renewal_policy` decision, publish a bounded status snapshot, and
/// report which groups are due now. Holds the state-directory lock for the
/// whole pass (local disk only, no network) and releases it before
/// returning.
fn tick(worker: *Worker) !Scheduled {
    const now = worker.unix_clock.now();
    var scheduled = Scheduled{ .earliest_next = now + worker.max_wake_interval_seconds };
    var earliest: ?i64 = null;

    var state = try acme.state.StateDir.open(worker.state_dir_path);
    defer state.close();

    for (worker.group_list.slice(), 0..) |group, i| {
        var id_buf: [acme.groups.group_id_len]u8 = undefined;
        const group_id = acme.groups.groupId(&id_buf, group.slice());

        var loaded_opt = acme.activate.loadCommitted(worker.allocator, &state, group_id, group.slice(), now) catch |err| blk: {
            if (acme.activate.isHardError(err)) {
                // An ownership/permission/lock/I-O/memory failure says
                // nothing about whether the live credential is still good --
                // unlike a corrupt pointer, there is no safe "treat as no
                // certificate" fallback (that would schedule a fresh CA
                // issuance in the face of a security-relevant state problem
                // an operator needs to fix). Still give the group a stable
                // status and next-check time rather than silently dropping
                // it from scheduling for the rest of the process lifetime.
                worker.logger.err(null, "ACME renewal: committed-generation check failed for a managed group with an unsafe-state error (class={s}, error={s}); leaving its current credential untouched, not scheduling automatic recovery", .{ @tagName(acme.client.classify(err)), @errorName(err) });
                const next = now + acme.renewal_policy.retry_floor_seconds;
                worker.setStatus(i, .{ .next_attempt_at = next, .last_failure_class = .persistence });
                earliest = if (earliest) |e| @min(e, next) else next;
                continue;
            }
            worker.logger.warn(null, "ACME renewal: committed-generation check failed for a managed group (class={s}, error={s}); treating as having no certificate", .{ @tagName(acme.client.classify(err)), @errorName(err) });
            break :blk null;
        };
        defer if (loaded_opt) |*loaded| loaded.deinit(worker.allocator);

        var cert_validity: ?acme.renewal_policy.CertificateValidity = null;
        var not_after: ?i64 = null;
        if (loaded_opt) |*loaded| {
            cert_validity = .{ .not_before = loaded.meta.notBefore(), .not_after = loaded.meta.notAfter() };
            not_after = loaded.meta.notAfter();
        }

        var groups_dir = try state.openOrCreateSubdir(acme.activate.groups_dir_name);
        defer groups_dir.close();
        var group_dir = try groups_dir.openOrCreateSubdir(group_id);
        defer group_dir.close();
        const record = try acme.renewal_state.loadOrConservativeDefault(worker.allocator, &group_dir, now, &worker.corrupt_anchor[i]);

        const decision = try acme.renewal_policy.nextAttempt(.{
            .now = now,
            .certificate = cert_validity,
            .renew_days_before_expiry = worker.renew_days_before_expiry,
            .last_attempt_at = if (record.last_attempt_at == 0) null else record.last_attempt_at,
            .failures = record.failures,
            .retry_after_at = record.retry_after_at,
            .jitter_percent = worker.jitter.percent(),
        });

        worker.setStatus(i, .{
            .not_after = not_after,
            .next_attempt_at = decision.next_attempt_at,
            .consecutive_failures = record.failures,
            .last_failure_class = record.last_failure_class,
            .activation_pending = worker.pending_success[i],
        });

        if (decision.next_attempt_at <= now) {
            scheduled.due[i] = true;
            scheduled.prior_failures[i] = record.failures;
        }
        earliest = if (earliest) |e| @min(e, decision.next_attempt_at) else decision.next_attempt_at;
    }

    if (earliest) |e| scheduled.earliest_next = e;
    return scheduled;
}

/// One pass over every group `tick` marked due: open the ACME session
/// (account), attempt `obtain()` + `verifyAndPersist()` once per due group,
/// then -- if anything succeeded, or a previous pass's publish is still
/// pending -- rebuild and republish the complete managed set (design §7.1:
/// a publish for one group must never drop another). A group's own failure
/// never aborts the others; this function returns an error only for a
/// setup failure (account/session) that makes every due group's attempt
/// moot, or a failure to republish (`worker.pending_publish` is left set
/// either way, for the next pass to retry without reissuing).
fn attemptDueGroups(worker: *Worker, scheduled: Scheduled) !void {
    // Test-only seam: `runLoop`'s own catch/floor logic otherwise has no
    // way to be exercised end-to-end, since every other call in this file
    // routes through `attemptDueGroupsWithDialer` directly rather than
    // `runLoop`. Production `Worker`s never set this.
    if (worker.dialer_override) |d| return attemptDueGroupsWithDialer(worker, scheduled, d);
    var dialer_inst = http.acme_tls_dialer.TlsDialer.init(worker.issue.trust_anchors);
    defer dialer_inst.deinit();
    try attemptDueGroupsWithDialer(worker, scheduled, dialer_inst.dialer());
}

/// The CA-reachable half of `attemptDueGroups`, taking an already-built
/// `Dialer` rather than constructing the production TLS one -- the seam a
/// test substitutes `fake_ca.FakeCa.dialer()` through. A CA session is only
/// ever opened when at least one group is actually due this pass: a
/// publish-only retry (`worker.pending_publish` with nothing newly due)
/// must never contact the CA, both because it has nothing to ask for and
/// because a CA outage must not block recovering a republish that needs no
/// network access at all.
fn attemptDueGroupsWithDialer(worker: *Worker, scheduled: Scheduled, dialer: acme.transport.Dialer) !void {
    var any_due = false;
    for (0..worker.group_list.len) |i| {
        if (scheduled.due[i]) {
            any_due = true;
            break;
        }
    }

    var issued_any = false;
    var unrecorded_failure = false;
    if (any_due) {
        var transport_inst = acme.transport.Transport{ .allocator = worker.allocator, .dialer = dialer };
        // StateDir's advisory lock protects short durable-state transitions,
        // not the potentially minutes-long HTTP-01 order/polling loop. The
        // session retains its key/client after this scope, so a routine
        // SIGHUP reload can read the last committed managed set while a
        // renewal is in flight.
        const client_cancel: acme.client.Cancel = .{ .ctx = &worker.cancel, .checkFn = cancelCheck };
        const session = acme.client.Session.openUnlocked(worker.allocator, &transport_inst, worker.state_dir_path, .{
            .directory_url = worker.issue.directory_url,
            .contact_email = worker.issue.contact_email,
            .terms_of_service_agreed = worker.issue.terms_of_service_agreed,
            .account_key_path = worker.issue.account_key_path,
        }, worker.unix_clock.now(), client_cancel) catch |err| {
            if (err == error.Cancelled) return err;
            // The CA/account setup failure makes every due group's attempt
            // moot, but it must not look like "never attempted" on a crash
            // or restart immediately afterward: persist a bounded failure
            // record now, before propagating, so the durable cross-restart
            // retry floor applies even if the process dies right here.
            recordSetupFailureForDueGroups(worker, scheduled, err);
            return err;
        };
        defer session.close();

        for (worker.group_list.slice(), 0..) |group, i| {
            if (worker.cancel.load(.acquire)) break;
            if (!scheduled.due[i]) continue;
            switch (attemptAndRecord(worker, &session.client, group, i, scheduled.prior_failures[i])) {
                .issued => issued_any = true,
                .failed => {},
                .failed_unrecorded => unrecorded_failure = true,
            }
        }
    }
    if (issued_any or worker.pending_publish) {
        try republishManagedSet(worker);
        // The republish above either returned an error (propagated by
        // `try`, leaving `pending_success` untouched for the next pass to
        // resolve) or succeeded, in which case every group still carrying a
        // pending success from this or an earlier pass is now actually
        // live: write its durable success record for the first time.
        const now = worker.unix_clock.now();
        for (worker.group_list.slice(), 0..) |group, i| {
            if (!worker.pending_success[i]) continue;
            recordSuccess(worker, group, now) catch |rec_err| {
                worker.logger.err(null, "ACME renewal: failed to persist the success record for a managed group (error={s})", .{@errorName(rec_err)});
                continue;
            };
            worker.pending_success[i] = false;
        }
    }
    if (unrecorded_failure) return error.RetryStateNotPersisted;
}

/// Persist a bounded failure record for every group `tick` marked due, used
/// when a CA/account setup failure (not a per-group attempt) made this
/// entire pass moot. Best-effort: a failure to persist is logged, never
/// escalated, since the caller already has its own (CA-connectivity) error
/// to report.
fn recordSetupFailureForDueGroups(worker: *Worker, scheduled: Scheduled, err: anyerror) void {
    const now = worker.unix_clock.now();
    const class = acme.client.classify(err);
    for (worker.group_list.slice(), 0..) |group, i| {
        if (!scheduled.due[i]) continue;
        recordFailure(worker, group, now, class, scheduled.prior_failures[i], null) catch |rec_err| {
            worker.logger.err(null, "ACME renewal: failed to persist the retry record for a managed group after a CA setup failure (error={s})", .{@errorName(rec_err)});
        };
    }
}

/// Rebuild the complete managed bundle set from whatever is durably
/// committed and republish it (design §7.1: a publish for one group must
/// never drop another). Tracks success/failure in `worker.pending_publish`
/// so a failed publish -- the issued certificate is already safely
/// persisted, but not yet live -- is retried on a bounded floor without any
/// further CA contact, instead of waiting for the next cert-validity-driven
/// due time (which, now that the generation is committed, may be months
/// away).
fn republishManagedSet(worker: *Worker) !void {
    var bundles = blk: {
        var state = acme.state.StateDir.open(worker.state_dir_path) catch |err| {
            worker.pending_publish = true;
            return err;
        };
        defer state.close();
        break :blk acme_activation.loadManagedBundleSet(worker.allocator, &state, &worker.group_list, worker.unix_clock.now()) catch |err| {
            worker.pending_publish = true;
            return err;
        };
    };
    defer bundles.deinit();
    if (bundles.slice().len == 0) {
        worker.pending_publish = false;
        return;
    }
    // The state-directory lock was released after the durable generation was
    // fully loaded above; all later work is in memory.
    publishManagedBundles(worker, bundles.slice()) catch |err| {
        worker.pending_publish = true;
        return err;
    };
    for (bundles.slice()) |spec| {
        worker.published.markGroup(spec.hostnames) catch |err| {
            worker.pending_publish = true;
            return err;
        };
    }
    worker.pending_publish = false;
}

/// The three distinguishable outcomes of one group's attempt:
///  - `.issued`: the CA issued a fresh generation, durably persisted as
///    `current`. `Worker.pending_success[index]` is set so the record of
///    this success is written only once the following republish actually
///    makes it live (see `attemptDueGroupsWithDialer`).
///  - `.failed`: the attempt failed and the durable failure record was
///    written, so `acme.renewal_policy`'s backoff governs the next attempt.
///  - `.failed_unrecorded`: the attempt failed *and* the durable failure
///    record itself could not be written (disk full, permissions, a stuck
///    lock). Without a distinct outcome here, the caller would recompute an
///    unmodified due record on its very next pass and re-contact the CA
///    immediately, forever, with no backoff at all.
const AttemptOutcome = enum { issued, failed, failed_unrecorded };

/// Attempts one group and durably records the outcome. `index` is the
/// group's position in `worker.group_list.slice()`, used to set
/// `Worker.pending_success`. A cancellation mid-attempt is dropped silently:
/// the worker is already shutting down, and the next process start
/// recomputes the schedule fresh from committed certificate validity alone,
/// so there is nothing useful to persist.
fn attemptAndRecord(worker: *Worker, client: *acme.client.Client, group: acme.groups.Group, index: usize, prior_failures: u32) AttemptOutcome {
    const now = worker.unix_clock.now();
    issueGroup(worker, client, group) catch |err| {
        if (err == error.Cancelled) {
            worker.logger.info(null, "ACME renewal attempt cancelled by shutdown for a managed group", .{});
            return .failed;
        }
        const class = acme.client.classify(err);
        worker.logger.warn(null, "ACME renewal attempt failed for a managed group (class={s}, error={s})", .{ @tagName(class), @errorName(err) });
        recordFailure(worker, group, now, class, prior_failures, client.diagnostics.last_retry_after_s) catch |rec_err| {
            worker.logger.err(null, "ACME renewal: failed to persist the retry record for a managed group (error={s})", .{@errorName(rec_err)});
            return .failed_unrecorded;
        };
        return .failed;
    };
    worker.pending_success[index] = true;
    return .issued;
}

fn openGroupStateDir(worker: *Worker, group_id: []const u8) !struct { state: acme.state.StateDir, groups: acme.state.SubDir, group: acme.state.SubDir } {
    var state = try acme.state.StateDir.open(worker.state_dir_path);
    errdefer state.close();
    var groups_dir = try state.openOrCreateSubdir(acme.activate.groups_dir_name);
    errdefer groups_dir.close();
    const group_dir = try groups_dir.openOrCreateSubdir(group_id);
    return .{ .state = state, .groups = groups_dir, .group = group_dir };
}

fn recordFailure(worker: *Worker, group: acme.groups.Group, now: i64, class: acme.client.FailureClass, prior_failures: u32, retry_after_s: ?u32) !void {
    var id_buf: [acme.groups.group_id_len]u8 = undefined;
    const group_id = acme.groups.groupId(&id_buf, group.slice());
    var opened = try openGroupStateDir(worker, group_id);
    defer opened.group.close();
    defer opened.groups.close();
    defer opened.state.close();

    const retry_after_seconds = if (retry_after_s) |s| @min(@as(i64, s), acme.renewal_policy.retry_ceiling_seconds) else null;
    try acme.renewal_state.save(worker.allocator, &opened.group, .{
        .last_attempt_at = now,
        .failures = prior_failures +| 1,
        .last_failure_class = class,
        .retry_after_at = if (retry_after_seconds) |s| now + s else null,
    });
}

fn recordSuccess(worker: *Worker, group: acme.groups.Group, now: i64) !void {
    // `last_attempt_at` is the persisted *failure* backoff anchor. A fresh
    // published generation must clear it: renewal_policy intentionally
    // ignores old failure state after success, and retaining `now` here
    // would impose its five-minute failure floor even when the new
    // certificate is already inside the configured renewal window.
    _ = now;
    var id_buf: [acme.groups.group_id_len]u8 = undefined;
    const group_id = acme.groups.groupId(&id_buf, group.slice());
    var opened = try openGroupStateDir(worker, group_id);
    defer opened.group.close();
    defer opened.groups.close();
    defer opened.state.close();

    try acme.renewal_state.save(worker.allocator, &opened.group, .{ .last_attempt_at = 0, .failures = 0, .last_failure_class = null, .retry_after_at = null });
}

fn issueGroup(worker: *Worker, client: *acme.client.Client, group: acme.groups.Group) !void {
    var issued = try acme.orders.obtain(worker.allocator, client, worker.challenge_store, group.slice(), .{
        .cancel = .{ .ctx = &worker.cancel, .checkFn = cancelCheck },
    });
    defer issued.deinit(worker.allocator);

    // Hold the filesystem lock only for the atomic verify/persist step.
    var state = try acme.state.StateDir.open(worker.state_dir_path);
    defer state.close();
    var id_buf: [acme.groups.group_id_len]u8 = undefined;
    const group_id = acme.groups.groupId(&id_buf, group.slice());
    _ = try acme.activate.verifyAndPersist(worker.allocator, &state, group_id, &issued.key, issued.chain_pem, .{
        .hostnames = group.slice(),
        .now = worker.unix_clock.now(),
    });
}

fn publishManagedBundles(worker: *Worker, bundles: []const ManagedBundleSpec) !void {
    var attempts: u8 = 0;
    while (attempts < 3) : (attempts += 1) {
        var prepared = if (worker.prepare_current_credentials) |prepare|
            try prepare(worker.credential_config_ctx, worker.allocator, worker.store, bundles)
        else
            try worker.store.prepareReloadFromBundles(worker.default_cert_path, worker.default_key_path, worker.sni_certs, bundles);
        defer prepared.deinit();
        worker.store.commitPreparedReload(&prepared) catch |err| {
            if (err == error.StaleManualCredentialConfig) continue;
            return err;
        };
        return;
    }
    return error.StaleManualCredentialConfig;
}

// ---------------------------------------------------------------------------

const testing = std.testing;
const secrets = @import("crypto").secrets;

const TestDirs = struct {
    tmp: testing.TmpDir,
    state_dir: []u8,

    fn init(allocator: std.mem.Allocator) !TestDirs {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        const tmp_abs = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
        defer allocator.free(tmp_abs);
        const state_dir = try std.fmt.allocPrint(allocator, "{s}/state", .{tmp_abs});
        return .{ .tmp = tmp, .state_dir = state_dir };
    }

    fn deinit(self: *TestDirs, allocator: std.mem.Allocator) void {
        allocator.free(self.state_dir);
        self.tmp.cleanup();
    }
};

fn testTrustAnchors(allocator: std.mem.Allocator) !*acme.transport.TrustAnchorSnapshot {
    return acme.transport.TrustAnchorSnapshot.load(allocator, "src/pki/testdata/ecdsa_p256_ca.crt");
}

fn newTestWorker(allocator: std.mem.Allocator, dirs: *const TestDirs, group_list: acme.groups.GroupList, store: *NativeCredentialStore, challenge_store: *ChallengeStore, published: *PublishedHosts, trust_anchors: *acme.transport.TrustAnchorSnapshot) Worker {
    return .{
        .allocator = allocator,
        .state_dir_path = dirs.state_dir,
        .default_cert_path = "",
        .default_key_path = "",
        .sni_certs = &.{},
        .issue = .{ .directory_url = "https://ca.test/directory", .terms_of_service_agreed = true, .trust_anchors = trust_anchors },
        .store = store,
        .challenge_store = challenge_store,
        .published = published,
        .group_list = group_list,
        .logger = http.logger.Logger.init(.warn, "test"),
        // Production randomness (`Jitter.defaultPercent`) draws from the OS
        // entropy source, not a seeded PRNG: a test that left it at its
        // default would assert an exact backoff value against a result that
        // is only right 1-in-21 runs. Zero here, consistent with every
        // other test in this file asserting an exact `earliest_next`.
        .jitter = .{ .percentFn = struct {
            fn f(_: ?*anyopaque) i8 {
                return 0;
            }
        }.f },
    };
}

fn issueTestLeafForCsr(raw: ?*anyopaque, allocator: std.mem.Allocator, csr_der: []const u8, hostnames: []const []const u8) anyerror![]u8 {
    const ca: *const acme.test_cert_builder.TestCa = @ptrCast(@alignCast(raw.?));
    const now = compat.unixTimestamp();
    return ca.issueForCsr(allocator, csr_der, hostnames, now - 3600, now + 365 * 24 * 3600);
}

test "tick: a fresh certificate outside the renewal window is not due, and the status snapshot reports its expiry" {
    const allocator = testing.allocator;
    var dirs = try TestDirs.init(allocator);
    defer dirs.deinit(allocator);

    const hostnames = [_][]const u8{"a.example.test"};
    const now: i64 = 1_700_000_000;
    var leaf = try acme.test_cert_builder.selfSignedLeaf(allocator, &hostnames, now - 3600, now + 90 * acme.renewal_policy.seconds_per_day);
    defer allocator.free(leaf.pem);
    defer leaf.key.deinit();
    {
        var state = try acme.state.StateDir.open(dirs.state_dir);
        defer state.close();
        var id_buf: [acme.groups.group_id_len]u8 = undefined;
        const group_id = acme.groups.groupId(&id_buf, &hostnames);
        _ = try acme.activate.verifyAndPersist(allocator, &state, group_id, &leaf.key, leaf.pem, .{ .hostnames = &hostnames, .now = now });
    }

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    var challenge_store = ChallengeStore.init(allocator);
    defer challenge_store.deinit();
    var published = PublishedHosts.init(allocator);
    defer published.deinit();
    const trust_anchors = try testTrustAnchors(allocator);
    defer trust_anchors.release();

    var worker = newTestWorker(allocator, &dirs, try acme.groups.parse("a.example.test"), &store, &challenge_store, &published, trust_anchors);
    worker.unix_clock = .{ .ctx = @constCast(&now), .nowFn = struct {
        fn f(ctx: ?*anyopaque) i64 {
            const n: *const i64 = @ptrCast(@alignCast(ctx.?));
            return n.*;
        }
    }.f };

    const scheduled = try tick(&worker);
    try testing.expect(!scheduled.due[0]);
    try testing.expectEqual(now + 60 * acme.renewal_policy.seconds_per_day, scheduled.earliest_next);

    var statuses: [1]GroupStatus = undefined;
    worker.snapshotStatus(&statuses);
    try testing.expectEqual(now + 90 * acme.renewal_policy.seconds_per_day, statuses[0].not_after.?);
    try testing.expectEqual(now + 60 * acme.renewal_policy.seconds_per_day, statuses[0].next_attempt_at);
    try testing.expectEqual(@as(u32, 0), statuses[0].consecutive_failures);
}

test "tick: no certificate, an expired certificate, and a renamed group are all immediately due" {
    const allocator = testing.allocator;
    var dirs = try TestDirs.init(allocator);
    defer dirs.deinit(allocator);
    const now: i64 = 1_700_000_000;

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    var challenge_store = ChallengeStore.init(allocator);
    defer challenge_store.deinit();
    var published = PublishedHosts.init(allocator);
    defer published.deinit();
    const trust_anchors = try testTrustAnchors(allocator);
    defer trust_anchors.release();

    // No certificate at all.
    {
        var worker = newTestWorker(allocator, &dirs, try acme.groups.parse("new.example.test"), &store, &challenge_store, &published, trust_anchors);
        const scheduled = try tick(&worker);
        try testing.expect(scheduled.due[0]);
    }

    // An expired generation for a different group.
    const hostnames = [_][]const u8{"expired.example.test"};
    var leaf = try acme.test_cert_builder.selfSignedLeaf(allocator, &hostnames, now - 120 * acme.renewal_policy.seconds_per_day, now - acme.renewal_policy.seconds_per_day);
    defer allocator.free(leaf.pem);
    defer leaf.key.deinit();
    {
        var state = try acme.state.StateDir.open(dirs.state_dir);
        defer state.close();
        var id_buf: [acme.groups.group_id_len]u8 = undefined;
        const group_id = acme.groups.groupId(&id_buf, &hostnames);
        _ = try acme.activate.verifyAndPersist(allocator, &state, group_id, &leaf.key, leaf.pem, .{ .hostnames = &hostnames, .now = now - acme.renewal_policy.seconds_per_day - 1, .min_remaining_seconds = 0 });
    }
    var worker = newTestWorker(allocator, &dirs, try acme.groups.parse("expired.example.test"), &store, &challenge_store, &published, trust_anchors);
    worker.unix_clock = .{ .ctx = @constCast(&now), .nowFn = struct {
        fn f(ctx: ?*anyopaque) i64 {
            const n: *const i64 = @ptrCast(@alignCast(ctx.?));
            return n.*;
        }
    }.f };
    const scheduled = try tick(&worker);
    try testing.expect(scheduled.due[0]);

    // A committed generation whose SAN set no longer matches the (renamed)
    // configured group is treated exactly like "no certificate".
    var worker_renamed = newTestWorker(allocator, &dirs, try acme.groups.parse("renamed.example.test"), &store, &challenge_store, &published, trust_anchors);
    const renamed_scheduled = try tick(&worker_renamed);
    try testing.expect(renamed_scheduled.due[0]);
}

test "attemptDueGroupsWithDialer: a successful renewal resets the durable failure record and publishes the new chain" {
    const allocator = testing.allocator;
    var dirs = try TestDirs.init(allocator);
    defer dirs.deinit(allocator);
    const now: i64 = 1_700_000_000;

    var ca = acme.fake_ca.FakeCa.init(allocator);
    defer ca.deinit();
    ca.script.new_order.expires_override = "2099-01-01T00:00:00Z";
    var issuer = try acme.test_cert_builder.TestCa.init(allocator, now - 3600, now + 365 * 24 * 3600);
    defer issuer.deinit(allocator);
    ca.issued_chain_factory = .{ .ctx = &issuer, .makeFn = issueTestLeafForCsr };

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    var challenge_store = ChallengeStore.init(allocator);
    defer challenge_store.deinit();
    var published = PublishedHosts.init(allocator);
    defer published.deinit();
    const trust_anchors = try testTrustAnchors(allocator);
    defer trust_anchors.release();

    var worker = newTestWorker(allocator, &dirs, try acme.groups.parse("issued.example.test"), &store, &challenge_store, &published, trust_anchors);

    var scheduled = Scheduled{ .earliest_next = now };
    scheduled.due[0] = true;
    scheduled.prior_failures[0] = 2;
    try attemptDueGroupsWithDialer(&worker, scheduled, ca.dialer());
    try testing.expect(published.isPublished("issued.example.test"));

    const credentials = @import("tls_core").credentials;
    const selection = credentials.SelectionContext{
        .role = .server,
        .server_name = "issued.example.test",
        .peer_signature_schemes = &.{0x0403},
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = null,
        .auth_policy = .{},
    };
    const selected = switch (try store.provider().selectCredential(&selection)) {
        .complete => |value| value,
        .pending => return error.TestUnexpectedPending,
    };
    defer selected.release();
    try testing.expect(selected.certificateChain().leaf() != null);

    // The durable record was reset, not merely left at the prior failure
    // count: a fresh `tick` sees zero failures and a far-future due time.
    const fresh = try tick(&worker);
    try testing.expect(!fresh.due[0]);
    var statuses: [1]GroupStatus = undefined;
    worker.snapshotStatus(&statuses);
    try testing.expectEqual(@as(u32, 0), statuses[0].consecutive_failures);
    try testing.expect(statuses[0].last_failure_class == null);
}

test "renewal worker: a second successful rotation issues a distinct generation, and a restart recovers it with no CA contact" {
    const allocator = testing.allocator;
    var dirs = try TestDirs.init(allocator);
    defer dirs.deinit(allocator);
    const now: i64 = 1_700_000_000;

    var ca = acme.fake_ca.FakeCa.init(allocator);
    defer ca.deinit();
    ca.script.new_order.expires_override = "2099-01-01T00:00:00Z";
    var issuer = try acme.test_cert_builder.TestCa.init(allocator, now - 3600, now + 365 * 24 * 3600);
    defer issuer.deinit(allocator);
    ca.issued_chain_factory = .{ .ctx = &issuer, .makeFn = issueTestLeafForCsr };

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    var challenge_store = ChallengeStore.init(allocator);
    defer challenge_store.deinit();
    var published = PublishedHosts.init(allocator);
    defer published.deinit();
    const trust_anchors = try testTrustAnchors(allocator);
    defer trust_anchors.release();

    var worker = newTestWorker(allocator, &dirs, try acme.groups.parse("rotating.example.test"), &store, &challenge_store, &published, trust_anchors);

    const credentials = @import("tls_core").credentials;
    const selection = credentials.SelectionContext{
        .role = .server,
        .server_name = "rotating.example.test",
        .peer_signature_schemes = &.{0x0403},
        .negotiated_version = 0x0304,
        .cipher_suite = 0x1301,
        .application_protocol = null,
        .auth_policy = .{},
    };

    var scheduled = Scheduled{ .earliest_next = now };
    scheduled.due[0] = true;
    try attemptDueGroupsWithDialer(&worker, scheduled, ca.dialer());
    const generation_a = switch (try store.provider().selectCredential(&selection)) {
        .complete => |value| value,
        .pending => return error.TestUnexpectedPending,
    };
    const generation_a_leaf = try allocator.dupe(u8, generation_a.certificateChain().leaf().?);
    defer allocator.free(generation_a_leaf);
    generation_a.release();

    // A fresh leaf key per issuance (design §5.1 step 5) means a second
    // rotation against the same CA produces a distinct generation, not a
    // no-op republish of the first.
    try attemptDueGroupsWithDialer(&worker, scheduled, ca.dialer());
    const generation_b = switch (try store.provider().selectCredential(&selection)) {
        .complete => |value| value,
        .pending => return error.TestUnexpectedPending,
    };
    defer generation_b.release();
    try testing.expect(!std.mem.eql(u8, generation_a_leaf, generation_b.certificateChain().leaf().?));

    // Restart: a fresh store recovers generation B from disk alone, with no
    // CA contact at all (`recoverFromDisk` takes no dialer).
    var restarted_store = NativeCredentialStore.init(allocator);
    defer restarted_store.deinit();
    var restarted_published = PublishedHosts.init(allocator);
    defer restarted_published.deinit();
    const restart_result = try acme_activation.recoverFromDisk(allocator, "rotating.example.test", dirs.state_dir, "", "", &.{}, &restarted_store, &restarted_published, compat.unixTimestamp());
    try testing.expect(!restart_result.needs_issuance[0]);
    const recovered = switch (try restarted_store.provider().selectCredential(&selection)) {
        .complete => |value| value,
        .pending => return error.TestUnexpectedPending,
    };
    defer recovered.release();
    try testing.expect(std.mem.eql(u8, generation_b.certificateChain().leaf().?, recovered.certificateChain().leaf().?));
}

test "attemptDueGroupsWithDialer: a verification failure never persists or publishes, and durably records the failure" {
    const allocator = testing.allocator;
    var dirs = try TestDirs.init(allocator);
    defer dirs.deinit(allocator);
    const now: i64 = 1_700_000_000;

    var ca = acme.fake_ca.FakeCa.init(allocator);
    defer ca.deinit();
    // The fake CA's default scripted certificate is not a verifiable X.509
    // chain (exactly the untrusted-CA-response case §6.4 exists for); pin
    // the order's `expires` far in the future the same way other callers of
    // the real-clock default `orders.Options` do.
    ca.script.new_order.expires_override = "2099-01-01T00:00:00Z";

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    var challenge_store = ChallengeStore.init(allocator);
    defer challenge_store.deinit();
    var published = PublishedHosts.init(allocator);
    defer published.deinit();
    const trust_anchors = try testTrustAnchors(allocator);
    defer trust_anchors.release();

    var worker = newTestWorker(allocator, &dirs, try acme.groups.parse("bad-chain.example.test"), &store, &challenge_store, &published, trust_anchors);

    var scheduled = Scheduled{ .earliest_next = now };
    scheduled.due[0] = true;
    try attemptDueGroupsWithDialer(&worker, scheduled, ca.dialer());
    try testing.expect(!published.isPublished("bad-chain.example.test"));

    var id_buf: [acme.groups.group_id_len]u8 = undefined;
    const group_id = acme.groups.groupId(&id_buf, &.{"bad-chain.example.test"});
    var state = try acme.state.StateDir.open(dirs.state_dir);
    defer state.close();
    const loaded = try acme.activate.loadCommitted(allocator, &state, group_id, &.{"bad-chain.example.test"}, now);
    try testing.expect(loaded == null);

    var groups_dir = try state.openOrCreateSubdir(acme.activate.groups_dir_name);
    defer groups_dir.close();
    var group_dir = try groups_dir.openOrCreateSubdir(group_id);
    defer group_dir.close();
    const record = (try acme.renewal_state.load(allocator, &group_dir)).?;
    try testing.expectEqual(@as(u32, 1), record.failures);
    try testing.expect(record.last_failure_class != null);
}

test "renewal worker: a restart recovers the committed generation and preserves the failure floor, never retrying immediately" {
    const allocator = testing.allocator;
    var dirs = try TestDirs.init(allocator);
    defer dirs.deinit(allocator);
    const now: i64 = 1_700_000_000;

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    var challenge_store = ChallengeStore.init(allocator);
    defer challenge_store.deinit();
    var published = PublishedHosts.init(allocator);
    defer published.deinit();
    const trust_anchors = try testTrustAnchors(allocator);
    defer trust_anchors.release();

    // Simulate a crash right after a failed attempt: a durable failure
    // record exists, but (unlike the production flow) nothing published
    // this process run yet.
    {
        var state = try acme.state.StateDir.open(dirs.state_dir);
        defer state.close();
        var groups_dir = try state.openOrCreateSubdir(acme.activate.groups_dir_name);
        defer groups_dir.close();
        var id_buf: [acme.groups.group_id_len]u8 = undefined;
        const group_id = acme.groups.groupId(&id_buf, &.{"restart.example.test"});
        var group_dir = try groups_dir.openOrCreateSubdir(group_id);
        defer group_dir.close();
        try acme.renewal_state.save(allocator, &group_dir, .{ .last_attempt_at = now - 10, .failures = 1, .last_failure_class = .transport });
    }

    var worker = newTestWorker(allocator, &dirs, try acme.groups.parse("restart.example.test"), &store, &challenge_store, &published, trust_anchors);
    worker.unix_clock = .{ .ctx = @constCast(&now), .nowFn = struct {
        fn f(ctx: ?*anyopaque) i64 {
            const n: *const i64 = @ptrCast(@alignCast(ctx.?));
            return n.*;
        }
    }.f };

    const scheduled = try tick(&worker);
    // 10s since the last attempt is well inside the 5-minute floor: a fresh
    // process must not treat "no certificate" as license to retry
    // immediately, even though it has no in-memory memory of the failure.
    try testing.expect(!scheduled.due[0]);
    try testing.expectEqual(now - 10 + acme.renewal_policy.retry_floor_seconds, scheduled.earliest_next);
}

test "renewal worker: a corrupt retry record applies a conservative cooldown rather than retrying immediately" {
    const allocator = testing.allocator;
    var dirs = try TestDirs.init(allocator);
    defer dirs.deinit(allocator);
    const now: i64 = 1_700_000_000;

    {
        var state = try acme.state.StateDir.open(dirs.state_dir);
        defer state.close();
        var groups_dir = try state.openOrCreateSubdir(acme.activate.groups_dir_name);
        defer groups_dir.close();
        var id_buf: [acme.groups.group_id_len]u8 = undefined;
        const group_id = acme.groups.groupId(&id_buf, &.{"corrupt.example.test"});
        var group_dir = try groups_dir.openOrCreateSubdir(group_id);
        defer group_dir.close();
        try group_dir.writeFileAtomic(acme.renewal_state.file_name, "not json", 0o600);
    }

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    var challenge_store = ChallengeStore.init(allocator);
    defer challenge_store.deinit();
    var published = PublishedHosts.init(allocator);
    defer published.deinit();
    const trust_anchors = try testTrustAnchors(allocator);
    defer trust_anchors.release();

    var worker = newTestWorker(allocator, &dirs, try acme.groups.parse("corrupt.example.test"), &store, &challenge_store, &published, trust_anchors);
    var clock = now;
    worker.unix_clock = .{ .ctx = &clock, .nowFn = struct {
        fn f(ctx: ?*anyopaque) i64 {
            const n: *const i64 = @ptrCast(@alignCast(ctx.?));
            return n.*;
        }
    }.f };

    const scheduled = try tick(&worker);
    try testing.expect(!scheduled.due[0]);
    try testing.expectEqual(now + acme.renewal_policy.retry_floor_seconds, scheduled.earliest_next);

    // Re-reading the still-corrupt file partway through the floor must not
    // push the deadline out any further: without a stable first-corruption
    // anchor, this would resynthesize `last_attempt_at` as the new `clock`,
    // perpetually postponing the deadline by another full floor on every
    // pass instead of counting down to one fixed point.
    clock = now + acme.renewal_policy.retry_floor_seconds - 1;
    const still_not_due = try tick(&worker);
    try testing.expect(!still_not_due.due[0]);
    try testing.expectEqual(now + acme.renewal_policy.retry_floor_seconds, still_not_due.earliest_next);

    // Once the anchor's own floor has actually elapsed, the still-corrupt
    // file must become due -- the cooldown is bounded, not permanent.
    clock = now + acme.renewal_policy.retry_floor_seconds + 1;
    const now_due = try tick(&worker);
    try testing.expect(now_due.due[0]);
}

test "Worker.start/stopAndJoin: shutdown cancellation returns promptly instead of blocking for a full wake interval" {
    const allocator = testing.allocator;
    var dirs = try TestDirs.init(allocator);
    defer dirs.deinit(allocator);
    const now: i64 = 1_700_000_000;

    // A certificate far outside its renewal window: the worker's only task
    // is to sleep, which is exactly the state cancellation must interrupt.
    const hostnames = [_][]const u8{"sleeping.example.test"};
    var leaf = try acme.test_cert_builder.selfSignedLeaf(allocator, &hostnames, now - 3600, now + 90 * acme.renewal_policy.seconds_per_day);
    defer allocator.free(leaf.pem);
    defer leaf.key.deinit();
    {
        var state = try acme.state.StateDir.open(dirs.state_dir);
        defer state.close();
        var id_buf: [acme.groups.group_id_len]u8 = undefined;
        const group_id = acme.groups.groupId(&id_buf, &hostnames);
        _ = try acme.activate.verifyAndPersist(allocator, &state, group_id, &leaf.key, leaf.pem, .{ .hostnames = &hostnames, .now = now });
    }

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    var challenge_store = ChallengeStore.init(allocator);
    defer challenge_store.deinit();
    var published = PublishedHosts.init(allocator);
    defer published.deinit();
    const trust_anchors = try testTrustAnchors(allocator);
    defer trust_anchors.release();

    var worker = newTestWorker(allocator, &dirs, try acme.groups.parse("sleeping.example.test"), &store, &challenge_store, &published, trust_anchors);
    worker.unix_clock = .{ .ctx = @constCast(&now), .nowFn = struct {
        fn f(ctx: ?*anyopaque) i64 {
            const n: *const i64 = @ptrCast(@alignCast(ctx.?));
            return n.*;
        }
    }.f };

    try worker.start();
    const start_ns = compat.monotonicNanoTimestamp();
    worker.stopAndJoin();
    const elapsed_ms = @divTrunc(compat.monotonicNanoTimestamp() - start_ns, std.time.ns_per_ms);
    try testing.expect(elapsed_ms < 5_000);
}

test "Worker.snapshotStatus never exposes more than the bounded, secret-free status shape" {
    // Compile-time structural check (design §9.4): a hostname, CA URL, key,
    // token or nonce field would be a type error here, not a runtime leak
    // caught by a string search.
    const info = @typeInfo(GroupStatus).@"struct";
    try testing.expectEqual(@as(usize, 5), info.fields.len);
}

const PublishFailureCtx = struct {
    calls: u32 = 0,
    default_cert_path: []const u8,
    default_key_path: []const u8,
    sni_certs: []const SniCertSpec,
};

fn failOnceThenPrepare(ctx_opt: ?*anyopaque, _: std.mem.Allocator, store: *NativeCredentialStore, bundles: []const ManagedBundleSpec) anyerror!NativeCredentialStore.PreparedReload {
    const ctx: *PublishFailureCtx = @ptrCast(@alignCast(ctx_opt.?));
    ctx.calls += 1;
    if (ctx.calls == 1) return error.InjectedPublishFailure;
    return store.prepareReloadFromBundles(ctx.default_cert_path, ctx.default_key_path, ctx.sni_certs, bundles);
}

test "attemptDueGroupsWithDialer: a failed publish after a successful issuance retries without reissuing (pending_publish)" {
    const allocator = testing.allocator;
    var dirs = try TestDirs.init(allocator);
    defer dirs.deinit(allocator);
    const now: i64 = 1_700_000_000;

    var ca = acme.fake_ca.FakeCa.init(allocator);
    defer ca.deinit();
    ca.script.new_order.expires_override = "2099-01-01T00:00:00Z";
    var issuer = try acme.test_cert_builder.TestCa.init(allocator, now - 3600, now + 365 * 24 * 3600);
    defer issuer.deinit(allocator);
    ca.issued_chain_factory = .{ .ctx = &issuer, .makeFn = issueTestLeafForCsr };

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    var challenge_store = ChallengeStore.init(allocator);
    defer challenge_store.deinit();
    var published = PublishedHosts.init(allocator);
    defer published.deinit();
    const trust_anchors = try testTrustAnchors(allocator);
    defer trust_anchors.release();

    const hostnames = [_][]const u8{"publish-retry.example.test"};
    var worker = newTestWorker(allocator, &dirs, try acme.groups.parse("publish-retry.example.test"), &store, &challenge_store, &published, trust_anchors);
    var pub_ctx = PublishFailureCtx{ .default_cert_path = "", .default_key_path = "", .sni_certs = &.{} };
    worker.prepare_current_credentials = failOnceThenPrepare;
    worker.credential_config_ctx = &pub_ctx;

    var scheduled = Scheduled{ .earliest_next = now };
    scheduled.due[0] = true;
    try testing.expectError(error.InjectedPublishFailure, attemptDueGroupsWithDialer(&worker, scheduled, ca.dialer()));
    try testing.expect(worker.pending_publish);
    try testing.expect(!published.isPublished("publish-retry.example.test"));

    // The issued generation is already safely persisted on disk even though
    // publication failed -- a crash here must never force a reissue.
    {
        var state = try acme.state.StateDir.open(dirs.state_dir);
        defer state.close();
        var id_buf: [acme.groups.group_id_len]u8 = undefined;
        const group_id = acme.groups.groupId(&id_buf, &hostnames);
        // `issueTestLeafForCsr` anchors the issued leaf's own validity window
        // to the real wall clock (not this test's symbolic `now`), matching
        // every other CA-issuing test in this file; verify against it too.
        var loaded = (try acme.activate.loadCommitted(allocator, &state, group_id, &hostnames, compat.unixTimestamp())).?;
        loaded.deinit(allocator);
    }

    // `tick` sees a far-future due time from the committed generation's own
    // validity regardless -- it is `pending_publish`, not per-group `due`,
    // that must drive the retry (design: the publish rebuild spans every
    // group, not just the one that happened to issue).
    const after_failure = try tick(&worker);
    try testing.expect(!after_failure.due[0]);

    // The durable success record must *not* exist yet: publication has not
    // actually landed, so writing `failures=0` now would tell both
    // `tick`'s own next-attempt decision and operator-facing metrics that
    // this renewal is already healthy while the live TLS provider may
    // still be serving a stale or absent credential. `activation_pending`
    // is how that in-between state is surfaced instead.
    {
        var id_buf: [acme.groups.group_id_len]u8 = undefined;
        const group_id = acme.groups.groupId(&id_buf, &hostnames);
        var state = try acme.state.StateDir.open(dirs.state_dir);
        defer state.close();
        var groups_dir = try state.openOrCreateSubdir(acme.activate.groups_dir_name);
        defer groups_dir.close();
        var group_dir = try groups_dir.openOrCreateSubdir(group_id);
        defer group_dir.close();
        try testing.expect((try acme.renewal_state.load(allocator, &group_dir)) == null);
    }
    var statuses_pending: [1]GroupStatus = undefined;
    worker.snapshotStatus(&statuses_pending);
    try testing.expect(statuses_pending[0].activation_pending);

    // A pass with nothing newly due must still retry the pending publish
    // without any further CA contact: `after_failure.due` is all-false, so
    // `attemptDueGroupsWithDialer` never opens a session at all here.
    try attemptDueGroupsWithDialer(&worker, after_failure, ca.dialer());
    try testing.expect(!worker.pending_publish);
    try testing.expect(published.isPublished("publish-retry.example.test"));
    try testing.expectEqual(@as(u32, 2), pub_ctx.calls);

    // Now that activation actually landed, the durable success record is
    // written for the first time and the pending status clears.
    {
        var id_buf: [acme.groups.group_id_len]u8 = undefined;
        const group_id = acme.groups.groupId(&id_buf, &hostnames);
        var state = try acme.state.StateDir.open(dirs.state_dir);
        defer state.close();
        var groups_dir = try state.openOrCreateSubdir(acme.activate.groups_dir_name);
        defer groups_dir.close();
        var group_dir = try groups_dir.openOrCreateSubdir(group_id);
        defer group_dir.close();
        const record = (try acme.renewal_state.load(allocator, &group_dir)).?;
        try testing.expectEqual(@as(u32, 0), record.failures);
    }
    // `tick`'s own `setStatus` call is what refreshes the snapshot; nothing
    // else does.
    _ = try tick(&worker);
    var statuses_resolved: [1]GroupStatus = undefined;
    worker.snapshotStatus(&statuses_resolved);
    try testing.expect(!statuses_resolved[0].activation_pending);
}

test "runLoop: a transient state-directory lock collision retries instead of permanently stopping the worker" {
    const allocator = testing.allocator;
    var dirs = try TestDirs.init(allocator);
    defer dirs.deinit(allocator);
    const now: i64 = 1_700_000_000;

    // A certificate far outside its renewal window: once the lock clears,
    // the worker's only task is to confirm nothing is due and go back to
    // sleep -- this isolates the test to the scheduling/lock level, with no
    // CA contact involved.
    const hostnames = [_][]const u8{"lock-collision.example.test"};
    var leaf = try acme.test_cert_builder.selfSignedLeaf(allocator, &hostnames, now - 3600, now + 90 * acme.renewal_policy.seconds_per_day);
    defer allocator.free(leaf.pem);
    defer leaf.key.deinit();
    {
        var state = try acme.state.StateDir.open(dirs.state_dir);
        defer state.close();
        var id_buf: [acme.groups.group_id_len]u8 = undefined;
        const group_id = acme.groups.groupId(&id_buf, &hostnames);
        _ = try acme.activate.verifyAndPersist(allocator, &state, group_id, &leaf.key, leaf.pem, .{ .hostnames = &hostnames, .now = now });
    }

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    var challenge_store = ChallengeStore.init(allocator);
    defer challenge_store.deinit();
    var published = PublishedHosts.init(allocator);
    defer published.deinit();
    const trust_anchors = try testTrustAnchors(allocator);
    defer trust_anchors.release();

    var worker = newTestWorker(allocator, &dirs, try acme.groups.parse("lock-collision.example.test"), &store, &challenge_store, &published, trust_anchors);
    worker.lock_retry_wait_seconds = 0;
    worker.unix_clock = .{ .ctx = @constCast(&now), .nowFn = struct {
        fn f(ctx: ?*anyopaque) i64 {
            const n: *const i64 = @ptrCast(@alignCast(ctx.?));
            return n.*;
        }
    }.f };

    var stopped = std.atomic.Value(bool).init(false);
    const Runner = struct {
        fn run(w: *Worker, s: *std.atomic.Value(bool)) void {
            runLoop(w) catch {
                s.store(true, .release);
            };
        }
    };

    // Hold the advisory lock for a short-lived legitimate collision (a
    // concurrent SIGHUP reload, another in-flight durable-state
    // transition) before the worker ever gets a chance to open it.
    var blocker = try acme.state.StateDir.open(dirs.state_dir);

    const thread = try std.Thread.spawn(.{}, Runner.run, .{ &worker, &stopped });
    compat.sleepNs(100 * std.time.ns_per_ms);
    // The old bug (an unqualified `try tick(worker)`) would have exited
    // `runLoop` on the very first colliding pass; `runThread` would then
    // have logged "stopped for the process lifetime" and the thread body
    // would already have returned.
    try testing.expect(!stopped.load(.acquire));

    blocker.close();
    compat.sleepNs(100 * std.time.ns_per_ms);
    try testing.expect(!stopped.load(.acquire));

    worker.cancel.store(true, .release);
    thread.join();
    // A clean cancellation exit, never the error path.
    try testing.expect(!stopped.load(.acquire));
}

test "tick: a hard unsafe-state error from loadCommitted is never scheduled for automatic reissuance" {
    const allocator = testing.allocator;
    var dirs = try TestDirs.init(allocator);
    defer dirs.deinit(allocator);
    const now: i64 = 1_700_000_000;

    const hostnames = [_][]const u8{"degraded.example.test"};
    var id_buf: [acme.groups.group_id_len]u8 = undefined;
    const group_id = acme.groups.groupId(&id_buf, &hostnames);
    var leaf = try acme.test_cert_builder.selfSignedLeaf(allocator, &hostnames, now - 3600, now + 90 * acme.renewal_policy.seconds_per_day);
    defer allocator.free(leaf.pem);
    defer leaf.key.deinit();
    {
        var state = try acme.state.StateDir.open(dirs.state_dir);
        defer state.close();
        _ = try acme.activate.verifyAndPersist(allocator, &state, group_id, &leaf.key, leaf.pem, .{ .hostnames = &hostnames, .now = now });
    }

    // Loosen the committed pointer's permissions directly on disk: the next
    // `loadCommitted` must see this as an unsafe-state error (`current`
    // requires an exact `0600`), not as "no certificate".
    const current_path = try std.fmt.allocPrint(allocator, "{s}/groups/{s}/current", .{ dirs.state_dir, group_id });
    defer allocator.free(current_path);
    try compat.chmodPath(current_path, 0o640);

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    var challenge_store = ChallengeStore.init(allocator);
    defer challenge_store.deinit();
    var published = PublishedHosts.init(allocator);
    defer published.deinit();
    const trust_anchors = try testTrustAnchors(allocator);
    defer trust_anchors.release();

    var worker = newTestWorker(allocator, &dirs, try acme.groups.parse("degraded.example.test"), &store, &challenge_store, &published, trust_anchors);
    worker.unix_clock = .{ .ctx = @constCast(&now), .nowFn = struct {
        fn f(ctx: ?*anyopaque) i64 {
            const n: *const i64 = @ptrCast(@alignCast(ctx.?));
            return n.*;
        }
    }.f };

    const scheduled = try tick(&worker);
    // Never scheduled for a fresh CA issuance in the face of a
    // security-relevant state problem an operator needs to fix.
    try testing.expect(!scheduled.due[0]);

    var statuses: [1]GroupStatus = undefined;
    worker.snapshotStatus(&statuses);
    // Still given a stable status and next-check time, rather than
    // silently disappearing from scheduling for the rest of the process
    // lifetime.
    try testing.expectEqual(now + acme.renewal_policy.retry_floor_seconds, statuses[0].next_attempt_at);
    try testing.expectEqual(acme.client.FailureClass.persistence, statuses[0].last_failure_class.?);
}

test "attemptDueGroupsWithDialer: a CA/account setup failure persists a durable retry floor for every due group" {
    const allocator = testing.allocator;
    var dirs = try TestDirs.init(allocator);
    defer dirs.deinit(allocator);
    const now: i64 = 1_700_000_000;

    var ca = acme.fake_ca.FakeCa.init(allocator);
    defer ca.deinit();
    ca.script.refuse_dial = true;

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    var challenge_store = ChallengeStore.init(allocator);
    defer challenge_store.deinit();
    var published = PublishedHosts.init(allocator);
    defer published.deinit();
    const trust_anchors = try testTrustAnchors(allocator);
    defer trust_anchors.release();

    var worker = newTestWorker(allocator, &dirs, try acme.groups.parse("setup-failure.example.test"), &store, &challenge_store, &published, trust_anchors);
    var clock = now;
    worker.unix_clock = .{ .ctx = &clock, .nowFn = struct {
        fn f(ctx: ?*anyopaque) i64 {
            const n: *const i64 = @ptrCast(@alignCast(ctx.?));
            return n.*;
        }
    }.f };

    var scheduled = Scheduled{ .earliest_next = now };
    scheduled.due[0] = true;
    try testing.expectError(error.DialFailed, attemptDueGroupsWithDialer(&worker, scheduled, ca.dialer()));

    // A durable failure record exists for the due group even though the
    // failure happened before any group-specific attempt -- a crash/restart
    // right here must not forget it and immediately hammer the CA again.
    var id_buf: [acme.groups.group_id_len]u8 = undefined;
    const group_id = acme.groups.groupId(&id_buf, &.{"setup-failure.example.test"});
    {
        var state = try acme.state.StateDir.open(dirs.state_dir);
        defer state.close();
        var groups_dir = try state.openOrCreateSubdir(acme.activate.groups_dir_name);
        defer groups_dir.close();
        var group_dir = try groups_dir.openOrCreateSubdir(group_id);
        defer group_dir.close();
        const record = (try acme.renewal_state.load(allocator, &group_dir)).?;
        try testing.expectEqual(@as(u32, 1), record.failures);
        try testing.expectEqual(now, record.last_attempt_at);
    }

    // Simulating a restart: a fresh `tick` well inside the floor must not
    // treat the group as due again.
    clock = now + 10;
    const scheduled_after = try tick(&worker);
    try testing.expect(!scheduled_after.due[0]);
    try testing.expectEqual(now + acme.renewal_policy.retry_floor_seconds, scheduled_after.earliest_next);
}

test "attemptDueGroupsWithDialer: a failed attempt whose own retry record cannot be written surfaces RetryStateNotPersisted" {
    const allocator = testing.allocator;
    var dirs = try TestDirs.init(allocator);
    defer dirs.deinit(allocator);
    const now: i64 = 1_700_000_000;

    var ca = acme.fake_ca.FakeCa.init(allocator);
    defer ca.deinit();
    // The fake CA's default scripted certificate is not a verifiable X.509
    // chain (the same untrusted-CA-response case the "verification
    // failure" test above exercises), so every attempt reaches
    // `attemptAndRecord`'s failure branch.
    ca.script.new_order.expires_override = "2099-01-01T00:00:00Z";

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    var challenge_store = ChallengeStore.init(allocator);
    defer challenge_store.deinit();
    var published = PublishedHosts.init(allocator);
    defer published.deinit();
    const trust_anchors = try testTrustAnchors(allocator);
    defer trust_anchors.release();

    const hostnames = [_][]const u8{"record-write-fails.example.test"};
    var worker = newTestWorker(allocator, &dirs, try acme.groups.parse(hostnames[0]), &store, &challenge_store, &published, trust_anchors);

    // Running as root bypasses the directory-permission enforcement this
    // test relies on (`StateDir.open`'s own "ACME state: refuses ...
    // group-writable directories" test skips the analogous owner check for
    // the same reason).
    if (compat.effectiveUid() == 0) return error.SkipZigTest;

    var id_buf: [acme.groups.group_id_len]u8 = undefined;
    const group_id = acme.groups.groupId(&id_buf, &hostnames);
    const group_dir_path = try std.fmt.allocPrint(allocator, "{s}/groups/{s}", .{ dirs.state_dir, group_id });
    defer allocator.free(group_dir_path);
    {
        var state = try acme.state.StateDir.open(dirs.state_dir);
        defer state.close();
        var groups_dir = try state.openOrCreateSubdir(acme.activate.groups_dir_name);
        defer groups_dir.close();
        var group_dir = try groups_dir.openOrCreateSubdir(group_id);
        defer group_dir.close();
    }
    // Read+execute only: `recordFailure`'s atomic write inside this
    // directory must now fail exactly like a disk-full or
    // permissions-changed state volume would.
    try compat.chmodPath(group_dir_path, 0o500);
    defer compat.chmodPath(group_dir_path, 0o700) catch {};

    var scheduled = Scheduled{ .earliest_next = now };
    scheduled.due[0] = true;
    // Before the fix, this call would swallow the record-write failure and
    // return successfully, leaving the caller (`runLoop`) with no signal
    // that the usual durable backoff never actually landed.
    try testing.expectError(error.RetryStateNotPersisted, attemptDueGroupsWithDialer(&worker, scheduled, ca.dialer()));
    try testing.expect(!published.isPublished(hostnames[0]));
}

test "runLoop: a per-group retry-record write failure applies a bounded floor instead of hammering the CA" {
    const allocator = testing.allocator;
    var dirs = try TestDirs.init(allocator);
    defer dirs.deinit(allocator);
    const now: i64 = 1_700_000_000;

    var ca = acme.fake_ca.FakeCa.init(allocator);
    defer ca.deinit();
    ca.script.new_order.expires_override = "2099-01-01T00:00:00Z";

    var store = NativeCredentialStore.init(allocator);
    defer store.deinit();
    var challenge_store = ChallengeStore.init(allocator);
    defer challenge_store.deinit();
    var published = PublishedHosts.init(allocator);
    defer published.deinit();
    const trust_anchors = try testTrustAnchors(allocator);
    defer trust_anchors.release();

    if (compat.effectiveUid() == 0) return error.SkipZigTest;

    const hostnames = [_][]const u8{"record-write-fails-loop.example.test"};
    var worker = newTestWorker(allocator, &dirs, try acme.groups.parse(hostnames[0]), &store, &challenge_store, &published, trust_anchors);
    worker.dialer_override = ca.dialer();
    worker.unix_clock = .{ .ctx = @constCast(&now), .nowFn = struct {
        fn f(ctx: ?*anyopaque) i64 {
            const n: *const i64 = @ptrCast(@alignCast(ctx.?));
            return n.*;
        }
    }.f };

    var id_buf: [acme.groups.group_id_len]u8 = undefined;
    const group_id = acme.groups.groupId(&id_buf, &hostnames);
    const group_dir_path = try std.fmt.allocPrint(allocator, "{s}/groups/{s}", .{ dirs.state_dir, group_id });
    defer allocator.free(group_dir_path);
    {
        var state = try acme.state.StateDir.open(dirs.state_dir);
        defer state.close();
        var groups_dir = try state.openOrCreateSubdir(acme.activate.groups_dir_name);
        defer groups_dir.close();
        var group_dir = try groups_dir.openOrCreateSubdir(group_id);
        defer group_dir.close();
    }
    try compat.chmodPath(group_dir_path, 0o500);
    defer compat.chmodPath(group_dir_path, 0o700) catch {};

    var stopped = std.atomic.Value(bool).init(false);
    const Runner = struct {
        fn run(w: *Worker, s: *std.atomic.Value(bool)) void {
            runLoop(w) catch {
                s.store(true, .release);
            };
        }
    };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{ &worker, &stopped });
    compat.sleepNs(300 * std.time.ns_per_ms);

    // Not a fatal persistence stop for the *process* (a failed state write
    // may well be writable again on the next pass; serving continues on
    // whatever was last published either way) -- just a conservative floor
    // on the CA contact rate.
    try testing.expect(!stopped.load(.acquire));
    const posts_after_first_window = ca.countPosts();
    try testing.expect(posts_after_first_window > 0);

    // The old bug (silently swallowing the record-write failure) would have
    // let every subsequent pass recompute the identical unmodified due
    // record and re-contact the CA again immediately, forever; this window
    // must see no further CA traffic at all.
    compat.sleepNs(300 * std.time.ns_per_ms);
    try testing.expectEqual(posts_after_first_window, ca.countPosts());

    worker.cancel.store(true, .release);
    thread.join();
    try testing.expect(!stopped.load(.acquire));
}

test {
    std.testing.refAllDecls(@This());
}
