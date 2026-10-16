//! Durable, permission-checked ACME state directory (#832, design §4.4/§9.2).
//!
//! One process owns a state directory at a time (advisory `flock` on `.lock`).
//! Every file is replaced with the same procedure — exclusive-create a `0600`
//! temp file in the *same* directory, write, `fsync`, `rename` over the
//! target, `fsync` the directory — so a crash or injected failure at any step
//! leaves either the previous complete file or the new complete file, never a
//! mixture and never a destroyed original. Readers never follow symlinks and
//! refuse key files with group/other permission bits.
//!
//! Not logged anywhere in this file: key material, file contents or CA URLs.

const std = @import("std");
const builtin = @import("builtin");
const crypto = @import("crypto");
const zig_compat = @import("zig_compat");
const account_mod = @import("account.zig");
const json_limits = @import("json_limits.zig");

const secrets = crypto.secrets;

pub const Error = error{
    OutOfMemory,
    /// State path is empty, too long, contains a NUL, or a name is unsafe.
    InvalidPath,
    /// The state path or a file in it is a symlink or not the expected kind.
    UnsafeFileType,
    /// The directory is group/other-writable, or a secret file has any
    /// group/other permission bit.
    InsecurePermissions,
    /// The state directory or a private file is not owned by the effective uid.
    WrongOwner,
    /// Another process (or another `StateDir` in this process) holds the lock.
    Locked,
    NotFound,
    TooLarge,
    /// Stored data failed strict validation. Nothing is repaired or deleted.
    CorruptState,
    /// `account.json` exists without `account.key` (or the reverse
    /// is unusable): a new key is never minted over an existing account.
    InconsistentState,
    /// The persisted account belongs to a different directory URL.
    DirectoryMismatch,
    IoFailure,
    /// Deterministic fault injected by tests; unreachable in production builds.
    InjectedFault,
};

pub const account_key_name = "account.key";
pub const account_record_name = "account.json";
pub const lock_name = ".lock";
pub const max_state_file_len = 16 * 1024;
/// Version 2 binds the record to the account key (`key_thumbprint`).
pub const state_version = 2;

/// Steps of the atomic write procedure at which tests inject a failure.
pub const Fault = enum {
    none,
    create_temp,
    write,
    short_write,
    fsync_file,
    close_file,
    rename,
    fsync_dir,
};

pub const StateDir = struct {
    dir_fd: zig_compat.Fd,
    lock_fd: zig_compat.Fd,
    /// Test-only one-shot fault; ignored (and compiled out) outside tests.
    fault: Fault = .none,

    /// Open (creating with `0700` when absent) and lock `path`. The path's
    /// final component must be a real directory, not a symlink; its parent
    /// must already exist.
    pub fn open(path: []const u8) Error!StateDir {
        if (path.len == 0 or path.len > std.fs.max_path_bytes - 1 or std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidPath;
        const io = zig_compat.io();
        const cwd = std.Io.Dir.cwd();
        if (cwd.statFile(io, path, .{ .follow_symlinks = false })) |_| {} else |err| switch (err) {
            error.FileNotFound => zig_compat.mkdirPath(path, 0o700) catch |mk| switch (mk) {
                error.Exists => {}, // lost a creation race; validated below
                else => return error.IoFailure,
            },
            else => return error.IoFailure,
        }

        // Open without following a final symlink, then validate the *descriptor*
        // (type, owner, mode) so the checks cannot race a swap of the path.
        const dir_fd = zig_compat.openDirNoFollow(path) catch {
            // Say why when we can: a symlink or file is a different problem
            // from an I/O failure.
            if (cwd.statFile(io, path, .{ .follow_symlinks = false })) |st| {
                if (st.kind != .directory) return error.UnsafeFileType;
            } else |_| {}
            return error.IoFailure;
        };
        errdefer zig_compat.closeFd(dir_fd);
        const identity = zig_compat.statFdIdentity(dir_fd) catch return error.IoFailure;
        if (!identity.is_directory) return error.UnsafeFileType;
        if (identity.uid != zig_compat.effectiveUid()) return error.WrongOwner;
        if (identity.mode & 0o022 != 0) return error.InsecurePermissions;

        const lock_fd = zig_compat.openAtNoFollow(dir_fd, lock_name, .{ .write = true, .create = true }, 0o600) catch return error.IoFailure;
        errdefer zig_compat.closeFd(lock_fd);
        zig_compat.lockExclusiveNonBlocking(lock_fd) catch |err| return if (err == error.WouldBlock) error.Locked else error.IoFailure;

        var self = StateDir{ .dir_fd = dir_fd, .lock_fd = lock_fd };
        self.removeStaleTemps();
        return self;
    }

    /// Releases the lock and the directory handle.
    pub fn close(self: *StateDir) void {
        zig_compat.closeFd(self.lock_fd);
        zig_compat.closeFd(self.dir_fd);
        self.* = undefined;
    }

    fn dir(self: *const StateDir) std.Io.Dir {
        return .{ .handle = self.dir_fd };
    }

    /// Replace `name` atomically with `data` at `mode`. On any failure the
    /// previous `name` is untouched and the temp file is removed.
    pub fn writeFileAtomic(self: *StateDir, name: []const u8, data: []const u8, mode: u32) Error!void {
        return writeFileAtomicRaw(self.dir_fd, &self.fault, name, data, mode);
    }

    /// Read `name` (bounded). With `private`, any group/other permission bit
    /// is `InsecurePermissions`. Never follows symlinks. When `private`, the
    /// caller owns key material and must free with `secrets.secureZeroAndFree`.
    pub fn readFileAlloc(self: *const StateDir, allocator: std.mem.Allocator, name: []const u8, max_len: usize, private: bool) Error![]u8 {
        return readFileAllocRaw(self.dir_fd, allocator, name, max_len, private);
    }

    /// Open (creating as `0700` if absent) a single-component subdirectory
    /// of this state directory with the same symlink/ownership/permission
    /// invariants as `open`, and remove any crashed writer's temp leftovers
    /// inside it. Used to build the nested `groups/<id>/generations/<gen>/`
    /// layout (#879, design §9.2) one validated level at a time.
    pub fn openOrCreateSubdir(self: *StateDir, name: []const u8) Error!SubDir {
        return openSubdirRaw(self.dir_fd, &self.fault, name, true);
    }

    /// Open an existing subdirectory with the same invariants as
    /// `openOrCreateSubdir`, without creating it. `error.NotFound` if absent.
    pub fn openSubdirStrict(self: *StateDir, name: []const u8) Error!SubDir {
        return openSubdirRaw(self.dir_fd, &self.fault, name, false);
    }

    /// Remove `.<name>.tmp-*` leftovers from a crashed writer. We hold the
    /// lock, so no live writer owns them. Best effort: failure to clean up
    /// must not block startup, and a leftover is mode `0600` anyway.
    fn removeStaleTemps(self: *StateDir) void {
        removeStaleTempsRaw(self.dir_fd);
    }
};

/// A validated, single-component subdirectory opened relative to a parent
/// directory descriptor (`StateDir.dir_fd` or another `SubDir`). Shares the
/// parent `StateDir`'s one-shot fault cell so tests can inject a failure at
/// any step of a nested write, and the same atomic-write/strict-read
/// procedure as the top-level directory (#879).
pub const SubDir = struct {
    fd: zig_compat.Fd,
    fault: *Fault,

    pub fn close(self: *SubDir) void {
        zig_compat.closeFd(self.fd);
        self.* = undefined;
    }

    fn dir(self: *const SubDir) std.Io.Dir {
        return .{ .handle = self.fd };
    }

    pub fn writeFileAtomic(self: *SubDir, name: []const u8, data: []const u8, mode: u32) Error!void {
        return writeFileAtomicRaw(self.fd, self.fault, name, data, mode);
    }

    pub fn readFileAlloc(self: *const SubDir, allocator: std.mem.Allocator, name: []const u8, max_len: usize, private: bool) Error![]u8 {
        return readFileAllocRaw(self.fd, allocator, name, max_len, private);
    }

    pub fn openOrCreateSubdir(self: *SubDir, name: []const u8) Error!SubDir {
        return openSubdirRaw(self.fd, self.fault, name, true);
    }

    pub fn openSubdirStrict(self: *SubDir, name: []const u8) Error!SubDir {
        return openSubdirRaw(self.fd, self.fault, name, false);
    }

    /// Rename `old` to `new` within this directory (the generation-commit
    /// step: `current.tmp` -> `current`).
    pub fn renameWithin(self: *SubDir, old: []const u8, new: []const u8) Error!void {
        if (!validName(old) or !validName(new)) return error.InvalidPath;
        zig_compat.renameAt(self.fd, old, new) catch return error.IoFailure;
    }

    /// Best-effort unlink; a missing file is not an error.
    pub fn removeFile(self: *SubDir, name: []const u8) void {
        if (!validName(name)) return;
        zig_compat.unlinkAt(self.fd, name);
    }

    /// Remove the now-empty-of-live-files subdirectory `name`. The caller
    /// must have already removed every entry it wrote inside it.
    pub fn removeEmpty(self: *SubDir, name: []const u8) Error!void {
        if (!validName(name)) return error.InvalidPath;
        zig_compat.rmdirAt(self.fd, name) catch return error.IoFailure;
    }

    pub fn fsync(self: *const SubDir) Error!void {
        zig_compat.fsyncFd(self.fd) catch return error.IoFailure;
    }

    /// Bounded iteration for generation discovery and orphan sweeps. Returns
    /// a fixed-capacity snapshot (never partial-reads a live mutation: the
    /// caller holds the top-level lock for the whole operation).
    pub fn listNames(self: *const SubDir, out: *[64][64]u8, out_len: *[64]usize) usize {
        var it = self.dir().iterate();
        var count: usize = 0;
        while (it.next(zig_compat.io()) catch return count) |entry| {
            if (entry.name.len == 0 or entry.name.len >= 64) continue;
            if (count == out.len) break;
            @memcpy(out[count][0..entry.name.len], entry.name);
            out_len[count] = entry.name.len;
            count += 1;
        }
        return count;
    }
};

fn hitFault(fault: *Fault, point: Fault) Error!void {
    if (!builtin.is_test) return;
    if (fault.* == point) {
        fault.* = .none;
        return error.InjectedFault;
    }
}

fn writeFileAtomicRaw(dir_fd: zig_compat.Fd, fault: *Fault, name: []const u8, data: []const u8, mode: u32) Error!void {
    if (!validName(name)) return error.InvalidPath;
    if (data.len > max_state_file_len) return error.TooLarge;

    var random: [8]u8 = undefined;
    zig_compat.randomBytes(&random);
    var temp_buf: [128]u8 = undefined;
    const temp_name = std.fmt.bufPrint(&temp_buf, ".{s}.tmp-{x}", .{ name, random }) catch return error.InvalidPath;

    try hitFault(fault, .create_temp);
    const fd = zig_compat.openAtNoFollow(dir_fd, temp_name, .{ .write = true, .create = true, .exclusive = true }, mode) catch return error.IoFailure;
    var fd_open = true;
    var renamed = false;
    defer {
        if (fd_open) zig_compat.closeFd(fd);
        if (!renamed) zig_compat.unlinkAt(dir_fd, temp_name);
    }
    // umask may have narrowed the mode, never widened it; make it exact.
    zig_compat.fchmodFd(fd, mode) catch return error.IoFailure;

    try hitFault(fault, .write);
    const limit = if (fault.* == .short_write) data.len / 2 else data.len;
    zig_compat.writeAllFd(fd, data[0..limit]) catch return error.IoFailure;
    try hitFault(fault, .short_write);

    try hitFault(fault, .fsync_file);
    zig_compat.fsyncFd(fd) catch return error.IoFailure;
    // close() can report deferred write errors; a reported failure must
    // not be committed. The descriptor is consumed either way.
    const close_result = zig_compat.closeFdChecked(fd);
    fd_open = false;
    try hitFault(fault, .close_file);
    close_result catch return error.IoFailure;

    try hitFault(fault, .rename);
    zig_compat.renameAt(dir_fd, temp_name, name) catch return error.IoFailure;
    renamed = true;

    // The rename is already visible; a failed directory fsync means we
    // cannot promise it survives a crash, which the caller must know.
    try hitFault(fault, .fsync_dir);
    zig_compat.fsyncFd(dir_fd) catch return error.IoFailure;
}

fn readFileAllocRaw(dir_fd: zig_compat.Fd, allocator: std.mem.Allocator, name: []const u8, max_len: usize, private: bool) Error![]u8 {
    if (!validName(name)) return error.InvalidPath;
    const parent: std.Io.Dir = .{ .handle = dir_fd };
    const st = parent.statFile(zig_compat.io(), name, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return error.NotFound,
        else => return error.IoFailure,
    };
    if (st.kind != .file) return error.UnsafeFileType;
    if (private and modeBits(st) & 0o077 != 0) return error.InsecurePermissions;
    if (st.size > max_len) return error.TooLarge;

    const fd = zig_compat.openAtNoFollow(dir_fd, name, .{}, 0) catch |err| switch (err) {
        error.NotFound => return error.NotFound,
        else => return error.IoFailure,
    };
    defer zig_compat.closeFd(fd);
    // Re-check on the descriptor we will actually read.
    const identity = zig_compat.statFdIdentity(fd) catch return error.IoFailure;
    if (!identity.is_regular) return error.UnsafeFileType;
    if (private) {
        if (identity.uid != zig_compat.effectiveUid()) return error.WrongOwner;
        if (identity.mode & 0o077 != 0) return error.InsecurePermissions;
    }

    var buf = try allocator.alloc(u8, @intCast(st.size));
    errdefer if (private) secrets.secureZeroAndFree(allocator, buf) else allocator.free(buf);
    var filled: usize = 0;
    while (filled < buf.len) {
        const n = zig_compat.readFd(fd, buf[filled..]) catch return error.IoFailure;
        if (n == 0) return error.CorruptState; // shrank under us
        filled += n;
    }
    // Grew under us: the bound we checked is no longer the truth.
    var probe: [1]u8 = undefined;
    const extra = zig_compat.readFd(fd, &probe) catch return error.IoFailure;
    if (extra != 0) return error.CorruptState;
    return buf;
}

/// Open (optionally creating, `0700`) a single validated-component
/// subdirectory of `parent_fd`: never a symlink, owned by the effective uid,
/// no group/other permission bits. Shared by `StateDir` and `SubDir` so
/// every nesting level gets identical defenses.
fn openSubdirRaw(parent_fd: zig_compat.Fd, fault: *Fault, name: []const u8, create: bool) Error!SubDir {
    if (!validName(name)) return error.InvalidPath;
    if (create) {
        zig_compat.mkdirAt(parent_fd, name, 0o700) catch |err| switch (err) {
            error.Exists => {},
            else => return error.IoFailure,
        };
    }
    const fd = zig_compat.openDirAtNoFollow(parent_fd, name) catch |err| switch (err) {
        error.NotFound => return error.NotFound,
        else => {
            // Say why when we can: a symlink or file is a different problem
            // from an I/O failure (mirrors `StateDir.open`'s top-level check).
            const parent: std.Io.Dir = .{ .handle = parent_fd };
            if (parent.statFile(zig_compat.io(), name, .{ .follow_symlinks = false })) |st| {
                if (st.kind != .directory) return error.UnsafeFileType;
            } else |_| {}
            return error.IoFailure;
        },
    };
    errdefer zig_compat.closeFd(fd);
    const identity = zig_compat.statFdIdentity(fd) catch return error.IoFailure;
    if (!identity.is_directory) return error.UnsafeFileType;
    if (identity.uid != zig_compat.effectiveUid()) return error.WrongOwner;
    if (identity.mode & 0o022 != 0) return error.InsecurePermissions;
    removeStaleTempsRaw(fd);
    return .{ .fd = fd, .fault = fault };
}

/// Remove `.<name>.tmp-*` leftovers from a crashed writer. Best effort: a
/// failure to clean up must not block startup, and a leftover is `0600`.
fn removeStaleTempsRaw(dir_fd: zig_compat.Fd) void {
    const parent: std.Io.Dir = .{ .handle = dir_fd };
    const io = zig_compat.io();
    var it = parent.iterate();
    var doomed: [8][128]u8 = undefined;
    var doomed_len: [8]usize = undefined;
    var count: usize = 0;
    while (it.next(io) catch return) |entry| {
        if (entry.kind != .file) continue;
        if (entry.name.len < 6 or entry.name[0] != '.' or entry.name.len >= 128) continue;
        if (std.mem.indexOf(u8, entry.name, ".tmp-") == null) continue;
        if (count == doomed.len) break;
        @memcpy(doomed[count][0..entry.name.len], entry.name);
        doomed_len[count] = entry.name.len;
        count += 1;
    }
    for (0..count) |i| zig_compat.unlinkAt(dir_fd, doomed[i][0..doomed_len[i]]);
}

fn modeBits(st: std.Io.File.Stat) u32 {
    return @as(u32, @intCast(@intFromEnum(st.permissions))) & 0o777;
}

/// File names are a single path component from a small closed alphabet; no
/// separators, no dot-dot, bounded.
pub fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > 64) return false;
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return false;
    for (name) |c| {
        const ok = (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9') or c == '.' or c == '_' or c == '-';
        if (!ok) return false;
    }
    return true;
}

// -- Account record ---------------------------------------------------------

/// Non-secret account metadata. `kid` is a CA-supplied URL that has already
/// passed the CA-URL rules; it is persisted so restart reuses the account
/// without another newAccount call.
pub const AccountRecord = struct {
    directory: []const u8,
    kid: []const u8,
    /// RFC 7638 thumbprint (43-char base64url SHA-256) of the account key
    /// that registered `kid`; a different key must never reuse the record.
    key_thumbprint: []const u8,
    created_at: i64,
    /// Lowercase hex SHA-256 of the contact string; the address itself is
    /// never written to disk.
    contact_hash: []const u8,
};

const AccountRecordJson = struct {
    version: u32,
    directory: []const u8,
    kid: []const u8,
    key_thumbprint: []const u8,
    created_at: i64,
    contact_hash: []const u8,
};

pub const LoadedRecord = struct {
    parsed: std.json.Parsed(AccountRecordJson),

    pub fn record(self: *const LoadedRecord) AccountRecord {
        const v = self.parsed.value;
        return .{ .directory = v.directory, .kid = v.kid, .key_thumbprint = v.key_thumbprint, .created_at = v.created_at, .contact_hash = v.contact_hash };
    }

    pub fn deinit(self: *LoadedRecord) void {
        self.parsed.deinit();
    }
};

pub fn contactHash(contact: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(contact, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

const record_limits = json_limits.Limits{ .max_bytes = max_state_file_len, .max_depth = 2, .max_string = 2048, .max_keys = 8, .max_array = 1 };

/// Persist `record` as versioned JSON (`0600`, atomic).
pub fn saveAccountRecord(state: *StateDir, allocator: std.mem.Allocator, record: AccountRecord) Error!void {
    const json = std.fmt.allocPrint(
        allocator,
        "{{\"version\":{d},\"directory\":{f},\"kid\":{f},\"key_thumbprint\":{f},\"created_at\":{d},\"contact_hash\":{f}}}\n",
        .{
            state_version,
            std.json.fmt(record.directory, .{}),
            std.json.fmt(record.kid, .{}),
            std.json.fmt(record.key_thumbprint, .{}),
            record.created_at,
            std.json.fmt(record.contact_hash, .{}),
        },
    ) catch return error.OutOfMemory;
    defer allocator.free(json);
    try state.writeFileAtomic(account_record_name, json, 0o600);
}

/// Strictly load `account.json`: bounded, versioned, `0600`-or-stricter. A
/// directory URL different from `expected_directory` is `DirectoryMismatch`
/// (a staging account must never be mistaken for a production one).
pub fn loadAccountRecord(state: *const StateDir, allocator: std.mem.Allocator, expected_directory: []const u8) Error!LoadedRecord {
    const bytes = try state.readFileAlloc(allocator, account_record_name, max_state_file_len, true);
    defer secrets.secureZeroAndFree(allocator, bytes);
    var parsed = json_limits.parseBounded(AccountRecordJson, allocator, bytes, record_limits) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.CorruptState,
    };
    errdefer parsed.deinit();
    const v = parsed.value;
    if (v.version != state_version) return error.CorruptState;
    if (v.kid.len == 0 or v.key_thumbprint.len != account_mod.thumbprint_len or v.contact_hash.len != 64 or v.created_at < 0) return error.CorruptState;
    for (v.key_thumbprint) |c| {
        const ok = (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '-' or c == '_';
        if (!ok) return error.CorruptState;
    }
    for (v.contact_hash) |c| {
        if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) return error.CorruptState;
    }
    if (!std.mem.eql(u8, v.directory, expected_directory)) return error.DirectoryMismatch;
    return .{ .parsed = parsed };
}

/// Load a pre-provisioned account key from an operator-chosen path. Same
/// strictness as the state directory's own key (no symlink, regular file,
/// owned by the effective uid, no group/other bits, bounded, strict PKCS#8),
/// but it is only ever read: a missing or invalid file is an error, never a
/// reason to create a key somewhere the operator did not expect.
pub fn loadPreprovisionedKey(path: []const u8) Error!account_mod.AccountKey {
    if (path.len == 0 or std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidPath;
    const fd = zig_compat.openAtNoFollow(zig_compat.cwd_fd, path, .{}, 0) catch |err| switch (err) {
        error.NotFound => return error.NotFound,
        else => return error.UnsafeFileType, // includes a symlink (ELOOP)
    };
    defer zig_compat.closeFd(fd);
    const identity = zig_compat.statFdIdentity(fd) catch return error.IoFailure;
    if (!identity.is_regular) return error.UnsafeFileType;
    if (identity.uid != zig_compat.effectiveUid()) return error.WrongOwner;
    if (identity.mode & 0o077 != 0) return error.InsecurePermissions;

    var buf: [account_mod.max_pem_len + 1]u8 = undefined;
    defer secrets.secureZero(&buf);
    var len: usize = 0;
    while (len < buf.len) {
        const n = zig_compat.readFd(fd, buf[len..]) catch return error.IoFailure;
        if (n == 0) break;
        len += n;
    }
    if (len > account_mod.max_pem_len) return error.TooLarge;
    return account_mod.AccountKey.fromPkcs8Pem(buf[0..len]) catch error.CorruptState;
}

/// Load `account.key`, or create it (exclusive: only when it does not
/// exist). An existing but unreadable/invalid key is an error — it is never
/// regenerated, because that would silently orphan the registered account.
pub fn loadOrCreateAccountKey(state: *StateDir, allocator: std.mem.Allocator) Error!struct { key: account_mod.AccountKey, created: bool } {
    if (state.readFileAlloc(allocator, account_key_name, account_mod.max_pem_len, true)) |pem| {
        defer secrets.secureZeroAndFree(allocator, pem);
        const key = account_mod.AccountKey.fromPkcs8Pem(pem) catch return error.CorruptState;
        return .{ .key = key, .created = false };
    } else |err| switch (err) {
        error.NotFound => {},
        else => return err,
    }
    // An account record without its key means the key was lost or moved;
    // creating a fresh one would orphan the account.
    if (state.readFileAlloc(allocator, account_record_name, max_state_file_len, true)) |bytes| {
        secrets.secureZeroAndFree(allocator, bytes);
        return error.InconsistentState;
    } else |err| switch (err) {
        error.NotFound => {},
        else => return err,
    }

    var key = account_mod.AccountKey.generate() catch return error.IoFailure;
    errdefer key.deinit();
    const pem = key.toPkcs8Pem(allocator) catch return error.OutOfMemory;
    defer secrets.secureZeroAndFree(allocator, pem);
    try state.writeFileAtomic(account_key_name, pem, 0o600);
    return .{ .key = key, .created = true };
}

// ---------------------------------------------------------------------------

const testing = std.testing;

const test_thumbprint = "A" ** account_mod.thumbprint_len;

const TempState = struct {
    tmp: testing.TmpDir,
    path: []u8,

    fn init() !TempState {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const n = try tmp.dir.realPath(zig_compat.io(), &buf);
        const path = try std.fmt.allocPrint(testing.allocator, "{s}/state", .{buf[0..n]});
        return .{ .tmp = tmp, .path = path };
    }

    fn deinit(self: *TempState) void {
        testing.allocator.free(self.path);
        self.tmp.cleanup();
    }
};

fn expectMode(state: *const StateDir, name: []const u8, expected: u32) !void {
    const st = try state.dir().statFile(zig_compat.io(), name, .{ .follow_symlinks = false });
    try testing.expectEqual(expected, modeBits(st));
}

test "ACME state: open creates a 0700 directory and a 0600 lock" {
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try StateDir.open(tmp.path);
    defer state.close();
    const st = try std.Io.Dir.cwd().statFile(zig_compat.io(), tmp.path, .{ .follow_symlinks = false });
    try testing.expectEqual(@as(u32, 0o700), modeBits(st));
    try expectMode(&state, lock_name, 0o600);
}

test "ACME state: second opener is rejected until the first closes" {
    var tmp = try TempState.init();
    defer tmp.deinit();
    var first = try StateDir.open(tmp.path);
    try testing.expectError(error.Locked, StateDir.open(tmp.path));
    first.close();
    var again = try StateDir.open(tmp.path);
    again.close();
}

test "ACME state: refuses symlink, file, and group-writable directories" {
    var tmp = try TempState.init();
    defer tmp.deinit();

    const target = try std.fmt.allocPrint(testing.allocator, "{s}-real", .{tmp.path});
    defer testing.allocator.free(target);
    {
        var real = try StateDir.open(target);
        real.close();
    }
    try tmp.tmp.dir.symLink(zig_compat.io(), target, "state", .{ .is_directory = true });
    try testing.expectError(error.UnsafeFileType, StateDir.open(tmp.path));

    const file_path = try std.fmt.allocPrint(testing.allocator, "{s}-file", .{tmp.path});
    defer testing.allocator.free(file_path);
    (try std.Io.Dir.cwd().createFile(zig_compat.io(), file_path, .{})).close(zig_compat.io());
    try testing.expectError(error.UnsafeFileType, StateDir.open(file_path));

    const loose = try std.fmt.allocPrint(testing.allocator, "{s}-loose", .{tmp.path});
    defer testing.allocator.free(loose);
    {
        var s = try StateDir.open(loose);
        s.close();
    }
    try zig_compat.chmodPath(loose, 0o770);
    try testing.expectError(error.InsecurePermissions, StateDir.open(loose));

    // A directory owned by someone else is refused (skipped when running as
    // root, where /usr is our own).
    if (zig_compat.effectiveUid() != 0) try testing.expectError(error.WrongOwner, StateDir.open("/usr"));

    try testing.expectError(error.InvalidPath, StateDir.open(""));
    try testing.expectError(error.InvalidPath, StateDir.open("a\x00b"));
}

test "ACME state: atomic write replaces content and leaves no temp files" {
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try StateDir.open(tmp.path);
    defer state.close();

    try state.writeFileAtomic("a.json", "one", 0o600);
    try state.writeFileAtomic("a.json", "two-longer", 0o600);
    const got = try state.readFileAlloc(testing.allocator, "a.json", 64, true);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("two-longer", got);
    try expectMode(&state, "a.json", 0o600);

    var it = state.dir().iterate();
    while (try it.next(zig_compat.io())) |entry| {
        try testing.expect(std.mem.indexOf(u8, entry.name, ".tmp-") == null);
    }
}

test "ACME state: a failure at every step keeps the previous file and removes the temp" {
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try StateDir.open(tmp.path);
    defer state.close();
    try state.writeFileAtomic("a.json", "original", 0o600);

    const points = [_]Fault{ .create_temp, .write, .short_write, .fsync_file, .close_file, .rename };
    for (points) |point| {
        state.fault = point;
        try testing.expectError(error.InjectedFault, state.writeFileAtomic("a.json", "replacement-content", 0o600));
        const got = try state.readFileAlloc(testing.allocator, "a.json", 64, true);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings("original", got);
        var it = state.dir().iterate();
        while (try it.next(zig_compat.io())) |entry| {
            try testing.expect(std.mem.indexOf(u8, entry.name, ".tmp-") == null);
        }
    }

    // fsync(dir) fails after the rename became visible: the write reports the
    // failure (durability is unproven) but the file is whole, never a mix.
    state.fault = .fsync_dir;
    try testing.expectError(error.InjectedFault, state.writeFileAtomic("a.json", "replacement-content", 0o600));
    const got = try state.readFileAlloc(testing.allocator, "a.json", 64, true);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("replacement-content", got);
}

test "ACME state: stale temp files from a crashed writer are removed at open" {
    var tmp = try TempState.init();
    defer tmp.deinit();
    {
        var first = try StateDir.open(tmp.path);
        defer first.close();
        const fd = try zig_compat.openAtNoFollow(first.dir_fd, ".account.key.tmp-deadbeef", .{ .write = true, .create = true, .exclusive = true }, 0o600);
        zig_compat.closeFd(fd);
    }
    var second = try StateDir.open(tmp.path);
    defer second.close();
    try testing.expectError(error.NotFound, second.readFileAlloc(testing.allocator, ".account.key.tmp-deadbeef", 8, true));
}

test "ACME state: reads enforce bounds, kind, and private permissions" {
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try StateDir.open(tmp.path);
    defer state.close();

    try state.writeFileAtomic("big", "0123456789", 0o600);
    try testing.expectError(error.TooLarge, state.readFileAlloc(testing.allocator, "big", 4, true));
    try testing.expectError(error.NotFound, state.readFileAlloc(testing.allocator, "missing", 4, true));
    try testing.expectError(error.InvalidPath, state.readFileAlloc(testing.allocator, "../x", 4, true));
    try testing.expectError(error.InvalidPath, state.readFileAlloc(testing.allocator, "a/b", 4, true));
    try testing.expectError(error.TooLarge, state.writeFileAtomic("big2", &([_]u8{0} ** (max_state_file_len + 1)), 0o600));

    try state.writeFileAtomic("open", "x", 0o644);
    try testing.expectError(error.InsecurePermissions, state.readFileAlloc(testing.allocator, "open", 4, true));
    const readable = try state.readFileAlloc(testing.allocator, "open", 4, false);
    testing.allocator.free(readable);

    try tmp.tmp.dir.symLink(zig_compat.io(), "big", "state/link", .{});
    try testing.expectError(error.UnsafeFileType, state.readFileAlloc(testing.allocator, "link", 64, true));
}

test "ACME state: account key is created 0600 once and reloaded identically" {
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try StateDir.open(tmp.path);
    defer state.close();

    var created = try loadOrCreateAccountKey(&state, testing.allocator);
    defer created.key.deinit();
    try testing.expect(created.created);
    try expectMode(&state, account_key_name, 0o600);

    var loaded = try loadOrCreateAccountKey(&state, testing.allocator);
    defer loaded.key.deinit();
    try testing.expect(!loaded.created);
    try testing.expectEqualSlices(u8, &created.key.jwk().x, &loaded.key.jwk().x);
}

test "ACME state: key generation write failure leaves no key and the next attempt succeeds" {
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try StateDir.open(tmp.path);
    defer state.close();
    state.fault = .rename;
    try testing.expectError(error.InjectedFault, loadOrCreateAccountKey(&state, testing.allocator));
    try testing.expectError(error.NotFound, state.readFileAlloc(testing.allocator, account_key_name, 512, true));
    var key = try loadOrCreateAccountKey(&state, testing.allocator);
    key.key.deinit();
}

test "ACME state: corrupt or loosened key is never regenerated" {
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try StateDir.open(tmp.path);
    defer state.close();

    try state.writeFileAtomic(account_key_name, "not a key", 0o600);
    try testing.expectError(error.CorruptState, loadOrCreateAccountKey(&state, testing.allocator));
    const still = try state.readFileAlloc(testing.allocator, account_key_name, 64, true);
    defer testing.allocator.free(still);
    try testing.expectEqualStrings("not a key", still);

    try state.writeFileAtomic(account_key_name, "not a key", 0o640);
    try testing.expectError(error.InsecurePermissions, loadOrCreateAccountKey(&state, testing.allocator));
}

test "ACME state: record without a key is inconsistent, not a reason to mint a key" {
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try StateDir.open(tmp.path);
    defer state.close();
    try saveAccountRecord(&state, testing.allocator, .{
        .directory = "https://ca.test/dir",
        .kid = "https://ca.test/acct/1",
        .key_thumbprint = test_thumbprint,
        .created_at = 1,
        .contact_hash = &contactHash("mailto:a@example.com"),
    });
    try testing.expectError(error.InconsistentState, loadOrCreateAccountKey(&state, testing.allocator));
    try testing.expectError(error.NotFound, state.readFileAlloc(testing.allocator, account_key_name, 512, true));
}

test "ACME state: account record round trips and detects directory mismatch" {
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try StateDir.open(tmp.path);
    defer state.close();
    const hash = contactHash("mailto:ops@example.com");
    try saveAccountRecord(&state, testing.allocator, .{
        .directory = "https://ca.test/dir",
        .kid = "https://ca.test/acct/42",
        .key_thumbprint = test_thumbprint,
        .created_at = 1_700_000_000,
        .contact_hash = &hash,
    });
    try expectMode(&state, account_record_name, 0o600);

    var loaded = try loadAccountRecord(&state, testing.allocator, "https://ca.test/dir");
    defer loaded.deinit();
    const record = loaded.record();
    try testing.expectEqualStrings("https://ca.test/acct/42", record.kid);
    try testing.expectEqual(@as(i64, 1_700_000_000), record.created_at);
    try testing.expectEqualStrings(&hash, record.contact_hash);
    try testing.expectEqualStrings(test_thumbprint, record.key_thumbprint);
    // The address itself is never persisted.
    const raw = try state.readFileAlloc(testing.allocator, account_record_name, max_state_file_len, true);
    defer testing.allocator.free(raw);
    try testing.expect(std.mem.indexOf(u8, raw, "ops@example.com") == null);

    try testing.expectError(error.DirectoryMismatch, loadAccountRecord(&state, testing.allocator, "https://staging.ca.test/dir"));
}

test "ACME state: malformed account records fail closed as corrupt" {
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try StateDir.open(tmp.path);
    defer state.close();
    const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const tp = test_thumbprint;
    const head = "{\"version\":2,\"directory\":\"https://ca.test/dir\",";
    const cases = [_][]const u8{
        "",
        "{",
        "[]",
        "{\"version\":2}",
        // Old (unbound) format and unknown versions.
        "{\"version\":1,\"directory\":\"https://ca.test/dir\",\"kid\":\"k\",\"created_at\":1,\"contact_hash\":\"" ++ hash ++ "\"}",
        "{\"version\":3,\"directory\":\"https://ca.test/dir\",\"kid\":\"k\",\"key_thumbprint\":\"" ++ tp ++ "\",\"created_at\":1,\"contact_hash\":\"" ++ hash ++ "\"}",
        head ++ "\"kid\":\"\",\"key_thumbprint\":\"" ++ tp ++ "\",\"created_at\":1,\"contact_hash\":\"" ++ hash ++ "\"}",
        head ++ "\"kid\":\"k\",\"key_thumbprint\":\"" ++ tp ++ "\",\"created_at\":-1,\"contact_hash\":\"" ++ hash ++ "\"}",
        head ++ "\"kid\":\"k\",\"key_thumbprint\":\"" ++ tp ++ "\",\"created_at\":1,\"contact_hash\":\"zz\"}",
        head ++ "\"kid\":\"k\",\"key_thumbprint\":\"" ++ tp ++ "\",\"created_at\":1,\"contact_hash\":\"" ++ ("G" ** 64) ++ "\"}",
        head ++ "\"kid\":\"k\",\"key_thumbprint\":\"short\",\"created_at\":1,\"contact_hash\":\"" ++ hash ++ "\"}",
        head ++ "\"kid\":\"k\",\"key_thumbprint\":\"" ++ ("+" ** account_mod.thumbprint_len) ++ "\",\"created_at\":1,\"contact_hash\":\"" ++ hash ++ "\"}",
        "{\"version\":2,\"version\":2,\"directory\":\"https://ca.test/dir\",\"kid\":\"k\",\"key_thumbprint\":\"" ++ tp ++ "\",\"created_at\":1,\"contact_hash\":\"" ++ hash ++ "\"}",
        "{\"version\":2,\"directory\":" ++ "[" ** 20 ++ "}",
    };
    for (cases) |content| {
        try state.writeFileAtomic(account_record_name, content, 0o600);
        try testing.expectError(error.CorruptState, loadAccountRecord(&state, testing.allocator, "https://ca.test/dir"));
    }
}

const RaceCtx = struct {
    path: []const u8,
    active: std.atomic.Value(u32) = .init(0),
    max_active: std.atomic.Value(u32) = .init(0),
    completed: std.atomic.Value(u32) = .init(0),
    unexpected: std.atomic.Value(u32) = .init(0),
};

fn raceWorker(ctx: *RaceCtx, tag: u8) void {
    var done: usize = 0;
    var spins: usize = 0;
    while (done < 5 and spins < 100_000) : (spins += 1) {
        var state = StateDir.open(ctx.path) catch |err| {
            if (err != error.Locked) _ = ctx.unexpected.fetchAdd(1, .monotonic);
            zig_compat.sleepNs(100_000);
            continue;
        };
        const now = ctx.active.fetchAdd(1, .acq_rel) + 1;
        _ = ctx.max_active.fetchMax(now, .acq_rel);
        var content: [256]u8 = undefined;
        @memset(&content, tag);
        state.writeFileAtomic("shared.json", &content, 0o600) catch {
            _ = ctx.unexpected.fetchAdd(1, .monotonic);
        };
        zig_compat.sleepNs(200_000);
        _ = ctx.active.fetchSub(1, .acq_rel);
        state.close();
        done += 1;
        _ = ctx.completed.fetchAdd(1, .monotonic);
    }
}

test "ACME state: racing openers are serialized and never corrupt the shared file" {
    var tmp = try TempState.init();
    defer tmp.deinit();
    {
        var seed = try StateDir.open(tmp.path);
        seed.close();
    }
    var ctx = RaceCtx{ .path = tmp.path };
    var threads: [4]std.Thread = undefined;
    for (&threads, 0..) |*t, i| t.* = try std.Thread.spawn(.{}, raceWorker, .{ &ctx, @as(u8, 'a') + @as(u8, @intCast(i)) });
    for (threads) |t| t.join();

    try testing.expectEqual(@as(u32, 20), ctx.completed.load(.monotonic));
    try testing.expectEqual(@as(u32, 1), ctx.max_active.load(.monotonic));
    try testing.expectEqual(@as(u32, 0), ctx.unexpected.load(.monotonic));

    var state = try StateDir.open(tmp.path);
    defer state.close();
    const got = try state.readFileAlloc(testing.allocator, "shared.json", 512, true);
    defer testing.allocator.free(got);
    try testing.expectEqual(@as(usize, 256), got.len);
    for (got) |c| try testing.expectEqual(got[0], c);
}

test "ACME state: pre-provisioned key loads strictly and is never created" {
    var tmp = try TempState.init();
    defer tmp.deinit();
    var state = try StateDir.open(tmp.path);
    defer state.close();

    var original = try account_mod.AccountKey.generate();
    defer original.deinit();
    const pem = try original.toPkcs8Pem(testing.allocator);
    defer secrets.secureZeroAndFree(testing.allocator, pem);

    const key_path = try std.fmt.allocPrint(testing.allocator, "{s}/provisioned.pem", .{tmp.path});
    defer testing.allocator.free(key_path);

    try testing.expectError(error.NotFound, loadPreprovisionedKey(key_path));
    try testing.expectError(error.NotFound, state.readFileAlloc(testing.allocator, "provisioned.pem", 8, true));

    try state.writeFileAtomic("provisioned.pem", pem, 0o600);
    var loaded = try loadPreprovisionedKey(key_path);
    defer loaded.deinit();
    try testing.expectEqualSlices(u8, &original.jwk().x, &loaded.jwk().x);

    try state.writeFileAtomic("provisioned.pem", pem, 0o640);
    try testing.expectError(error.InsecurePermissions, loadPreprovisionedKey(key_path));
    try state.writeFileAtomic("provisioned.pem", "garbage", 0o600);
    try testing.expectError(error.CorruptState, loadPreprovisionedKey(key_path));
    try state.writeFileAtomic("provisioned.pem", &([_]u8{'a'} ** 600), 0o600);
    try testing.expectError(error.TooLarge, loadPreprovisionedKey(key_path));

    const link_path = try std.fmt.allocPrint(testing.allocator, "{s}/link.pem", .{tmp.path});
    defer testing.allocator.free(link_path);
    try tmp.tmp.dir.symLink(zig_compat.io(), "provisioned.pem", "state/link.pem", .{});
    try testing.expectError(error.UnsafeFileType, loadPreprovisionedKey(link_path));
    try testing.expectError(error.InvalidPath, loadPreprovisionedKey(""));
}
