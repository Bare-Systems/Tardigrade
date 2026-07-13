//! Nonblocking encrypted byte-stream contract for TLS-over-TCP.
//!
//! HTTP/1.1 and HTTP/2 should consume decrypted bytes and produce plaintext
//! writes without caring whether the TLS implementation underneath is OpenSSL
//! or the native record path. This module defines that small contract and the
//! native record-mode stream state that maps caller-fed ciphertext into
//! plaintext queues without blocking or growing unbounded buffers.

const std = @import("std");
const builtin = @import("builtin");
const crypto = @import("crypto");
const algorithms = @import("algorithms.zig");
const events = @import("events.zig");
const record_codec = @import("record_codec.zig");
const record_epoch_bridge = @import("record_epoch_bridge.zig");

const provider = crypto.provider;

pub const Error = record_epoch_bridge.Error || error{
    WouldBlock,
    EndOfStream,
    StreamClosed,
    PlaintextBufferFull,
    CiphertextBufferFull,
    UnsupportedRecordContent,
    CarrierInputBufferFull,
    SocketPairFailed,
    FcntlFailed,
    SocketReadFailed,
    SocketWriteFailed,
};

const Lifecycle = enum {
    handshaking,
    open,
    closing,
    closed,
    failed,
};

pub const BackendKind = enum {
    openssl,
    pure_zig_record,
};

pub const Readiness = struct {
    wants_read: bool = false,
    wants_write: bool = false,
    can_read_plaintext: bool = false,
    can_write_plaintext: bool = false,
    peer_closed: bool = false,
};

pub const DriveResult = struct {
    made_progress: bool,
    readiness: Readiness,
};

pub const EncryptedStream = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        backendFn: *const fn (*anyopaque) BackendKind,
        readFn: *const fn (*anyopaque, []u8) Error!usize,
        writeFn: *const fn (*anyopaque, []const u8) Error!usize,
        closeFn: *const fn (*anyopaque) void,
        readinessFn: *const fn (*anyopaque) Readiness,
        driveFn: *const fn (*anyopaque) Error!DriveResult,
    };

    pub fn backend(self: EncryptedStream) BackendKind {
        return self.vtable.backendFn(self.ptr);
    }

    pub fn read(self: EncryptedStream, out: []u8) Error!usize {
        return self.vtable.readFn(self.ptr, out);
    }

    pub fn write(self: EncryptedStream, bytes: []const u8) Error!usize {
        return self.vtable.writeFn(self.ptr, bytes);
    }

    pub fn close(self: EncryptedStream) void {
        self.vtable.closeFn(self.ptr);
    }

    pub fn readiness(self: EncryptedStream) Readiness {
        return self.vtable.readinessFn(self.ptr);
    }

    pub fn drive(self: EncryptedStream) Error!DriveResult {
        return self.vtable.driveFn(self.ptr);
    }
};

pub const Carrier = struct {
    ptr: *anyopaque,
    readFn: *const fn (*anyopaque, []u8) Error!usize,
    writeFn: *const fn (*anyopaque, []const u8) Error!usize,
    closeFn: ?*const fn (*anyopaque) void = null,
    owns_handle: bool = false,

    pub fn read(self: Carrier, out: []u8) Error!usize {
        return self.readFn(self.ptr, out);
    }

    pub fn write(self: Carrier, bytes: []const u8) Error!usize {
        return self.writeFn(self.ptr, bytes);
    }

    pub fn close(self: Carrier) void {
        if (self.closeFn) |closeFn| closeFn(self.ptr);
    }
};

pub const PureZigRecordStream = struct {
    pub const max_plaintext_queue = 32 * 1024;
    pub const max_ciphertext_queue = 4 * record_codec.max_ciphertext_record_len;
    pub const max_carrier_input_queue = 4 * record_codec.max_ciphertext_record_len;
    pub const max_handshake_queue = 16 * 1024;
    const drive_read_budget = 2 * record_codec.max_ciphertext_record_len;
    const drive_write_budget = 2 * record_codec.max_ciphertext_record_len;
    const drive_record_budget = 8;
    const drive_read_chunk = 4096;

    bridge: record_epoch_bridge.Bridge,
    initial_parser: record_codec.Parser = record_codec.Parser.init(.plaintext),
    ciphertext_parser: record_codec.Parser = record_codec.Parser.init(.ciphertext),
    inbound_carrier: ByteQueue(max_carrier_input_queue, error.CarrierInputBufferFull) = .{},
    inbound_plaintext: ByteQueue(max_plaintext_queue, error.PlaintextBufferFull) = .{},
    outbound_ciphertext: ByteQueue(max_ciphertext_queue, error.CiphertextBufferFull) = .{},
    inbound_handshake: ByteQueue(max_handshake_queue, error.PlaintextBufferFull) = .{},
    carrier: ?Carrier = null,
    lifecycle: Lifecycle = .handshaking,
    peer_closed: bool = false,
    close_notify_queued: bool = false,
    failed: ?Error = null,

    pub fn init(crypto_provider: provider.CryptoProvider, cipher_suite: algorithms.CipherSuite) PureZigRecordStream {
        return .{ .bridge = record_epoch_bridge.Bridge.init(crypto_provider, cipher_suite) };
    }

    pub fn initWithCarrier(crypto_provider: provider.CryptoProvider, cipher_suite: algorithms.CipherSuite, carrier: Carrier) PureZigRecordStream {
        var stream_state = init(crypto_provider, cipher_suite);
        stream_state.carrier = carrier;
        return stream_state;
    }

    pub fn deinit(self: *PureZigRecordStream) void {
        self.bridge.deinit();
        self.inbound_carrier.clear();
        self.inbound_plaintext.clear();
        self.outbound_ciphertext.clear();
        self.inbound_handshake.clear();
        self.initial_parser.reset();
        self.ciphertext_parser.reset();
        self.closeCarrier();
        self.lifecycle = .closed;
        self.peer_closed = true;
        self.close_notify_queued = false;
        self.failed = null;
    }

    pub fn stream(self: *PureZigRecordStream) EncryptedStream {
        return .{ .ptr = self, .vtable = &pure_zig_record_vtable };
    }

    pub fn applyEvent(self: *PureZigRecordStream, event: events.Event) Error!void {
        if (self.failed) |err| return err;
        if (self.lifecycle == .closed or self.lifecycle == .failed or self.lifecycle == .closing) return error.StreamClosed;
        if (event == .handshake_bytes and self.outbound_ciphertext.available() < record_codec.max_ciphertext_record_len) return error.WouldBlock;
        var record_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
        if (self.bridge.applyEvent(event, &record_buf) catch |err| return self.fail(err)) |record| {
            self.outbound_ciphertext.append(record) catch |err| return self.fail(err);
        }
        if (event == .handshake_complete) self.lifecycle = .open;
    }

    pub fn feedHandshakeCiphertext(self: *PureZigRecordStream, epoch: events.EncryptionEpoch, bytes: []const u8) Error!usize {
        if (self.failed) |err| return err;
        if (self.lifecycle == .closed or self.lifecycle == .failed) return error.StreamClosed;
        if (self.inbound_handshake.available() < record_codec.max_plaintext_fragment_len) return error.WouldBlock;
        var sink = record_codec.RecordSink(1, record_codec.max_ciphertext_fragment_len){};
        const parser = self.parserForEpoch(epoch);
        const consumed = feedUntilOneRecord(parser, bytes, &sink) catch |err| return self.fail(err);
        self.openHandshakeSink(epoch, &sink) catch |err| return self.fail(err);
        return consumed;
    }

    pub fn readHandshake(self: *PureZigRecordStream, out: []u8) Error!usize {
        if (self.failed) |err| return err;
        if (self.lifecycle == .closed or self.lifecycle == .failed) return error.StreamClosed;
        return self.inbound_handshake.read(out) orelse error.WouldBlock;
    }

    pub fn feedCiphertext(self: *PureZigRecordStream, bytes: []const u8) Error!usize {
        if (self.failed) |err| return err;
        if (self.lifecycle == .closed or self.lifecycle == .failed) return error.StreamClosed;
        if (!self.canAcceptCarrierRead()) return error.WouldBlock;
        var sink = record_codec.RecordSink(1, record_codec.max_ciphertext_fragment_len){};
        const consumed = feedUntilOneRecord(&self.ciphertext_parser, bytes, &sink) catch |err| return self.fail(err);

        var plaintext_buf: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
        for (sink.items[0..sink.len]) |record| {
            const opened = self.bridge.openProtected(.application, record, &plaintext_buf) catch |err| return self.fail(err);
            switch (opened.inner.content_type) {
                .application_data => self.inbound_plaintext.append(opened.inner.content) catch |err| return self.fail(err),
                .handshake => self.inbound_handshake.append(opened.inner.content) catch |err| return self.fail(err),
                .alert => self.handleAlert(opened.inner.content) catch |err| return self.fail(err),
                .change_cipher_spec => return self.fail(error.UnsupportedRecordContent),
            }
        }
        return consumed;
    }

    pub fn markPeerClosed(self: *PureZigRecordStream) void {
        self.peer_closed = true;
    }

    pub fn readPlaintext(self: *PureZigRecordStream, out: []u8) Error!usize {
        if (self.failed) |err| return err;
        if (self.lifecycle == .closed or self.lifecycle == .failed) return error.StreamClosed;
        if (self.inbound_plaintext.read(out)) |n| return n;
        if (self.peer_closed) return error.EndOfStream;
        return error.WouldBlock;
    }

    pub fn writePlaintext(self: *PureZigRecordStream, bytes: []const u8) Error!usize {
        if (self.failed) |err| return err;
        if (self.lifecycle == .closing or self.lifecycle == .closed or self.lifecycle == .failed) return error.StreamClosed;
        if (bytes.len == 0) return 0;
        if (self.lifecycle != .open or !self.bridge.handshake_complete) return error.WouldBlock;
        if (self.outbound_ciphertext.available() < record_codec.max_ciphertext_record_len) return error.WouldBlock;

        const n = @min(bytes.len, record_codec.max_plaintext_fragment_len);
        var record_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
        const record = self.bridge.sealApplicationData(bytes[0..n], &record_buf) catch |err| return self.fail(err);
        self.outbound_ciphertext.append(record) catch |err| return self.fail(err);
        return n;
    }

    pub fn drainCiphertext(self: *PureZigRecordStream, out: []u8) Error!usize {
        if (self.failed) |err| return err;
        if (self.outbound_ciphertext.read(out)) |n| return n;
        if (self.lifecycle == .closed or self.lifecycle == .failed) return error.StreamClosed;
        return error.WouldBlock;
    }

    pub fn peekCiphertext(self: *const PureZigRecordStream) []const u8 {
        if (self.failed != null or self.lifecycle == .closed or self.lifecycle == .failed) return &.{};
        return self.outbound_ciphertext.slice();
    }

    pub fn consumeCiphertext(self: *PureZigRecordStream, count: usize) Error!void {
        if (self.failed) |err| return err;
        try self.outbound_ciphertext.discard(count);
        if (self.lifecycle == .closing and self.carrier == null and self.close_notify_queued and self.outbound_ciphertext.len == 0) {
            self.lifecycle = .closed;
        }
    }

    pub fn readiness(self: *const PureZigRecordStream) Readiness {
        if (self.failed != null or self.lifecycle == .failed or self.lifecycle == .closed) {
            return .{ .peer_closed = self.peer_closed };
        }
        return .{
            .wants_read = self.canAcceptCarrierRead(),
            .wants_write = self.outbound_ciphertext.len > 0 or (self.lifecycle == .closing and !self.close_notify_queued),
            .can_read_plaintext = self.inbound_plaintext.len > 0,
            .can_write_plaintext = self.lifecycle == .open and self.bridge.handshake_complete and self.outbound_ciphertext.available() >= record_codec.max_ciphertext_record_len,
            .peer_closed = self.peer_closed,
        };
    }

    pub fn drive(self: *PureZigRecordStream) Error!DriveResult {
        if (self.failed) |err| return err;
        var made_progress = false;
        if (self.lifecycle == .closed or self.lifecycle == .failed) {
            return .{ .made_progress = false, .readiness = self.readiness() };
        }

        if (self.carrier) |carrier| {
            var written_total: usize = 0;
            while (self.outbound_ciphertext.len > 0 and written_total < drive_write_budget) {
                const written = carrier.write(self.peekCiphertext()) catch |err| switch (err) {
                    error.WouldBlock => 0,
                    else => return self.fail(err),
                };
                if (written == 0) break;
                try self.consumeCiphertext(written);
                written_total += written;
                made_progress = true;
            }

            if (try self.queueCloseNotify()) made_progress = true;

            var wrote_close_notify = false;
            while (self.outbound_ciphertext.len > 0 and written_total < drive_write_budget) {
                const written = carrier.write(self.peekCiphertext()) catch |err| switch (err) {
                    error.WouldBlock => 0,
                    else => return self.fail(err),
                };
                if (written == 0) break;
                try self.consumeCiphertext(written);
                written_total += written;
                made_progress = true;
                wrote_close_notify = true;
            }

            if (self.lifecycle == .closing and self.close_notify_queued and self.outbound_ciphertext.len == 0 and wrote_close_notify) {
                self.lifecycle = .closed;
                self.closeCarrier();
                made_progress = true;
                return .{ .made_progress = made_progress, .readiness = self.readiness() };
            }

            if (try self.processCarrierInput(drive_record_budget)) made_progress = true;

            var read_total: usize = 0;
            while (read_total < drive_read_budget and self.canAcceptCarrierRead() and self.inbound_carrier.available() > 0) {
                var buf: [drive_read_chunk]u8 = undefined;
                const read_cap = @min(buf.len, @min(self.inbound_carrier.available(), drive_read_budget - read_total));
                if (read_cap == 0) break;
                const maybe_read_len = carrier.read(buf[0..read_cap]) catch |err| switch (err) {
                    error.WouldBlock => null,
                    error.EndOfStream => eof: {
                        self.peer_closed = true;
                        made_progress = true;
                        break :eof null;
                    },
                    else => return self.fail(err),
                };
                if (maybe_read_len) |read_len| {
                    if (read_len == 0) {
                        self.peer_closed = true;
                        made_progress = true;
                    } else {
                        self.inbound_carrier.append(buf[0..read_len]) catch |err| return self.fail(err);
                        read_total += read_len;
                        made_progress = true;
                        if (try self.processCarrierInput(drive_record_budget)) made_progress = true;
                    }
                } else {
                    break;
                }
            }
        } else if (self.lifecycle == .closing) {
            if (try self.queueCloseNotify()) made_progress = true;
            if (self.close_notify_queued and self.outbound_ciphertext.len == 0) {
                self.lifecycle = .closed;
                made_progress = true;
            }
        } else {
            if (try self.processCarrierInput(drive_record_budget)) made_progress = true;
        }

        if (self.lifecycle == .closing and self.carrier != null and self.close_notify_queued and self.outbound_ciphertext.len == 0) {
            self.lifecycle = .closed;
            self.closeCarrier();
            made_progress = true;
        }
        return .{ .made_progress = made_progress, .readiness = self.readiness() };
    }

    pub fn queuedCiphertextLen(self: *const PureZigRecordStream) usize {
        return self.outbound_ciphertext.len;
    }

    fn parserForEpoch(self: *PureZigRecordStream, epoch: events.EncryptionEpoch) *record_codec.Parser {
        return switch (epoch) {
            .initial => &self.initial_parser,
            .handshake,
            .application,
            .zero_rtt,
            => &self.ciphertext_parser,
        };
    }

    fn openHandshakeSink(self: *PureZigRecordStream, epoch: events.EncryptionEpoch, sink: anytype) Error!void {
        var plaintext_buf: [record_codec.max_ciphertext_fragment_len]u8 = undefined;
        for (sink.items[0..sink.len]) |record| {
            const opened = try self.bridge.openHandshake(epoch, record, &plaintext_buf);
            try self.inbound_handshake.append(opened.inner.content);
        }
    }

    fn handleAlert(self: *PureZigRecordStream, alert: []const u8) Error!void {
        if (alert.len >= 2 and alert[1] == 0) {
            self.peer_closed = true;
            return;
        }
        return self.fail(error.UnsupportedRecordContent);
    }

    fn feedCarrierCiphertext(self: *PureZigRecordStream, bytes: []const u8) Error!usize {
        if (self.bridge.handshake_complete) return self.feedCiphertext(bytes);
        const epoch: events.EncryptionEpoch = if (self.bridge.hasReadKeys(.handshake)) .handshake else .initial;
        return self.feedHandshakeCiphertext(epoch, bytes);
    }

    fn canAcceptCarrierRead(self: *const PureZigRecordStream) bool {
        return self.lifecycle != .closed and self.lifecycle != .failed and self.lifecycle != .closing and !self.peer_closed and
            self.inbound_carrier.available() > 0 and
            self.inbound_plaintext.available() >= record_codec.max_plaintext_fragment_len and
            self.inbound_handshake.available() >= record_codec.max_plaintext_fragment_len;
    }

    fn queueCloseNotify(self: *PureZigRecordStream) Error!bool {
        if (self.lifecycle != .closing or self.close_notify_queued or self.outbound_ciphertext.len > 0) return false;
        if (!self.bridge.handshake_complete) {
            self.lifecycle = .closed;
            return true;
        }
        if (self.outbound_ciphertext.available() < record_codec.max_ciphertext_record_len) return false;
        var alert_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
        const close_notify = self.bridge.sealProtected(.application, .alert, &.{ 1, 0 }, &alert_buf) catch |err| return self.fail(err);
        self.outbound_ciphertext.append(close_notify) catch |err| return self.fail(err);
        self.close_notify_queued = true;
        return true;
    }

    fn processCarrierInput(self: *PureZigRecordStream, record_budget: usize) Error!bool {
        var made_progress = false;
        var processed: usize = 0;
        while (processed < record_budget and self.inbound_carrier.len > 0 and self.canAcceptCarrierRead()) {
            const pending = self.inbound_carrier.slice();
            const consumed = self.feedCarrierCiphertext(pending) catch |err| switch (err) {
                error.WouldBlock => break,
                else => return err,
            };
            if (consumed == 0) break;
            try self.inbound_carrier.discard(consumed);
            processed += 1;
            made_progress = true;
        }
        return made_progress;
    }

    fn closeCarrier(self: *PureZigRecordStream) void {
        if (self.carrier) |carrier| {
            if (carrier.owns_handle) carrier.close();
            self.carrier = null;
        }
    }

    fn fail(self: *PureZigRecordStream, err: Error) Error {
        self.failed = err;
        self.lifecycle = .failed;
        self.inbound_carrier.clear();
        self.inbound_plaintext.clear();
        self.outbound_ciphertext.clear();
        self.inbound_handshake.clear();
        self.initial_parser.reset();
        self.ciphertext_parser.reset();
        self.bridge.deinit();
        self.closeCarrier();
        return err;
    }
};

fn feedUntilOneRecord(parser: *record_codec.Parser, bytes: []const u8, sink: anytype) Error!usize {
    const result = try parser.feedOne(bytes, sink);
    return result.consumed;
}

fn pureBackend(_: *anyopaque) BackendKind {
    return .pure_zig_record;
}

fn pureRead(ptr: *anyopaque, out: []u8) Error!usize {
    const self: *PureZigRecordStream = @ptrCast(@alignCast(ptr));
    return self.readPlaintext(out);
}

fn pureWrite(ptr: *anyopaque, bytes: []const u8) Error!usize {
    const self: *PureZigRecordStream = @ptrCast(@alignCast(ptr));
    return self.writePlaintext(bytes);
}

fn pureClose(ptr: *anyopaque) void {
    const self: *PureZigRecordStream = @ptrCast(@alignCast(ptr));
    if (self.lifecycle == .handshaking or self.lifecycle == .open) self.lifecycle = .closing;
}

fn pureReadiness(ptr: *anyopaque) Readiness {
    const self: *PureZigRecordStream = @ptrCast(@alignCast(ptr));
    return self.readiness();
}

fn pureDrive(ptr: *anyopaque) Error!DriveResult {
    const self: *PureZigRecordStream = @ptrCast(@alignCast(ptr));
    return self.drive();
}

const pure_zig_record_vtable = EncryptedStream.VTable{
    .backendFn = pureBackend,
    .readFn = pureRead,
    .writeFn = pureWrite,
    .closeFn = pureClose,
    .readinessFn = pureReadiness,
    .driveFn = pureDrive,
};

fn ByteQueue(comptime capacity: usize, comptime full_error: Error) type {
    return struct {
        buf: [capacity]u8 = undefined,
        len: usize = 0,

        const Self = @This();

        fn append(self: *Self, bytes: []const u8) Error!void {
            if (bytes.len > self.available()) return full_error;
            @memcpy(self.buf[self.len..][0..bytes.len], bytes);
            self.len += bytes.len;
        }

        fn read(self: *Self, out: []u8) ?usize {
            if (self.len == 0) return null;
            const n = @min(out.len, self.len);
            if (n == 0) return 0;
            @memcpy(out[0..n], self.buf[0..n]);
            self.discard(n) catch unreachable;
            return n;
        }

        fn slice(self: *const Self) []const u8 {
            return self.buf[0..self.len];
        }

        fn discard(self: *Self, count: usize) Error!void {
            if (count > self.len) return error.WouldBlock;
            std.mem.copyForwards(u8, self.buf[0 .. self.len - count], self.buf[count..self.len]);
            self.len -= count;
        }

        fn available(self: *const Self) usize {
            return capacity - self.len;
        }

        fn clear(self: *Self) void {
            if (self.len > 0) @memset(self.buf[0..self.len], 0);
            self.len = 0;
        }
    };
}

fn testProvider() provider.CryptoProvider {
    const pure_zig = crypto.pure_zig;
    const State = struct {
        var entropy = pure_zig.DeterministicEntropy.init(0x353);
        var provider_state = pure_zig.Provider.init(entropy.entropy());
    };
    return State.provider_state.cryptoProvider();
}

fn secret(comptime fill: u8) [32]u8 {
    return [_]u8{fill} ** 32;
}

fn establish(client: *PureZigRecordStream, server: *PureZigRecordStream) !void {
    const client_hs = secret(0x11);
    const server_hs = secret(0x22);
    const client_app = secret(0x33);
    const server_app = secret(0x44);

    try client.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .write, .data = &client_hs } });
    try client.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .read, .data = &server_hs } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .read, .data = &client_hs } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .write, .data = &server_hs } });
    try client.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .write, .data = &client_app } });
    try client.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .read, .data = &server_app } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .read, .data = &client_app } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .application, .direction = .write, .data = &server_app } });
    try client.applyEvent(.handshake_complete);
    try server.applyEvent(.handshake_complete);
}

fn pumpCiphertext(from: *PureZigRecordStream, to: *PureZigRecordStream, max_chunk: usize) !usize {
    var moved: usize = 0;
    var buf: [128]u8 = undefined;
    while (from.queuedCiphertextLen() > 0) {
        const n = try from.drainCiphertext(buf[0..@min(max_chunk, buf.len)]);
        moved += n;
        try feedAllCiphertext(to, buf[0..n]);
    }
    return moved;
}

fn pumpHandshake(from: *PureZigRecordStream, to: *PureZigRecordStream, epoch: events.EncryptionEpoch, max_chunk: usize) !usize {
    var moved: usize = 0;
    var buf: [128]u8 = undefined;
    while (from.queuedCiphertextLen() > 0) {
        const n = try from.drainCiphertext(buf[0..@min(max_chunk, buf.len)]);
        moved += n;
        try feedAllHandshake(to, epoch, buf[0..n]);
    }
    return moved;
}

fn feedAllCiphertext(stream: *PureZigRecordStream, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const consumed = try stream.feedCiphertext(bytes[offset..]);
        if (consumed == 0) return error.WouldBlock;
        offset += consumed;
    }
}

fn feedAllHandshake(stream: *PureZigRecordStream, epoch: events.EncryptionEpoch, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const consumed = try stream.feedHandshakeCiphertext(epoch, bytes[offset..]);
        if (consumed == 0) return error.WouldBlock;
        offset += consumed;
    }
}

fn testSocketPair() ![2]std.posix.fd_t {
    var fds: [2]std.posix.fd_t = undefined;
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds);
        if (linux.errno(rc) != .SUCCESS) return error.SocketPairFailed;
    } else {
        if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    }
    errdefer closeFd(fds[0]);
    errdefer closeFd(fds[1]);
    try setNonBlocking(fds[0]);
    try setNonBlocking(fds[1]);
    return fds;
}

fn closeFd(fd: std.posix.fd_t) void {
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.close(fd);
    } else {
        _ = std.c.close(fd);
    }
}

fn setNonBlocking(fd: std.posix.fd_t) !void {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const status_flags = linux.fcntl(fd, linux.F.GETFL, 0);
        if (linux.errno(status_flags) != .SUCCESS) return error.FcntlFailed;
        const nonblock: usize = @intCast(@as(u32, @bitCast(linux.O{ .NONBLOCK = true })));
        const rc = linux.fcntl(fd, linux.F.SETFL, status_flags | nonblock);
        if (linux.errno(rc) != .SUCCESS) return error.FcntlFailed;
    } else {
        const status_flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
        if (status_flags < 0) return error.FcntlFailed;
        const nonblock = @as(c_int, @bitCast(std.posix.O{ .NONBLOCK = true }));
        if (std.c.fcntl(fd, std.c.F.SETFL, status_flags | nonblock) < 0) return error.FcntlFailed;
    }
}

fn flushStreamToFd(stream: *PureZigRecordStream, fd: std.posix.fd_t, max_chunk: usize) !usize {
    var moved: usize = 0;
    while (stream.queuedCiphertextLen() > 0) {
        const pending = stream.peekCiphertext();
        const n = @min(max_chunk, pending.len);
        const written = writeFd(fd, pending[0..n]) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
        if (written == 0) break;
        try stream.consumeCiphertext(written);
        moved += written;
    }
    return moved;
}

fn readFdIntoStream(fd: std.posix.fd_t, stream: *PureZigRecordStream, max_chunk: usize) !usize {
    var moved: usize = 0;
    var buf: [32]u8 = undefined;
    while (true) {
        const n = readFd(fd, buf[0..@min(max_chunk, buf.len)]) catch |err| switch (err) {
            error.WouldBlock => return moved,
            else => return err,
        };
        if (n == 0) {
            stream.markPeerClosed();
            return moved;
        }
        moved += n;
        try feedAllCiphertext(stream, buf[0..n]);
    }
}

fn readFd(fd: std.posix.fd_t, out: []u8) Error!usize {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.read(fd, out.ptr, out.len);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            else => error.SocketReadFailed,
        };
    }
    const rc = std.c.read(fd, out.ptr, out.len);
    if (rc < 0) {
        if (std.posix.errno(rc) == .AGAIN) return error.WouldBlock;
        return error.SocketReadFailed;
    }
    return @intCast(rc);
}

fn writeFd(fd: std.posix.fd_t, bytes: []const u8) Error!usize {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.write(fd, bytes.ptr, bytes.len);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            else => error.SocketWriteFailed,
        };
    }
    const rc = std.c.write(fd, bytes.ptr, bytes.len);
    if (rc < 0) {
        if (std.posix.errno(rc) == .AGAIN) return error.WouldBlock;
        return error.SocketWriteFailed;
    }
    return @intCast(rc);
}

const testing = std.testing;

test "pure Zig encrypted stream carries fragmented handshake and application data" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();

    try client.applyEvent(.{ .handshake_bytes = .{ .epoch = .initial, .data = "client hello" } });
    _ = try pumpHandshake(&client, &server, .initial, 3);
    var handshake_buf: [64]u8 = undefined;
    const client_hello_len = try server.readHandshake(&handshake_buf);
    try testing.expectEqualStrings("client hello", handshake_buf[0..client_hello_len]);

    try establish(&client, &server);
    const stream = client.stream();
    try testing.expectEqual(BackendKind.pure_zig_record, stream.backend());

    const written = try stream.write("hello from client");
    try testing.expectEqual(@as(usize, "hello from client".len), written);
    try testing.expect(stream.readiness().wants_write);

    const moved = try pumpCiphertext(&client, &server, 5);
    try testing.expect(moved > written);
    try testing.expect(!stream.readiness().wants_write);

    var plain: [64]u8 = undefined;
    const got = try server.stream().read(&plain);
    try testing.expectEqualStrings("hello from client", plain[0..got]);

    try server.applyEvent(.{ .handshake_bytes = .{ .epoch = .application, .data = "ticket" } });
    _ = try pumpCiphertext(&server, &client, 4);
    const ticket_len = try client.readHandshake(&plain);
    try testing.expectEqualStrings("ticket", plain[0..ticket_len]);

    var alert_buf: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const close_notify = try server.bridge.sealProtected(.application, .alert, &.{ 1, 0 }, &alert_buf);
    try server.outbound_ciphertext.append(close_notify);
    _ = try pumpCiphertext(&server, &client, 3);
    try testing.expectError(error.EndOfStream, client.stream().read(&plain));
}

test "encrypted stream backpressure is atomic around record protection state" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    client.outbound_ciphertext.len = PureZigRecordStream.max_ciphertext_queue - 1;
    const write_seq = client.bridge.write_application.?.sequence;
    try testing.expectError(error.WouldBlock, client.applyEvent(.{ .handshake_bytes = .{ .epoch = .application, .data = "retryable" } }));
    try testing.expectEqual(write_seq, client.bridge.write_application.?.sequence);
    client.outbound_ciphertext.len = 0;

    _ = try client.stream().write("retryable plaintext");
    var record_bytes: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const record_len = try client.drainCiphertext(&record_bytes);
    server.inbound_plaintext.len = PureZigRecordStream.max_plaintext_queue;
    const read_seq = server.bridge.read_application.?.sequence;
    try testing.expectError(error.WouldBlock, server.feedCiphertext(record_bytes[0..record_len]));
    try testing.expectEqual(read_seq, server.bridge.read_application.?.sequence);
    server.inbound_plaintext.len = 0;
}

test "encrypted stream coalesced record backpressure consumes only retry-safe records" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    var coalesced: [record_codec.max_ciphertext_record_len * 2]u8 = undefined;
    try testing.expectEqual(@as(usize, 3), try client.stream().write("one"));
    const first_len = try client.drainCiphertext(coalesced[0..record_codec.max_ciphertext_record_len]);
    try testing.expectEqual(@as(usize, 3), try client.stream().write("two"));
    const second_len = try client.drainCiphertext(coalesced[first_len..]);
    const total_len = first_len + second_len;

    server.inbound_plaintext.len = PureZigRecordStream.max_plaintext_queue - record_codec.max_plaintext_fragment_len;
    const read_seq = server.bridge.read_application.?.sequence;
    const consumed = try server.feedCiphertext(coalesced[0..total_len]);
    try testing.expectEqual(first_len, consumed);
    try testing.expectEqual(read_seq + 1, server.bridge.read_application.?.sequence);
    try testing.expectError(error.WouldBlock, server.feedCiphertext(coalesced[consumed..total_len]));
    try testing.expectEqual(read_seq + 1, server.bridge.read_application.?.sequence);
}

test "encrypted stream callers preserve partial feed suffixes across record boundaries" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    var coalesced: [record_codec.max_ciphertext_record_len * 2]u8 = undefined;
    try testing.expectEqual(@as(usize, 5), try client.stream().write("first"));
    const first_len = try client.drainCiphertext(coalesced[0..record_codec.max_ciphertext_record_len]);
    try testing.expectEqual(@as(usize, 6), try client.stream().write("second"));
    const second_len = try client.drainCiphertext(coalesced[first_len..]);

    const boundary_split = first_len + 2;
    try feedAllCiphertext(&server, coalesced[0..boundary_split]);
    try feedAllCiphertext(&server, coalesced[boundary_split .. first_len + second_len]);

    var plain: [16]u8 = undefined;
    const first_read = try server.stream().read(plain[0..5]);
    try testing.expectEqualStrings("first", plain[0..first_read]);
    const second_read = try server.stream().read(&plain);
    try testing.expectEqualStrings("second", plain[0..second_read]);
}

test "pure Zig encrypted stream exchanges application data over nonblocking socketpair carrier" {
    const fds = try testSocketPair();
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    const cp = testProvider();
    var client = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    try testing.expectEqual(@as(usize, "client to server".len), try client.stream().write("client to server"));
    try testing.expect((try flushStreamToFd(&client, fds[0], 4)) > "client to server".len);
    try testing.expect((try readFdIntoStream(fds[1], &server, 3)) > "client to server".len);

    var plain: [64]u8 = undefined;
    const server_read = try server.stream().read(&plain);
    try testing.expectEqualStrings("client to server", plain[0..server_read]);

    try testing.expectEqual(@as(usize, "server to client".len), try server.stream().write("server to client"));
    try testing.expect((try flushStreamToFd(&server, fds[1], 5)) > "server to client".len);
    try testing.expect((try readFdIntoStream(fds[0], &client, 2)) > "server to client".len);

    const client_read = try client.stream().read(&plain);
    try testing.expectEqualStrings("server to client", plain[0..client_read]);
    try testing.expectError(error.WouldBlock, client.stream().read(&plain));
}

test "encrypted stream drive retains ciphertext across partial carrier writes" {
    const MemoryCarrier = struct {
        written: ByteQueue(256, error.CiphertextBufferFull) = .{},
        max_write: usize = 3,

        fn carrier(self: *@This()) Carrier {
            return .{ .ptr = self, .readFn = read, .writeFn = write };
        }

        fn read(_: *anyopaque, _: []u8) Error!usize {
            return error.WouldBlock;
        }

        fn write(ptr: *anyopaque, bytes: []const u8) Error!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            const n = @min(bytes.len, self.max_write);
            if (n == 0) return error.WouldBlock;
            try self.written.append(bytes[0..n]);
            return n;
        }
    };

    const cp = testProvider();
    var carrier = MemoryCarrier{};
    var stream_state = PureZigRecordStream.initWithCarrier(cp, .tls_aes_128_gcm_sha256, carrier.carrier());
    defer stream_state.deinit();
    var peer = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer peer.deinit();
    try establish(&stream_state, &peer);

    _ = try stream_state.stream().write("partial write");
    const initial = stream_state.queuedCiphertextLen();
    const first = try stream_state.stream().drive();
    try testing.expect(first.made_progress);
    try testing.expectEqual(initial, carrier.written.len + stream_state.queuedCiphertextLen());
    try testing.expect(carrier.written.len >= carrier.max_write);

    if (stream_state.queuedCiphertextLen() == 0) return;

    try testing.expectEqual(initial - carrier.written.len, stream_state.queuedCiphertextLen());

    const after_first = carrier.written.len;
    const second = try stream_state.stream().drive();
    try testing.expect(second.made_progress);
    try testing.expect(carrier.written.len > after_first);
    try testing.expectEqual(initial - carrier.written.len, stream_state.queuedCiphertextLen());
}

test "encrypted stream drive routes pre-application carrier records by epoch" {
    const SourceCarrier = struct {
        bytes: []const u8,
        offset: usize = 0,

        fn carrier(self: *@This()) Carrier {
            return .{ .ptr = self, .readFn = read, .writeFn = write };
        }

        fn read(ptr: *anyopaque, out: []u8) Error!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (self.offset == self.bytes.len) return error.WouldBlock;
            const n = @min(out.len, self.bytes.len - self.offset);
            @memcpy(out[0..n], self.bytes[self.offset..][0..n]);
            self.offset += n;
            return n;
        }

        fn write(_: *anyopaque, _: []const u8) Error!usize {
            return error.WouldBlock;
        }
    };

    const cp = testProvider();
    var client = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();

    try client.applyEvent(.{ .handshake_bytes = .{ .epoch = .initial, .data = "client hello" } });
    var initial_record: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const initial_len = try client.drainCiphertext(&initial_record);
    var initial_source = SourceCarrier{ .bytes = initial_record[0..initial_len] };
    server.carrier = initial_source.carrier();
    while (initial_source.offset < initial_source.bytes.len) {
        const result = try server.stream().drive();
        try testing.expect(result.made_progress);
    }

    var handshake_buf: [64]u8 = undefined;
    const initial_read = try server.readHandshake(&handshake_buf);
    try testing.expectEqualStrings("client hello", handshake_buf[0..initial_read]);

    const client_hs = secret(0x11);
    try client.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .write, .data = &client_hs } });
    try server.applyEvent(.{ .traffic_secret = .{ .epoch = .handshake, .direction = .read, .data = &client_hs } });
    try client.applyEvent(.{ .handshake_bytes = .{ .epoch = .handshake, .data = "finished" } });
    var handshake_record: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const handshake_len = try client.drainCiphertext(&handshake_record);
    var handshake_source = SourceCarrier{ .bytes = handshake_record[0..handshake_len] };
    server.carrier = handshake_source.carrier();
    while (handshake_source.offset < handshake_source.bytes.len) {
        const result = try server.stream().drive();
        try testing.expect(result.made_progress);
    }

    const handshake_read = try server.readHandshake(&handshake_buf);
    try testing.expectEqualStrings("finished", handshake_buf[0..handshake_read]);
}

test "encrypted stream drive treats zero-length carrier read as EOF" {
    const EofCarrier = struct {
        fn carrier(self: *@This()) Carrier {
            return .{ .ptr = self, .readFn = read, .writeFn = write };
        }

        fn read(_: *anyopaque, _: []u8) Error!usize {
            return 0;
        }

        fn write(_: *anyopaque, _: []const u8) Error!usize {
            return error.WouldBlock;
        }
    };

    const cp = testProvider();
    var carrier = EofCarrier{};
    var stream_state = PureZigRecordStream.initWithCarrier(cp, .tls_aes_128_gcm_sha256, carrier.carrier());
    defer stream_state.deinit();

    const result = try stream_state.stream().drive();
    try testing.expect(result.made_progress);
    try testing.expect(result.readiness.peer_closed);

    var buf: [8]u8 = undefined;
    try testing.expectError(error.EndOfStream, stream_state.stream().read(&buf));
}

test "encrypted stream close sends close_notify before closing owned carrier" {
    const ClosingCarrier = struct {
        written: ByteQueue(record_codec.max_ciphertext_record_len, error.CiphertextBufferFull) = .{},
        max_write: usize = 3,
        closed: bool = false,

        fn carrier(self: *@This()) Carrier {
            return .{ .ptr = self, .readFn = read, .writeFn = write, .closeFn = close, .owns_handle = true };
        }

        fn read(_: *anyopaque, _: []u8) Error!usize {
            return error.WouldBlock;
        }

        fn write(ptr: *anyopaque, bytes: []const u8) Error!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            const n = @min(bytes.len, self.max_write);
            if (n == 0) return error.WouldBlock;
            try self.written.append(bytes[0..n]);
            return n;
        }

        fn close(ptr: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.closed = true;
        }
    };

    const cp = testProvider();
    var carrier = ClosingCarrier{};
    var stream_state = PureZigRecordStream.initWithCarrier(cp, .tls_aes_128_gcm_sha256, carrier.carrier());
    defer stream_state.deinit();
    var peer = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer peer.deinit();
    try establish(&stream_state, &peer);

    stream_state.stream().close();
    var iterations: usize = 0;
    while (stream_state.lifecycle != .closed and iterations < record_codec.max_ciphertext_record_len) : (iterations += 1) {
        _ = try stream_state.stream().drive();
    }
    try testing.expectEqual(Lifecycle.closed, stream_state.lifecycle);
    try testing.expect(carrier.closed);
    try testing.expect(carrier.written.len > 0);

    try feedAllCiphertext(&peer, carrier.written.slice());
    var buf: [8]u8 = undefined;
    try testing.expectError(error.EndOfStream, peer.stream().read(&buf));
}

test "encrypted stream close flushes queued app data before close_notify" {
    const ClosingCarrier = struct {
        written: ByteQueue(2 * record_codec.max_ciphertext_record_len, error.CiphertextBufferFull) = .{},
        max_write: usize,
        closed: bool = false,

        fn carrier(self: *@This()) Carrier {
            return .{ .ptr = self, .readFn = read, .writeFn = write, .closeFn = close, .owns_handle = true };
        }

        fn read(_: *anyopaque, _: []u8) Error!usize {
            return error.WouldBlock;
        }

        fn write(ptr: *anyopaque, bytes: []const u8) Error!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            const n = @min(bytes.len, self.max_write);
            if (n == 0) return error.WouldBlock;
            try self.written.append(bytes[0..n]);
            return n;
        }

        fn close(ptr: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.closed = true;
        }
    };

    const cp = testProvider();
    inline for (.{ record_codec.max_ciphertext_record_len, 3 }) |max_write| {
        var carrier = ClosingCarrier{ .max_write = max_write };
        var stream_state = PureZigRecordStream.initWithCarrier(cp, .tls_aes_128_gcm_sha256, carrier.carrier());
        defer stream_state.deinit();
        var peer = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
        defer peer.deinit();
        try establish(&stream_state, &peer);

        try testing.expectEqual(@as(usize, "queued app".len), try stream_state.stream().write("queued app"));
        stream_state.stream().close();
        var iterations: usize = 0;
        while (stream_state.lifecycle != .closed and iterations < record_codec.max_ciphertext_record_len) : (iterations += 1) {
            _ = try stream_state.stream().drive();
        }
        try testing.expectEqual(Lifecycle.closed, stream_state.lifecycle);
        try testing.expect(carrier.closed);

        try feedAllCiphertext(&peer, carrier.written.slice());
        var plain: [32]u8 = undefined;
        const got = try peer.stream().read(&plain);
        try testing.expectEqualStrings("queued app", plain[0..got]);
        try testing.expectError(error.EndOfStream, peer.stream().read(&plain));
    }
}

test "encrypted stream manual close drains one close_notify and becomes closed" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    client.stream().close();
    const queued = try client.stream().drive();
    try testing.expect(queued.made_progress);
    try testing.expect(client.queuedCiphertextLen() > 0);

    var close_notify: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const n = try client.drainCiphertext(&close_notify);
    try feedAllCiphertext(&server, close_notify[0..n]);
    _ = try client.stream().drive();
    try testing.expectEqual(Lifecycle.closed, client.lifecycle);
    try testing.expectEqual(@as(usize, 0), client.queuedCiphertextLen());

    var buf: [8]u8 = undefined;
    try testing.expectError(error.EndOfStream, server.stream().read(&buf));
}

test "encrypted stream fatal parser errors latch and close owned carrier" {
    const ClosingCarrier = struct {
        closed: bool = false,

        fn carrier(self: *@This()) Carrier {
            return .{ .ptr = self, .readFn = read, .writeFn = write, .closeFn = close, .owns_handle = true };
        }

        fn read(_: *anyopaque, _: []u8) Error!usize {
            return error.WouldBlock;
        }

        fn write(_: *anyopaque, _: []const u8) Error!usize {
            return error.WouldBlock;
        }

        fn close(ptr: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.closed = true;
        }
    };

    const cp = testProvider();
    var carrier = ClosingCarrier{};
    var stream_state = PureZigRecordStream.initWithCarrier(cp, .tls_aes_128_gcm_sha256, carrier.carrier());
    defer stream_state.deinit();

    try testing.expectError(error.InvalidRecordType, stream_state.feedCiphertext(&.{ 0xff, 0x03, 0x03, 0x00, 0x00 }));
    try testing.expectEqual(Lifecycle.failed, stream_state.lifecycle);
    try testing.expect(carrier.closed);
    try testing.expectError(error.InvalidRecordType, stream_state.stream().write("x"));
    var buf: [8]u8 = undefined;
    try testing.expectError(error.InvalidRecordType, stream_state.stream().read(&buf));
    const readiness = stream_state.stream().readiness();
    try testing.expect(!readiness.wants_read);
    try testing.expect(!readiness.wants_write);
}

test "encrypted stream fatal failure clears queued handshake and ciphertext helpers" {
    const cp = testProvider();
    var client = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();

    try client.applyEvent(.{ .handshake_bytes = .{ .epoch = .initial, .data = "queued hello" } });
    var initial_record: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const initial_len = try client.drainCiphertext(&initial_record);
    try feedAllHandshake(&server, .initial, initial_record[0..initial_len]);
    try server.applyEvent(.{ .handshake_bytes = .{ .epoch = .initial, .data = "queued response" } });
    try testing.expect(server.queuedCiphertextLen() > 0);

    try testing.expectEqual(error.InvalidRecordType, server.fail(error.InvalidRecordType));
    try testing.expectEqual(Lifecycle.failed, server.lifecycle);

    var buf: [64]u8 = undefined;
    try testing.expectError(error.InvalidRecordType, server.readHandshake(&buf));
    try testing.expectError(error.InvalidRecordType, server.drainCiphertext(&buf));
    try testing.expectEqual(@as(usize, 0), server.peekCiphertext().len);
}

test "encrypted stream authentication failures latch and close owned carrier" {
    const ClosingCarrier = struct {
        closed: bool = false,

        fn carrier(self: *@This()) Carrier {
            return .{ .ptr = self, .readFn = read, .writeFn = write, .closeFn = close, .owns_handle = true };
        }

        fn read(_: *anyopaque, _: []u8) Error!usize {
            return error.WouldBlock;
        }

        fn write(_: *anyopaque, _: []const u8) Error!usize {
            return error.WouldBlock;
        }

        fn close(ptr: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.closed = true;
        }
    };

    const cp = testProvider();
    var client = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer client.deinit();
    var server = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer server.deinit();
    try establish(&client, &server);

    try testing.expectEqual(@as(usize, 6), try client.stream().write("cipher"));
    var record: [record_codec.max_ciphertext_record_len]u8 = undefined;
    const record_len = try client.drainCiphertext(&record);
    record[record_len - 1] ^= 0xff;

    var carrier = ClosingCarrier{};
    server.carrier = carrier.carrier();
    try testing.expectError(error.AuthenticationFailed, server.feedCiphertext(record[0..record_len]));
    try testing.expectEqual(Lifecycle.failed, server.lifecycle);
    try testing.expect(carrier.closed);
    try testing.expectError(error.AuthenticationFailed, server.stream().drive());
}

test "encrypted stream reports would-block and stable readiness without busy-loop progress" {
    const cp = testProvider();
    var stream_state = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer stream_state.deinit();
    const stream = stream_state.stream();

    var buf: [8]u8 = undefined;
    try testing.expectError(error.WouldBlock, stream.read(&buf));
    try testing.expectError(error.WouldBlock, stream.write("x"));

    const before = stream.readiness();
    try testing.expect(before.wants_read);
    try testing.expect(!before.wants_write);
    try testing.expect(!before.can_read_plaintext);
    try testing.expect(!before.can_write_plaintext);

    stream_state.inbound_handshake.len = 1;
    try testing.expect(!stream.readiness().wants_read);
    const blocked = try stream.drive();
    try testing.expect(!blocked.made_progress);
    try testing.expect(!blocked.readiness.wants_read);
    stream_state.inbound_handshake.len = 0;

    const drive = try stream.drive();
    try testing.expect(!drive.made_progress);
    try testing.expectEqual(before, drive.readiness);
}

test "encrypted stream interface accepts OpenSSL-like and pure-Zig backends" {
    const FakeOpenSsl = struct {
        inbound: ByteQueue(64, error.PlaintextBufferFull) = .{},
        outbound: ByteQueue(64, error.CiphertextBufferFull) = .{},
        closed: bool = false,

        fn stream(self: *@This()) EncryptedStream {
            return .{ .ptr = self, .vtable = &vtable };
        }

        fn backend(_: *anyopaque) BackendKind {
            return .openssl;
        }

        fn read(ptr: *anyopaque, out: []u8) Error!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return self.inbound.read(out) orelse error.WouldBlock;
        }

        fn write(ptr: *anyopaque, bytes: []const u8) Error!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            const n = @min(bytes.len, self.outbound.available());
            if (n == 0) return error.WouldBlock;
            try self.outbound.append(bytes[0..n]);
            return n;
        }

        fn close(ptr: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.closed = true;
        }

        fn readiness(ptr: *anyopaque) Readiness {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return .{
                .wants_read = !self.closed,
                .wants_write = self.outbound.len > 0,
                .can_read_plaintext = self.inbound.len > 0,
                .can_write_plaintext = !self.closed and self.outbound.available() > 0,
                .peer_closed = false,
            };
        }

        fn drive(ptr: *anyopaque) Error!DriveResult {
            return .{ .made_progress = false, .readiness = readiness(ptr) };
        }

        const vtable = EncryptedStream.VTable{
            .backendFn = backend,
            .readFn = read,
            .writeFn = write,
            .closeFn = close,
            .readinessFn = readiness,
            .driveFn = drive,
        };
    };

    var fake = FakeOpenSsl{};
    var streams = [_]EncryptedStream{fake.stream()};
    try testing.expectEqual(BackendKind.openssl, streams[0].backend());
    try testing.expectEqual(@as(usize, 4), try streams[0].write("ping"));
    streams[0].close();
    try testing.expect(!streams[0].readiness().can_write_plaintext);

    const cp = testProvider();
    var native = PureZigRecordStream.init(cp, .tls_aes_128_gcm_sha256);
    defer native.deinit();
    streams[0] = native.stream();
    try testing.expectEqual(BackendKind.pure_zig_record, streams[0].backend());
}
