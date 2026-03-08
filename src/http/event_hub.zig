const std = @import("std");

pub const Event = struct {
    id: u64,
    topic: []u8,
    payload: []u8,
    created_ms: u64,
};

pub const Topic = struct {
    next_id: u64 = 1,
    events: std.ArrayList(Event),

    fn init(allocator: std.mem.Allocator) Topic {
        return .{ .events = std.ArrayList(Event).init(allocator) };
    }

    fn deinit(self: *Topic, allocator: std.mem.Allocator) void {
        for (self.events.items) |e| {
            allocator.free(e.topic);
            allocator.free(e.payload);
        }
        self.events.deinit();
    }
};

pub const EventHub = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    topics: std.StringHashMap(Topic),
    max_events_per_topic: usize,

    pub fn init(allocator: std.mem.Allocator, max_events_per_topic: usize) EventHub {
        return .{
            .allocator = allocator,
            .topics = std.StringHashMap(Topic).init(allocator),
            .max_events_per_topic = max_events_per_topic,
        };
    }

    pub fn deinit(self: *EventHub) void {
        var it = self.topics.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            var topic = entry.value_ptr.*;
            topic.deinit(self.allocator);
        }
        self.topics.deinit();
    }

    pub fn publish(self: *EventHub, topic_name: []const u8, payload: []const u8, now_ms: u64) !u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const gop = try self.getOrCreateTopicLocked(topic_name);
        var topic = gop.value_ptr;
        const id = topic.next_id;
        topic.next_id += 1;
        try topic.events.append(.{
            .id = id,
            .topic = try self.allocator.dupe(u8, topic_name),
            .payload = try self.allocator.dupe(u8, payload),
            .created_ms = now_ms,
        });
        while (topic.events.items.len > self.max_events_per_topic) {
            const ev = topic.events.orderedRemove(0);
            self.allocator.free(ev.topic);
            self.allocator.free(ev.payload);
        }
        return id;
    }

    pub fn snapshotSince(self: *EventHub, allocator: std.mem.Allocator, topic_name: []const u8, after_id: u64) ![]Event {
        self.mutex.lock();
        defer self.mutex.unlock();
        const topic = self.topics.getPtr(topic_name) orelse return allocator.alloc(Event, 0);
        var out = std.ArrayList(Event).init(allocator);
        errdefer {
            for (out.items) |e| {
                allocator.free(e.topic);
                allocator.free(e.payload);
            }
            out.deinit();
        }
        for (topic.events.items) |ev| {
            if (ev.id <= after_id) continue;
            try out.append(.{
                .id = ev.id,
                .topic = try allocator.dupe(u8, ev.topic),
                .payload = try allocator.dupe(u8, ev.payload),
                .created_ms = ev.created_ms,
            });
        }
        return out.toOwnedSlice();
    }

    pub fn oldestId(self: *EventHub, topic_name: []const u8) ?u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        const topic = self.topics.getPtr(topic_name) orelse return null;
        if (topic.events.items.len == 0) return null;
        return topic.events.items[0].id;
    }

    fn getOrCreateTopicLocked(self: *EventHub, topic_name: []const u8) !std.StringHashMap(Topic).GetOrPutResult {
        const gop = try self.topics.getOrPut(topic_name);
        if (!gop.found_existing) {
            gop.key_ptr.* = try self.allocator.dupe(u8, topic_name);
            gop.value_ptr.* = Topic.init(self.allocator);
        }
        return gop;
    }
};

pub fn deinitSnapshot(allocator: std.mem.Allocator, events: []Event) void {
    for (events) |e| {
        allocator.free(e.topic);
        allocator.free(e.payload);
    }
    allocator.free(events);
}

test "event hub publish and snapshot" {
    const allocator = std.testing.allocator;
    var hub = EventHub.init(allocator, 3);
    defer hub.deinit();
    _ = try hub.publish("alerts", "a", 1);
    _ = try hub.publish("alerts", "b", 2);
    _ = try hub.publish("alerts", "c", 3);
    const events = try hub.snapshotSince(allocator, "alerts", 1);
    defer deinitSnapshot(allocator, events);
    try std.testing.expectEqual(@as(usize, 2), events.len);
    try std.testing.expectEqual(@as(u64, 2), events[0].id);
}
