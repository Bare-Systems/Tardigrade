//! UTCTime and GeneralizedTime parsing for X.509 (#339).

const std = @import("std");

pub const Error = error{
    MalformedTime,
};

pub const UtcTime = struct {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: ?u8,
};

pub const GeneralizedTime = struct {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: ?u8,
};

pub fn parseUtcTime(content: []const u8) Error!UtcTime {
    if (content.len != 11 and content.len != 13) return error.MalformedTime;
    if (content[content.len - 1] != 'Z') return error.MalformedTime;

    const yy = try parseTwoDigits(content[0..2]);
    const year: u16 = if (yy >= 50) @as(u16, 1900) + yy else @as(u16, 2000) + yy;
    const month = try parseTwoDigits(content[2..4]);
    const day = try parseTwoDigits(content[4..6]);
    const hour = try parseTwoDigits(content[6..8]);
    const minute = try parseTwoDigits(content[8..10]);

    const second: ?u8 = if (content.len == 13) try parseTwoDigits(content[10..12]) else null;

    try validateDateTime(year, month, day, hour, minute, second);
    return .{ .year = year, .month = month, .day = day, .hour = hour, .minute = minute, .second = second };
}

pub fn parseGeneralizedTime(content: []const u8) Error!GeneralizedTime {
    if (content.len != 13 and content.len != 15) return error.MalformedTime;
    if (content[content.len - 1] != 'Z') return error.MalformedTime;
    for (content[0 .. content.len - 1]) |c| {
        if (c < '0' or c > '9') return error.MalformedTime;
    }

    const year = try parseFourDigits(content[0..4]);
    const month = try parseTwoDigits(content[4..6]);
    const day = try parseTwoDigits(content[6..8]);
    const hour = try parseTwoDigits(content[8..10]);
    const minute = try parseTwoDigits(content[10..12]);

    const second: ?u8 = if (content.len == 15) try parseTwoDigits(content[12..14]) else null;

    try validateDateTime(year, month, day, hour, minute, second);
    return .{ .year = year, .month = month, .day = day, .hour = hour, .minute = minute, .second = second };
}

fn parseTwoDigits(digits: []const u8) Error!u8 {
    if (digits.len != 2) return error.MalformedTime;
    if (digits[0] < '0' or digits[0] > '9') return error.MalformedTime;
    if (digits[1] < '0' or digits[1] > '9') return error.MalformedTime;
    return @intCast((digits[0] - '0') * 10 + (digits[1] - '0'));
}

fn parseFourDigits(digits: []const u8) Error!u16 {
    if (digits.len != 4) return error.MalformedTime;
    var value: u16 = 0;
    for (digits) |c| {
        if (c < '0' or c > '9') return error.MalformedTime;
        value = value * 10 + (c - '0');
    }
    return value;
}

fn validateDateTime(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: ?u8) Error!void {
    if (month < 1 or month > 12) return error.MalformedTime;
    if (day < 1 or day > daysInMonth(year, month)) return error.MalformedTime;
    if (hour > 23) return error.MalformedTime;
    if (minute > 59) return error.MalformedTime;
    if (second) |s| {
        if (s > 59) return error.MalformedTime;
    }
}

fn daysInMonth(year: u16, month: u8) u8 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeapYear(year)) 29 else 28,
        else => 0,
    };
}

fn isLeapYear(year: u16) bool {
    if (@rem(year, 4) != 0) return false;
    if (@rem(year, 100) != 0) return true;
    return @rem(year, 400) == 0;
}

const testing = std.testing;

test "parse canonical UTCTime and GeneralizedTime" {
    const utc = try parseUtcTime("240101000000Z");
    try testing.expectEqual(@as(u16, 2024), utc.year);
    try testing.expectEqual(@as(u8, 1), utc.month);
    try testing.expectEqual(@as(u8, 1), utc.day);

    const gen = try parseGeneralizedTime("20240101000000Z");
    try testing.expectEqual(@as(u16, 2024), gen.year);
}

test "reject invalid calendar values" {
    try testing.expectError(error.MalformedTime, parseUtcTime("240231000000Z"));
    try testing.expectError(error.MalformedTime, parseUtcTime("240101250000Z"));
    try testing.expectError(error.MalformedTime, parseGeneralizedTime("20240230000000Z"));
}

test {
    testing.refAllDecls(@This());
}
