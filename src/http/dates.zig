const std = @import("std");

pub fn monthNameToNum(name: []const u8) ?u8 {
    if (std.mem.eql(u8, name, "Jan")) return 1;
    if (std.mem.eql(u8, name, "Feb")) return 2;
    if (std.mem.eql(u8, name, "Mar")) return 3;
    if (std.mem.eql(u8, name, "Apr")) return 4;
    if (std.mem.eql(u8, name, "May")) return 5;
    if (std.mem.eql(u8, name, "Jun")) return 6;
    if (std.mem.eql(u8, name, "Jul")) return 7;
    if (std.mem.eql(u8, name, "Aug")) return 8;
    if (std.mem.eql(u8, name, "Sep")) return 9;
    if (std.mem.eql(u8, name, "Oct")) return 10;
    if (std.mem.eql(u8, name, "Nov")) return 11;
    if (std.mem.eql(u8, name, "Dec")) return 12;
    return null;
}

fn parseTime(tok: []const u8) ?struct { hour: u8, min: u8, sec: u8 } {
    const first = std.mem.indexOf(u8, tok, ":") orelse return null;
    const second = std.mem.indexOfPos(u8, tok, first + 1, ":") orelse return null;
    const h = tok[0..first];
    const m = tok[first + 1 .. second];
    const s = tok[second + 1 ..];
    const hour = std.fmt.parseInt(u8, h, 10) catch return null;
    const min = std.fmt.parseInt(u8, m, 10) catch return null;
    const sec = std.fmt.parseInt(u8, s, 10) catch return null;
    return .{ .hour = hour, .min = min, .sec = sec };
}

fn toEpochSeconds(year: i32, month: i32, day: i32, hour: i32, min: i32, sec: i32) i64 {
    // Convert Gregorian date to Julian Day Number then to Unix epoch seconds
    const a = @divTrunc(14 - month, 12);
    const y = year + 4800 - a;
    const m = month + 12 * a - 3;
    const jdn = day + @divTrunc(153 * m + 2, 5) + 365 * y + @divTrunc(y, 4) - @divTrunc(y, 100) + @divTrunc(y, 400) - 32045;
    const days_since_epoch_i64: i64 = @as(i64, jdn - 2440588);
    const total_i64 = days_since_epoch_i64 * 86400 + @as(i64, hour) * 3600 + @as(i64, min) * 60 + @as(i64, sec);
    return total_i64;
}

pub fn parseHttpDate(s: []const u8) ?i64 {
    const trimmed = std.mem.trim(u8, s, " \t");

    // Try RFC1123: "Day, DD Mon YYYY HH:MM:SS GMT"
    if (std.mem.indexOf(u8, trimmed, ",") != null) {
        // Split on comma
        const comma = std.mem.indexOf(u8, trimmed, ",") orelse return null;
        const after = std.mem.trim(u8, trimmed[comma + 1 ..], " \t");

        // If contains '-', treat as RFC850: DD-Mon-YY
        if (std.mem.indexOf(u8, after, "-") != null) {
            // RFC850: "Sunday, 06-Nov-94 08:49:37 GMT"
            const first_sp = std.mem.indexOf(u8, after, " ") orelse return null;
            const date_tok = after[0..first_sp];
            const rest = std.mem.trim(u8, after[first_sp + 1 ..], " \t");
            const second_sp = std.mem.indexOf(u8, rest, " ") orelse return null;
            const time_tok = rest[0..second_sp];
            const tz = std.mem.trim(u8, rest[second_sp + 1 ..], " \t");
            if (!std.mem.eql(u8, tz, "GMT")) return null;

            const dash1 = std.mem.indexOf(u8, date_tok, "-") orelse return null;
            const dash2 = std.mem.indexOfPos(u8, date_tok, dash1 + 1, "-") orelse return null;
            const dd_s = date_tok[0..dash1];
            const mon_s = date_tok[dash1 + 1 .. dash2];
            const yy_s = date_tok[dash2 + 1 ..];
            const day = std.fmt.parseInt(i32, dd_s, 10) catch return null;
            const month = monthNameToNum(mon_s) orelse return null;
            const yy = std.fmt.parseInt(i32, yy_s, 10) catch return null;
            const year: i32 = if (yy >= 70) 1900 + yy else 2000 + yy;
            const tm = parseTime(time_tok) orelse return null;
            return toEpochSeconds(year, @as(i32, month), day, @as(i32, tm.hour), @as(i32, tm.min), @as(i32, tm.sec));
        } else {
            // RFC1123: "06 Nov 1994 08:49:37 GMT" (after the comma)
            // split tokens by spaces: dd mon year time tz
            const sp1 = std.mem.indexOf(u8, after, " ") orelse return null;
            const dd = after[0..sp1];
            const rem1 = std.mem.trim(u8, after[sp1 + 1 ..], " \t");
            const sp2 = std.mem.indexOf(u8, rem1, " ") orelse return null;
            const mon = rem1[0..sp2];
            const rem2 = std.mem.trim(u8, rem1[sp2 + 1 ..], " \t");
            const sp3 = std.mem.indexOf(u8, rem2, " ") orelse return null;
            const year_s = rem2[0..sp3];
            const rem3 = std.mem.trim(u8, rem2[sp3 + 1 ..], " \t");
            const sp4 = std.mem.indexOf(u8, rem3, " ") orelse return null;
            const time_tok = rem3[0..sp4];
            const tz = std.mem.trim(u8, rem3[sp4 + 1 ..], " \t");
            if (!std.mem.eql(u8, tz, "GMT")) return null;
            const day = std.fmt.parseInt(i32, dd, 10) catch return null;
            const month = monthNameToNum(mon) orelse return null;
            const year = std.fmt.parseInt(i32, year_s, 10) catch return null;
            const tm = parseTime(time_tok) orelse return null;
            return toEpochSeconds(year, @as(i32, month), day, @as(i32, tm.hour), @as(i32, tm.min), @as(i32, tm.sec));
        }
    }

    // Try asctime: "Sun Nov  6 08:49:37 1994"
    const sp1 = std.mem.indexOf(u8, trimmed, " ") orelse return null;
    const rem0 = std.mem.trim(u8, trimmed[sp1 + 1 ..], " \t");
    const sp2 = std.mem.indexOf(u8, rem0, " ") orelse return null;
    const mon = rem0[0..sp2];
    const rem1 = std.mem.trim(u8, rem0[sp2 + 1 ..], " \t");
    const sp3 = std.mem.indexOf(u8, rem1, " ") orelse return null;
    const day_s = rem1[0..sp3];
    const rem2 = std.mem.trim(u8, rem1[sp3 + 1 ..], " \t");
    const sp4 = std.mem.indexOf(u8, rem2, " ") orelse return null;
    const time_tok2 = rem2[0..sp4];
    const year_s2 = std.mem.trim(u8, rem2[sp4 + 1 ..], " \t");
    const day = std.fmt.parseInt(i32, day_s, 10) catch return null;
    const month = monthNameToNum(mon) orelse return null;
    const year = std.fmt.parseInt(i32, year_s2, 10) catch return null;
    const tm2 = parseTime(time_tok2) orelse return null;
    return toEpochSeconds(year, @as(i32, month), day, @as(i32, tm2.hour), @as(i32, tm2.min), @as(i32, tm2.sec));
}
