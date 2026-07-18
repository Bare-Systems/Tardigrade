//! Shared ASCII DNS host-name validation for TLS SNI.

pub const max_name_len = 253;

pub const Error = error{InvalidDnsName};

pub fn validateHostName(name: []const u8) Error!void {
    if (name.len == 0 or name.len > max_name_len) return error.InvalidDnsName;
    if (name[0] == '.' or name[name.len - 1] == '.') return error.InvalidDnsName;
    var label_len: usize = 0;
    var label_start: usize = 0;
    for (name, 0..) |ch, i| {
        if (ch == '.') {
            try validateLabel(name[label_start..i], label_len);
            label_len = 0;
            label_start = i + 1;
            continue;
        }
        if (!isDnsLabelByte(ch)) return error.InvalidDnsName;
        label_len += 1;
    }
    try validateLabel(name[label_start..], label_len);
}

pub fn validateWildcardSuffix(name: []const u8) Error!void {
    try validateHostName(name);
    if (labelCount(name) < 2) return error.InvalidDnsName;
}

fn validateLabel(label: []const u8, label_len: usize) Error!void {
    if (label_len == 0 or label_len > 63) return error.InvalidDnsName;
    if (label[0] == '-' or label[label.len - 1] == '-') return error.InvalidDnsName;
}

fn labelCount(name: []const u8) usize {
    var count: usize = 1;
    for (name) |ch| {
        if (ch == '.') count += 1;
    }
    return count;
}

pub fn isDnsLabelByte(ch: u8) bool {
    return (ch >= 'A' and ch <= 'Z') or
        (ch >= 'a' and ch <= 'z') or
        (ch >= '0' and ch <= '9') or
        ch == '-';
}
