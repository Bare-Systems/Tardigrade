const std = @import("std");

/// HTTP Status Codes as defined in RFC 7231 and related RFCs
pub const Status = enum(u16) {
    // 1xx Informational
    @"continue" = 100,
    switching_protocols = 101,
    processing = 102,
    early_hints = 103,

    // 2xx Success
    ok = 200,
    created = 201,
    accepted = 202,
    non_authoritative_information = 203,
    no_content = 204,
    reset_content = 205,
    partial_content = 206,
    multi_status = 207,
    already_reported = 208,
    im_used = 226,

    // 3xx Redirection
    multiple_choices = 300,
    moved_permanently = 301,
    found = 302,
    see_other = 303,
    not_modified = 304,
    use_proxy = 305,
    temporary_redirect = 307,
    permanent_redirect = 308,

    // 4xx Client Errors
    bad_request = 400,
    unauthorized = 401,
    payment_required = 402,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    not_acceptable = 406,
    proxy_authentication_required = 407,
    request_timeout = 408,
    conflict = 409,
    gone = 410,
    length_required = 411,
    precondition_failed = 412,
    payload_too_large = 413,
    uri_too_long = 414,
    unsupported_media_type = 415,
    range_not_satisfiable = 416,
    expectation_failed = 417,
    im_a_teapot = 418,
    misdirected_request = 421,
    unprocessable_entity = 422,
    locked = 423,
    failed_dependency = 424,
    too_early = 425,
    upgrade_required = 426,
    precondition_required = 428,
    too_many_requests = 429,
    request_header_fields_too_large = 431,
    unavailable_for_legal_reasons = 451,

    // 5xx Server Errors
    internal_server_error = 500,
    not_implemented = 501,
    bad_gateway = 502,
    service_unavailable = 503,
    gateway_timeout = 504,
    http_version_not_supported = 505,
    variant_also_negotiates = 506,
    insufficient_storage = 507,
    loop_detected = 508,
    not_extended = 510,
    network_authentication_required = 511,

    /// Get the numeric status code
    pub fn code(self: Status) u16 {
        return @intFromEnum(self);
    }

    /// Get the reason phrase for this status code
    pub fn phrase(self: Status) []const u8 {
        return switch (self) {
            // 1xx
            .@"continue" => "Continue",
            .switching_protocols => "Switching Protocols",
            .processing => "Processing",
            .early_hints => "Early Hints",

            // 2xx
            .ok => "OK",
            .created => "Created",
            .accepted => "Accepted",
            .non_authoritative_information => "Non-Authoritative Information",
            .no_content => "No Content",
            .reset_content => "Reset Content",
            .partial_content => "Partial Content",
            .multi_status => "Multi-Status",
            .already_reported => "Already Reported",
            .im_used => "IM Used",

            // 3xx
            .multiple_choices => "Multiple Choices",
            .moved_permanently => "Moved Permanently",
            .found => "Found",
            .see_other => "See Other",
            .not_modified => "Not Modified",
            .use_proxy => "Use Proxy",
            .temporary_redirect => "Temporary Redirect",
            .permanent_redirect => "Permanent Redirect",

            // 4xx
            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .payment_required => "Payment Required",
            .forbidden => "Forbidden",
            .not_found => "Not Found",
            .method_not_allowed => "Method Not Allowed",
            .not_acceptable => "Not Acceptable",
            .proxy_authentication_required => "Proxy Authentication Required",
            .request_timeout => "Request Timeout",
            .conflict => "Conflict",
            .gone => "Gone",
            .length_required => "Length Required",
            .precondition_failed => "Precondition Failed",
            .payload_too_large => "Payload Too Large",
            .uri_too_long => "URI Too Long",
            .unsupported_media_type => "Unsupported Media Type",
            .range_not_satisfiable => "Range Not Satisfiable",
            .expectation_failed => "Expectation Failed",
            .im_a_teapot => "I'm a teapot",
            .misdirected_request => "Misdirected Request",
            .unprocessable_entity => "Unprocessable Entity",
            .locked => "Locked",
            .failed_dependency => "Failed Dependency",
            .too_early => "Too Early",
            .upgrade_required => "Upgrade Required",
            .precondition_required => "Precondition Required",
            .too_many_requests => "Too Many Requests",
            .request_header_fields_too_large => "Request Header Fields Too Large",
            .unavailable_for_legal_reasons => "Unavailable For Legal Reasons",

            // 5xx
            .internal_server_error => "Internal Server Error",
            .not_implemented => "Not Implemented",
            .bad_gateway => "Bad Gateway",
            .service_unavailable => "Service Unavailable",
            .gateway_timeout => "Gateway Timeout",
            .http_version_not_supported => "HTTP Version Not Supported",
            .variant_also_negotiates => "Variant Also Negotiates",
            .insufficient_storage => "Insufficient Storage",
            .loop_detected => "Loop Detected",
            .not_extended => "Not Extended",
            .network_authentication_required => "Network Authentication Required",
        };
    }

    /// Check if this is an informational status (1xx)
    pub fn isInformational(self: Status) bool {
        const c = self.code();
        return c >= 100 and c < 200;
    }

    /// Check if this is a success status (2xx)
    pub fn isSuccess(self: Status) bool {
        const c = self.code();
        return c >= 200 and c < 300;
    }

    /// Check if this is a redirection status (3xx)
    pub fn isRedirection(self: Status) bool {
        const c = self.code();
        return c >= 300 and c < 400;
    }

    /// Check if this is a client error status (4xx)
    pub fn isClientError(self: Status) bool {
        const c = self.code();
        return c >= 400 and c < 500;
    }

    /// Check if this is a server error status (5xx)
    pub fn isServerError(self: Status) bool {
        const c = self.code();
        return c >= 500 and c < 600;
    }

    /// Check if this is any error status (4xx or 5xx)
    pub fn isError(self: Status) bool {
        return self.isClientError() or self.isServerError();
    }

    /// Create a Status from a numeric code
    pub fn fromCode(code_num: u16) ?Status {
        return std.meta.intToEnum(Status, code_num) catch null;
    }
};

// Tests
test "status code values" {
    const testing = std.testing;

    try testing.expectEqual(@as(u16, 200), Status.ok.code());
    try testing.expectEqual(@as(u16, 404), Status.not_found.code());
    try testing.expectEqual(@as(u16, 500), Status.internal_server_error.code());
    try testing.expectEqual(@as(u16, 301), Status.moved_permanently.code());
}

test "status reason phrases" {
    const testing = std.testing;

    try testing.expectEqualStrings("OK", Status.ok.phrase());
    try testing.expectEqualStrings("Not Found", Status.not_found.phrase());
    try testing.expectEqualStrings("Internal Server Error", Status.internal_server_error.phrase());
    try testing.expectEqualStrings("Bad Request", Status.bad_request.phrase());
    try testing.expectEqualStrings("Moved Permanently", Status.moved_permanently.phrase());
}

test "status category checks" {
    const testing = std.testing;

    // Informational
    try testing.expect(Status.@"continue".isInformational());
    try testing.expect(!Status.ok.isInformational());

    // Success
    try testing.expect(Status.ok.isSuccess());
    try testing.expect(Status.created.isSuccess());
    try testing.expect(!Status.not_found.isSuccess());

    // Redirection
    try testing.expect(Status.moved_permanently.isRedirection());
    try testing.expect(Status.found.isRedirection());
    try testing.expect(!Status.ok.isRedirection());

    // Client error
    try testing.expect(Status.bad_request.isClientError());
    try testing.expect(Status.not_found.isClientError());
    try testing.expect(!Status.internal_server_error.isClientError());

    // Server error
    try testing.expect(Status.internal_server_error.isServerError());
    try testing.expect(Status.bad_gateway.isServerError());
    try testing.expect(!Status.not_found.isServerError());

    // Any error
    try testing.expect(Status.not_found.isError());
    try testing.expect(Status.internal_server_error.isError());
    try testing.expect(!Status.ok.isError());
}

test "status from code" {
    const testing = std.testing;

    try testing.expectEqual(Status.ok, Status.fromCode(200).?);
    try testing.expectEqual(Status.not_found, Status.fromCode(404).?);
    try testing.expect(Status.fromCode(999) == null);
}
