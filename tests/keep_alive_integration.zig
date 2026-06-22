const std = @import("std");

// Keepalive worker-starvation tests live in tests/integration.zig where they
// can use the full TardigradeProcess harness. See:
//   "idle keepalive connections parked off the worker pool do not starve active requests (#204)"
//   "reload does not disrupt a parked keepalive connection (#170)"
test "keepalive integration tests are in integration.zig" {}
