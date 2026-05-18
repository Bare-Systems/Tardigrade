done = function(summary, latency, requests)
  local duration_s = summary.duration / 1000000
  local rps = 0.0
  local throughput_mbps = 0.0
  local error_total = 0

  if duration_s > 0 then
    rps = summary.requests / duration_s
    throughput_mbps = (summary.bytes / duration_s) / (1024 * 1024)
  end

  if summary.errors then
    error_total = (summary.errors.connect or 0)
      + (summary.errors.read or 0)
      + (summary.errors.write or 0)
      + (summary.errors.status or 0)
      + (summary.errors.timeout or 0)
  end

  io.write(string.format(
    "\nWRK_SUMMARY {\"rps\":%.2f,\"p50_ms\":%.3f,\"p95_ms\":%.3f,\"p99_ms\":%.3f,\"p999_ms\":%.3f,\"errors\":%d,\"throughput_mbps\":%.2f}\n",
    rps,
    latency:percentile(50.0) / 1000,
    latency:percentile(95.0) / 1000,
    latency:percentile(99.0) / 1000,
    latency:percentile(99.9) / 1000,
    error_total,
    throughput_mbps
  ))
end
