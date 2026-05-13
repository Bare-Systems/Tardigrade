# Proxy Payload Scaling Report

Date: 2026-05-13

Canonical target:
- `tardigrade-perf` (`LXC 102`) on `beelink`
- load driver: `wrk` inside the guest against `127.0.0.1`
- Tardigrade route host header: `tardigrade-perf`
- duration: `30s`
- threads: `2`
- connections: `2`

Saved artifacts:
- `payload-scaling-loopback.json`
- `proxy-payload-256k.strace.txt`
- `proxy-payload-256k.strace.wrk.txt`

## Results

| Scenario | Payload | req/s | p50 (ms) | p99 (ms) | Payload throughput (MiB/s) |
| --- | ---: | ---: | ---: | ---: | ---: |
| `proxy-http1` | 2 B | 7100.06 | 0.270 | 0.279 | 0.01 |
| `proxy-payload-64k` | 65536 B | 3837.25 | 0.474 | 0.688 | 239.83 |
| `proxy-payload-256k` | 262144 B | 2636.37 | 0.691 | 1.000 | 659.09 |

Payload throughput above is computed from `req/s * Content-Length`, so it excludes headers and protocol framing.

## Interpretation

The curve starts bending in request rate immediately once the response stops being tiny:
- moving from `/proxy/health` to `64 KiB` drops req/s by about `46%`
- moving from `64 KiB` to `256 KiB` drops req/s by another `31%`

That said, the latency curve is still healthy through `256 KiB`:
- p50 rises from `0.270 ms` to `0.691 ms`
- p99 rises from `0.279 ms` to `1.000 ms`

So by `256 KiB` the proxy is clearly bandwidth-oriented instead of per-request-overhead-oriented, but it is not yet showing pathological tail behavior. The main bend so far is throughput-per-request, not unstable latency.

## Hotspots

`perf` was not available inside the guest, so the larger-payload profile used host-side `strace -f -c` against the live `tardigrade-perf` process while driving `/proxy/payload-256k.bin`.

Important caveat:
- the `strace` run perturbed the benchmark heavily and the companion `wrk` output shows socket read errors plus much lower req/s
- treat it as a hotspot sample only, not as a comparable performance number

Top syscall buckets from the `256 KiB` sample:

| Syscall | Time share |
| --- | ---: |
| `epoll_pwait` | 25.38% |
| `readv` | 17.70% |
| `futex` | 13.80% |
| `write` | 11.32% |
| `munmap` | 9.67% |
| `mmap` | 4.73% |
| `fcntl` | 4.41% |
| `sendmsg` | 2.08% |

What this points to:
- write-side pressure is real on the larger payload path: `write` plus `sendmsg` are a meaningful slice
- allocator churn is still visible: `mmap` plus `munmap` account for about `14.4%`
- synchronization is still non-trivial: `futex` remains a large bucket even on the loopback payload case

Connection-lifecycle syscalls such as `accept`, `setsockopt`, and some extra `read` pressure were inflated by the `strace` overhead itself, so they are not reliable ranking signals from this sample.

## Next Optimization Targets

1. Reduce allocation churn on buffered proxy response handling for larger bodies.
   The `mmap` and `munmap` share is still too visible for a `256 KiB` steady-state success path.

2. Cut write-side syscall pressure on larger buffered responses.
   The `write` and `sendmsg` share suggests there is still room to batch or streamline response emission for larger payloads.

3. Re-profile with a lower-perturbation sampler once available on the target.
   `perf` or an equivalent low-overhead profiler would let us separate real connection-lifecycle cost from the reconnect noise introduced by `strace`.

4. Extend the ladder once a larger buffered payload is intentionally supported.
   `256 KiB` still looks healthy. The next interesting bend point is above that, not below it.
