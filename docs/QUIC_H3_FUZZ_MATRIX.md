# QUIC/H3 Fuzz and Property Matrix

This matrix tracks the deterministic parser/state-machine fuzz coverage for
#247/#537. Default smoke coverage is run by `zig build test` and the focused
QUIC/H3 subset by:

```bash
zig build test-quic --summary all --error-style verbose
```

For longer local or scheduled coverage-guided runs, use the same offline test
targets with Zig's fuzz runner against the target-local `std.testing.fuzz`
cases:

```bash
zig build test-quic -Doptimize=ReleaseFast --fuzz=10M --summary all --error-style verbose
zig build test-quic -Doptimize=ReleaseFast -Dquic-test-filter="fuzz: packet parser" --fuzz=10M --summary all --error-style verbose
zig build test-quic -Doptimize=ReleaseFast -Dquic-test-filter="fuzz: frame decoder" --fuzz=10M --summary all --error-style verbose
zig build test-quic -Doptimize=ReleaseFast -Dquic-test-filter="fuzz: transport parameter decoder" --fuzz=10M --summary all --error-style verbose
zig build test-quic -Doptimize=ReleaseFast -Dquic-test-filter="fuzz: transport parameters canonical" --fuzz=10M --summary all --error-style verbose
zig build test-quic -Doptimize=ReleaseFast -Dquic-test-filter="fuzz: Retry token issue validate" --fuzz=10M --summary all --error-style verbose
zig build test-quic -Doptimize=ReleaseFast -Dquic-test-filter="fuzz: CRYPTO reassembly command sequences" --fuzz=10M --summary all --error-style verbose
zig build test-quic -Doptimize=ReleaseFast -Dquic-test-filter="fuzz: stream manager command sequences" --fuzz=10M --summary all --error-style verbose
zig build test-quic -Doptimize=ReleaseFast -Dquic-test-filter="fuzz: stream send queue ack loss close command sequences" --fuzz=10M --summary all --error-style verbose
zig build test-quic -Doptimize=ReleaseFast -Dquic-test-filter="fuzz: QPACK stateful dynamic table and instruction streams" --fuzz=10M --summary all --error-style verbose
zig build test-quic -Doptimize=ReleaseFast -Dquic-test-filter="fuzz: H3 connection state command sequences" --fuzz=10M --summary all --error-style verbose
```

The `--fuzz=<runs>` limit keeps scheduled runs bounded; suffixes `K`, `M`, and
`G` scale the run count. The optional `-Dquic-test-filter` gives explicit target
selection, and the failing fuzz case is reported by Zig's unit-test runner with
the test name and minimized input needed for deterministic reproduction. Keep
external peers out of these loops; ngtcp2/nghttp3, quiche, and aioquic remain under
`scripts/interop/run-interop.sh`.

## Host memory requirement for command-sequence targets

Command-sequence targets need a host with several GB of free RAM per fuzz
process, and a memory-saturated host will get the process `SIGKILL`ed mid-row.
Provision **at least 4 GB of available RAM per active command-sequence fuzz
process**, and prefer **6-8 GB of guest memory for a guest running one
canonical fuzz process**. Do not run canonical rows on a machine already near
its memory limit; a row killed this way is `INTERRUPTED`, not a finding, and
must be rerun rather than recorded.

Those figures are provisioning numbers, not the measurement. The measured
warm-up transient below is ~1.87 GB, so sizing to ~2 GB would leave under 10%
margin -- not enough to absorb allocator-metadata variance between hosts, the
fuzz runtime's own corpus and coverage state, OS page cache, or a target that
grows a little. The 4 GB floor is that transient plus real margin; the 6-8 GB
guest recommendation additionally covers the guest OS.

This is a property of `std.testing.allocator`, not of any target. Measured on
one host, sampling process RSS every 5s under `-Doptimize=ReleaseFast`:

| target | warm-up peak | steady-state mean |
| --- | --- | --- |
| `fuzz: packet parser` (allocation-free) | 3 MB | 2 MB |
| `fuzz: stream manager command sequences` | 1,669 MB | 265 MB |
| `fuzz: H3 connection state command sequences` | 1,867 MB | 286 MB |
| `fuzz: H3 connection state command sequences`, `smp_allocator` substituted | 4 MB | 4 MB |

The last row is the control: changing *only* the allocator in the same target
moves it from 1,867 MB to 4 MB. The footprint is `std.heap.DebugAllocator`'s
per-allocation metadata and 10-frame stack traces, retained so the fuzz targets
keep leak detection, under the allocation churn a command-sequence target
generates. The two command-sequence targets above are within ~8% of each other,
which is why this is documented here as a shared property rather than filed
against either one.

The survival control makes the same point at campaign scale. On one host, same
target, same fuzz runtime, changing *only* the allocator:

| allocator | outcome |
| --- | --- |
| `std.testing.allocator` | `SIGKILL` at 397,458 runs; again at 518,799 |
| `std.heap.smp_allocator` | **601,913 runs, clean exit** |

The kills correlate with elapsed time (~13-15 minutes each) rather than with a
run count, and the `.zig-cache/f/crash` artifact they leave is **zero bytes** --
an external kill, not a finding. A row that ends this way must be recorded as
`INTERRUPTED` and rerun on a host with headroom; it is not a reproducer and
there is nothing to minimize.

### Guest memory preflight before a canonical long row

Sizing a guest correctly on paper is not the same as confirming it. Before
launching the H3 conn-state 50M row (or any other command-sequence row) on the
real disposable campaign VM, run the **same canonical target for ~1M
mutations in that VM** while sampling guest RSS and `MemAvailable` alongside
host memory:

```bash
# In the campaign guest, alongside the row's own zig build invocation:
while :; do
  printf '%s rss_kb=%s mem_available_kb=%s\n' \
    "$(date -u +%FT%TZ)" \
    "$(ps -o rss= -C test 2>/dev/null | tr -d ' ' | head -1)" \
    "$(awk '/MemAvailable/{print $2}' /proc/meminfo)"
  sleep 5
done
```

Proceed to the 50M row, and then the required 100M finding-driven follow-up,
only if that preflight **completes** with the warm-up transient staying under
~2 GB and host headroom staying healthy. If it is killed, or the transient is
materially larger than the table above, the guest is undersized -- fix the
provisioning rather than starting a long row that will be interrupted hours in.

This preflight is about the *execution environment*, so it is separate from and
additional to #675's deterministic pre-campaign gate, which is about the source
tree.

**Do not substitute a non-instrumented allocator in the real campaign** to make
a row fit. The leak detection is the point; see below.

The footprint is **stable, not monotonic** — the ramp to ~1.9 GB is a cold-corpus
warm-up transient, after which RSS oscillates in a band (90-480 MB observed) with
no upward trend in its floor. There is no leak here to fix, and the leak
detection that costs this memory is deliberately kept: #675 counts "allocator
growth attributable to bounded command-sequence targets" as a real finding
class, so substituting a non-instrumented allocator to save memory would blind
the campaign to exactly the defects it is looking for.

Use `-Doptimize=ReleaseFast` for coverage-guided runs with Zig 0.16.0; the
ordinary deterministic smoke tests continue to run in the default Debug mode.

| Area | Existing or New Target | Properties Covered | Open Follow-Up |
| --- | --- | --- | --- |
| QUIC varints | `src/quic/varint.zig` `fuzz: varint decode and minimal re-encode never panic`; `fuzz: varint encode round-trips arbitrary in-range values` | Minimal re-encode, in-range encode/decode round-trip, truncation rejection. | None for the current varint codec surface. |
| QUIC packet numbers | `src/quic/packet.zig` `fuzz: packet number truncation reconstructs recent sends`; upper-bound deterministic regressions | Packet-number length selection, truncation, and reconstruction across the legal `2^62 - 1` range, including exact values near `max_packet_number`. | Add recovered packet-number comparisons from loss/reordering driver state when that state exposes a narrow property API. |
| QUIC packet/header/coalescing | `src/quic/packet.zig` `fuzz: packet parser preserves bounded slice and progress invariants`; `fuzz: packet writers round-trip public parser fields`; deterministic coalesced invalid-tail and boundary-matrix regression tests | Empty/truncated inputs, fixed-bit failures, long/short header CID boundaries, version-negotiation empty/misaligned/exact-list boundaries, Initial token/Length cursor handling including exact/under/huge values, Retry token/tag split, short-header caller CID length, coalesced valid+invalid and multiple-valid-prefix progress, parsed slices staying inside the input, nonzero bounded `packet_len`, and canonical long-header, short-header, and Retry writer/parser public-field round-trips. | None for the current packet/header codec surface. |
| QUIC frame and ACK ranges | `src/quic/frame.zig` `fuzz: frame decoder preserves bounded consumption and slice invariants`; `fuzz: canonical frame encoders round-trip supported families`; ACK boundary and decoder-only family regressions | Supported frame families, unknown type handling, varint truncation, STREAM/CRYPTO payload slices, NEW_TOKEN empty/non-empty handling, DATA_BLOCKED/STREAM_DATA_BLOCKED/STREAMS_BLOCKED decoding, fixed-size PATH frames, NEW_CONNECTION_ID length/token boundaries, CONNECTION_CLOSE reason slices, parser monotonicity including typed malformed-tail termination, ACK and ACK_ECN exact consumption, underflow, overlap, huge-gap arithmetic, and semantic encode/decode round-trips for supported canonical encoders. | Add encode coverage for ACK ECN and NEW_TOKEN if/when production encoders are added. |
| Transport parameters | `src/quic/tls_backend.zig` `fuzz: transport parameter decoder preserves bounded structural contract`; `fuzz: transport parameters canonical encode and binding round-trip`; deterministic structural, semantic, and CID-binding regressions | Empty blocks, truncated ID/length/value varints, declared length overrun, integer trailing bytes, duplicate known and tracked-unknown IDs, best-effort unknown duplicate tracking that keeps more than 64 distinct well-formed unknown IDs skippable, `max_udp_payload_size`, `active_connection_id_limit`, `ack_delay_exponent`, `max_ack_delay`, initial flow-control values including symmetric decode/config/encode enforcement of `initial_max_streams_* <= 2^60`, `disable_active_migration`, CID binding zero/max/max+1 lengths, stateless reset-token exact/short/long lengths, bounded successful decode invariants, and canonical encode/decode preservation of supported `TransportParameters` and `CidBinding` fields. | None for the current raw transport-parameter codec/validation surface. |
| Retry/public token boundary | `src/quic/path.zig` `fuzz: Retry token issue validate and mutation boundary is deterministic`; deterministic issue/validate, mutation, authenticated-malformed-plaintext, key-rotation, address-binding, and time-boundary regressions. Runtime invalid-token acceptance remains in #387 coverage. | Offline `RetryTokens.issueRetry`/`validateRetry` preserves ODCID, Retry SCID, and QUIC version across IPv4/IPv6 including scope IDs; validates retained old keys and rejects retired/unknown keys; rejects nonce, ciphertext, and tag mutations; rejects short/oversized/truncated tokens; maps authenticated wrong-kind and malformed plaintext to public token errors; enforces address/port binding and exact expiry/future-skew boundaries including `u64` saturation behavior. Retry SCID and version comparisons are exposed in `RetryContext`; the connection layer owns comparing them to the active Retry packet and transport-parameter binding. No explicit temporary-plaintext zeroization contract exists on this owner today; token buffers are bounded stack slices and no diagnostics include token plaintext, keys, nonces, or reusable material. | None for the current offline Retry token codec/state boundary. |
| CRYPTO reassembly | `src/quic/tls_adapter.zig` `fuzz: CRYPTO reassembly command sequences preserve bounded invariants`; deterministic overlap/gap/consumed retransmit/range-capacity/offset-overflow regressions; connection-driver tests for handshake composition. | Real `CryptoReassembler`/`CryptoStream` per Initial, Handshake, and Application epoch; zero-length fragments, duplicates, left/right overlap, contained retransmits, reverse/gap-fill delivery, exact capacity and one-past-capacity probes, very large offsets, overflow-safe offset+length rejection, monotonic consumed offsets, bounded range count/storage, rejected insert stability, reset/deinit emptying state, and no diagnostics containing crypto bytes or secrets. 0-RTT CRYPTO remains inapplicable: the production owner rejects `.zero_rtt` via `InvalidCryptoLevel`. | None for the current parser/state-machine fuzz scope. Broader handshake/loss/reorder integration remains under #247. |
| Streams and flow control | `src/quic/stream.zig` `fuzz: stream manager command sequences preserve flow-control invariants`; `src/quic/connection.zig` `fuzz: stream send queue ack loss close command sequences preserve retransmission invariants`; `stream send queue keeps lost ranges retransmittable across duplicate ACK and loss signals`; deterministic stream overlap/final-size/reset/STOP_SENDING/MAX_* regressions; QUIC/H3 driver request/response accounting. | Real `StreamManager`, `Stream`, `ReceiveBuffer`, and connection send-queue range bookkeeping; client/server stream-ID directionality, local bidi/uni opens, peer stream creation and illegal IDs, STREAM offset/FIN sequences, duplicate/overlap mismatch rejection, zero-length send/receive, MAX_DATA/MAX_STREAM_DATA/MAX_STREAMS monotonicity, stream and connection flow-control exact/+1 behavior through bounded windows, duplicate/conflicting RESET_STREAM final size, STOP_SENDING ordering, local reset, close/resource counters, send accounting, receive credit, duplicate ACK/loss range idempotence, loss requeue through the same helper used by production recovery, ACK subtraction from retransmission responsibility in loss-first and ACK-first orderings including split overlaps, FIN retransmission independent of byte ranges, FIN ACK preventing later duplicate-loss resurrection, close/teardown, and lost bytes remaining retransmittable until acknowledged/reset. | None for the current parser/state-machine fuzz scope. Full network loss/PTO/reorder/reset soak and performance evidence remain under #247. |
| QPACK stateful decoder/encoder | `src/http3/qpack.zig` `fuzz: QPACK static decoder never panics on arbitrary field sections`; `fuzz: QPACK static-table selections round-trip through encoder`; `fuzz: QPACK stateful dynamic table and instruction streams preserve invariants`; deterministic dynamic table, split instruction, blocked stream, ack/cancel/increment, wrapped RIC, malformed Huffman, truncation, malformed-tail no-replay, and capacity-eviction insertion-count regressions. | Real `DynamicTable`, `EncoderStream`, `EncoderStreamReader`, `DynamicDecoder`, `BlockedStreams`, `DecoderStream`, and `DecoderStreamReader`; capacity 0 and bounded nonzero capacities, capacity increase/decrease, insertion at/over capacity, eviction order and exact byte accounting, static/dynamic name references, duplicate instructions, relative/post-base/index-0/out-of-range checks, wrapped Required Insert Count, split/truncated instructions and strings, malformed Huffman rejection, multiple instructions per buffer, blocked stream registration/unblock/cancel and one-over limit, decoder instruction Section Acknowledgement/Stream Cancellation/Insert Count Increment, monotonic insertion/known-received counts across capacity eviction and malformed inputs, length-seeded command slicing progress, direct owner/corpus capacity-churn regressions, consumed-prefix commit before malformed-tail errors, and invalid instructions returning typed errors without replaying already-applied instructions. | None for the current parser/state-machine fuzz scope. H3 does not yet negotiate nonzero QPACK settings on the main request path, so dynamic request integration remains non-wire-reachable until that production feature is enabled. |
| HTTP/3 frame, control, request, and critical-stream state | `src/http3/frame.zig` `fuzz: frame decoder never panics on arbitrary bytes`; `fuzz: SETTINGS decoder never panics on arbitrary payloads`; `fuzz: control stream ingestion never panics or leaks`; `src/http3/conn.zig` `fuzz: H3 connection state command sequences preserve critical stream and request invariants`; deterministic request-order, duplicate critical stream, closed/reset critical stream, request reset cleanup, priority, inbound/outbound GOAWAY, and SETTINGS regressions. | Frame parse bounds, SETTINGS duplicate/boolean/reserved validation, fragmented control-stream ingest, exactly-one peer control/QPACK encoder/QPACK decoder streams, unknown uni stream draining, duplicate critical stream close codes, critical stream FIN/reset close codes, SETTINGS-first and duplicate SETTINGS handling, forbidden control frames, request HEADERS/DATA/trailing HEADERS ordering, DATA-before-HEADERS rejection, duplicate initial HEADERS rejection, request RESET cleanup at default concurrency scale, server-initiated bidi rejection at clients, exact H3 error-code mapping, inbound GOAWAY monotonicity, local post-GOAWAY request rejection before stream allocation, sent-GOAWAY boundary-and-greater request rejection without connection close, bounded pending uni/request/priority maps -- `pending_uni` is bounded by `Conn.max_pending_uni` (`default_max_pending_uni`, H3_EXCESSIVE_LOAD on exceed, #753 part A), which the model lowers to `fuzz_max_pending_uni` so the control stays reachable against a transport that now models a realistic live unidirectional stream limit; peer streams already reset before their first acceptance are never tracked at all (#742), and teardown of request/control state. Push remains rejected because this stack never sends `MAX_PUSH_ID`; nonzero-QPACK request blocking is not wire-reachable while local H3 settings validation rejects dynamic QPACK. | None for the current parser/state-machine fuzz scope. Broader drain/soak/performance evidence remains under separately-owned #247 rollout work, not #537 parser/state fuzzing. |
| External H3 interop | `tests/h3_interop_tool.zig`; `scripts/interop/run-interop.sh`; integration `h3interop.*` filters | Native-to-external and external-to-native peer proof outside fuzz loops. | Keep separate from parser/property fuzzing; do not fold network peers into fuzz targets. |
