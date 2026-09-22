# cxl-nic

Executable functional checks for packet reordering and safe publication to a CPU.
Includes a Python protocol model, an independent event-log checker, a bare-metal
RISC-V guest that reads published packets through CXLMemSim, and a trace-driven
finite LLC model.

Run builds and verification on the Linux servers (Lenovo/Giga).

## Protocol checks

Python 3.10 or newer is sufficient for the model and unit tests.

```bash
bash scripts/verify.sh results/protocol-run-001
```

Use a new result directory for each run. The command runs unit tests, 64 seeded
schedules with 48 packets per flow, and bounded exploration of two-packet
publication interleavings. Results include a JSON summary, replayable JSONL traces,
unit-test logs and source hashes. Override `VERIFY_SEEDS` or
`VERIFY_PACKETS_PER_FLOW` to choose a different run size.

Replay a saved trace independently:

```bash
python3 - <<'PY'
import json
from cxl_nic.checker import validate_trace
with open('results/protocol-run-001/verification/seed-0000.jsonl') as events:
    print(validate_trace(json.loads(line) for line in events))
PY
```

## RISC-V guest integration

The pinned QEMU and CXLMemSim sources are Git submodules under `thirdparty/`.
Prepare them on Lenovo using the existing reference checkouts:

```bash
CXLMEMSIM_REFERENCE_COMPONENTS=/home/yuer/mypro/cxl/ref-repo/CXLMemSim-riscv/components \
    bash scripts/prepare_thirdparty.sh
rsync -az --exclude=/build/ --exclude=/results/ --exclude=/audit/ \
    --exclude=/.git/ ./ giga:/root/cxl-nic/
```

The preparation script creates independent checkouts without changing the reference
repository. Without `CXLMEMSIM_REFERENCE_COMPONENTS`, it fetches from GitHub.
Then build and run on Giga (Debian/Ubuntu; dependency installation requires root):

```bash
cd /root/cxl-nic
bash scripts/build_integration.sh --install-deps
bash scripts/build_guest.sh
python3 -m cxl_nic.integration --output results/integration-run-001
```

Use `--device-type type2` to run the same functional publication suite through
the pinned QEMU Type2 device. The default remains `type3`. Add `--data-path ncp`
to send packet payload and ready publication through an explicit NC-P operation:

```bash
python3 -m cxl_nic.integration --device-type type2 --data-path ncp \
    --host-llc-sets 64 --host-llc-ways 8 --output results/integration-ncp-001
python3 -m cxl_nic.integration --device-type type2 --data-path ddio \
    --host-llc-sets 64 --host-llc-ways 8 --output results/integration-ddio-001
bash scripts/verify_integration_cache.sh results/integration-cache-matrix-001
```

In NC-P mode, QEMU registers its Type2 connection as the host requester and
CXLMemSim installs pushed cache lines in a finite set-associative host-LLC model.
NC-P completion is returned only after the line is installed. A host demand hit
is served from that line; conflict eviction writes a dirty line to NIC-memory
backing, while an ordinary NC-write writes back and withdraws a resident line.
The matched `ddio` baseline first updates host-memory backing and then allocates a
clean line in the same LLC model, so a clean eviction needs no writeback. Both modes
use the same Type2 transport harness, reorder protocol, addresses and cache geometry;
`ddio` therefore models the data-placement difference and is not a physical PCIe
DDIO implementation. Results report completion, all host read hits, first-demand
hits, evictions, writebacks and residency. `--data-path legacy` remains the default
regression path. These are executable simulator mechanisms and do not manipulate a
physical QEMU host cache.

The matrix command runs both paths with the default 64-set/eight-way LLC and a
one-set/one-way pressure case. It requires identical cache-injection work,
complete first-demand hits with the default geometry, misses under pressure,
dirty NC-P writeback, and clean DDIO eviction. Pressure hit and eviction counts
can vary with guest polling, so they are recorded without requiring equality;
latency comparisons use the deterministic timing model below.

Omit `--install-deps` when the build dependencies are already installed. Use
`JOBS=8` to set build parallelism. No guest Linux image is required.

The default suite runs two flows with 16 packets each, reversed ingress windows,
duplicates, sequence-number wrap, slot reuse, and delayed payload/descriptor
writes. One flow must progress while the other's publication is held. The guest
copies actual CXL loads to DRAM, validates a fresh per-run payload pattern, logs
the observed bytes, and returns slot ownership through CXL stores. The independent
checker compares those observations with ingress; reuse waits for the guest's
release store to reach the backend.

Two negative controls deliberately publish ready before the final payload line,
or corrupt a payload byte. They pass only when the guest reports the corresponding
payload error and writes its failure status through the backend. Each case has an
isolated backend, backing file, UART log, JSONL trace and JSON result. The suite also
records source and binary hashes and checks that QEMU connected successfully.
Use `--case adversarial`, `--case early-ready` or `--case corrupt-payload` to run
one case, and `--packets-per-flow` to change the workload size (minimum four).

## Cache replay and the non-CXL baseline

Replay a successful guest trace on Giga:

```bash
bash scripts/verify_cache.sh \
    results/integration-run-001/adversarial/events.jsonl results/cache-run-001
```

This runs a symbolic cache comparison using exactly the same validated ingress,
reorder, credit, write-completion, consumption and release events for three arms:

- `ddio-host`: NIC reorder followed by delayed DMA/DDIO, with host memory backing.
- `ncp-nic`: the same scheduling with an NC-P insertion hypothesis and NIC backing.
- `ncp-host-control`: host backing to isolate allocation policy from memory home.

The default cache has 64 sets, eight ways, 64-byte lines, modulo set indexing and
LRU replacement. Both I/O policies can allocate in every way by default; this is
an explicit matched-resource assumption, not a claim about a hardware platform.
An I/O hit updates an existing line in any way. The admission mask only restricts
allocation on a miss. Dirty evictions write to the line's declared home; misses
read back and check the actual bytes. Metadata and release stores share capacity
with payload and synthetic host background reads.

The suite checks matched resources, a full-cache background sweep, an explicitly
hypothetical two-way DDIO/eight-way NC-P allocation comparison, and immediate
NC-write-style payload withdrawal. Identical policies and home must yield identical
results when only the protocol label changes. Withdrawal updates backing and removes
the old cache copy; deferred actions carry the full slot identity and cannot affect
a released or reused slot. This policy only supports immutable RX payload.

Customize a replay directly:

```bash
python3 -m cxl_nic.cache_replay \
    --trace results/integration-run-001/adversarial/events.jsonl \
    --output results/cache-custom-001 --sets 64 --ways 8 \
    --ddio-ways 0,1 --ncp-ways all --background-lines 128 \
    --withdraw-after-events 100
```

Omit `--withdraw-after-events` to disable withdrawal; its delay counts trace
records, not cycles or nanoseconds. `none` disables new I/O allocations, while
existing cache lines can still be updated coherently. Results contain per-arm
operation logs, source/trace hashes, separate first-payload-line and metadata
counts, backing traffic by home, and separate final-flush traffic.

The replay treats a packet's successful ready read, descriptor read and payload
reads as one ordered group at its `consume` event. Failed polls, private caches,
prefetching, concurrent sub-packet loads and ordinary guest RAM accesses are not
in the input trace. Background references are explicit synthetic competition.
These are cache-model results, not the guest's measured LLC hit rate, latency or
throughput. Allocation and home conventions follow the
[Intel DDIO description](https://www.intel.com/content/www/us/en/developer/articles/technical/ddio-analysis-performance-monitoring.html)
and [CXL-NIC paper](https://saksham.web.illinois.edu/assets/pdf/cxl-nic.pdf);
the model does not reproduce their hardware.

## Reliable-reordering virtual time

Run the deterministic policy matrix on Giga:

```bash
bash scripts/verify_timing.sh results/timing-run-001
```

The input workload contains complete packets with sender sequence numbers. Packets
can be delayed and arrive out of order, but every serial eventually arrives exactly
once. Permanent loss, retransmission, checksums, timeout recovery and congestion
control are outside this stage. A temporary gap remains central to the experiment:
it determines how long future packets wait before they are eligible for ordered
delivery and cache injection.

The matrix uses the same packet arrivals, payloads, cache, CPU service parameters
and link parameters for every arm:

- `A`: arrival-time DMA/DDIO; the CPU may read packets out of order into a software
  reorder buffer, while application delivery remains in sender order.
- `B0`: NIC reorder followed by an unrestricted contiguous DMA/DDIO burst.
- `B1`: NIC reorder followed by credit-limited delayed DMA/DDIO.
- `C`: arrival-time NC-P hypothesis, with ordered publication to the CPU.
- `D0`: NIC reorder followed by an unrestricted contiguous NC-P burst.
- `D1`: NIC reorder followed by credit-limited delayed NC-P.
- `E`: NIC reorder and ordered publication without payload push; CPU demand fetches
  from NIC memory.
- `D1-host-control`: the D1 scheduler with host backing, used only to prove that a
  protocol label does not change a matched B1 result.

All times are integer virtual nanoseconds. The engine models a serialized 64-byte
link, propagation latency, a single CPU consumer, per-flow push credit, finite NIC
buffering, a finite CPU software reorder buffer for arm A, the shared LLC, optional
periodic background references and optional post-push NC-write withdrawal. A
NIC-home CPU miss consumes return-link bandwidth and waits behind queued producer
traffic. Host and NIC backing service times are separate parameters.

The verification script runs the full matrix plus gap-delay, LLC pressure, I/O way
admission, NC-write withdrawal, tight-credit and packet-stride cases. Packet stride
is expressed in cache lines; 128 and 129 line strides expose sensitivity to the
model's simple modulo set mapping. It records ordered-delivery p50/p99 latency,
first payload-line hit rate, push-to-demand distance, premature absence, credit
stalls, NIC/CPU buffer occupancy and producer/CPU link bytes. B1 and the host-backed
D1 control must be exactly equal whenever their admission and withdrawal policies
match.

The default numeric parameters are deliberately uncalibrated. Cache writeback bytes
are counted by backing home, but their queueing time is not yet fed back into virtual
time. The model also excludes CPU private caches, prefetching, interrupts, failed
polls, hardware LLC hashing/replacement and actual PCIe/CXL transaction channels.
Therefore its output supports mechanism and sensitivity claims under the recorded
configuration, not nanosecond hardware-performance claims.

Run one custom matrix with:

```bash
python3 -m cxl_nic.timing --output results/timing-custom-001 \
    --packets-per-flow 64 --gap-delay-ns 800 \
    --push-credit-bytes-per-flow 3072 \
    --background-interval-ns 20 --background-working-set-lines 1024 \
    --ddio-ways 0,1 --ncp-ways all
```

## Scope

The model uses one fixed session, sender-provided packet sequence numbers and
explicit epochs, complete packets, per-flow delivery and reserved per-flow credits.
The NIC reorder stage, rather than either cache-injection operation, enforces packet
order and publishes only a contiguous per-flow prefix. The current scope assumes
reliable eventual delivery of every complete packet with finite reordering; loss
recovery is a later layer.
`complete(op_id)` means a write has become CPU-visible. Atomic ready markers and
CPU acquire are abstract operations whose hardware implementation remains to be
validated. Missing packets stall the flow; explicit gap failure terminates it
without silently skipping packets. Buffer ownership and credits end at CPU release.
Operation IDs are unique within a session; repeated completion callbacks are
ignored, while a second physical write must be represented as a separate operation.

These checks exercise the shared functional contract intended for both PCIe NIC
reordering plus delayed DMA/DDIO and CXL NIC reordering plus delayed NC-P. They do
not implement either NIC transport or measure their performance. The guest path
supports the pinned Type2 and Type3 legacy TCP endpoints, whose backend responses
provide authoritative data for guest reads. Type2 NC-P and matched DDIO modes
additionally exercise explicit injection/completion operations and a finite
simulated host LLC. They validate publication, data delivery, ownership, modeled
first-demand hits and dirty writebacks with actual guest loads/stores, but do not
establish physical CPU memory ordering or hardware LLC residency/hit rate. Guest
fences are exercised under QEMU TCG;
weak-memory behavior still needs separate validation.

Bounded and seeded schedules are evidence for the tested cases, not a formal proof
over all executions. Design/audit documents and generated results are excluded
from Git submissions.
