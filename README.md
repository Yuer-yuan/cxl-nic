# cxl-nic

Executable functional checks for packet reordering and safe publication to a CPU.
Includes a Python model, an independent event-log checker, and a bare-metal
RISC-V guest that reads published packets through CXLMemSim.

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

## Scope

The model uses one fixed session, sender-provided packet sequence numbers and
explicit epochs, complete packets, per-flow delivery and reserved per-flow credits.
`complete(op_id)` means a write has become CPU-visible. Atomic ready markers and
CPU acquire are abstract operations whose hardware implementation remains to be
validated. Missing packets stall the flow; explicit gap failure terminates it
without silently skipping packets. Buffer ownership and credits end at CPU release.
Operation IDs are unique within a session; repeated completion callbacks are
ignored, while a second physical write must be represented as a separate operation.

These checks exercise the shared functional contract intended for both PCIe NIC
reordering plus delayed DMA/DDIO and CXL NIC reordering plus delayed NC-P. They do
not implement either NIC transport or measure their performance. The guest path
uses the existing Type3 legacy TCP backend, whose responses provide authoritative
data for guest reads. It validates publication, data delivery and ownership with
actual guest loads/stores, but does not establish CXL.cache/NC-P semantics, physical
CPU memory ordering, LLC residency or LLC hit rate. Guest fences are exercised
under QEMU TCG; weak-memory behavior still needs separate validation.

Bounded and seeded schedules are evidence for the tested cases, not a formal proof
over all executions. Design/audit documents and generated results are excluded
from Git submissions.
