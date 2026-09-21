# cxl-nic

Executable functional checks for packet reordering and safe publication to a CPU.
The current implementation is a Python model with an independent event-log checker.

Run builds and verification on the Linux servers (Lenovo/Giga). Python 3.10 or newer
is sufficient; this stage has no third-party dependencies.

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
not implement either hardware transport, CPU memory ordering, LLC behavior or a
performance model. Bounded and seeded schedules are evidence for the tested cases,
not a formal proof over all executions. Design/audit documents and generated results
are excluded from Git submissions.
