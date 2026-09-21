"""Reproducible functional verification; event steps have no physical duration."""

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import platform
import random
import sys

from .checker import validate_trace
from .model import Config, Protocol


def payload_for(flow, serial, size):
    # Each block has a distinct pattern so swapped/aliased cache lines are visible.
    blocks = [hashlib.sha256(f"{flow}:{serial}:{block}".encode()).digest()
              for block in range((size + 31) // 32)]
    return b"".join(blocks)[:size]


def save_trace(path, trace):
    with path.open("w") as out:
        for event in trace:
            out.write(json.dumps(event, sort_keys=True) + "\n")


def random_schedule(seed, packets_per_flow=48, trace_path=None):
    rng = random.Random(seed)
    config = Config(window=4, sequence_bits=4, max_packet_bytes=1500,
                    per_flow_credit_bytes=3072)
    starts = {0: 14, 1: 30}
    protocol = Protocol(config, starts)
    lengths = (1, 63, 64, 65, 128, 1500)
    remaining = {
        flow: {serial: payload_for(flow, serial, rng.choice(lengths))
               for serial in range(start, start + packets_per_flow)}
        for flow, start in starts.items()
    }
    expected_payloads = {flow: dict(packets) for flow, packets in remaining.items()}
    receive_base = dict(starts)
    freed = {flow: set() for flow in starts}
    held = []
    expected = dict(starts)
    seen = {flow: [] for flow in starts}
    steps = 0
    step_limit = packets_per_flow * len(starts) * 300

    def record_delivery(delivery):
        flow = delivery.token.flow
        serial = delivery.token.serial
        if (serial != expected[flow]
                or delivery.payload != expected_payloads[flow].get(serial)):
            raise AssertionError(f"delivery mismatch, seed={seed} token={delivery.token}")
        expected[flow] += 1
        seen[flow].append(serial)
        held.append(delivery)

    def do_release(idx):
        delivery = held.pop(idx)
        protocol.release(delivery.token)
        flow, serial = delivery.token.flow, delivery.token.serial
        freed[flow].add(serial)
        while receive_base[flow] in freed[flow]:
            freed[flow].remove(receive_base[flow])
            receive_base[flow] += 1

    try:
        while (any(remaining.values()) or protocol.pending or held
               or any(len(seen[f]) != packets_per_flow for f in starts)):
            steps += 1
            if steps > step_limit:
                raise AssertionError(f"fair-schedule watchdog: seed={seed}")
            action = rng.randrange(4)
            if action == 0:
                candidates = [(f, s) for f in starts for s in remaining[f]
                              if receive_base[f] <= s < receive_base[f] + config.window]
                if candidates:
                    flow, serial = rng.choice(candidates)
                    payload = remaining[flow].pop(serial)
                    assert protocol.receive(flow, serial % 16, serial // 16, payload) == "accepted"
                    if rng.randrange(3) == 0:
                        assert protocol.receive(flow, serial % 16, serial // 16, payload) == "duplicate"
            elif action == 1 and protocol.pending:
                op_id = rng.choice(list(protocol.pending))
                assert protocol.complete(op_id)
                if rng.randrange(5) == 0:
                    assert not protocol.complete(op_id)
            elif action == 2:
                # One consumer is periodically stopped while the other progresses.
                flow = rng.choice(list(starts))
                if flow != 0 or steps % 113 > 35:
                    delivery = protocol.acquire(flow)
                    if delivery is not None:
                        record_delivery(delivery)
            elif action == 3 and held:
                do_release(rng.randrange(len(held)))
            protocol.pump()
            protocol.check_invariants()
        summary = validate_trace(protocol.trace)
        for flow, start in starts.items():
            assert seen[flow] == list(range(start, start + packets_per_flow))
        if trace_path:
            save_trace(trace_path, protocol.trace)
        return {"seed": seed, "scheduler_steps": steps, **summary}
    except Exception:
        if trace_path:
            save_trace(trace_path, protocol.trace)
        raise


def critical_interleavings(trace_path=None):
    """Exhaust every enabled order in an explicitly reduced two-packet case.

    Each packet retains its final payload-line write and descriptor-length write.
    Other writes are completed in a fixed prefix. Then enumerate all remaining
    visibility, ready, CPU acquire and CPU release interleavings. This is bounded
    exploration of the publication boundary, not exhaustive protocol verification.
    """
    protocol = Protocol(Config(window=2, sequence_bits=3, max_packet_bytes=65,
                               per_flow_credit_bytes=256))
    protocol.receive(0, 1, 0, b"B" * 65)
    protocol.receive(0, 0, 0, b"A" * 65)
    protocol.pump()
    for op_id, write in list(protocol.pending.items()):
        critical = ((write.kind == "payload" and write.offset == 64)
                    or (write.kind == "descriptor" and write.field == "length"))
        if not critical:
            protocol.complete(op_id)
    states = 0
    leaves = 0
    representative = None

    def visit(current, held, consumed, released):
        nonlocal states, leaves, representative
        states += 1
        current.check_invariants()
        if released == 2:
            assert not current.pending and not held
            validate_trace(current.trace)
            leaves += 1
            if representative is None:
                representative = current.trace
            return
        branches = 0
        for op_id in list(current.pending):
            next_model = deepcopy(current)
            next_model.complete(op_id)
            visit(next_model, held, consumed, released)
            branches += 1
        next_model = deepcopy(current)
        delivery = next_model.acquire(0)
        if delivery is not None:
            assert delivery.token.serial == consumed
            assert delivery.payload == (b"A" if consumed == 0 else b"B") * 65
            visit(next_model, held + [delivery.token], consumed + 1, released)
            branches += 1
        for index, token in enumerate(held):
            next_model = deepcopy(current)
            next_model.release(token)
            visit(next_model, held[:index] + held[index + 1:], consumed, released + 1)
            branches += 1
        if not branches:
            raise AssertionError("deadlocked reduced publication schedule")

    visit(protocol, [], 0, 0)
    if trace_path and representative:
        save_trace(trace_path, representative)
    return {"states": states, "complete_schedules": leaves,
            "scope": "two packets; final payload line and descriptor length; ready/acquire/release"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seeds", type=int, default=64)
    parser.add_argument("--packets-per-flow", type=int, default=48)
    parser.add_argument("--skip-exploration", action="store_true")
    args = parser.parse_args(argv)
    if sys.flags.optimize:
        parser.error("verification requires assertions enabled")
    if args.seeds < 1 or args.packets_per_flow < 1:
        parser.error("seeds and packets-per-flow must be positive")
    # A fresh directory avoids mixing evidence from separate executions.
    args.output.mkdir(parents=True, exist_ok=False)
    files = sorted(Path(__file__).parent.glob("*.py"))
    result = {
        "status": "running",
        "scope": "functional contract; no cache, wire protocol, ISA or hardware timing claim",
        "python": sys.version,
        "platform": platform.platform(),
        "source_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
        "seeds": args.seeds,
        "packets_per_flow": args.packets_per_flow,
        "random_schedules": [],
    }
    try:
        for seed in range(args.seeds):
            summary = random_schedule(seed, args.packets_per_flow,
                                      args.output / f"seed-{seed:04d}.jsonl")
            result["random_schedules"].append(summary)
        if not args.skip_exploration:
            result["critical_interleavings"] = critical_interleavings(
                args.output / "critical-interleavings-example.jsonl")
        result["status"] = "passed"
    except Exception as error:
        result["status"] = "failed"
        result["error"] = repr(error)
        raise
    finally:
        (args.output / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": result["status"], "seeds": args.seeds,
                      "packets": 2 * args.seeds * args.packets_per_flow,
                      "critical_interleavings": result.get("critical_interleavings"),
                      "result": str(args.output / "result.json")}, sort_keys=True))


if __name__ == "__main__":
    main()
