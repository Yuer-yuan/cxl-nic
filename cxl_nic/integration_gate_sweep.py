"""Compare sampled NC-P gating with matched Type2 guest integration controls."""

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys

from .integration import PINS, ROOT

GATE_THRESHOLD_LINES = 38


@dataclass(frozen=True)
class Arm:
    name: str
    path: str
    sets: int = 64
    ways: int = 8
    gate_lines: int | None = None
    sample_every_lines: int | None = None
    control_delay_lines: int = 0
    global_credit_bytes: int | None = None


ARMS = (
    Arm("ddio_base", "ddio"),
    Arm("ncp_base", "ncp"),
    Arm("gate_instant", "ncp", gate_lines=GATE_THRESHOLD_LINES),
    Arm("gate_sample_1", "ncp", gate_lines=GATE_THRESHOLD_LINES, sample_every_lines=1),
    Arm("gate_sample_8", "ncp", gate_lines=GATE_THRESHOLD_LINES, sample_every_lines=8),
    Arm("gate_sample_32", "ncp", gate_lines=GATE_THRESHOLD_LINES, sample_every_lines=32),
    Arm("gate_delay_8", "ncp", gate_lines=GATE_THRESHOLD_LINES, sample_every_lines=8,
        control_delay_lines=8),
    Arm("ddio_llc_128", "ddio", sets=16),
    Arm("ncp_llc_128", "ncp", sets=16),
    Arm("gate_llc_128", "ncp", sets=16, gate_lines=GATE_THRESHOLD_LINES),
    Arm("ddio_budget_3072", "ddio", global_credit_bytes=3072),
    Arm("ncp_budget_3072", "ncp", global_credit_bytes=3072),
    Arm("gate_budget_3072", "ncp", gate_lines=GATE_THRESHOLD_LINES,
        global_credit_bytes=3072),
)

MATCHED_PAIRS = (("ddio_base", "ncp_base"),
                 ("ddio_llc_128", "ncp_llc_128"),
                 ("ddio_budget_3072", "ncp_budget_3072"))
GATE_REFERENCES = {
    "gate_instant": "ncp_base",
    "gate_sample_1": "ncp_base",
    "gate_sample_8": "ncp_base",
    "gate_sample_32": "ncp_base",
    "gate_delay_8": "ncp_base",
    "gate_llc_128": "ncp_llc_128",
    "gate_budget_3072": "ncp_budget_3072",
}


def validate_results(results, packets_per_flow):
    if set(results) != {arm.name for arm in ARMS}:
        raise ValueError("gate sweep arms are incomplete")
    measured = {}
    reference_demand = None
    for arm in ARMS:
        result = results[arm.name]
        if (result.get("status") != "passed" or result.get("pins") != PINS
                or result.get("device_type") != "type2" or result.get("data_path") != arm.path
                or result.get("ncp_gate_resident_lines") != arm.gate_lines
                or result.get("ncp_gate_sample_every_lines") != arm.sample_every_lines
                or result.get("ncp_gate_control_delay_lines") != arm.control_delay_lines
                or result.get("global_push_credit_bytes") != arm.global_credit_bytes):
            raise ValueError(f"{arm.name}: endpoint or policy configuration differs")
        cases = result.get("cases", ())
        if len(cases) != 1 or cases[0].get("mode") != "adversarial":
            raise ValueError(f"{arm.name}: expected one adversarial guest case")
        case = cases[0]
        if (case.get("status") != "passed" or case.get("guest_status") != 2
                or case.get("consumed") != {"0": packets_per_flow, "1": packets_per_flow}
                or case.get("trace", {}).get("released") != 2 * packets_per_flow
                or case.get("other_flow_progress_while_held") is not True):
            raise ValueError(f"{arm.name}: ordered guest delivery is incomplete")
        stats = case.get(arm.path)
        if (not isinstance(stats, dict) or stats.get("configured_sets") != arm.sets
                or stats.get("configured_ways") != arm.ways):
            raise ValueError(f"{arm.name}: host LLC geometry differs")
        demand = stats["first_demands"]
        if (demand <= 0 or stats["first_demand_hits"] + stats["first_demand_misses"] != demand):
            raise ValueError(f"{arm.name}: first-demand accounting is inconsistent")
        if reference_demand is None:
            reference_demand = demand
        elif demand != reference_demand:
            raise ValueError(f"{arm.name}: guest demand work differs")
        payload_lines = case["payload_lines"]
        if payload_lines <= 0:
            raise ValueError(f"{arm.name}: no payload lines were checked")
        payload_demand = stats.get("payload_first_demand")
        ready_demand = stats.get("ready_first_demand")
        if (not isinstance(payload_demand, dict) or not isinstance(ready_demand, dict)
                or payload_demand.get("lines") != payload_lines
                or ready_demand.get("lines") != 2 * packets_per_flow
                or payload_demand.get("hits", -1) + ready_demand.get("hits", -1)
                != stats["first_demand_hits"]):
            raise ValueError(f"{arm.name}: payload/ready first-demand split differs")
        if arm.global_credit_bytes is not None:
            if case["trace"]["global_credit_peak_bytes"] > arm.global_credit_bytes:
                raise ValueError(f"{arm.name}: global credit limit exceeded")
        gate = case.get("gate_sampling")
        if arm.gate_lines is None:
            if (gate is not None or stats["gated_push_lines"] or stats["gated_nc_write_lines"]
                    or stats["nc_writes"] or stats["pushes"] != payload_lines + 2 * packets_per_flow):
                raise ValueError(f"{arm.name}: ungated placement accounting differs")
        else:
            if (not isinstance(gate, dict)
                    or gate["control_path"] != "producer_controller_model"
                    or gate["sample_every_payload_lines"] != arm.sample_every_lines
                    or gate["control_delay_payload_lines"] != arm.control_delay_lines
                    or gate["payload_lines"] != payload_lines
                    or gate["push_lines"] + gate["nc_write_lines"] != payload_lines
                    or gate["push_lines"] != stats["gated_push_lines"]
                    or gate["nc_write_lines"] != stats["gated_nc_write_lines"]
                    or gate["nc_write_lines"] != stats["nc_writes"]
                    or gate["samples"] != (
                        payload_lines if arm.sample_every_lines is None else
                        (payload_lines + arm.sample_every_lines - 1) // arm.sample_every_lines)
                    or gate["control_writes"] - gate["control_applies"]
                    != gate["pending_control_writes"]):
                raise ValueError(f"{arm.name}: sampled gate accounting differs")
        measured[arm.name] = {"stats": stats, "case": case}

    for ddio_name, ncp_name in MATCHED_PAIRS:
        ddio = measured[ddio_name]["stats"]
        ncp = measured[ncp_name]["stats"]
        if (ddio["pushes"] != ncp["pushes"]
                or ddio["push_bytes"] != ncp["push_bytes"]
                or ddio["first_demands"] != ncp["first_demands"]):
            raise ValueError(f"{ddio_name}/{ncp_name}: matched work differs")
    for name, reference in GATE_REFERENCES.items():
        gated = measured[name]["stats"]
        plain = measured[reference]["stats"]
        if (gated["pushes"] + gated["nc_writes"] != plain["pushes"]
                or gated["push_bytes"] + gated["nc_write_bytes"] != plain["push_bytes"]):
            raise ValueError(f"{name}: logical payload work differs from NC-P reference")
    instant = measured["gate_instant"]["case"]["gate_sampling"]
    sampled = measured["gate_sample_32"]["case"]["gate_sampling"]
    if instant["push_lines"] == sampled["push_lines"]:
        raise ValueError("32-line sampling did not exercise stale flag behavior")

    return {
        "status": "passed",
        "scope": ("Type2 QEMU guest and finite CXLMemSim host LLC; reliable finite reordering; "
                  "sample/control intervals count payload writes, not time or CXL cycles"),
        "checks": {"ordered_guest_delivery": "passed",
                   "matched_ddio_ncp_work": "passed",
                   "sampled_gate_accounting": "passed",
                   "payload_ready_demand_split": "passed",
                   "global_credit_bound": "passed"},
        "arms": {arm.name: {
            "configuration": asdict(arm),
            "payload_lines": measured[arm.name]["case"]["payload_lines"],
            "first_demands": measured[arm.name]["stats"]["first_demands"],
            "first_demand_hits": measured[arm.name]["stats"]["first_demand_hits"],
            "first_demand_misses": measured[arm.name]["stats"]["first_demand_misses"],
            "payload_first_demand": measured[arm.name]["stats"]["payload_first_demand"],
            "ready_first_demand": measured[arm.name]["stats"]["ready_first_demand"],
            "evictions": measured[arm.name]["stats"]["evictions"],
            "writebacks": measured[arm.name]["stats"]["writebacks"],
            "pushes": measured[arm.name]["stats"]["pushes"],
            "nc_writes": measured[arm.name]["stats"]["nc_writes"],
            "backing_read_bytes": measured[arm.name]["stats"]["backing_read_bytes"],
            "producer_backing_write_bytes":
                measured[arm.name]["stats"]["producer_backing_write_bytes"],
            "global_credit_peak_bytes":
                measured[arm.name]["case"]["trace"]["global_credit_peak_bytes"],
            "gate_sampling": measured[arm.name]["case"]["gate_sampling"],
        } for arm in ARMS},
    }


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_sweep(output, packets_per_flow=16, timeout=180):
    if packets_per_flow < 4 or timeout <= 0:
        raise ValueError("at least four packets per flow and a positive timeout are required")
    output.mkdir(parents=True, exist_ok=False)
    commands = []
    result = {"status": "running"}
    try:
        for arm in ARMS:
            command = [sys.executable, "-m", "cxl_nic.integration", "--device-type", "type2",
                       "--data-path", arm.path, "--host-llc-sets", str(arm.sets),
                       "--host-llc-ways", str(arm.ways), "--case", "adversarial",
                       "--packets-per-flow", str(packets_per_flow),
                       "--timeout", str(timeout), "--output", str(output / arm.name)]
            if arm.gate_lines is not None:
                command.extend(("--ncp-gate-resident-lines", str(arm.gate_lines)))
            if arm.sample_every_lines is not None:
                command.extend(("--ncp-gate-sample-every-lines", str(arm.sample_every_lines)))
            if arm.control_delay_lines:
                command.extend(("--ncp-gate-control-delay-lines", str(arm.control_delay_lines)))
            if arm.global_credit_bytes is not None:
                command.extend(("--global-push-credit-bytes", str(arm.global_credit_bytes)))
            commands.append(command)
            completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
            (output / f"{arm.name}.stdout.log").write_text(completed.stdout)
            (output / f"{arm.name}.stderr.log").write_text(completed.stderr)
            if completed.returncode:
                raise RuntimeError(f"{arm.name} exited with status {completed.returncode}")
        loaded = {arm.name: json.loads((output / arm.name / "result.json").read_text())
                  for arm in ARMS}
        result = validate_results(loaded, packets_per_flow)
        result.update(
            commands=commands,
            pins=PINS,
            result_sha256={arm.name: _digest(output / arm.name / "result.json") for arm in ARMS},
            source_sha256={
                str(path.relative_to(ROOT)): _digest(path)
                for directory in ("cxl_nic", "scripts", "tests")
                for path in sorted((ROOT / directory).glob("*"))
                if path.is_file() and path.suffix in (".py", ".sh")},
        )
    except Exception as error:
        result.update(status="failed", error=repr(error), commands=commands, pins=PINS)
        raise
    finally:
        (output / "commands.log").write_text(
            "\n".join(shlex.join(command) for command in commands) + ("\n" if commands else ""))
        (output / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--packets-per-flow", type=int, default=16)
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args(argv)
    result = run_sweep(args.output.resolve(), args.packets_per_flow, args.timeout)
    print(json.dumps({"status": result["status"], "arms": len(result["arms"]),
                      "result": str(args.output / "result.json")}, sort_keys=True))


if __name__ == "__main__":
    main()
