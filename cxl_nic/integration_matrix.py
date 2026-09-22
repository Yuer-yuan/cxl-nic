"""Run and audit matched NC-P and delayed-DDIO guest integrations.

The matrix checks functional publication with a roomy simulated LLC, then uses
the same workload with a one-line LLC to exercise eviction and backing behavior.
An NC-P post-push NC-write arm exercises deliberate withdrawal before CPU demand.
Latency comparison remains in the deterministic timing model.
"""

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys

from .integration import PINS, ROOT


@dataclass(frozen=True)
class Arm:
    path: str
    sets: int
    ways: int
    case: str
    post_push: str = "none"
    gate_resident_lines: int | None = None


ARMS = {
    "ncp_default": Arm("ncp", 64, 8, "all"),
    "ddio_default": Arm("ddio", 64, 8, "all"),
    "ncp_pressure": Arm("ncp", 1, 1, "adversarial"),
    "ddio_pressure": Arm("ddio", 1, 1, "adversarial"),
    "ncp_withdraw": Arm("ncp", 64, 8, "adversarial", post_push="before-ready"),
    "ncp_gate": Arm("ncp", 64, 8, "adversarial", gate_resident_lines=32),
}
EXPECTED_CASES = {
    "default": {"adversarial": "passed", "early-ready": "expected_rejection",
                "corrupt-payload": "expected_rejection"},
    "pressure": {"adversarial": "passed"},
}
COUNTERS = ("pushes", "push_bytes", "first_demands", "first_demand_hits",
            "first_demand_misses", "evictions", "writebacks", "resident",
            "nc_writes", "nc_write_bytes", "gated_push_lines", "gated_nc_write_lines")
TRAFFIC_COUNTERS = ("backing_read_bytes", "first_demand_backing_bytes",
                    "dirty_writeback_bytes", "producer_backing_write_bytes")


def _case(result, mode):
    matches = [case for case in result.get("cases", ()) if case.get("mode") == mode]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {mode} case")
    return matches[0]


def _stats(result, path):
    case = _case(result, "adversarial")
    stats = case.get(path)
    if not isinstance(stats, dict):
        raise ValueError(f"adversarial case has no {path} statistics")
    missing = [name for name in COUNTERS
               if type(stats.get(name)) is not int or stats.get(name, -1) < 0]
    if missing:
        raise ValueError(f"{path} statistics have invalid counters: {missing}")
    if stats["first_demand_hits"] + stats["first_demand_misses"] != stats["first_demands"]:
        raise ValueError(f"{path} first-demand denominator is inconsistent")
    for name in TRAFFIC_COUNTERS:
        counter = stats.get(name)
        if (not isinstance(counter, dict) or set(counter) != {"host", "nic"}
                or any(type(value) is not int or value < 0 for value in counter.values())):
            raise ValueError(f"{path} has invalid {name}")
    return stats


def _work(stats):
    return {name: stats[name] for name in ("pushes", "push_bytes", "first_demands")}


def _short(stats):
    return {name: stats[name] for name in COUNTERS + TRAFFIC_COUNTERS}


def compare_results(results):
    """Validate the integration matrix and return its concise evidence summary."""
    if set(results) != set(ARMS):
        raise ValueError(f"matrix arms differ: expected {sorted(ARMS)}, got {sorted(results)}")

    stats = {}
    for name, arm in ARMS.items():
        result = results[name]
        if result.get("status") != "passed":
            raise ValueError(f"{name} did not pass")
        if result.get("device_type") != "type2" or result.get("data_path") != arm.path:
            raise ValueError(f"{name} endpoint or data path differs from the matrix")
        if result.get("ncp_post_push") != arm.post_push:
            raise ValueError(f"{name} post-push policy differs from the matrix")
        if result.get("ncp_gate_resident_lines") != arm.gate_resident_lines:
            raise ValueError(f"{name} adaptive-gate policy differs from the matrix")
        if result.get("pins") != PINS:
            raise ValueError(f"{name} third-party pins differ from the audited revisions")
        expected = EXPECTED_CASES["default" if arm.case == "all" else "pressure"]
        actual = {case.get("mode"): case.get("status") for case in result.get("cases", ())}
        if len(result.get("cases", ())) != len(expected) or actual != expected:
            raise ValueError(f"{name} case outcomes differ: {actual}")
        stats[name] = _stats(result, arm.path)
        if (stats[name].get("configured_sets") != arm.sets
                or stats[name].get("configured_ways") != arm.ways):
            raise ValueError(f"{name} host LLC geometry differs")

    for suffix in ("default", "pressure"):
        ncp = stats[f"ncp_{suffix}"]
        ddio = stats[f"ddio_{suffix}"]
        if _work(ncp) != _work(ddio):
            raise ValueError(f"{suffix} NC-P/DDIO work volumes differ")
        if ncp["pushes"] <= 0 or ncp["first_demands"] <= 0:
            raise ValueError(f"{suffix} did not exercise cache injection and demand")

    for name in ("ncp_default", "ddio_default"):
        arm = stats[name]
        if arm["first_demand_hits"] != arm["first_demands"] or arm["first_demand_misses"]:
            raise ValueError(f"{name} did not preserve every line until first demand")

    for name in ("ncp_pressure", "ddio_pressure"):
        if stats[name]["first_demand_misses"] <= 0:
            raise ValueError(f"{name} did not exercise LLC pressure")
    if stats["ncp_pressure"]["writebacks"] <= 0:
        raise ValueError("NC-P pressure did not exercise dirty backing writeback")
    if stats["ddio_pressure"]["writebacks"] != 0:
        raise ValueError("DDIO clean eviction unexpectedly wrote back a line")

    for name, policy in ARMS.items():
        arm = stats[name]
        home = "nic" if policy.path == "ncp" else "host"
        other = "host" if policy.path == "ncp" else "nic"
        if (arm["first_demand_backing_bytes"][home] != arm["first_demand_misses"] * 64
                or arm["first_demand_backing_bytes"][other] != 0):
            raise ValueError(f"{name} first-demand misses used the wrong backing home")
        if (arm["dirty_writeback_bytes"][home] != arm["writebacks"] * 64
                or arm["dirty_writeback_bytes"][other] != 0):
            raise ValueError(f"{name} dirty writebacks used the wrong backing home")
        expected_producer = arm["pushes"] * 64 if policy.path == "ddio" else 0
        if (arm["producer_backing_write_bytes"] !=
                {"host": expected_producer, "nic": arm["nc_writes"] * 64}):
            raise ValueError(f"{name} producer backing traffic differs")
        if policy.path == "ddio" and (arm["nc_writes"] or arm["nc_write_bytes"]):
            raise ValueError(f"{name} unexpectedly used NC-write")
        if name != "ncp_gate" and (arm["gated_push_lines"] or arm["gated_nc_write_lines"]):
            raise ValueError(f"{name} unexpectedly used adaptive gating")

    withdrawn = stats["ncp_withdraw"]
    if (withdrawn["nc_writes"] <= 0
            or withdrawn["first_demand_misses"] < withdrawn["nc_writes"]
            or withdrawn["nc_write_bytes"] <= 0):
        raise ValueError("post-push NC-write did not force NIC-backing fallback")

    gated = stats["ncp_gate"]
    if (gated["gated_push_lines"] <= 0 or gated["gated_nc_write_lines"] <= 0
            or gated["gated_nc_write_lines"] != gated["nc_writes"]
            or gated["first_demand_misses"] < gated["gated_nc_write_lines"]):
        raise ValueError("adaptive gate did not exercise both write policies")

    return {
        "status": "passed",
        "scope": ("matched functional guest integration with a finite simulated host LLC; "
                  "reliable finite reordering; no physical LLC or latency claim"),
        "checks": {
            "publication_and_negative_controls": "passed",
            "matched_work_volume": "passed",
            "default_first_demand_hits": "passed",
            "pressure_eviction": "passed",
            "backing_semantics": "passed",
            "backing_home_traffic": "passed",
            "post_push_withdrawal": "passed",
            "adaptive_push_write_gate": "passed",
        },
        "arms": {name: _short(stats[name]) for name in ARMS},
    }


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--packets-per-flow", type=int, default=16)
    parser.add_argument("--timeout", type=float, default=180)
    args = parser.parse_args(argv)
    if args.packets_per_flow < 4 or args.timeout <= 0:
        parser.error("at least four packets per flow and a positive timeout are required")

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    commands = []
    result = {"status": "running"}
    try:
        for name, arm in ARMS.items():
            command = [sys.executable, "-m", "cxl_nic.integration", "--device-type", "type2",
                       "--data-path", arm.path, "--host-llc-sets", str(arm.sets),
                       "--host-llc-ways", str(arm.ways), "--case", arm.case,
                       "--ncp-post-push", arm.post_push,
                       "--packets-per-flow", str(args.packets_per_flow),
                       "--timeout", str(args.timeout), "--output", str(output / name)]
            if arm.gate_resident_lines is not None:
                command.extend(("--ncp-gate-resident-lines", str(arm.gate_resident_lines)))
            commands.append(command)
            completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
            (output / f"{name}.stdout.log").write_text(completed.stdout)
            (output / f"{name}.stderr.log").write_text(completed.stderr)
            if completed.returncode:
                raise RuntimeError(f"{name} exited with status {completed.returncode}")

        loaded = {name: json.loads((output / name / "result.json").read_text()) for name in ARMS}
        result = compare_results(loaded)
        result.update(
            commands=commands,
            pins=PINS,
            result_sha256={name: _digest(output / name / "result.json") for name in ARMS},
            source_sha256={
                "cxl_nic/integration.py": _digest(ROOT / "cxl_nic/integration.py"),
                "cxl_nic/integration_matrix.py": _digest(ROOT / "cxl_nic/integration_matrix.py"),
                "scripts/verify_integration_cache.sh":
                    _digest(ROOT / "scripts/verify_integration_cache.sh"),
            },
        )
    except Exception as error:
        result.update(status="failed", error=repr(error), commands=commands, pins=PINS)
        raise
    finally:
        (output / "commands.log").write_text(
            "\n".join(shlex.join(command) for command in commands) + ("\n" if commands else ""))
        (output / "comparison.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": result["status"], "result": str(output / "comparison.json")}))


if __name__ == "__main__":
    main()
