"""Run controlled cache/reorder timing sensitivities on matched policy arms."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, replace
import hashlib
import json
from pathlib import Path

from .timing import TimingConfig, generate_workload, run_matrix


POLICY_NAMES = ("B1", "D1", "D1-gated", "D1-host-control")
PAPER_ANCHORS = {
    "source": "https://doi.org/10.1145/3725843.3756102",
    "fpga_clock_mhz": 400,
    "cache_line_bytes": 64,
    "theoretical_rx_gbps": 204,
    "ncp_nc_write_approx_fraction_of_limit": 0.90,
    "derived_approx_ncp_nc_write_gbps": 184,
    "host_llc_mib": 60,
    "host_cpu_ghz": 2.2,
    "adaptive_gate_threshold_reported": False,
    "host_flag_sampling_interval_reported": False,
    "host_flag_control_latency_reported": False,
    "post_push_delay_cycles_reported": False,
}
BASE_CONFIG = TimingConfig(background_interval_ns=20,
                           background_working_set_lines=128,
                           ncp_gate_resident_lines=384)


@dataclass(frozen=True)
class SweepCase:
    name: str
    axis: str
    value: int
    flows: int = 2
    packets_per_flow: int = 32
    sizes: tuple[int, ...] = (64, 65, 256, 1500)
    config_changes: tuple[tuple[str, int], ...] = ()

    def config(self):
        return replace(BASE_CONFIG, **dict(self.config_changes))

    def workload(self):
        return generate_workload(
            flows=self.flows, packets_per_flow=self.packets_per_flow,
            interarrival_ns=80, reorder_jitter_ns=120,
            gap_every=8, gap_delay_ns=800, sizes=self.sizes, seed=1)


CASES = (
    SweepCase("gate-000", "gate_threshold_lines", 0,
              config_changes=(("ncp_gate_resident_lines", 0),)),
    SweepCase("gate-128", "gate_threshold_lines", 128,
              config_changes=(("ncp_gate_resident_lines", 128),)),
    SweepCase("gate-256", "gate_threshold_lines", 256,
              config_changes=(("ncp_gate_resident_lines", 256),)),
    SweepCase("gate-384", "gate_threshold_lines", 384),
    SweepCase("gate-513", "gate_threshold_lines", 513,
              config_changes=(("ncp_gate_resident_lines", 513),)),
    SweepCase("llc-128", "llc_capacity_lines", 128,
              config_changes=(("cache_sets", 16),
                              ("background_working_set_lines", 32),
                              ("ncp_gate_resident_lines", 96))),
    SweepCase("llc-256", "llc_capacity_lines", 256,
              config_changes=(("cache_sets", 32),
                              ("background_working_set_lines", 64),
                              ("ncp_gate_resident_lines", 192))),
    SweepCase("llc-512", "llc_capacity_lines", 512),
    SweepCase("cpu-020", "cpu_base_ns", 20,
              config_changes=(("cpu_base_ns", 20),)),
    SweepCase("cpu-040", "cpu_base_ns", 40),
    SweepCase("cpu-160", "cpu_base_ns", 160,
              config_changes=(("cpu_base_ns", 160),)),
    SweepCase("size-0064", "packet_size_bytes", 64, sizes=(64,)),
    SweepCase("size-0256", "packet_size_bytes", 256, sizes=(256,)),
    SweepCase("size-1500", "packet_size_bytes", 1500, sizes=(1500,)),
    SweepCase("flows-01", "flows", 1, flows=1, packets_per_flow=64),
    SweepCase("flows-02", "flows", 2),
    SweepCase("flows-04", "flows", 4, flows=4, packets_per_flow=16),
    SweepCase("flows-08", "flows", 8, flows=8, packets_per_flow=8),
    SweepCase("global-1536", "global_push_credit_bytes", 1536,
              config_changes=(("global_push_credit_bytes", 1536),)),
    SweepCase("global-3072", "global_push_credit_bytes", 3072,
              config_changes=(("global_push_credit_bytes", 3072),)),
    SweepCase("sample-0020", "ncp_gate_sample_interval_ns", 20,
              config_changes=(("ncp_gate_sample_interval_ns", 20),
                              ("ncp_gate_control_latency_ns", 100))),
    SweepCase("sample-0200", "ncp_gate_sample_interval_ns", 200,
              config_changes=(("ncp_gate_sample_interval_ns", 200),
                              ("ncp_gate_control_latency_ns", 100))),
    SweepCase("sample-1600", "ncp_gate_sample_interval_ns", 1600,
              config_changes=(("ncp_gate_sample_interval_ns", 1600),
                              ("ncp_gate_control_latency_ns", 100))),
    SweepCase("bandwidth-100", "link_bandwidth_gbps", 100),
    SweepCase("bandwidth-184", "link_bandwidth_gbps", 184,
              config_changes=(("link_bandwidth_gbps", 184),)),
    SweepCase("bandwidth-204", "link_bandwidth_gbps", 204,
              config_changes=(("link_bandwidth_gbps", 204),)),
    SweepCase("link-latency-050", "link_latency_ns", 50,
              config_changes=(("link_latency_ns", 50),)),
    SweepCase("link-latency-100", "link_latency_ns", 100),
    SweepCase("link-latency-200", "link_latency_ns", 200,
              config_changes=(("link_latency_ns", 200),)),
    SweepCase("nic-miss-100", "nic_miss_ns", 100,
              config_changes=(("nic_miss_ns", 100),)),
    SweepCase("nic-miss-250", "nic_miss_ns", 250),
    SweepCase("nic-miss-500", "nic_miss_ns", 500,
              config_changes=(("nic_miss_ns", 500),)),
)


def validate_cases(cases=CASES):
    names = [case.name for case in cases]
    if len(names) != len(set(names)):
        raise ValueError("sweep case names must be unique")
    for case in cases:
        if case.flows * case.packets_per_flow != 64:
            raise ValueError(f"{case.name}: sweep cases must retain 64 total packets")
        config = case.config()
        if case.axis == "llc_capacity_lines":
            if config.cache_sets * config.cache_ways != case.value:
                raise ValueError(f"{case.name}: cache capacity does not match its axis value")
            if (config.background_working_set_lines * 4 != case.value
                    or config.ncp_gate_resident_lines * 4 != case.value * 3):
                raise ValueError(f"{case.name}: capacity sweep must retain 1/4 background and 3/4 gate")
        if case.axis == "gate_threshold_lines" and config.ncp_gate_resident_lines != case.value:
            raise ValueError(f"{case.name}: gate threshold does not match its axis value")
        if case.axis in ("link_bandwidth_gbps", "link_latency_ns", "nic_miss_ns",
                         "global_push_credit_bytes", "ncp_gate_sample_interval_ns"):
            if getattr(config, case.axis) != case.value:
                raise ValueError(f"{case.name}: timing parameter does not match its axis value")
    return tuple(cases)


def _validate_result(case, result):
    if result.get("status") != "passed" or result.get("fairness_control") != "passed":
        raise ValueError(f"{case.name}: policy matrix or matched label control failed")
    if set(result.get("arms", ())) != set(POLICY_NAMES):
        raise ValueError(f"{case.name}: policy arms differ from the sweep")
    expected_config = asdict(case.config())
    for name, arm in result["arms"].items():
        if arm.get("packets") != 64 or arm.get("config") != expected_config:
            raise ValueError(f"{case.name}/{name}: work volume or configuration differs")
        payload = arm["payload_first_demand"]
        background = arm["background_demand"]
        if payload["hits"] + payload["misses"] != payload["lines"]:
            raise ValueError(f"{case.name}/{name}: payload denominator is inconsistent")
        if background["hits"] + background["misses"] != background["accesses"]:
            raise ValueError(f"{case.name}/{name}: background denominator is inconsistent")
        if arm["link_bytes"] != arm["producer_link_bytes"] + arm["cpu_nic_read_bytes"]:
            raise ValueError(f"{case.name}/{name}: link traffic is inconsistent")
        if (case.config().global_push_credit_bytes is not None
                and arm["global_credit_peak_bytes"] > case.config().global_push_credit_bytes):
            raise ValueError(f"{case.name}/{name}: global push budget exceeded")
        gate = arm["adaptive_gate"]
        decisions = gate["ncp_lines"] + gate["nc_write_lines"]
        if name == "D1-gated":
            if (decisions != payload["lines"]
                    or gate["threshold_resident_lines"] != case.config().ncp_gate_resident_lines
                    or gate["nc_write_bytes"] != gate["nc_write_lines"] * 64):
                raise ValueError(f"{case.name}: adaptive gate accounting is inconsistent")
            sample = arm["gate_sampling"]
            if (case.config().ncp_gate_sample_interval_ns is not None
                    and (sample["samples"] == 0
                         or sample["control_writes"] < sample["control_applies"])):
                raise ValueError(f"{case.name}: sampled gate accounting is inconsistent")
        elif decisions or gate["nc_write_bytes"]:
            raise ValueError(f"{case.name}/{name}: non-gated arm recorded gate decisions")


def _short(arm):
    background = arm["background_demand"]
    duration = arm["duration_ns"]
    return {
        "p50_ns": arm["delivery_latency_ns"]["p50"],
        "p99_ns": arm["delivery_latency_ns"]["p99"],
        "payload_first_hit_rate": arm["payload_first_demand"]["hit_rate"],
        "background_hit_rate": background["hit_rate"],
        "background_misses_per_us": (background["misses"] * 1000 / duration
                                      if duration else None),
        "producer_link_bytes": arm["producer_link_bytes"],
        "cpu_nic_read_bytes": arm["cpu_nic_read_bytes"],
        "nic_buffer_peak_bytes": arm["nic_buffer_peak_bytes"],
        "credit_stall_ns": sum(arm["credit_stall_ns"].values()),
        "global_credit_peak_bytes": arm["global_credit_peak_bytes"],
        "global_stall_ns": sum(arm["global_stall_ns"].values()),
        "adaptive_gate": arm["adaptive_gate"],
        "gate_sampling": arm["gate_sampling"],
        "backing_traffic_bytes": arm["backing_traffic_bytes"],
    }


def _validate_cross_cases(results):
    gate_cases = sorted((case["value"], case["arms"]) for case in results.values()
                        if case["axis"] == "gate_threshold_lines")
    gated = [arms["D1-gated"] for _, arms in gate_cases]
    ncp_lines = [arm["adaptive_gate"]["ncp_lines"] for arm in gated]
    if ncp_lines != sorted(ncp_lines):
        raise ValueError("gate threshold sweep did not monotonically increase NC-P choices")
    first_gate = gated[0]["adaptive_gate"]
    if first_gate["ncp_lines"] != 0 or first_gate["nc_write_lines"] == 0:
        raise ValueError("zero-threshold endpoint did not choose NC-write for every line")
    last_d1 = gate_cases[-1][1]["D1"]
    last_gated = gated[-1]
    if last_gated["adaptive_gate"]["nc_write_lines"] != 0:
        raise ValueError("above-capacity endpoint did not choose NC-P for every line")
    for key in set(last_d1) - {"adaptive_gate", "gate_sampling"}:
        if last_d1[key] != last_gated[key]:
            raise ValueError(f"above-capacity gate changed D1 behavior: {key}")


def run_sweep(output, cases=CASES):
    cases = validate_cases(cases)
    output.mkdir(parents=True, exist_ok=False)
    results = {}
    hashes = {}
    for case in cases:
        case_output = output / case.name
        case_output.mkdir()
        packets = case.workload()
        workload_data = "".join(json.dumps({"flow": packet.flow, "serial": packet.serial,
                                                "arrival_ns": packet.arrival_ns,
                                                "payload": packet.payload.hex()}, sort_keys=True) + "\n"
                                for packet in packets)
        (case_output / "workload.jsonl").write_text(workload_data)
        result = run_matrix(packets, case.config(), POLICY_NAMES, case_output)
        _validate_result(case, result)
        result.update(case=asdict(case), config=asdict(case.config()),
                      workload_sha256=hashlib.sha256(workload_data.encode()).hexdigest())
        result_path = case_output / "result.json"
        result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        hashes[case.name] = hashlib.sha256(result_path.read_bytes()).hexdigest()
        results[case.name] = {
            "axis": case.axis, "value": case.value,
            "arms": {name: _short(arm) for name, arm in result["arms"].items()}}
    _validate_cross_cases(results)
    root = Path(__file__).resolve().parent.parent
    sources = tuple(sorted((root / "cxl_nic").glob("*.py"))) + (
        root / "scripts/verify_timing_sweep.sh",)
    summary = {
        "status": "passed",
        "scope": ("controlled uncalibrated virtual-time sensitivities; reliable finite "
                  "reordering; 64 packets per case"),
        "policies": list(POLICY_NAMES),
        "paper_anchors": PAPER_ANCHORS,
        "unresolved_calibration": [
            "CXL one-way request latency",
            "host-memory and NIC-memory miss service",
            "adaptive gate threshold",
            "host flag sampling interval and control latency",
            "post-push delay cycles",
            "physical LLC indexing and replacement"],
        "checks": {"matched_label_control": "passed",
                   "ordered_delivery_and_conservation": "passed",
                   "adaptive_gate_accounting": "passed",
                   "gate_threshold_monotonicity": "passed",
                   "gate_d1_endpoint_invariance": "passed"},
        "cases": results,
        "result_sha256": hashes,
        "source_sha256": {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in sources},
    }
    (output / "result.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    result = run_sweep(args.output)
    print(json.dumps({"status": result["status"], "cases": len(result["cases"]),
                      "result": str(args.output / "result.json")}, sort_keys=True))


if __name__ == "__main__":
    main()
