"""Paired, trace-driven LLC hypotheses; event order is not physical time.

Replay validated publication/guest observations through a shared finite cache.
This is a shadow experiment, not an implementation of CXL.cache transactions
or a measurement of the QEMU guest's cache hit rate.
"""

import argparse
from dataclasses import asdict, dataclass
import hashlib
import heapq
import json
from pathlib import Path
import struct

from .cache import Cache
from .checker import validate_trace
from .verify import save_trace


FIELDS = ("flow", "serial", "slot", "generation", "length")
LINE = 64
SLOT_BASE = 0x10000
SLOT_STRIDE = 0x1000
PAYLOAD_OFFSET = 256
BACKGROUND_BASE = 1 << 48


class ReplayError(ValueError):
    pass


@dataclass(frozen=True)
class ReplayConfig:
    sets: int = 64
    ways: int = 8
    background_lines: int = 0
    withdraw_after_events: int | None = None

    def __post_init__(self):
        for field in ("sets", "ways"):
            if type(getattr(self, field)) is not int or getattr(self, field) <= 0:
                raise ReplayError(f"{field} must be a positive integer")
        if type(self.background_lines) is not int or self.background_lines < 0:
            raise ReplayError("background_lines must be a nonnegative integer")
        delay = self.withdraw_after_events
        if delay is not None and (type(delay) is not int or delay < 0):
            raise ReplayError("withdraw_after_events must be a nonnegative integer or None")


def identity(token):
    return tuple(token[name] for name in FIELDS[:4])


class Replay:
    """The payload is immutable between publication and CPU release.

    Generations guard deferred actions, never cache tags. Both packet addresses
    and CPU background references compete in the same set-associative cache.
    """

    def __init__(self, events, *, home="host", admission=None, config=ReplayConfig()):
        self.events = list(events)
        self.validation = validate_trace(self.events)
        if home not in ("host", "nic"):
            raise ReplayError("home must be host or nic")
        self.config = config
        self.home = home
        self.admission = tuple(range(config.ways)) if admission is None else tuple(admission)
        if (len(set(self.admission)) != len(self.admission)
                or any(type(way) is not int or not 0 <= way < config.ways for way in self.admission)):
            raise ReplayError("admission must contain distinct valid way indices")
        self.admission = tuple(sorted(self.admission))
        self.cache = Cache(config.sets, config.ways)
        protocol_config = self.events[0]
        self.window = protocol_config["window"]
        self.maximum = protocol_config["max_packet_bytes"]
        if self.maximum > SLOT_STRIDE - PAYLOAD_OFFSET:
            raise ReplayError("packet exceeds the fixed 4 KiB slot layout")
        self.flows = sorted(int(flow) for flow in protocol_config["initial_serials"])
        self.flow_indices = {flow: index for index, flow in enumerate(self.flows)}
        if SLOT_BASE + len(self.flows) * self.window * SLOT_STRIDE >= BACKGROUND_BASE:
            raise ReplayError("packet and background address ranges overlap")
        for flow in self.flows:
            for slot in range(self.window):
                base = self.base({"flow": flow, "slot": slot})
                for offset in (0, 64, 128):
                    self.cache.define(base + offset, home)
                for offset in range(0, self.maximum, LINE):
                    self.cache.define(base + PAYLOAD_OFFSET + offset, home)
        self.active = {}
        self.packets = {}
        self.admitted = {}
        self.deferred = []
        self.timer_id = 0
        self.background_index = 0
        self.operations = []
        self.demands = []
        self.counts = {name: 0 for name in (
            "packets", "payload_first_hits", "payload_first_misses", "payload_push_lines",
            "admitted_push_lines", "admitted_absent_at_first_demand",
            "withdrawals_scheduled", "withdrawals_applied", "withdrawals_stale",
            "withdrawn_lines")}

    def base(self, token):
        return SLOT_BASE + (self.flow_indices[token["flow"]] * self.window + token["slot"]) * SLOT_STRIDE

    def log(self, step, operation, **fields):
        self.operations.append({"step": step, "operation": operation, **fields})

    def service_deferred(self, step):
        while self.deferred and self.deferred[0][0] <= step:
            due, _, token = heapq.heappop(self.deferred)
            key = identity(token)
            slot = token["flow"], token["slot"]
            if self.active.get(slot) != key:
                self.counts["withdrawals_stale"] += 1
                self.log(step, "withdraw_stale", due=due, token=token)
                continue
            payload = self.packets[key]
            # Full-line overwrite and invalidate, without writing back stale dirty data.
            # This action is safe only for the immutable RX payload modeled here.
            for offset in range(0, len(payload), LINE):
                self.cache.bypass_write(self.base(token) + PAYLOAD_OFFSET + offset,
                                        payload[offset:offset + LINE].ljust(LINE, b"\0"))
                self.counts["withdrawn_lines"] += 1
            self.counts["withdrawals_applied"] += 1
            self.log(step, "withdraw_applied", due=due, token=token)

    def visible(self, event, step):
        token = event["token"]
        base = self.base(token)
        kind = event["kind"]
        if kind == "payload":
            address = base + PAYLOAD_OFFSET + event["offset"]
            data = bytes.fromhex(event["data"])
        elif kind == "descriptor":
            address = base + FIELDS.index(event["field"]) * 8
            data = struct.pack("<Q", event["value"])
        else:
            address = base + 64
            data = struct.pack("<Q", token["generation"])
        hit = self.cache.io_write(address, data, self.admission)
        self.log(step, "io_write", token=token, kind=kind, address=address, hit=hit,
                 resident=self.cache.resident(address))
        if kind == "payload":
            self.counts["payload_push_lines"] += 1
            admitted = self.cache.resident(address)
            self.admitted[identity(token), event["offset"]] = admitted
            self.counts["admitted_push_lines"] += int(admitted)
        elif kind == "ready" and self.config.withdraw_after_events is not None:
            due = step + self.config.withdraw_after_events
            self.timer_id += 1
            heapq.heappush(self.deferred, (due, self.timer_id, dict(token)))
            self.counts["withdrawals_scheduled"] += 1
            self.log(step, "withdraw_scheduled", token=token, due=due)
            self.service_deferred(step)

    def consume(self, event, step):
        token = event["token"]
        base = self.base(token)
        for _ in range(self.config.background_lines):
            address = BACKGROUND_BASE + self.background_index * LINE
            self.background_index += 1
            self.cache.define(address, "host")
            self.cache.read(address, LINE, category="background")
        if self.config.background_lines:
            self.log(step, "background", lines=self.config.background_lines)
        ready, _ = self.cache.read(base + 64, 8, category="ready")
        descriptor, _ = self.cache.read(base, 40, category="descriptor")
        actual_descriptor = dict(zip(FIELDS, struct.unpack("<5Q", descriptor)))
        if struct.unpack("<Q", ready)[0] != token["generation"] or actual_descriptor != event["descriptor"]:
            raise ReplayError("cache returned stale ready/descriptor data")
        expected = self.packets[identity(token)]
        observed = bytearray()
        for offset in range(0, len(expected), LINE):
            address = base + PAYLOAD_OFFSET + offset
            if self.admitted[identity(token), offset] and not self.cache.resident(address):
                self.counts["admitted_absent_at_first_demand"] += 1
            data, hit = self.cache.read(address, min(LINE, len(expected) - offset), category="payload")
            observed.extend(data)
            self.counts["payload_first_hits" if hit else "payload_first_misses"] += 1
            record = {"token": token, "offset": offset, "address": address,
                      "hit": hit, "source": "llc" if hit else self.home}
            self.demands.append(record)
            self.log(step, "payload_first_demand", **record)
        if bytes(observed) != expected or bytes(observed).hex() != event["payload"]:
            raise ReplayError("modeled cache bytes differ from ingress/CPU observations")
        self.counts["packets"] += 1

    def run(self):
        for step, event in enumerate(self.events):
            self.service_deferred(step)
            name = event["event"]
            if name == "receive":
                token = event["token"]
                self.active[token["flow"], token["slot"]] = identity(token)
                self.packets[identity(token)] = bytes.fromhex(event["payload"])
            elif name == "visible":
                self.visible(event, step)
            elif name == "consume":
                self.consume(event, step)
            elif name == "release":
                token = event["token"]
                self.cache.cpu_write(self.base(token) + 128, struct.pack("<Q", token["generation"]))
                del self.active[token["flow"], token["slot"]]
                self.log(step, "cpu_release", token=token)
        if self.active:
            raise ReplayError("replay ended with live slots")
        # Retired-session timers must be canceled by ownership, without changing cache data.
        while self.deferred:
            self.service_deferred(self.deferred[0][0])
        demand_count = self.counts["payload_first_hits"] + self.counts["payload_first_misses"]
        if demand_count != self.counts["payload_push_lines"]:
            raise ReplayError("first-demand denominator differs from injected payload lines")
        before_flush = self.cache.snapshot()
        self.cache.flush()
        return {"config": asdict(self.config), "home": self.home,
                "admission": list(self.admission), "protocol": self.validation,
                "counts": self.counts,
                "payload_first_demand_hit_rate": self.counts["payload_first_hits"] / demand_count if demand_count else None,
                "cache_before_final_flush": before_flush,
                "cache_after_final_flush": self.cache.snapshot()}


def paired_replay(events, *, config=ReplayConfig(), ddio_admission=None, ncp_admission=None, output=None):
    """Identical reorder/credit/issue/completion/consume events for every arm."""
    events = list(events)
    outcomes = {}
    runs = {}
    for name, home, admission in (("ddio-host", "host", ddio_admission),
                                  ("ncp-nic", "nic", ncp_admission),
                                  ("ncp-host-control", "host", ncp_admission)):
        # Optional cache withdrawal is a separate CXL hypothesis; baseline is unchanged.
        arm_config = config if name != "ddio-host" else ReplayConfig(config.sets, config.ways, config.background_lines)
        run = Replay(events, home=home, admission=admission, config=arm_config)
        outcomes[name] = run.run()
        runs[name] = run
        if output is not None:
            save_trace(output / f"{name}.jsonl", run.operations)
    matched = (runs["ddio-host"].admission == runs["ncp-host-control"].admission
               and config.withdraw_after_events is None)
    if matched:
        if outcomes["ddio-host"] != outcomes["ncp-host-control"]:
            raise ReplayError("changing only the protocol label changed the result")
        if runs["ddio-host"].operations != runs["ncp-host-control"].operations:
            raise ReplayError("label invariance failed at an intermediate operation")
        # Changing home alone must not secretly change LLC capacity or insertion policy.
        for host, nic in zip(runs["ddio-host"].demands, runs["ncp-nic"].demands, strict=True):
            if {k: v for k, v in host.items() if k != "source"} != {k: v for k, v in nic.items() if k != "source"}:
                raise ReplayError("home-only change unexpectedly changed cache hits")
    return {"status": "passed", "arms": outcomes,
            "label_invariance": "passed" if matched else "not_applicable_different_policy",
            "scope": "trace-driven symbolic LLC; identical event order, no physical timing or CXL.cache transactions"}


def admission_argument(value, ways):
    if value == "all":
        return tuple(range(ways))
    if value == "none":
        return ()
    return tuple(int(part) for part in value.split(","))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sets", type=int, default=64)
    parser.add_argument("--ways", type=int, default=8)
    parser.add_argument("--background-lines", type=int, default=0)
    parser.add_argument("--ddio-ways", default="all", help="all, none, or comma-separated way indices")
    parser.add_argument("--ncp-ways", default="all", help="all, none, or comma-separated way indices")
    parser.add_argument("--withdraw-after-events", type=int)
    args = parser.parse_args(argv)
    config = ReplayConfig(args.sets, args.ways, args.background_lines, args.withdraw_after_events)
    ddio = admission_argument(args.ddio_ways, args.ways)
    ncp = admission_argument(args.ncp_ways, args.ways)
    data = args.trace.read_bytes()
    events = [json.loads(line) for line in data.splitlines()]
    args.output.mkdir(parents=True, exist_ok=False)
    result = {"status": "running", "trace_sha256": hashlib.sha256(data).hexdigest(),
              "trace_path": str(args.trace.resolve())}
    try:
        result.update(paired_replay(events, config=config, ddio_admission=ddio,
                                    ncp_admission=ncp, output=args.output))
        root = Path(__file__).resolve().parent.parent
        result["source_sha256"] = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                                   for path in sorted((root / "cxl_nic").glob("*.py"))}
    except Exception as error:
        result.update(status="failed", error=repr(error))
        raise
    finally:
        (args.output / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": result["status"], "label_invariance": result["label_invariance"],
                      "first_payload_hit_rate": {name: arm["payload_first_demand_hit_rate"]
                                                 for name, arm in result["arms"].items()},
                      "result": str(args.output / "result.json")}))


if __name__ == "__main__":
    main()
