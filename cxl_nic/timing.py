"""Deterministic virtual-time model for reliable, finitely reordered packets.

The model compares cache-injection policies on one identical arrival trace.  It
does not use wall time and does not claim to implement PCIe or CXL transactions.
Every packet is complete, has a sender sequence number, and eventually arrives;
loss, retransmission, checksums, and timeout recovery are intentionally excluded.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
import hashlib
import heapq
import json
import math
from pathlib import Path
import random
import struct

from .cache import Cache, LINE_BYTES


PACKET_BASE = 1 << 32
DESCRIPTOR_OFFSET = 0
READY_OFFSET = 64
RELEASE_OFFSET = 128
PAYLOAD_OFFSET = 256
BACKGROUND_BASE = 1 << 52


class TimingError(ValueError):
    pass


def aligned_size(size):
    return (size + LINE_BYTES - 1) // LINE_BYTES * LINE_BYTES


@dataclass(frozen=True)
class Packet:
    flow: int
    serial: int
    arrival_ns: int
    payload: bytes

    def __post_init__(self):
        if type(self.flow) is not int or self.flow < 0:
            raise TimingError("flow must be a nonnegative integer")
        if type(self.serial) is not int or self.serial < 0:
            raise TimingError("serial must be a nonnegative integer")
        if type(self.arrival_ns) is not int or self.arrival_ns < 0:
            raise TimingError("arrival_ns must be a nonnegative integer")
        if not isinstance(self.payload, bytes) or not self.payload:
            raise TimingError("payload must be nonempty immutable bytes")
        if len(self.payload) > 1500:
            raise TimingError("payload exceeds the modeled Ethernet MTU")


@dataclass(frozen=True)
class Policy:
    name: str
    family: str
    home: str
    reorder_before_push: bool
    use_credit: bool
    push_payload: bool = True
    cpu_reorder: bool = False

    def __post_init__(self):
        if self.family not in ("ddio", "ncp", "demand"):
            raise TimingError("unknown policy family")
        if self.home not in ("host", "nic"):
            raise TimingError("policy home must be host or nic")
        if not isinstance(self.name, str) or not self.name:
            raise TimingError("policy name must be nonempty")


POLICIES = {
    "A": Policy("A", "ddio", "host", False, False, True, True),
    "B0": Policy("B0", "ddio", "host", True, False),
    "B1": Policy("B1", "ddio", "host", True, True),
    "C": Policy("C", "ncp", "nic", False, False),
    "D0": Policy("D0", "ncp", "nic", True, False),
    "D1": Policy("D1", "ncp", "nic", True, True),
    "E": Policy("E", "demand", "nic", True, True, False),
    # Same mechanism and host backing as B1.  It is a mandatory label-invariance
    # control, not an additional architectural proposal.
    "D1-host-control": Policy("D1-host-control", "ncp", "host", True, True),
}


@dataclass(frozen=True)
class TimingConfig:
    cache_sets: int = 64
    cache_ways: int = 8
    packet_stride_lines: int = 129
    ddio_ways: tuple[int, ...] | None = None
    ncp_ways: tuple[int, ...] | None = None
    link_bandwidth_gbps: int = 100
    link_latency_ns: int = 100
    cpu_base_ns: int = 40
    llc_hit_ns: int = 12
    host_miss_ns: int = 90
    nic_miss_ns: int = 250
    push_credit_bytes_per_flow: int = 3072
    nic_buffer_bytes: int = 8 << 20
    cpu_reorder_buffer_bytes: int = 8 << 20
    background_interval_ns: int | None = None
    background_working_set_lines: int = 0
    ncp_withdraw_ns: int | None = None
    max_time_ns: int = 10_000_000

    def __post_init__(self):
        positive = ("cache_sets", "cache_ways", "packet_stride_lines", "link_bandwidth_gbps",
                    "link_latency_ns", "cpu_base_ns", "llc_hit_ns",
                    "host_miss_ns", "nic_miss_ns", "push_credit_bytes_per_flow",
                    "nic_buffer_bytes", "cpu_reorder_buffer_bytes", "max_time_ns")
        for name in positive:
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise TimingError(f"{name} must be a positive integer")
        for name in ("background_interval_ns", "ncp_withdraw_ns"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value < 0):
                raise TimingError(f"{name} must be a nonnegative integer or None")
        if self.background_interval_ns == 0:
            raise TimingError("background_interval_ns must be positive when enabled")
        if self.packet_stride_lines * LINE_BYTES < PAYLOAD_OFFSET + 1500:
            raise TimingError("packet_stride_lines cannot fit metadata and a 1500-byte packet")
        if type(self.background_working_set_lines) is not int or self.background_working_set_lines < 0:
            raise TimingError("background_working_set_lines must be nonnegative")
        if (self.background_working_set_lines == 0) != (self.background_interval_ns is None):
            raise TimingError("background interval and working set must be enabled together")
        for name in ("ddio_ways", "ncp_ways"):
            value = getattr(self, name)
            if value is None:
                continue
            if (not isinstance(value, tuple) or len(set(value)) != len(value)
                    or any(type(way) is not int or not 0 <= way < self.cache_ways for way in value)):
                raise TimingError(f"{name} must contain distinct valid way indices")

    def admission(self, family):
        value = self.ddio_ways if family == "ddio" else self.ncp_ways
        return tuple(range(self.cache_ways)) if value is None else tuple(sorted(value))


@dataclass
class _PacketState:
    packet: Packet
    index: int
    base: int
    charge: int
    arrived: bool = False
    issued: bool = False
    data_complete: bool = False
    publishing: bool = False
    ready: bool = False
    consuming: bool = False
    cpu_done: bool = False
    cpu_buffered: bool = False
    buffer_released: bool = False
    released: bool = False
    credit_reserved: bool = False
    pending_payload_lines: int = 0
    issue_ns: int | None = None
    ready_ns: int | None = None
    consume_ns: int | None = None
    processing_done_ns: int | None = None
    delivery_ns: int | None = None
    visible_ns: dict[int, int] = field(default_factory=dict)
    admitted: dict[int, bool] = field(default_factory=dict)


def payload_for(flow, serial, size):
    blocks = [hashlib.sha256(f"timing:{flow}:{serial}:{block}".encode()).digest()
              for block in range((size + 31) // 32)]
    return b"".join(blocks)[:size]


def validate_workload(packets):
    packets = tuple(packets)
    if not packets:
        raise TimingError("workload must contain packets")
    seen = set()
    by_flow = {}
    for packet in packets:
        if not isinstance(packet, Packet):
            raise TimingError("workload entries must be Packet instances")
        key = packet.flow, packet.serial
        if key in seen:
            raise TimingError("duplicate flow/serial in reliable workload")
        seen.add(key)
        by_flow.setdefault(packet.flow, []).append(packet.serial)
    initial = {}
    for flow, serials in by_flow.items():
        ordered = sorted(serials)
        if ordered != list(range(ordered[0], ordered[-1] + 1)):
            raise TimingError("reliable workload must contain every serial in each flow")
        initial[flow] = ordered[0]
    return packets, initial


def generate_workload(*, flows=2, packets_per_flow=64, interarrival_ns=80,
                      reorder_jitter_ns=120, gap_every=8, gap_delay_ns=800,
                      sizes=(64, 65, 256, 1500), seed=1):
    integers = {"flows": flows, "packets_per_flow": packets_per_flow,
                "interarrival_ns": interarrival_ns, "reorder_jitter_ns": reorder_jitter_ns,
                "gap_every": gap_every, "gap_delay_ns": gap_delay_ns, "seed": seed}
    if any(type(value) is not int for value in integers.values()):
        raise TimingError("workload generator arguments must be integers")
    if flows <= 0 or packets_per_flow <= 0 or interarrival_ns <= 0:
        raise TimingError("flows, packet count, and interarrival must be positive")
    if reorder_jitter_ns < 0 or gap_delay_ns < 0 or gap_every <= 0:
        raise TimingError("jitter/delay must be nonnegative and gap_every positive")
    if (not isinstance(sizes, tuple) or not sizes
            or any(type(size) is not int or not 1 <= size <= 1500 for size in sizes)):
        raise TimingError("sizes must be a nonempty tuple of 1..1500 byte integers")
    rng = random.Random(seed)
    packets = []
    for flow in range(flows):
        for serial in range(packets_per_flow):
            arrival = serial * interarrival_ns + flow * max(1, interarrival_ns // flows)
            arrival += rng.randrange(reorder_jitter_ns + 1)
            if serial % gap_every == 0:
                arrival += gap_delay_ns
            size = sizes[(serial + flow) % len(sizes)]
            packets.append(Packet(flow, serial, arrival, payload_for(flow, serial, size)))
    return tuple(sorted(packets, key=lambda packet: (packet.arrival_ns, packet.flow, packet.serial)))


def _nearest_rank(values, percentile):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


class Simulation:
    """One policy arm; all event timestamps are integer virtual nanoseconds."""

    def __init__(self, packets, policy, config=TimingConfig()):
        self.packets, self.initial = validate_workload(packets)
        if isinstance(policy, str):
            try:
                policy = POLICIES[policy]
            except KeyError as error:
                raise TimingError(f"unknown policy {policy}") from error
        if not isinstance(policy, Policy):
            raise TimingError("policy must be a Policy or known policy name")
        self.policy = policy
        self.config = config
        self.admission = config.admission(policy.family)
        self.cache = Cache(config.cache_sets, config.cache_ways)
        self.flows = sorted(self.initial)
        self.states = {}
        self.by_index = {}
        for index, packet in enumerate(sorted(self.packets, key=lambda item: (item.flow, item.serial))):
            base = PACKET_BASE + index * config.packet_stride_lines * LINE_BYTES
            state = _PacketState(packet, index, base, aligned_size(len(packet.payload)))
            self.states[packet.flow, packet.serial] = state
            self.by_index[index] = state
            self.cache.define(base + DESCRIPTOR_OFFSET, policy.home)
            self.cache.define(base + READY_OFFSET, policy.home)
            self.cache.define(base + RELEASE_OFFSET, policy.home)
            padded = packet.payload.ljust(state.charge, b"\0")
            for offset in range(0, state.charge, LINE_BYTES):
                initial = padded[offset:offset + LINE_BYTES] if policy.home == "nic" else bytes(LINE_BYTES)
                self.cache.define(base + PAYLOAD_OFFSET + offset, policy.home, initial)
        for line in range(config.background_working_set_lines):
            self.cache.define(BACKGROUND_BASE + line * LINE_BYTES, "host",
                              bytes([line & 255]) * LINE_BYTES)
        self.events = []
        self._event_id = 0
        self.log = []
        self.link_available_ns = 0
        self.link_bytes = 0
        self.producer_link_bytes = 0
        self.cpu_nic_read_bytes = 0
        self.payload_push_bytes = 0
        self.cpu_scheduled = False
        self.cpu_round_robin = 0
        self.next_issue = dict(self.initial)
        self.next_publish = dict(self.initial)
        self.next_consume = dict(self.initial)
        self.credit = dict.fromkeys(self.flows, 0)
        self.credit_peak = dict.fromkeys(self.flows, 0)
        self.credit_stall_start = dict.fromkeys(self.flows, None)
        self.credit_stall_ns = dict.fromkeys(self.flows, 0)
        self.credit_stall_events = dict.fromkeys(self.flows, 0)
        self.nic_buffer = 0
        self.nic_buffer_peak = 0
        self.cpu_reorder_buffer = 0
        self.cpu_reorder_buffer_peak = 0
        self.background_index = 0
        self.first_hits = 0
        self.first_misses = 0
        self.admitted_absent = 0
        self.withdrawals = 0
        self.delivered = []
        self.demand_records = []
        for state in self.states.values():
            self._schedule(state.packet.arrival_ns, "arrival", state.index)
        if config.background_interval_ns is not None:
            self._schedule(0, "background")

    def _schedule(self, time_ns, kind, *arguments):
        self._event_id += 1
        heapq.heappush(self.events, (time_ns, self._event_id, kind, arguments))

    def _record(self, time_ns, event, **fields):
        self.log.append({"time_ns": time_ns, "event": event, **fields})

    def _link_line(self, now, kind, *arguments):
        start = max(now, self.link_available_ns)
        serialization = math.ceil(LINE_BYTES * 8 / self.config.link_bandwidth_gbps)
        self.link_available_ns = start + serialization
        complete = self.link_available_ns + self.config.link_latency_ns
        self.link_bytes += LINE_BYTES
        self.producer_link_bytes += LINE_BYTES
        self._schedule(complete, kind, *arguments)
        return start, complete

    def _cpu_access_complete(self, cursor, hit):
        if hit:
            return cursor + self.config.llc_hit_ns
        if self.policy.home == "host":
            return cursor + self.config.host_miss_ns
        # A NIC-home miss is a demand fetch over the same modeled link.  The
        # configured miss value is device-memory/backing service after the
        # serialized request; it is not a measured hardware latency.
        start = max(cursor, self.link_available_ns)
        serialization = math.ceil(LINE_BYTES * 8 / self.config.link_bandwidth_gbps)
        self.link_available_ns = start + serialization
        self.link_bytes += LINE_BYTES
        self.cpu_nic_read_bytes += LINE_BYTES
        return self.link_available_ns + self.config.link_latency_ns + self.config.nic_miss_ns

    def _descriptor(self, state):
        packet = state.packet
        return struct.pack("<5Q", packet.flow, packet.serial, state.index, 1,
                           len(packet.payload)).ljust(LINE_BYTES, b"\0")

    def _issue(self, state, now):
        if state.issued:
            raise TimingError("packet issued twice")
        state.issued = True
        state.issue_ns = now
        if self.policy.use_credit:
            flow = state.packet.flow
            self.credit[flow] += state.charge
            self.credit_peak[flow] = max(self.credit_peak[flow], self.credit[flow])
            state.credit_reserved = True
            if self.credit_stall_start[flow] is not None:
                self.credit_stall_ns[flow] += now - self.credit_stall_start[flow]
                self.credit_stall_start[flow] = None
        self._record(now, "issue", policy=self.policy.name, flow=state.packet.flow,
                     serial=state.packet.serial, sequence_wait_ns=now - state.packet.arrival_ns)
        if not self.policy.push_payload:
            state.data_complete = True
            self._try_publish(state.packet.flow, now, state)
            return
        state.pending_payload_lines = state.charge // LINE_BYTES
        padded = state.packet.payload.ljust(state.charge, b"\0")
        for offset in range(0, state.charge, LINE_BYTES):
            self._link_line(now, "payload_visible", state.index, offset,
                            padded[offset:offset + LINE_BYTES])
            self.payload_push_bytes += LINE_BYTES

    def _try_issue(self, flow, now):
        if not self.policy.reorder_before_push:
            return
        while True:
            state = self.states.get((flow, self.next_issue[flow]))
            if state is None or not state.arrived:
                return
            if self.policy.use_credit and self.credit[flow] + state.charge > self.config.push_credit_bytes_per_flow:
                if self.credit_stall_start[flow] is None:
                    self.credit_stall_start[flow] = now
                    self.credit_stall_events[flow] += 1
                return
            self.next_issue[flow] += 1
            self._issue(state, now)

    def _try_publish(self, flow, now, candidate=None):
        state = candidate if self.policy.cpu_reorder else self.states.get((flow, self.next_publish[flow]))
        if (state is None or not state.issued or not state.data_complete
                or state.publishing or state.ready):
            return
        state.publishing = True
        self._link_line(now, "descriptor_visible", state.index)
        self._link_line(now, "ready_visible", state.index)

    def _try_cpu(self, now):
        if self.cpu_scheduled:
            return
        if self.policy.cpu_reorder:
            candidates = [state for state in self.states.values()
                          if state.ready and not state.consuming and not state.cpu_done]
            if candidates:
                state = min(candidates, key=lambda item: (item.ready_ns, item.packet.flow,
                                                          item.packet.serial))
                state.consuming = True
                self.cpu_scheduled = True
                self._schedule(now, "cpu_consume", state.index)
            return
        for offset in range(len(self.flows)):
            index = (self.cpu_round_robin + offset) % len(self.flows)
            flow = self.flows[index]
            state = self.states.get((flow, self.next_consume[flow]))
            if state is not None and state.ready and not state.released:
                self.cpu_round_robin = (index + 1) % len(self.flows)
                state.consuming = True
                self.cpu_scheduled = True
                self._schedule(now, "cpu_consume", state.index)
                return

    def _arrival(self, now, state):
        state.arrived = True
        self.nic_buffer += state.charge
        self.nic_buffer_peak = max(self.nic_buffer_peak, self.nic_buffer)
        if self.nic_buffer > self.config.nic_buffer_bytes:
            raise TimingError("NIC buffer capacity exceeded")
        self._record(now, "arrival", flow=state.packet.flow, serial=state.packet.serial,
                     bytes=len(state.packet.payload))
        if self.policy.reorder_before_push:
            self._try_issue(state.packet.flow, now)
        else:
            self._issue(state, now)

    def _payload_visible(self, now, state, offset, data):
        address = state.base + PAYLOAD_OFFSET + offset
        self.cache.io_write(address, data, self.admission)
        state.visible_ns[offset] = now
        state.admitted[offset] = self.cache.resident(address)
        state.pending_payload_lines -= 1
        self._record(now, "payload_visible", flow=state.packet.flow,
                     serial=state.packet.serial, offset=offset,
                     admitted=state.admitted[offset])
        if self.policy.family == "ncp" and self.config.ncp_withdraw_ns is not None:
            self._schedule(now + self.config.ncp_withdraw_ns, "withdraw", state.index, offset, data)
        if state.pending_payload_lines == 0:
            state.data_complete = True
            self._try_publish(state.packet.flow, now, state)

    def _descriptor_visible(self, now, state):
        self.cache.io_write(state.base + DESCRIPTOR_OFFSET, self._descriptor(state), self.admission)
        self._record(now, "descriptor_visible", flow=state.packet.flow, serial=state.packet.serial)

    def _ready_visible(self, now, state):
        self.cache.io_write(state.base + READY_OFFSET,
                            struct.pack("<Q", 1).ljust(LINE_BYTES, b"\0"), self.admission)
        state.ready = True
        state.ready_ns = now
        state.publishing = False
        if not self.policy.cpu_reorder:
            if state.packet.serial != self.next_publish[state.packet.flow]:
                raise TimingError("ready publication skipped a serial")
            self.next_publish[state.packet.flow] += 1
        self._record(now, "ready_visible", flow=state.packet.flow, serial=state.packet.serial)
        if not self.policy.cpu_reorder:
            self._try_publish(state.packet.flow, now)
        self._try_cpu(now)

    def _withdraw(self, now, state, offset, data):
        if state.released:
            self._record(now, "withdraw_stale", flow=state.packet.flow,
                         serial=state.packet.serial, offset=offset)
            return
        self.cache.bypass_write(state.base + PAYLOAD_OFFSET + offset, data)
        self.withdrawals += 1
        self._record(now, "withdraw", flow=state.packet.flow,
                     serial=state.packet.serial, offset=offset)

    def _background(self, now):
        address = BACKGROUND_BASE + (self.background_index % self.config.background_working_set_lines) * LINE_BYTES
        self.background_index += 1
        self.cache.read(address, LINE_BYTES, category="background")
        self._record(now, "background", address=address)
        next_time = now + self.config.background_interval_ns
        if next_time <= self.config.max_time_ns:
            self._schedule(next_time, "background")

    def _cpu_consume(self, now, state):
        packet = state.packet
        if ((not self.policy.cpu_reorder and packet.serial != self.next_consume[packet.flow])
                or not state.ready):
            raise TimingError("CPU consumption was not an ordered ready packet")
        finish = now + self.config.cpu_base_ns
        ready, ready_hit = self.cache.read(state.base + READY_OFFSET, 8, category="ready")
        descriptor, descriptor_hit = self.cache.read(
            state.base + DESCRIPTOR_OFFSET, 40, category="descriptor")
        finish = self._cpu_access_complete(finish, ready_hit)
        finish = self._cpu_access_complete(finish, descriptor_hit)
        expected_descriptor = struct.unpack("<5Q", descriptor)
        if struct.unpack("<Q", ready)[0] != 1 or expected_descriptor != (
                packet.flow, packet.serial, state.index, 1, len(packet.payload)):
            raise TimingError("CPU observed stale publication metadata")
        observed = bytearray()
        line_records = []
        for offset in range(0, state.charge, LINE_BYTES):
            address = state.base + PAYLOAD_OFFSET + offset
            size = min(LINE_BYTES, len(packet.payload) - offset)
            if state.admitted.get(offset, False) and not self.cache.resident(address):
                self.admitted_absent += 1
            data, hit = self.cache.read(address, size, category="payload")
            observed.extend(data)
            finish = self._cpu_access_complete(finish, hit)
            self.first_hits += int(hit)
            self.first_misses += int(not hit)
            push_to_demand = None
            if offset in state.visible_ns:
                push_to_demand = now - state.visible_ns[offset]
            record = {"flow": packet.flow, "serial": packet.serial, "offset": offset,
                      "time_ns": now, "hit": hit,
                      "source": "llc" if hit else self.policy.home,
                      "push_to_first_demand_ns": push_to_demand}
            self.demand_records.append(record)
            line_records.append(record)
        if bytes(observed) != packet.payload:
            raise TimingError("CPU payload differs from reliable ingress")
        state.consume_ns = now
        state.processing_done_ns = finish
        self._record(now, "cpu_consume", flow=packet.flow, serial=packet.serial,
                     ready_hit=ready_hit, descriptor_hit=descriptor_hit,
                     payload_hits=sum(record["hit"] for record in line_records),
                     payload_lines=len(line_records), finish_ns=state.processing_done_ns)
        self._schedule(state.processing_done_ns, "release", state.index)

    def _deliver_cpu_reordered(self, flow, now):
        while True:
            state = self.states.get((flow, self.next_consume[flow]))
            if state is None or not state.cpu_done:
                return
            state.released = True
            state.delivery_ns = now
            if state.cpu_buffered:
                self.cpu_reorder_buffer -= state.charge
                state.cpu_buffered = False
            self.next_consume[flow] += 1
            self.delivered.append((flow, state.packet.serial, now))
            self._record(now, "ordered_delivery", flow=flow, serial=state.packet.serial,
                         latency_ns=now - state.packet.arrival_ns)

    def _release(self, now, state):
        packet = state.packet
        self.cache.cpu_write(state.base + RELEASE_OFFSET, struct.pack("<Q", 1))
        state.buffer_released = True
        state.cpu_done = True
        state.consuming = False
        if state.credit_reserved:
            self.credit[packet.flow] -= state.charge
        self.nic_buffer -= state.charge
        self.cpu_scheduled = False
        self._record(now, "buffer_release", flow=packet.flow, serial=packet.serial)
        if self.policy.cpu_reorder:
            if packet.serial != self.next_consume[packet.flow]:
                state.cpu_buffered = True
                self.cpu_reorder_buffer += state.charge
                self.cpu_reorder_buffer_peak = max(self.cpu_reorder_buffer_peak,
                                                   self.cpu_reorder_buffer)
                if self.cpu_reorder_buffer > self.config.cpu_reorder_buffer_bytes:
                    raise TimingError("CPU reorder buffer capacity exceeded")
            self._deliver_cpu_reordered(packet.flow, now)
        else:
            state.released = True
            state.delivery_ns = now
            self.next_consume[packet.flow] += 1
            self.delivered.append((packet.flow, packet.serial, now))
            self._record(now, "ordered_delivery", flow=packet.flow, serial=packet.serial,
                         latency_ns=now - packet.arrival_ns)
        self._try_issue(packet.flow, now)
        self._try_cpu(now)

    def run(self):
        total = len(self.states)
        while len(self.delivered) < total:
            if not self.events:
                raise TimingError("event queue drained before reliable workload completed")
            now, _, kind, arguments = heapq.heappop(self.events)
            if now > self.config.max_time_ns:
                raise TimingError("virtual-time deadline expired")
            state = self.by_index[arguments[0]] if arguments and kind != "background" else None
            if kind == "arrival":
                self._arrival(now, state)
            elif kind == "payload_visible":
                self._payload_visible(now, state, arguments[1], arguments[2])
            elif kind == "descriptor_visible":
                self._descriptor_visible(now, state)
            elif kind == "ready_visible":
                self._ready_visible(now, state)
            elif kind == "withdraw":
                self._withdraw(now, state, arguments[1], arguments[2])
            elif kind == "background":
                self._background(now)
            elif kind == "cpu_consume":
                self._cpu_consume(now, state)
            elif kind == "release":
                self._release(now, state)
            else:
                raise TimingError(f"unknown event {kind}")
        for flow in self.flows:
            expected = sorted(packet.serial for packet in self.packets if packet.flow == flow)
            actual = [serial for delivered_flow, serial, _ in self.delivered if delivered_flow == flow]
            if actual != expected:
                raise TimingError("delivery order differs from sender sequence")
        if self.nic_buffer != 0 or self.cpu_reorder_buffer != 0 or any(self.credit.values()):
            raise TimingError("buffer or credit leaked after completion")
        latencies = [state.delivery_ns - state.packet.arrival_ns for state in self.states.values()]
        sequence_waits = [state.issue_ns - state.packet.arrival_ns for state in self.states.values()]
        push_to_demand = [record["push_to_first_demand_ns"] for record in self.demand_records
                          if record["push_to_first_demand_ns"] is not None]
        begin = min(packet.arrival_ns for packet in self.packets)
        end = max(time_ns for _, _, time_ns in self.delivered)
        cache_before_flush = self.cache.snapshot()
        self.cache.flush()
        lines = self.first_hits + self.first_misses
        expected_lines = sum(state.charge // LINE_BYTES for state in self.states.values())
        expected_push = expected_lines * LINE_BYTES if self.policy.push_payload else 0
        expected_producer = expected_push + total * 2 * LINE_BYTES
        if lines != expected_lines:
            raise TimingError("payload first-demand denominator is not one per cache line")
        if self.payload_push_bytes != expected_push or self.producer_link_bytes != expected_producer:
            raise TimingError("producer link-byte conservation failed")
        if self.link_bytes != self.producer_link_bytes + self.cpu_nic_read_bytes:
            raise TimingError("modeled link-byte classes do not sum to the total")
        if self.policy.use_credit and any(
                value > self.config.push_credit_bytes_per_flow for value in self.credit_peak.values()):
            raise TimingError("push credit exceeded its configured bound")
        for state in self.states.values():
            times = (state.packet.arrival_ns, state.issue_ns, state.ready_ns,
                     state.consume_ns, state.processing_done_ns, state.delivery_ns)
            if any(value is None for value in times) or tuple(sorted(times)) != times:
                raise TimingError("packet lifecycle timestamps are incomplete or reversed")
            if state.visible_ns and max(state.visible_ns.values()) > state.ready_ns:
                raise TimingError("packet became ready before every payload line")
        if any(value is not None and value < 0 for value in push_to_demand):
            raise TimingError("CPU demanded a payload line before it became visible")
        result = {
            "status": "passed",
            "scope": "integer virtual time; reliable finite reordering; no loss/retransmission/hardware timing",
            "policy": asdict(self.policy),
            "config": asdict(self.config),
            "admission": list(self.admission),
            "packets": total,
            "payload_bytes": sum(len(packet.payload) for packet in self.packets),
            "duration_ns": end - begin,
            "throughput_gbps": (sum(len(packet.payload) for packet in self.packets) * 8 / (end - begin)
                                 if end > begin else None),
            "delivery_latency_ns": {"min": min(latencies), "p50": _nearest_rank(latencies, .50),
                                    "p99": _nearest_rank(latencies, .99), "max": max(latencies)},
            "sequence_wait_ns": {"p50": _nearest_rank(sequence_waits, .50),
                                 "p99": _nearest_rank(sequence_waits, .99), "max": max(sequence_waits)},
            "push_to_first_demand_ns": {"p50": _nearest_rank(push_to_demand, .50),
                                        "p99": _nearest_rank(push_to_demand, .99),
                                        "max": max(push_to_demand) if push_to_demand else None},
            "payload_first_demand": {"hits": self.first_hits, "misses": self.first_misses,
                                     "lines": lines,
                                     "hit_rate": self.first_hits / lines if lines else None},
            "admitted_absent_at_first_demand": self.admitted_absent,
            "link_bytes": self.link_bytes,
            "producer_link_bytes": self.producer_link_bytes,
            "cpu_nic_read_bytes": self.cpu_nic_read_bytes,
            "payload_push_bytes": self.payload_push_bytes,
            "link_busy_until_ns": self.link_available_ns,
            "nic_buffer_peak_bytes": self.nic_buffer_peak,
            "cpu_reorder_buffer_peak_bytes": self.cpu_reorder_buffer_peak,
            "credit_peak_bytes": {str(flow): value for flow, value in self.credit_peak.items()},
            "credit_stall_events": {str(flow): value for flow, value in self.credit_stall_events.items()},
            "credit_stall_ns": {str(flow): value for flow, value in self.credit_stall_ns.items()},
            "withdrawn_payload_lines": self.withdrawals,
            "delivery_order": [{"flow": flow, "serial": serial, "time_ns": time_ns}
                               for flow, serial, time_ns in self.delivered],
            "packet_records": [{"flow": state.packet.flow, "serial": state.packet.serial,
                                "arrival_ns": state.packet.arrival_ns, "issue_ns": state.issue_ns,
                                "ready_ns": state.ready_ns, "consume_ns": state.consume_ns,
                                "processing_done_ns": state.processing_done_ns,
                                "delivery_ns": state.delivery_ns}
                               for state in sorted(self.states.values(), key=lambda item: item.index)],
            "cache_before_final_flush": cache_before_flush,
            "cache_after_final_flush": self.cache.snapshot(),
        }
        return result


def _comparable(result):
    return {key: result[key] for key in (
        "packets", "payload_bytes", "duration_ns", "throughput_gbps",
        "delivery_latency_ns", "sequence_wait_ns", "push_to_first_demand_ns",
        "payload_first_demand", "admitted_absent_at_first_demand", "link_bytes",
        "producer_link_bytes", "cpu_nic_read_bytes", "payload_push_bytes",
        "link_busy_until_ns", "nic_buffer_peak_bytes",
        "cpu_reorder_buffer_peak_bytes",
        "credit_peak_bytes", "credit_stall_events", "credit_stall_ns",
        "withdrawn_payload_lines", "delivery_order", "packet_records",
        "cache_before_final_flush", "cache_after_final_flush")}


def run_matrix(packets, config=TimingConfig(), policy_names=None, output=None):
    packets, _ = validate_workload(packets)
    names = tuple(POLICIES) if policy_names is None else tuple(policy_names)
    if not names or any(name not in POLICIES for name in names):
        raise TimingError("policy matrix contains an unknown or empty policy list")
    arms = {}
    for name in names:
        simulation = Simulation(packets, POLICIES[name], config)
        arms[name] = simulation.run()
        if output is not None:
            with (output / f"{name}.jsonl").open("w") as stream:
                for event in simulation.log:
                    stream.write(json.dumps(event, sort_keys=True) + "\n")
    fairness = "not_run"
    if "B1" in arms and "D1-host-control" in arms:
        matched = (config.admission("ddio") == config.admission("ncp")
                   and config.ncp_withdraw_ns is None)
        if matched:
            if _comparable(arms["B1"]) != _comparable(arms["D1-host-control"]):
                raise TimingError("protocol-label control changed a matched virtual-time result")
            fairness = "passed"
        else:
            fairness = "not_applicable_different_policy"
    return {"status": "passed", "fairness_control": fairness,
            "assumptions": {"reliable_delivery": True, "permanent_loss": False,
                            "retransmission": False, "timeout_recovery": False,
                            "application_delivery": "strict per-flow sender order",
                            "cpu_payload_demand": "A may read out of order; other arms read in order"},
            "arms": arms}


def _way_argument(value):
    if value == "all":
        return None
    if value == "none":
        return ()
    try:
        return tuple(int(part) for part in value.split(","))
    except ValueError as error:
        raise argparse.ArgumentTypeError("ways must be all, none, or comma-separated integers") from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--flows", type=int, default=2)
    parser.add_argument("--packets-per-flow", type=int, default=64)
    parser.add_argument("--interarrival-ns", type=int, default=80)
    parser.add_argument("--reorder-jitter-ns", type=int, default=120)
    parser.add_argument("--gap-every", type=int, default=8)
    parser.add_argument("--gap-delay-ns", type=int, default=800)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--cache-sets", type=int, default=64)
    parser.add_argument("--cache-ways", type=int, default=8)
    parser.add_argument("--packet-stride-lines", type=int, default=129)
    parser.add_argument("--ddio-ways", type=_way_argument, default=None)
    parser.add_argument("--ncp-ways", type=_way_argument, default=None)
    parser.add_argument("--link-bandwidth-gbps", type=int, default=100)
    parser.add_argument("--link-latency-ns", type=int, default=100)
    parser.add_argument("--cpu-base-ns", type=int, default=40)
    parser.add_argument("--llc-hit-ns", type=int, default=12)
    parser.add_argument("--host-miss-ns", type=int, default=90)
    parser.add_argument("--nic-miss-ns", type=int, default=250,
                        help="symbolic NIC backing service, in addition to link queue/latency")
    parser.add_argument("--push-credit-bytes-per-flow", type=int, default=3072)
    parser.add_argument("--nic-buffer-bytes", type=int, default=8 << 20)
    parser.add_argument("--cpu-reorder-buffer-bytes", type=int, default=8 << 20)
    parser.add_argument("--background-interval-ns", type=int)
    parser.add_argument("--background-working-set-lines", type=int, default=0)
    parser.add_argument("--ncp-withdraw-ns", type=int)
    parser.add_argument("--max-time-ns", type=int, default=10_000_000)
    parser.add_argument("--policies", default=",".join(POLICIES),
                        help="comma-separated A,B0,B1,C,D0,D1,E,D1-host-control")
    args = parser.parse_args(argv)
    packets = generate_workload(flows=args.flows, packets_per_flow=args.packets_per_flow,
                                interarrival_ns=args.interarrival_ns,
                                reorder_jitter_ns=args.reorder_jitter_ns,
                                gap_every=args.gap_every, gap_delay_ns=args.gap_delay_ns,
                                seed=args.seed)
    config = TimingConfig(cache_sets=args.cache_sets, cache_ways=args.cache_ways,
                          packet_stride_lines=args.packet_stride_lines,
                          ddio_ways=args.ddio_ways, ncp_ways=args.ncp_ways,
                          link_bandwidth_gbps=args.link_bandwidth_gbps,
                          link_latency_ns=args.link_latency_ns,
                          cpu_base_ns=args.cpu_base_ns, llc_hit_ns=args.llc_hit_ns,
                          host_miss_ns=args.host_miss_ns, nic_miss_ns=args.nic_miss_ns,
                          push_credit_bytes_per_flow=args.push_credit_bytes_per_flow,
                          nic_buffer_bytes=args.nic_buffer_bytes,
                          cpu_reorder_buffer_bytes=args.cpu_reorder_buffer_bytes,
                          background_interval_ns=args.background_interval_ns,
                          background_working_set_lines=args.background_working_set_lines,
                          ncp_withdraw_ns=args.ncp_withdraw_ns,
                          max_time_ns=args.max_time_ns)
    args.output.mkdir(parents=True, exist_ok=False)
    workload = [{"flow": packet.flow, "serial": packet.serial,
                 "arrival_ns": packet.arrival_ns, "payload": packet.payload.hex()}
                for packet in packets]
    workload_data = "".join(json.dumps(item, sort_keys=True) + "\n" for item in workload)
    (args.output / "workload.jsonl").write_text(workload_data)
    result = {"status": "running", "workload_sha256": hashlib.sha256(workload_data.encode()).hexdigest()}
    try:
        result.update(run_matrix(packets, config, args.policies.split(","), args.output))
        root = Path(__file__).resolve().parent.parent
        result["source_sha256"] = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                                   for path in sorted((root / "cxl_nic").glob("*.py"))}
    except Exception as error:
        result.update(status="failed", error=repr(error))
        raise
    finally:
        (args.output / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": result["status"], "fairness_control": result["fairness_control"],
                      "arms": {name: {"p99_ns": arm["delivery_latency_ns"]["p99"],
                                      "first_hit_rate": arm["payload_first_demand"]["hit_rate"]}
                               for name, arm in result["arms"].items()},
                      "result": str(args.output / "result.json")}))


if __name__ == "__main__":
    main()
