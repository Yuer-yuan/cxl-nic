"""Independent replay checker for packet reordering and publication traces.

The checker uses only logged events. It does not import the producer model or
trust its counters, descriptors, memory contents, or reported completion status.
Serial numbers are unbounded logical sequence numbers; wrapping wire sequence
numbers must be resolved by the receiver before they enter a trace.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping


LINE_BYTES = 64
DESCRIPTOR_FIELDS = frozenset({"flow", "serial", "slot", "generation", "length"})


class TraceViolation(ValueError):
    """A trace violates the reordering or publication contract."""


@dataclass(frozen=True)
class _Token:
    flow: int
    serial: int
    slot: int
    generation: int


@dataclass
class _Packet:
    token: _Token
    payload: bytes
    issued: dict[tuple[str, Any], int] = field(default_factory=dict)
    visible: set[tuple[str, Any]] = field(default_factory=set)
    pending: set[int] = field(default_factory=set)
    charged: bool = False
    ready_issued: bool = False
    ready_visible: bool = False
    consumed: bool = False
    released: bool = False

    @property
    def charge(self) -> int:
        return ((len(self.payload) + LINE_BYTES - 1) // LINE_BYTES) * LINE_BYTES

    @property
    def descriptor(self) -> dict[str, int]:
        return {
            "flow": self.token.flow,
            "serial": self.token.serial,
            "slot": self.token.slot,
            "generation": self.token.generation,
            "length": len(self.payload),
        }

    @property
    def required_data(self) -> set[tuple[str, Any]]:
        return {
            *(('payload', offset) for offset in range(0, self.charge, LINE_BYTES)),
            *(('descriptor', name) for name in DESCRIPTOR_FIELDS),
        }


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise TraceViolation(message)


def _integer(value: Any, name: str, minimum: int = 0) -> int:
    _require(type(value) is int and value >= minimum, f"{name} must be an integer >= {minimum}")
    return value


def _hex_bytes(value: Any, name: str) -> bytes:
    _require(isinstance(value, str), f"{name} must be a hex string")
    try:
        data = bytes.fromhex(value)
    except ValueError as error:
        raise TraceViolation(f"{name} is not valid hex") from error
    _require(len(value) == 2 * len(data), f"{name} must use contiguous hex digits")
    return data


def _token(value: Any) -> _Token:
    _require(isinstance(value, Mapping), "token must be a mapping")
    _require(set(value) == {"flow", "serial", "slot", "generation"}, "token fields are incomplete or unknown")
    return _Token(
        _integer(value["flow"], "token.flow"),
        _integer(value["serial"], "token.serial"),
        _integer(value["slot"], "token.slot"),
        _integer(value["generation"], "token.generation", 1),
    )


def validate_trace(events: Iterable[Mapping[str, Any]], require_drained: bool = True) -> dict[str, Any]:
    """Replay a complete trace, returning counters or raising ``TraceViolation``.

    ``require_drained=False`` permits unfinished packets and explicit flow halts,
    which is useful when checking a snapshot of a running or failed experiment.
    All observed ordering, visibility, reuse, and credit rules still apply.
    Extra top-level event fields (for example a log index) are ignored.
    """
    iterator = iter(events)
    try:
        config = next(iterator)
    except StopIteration as error:
        raise TraceViolation("trace is empty; first event must be config") from error
    _require(isinstance(config, Mapping) and config.get("event") == "config", "first event must be config")
    window = _integer(config.get("window"), "window", 1)
    sequence_bits = _integer(config.get("sequence_bits"), "sequence_bits", 2)
    _require(sequence_bits <= 64, "sequence_bits must be <= 64")
    _require(window < 1 << (sequence_bits - 1), "window must be smaller than half the wire sequence space")
    max_packet_bytes = _integer(config.get("max_packet_bytes"), "max_packet_bytes", 1)
    credit_limit = _integer(config.get("per_flow_credit_bytes"), "per_flow_credit_bytes", 1)
    max_packet_charge = ((max_packet_bytes + LINE_BYTES - 1) // LINE_BYTES) * LINE_BYTES
    _require(credit_limit >= max_packet_charge, "each flow needs credit for a complete maximum-size packet")
    global_limit = config.get("global_push_credit_bytes")
    if global_limit is not None:
        global_limit = _integer(global_limit, "global_push_credit_bytes", max_packet_charge)
    initial = config.get("initial_serials")
    _require(isinstance(initial, Mapping) and bool(initial), "initial_serials must be a nonempty mapping")
    bases: dict[int, int] = {}
    for flow, serial in initial.items():
        _require(isinstance(flow, str) and flow.isdecimal() and str(int(flow)) == flow,
                 "initial_serials keys must be canonical nonnegative decimal strings")
        bases[int(flow)] = _integer(serial, f"initial_serials[{flow}]")
    next_issue = dict(bases)
    next_ready = dict(bases)
    next_consume = dict(bases)
    credit = dict.fromkeys(bases, 0)
    peak_credit = dict.fromkeys(bases, 0)
    global_credit = 0
    global_peak = 0
    released_serials: dict[int, set[int]] = {flow: set() for flow in bases}
    pending_ready: dict[int, int] = {}
    generations: dict[tuple[int, int], int] = {}
    active_slots: dict[tuple[int, int], _Token] = {}
    packets: dict[_Token, _Packet] = {}
    operations: dict[int, tuple[_Token, tuple[str, Any], tuple[Any, ...]]] = {}
    visible_operations: set[int] = set()
    halted: dict[int, int] = {}
    counts = dict(events=1, received=0, consumed=0, released=0, rejected=0, halted=0)

    def active_packet(event: Mapping[str, Any]) -> _Packet:
        token = _token(event.get("token"))
        _require(token in packets, f"unknown token {token}")
        packet = packets[token]
        _require(not packet.released, f"stale access after release: {token}")
        _require(active_slots.get((token.flow, token.slot)) == token, f"slot identity mismatch: {token}")
        return packet

    def operation(event: Mapping[str, Any], packet: _Packet) -> tuple[tuple[str, Any], tuple[Any, ...]]:
        kind = event.get("kind")
        if kind == "payload":
            offset = _integer(event.get("offset"), "payload offset")
            _require(offset % LINE_BYTES == 0 and offset < packet.charge, "payload offset is outside its aligned packet")
            data = _hex_bytes(event.get("data"), "payload line")
            _require(len(data) == LINE_BYTES, "payload write must cover exactly one 64-byte line")
            expected = packet.payload[offset:offset + LINE_BYTES].ljust(LINE_BYTES, b"\0")
            _require(data == expected, "payload write differs from received bytes or zero padding")
            return (kind, offset), (kind, offset, data)
        if kind == "descriptor":
            name = event.get("field")
            _require(isinstance(name, str) and name in DESCRIPTOR_FIELDS, "unknown descriptor field")
            value = _integer(event.get("value"), f"descriptor.{name}")
            _require(value == packet.descriptor[name], f"descriptor.{name} differs from received packet identity/length")
            return (kind, name), (kind, name, value)
        _require(kind == "ready", f"unknown write kind: {kind!r}")
        return ("ready", None), ("ready",)

    for index, event in enumerate(iterator, start=1):
        try:
            _require(isinstance(event, Mapping), "event must be a mapping")
            kind = event.get("event")
            counts["events"] += 1
            if kind == "receive":
                token = _token(event.get("token"))
                _require(token.flow in bases, "receive references an unconfigured flow")
                _require(token.flow not in halted, "receive after flow halt")
                _require(bases[token.flow] <= token.serial < bases[token.flow] + window,
                         "receive falls outside the window based on contiguous releases")
                _require(token.serial not in released_serials[token.flow],
                         "receive reaccepted an already released serial")
                _require(token.slot == token.serial % window, "slot does not match serial modulo window")
                slot = (token.flow, token.slot)
                _require(slot not in active_slots, "slot reused before release")
                _require(token.generation == generations.get(slot, 0) + 1, "slot generation did not advance exactly once")
                _require(token not in packets, "duplicate packet acceptance")
                payload = _hex_bytes(event.get("payload"), "received payload")
                _require(0 < len(payload) <= max_packet_bytes, "received payload length is outside configured bounds")
                packets[token] = _Packet(token, payload)
                active_slots[slot] = token
                generations[slot] = token.generation
                counts["received"] += 1
            elif kind in ("issue", "visible"):
                packet = active_packet(event)
                op_id = _integer(event.get("op_id"), "op_id")
                component, signature = operation(event, packet)
                flow = packet.token.flow
                if kind == "issue":
                    if flow in halted:
                        _require(component[0] == "ready" and packet.token.serial < halted[flow]
                                 and packet.charged,
                                 "only an already issued packet before the halted gap may issue ready")
                    _require(op_id not in operations, "duplicate issued op_id")
                    _require(not packet.ready_issued, "write issued after packet commit was issued")
                    _require(component not in packet.issued, "packet component issued twice")
                    if component[0] == "ready":
                        _require(packet.required_data <= packet.visible,
                                 "ready issued before all payload and descriptor writes became visible")
                        _require(packet.token.serial == next_ready[flow],
                                 "ready issued before the preceding serial's ready became visible")
                        _require(flow not in pending_ready, "multiple ready commits in flight for one flow")
                        packet.ready_issued = True
                        pending_ready[flow] = op_id
                    if not packet.charged:
                        _require(packet.token.serial == next_issue[flow],
                                 "first write issued outside the contiguous packet prefix")
                        _require(credit[flow] + packet.charge <= credit_limit,
                                 "per-flow credit exceeded before release")
                        _require(global_limit is None or global_credit + packet.charge <= global_limit,
                                 "global push credit exceeded before release")
                        credit[flow] += packet.charge
                        global_credit += packet.charge
                        global_peak = max(global_peak, global_credit)
                        peak_credit[flow] = max(peak_credit[flow], credit[flow])
                        packet.charged = True
                        next_issue[flow] += 1
                    packet.issued[component] = op_id
                    packet.pending.add(op_id)
                    operations[op_id] = (packet.token, component, signature)
                else:
                    _require(op_id in operations, "write became visible without a matching issue")
                    _require(op_id not in visible_operations, "duplicate write visibility/completion")
                    _require(operations[op_id] == (packet.token, component, signature),
                             "visible write identity/content differs from issued write")
                    _require(op_id in packet.pending, "visible write is not pending for its packet")
                    packet.pending.remove(op_id)
                    packet.visible.add(component)
                    visible_operations.add(op_id)
                    if component[0] == "ready":
                        _require(pending_ready.get(flow) == op_id, "ready commit identity mismatch")
                        _require(packet.required_data <= packet.visible, "ready visible before packet data")
                        _require(packet.token.serial == next_ready[flow], "out-of-order ready visibility")
                        packet.ready_visible = True
                        next_ready[flow] += 1
                        del pending_ready[flow]
            elif kind == "consume":
                packet = active_packet(event)
                flow = packet.token.flow
                _require(packet.ready_visible, "CPU consumed before ready was visible")
                _require(not packet.consumed, "CPU consumed a packet twice")
                _require(packet.token.serial == next_consume[flow], "CPU consumed packets out of order")
                descriptor = event.get("descriptor")
                _require(isinstance(descriptor, Mapping) and set(descriptor) == DESCRIPTOR_FIELDS,
                         "CPU descriptor fields are incomplete or unknown")
                for name in DESCRIPTOR_FIELDS:
                    _integer(descriptor[name], f"consumed descriptor.{name}")
                _require(descriptor == packet.descriptor, "CPU descriptor differs from accepted packet")
                _require(_hex_bytes(event.get("payload"), "consumed payload") == packet.payload,
                         "CPU payload differs from accepted packet")
                _require(packet.required_data <= packet.visible, "CPU consumed incomplete packet memory")
                packet.consumed = True
                next_consume[flow] += 1
                counts["consumed"] += 1
            elif kind == "release":
                packet = active_packet(event)
                flow = packet.token.flow
                _require(packet.consumed, "packet released before CPU consumed it")
                _require(not packet.pending, "packet released with writes still pending")
                _require(packet.charged, "released packet never reserved credit")
                packet.released = True
                credit[flow] -= packet.charge
                global_credit -= packet.charge
                del active_slots[(flow, packet.token.slot)]
                released_serials[flow].add(packet.token.serial)
                while bases[flow] in released_serials[flow]:
                    released_serials[flow].remove(bases[flow])
                    bases[flow] += 1
                counts["released"] += 1
            elif kind == "reject":
                _require("flow" in event and "serial" in event and isinstance(event.get("reason"), str),
                         "reject must identify flow, serial, and reason")
                counts["rejected"] += 1
            elif kind == "halt":
                flow = _integer(event.get("flow"), "halt.flow")
                _require(flow in bases, "halt references an unconfigured flow")
                serial = _integer(event.get("serial"), "halt.serial")
                _require(isinstance(event.get("reason"), str), "halt must include a reason")
                _require(flow not in halted, "flow halted more than once")
                _require(serial == next_issue[flow], "halt serial must equal the next unissued serial")
                active_serials = {
                    token.serial for token in active_slots.values() if token.flow == flow
                }
                _require(serial not in active_serials, "halt serial is already accepted; there is no missing packet")
                _require(any(accepted > serial for accepted in active_serials),
                         "halt requires a later accepted packet beyond the missing serial")
                halted[flow] = serial
                counts["halted"] += 1
            else:
                raise TraceViolation(f"unknown event kind: {kind!r}")
        except TraceViolation as error:
            raise TraceViolation(f"event {index} ({event.get('event') if isinstance(event, Mapping) else '?'}): {error}") from error

    pending_writes = len(operations) - len(visible_operations)
    outstanding_packets = sum(not packet.released for packet in packets.values())
    if require_drained:
        _require(not halted, "trace contains halted flows")
        _require(outstanding_packets == 0, f"trace is not drained: {outstanding_packets} accepted packets await release")
        _require(pending_writes == 0, f"trace is not drained: {pending_writes} writes await visibility")
        _require(not any(credit.values()), "trace is not drained: credit remains reserved")
        _require(global_credit == 0, "trace is not drained: global credit remains reserved")
    return {
        **counts,
        "pending_writes": pending_writes,
        "outstanding_packets": outstanding_packets,
        "peak_credit_bytes": {str(flow): value for flow, value in sorted(peak_credit.items())},
        "credit_bytes": {str(flow): value for flow, value in sorted(credit.items())},
        "global_credit_bytes": global_credit,
        "global_credit_peak_bytes": global_peak,
        "release_bases": {str(flow): value for flow, value in sorted(bases.items())},
    }
