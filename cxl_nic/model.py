"""Functional model. A write completion means CPU-visible data, not link acceptance.

All transitions are explicit. The scheduler may complete writes in any order.
There is no CPU/cache/PCIe/CXL timing model in this module.
"""

from copy import deepcopy
from dataclasses import asdict, dataclass, field
from typing import Dict, Optional


LINE_BYTES = 64
DESCRIPTOR_FIELDS = ("flow", "serial", "slot", "generation", "length")


def aligned_size(size: int) -> int:
    return ((size + LINE_BYTES - 1) // LINE_BYTES) * LINE_BYTES


class ProtocolError(ValueError):
    """An input or ownership transition violates the contract."""


@dataclass(frozen=True)
class Config:
    window: int = 4
    sequence_bits: int = 8
    max_packet_bytes: int = 1500
    per_flow_credit_bytes: int = 3072

    def __post_init__(self):
        for name, value in asdict(self).items():
            if type(value) is not int or value <= 0:
                raise ProtocolError(f"{name} must be a positive integer")
        if self.sequence_bits > 64:
            raise ProtocolError("sequence_bits must be <= 64")
        if self.window >= (1 << (self.sequence_bits - 1)):
            raise ProtocolError("window must be smaller than half the sequence space")
        if self.per_flow_credit_bytes < aligned_size(self.max_packet_bytes):
            raise ProtocolError("each flow needs credit for a complete maximum-size packet")


@dataclass(frozen=True)
class Token:
    flow: int
    serial: int
    slot: int
    generation: int


@dataclass(frozen=True)
class Write:
    op_id: int
    token: Token
    kind: str
    offset: Optional[int] = None
    data: Optional[bytes] = None
    field: Optional[str] = None
    value: Optional[int] = None

    def event_fields(self):
        result = {"op_id": self.op_id, "token": asdict(self.token), "kind": self.kind}
        if self.kind == "payload":
            result.update(offset=self.offset, data=self.data.hex())
        elif self.kind == "descriptor":
            result.update(field=self.field, value=self.value)
        return result


@dataclass(frozen=True)
class Delivery:
    token: Token
    payload: bytes
    descriptor: dict


@dataclass
class _Packet:
    token: Token
    payload: bytes
    phase: str = "WAIT_SEQ"
    data_writes: set = field(default_factory=set)


@dataclass
class _HostSlot:
    data: bytearray
    descriptor: dict = field(default_factory=dict)
    ready: Optional[int] = None


@dataclass
class _Flow:
    base: int
    next_issue: int
    next_publish: int
    next_consume: int
    packets: dict = field(default_factory=dict)
    generations: dict = field(default_factory=dict)
    released: set = field(default_factory=set)
    credit: int = 0
    halted: bool = False


class Protocol:
    """One fixed session, SPSC delivery per flow, explicit sender epoch.

    The NIC stores complete packets in reserved per-flow slots. Each flow also
    owns a fixed push-credit reservation: a paused consumer cannot take another
    flow's allocation. CPU ownership lasts until release(), not acquire().
    """

    def __init__(self, config: Config = Config(), initial_serials=None):
        self.config = config
        initial_serials = {0: 0} if initial_serials is None else dict(initial_serials)
        if not initial_serials:
            raise ProtocolError("at least one flow is required")
        for flow, serial in initial_serials.items():
            if type(flow) is not int or flow < 0 or type(serial) is not int or serial < 0:
                raise ProtocolError("flow ids and initial serials must be nonnegative integers")
        self._flows = {f: _Flow(s, s, s, s) for f, s in initial_serials.items()}
        self._flow_order = sorted(self._flows)
        self._round_robin = 0
        self._host = {
            (f, slot): _HostSlot(bytearray([0xA5]) * aligned_size(config.max_packet_bytes))
            for f in self._flows for slot in range(config.window)
        }
        self.pending: Dict[int, Write] = {}
        self._next_op = 1
        self.trace = []
        self._emit("config", **asdict(config),
                   initial_serials={str(f): s for f, s in initial_serials.items()})

    def _emit(self, event, **kwargs):
        self.trace.append({"event": event, **deepcopy(kwargs)})

    def _flow(self, flow):
        if type(flow) is not int or flow not in self._flows:
            raise ProtocolError(f"unknown flow {flow}")
        return self._flows[flow]

    def receive(self, flow: int, sequence: int, epoch: int, payload: bytes) -> str:
        state = self._flow(flow)
        if (type(sequence) is not int or not 0 <= sequence < (1 << self.config.sequence_bits)
                or type(epoch) is not int or epoch < 0):
            raise ProtocolError("invalid sequence/epoch")
        if not isinstance(payload, bytes) or not 1 <= len(payload) <= self.config.max_packet_bytes:
            raise ProtocolError("payload must be nonempty bytes within the configured maximum")
        serial = (epoch << self.config.sequence_bits) + sequence
        reason = None
        if state.halted:
            reason = "halted"
        elif serial < state.base or serial in state.released:
            reason = "late"
        elif serial >= state.base + self.config.window:
            reason = "outside_window"
        elif serial in state.packets:
            if state.packets[serial].payload != payload:
                raise ProtocolError("conflicting duplicate payload")
            reason = "duplicate"
        if reason:
            self._emit("reject", flow=flow, serial=serial, reason=reason)
            return reason
        slot = serial % self.config.window
        if any(p.token.slot == slot for p in state.packets.values()):
            raise ProtocolError("slot still owned")
        generation = state.generations.get(slot, 0) + 1
        state.generations[slot] = generation
        token = Token(flow, serial, slot, generation)
        state.packets[serial] = _Packet(token, payload)
        # Host data, metadata and ready intentionally retain old contents.
        self._emit("receive", token=asdict(token), payload=payload.hex())
        return "accepted"

    def _issue(self, token, kind, **kwargs):
        write = Write(self._next_op, token, kind, **kwargs)
        self._next_op += 1
        self.pending[write.op_id] = write
        self._emit("issue", **write.event_fields())
        return write.op_id

    @staticmethod
    def _descriptor(packet):
        return {**asdict(packet.token), "length": len(packet.payload)}

    def pump(self) -> int:
        """Issue complete packets from each contiguous prefix while credit allows."""
        count = 0
        while True:
            progressed = False
            start = self._round_robin
            for offset in range(len(self._flow_order)):
                idx = (start + offset) % len(self._flow_order)
                flow = self._flow_order[idx]
                state = self._flows[flow]
                packet = state.packets.get(state.next_issue)
                if state.halted or packet is None or packet.phase != "WAIT_SEQ":
                    continue
                size = aligned_size(len(packet.payload))
                if state.credit + size > self.config.per_flow_credit_bytes:
                    continue
                state.credit += size
                packet.phase = "PUSHING"
                padded = packet.payload.ljust(size, b"\0")
                for line in range(0, size, LINE_BYTES):
                    packet.data_writes.add(self._issue(
                        packet.token, "payload", offset=line, data=padded[line:line + LINE_BYTES]))
                for key, value in self._descriptor(packet).items():
                    packet.data_writes.add(self._issue(packet.token, "descriptor", field=key, value=value))
                state.next_issue += 1
                self._round_robin = (idx + 1) % len(self._flow_order)
                progressed = True
                count += 1
            if not progressed:
                break
        return count

    def _try_commit(self, flow):
        state = self._flows[flow]
        packet = state.packets.get(state.next_publish)
        if packet is not None and packet.phase == "PREPARED":
            packet.phase = "COMMITTING"
            self._issue(packet.token, "ready")

    def complete(self, op_id: int) -> bool:
        """Make one issued write visible; repeated callbacks are idempotent.

        A callback is not a second physical write. Every physical write must be
        represented by one unique issued operation and drained before reuse.
        """
        write = self.pending.get(op_id)
        if write is None:
            return False
        state = self._flow(write.token.flow)
        packet = state.packets.get(write.token.serial)
        if packet is None or packet.token != write.token:
            raise ProtocolError("physical write outlived its slot ownership")
        host = self._host[(write.token.flow, write.token.slot)]
        if write.kind == "ready":
            if packet.phase != "COMMITTING" or packet.data_writes or state.next_publish != write.token.serial:
                raise ProtocolError("publication before visible prefix")
            host.ready = write.token.generation  # Atomic generation in a fixed flow/slot.
            packet.phase = "READY"
            state.next_publish += 1
        else:
            if packet.phase != "PUSHING" or op_id not in packet.data_writes:
                raise ProtocolError("payload/descriptor write after publication")
            if write.kind == "payload":
                host.data[write.offset:write.offset + LINE_BYTES] = write.data
            else:
                host.descriptor[write.field] = write.value
            packet.data_writes.remove(op_id)
            if not packet.data_writes:
                packet.phase = "PREPARED"
        del self.pending[op_id]
        self._emit("visible", **write.event_fields())
        self._try_commit(write.token.flow)
        return True

    def acquire(self, flow: int) -> Optional[Delivery]:
        """Abstract acquire: snapshot actual host bytes after matching ready."""
        state = self._flow(flow)
        packet = state.packets.get(state.next_consume)
        if packet is None:
            return None
        host = self._host[(flow, packet.token.slot)]
        if host.ready != packet.token.generation:
            return None
        if packet.phase != "READY":
            raise ProtocolError("ready marker without published ownership")
        descriptor = dict(host.descriptor)
        length = descriptor.get("length", 0)
        if type(length) is not int or not 1 <= length <= self.config.max_packet_bytes:
            raise ProtocolError("invalid visible descriptor length")
        payload = bytes(host.data[:length])
        packet.phase = "CPU_OWNED"
        state.next_consume += 1
        self._emit("consume", token=asdict(packet.token), descriptor=descriptor, payload=payload.hex())
        return Delivery(packet.token, payload, descriptor)

    def release(self, token: Token):
        if not isinstance(token, Token):
            raise ProtocolError("release requires an ownership token")
        state = self._flow(token.flow)
        packet = state.packets.get(token.serial)
        if packet is None or packet.token != token or packet.phase != "CPU_OWNED":
            raise ProtocolError("invalid, duplicate or premature release")
        if any(w.token == token for w in self.pending.values()):
            raise ProtocolError("release while old physical writes remain in flight")
        state.credit -= aligned_size(len(packet.payload))
        del state.packets[token.serial]
        state.released.add(token.serial)
        while state.base in state.released:
            state.released.remove(state.base)
            state.base += 1
        self._emit("release", token=asdict(token))

    def fail_gap(self, flow: int):
        """Explicit terminal error for a missing packet; never skips its serial."""
        state = self._flow(flow)
        if (state.halted or state.next_issue in state.packets
                or not any(s > state.next_issue for s in state.packets)):
            raise ProtocolError("no unresolved gap to fail")
        state.halted = True
        self._emit("halt", flow=flow, serial=state.next_issue, reason="missing_packet")

    def check_invariants(self):
        """Internal assertions complement the independent trace checker."""
        for flow, state in self._flows.items():
            assert state.base <= state.next_consume <= state.next_publish <= state.next_issue
            assert len(state.packets) + len(state.released) <= self.config.window
            credit = sum(aligned_size(len(p.payload)) for p in state.packets.values()
                         if p.phase != "WAIT_SEQ")
            assert credit == state.credit <= self.config.per_flow_credit_bytes
            assert len({p.token.slot for p in state.packets.values()}) == len(state.packets)
            for serial, packet in state.packets.items():
                assert state.base <= serial < state.base + self.config.window
                token = packet.token
                assert token.slot == serial % self.config.window
                assert state.generations[token.slot] == token.generation
                pending_data = {op for op, w in self.pending.items()
                                if w.token == token and w.kind != "ready"}
                assert pending_data == packet.data_writes
                if packet.phase in ("PREPARED", "COMMITTING", "READY", "CPU_OWNED"):
                    host = self._host[(flow, token.slot)]
                    assert host.descriptor == self._descriptor(packet)
                    assert bytes(host.data[:len(packet.payload)]) == packet.payload
                    assert not pending_data
                if packet.phase in ("READY", "CPU_OWNED"):
                    assert self._host[(flow, token.slot)].ready == token.generation
                    assert not any(w.token == token for w in self.pending.values())
            ready_writes = [w for w in self.pending.values() if w.token.flow == flow and w.kind == "ready"]
            assert len(ready_writes) <= 1
        for write in self.pending.values():
            packet = self._flows[write.token.flow].packets.get(write.token.serial)
            assert packet is not None and packet.token == write.token
