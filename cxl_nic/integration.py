"""RISC-V guest publication checks over pinned QEMU and CXLMemSim endpoints.

Type2 guest loads use an HDM fixed window. QEMU models the NC-P DCOH request,
CXL.cache write transaction sequence, host cache and CXL.mem miss/writeback
flows. It does not model a physical CPU cache or CXL link timing.
"""

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import random
import re
import secrets
import selectors
import signal
import socket
import struct
import subprocess
import time

from .checker import validate_trace
from .model import Config, Protocol
from .transport import Client
from .verify import save_trace


ROOT = Path(__file__).resolve().parent.parent
MAGIC = 0x43584C4E49433031
MASK = (1 << 64) - 1
SLOT_BASE = 0x10000
SLOT_STRIDE = 0x1000
PAYLOAD_OFFSET = 256
READY_OFFSET = 64
RELEASE_OFFSET = 128
TYPE2_DPA_BASE = 0x200000
INITIAL = {0: 254, 1: 510}
FIELDS = ("flow", "serial", "slot", "generation", "length")
PINS = {"qemu": "c86e85e57e3d449bf08982a17a5a952716fa0857",
        "cxlmemsim": "b5e183ea9732fa023c5df1a749a857430c3a237b"}


def pattern(nonce, flow, serial, length):
    result = bytearray()
    for block in range((length + 7) // 8):
        value = nonce ^ (flow << 56) ^ ((serial * 0x9E3779B97F4A7C15) & MASK)
        value ^= (block * 0xD6E8FEB86659FD93) & MASK
        value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & MASK
        value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & MASK
        value ^= value >> 31
        result.extend(struct.pack("<Q", value))
    return bytes(result[:length])


def slot_address(token):
    return SLOT_BASE + (token.flow * 4 + token.slot) * SLOT_STRIDE


def write_address(write):
    base = slot_address(write.token)
    if write.kind == "payload":
        return base + PAYLOAD_OFFSET + write.offset, write.data
    if write.kind == "descriptor":
        return base + FIELDS.index(write.field) * 8, struct.pack("<Q", write.value)
    return base + READY_OFFSET, struct.pack("<Q", write.token.generation)


def backend_address(address, device_type):
    if device_type not in ("type2", "type3"):
        raise ValueError("device_type must be type2 or type3")
    return address + (TYPE2_DPA_BASE if device_type == "type2" else 0)


class GuestOutput:
    def __init__(self, process, path):
        self.process = process
        self.selector = selectors.DefaultSelector()
        self.selector.register(process.stdout, selectors.EVENT_READ)
        self.log = path.open("wb")
        self.buffer = b""

    def poll(self, timeout=0):
        lines = []
        for key, _ in self.selector.select(timeout):
            data = os.read(key.fileobj.fileno(), 65536)
            if not data:
                self.selector.unregister(key.fileobj)
                continue
            self.log.write(data)
            self.log.flush()
            self.buffer += data
            while b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)
                lines.append(line.decode(errors="replace").strip())
        return lines

    def close(self):
        self.poll()
        self.log.close()
        self.selector.close()
        self.process.stdout.close()


def stop_owned(process):
    if process is not None and process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def available_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class GateController:
    """Hold a host push flag between deterministic payload-line samples.

    Sampling and control delay are counted in payload writes, not wall time or
    CXL cycles. The immediate mode remains the original occupancy oracle.
    """

    def __init__(self, threshold, sample_every_lines=None, control_delay_lines=0):
        if type(threshold) is not int or threshold < 0:
            raise ValueError("gate threshold must be a nonnegative integer")
        if (sample_every_lines is not None
                and (type(sample_every_lines) is not int or sample_every_lines <= 0)):
            raise ValueError("ncp_gate_sample_every_lines must be positive or None")
        if type(control_delay_lines) is not int or control_delay_lines < 0:
            raise ValueError("ncp_gate_control_delay_lines must be nonnegative")
        if sample_every_lines is None and control_delay_lines:
            raise ValueError("gate control delay requires sampled gating")
        self.threshold = threshold
        self.sample_every_lines = sample_every_lines
        self.control_delay_lines = control_delay_lines
        self.lines = 0
        self.enabled = True
        self.requested = True
        self.pending = []
        self.samples = 0
        self.control_writes = 0
        self.control_applies = 0
        self.push_lines = 0
        self.nc_write_lines = 0

    def _apply_due(self):
        while self.pending and self.pending[0][0] <= self.lines:
            _, enabled = self.pending.pop(0)
            self.enabled = enabled
            self.control_applies += 1

    def choose_push(self, resident_lines):
        """Choose placement for the next line; query occupancy only on a sample."""
        self._apply_due()
        if self.sample_every_lines is None or self.lines % self.sample_every_lines == 0:
            desired = resident_lines() < self.threshold
            self.samples += 1
            if self.sample_every_lines is None:
                self.enabled = desired
            elif desired != self.requested:
                self.requested = desired
                self.pending.append((self.lines + self.control_delay_lines, desired))
                self.control_writes += 1
                self._apply_due()
        push = self.enabled
        self.lines += 1
        if push:
            self.push_lines += 1
        else:
            self.nc_write_lines += 1
        return push

    def snapshot(self):
        return {"mode": "instant" if self.sample_every_lines is None else "sampled_lines",
                "control_path": "producer_controller_model",
                "sample_every_payload_lines": self.sample_every_lines,
                "control_delay_payload_lines": self.control_delay_lines,
                "payload_lines": self.lines,
                "samples": self.samples,
                "control_writes": self.control_writes,
                "control_applies": self.control_applies,
                "pending_control_writes": len(self.pending),
                "push_lines": self.push_lines,
                "nc_write_lines": self.nc_write_lines}


def qemu_command(binary, guest, device_type="type3", port=None,
                 ncp_port=None, llc_sets=64, llc_ways=8):
    command = [str(binary), "-M", "sifive_u", "-machine",
               "cxl=on,cxl-fmw.0.targets.0=cxl.1,cxl-fmw.0.size=256M",
               "-smp", "2", "-m", "256M", "-bios", "none", "-kernel", str(guest),
               "-display", "none", "-monitor", "none", "-serial", "stdio", "-no-reboot"]
    if device_type == "type3":
        return command + ["-object", "memory-backend-ram,id=t3mem,size=256M",
                          "-device", "pxb-cxl,bus=pcie.0,bus_nr=64,id=cxl.1",
                          "-device", "cxl-rp,bus=cxl.1,port=0,id=rp-t3,chassis=0,slot=0",
                          "-device", "cxl-type3,bus=rp-t3,volatile-memdev=t3mem,id=t3"]
    if device_type != "type2":
        raise ValueError("device_type must be type2 or type3")
    if type(port) is not int or not 0 < port <= 65535:
        raise ValueError("a valid CXLMemSim port is required for Type2")
    type2 = ("cxl-type2,bus=rp-t2,id=t2,sn=200,gpu-mode=0,"
             "cache-size=1M,mem-size=256M,"
             "cxlmemsim-addr=127.0.0.1,"
             f"cxlmemsim-port={port},coherency-enabled=true")
    if ncp_port is not None:
        type2 += (f",ncp-ingress-port={ncp_port},ncp-host-sets={llc_sets},"
                  f"ncp-host-ways={llc_ways}")
    return command + ["-device", "pxb-cxl,bus=pcie.0,bus_nr=64,id=cxl.1",
                      "-device", "cxl-rp,bus=cxl.1,port=0,id=rp-t2,chassis=0,slot=0",
                      "-device", type2]


def run_case(directory, qemu, server, guest, topology, mode, count, timeout,
             device_type="type3", data_path="legacy", llc_sets=64, llc_ways=8,
             ncp_post_push="none", ncp_gate_resident_lines=None,
             global_push_credit_bytes=None, ncp_gate_sample_every_lines=None,
             ncp_gate_control_delay_lines=0, llc_owner="cxlmemsim"):
    if data_path not in ("legacy", "ncp", "ddio"):
        raise ValueError("data_path must be legacy, ncp, or ddio")
    if data_path in ("ncp", "ddio") and device_type != "type2":
        raise ValueError("modeled cache injection requires a Type2 endpoint")
    if llc_owner not in ("cxlmemsim", "qemu"):
        raise ValueError("llc_owner must be cxlmemsim or qemu")
    if llc_owner == "qemu" and (device_type != "type2" or data_path == "legacy"):
        raise ValueError("QEMU host cache requires Type2 NC-P or DDIO mode")
    if ncp_post_push not in ("none", "before-ready"):
        raise ValueError("ncp_post_push must be none or before-ready")
    if ncp_post_push != "none" and (data_path != "ncp" or mode != "adversarial"):
        raise ValueError("post-push NC-write requires adversarial NC-P mode")
    if (ncp_gate_resident_lines is not None
            and (type(ncp_gate_resident_lines) is not int or ncp_gate_resident_lines < 0)):
        raise ValueError("ncp_gate_resident_lines must be a nonnegative integer or None")
    if ncp_gate_resident_lines is not None and (data_path != "ncp" or mode != "adversarial"):
        raise ValueError("adaptive gating requires adversarial NC-P mode")
    if ncp_gate_resident_lines is not None and ncp_post_push != "none":
        raise ValueError("adaptive gating and post-push withdrawal are separate policies")
    if ((ncp_gate_sample_every_lines is not None or ncp_gate_control_delay_lines)
            and ncp_gate_resident_lines is None):
        raise ValueError("gate sampling requires ncp_gate_resident_lines")
    gate = (GateController(ncp_gate_resident_lines, ncp_gate_sample_every_lines,
                           ncp_gate_control_delay_lines)
            if ncp_gate_resident_lines is not None else None)
    if (global_push_credit_bytes is not None
            and (type(global_push_credit_bytes) is not int or global_push_credit_bytes < 1536)):
        raise ValueError("global_push_credit_bytes must fit one maximum-size packet")
    if mode == "adversarial" and global_push_credit_bytes is not None and global_push_credit_bytes < 3072:
        raise ValueError("adversarial hold requires credit for both initial maximum-size packets")
    directory.mkdir()
    port = available_port()
    ncp_port = available_port() if llc_owner == "qemu" else None
    while ncp_port == port:
        ncp_port = available_port()
    nonce = secrets.randbits(64)
    server_argv = [str(server), "--comm-mode=tcp", f"--port={port}", "--capacity=256",
                   "--backing-mode=file", f"--backing-file={directory / 'backing.raw'}",
                   f"--topology={topology}"]
    qemu_argv = qemu_command(qemu, guest, device_type, port, ncp_port,
                             llc_sets, llc_ways)
    server_environment = {**os.environ, "CXL_BASE_ADDR": "0"}
    qemu_environment = {**os.environ, "CXL_TRANSPORT_MODE": "tcp",
                        "CXL_MEMSIM_HOST": "127.0.0.1", "CXL_MEMSIM_PORT": str(port),
                        "CXL_LATENCY_INJECT": "0"}
    result = {"mode": mode, "status": "running", "nonce": nonce,
              "qemu_argv": qemu_argv, "server_argv": server_argv,
              "packets_per_flow": count, "device_type": device_type,
              "backend_dpa_base": backend_address(0, device_type),
              "data_path": data_path,
              "guest_memory_path": "type2_hdm_cxl_mem" if device_type == "type2" else "type3_hdm_cxl_mem",
              "llc_owner": llc_owner,
              "ncp_post_push": ncp_post_push,
              "ncp_gate_resident_lines": ncp_gate_resident_lines,
              "ncp_gate_sample_every_lines": ncp_gate_sample_every_lines,
              "ncp_gate_control_delay_lines": ncp_gate_control_delay_lines,
              "global_push_credit_bytes": global_push_credit_bytes,
              "backend": ({"ncp": "explicit NC-P with NIC-memory backing",
                           "ddio": "modeled DDIO with host-memory backing"}[data_path]
                          if data_path != "legacy" else
                          f"legacy TCP authoritative {device_type.capitalize()} memory"),
              "fault_injected": False}
    protocol = Protocol(Config(global_push_credit_bytes=global_push_credit_bytes), INITIAL)
    server_process = guest_process = client = cache_client = output = None
    log = (directory / "server.log").open("wb")
    deadline = time.monotonic() + timeout
    try:
        server_process = subprocess.Popen(server_argv, stdout=log, stderr=subprocess.STDOUT,
                                          env=server_environment, start_new_session=True)
        while client is None:
            if server_process.poll() is not None:
                raise RuntimeError("CXLMemSim exited during startup; see server.log")
            if time.monotonic() > deadline:
                raise TimeoutError("CXLMemSim did not start")
            try:
                client = Client(("127.0.0.1", port), timeout=min(5.0, timeout))
            except OSError:
                time.sleep(0.05)
        if data_path != "legacy" and llc_owner == "cxlmemsim":
            client.configure_host_llc(llc_sets, llc_ways)
        control = struct.pack("<8Q", MAGIC, nonce, count, INITIAL[0], INITIAL[1], 2, 4, 1500)
        client.write(backend_address(0, device_type), control)
        client.write(backend_address(64, device_type), bytes(64))
        for index in range(8):
            base = SLOT_BASE + index * SLOT_STRIDE
            client.write(backend_address(base, device_type), bytes(64))
            client.write(backend_address(base + READY_OFFSET, device_type), bytes(64))
            client.write(backend_address(base + RELEASE_OFFSET, device_type), bytes(64))
        guest_process = subprocess.Popen(qemu_argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                         stdin=subprocess.DEVNULL, env=qemu_environment,
                                         start_new_session=True, bufsize=0)
        output = GuestOutput(guest_process, directory / "guest.log")
        if llc_owner == "qemu":
            while cache_client is None:
                if guest_process.poll() is not None:
                    raise RuntimeError("QEMU exited before host cache ingress connected")
                if time.monotonic() > deadline:
                    raise TimeoutError("QEMU host cache ingress did not start")
                try:
                    cache_client = Client(("127.0.0.1", ncp_port), timeout=min(5.0, timeout))
                except OSError:
                    time.sleep(0.05)
            cache_client.configure_host_llc(llc_sets, llc_ways)
        producer = cache_client or client
        lengths = (1500, 65, 64, 63, 1, 256)
        payloads = {f: {s: pattern(nonce, f, s, lengths[(s - start) % len(lengths)])
                        for s in range(start, start + count)} for f, start in INITIAL.items()}
        result["payload_lines"] = sum((len(payload) + 63) // 64
                                      for packets in payloads.values()
                                      for payload in packets.values())
        remaining = {f: dict(packets) for f, packets in payloads.items()}
        bases = dict(INITIAL)
        freed = {f: set() for f in INITIAL}
        consumed = {f: 0 for f in INITIAL}
        held = {}
        guest_ready = False
        guest_done = False
        guest_failure = None
        first_target = None
        corruption_done = False
        held_progress = False
        withdrawn = set()
        withdrawal_lines = 0
        rng = random.Random(0xC1A0)

        while True:
            if time.monotonic() > deadline:
                raise TimeoutError(f"integration deadline expired in {mode}")
            if server_process.poll() is not None:
                raise RuntimeError("CXLMemSim exited before the test completed")
            for line in output.poll():
                if line == "READY":
                    if client.read_u64(backend_address(64, device_type)) != 1:
                        raise RuntimeError("guest handshake was not visible through CXLMemSim")
                    guest_ready = True
                elif line.startswith("PACKET "):
                    parts = line.split()
                    if len(parts) != 7:
                        raise RuntimeError("malformed guest packet observation")
                    values = [int(value) for value in parts[1:6]]
                    descriptor = dict(zip(FIELDS, values))
                    data = bytes.fromhex(parts[6])
                    flow = descriptor["flow"]
                    delivery = protocol.observe_consumption(flow, descriptor, data)
                    if data != payloads[flow][delivery.token.serial] or descriptor != {
                            **asdict(delivery.token), "length": len(data)}:
                        raise RuntimeError("guest observation differs from ingress")
                    held[delivery.token] = delivery
                    consumed[flow] += 1
                    if flow == 1 and consumed[0] == 0:
                        held_progress = True
                elif line.startswith("FAIL ") or line.startswith("TRAP "):
                    guest_failure = line
                elif line.startswith("DONE "):
                    if int(line.split()[1]) != 2 * count:
                        raise RuntimeError("guest DONE count mismatch")
                    guest_done = True
            if guest_failure:
                if mode == "adversarial" or not result["fault_injected"]:
                    raise RuntimeError(f"guest failed: {guest_failure}")
                fields = guest_failure.split()
                if (len(fields) != 5 or fields[0] != "FAIL" or int(fields[1]) != 2
                        or int(fields[2]) != 0 or int(fields[3]) != INITIAL[0]):
                    raise RuntimeError(f"unexpected negative-control failure: {guest_failure}")
                offset = int(fields[4])
                if ((mode == "corrupt-payload" and offset != 0)
                        or (mode == "early-ready" and not 1472 <= offset < 1500)):
                    raise RuntimeError(f"failure did not identify the injected byte range: {guest_failure}")
                status = client.read_u64(backend_address(64, device_type))
                if status < 0x100:
                    # UART can precede the guest's final status store.
                    time.sleep(0.001)
                    continue
                if status != 0x102:
                    raise RuntimeError("negative-control guest status does not match payload rejection")
                result.update(status="expected_rejection", guest_failure=guest_failure,
                              guest_status=status, trace=validate_trace(protocol.trace, require_drained=False))
                break
            if guest_process.poll() is not None:
                raise RuntimeError("QEMU exited before verification completed; see guest.log")
            if not guest_ready:
                time.sleep(0.001)
                continue

            for token in list(held):
                release = backend_address(slot_address(token) + RELEASE_OFFSET, device_type)
                if client.read_u64(release) == token.generation:
                    protocol.release(token)
                    del held[token]
                    freed[token.flow].add(token.serial)
                    while bases[token.flow] in freed[token.flow]:
                        freed[token.flow].remove(bases[token.flow])
                        bases[token.flow] += 1
            for flow in INITIAL:
                # Reverse each admitted window to ensure actual ingress reordering.
                candidates = sorted((s for s in remaining[flow]
                                     if bases[flow] <= s < bases[flow] + 4), reverse=True)
                for serial in candidates:
                    payload = remaining[flow].pop(serial)
                    if protocol.receive(flow, serial & 255, serial >> 8, payload) != "accepted":
                        raise RuntimeError("unexpected ingress rejection")
                    if protocol.receive(flow, serial & 255, serial >> 8, payload) != "duplicate":
                        raise RuntimeError("duplicate changed ingress state")
            protocol.pump()
            for write in protocol.pending.values():
                if write.token.flow == 0 and write.token.serial == INITIAL[0]:
                    first_target = write.token
                    break

            if ncp_post_push == "before-ready":
                ready_tokens = sorted({write.token for write in protocol.pending.values()
                                       if write.kind == "ready" and write.token not in withdrawn},
                                      key=lambda token: (token.flow, token.serial))
                for token in ready_tokens:
                    payload = payloads[token.flow][token.serial]
                    for offset in range(0, len(payload), 64):
                        address = slot_address(token) + PAYLOAD_OFFSET + offset
                        producer.ncp_nc_write(backend_address(address, device_type),
                                              payload[offset:offset + 64])
                        withdrawal_lines += 1
                    withdrawn.add(token)

            eligible = []
            for write in protocol.pending.values():
                target = write.token.flow == 0 and write.token.serial == INITIAL[0]
                last_line = target and write.kind == "payload" and write.offset == 1472
                length_field = target and write.kind == "descriptor" and write.field == "length"
                if mode == "early-ready" and last_line:
                    continue
                if mode == "adversarial" and ((last_line and consumed[1] < 1)
                                               or (length_field and consumed[1] < 2)):
                    continue
                eligible.append(write)
            if eligible:
                write = rng.choice(eligible)
                address, data = write_address(write)
                if (mode == "corrupt-payload" and not corruption_done
                        and write.token.flow == 0 and write.token.serial == INITIAL[0]
                        and write.kind == "payload" and write.offset == 0):
                    data = bytes([data[0] ^ 0x80]) + data[1:]
                    corruption_done = True
                    result["fault_injected"] = True
                target_address = backend_address(address, device_type)
                if data_path == "ncp" and write.kind == "payload" and gate is not None:
                    if gate.choose_push(lambda: producer.query_ncp()["resident"]):
                        producer.ncp_write(target_address, data)
                    else:
                        producer.ncp_nc_write(target_address, data)
                elif data_path != "legacy" and write.kind in ("payload", "ready"):
                    (producer.ncp_write if data_path == "ncp" else producer.ddio_write)(target_address, data)
                else:
                    producer.write(target_address, data)
                protocol.complete(write.op_id)
            if mode == "early-ready" and first_target is not None and not result["fault_injected"]:
                waiting = [w for w in protocol.pending.values() if w.token == first_target]
                if len(waiting) == 1 and waiting[0].kind == "payload" and waiting[0].offset == 1472:
                    ready = backend_address(slot_address(first_target) + READY_OFFSET, device_type)
                    ready_data = struct.pack("<Q", first_target.generation)
                    if data_path != "legacy":
                        (producer.ncp_write if data_path == "ncp" else producer.ddio_write)(ready, ready_data)
                    else:
                        producer.write(ready, ready_data)
                    result["fault_injected"] = True
            protocol.check_invariants()
            if guest_done:
                if mode != "adversarial":
                    raise RuntimeError("negative control incorrectly completed successfully")
                if held or any(remaining.values()) or protocol.pending:
                    continue
                status = client.read_u64(backend_address(64, device_type))
                if status != 2:
                    continue
                if not held_progress or consumed != {0: count, 1: count}:
                    raise RuntimeError("missing cross-flow progress or delivery evidence")
                result.update(status="passed", guest_status=status, consumed=consumed,
                              other_flow_progress_while_held=held_progress,
                              trace=validate_trace(protocol.trace))
                break
            if not eligible:
                time.sleep(0.001)

        result["producer_backend_reads"] = client.reads + (cache_client.reads if cache_client else 0)
        result["producer_backend_writes"] = client.writes + (cache_client.writes if cache_client else 0)
        if data_path != "legacy":
            cache = (producer.query_ncp if data_path == "ncp" else producer.query_ddio)()
            cache.update(producer.query_host_llc_traffic())
            demand_by_kind = {kind: {"lines": 0, "hits": 0}
                              for kind in ("payload", "ready")}
            payload_span = ((max(lengths) + 63) // 64) * 64
            for flow in INITIAL:
                for slot in range(4):
                    base = SLOT_BASE + (flow * 4 + slot) * SLOT_STRIDE
                    for kind, offset, span in (("payload", PAYLOAD_OFFSET, payload_span),
                                               ("ready", READY_OFFSET, 64)):
                        observed = producer.query_first_demands(
                            backend_address(base + offset, device_type), span)
                        demand_by_kind[kind]["lines"] += observed["lines"]
                        demand_by_kind[kind]["hits"] += observed["hits"]
            for observed in demand_by_kind.values():
                observed["misses"] = observed["lines"] - observed["hits"]
                observed["hit_rate"] = (observed["hits"] / observed["lines"]
                                        if observed["lines"] else None)
            if (sum(item["lines"] for item in demand_by_kind.values()) != cache["first_demands"]
                    or sum(item["hits"] for item in demand_by_kind.values()) != cache["first_demand_hits"]):
                raise RuntimeError("payload/ready first-demand ranges do not conserve LLC counters")
            if (result["status"] == "passed"
                    and (demand_by_kind["payload"]["lines"] != result["payload_lines"]
                         or demand_by_kind["ready"]["lines"] != 2 * count)):
                raise RuntimeError("successful guest did not demand every payload and ready line")
            cache["payload_first_demand"] = demand_by_kind["payload"]
            cache["ready_first_demand"] = demand_by_kind["ready"]
            cache.update(nc_writes=producer.ncp_nc_writes,
                         nc_write_bytes=producer.ncp_nc_write_bytes,
                         gated_push_lines=gate.push_lines if gate is not None else 0,
                         gated_nc_write_lines=gate.nc_write_lines if gate is not None else 0)
            completed = producer.ncp_writes if data_path == "ncp" else producer.ddio_writes
            result[data_path] = {**cache, "configured_sets": llc_sets,
                                 "configured_ways": llc_ways}
            if llc_owner == "qemu":
                server_cache = client.query_ncp()
                result["cxlmemsim_cache_bypass"] = server_cache
                if (server_cache["pushes"] or server_cache["host_reads"]
                        or server_cache["first_demands"]):
                    raise RuntimeError("QEMU cache run also used the CXLMemSim LLC model")
                cache_protocol = producer.query_cxl_cache_protocol()
                mem_protocol = producer.query_cxl_mem_protocol()
                result["cxl_cache_protocol"] = cache_protocol
                result["cxl_mem_protocol"] = mem_protocol
                expected_pushes = completed if data_path == "ncp" else 0
                if (any(cache_protocol[key] != expected_pushes for key in
                        ("dcoh_staged", "d2h_write_requests", "h2d_write_pulls",
                         "h2d_go_i", "dcoh_invalidations"))
                        or cache_protocol["d2h_data_bytes"] != expected_pushes * 64
                        or cache_protocol["nc_d2h_write_requests"] !=
                        producer.ncp_nc_writes
                        or cache_protocol["nc_memwr_fwd"] != producer.ncp_nc_writes):
                    raise RuntimeError("DCOH/CXL.cache push transaction did not complete")
                if (mem_protocol["m2s_reads"] != mem_protocol["s2m_read_completions"]
                        or mem_protocol["s2m_read_data_bytes"] !=
                        mem_protocol["m2s_reads"] * 64
                        or mem_protocol["dcoh_read_misses"] != mem_protocol["m2s_reads"]
                        or mem_protocol["m2s_writes"] !=
                        mem_protocol["s2m_write_completions"]
                        or mem_protocol["dirty_writeback_bytes"] !=
                        cache["dirty_writeback_bytes"]["nic"]):
                    raise RuntimeError("CXL.mem miss or writeback transaction is inconsistent")
            if (cache["pushes"] != completed
                    or cache["first_demands"] == 0
                    or cache["first_demand_hits"] > cache["first_demands"]):
                raise RuntimeError("cache injection completion or first-demand evidence is inconsistent")
            first_backing = cache["first_demand_backing_bytes"]
            dirty_backing = cache["dirty_writeback_bytes"]
            producer_backing = cache["producer_backing_write_bytes"]
            expected_home = "nic" if data_path == "ncp" else "host"
            other_home = "host" if data_path == "ncp" else "nic"
            if (first_backing[expected_home] != cache["first_demand_misses"] * 64
                    or first_backing[other_home] != 0
                    or dirty_backing[expected_home] != cache["writebacks"] * 64
                    or dirty_backing[other_home] != 0
                    or cache["backing_read_bytes"][expected_home] < first_backing[expected_home]
                    or cache["backing_read_bytes"][other_home] != 0
                    or producer_backing["nic"] != producer.ncp_nc_writes * 64
                    or producer_backing["host"] != (completed * 64 if data_path == "ddio" else 0)):
                raise RuntimeError("cache backing-home traffic is inconsistent")
            if (ncp_post_push == "before-ready"
                    and (withdrawal_lines != producer.ncp_nc_writes
                         or cache["first_demand_misses"] < withdrawal_lines)):
                raise RuntimeError("post-push NC-write did not force payload fallback")
            if (gate is not None
                    and (gate.lines != result["payload_lines"]
                         or not gate.push_lines or not gate.nc_write_lines
                         or gate.nc_write_lines != producer.ncp_nc_writes
                         or cache["first_demand_misses"] < gate.nc_write_lines)):
                raise RuntimeError("adaptive gate did not exercise both push and NC-write")
            result["withdrawal_lines"] = withdrawal_lines
            result["gate_decisions"] = {"push_lines": gate.push_lines if gate is not None else 0,
                                        "nc_write_lines": gate.nc_write_lines if gate is not None else 0}
            result["gate_sampling"] = gate.snapshot() if gate is not None else None
    except Exception as error:
        result.update(status="failed", error=repr(error))
        raise
    finally:
        stop_owned(guest_process)
        if output is not None:
            output.close()
        if client is not None:
            client.close()
        if cache_client is not None:
            cache_client.close()
        stop_owned(server_process)
        log.close()
        save_trace(directory / "events.jsonl", protocol.trace)
        (directory / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    guest_log = (directory / "guest.log").read_text(errors="replace")
    connected = ((device_type == "type3" and "Successfully connected to CXLMemSim" in guest_log)
                 or (device_type == "type2"
                     and "CXL Type2: Connected to CXLMemSim" in guest_log
                     and "CXL Type2: Device realized" in guest_log))
    if (not connected
            or (device_type == "type2" and
                "CXL Type2: CXL.mem HDM read path active" not in guest_log)
            or (llc_owner == "qemu"
                and "CXL Type2: QEMU host NC-P cache active" not in guest_log)
            or re.search(r"CXL Type[23]:.*(?:failed|Failed|denied|falling back)", guest_log)):
        result.update(status="failed", error="guest transport connection/fallback check failed")
        (directory / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        raise RuntimeError(result["error"])
    return result


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--qemu", type=Path, default=ROOT / "build/integration/qemu/qemu-system-riscv64")
    parser.add_argument("--server", type=Path, default=ROOT / "build/integration/cxlmemsim/cxlmemsim_server")
    parser.add_argument("--guest", type=Path, default=ROOT / "build/integration/guest/consumer.elf")
    parser.add_argument("--packets-per-flow", type=int, default=16)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--device-type", choices=("type2", "type3"), default="type3")
    parser.add_argument("--data-path", choices=("legacy", "ncp", "ddio"), default="legacy")
    parser.add_argument("--llc-owner", choices=("cxlmemsim", "qemu"), default="cxlmemsim")
    parser.add_argument("--host-llc-sets", "--ncp-sets", dest="host_llc_sets", type=int, default=64)
    parser.add_argument("--host-llc-ways", "--ncp-ways", dest="host_llc_ways", type=int, default=8)
    parser.add_argument("--ncp-post-push", choices=("none", "before-ready"), default="none")
    parser.add_argument("--ncp-gate-resident-lines", type=int)
    parser.add_argument("--ncp-gate-sample-every-lines", type=int)
    parser.add_argument("--ncp-gate-control-delay-lines", type=int, default=0)
    parser.add_argument("--global-push-credit-bytes", type=int)
    parser.add_argument("--case", choices=("all", "adversarial", "early-ready", "corrupt-payload"), default="all")
    args = parser.parse_args(argv)
    if args.packets_per_flow < 4 or args.timeout <= 0:
        parser.error("at least four packets per flow and a positive timeout are required")
    if args.data_path in ("ncp", "ddio") and args.device_type != "type2":
        parser.error("modeled cache injection requires --device-type type2")
    if args.llc_owner == "qemu" and (args.device_type != "type2" or args.data_path == "legacy"):
        parser.error("--llc-owner qemu requires Type2 NC-P or DDIO mode")
    if args.ncp_post_push != "none" and (args.data_path != "ncp" or args.case != "adversarial"):
        parser.error("--ncp-post-push requires --data-path ncp --case adversarial")
    if args.ncp_gate_resident_lines is not None and args.ncp_gate_resident_lines < 0:
        parser.error("--ncp-gate-resident-lines must be nonnegative")
    if args.ncp_gate_resident_lines is not None and (args.data_path != "ncp" or args.case != "adversarial"):
        parser.error("--ncp-gate-resident-lines requires --data-path ncp --case adversarial")
    if args.ncp_gate_resident_lines is not None and args.ncp_post_push != "none":
        parser.error("adaptive gating and post-push withdrawal are separate policies")
    if ((args.ncp_gate_sample_every_lines is not None or args.ncp_gate_control_delay_lines)
            and args.ncp_gate_resident_lines is None):
        parser.error("gate sampling requires --ncp-gate-resident-lines")
    if (args.ncp_gate_sample_every_lines is not None
            and args.ncp_gate_sample_every_lines <= 0):
        parser.error("--ncp-gate-sample-every-lines must be positive")
    if args.ncp_gate_control_delay_lines < 0:
        parser.error("--ncp-gate-control-delay-lines must be nonnegative")
    if args.ncp_gate_sample_every_lines is None and args.ncp_gate_control_delay_lines:
        parser.error("gate control delay requires sampled gating")
    if args.global_push_credit_bytes is not None and args.global_push_credit_bytes < 1536:
        parser.error("--global-push-credit-bytes must fit one maximum-size packet")
    if (args.case in ("all", "adversarial") and args.global_push_credit_bytes is not None
            and args.global_push_credit_bytes < 3072):
        parser.error("adversarial hold requires credit for both initial maximum-size packets")
    if (args.host_llc_sets <= 0 or args.host_llc_ways <= 0 or args.host_llc_sets > 65536
            or args.host_llc_ways > 64 or args.host_llc_sets * args.host_llc_ways > 1048576):
        parser.error("host LLC dimensions are out of range")
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    result = {"status": "running", "cases": [], "pins": PINS,
              "device_type": args.device_type,
              "data_path": args.data_path,
              "llc_owner": args.llc_owner,
              "ncp_post_push": args.ncp_post_push,
              "ncp_gate_resident_lines": args.ncp_gate_resident_lines,
              "ncp_gate_sample_every_lines": args.ncp_gate_sample_every_lines,
              "ncp_gate_control_delay_lines": args.ncp_gate_control_delay_lines,
              "global_push_credit_bytes": args.global_push_credit_bytes,
              "scope": (f"RISC-V guest functional publication over {args.device_type.capitalize()} "
                        + (f"finite {args.llc_owner} host-cache model; "
                           "Type2 HDM CXL.mem path, QEMU transaction sequence "
                           "when selected; no physical LLC or CXL link timing proof"
                           if args.data_path != "legacy" else
                           "legacy TCP; no NC-P/LLC/ISA proof"))}
    try:
        for name, revision in PINS.items():
            path = ROOT / "thirdparty" / name
            actual = subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
            if actual != revision:
                raise RuntimeError(f"{name} revision differs from audited source")
            if subprocess.check_output(["git", "-C", str(path), "status", "--porcelain", "--untracked-files=no"], text=True):
                raise RuntimeError(f"{name} has tracked source changes")
        for name in ("qemu", "server", "guest"):
            path = getattr(args, name).resolve()
            setattr(args, name, path)
            result[name] = {"path": str(path), "sha256": digest(path)}
        result["source_sha256"] = {
            str(path.relative_to(ROOT)): digest(path)
            for directory in ("cxl_nic", "guest", "scripts", "tests")
            for path in sorted((ROOT / directory).glob("*"))
            if path.is_file() and path.suffix in (".py", ".c", ".S", ".ld", ".sh")}
        cases = ("adversarial", "early-ready", "corrupt-payload") if args.case == "all" else (args.case,)
        for mode in cases:
            case = run_case(args.output / mode, args.qemu, args.server, args.guest,
                            ROOT / "thirdparty/cxlmemsim/qemu_integration/topology_simple.txt",
                            mode, args.packets_per_flow, args.timeout, args.device_type,
                            args.data_path, args.host_llc_sets, args.host_llc_ways,
                            args.ncp_post_push, args.ncp_gate_resident_lines,
                            args.global_push_credit_bytes,
                            args.ncp_gate_sample_every_lines,
                            args.ncp_gate_control_delay_lines, args.llc_owner)
            result["cases"].append(case)
        result["status"] = "passed"
    except Exception as error:
        result.update(status="failed", error=repr(error))
        raise
    finally:
        (args.output / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": result["status"], "cases": [(c["mode"], c["status"]) for c in result["cases"]],
                      "result": str(args.output / "result.json")}))


if __name__ == "__main__":
    main()
