"""RISC-V guest validation over the pinned CXLMemSim legacy TCP backend.

This exercises publication and ownership using real guest loads/stores, without
claiming a physical CXL.cache, NC-P, LLC, or weak-memory implementation.
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
INITIAL = {0: 254, 1: 510}
FIELDS = ("flow", "serial", "slot", "generation", "length")
PINS = {"qemu": "9e75918b07d6f90a063484f8a1acbed3bb56078b",
        "cxlmemsim": "3ade2316bc09a30e4050be56e2919310b2baa3c8"}


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


def qemu_command(binary, guest):
    return [str(binary), "-M", "sifive_u", "-machine",
            "cxl=on,cxl-fmw.0.targets.0=cxl.1,cxl-fmw.0.size=256M",
            "-smp", "2", "-m", "256M", "-bios", "none", "-kernel", str(guest),
            "-display", "none", "-monitor", "none", "-serial", "stdio", "-no-reboot",
            "-object", "memory-backend-ram,id=t3mem,size=256M",
            "-device", "pxb-cxl,bus=pcie.0,bus_nr=64,id=cxl.1",
            "-device", "cxl-rp,bus=cxl.1,port=0,id=rp-t3,chassis=0,slot=0",
            "-device", "cxl-type3,bus=rp-t3,volatile-memdev=t3mem,id=t3"]


def run_case(directory, qemu, server, guest, topology, mode, count, timeout):
    directory.mkdir()
    port = available_port()
    nonce = secrets.randbits(64)
    server_argv = [str(server), "--comm-mode=tcp", f"--port={port}", "--capacity=256",
                   "--backing-mode=file", f"--backing-file={directory / 'backing.raw'}",
                   f"--topology={topology}"]
    qemu_argv = qemu_command(qemu, guest)
    server_environment = {**os.environ, "CXL_BASE_ADDR": "0"}
    qemu_environment = {**os.environ, "CXL_TRANSPORT_MODE": "tcp",
                        "CXL_MEMSIM_HOST": "127.0.0.1", "CXL_MEMSIM_PORT": str(port),
                        "CXL_LATENCY_INJECT": "0"}
    result = {"mode": mode, "status": "running", "nonce": nonce,
              "qemu_argv": qemu_argv, "server_argv": server_argv,
              "packets_per_flow": count, "backend": "legacy TCP authoritative Type3 memory",
              "fault_injected": False}
    protocol = Protocol(Config(), INITIAL)
    server_process = guest_process = client = output = None
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
        control = struct.pack("<8Q", MAGIC, nonce, count, INITIAL[0], INITIAL[1], 2, 4, 1500)
        client.write(0, control)
        client.write(64, bytes(64))
        for index in range(8):
            base = SLOT_BASE + index * SLOT_STRIDE
            client.write(base, bytes(64))
            client.write(base + READY_OFFSET, bytes(64))
            client.write(base + RELEASE_OFFSET, bytes(64))
        guest_process = subprocess.Popen(qemu_argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                         stdin=subprocess.DEVNULL, env=qemu_environment,
                                         start_new_session=True, bufsize=0)
        output = GuestOutput(guest_process, directory / "guest.log")
        lengths = (1500, 65, 64, 63, 1, 256)
        payloads = {f: {s: pattern(nonce, f, s, lengths[(s - start) % len(lengths)])
                        for s in range(start, start + count)} for f, start in INITIAL.items()}
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
        rng = random.Random(0xC1A0)

        while True:
            if time.monotonic() > deadline:
                raise TimeoutError(f"integration deadline expired in {mode}")
            if server_process.poll() is not None:
                raise RuntimeError("CXLMemSim exited before the test completed")
            for line in output.poll():
                if line == "READY":
                    if client.read_u64(64) != 1:
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
                status = client.read_u64(64)
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
                if client.read_u64(slot_address(token) + RELEASE_OFFSET) == token.generation:
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
                client.write(address, data)
                protocol.complete(write.op_id)
            if mode == "early-ready" and first_target is not None and not result["fault_injected"]:
                waiting = [w for w in protocol.pending.values() if w.token == first_target]
                if len(waiting) == 1 and waiting[0].kind == "payload" and waiting[0].offset == 1472:
                    client.write_u64(slot_address(first_target) + READY_OFFSET, first_target.generation)
                    result["fault_injected"] = True
            protocol.check_invariants()
            if guest_done:
                if mode != "adversarial":
                    raise RuntimeError("negative control incorrectly completed successfully")
                if held or any(remaining.values()) or protocol.pending:
                    continue
                status = client.read_u64(64)
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

        result["producer_backend_reads"] = client.reads
        result["producer_backend_writes"] = client.writes
    except Exception as error:
        result.update(status="failed", error=repr(error))
        raise
    finally:
        stop_owned(guest_process)
        if output is not None:
            output.close()
        if client is not None:
            client.close()
        stop_owned(server_process)
        log.close()
        save_trace(directory / "events.jsonl", protocol.trace)
        (directory / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    guest_log = (directory / "guest.log").read_text(errors="replace")
    if ("Successfully connected to CXLMemSim" not in guest_log
            or re.search(r"CXL Type3:.*(?:failed|Failed|denied|falling back)", guest_log)):
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
    parser.add_argument("--case", choices=("all", "adversarial", "early-ready", "corrupt-payload"), default="all")
    args = parser.parse_args(argv)
    if args.packets_per_flow < 4 or args.timeout <= 0:
        parser.error("at least four packets per flow and a positive timeout are required")
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    result = {"status": "running", "cases": [], "pins": PINS,
              "scope": "RISC-V guest functional publication over Type3 TCP; no NC-P/LLC/ISA proof"}
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
                            mode, args.packets_per_flow, args.timeout)
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
