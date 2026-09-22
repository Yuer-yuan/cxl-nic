"""Existing CXLMemSim legacy TCP protocol, with bounded DPA accesses."""

import socket
import struct
import time


REQUEST = struct.Struct("<BQQQQQ64s")
RESPONSE = struct.Struct("<BQQ64s")
NCP_STATS = struct.Struct("<8Q")
OP_NCP_CONFIG = 20
OP_NCP_WRITE = 21
OP_NCP_QUERY = 22


class TransportError(RuntimeError):
    pass


class Client:
    def __init__(self, address, capacity=256 << 20, timeout=5.0):
        self.capacity = capacity
        self.socket = socket.create_connection(address, timeout=timeout)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.closed = False
        self.reads = 0
        self.writes = 0
        self.ncp_writes = 0

    def close(self):
        if not self.closed:
            self.socket.close()
            self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()

    def _exchange(self, op, address=0, size=0, data=b"", value=0, expected=0):
        if (type(address) is not int or type(size) is not int
                or address < 0 or size < 0 or address + size > self.capacity
                or size > 64 or (size and address // 64 != (address + size - 1) // 64)):
            raise ValueError("request must stay within one cache line and the DPA capacity")
        if (type(op) is not int or not 0 <= op <= 255
                or type(value) is not int or not 0 <= value < 1 << 64
                or type(expected) is not int or not 0 <= expected < 1 << 64):
            raise ValueError("operation and request values must be unsigned wire integers")
        if self.closed:
            raise TransportError("transport is closed")
        try:
            self.socket.sendall(REQUEST.pack(op, address, size, time.monotonic_ns(), value, expected,
                                            data.ljust(64, b"\0")))
            chunks = bytearray()
            while len(chunks) < RESPONSE.size:
                part = self.socket.recv(RESPONSE.size - len(chunks))
                if not part:
                    raise TransportError("server closed before a complete response")
                chunks.extend(part)
            status, latency, old_value, response = RESPONSE.unpack(chunks)
            if status != 0:
                raise TransportError(f"server returned status {status} for op {op}")
        except (OSError, TransportError) as error:
            # Never reuse an ambiguous request stream after timeout or disconnect.
            self.close()
            if isinstance(error, TransportError):
                raise
            raise TransportError(str(error)) from error
        return latency, old_value, response

    def _request(self, op, address=0, size=0, data=b"", value=0, expected=0):
        return self._exchange(op, address, size, data, value, expected)[2][:size]

    def read(self, address, size):
        if type(size) is not int or size <= 0:
            raise ValueError("read size must be positive")
        data = self._request(0, address, size)
        self.reads += 1
        return data

    def write(self, address, data):
        if not isinstance(data, bytes) or not data:
            raise ValueError("write requires nonempty bytes")
        self._request(1, address, len(data), data)
        self.writes += 1

    def read_u64(self, address):
        return struct.unpack("<Q", self.read(address, 8))[0]

    def write_u64(self, address, value):
        self.write(address, struct.pack("<Q", value))

    def configure_ncp(self, sets, ways):
        if (type(sets) is not int or type(ways) is not int or sets <= 0 or ways <= 0
                or sets > 65536 or ways > 64 or sets * ways > 1048576):
            raise ValueError("NC-P host LLC dimensions are out of range")
        _, _, data = self._exchange(OP_NCP_CONFIG, value=sets, expected=ways)
        actual_sets, actual_ways = struct.unpack_from("<QQ", data)
        if (actual_sets, actual_ways) != (sets, ways):
            self.close()
            raise TransportError("server returned a different NC-P host LLC configuration")

    def ncp_write(self, address, data):
        if not isinstance(data, bytes) or not data:
            raise ValueError("NC-P write requires nonempty bytes")
        self._request(OP_NCP_WRITE, address, len(data), data)
        self.ncp_writes += 1

    def query_ncp(self):
        latency, resident, data = self._exchange(OP_NCP_QUERY)
        values = NCP_STATS.unpack(data)
        result = dict(zip(("pushes", "push_bytes", "host_reads", "host_read_hits",
                           "first_demands", "first_demand_hits", "evictions", "writebacks"),
                          values))
        result.update(resident=resident, query_latency_ns=latency,
                      host_read_misses=result["host_reads"] - result["host_read_hits"],
                      first_demand_misses=result["first_demands"] - result["first_demand_hits"])
        if result["host_read_misses"] < 0 or result["first_demand_misses"] < 0:
            self.close()
            raise TransportError("server returned inconsistent NC-P counters")
        return result
