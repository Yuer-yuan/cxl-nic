"""Existing CXLMemSim legacy TCP protocol, with bounded DPA accesses."""

import socket
import struct
import time


REQUEST = struct.Struct("<BQQQQQ64s")
RESPONSE = struct.Struct("<BQQ64s")


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

    def close(self):
        if not self.closed:
            self.socket.close()
            self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()

    def _request(self, op, address=0, size=0, data=b""):
        if (type(address) is not int or type(size) is not int
                or address < 0 or size < 0 or address + size > self.capacity
                or size > 64 or (size and address // 64 != (address + size - 1) // 64)):
            raise ValueError("request must stay within one cache line and the DPA capacity")
        if self.closed:
            raise TransportError("transport is closed")
        try:
            self.socket.sendall(REQUEST.pack(op, address, size, time.monotonic_ns(), 0, 0,
                                            data.ljust(64, b"\0")))
            chunks = bytearray()
            while len(chunks) < RESPONSE.size:
                part = self.socket.recv(RESPONSE.size - len(chunks))
                if not part:
                    raise TransportError("server closed before a complete response")
                chunks.extend(part)
            status, _, _, response = RESPONSE.unpack(chunks)
            if status != 0:
                raise TransportError(f"server returned status {status} for op {op}")
        except (OSError, TransportError) as error:
            # Never reuse an ambiguous request stream after timeout or disconnect.
            self.close()
            if isinstance(error, TransportError):
                raise
            raise TransportError(str(error)) from error
        return response[:size]

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
