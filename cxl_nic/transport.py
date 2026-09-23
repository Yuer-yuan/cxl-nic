"""Existing CXLMemSim legacy TCP protocol, with bounded DPA accesses."""

import socket
import struct
import time


REQUEST = struct.Struct("<BQQQQQ64s")
RESPONSE = struct.Struct("<BQQ64s")
NCP_STATS = struct.Struct("<8Q")
HOST_LLC_TRAFFIC = struct.Struct("<8Q")
OP_NCP_CONFIG = 20
OP_NCP_WRITE = 21
OP_NCP_QUERY = 22
OP_DDIO_WRITE = 23
OP_DDIO_QUERY = 24
OP_HOST_LLC_TRAFFIC_QUERY = 25
OP_NCP_NC_WRITE = 26
OP_NCP_DEMAND_RANGE_QUERY = 27
OP_CXL_CACHE_PROTOCOL_QUERY = 28
OP_CXL_MEM_PROTOCOL_QUERY = 29


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
        self.ncp_nc_writes = 0
        self.ncp_nc_write_bytes = 0
        self.ddio_writes = 0

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

    def configure_host_llc(self, sets, ways):
        if (type(sets) is not int or type(ways) is not int or sets <= 0 or ways <= 0
                or sets > 65536 or ways > 64 or sets * ways > 1048576):
            raise ValueError("NC-P host LLC dimensions are out of range")
        _, _, data = self._exchange(OP_NCP_CONFIG, value=sets, expected=ways)
        actual_sets, actual_ways = struct.unpack_from("<QQ", data)
        if (actual_sets, actual_ways) != (sets, ways):
            self.close()
            raise TransportError("server returned a different host LLC configuration")

    def configure_ncp(self, sets, ways):
        self.configure_host_llc(sets, ways)

    def ncp_write(self, address, data):
        if not isinstance(data, bytes) or not data:
            raise ValueError("NC-P write requires nonempty bytes")
        self._request(OP_NCP_WRITE, address, len(data), data)
        self.ncp_writes += 1

    def ddio_write(self, address, data):
        if not isinstance(data, bytes) or not data:
            raise ValueError("DDIO write requires nonempty bytes")
        self._request(OP_DDIO_WRITE, address, len(data), data)
        self.ddio_writes += 1

    def ncp_nc_write(self, address, data):
        if not isinstance(data, bytes) or not data:
            raise ValueError("NC-write requires nonempty bytes")
        self._request(OP_NCP_NC_WRITE, address, len(data), data)
        self.ncp_nc_writes += 1
        self.ncp_nc_write_bytes += len(data)

    def _query_host_llc(self, operation):
        latency, resident, data = self._exchange(operation)
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

    def query_ncp(self):
        return self._query_host_llc(OP_NCP_QUERY)

    def query_ddio(self):
        return self._query_host_llc(OP_DDIO_QUERY)

    def query_first_demands(self, address, length):
        if (type(address) is not int or type(length) is not int
                or address < 0 or address % 64 or length <= 0 or length % 64
                or length > 1 << 20 or address + length > self.capacity):
            raise ValueError("first-demand range must be aligned, nonempty and within capacity")
        _, _, data = self._exchange(OP_NCP_DEMAND_RANGE_QUERY, address=address, value=length)
        demands, hits = struct.unpack_from("<QQ", data)
        if hits > demands:
            self.close()
            raise TransportError("server returned more first-demand hits than demands")
        return {"lines": demands, "hits": hits, "misses": demands - hits,
                "hit_rate": hits / demands if demands else None}

    def query_host_llc_traffic(self):
        _, _, data = self._exchange(OP_HOST_LLC_TRAFFIC_QUERY)
        values = HOST_LLC_TRAFFIC.unpack(data)
        result = {
            "backing_read_bytes": {"host": values[0], "nic": values[1]},
            "first_demand_backing_bytes": {"host": values[2], "nic": values[3]},
            "dirty_writeback_bytes": {"host": values[4], "nic": values[5]},
            "producer_backing_write_bytes": {"host": values[6], "nic": values[7]},
        }
        flat = [value for counter in result.values() for value in counter.values()]
        if (any(value % 64 for value in flat)
                or any(result["first_demand_backing_bytes"][home]
                       > result["backing_read_bytes"][home] for home in ("host", "nic"))):
            self.close()
            raise TransportError("server returned inconsistent host LLC backing traffic")
        return result

    def query_cxl_cache_protocol(self):
        _, _, data = self._exchange(OP_CXL_CACHE_PROTOCOL_QUERY)
        return dict(zip(("dcoh_staged", "d2h_write_requests", "h2d_write_pulls",
                         "d2h_data_bytes", "h2d_go_i", "dcoh_invalidations",
                         "nc_d2h_write_requests", "nc_memwr_fwd"),
                        struct.unpack("<8Q", data)))

    def query_cxl_mem_protocol(self):
        _, _, data = self._exchange(OP_CXL_MEM_PROTOCOL_QUERY)
        return dict(zip(("m2s_reads", "s2m_read_data_bytes", "s2m_read_completions",
                         "m2s_writes", "m2s_write_data_bytes",
                         "s2m_write_completions", "dirty_writeback_bytes",
                         "dcoh_read_misses"), struct.unpack("<8Q", data)))
