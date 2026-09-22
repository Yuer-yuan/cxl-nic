"""Symbolic shared LLC with explicit backing; no time or hardware protocol model.

Tags are physical line addresses, never packet generations. Callers must enforce
ownership and drain old operations before slot reuse. Full-line stores carry all
data and avoid a backing read; no coherence permission traffic is modeled here.
"""

from copy import deepcopy
from dataclasses import dataclass


LINE_BYTES = 64
HOMES = ("host", "nic")


def _home_counts():
    return {home: 0 for home in HOMES}


@dataclass
class _Backing:
    home: str
    data: bytearray


@dataclass
class _Line:
    address: int
    data: bytearray
    dirty: bool
    touched: int


class Cache:
    """Finite set-associative LRU cache shared by every access category.

    I/O admission restricts allocation on a miss. Existing lines are found in
    all ways, including CPU-filled lines outside an I/O allocation mask. Reads
    and stores must lie within one explicitly defined 64-byte line.
    """

    def __init__(self, sets, ways):
        if type(sets) is not int or sets <= 0 or type(ways) is not int or ways <= 0:
            raise ValueError("sets and ways must be positive integers")
        self.sets = sets
        self.ways = ways
        self._sets = [[None for _ in range(ways)] for _ in range(sets)]
        self._backing = {}
        self._clock = 0
        self.events = []
        self._stats = {
            "reads": {},
            "cpu_writes": {"hits": 0, "misses": 0, "bytes": 0},
            "io_writes": {"hits": 0, "misses": 0, "bytes": 0,
                          "allocated": 0, "bypassed": 0},
            "allocations": {"read": 0, "cpu_write": 0, "io_write": 0},
            "evictions": {"clean": 0, "dirty": 0},
            "backing_read_bytes": _home_counts(),
            "backing_write_bytes": _home_counts(),
            "dirty_eviction_bytes": _home_counts(),
            "flush_writeback_bytes": _home_counts(),
            "bypass": {"lines": 0, "bytes": 0, "discarded_dirty": 0},
        }

    @staticmethod
    def _address(address):
        if type(address) is not int or address < 0:
            raise ValueError("address must be a nonnegative integer")
        return address - address % LINE_BYTES

    def define(self, address, home, data=bytes(LINE_BYTES)):
        base = self._address(address)
        if address != base or base in self._backing:
            raise ValueError("backing addresses must be aligned and unique")
        if home not in HOMES:
            raise ValueError("backing home must be 'host' or 'nic'")
        if not isinstance(data, bytes) or len(data) != LINE_BYTES:
            raise ValueError("backing must contain exactly 64 immutable bytes")
        self._backing[base] = _Backing(home, bytearray(data))

    def _access(self, address, size):
        base = self._address(address)
        if type(size) is not int or not 1 <= size <= LINE_BYTES:
            raise ValueError("access size must be between 1 and 64 bytes")
        offset = address - base
        if offset + size > LINE_BYTES:
            raise ValueError("access cannot cross a cache line")
        if base not in self._backing:
            raise ValueError("access requires explicitly defined backing")
        return base, offset

    def _store_access(self, address, data):
        if not isinstance(data, bytes) or not data:
            raise ValueError("stores require nonempty immutable bytes")
        return self._access(address, len(data))

    def _index(self, base):
        return (base // LINE_BYTES) % self.sets

    def _find(self, base):
        for way, line in enumerate(self._sets[self._index(base)]):
            if line is not None and line.address == base:
                return way, line
        return None, None

    def _touch(self, line):
        self._clock += 1
        line.touched = self._clock

    def _read_backing(self, base):
        backing = self._backing[base]
        self._stats["backing_read_bytes"][backing.home] += LINE_BYTES
        return bytearray(backing.data)

    def _write_backing(self, base, data):
        backing = self._backing[base]
        backing.data[:] = data
        self._stats["backing_write_bytes"][backing.home] += LINE_BYTES

    def _allocate(self, base, data, admission, source):
        index = self._index(base)
        lines = self._sets[index]
        empty = [way for way in admission if lines[way] is None]
        way = min(empty) if empty else min(admission, key=lambda item: lines[item].touched)
        victim = lines[way]
        if victim is not None:
            home = self._backing[victim.address].home
            self._stats["evictions"]["dirty" if victim.dirty else "clean"] += 1
            if victim.dirty:
                self._write_backing(victim.address, victim.data)
                self._stats["dirty_eviction_bytes"][home] += LINE_BYTES
            self.events.append({"event": "evict", "address": victim.address,
                                "home": home, "dirty": victim.dirty,
                                "set": index, "way": way, "source": source})
        line = _Line(base, bytearray(data), False, 0)
        lines[way] = line
        self._stats["allocations"][source] += 1
        self._touch(line)
        return line

    def read(self, address, size, category="payload"):
        base, offset = self._access(address, size)
        if not isinstance(category, str) or not category:
            raise ValueError("read category must be a nonempty string")
        _, line = self._find(base)
        hit = line is not None
        counts = self._stats["reads"].setdefault(
            category, {"hits": 0, "misses": 0, "bytes": 0,
                       "hit_bytes": 0, "miss_bytes": 0, "backing_misses": _home_counts()})
        counts["hits" if hit else "misses"] += 1
        counts["bytes"] += size
        counts["hit_bytes" if hit else "miss_bytes"] += size
        if hit:
            self._touch(line)
        else:
            counts["backing_misses"][self._backing[base].home] += 1
            line = self._allocate(base, self._read_backing(base), tuple(range(self.ways)), "read")
        return bytes(line.data[offset:offset + size]), hit

    def cpu_write(self, address, data):
        base, offset = self._store_access(address, data)
        _, line = self._find(base)
        hit = line is not None
        counts = self._stats["cpu_writes"]
        counts["hits" if hit else "misses"] += 1
        counts["bytes"] += len(data)
        if hit:
            self._touch(line)
        else:
            old = bytearray(LINE_BYTES) if len(data) == LINE_BYTES else self._read_backing(base)
            line = self._allocate(base, old, tuple(range(self.ways)), "cpu_write")
        line.data[offset:offset + len(data)] = data
        line.dirty = True
        return hit

    def _admission(self, admission):
        if not isinstance(admission, tuple) or any(
                type(way) is not int or not 0 <= way < self.ways for way in admission):
            raise ValueError("admission must be a tuple of valid way IDs")
        if len(set(admission)) != len(admission):
            raise ValueError("admission cannot contain duplicate way IDs")
        return tuple(sorted(admission))

    def io_write(self, address, data, admission):
        base, offset = self._store_access(address, data)
        admission = self._admission(admission)
        _, line = self._find(base)
        hit = line is not None
        counts = self._stats["io_writes"]
        counts["hits" if hit else "misses"] += 1
        counts["bytes"] += len(data)
        if hit:
            self._touch(line)
        elif admission:
            old = bytearray(LINE_BYTES) if len(data) == LINE_BYTES else self._read_backing(base)
            line = self._allocate(base, old, admission, "io_write")
            counts["allocated"] += 1
        else:
            self._bypass(base, offset, data, "io_no_allocate")
            counts["bypassed"] += 1
            return False
        line.data[offset:offset + len(data)] = data
        line.dirty = True
        return hit

    def _bypass(self, base, offset, data, source):
        way, line = self._find(base)
        dirty = line is not None and line.dirty
        if len(data) == LINE_BYTES:
            merged = bytearray(data)
        else:
            # Uncovered bytes must come from the current coherent value. A
            # resident dirty copy can be newer than its backing allocation.
            merged = bytearray(line.data) if line is not None else self._read_backing(base)
            merged[offset:offset + len(data)] = data
        if line is not None:
            self._sets[self._index(base)][way] = None
        self._write_backing(base, merged)
        self._stats["bypass"]["lines"] += 1
        self._stats["bypass"]["bytes"] += len(data)
        self._stats["bypass"]["discarded_dirty"] += int(dirty)
        self.events.append({"event": "bypass", "address": base,
                            "home": self._backing[base].home, "source": source,
                            "discarded_dirty": dirty, "bytes": len(data)})

    def bypass_write(self, address, data):
        """Coherently merge a store into home and invalidate an existing line.

        A full overwrite supersedes old dirty data. Partial writes retain the
        newest uncovered bytes, including dirty CPU updates. This is a symbolic
        coherent action, not a model of a device's raw local memory store.
        """
        base, offset = self._store_access(address, data)
        self._bypass(base, offset, data, "explicit")

    def resident(self, address):
        base = self._address(address)
        return self._find(base)[1] is not None

    def resident_lines(self):
        """Return current whole-cache occupancy without exposing line contents."""
        return sum(line is not None for lines in self._sets for line in lines)

    def flush(self):
        """Write back dirty lines without invalidating or resetting statistics."""
        for lines in self._sets:
            for line in lines:
                if line is not None and line.dirty:
                    home = self._backing[line.address].home
                    self._write_backing(line.address, line.data)
                    self._stats["flush_writeback_bytes"][home] += LINE_BYTES
                    self.events.append({"event": "flush", "address": line.address, "home": home})
                    line.dirty = False

    def snapshot(self):
        lines = [
            {"set": index, "way": way, "address": line.address,
             "home": self._backing[line.address].home, "dirty": line.dirty,
             "touched": line.touched, "data": bytes(line.data).hex()}
            for index, entries in enumerate(self._sets)
            for way, line in enumerate(entries) if line is not None
        ]
        return {"sets": self.sets, "ways": self.ways, "line_bytes": LINE_BYTES,
                "capacity_bytes": self.sets * self.ways * LINE_BYTES,
                "occupancy": self.resident_lines(), "lines": lines,
                "stats": deepcopy(self._stats)}
