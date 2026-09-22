"""Hand-checkable traces for physical tags, admission, and byte preservation."""

import unittest

from cxl_nic.cache import Cache


class CacheTests(unittest.TestCase):
    @staticmethod
    def cache(sets=1, ways=2):
        cache = Cache(sets, ways)
        for index in range(8):
            cache.define(index * 64, "host" if index % 2 == 0 else "nic", bytes([index]) * 64)
        return cache

    def test_lru_conflict_evicts_correct_dirty_line_and_restores_bytes(self):
        cache = self.cache()
        cache.io_write(0, b"A" * 64, (0, 1))
        cache.io_write(64, b"B" * 64, (0, 1))
        self.assertEqual(cache.read(0, 64), (b"A" * 64, True))
        cache.io_write(128, b"C" * 64, (0, 1))
        self.assertTrue(cache.resident(0))
        self.assertFalse(cache.resident(64))
        self.assertEqual(cache.events[-1]["address"], 64)
        self.assertEqual(cache.snapshot()["stats"]["dirty_eviction_bytes"], {"host": 0, "nic": 64})
        self.assertEqual(cache.read(64, 64), (b"B" * 64, False))
        self.assertEqual(cache.snapshot()["occupancy"], 2)

    def test_true_address_tags_distinguish_different_lines_with_same_set(self):
        cache = self.cache(sets=2, ways=1)
        self.assertEqual(cache.read(0, 1), (b"\x00", False))
        self.assertEqual(cache.read(64, 1), (b"\x01", False))
        self.assertEqual(cache.read(128, 1), (b"\x02", False))
        self.assertFalse(cache.resident(0))
        self.assertTrue(cache.resident(64))
        self.assertEqual(cache.read(0, 1), (b"\x00", False))

    def test_io_hit_outside_admission_mask_updates_existing_way(self):
        cache = self.cache()
        cache.read(0, 64)  # way 0
        cache.read(64, 64)  # CPU may fill way 1
        self.assertTrue(cache.io_write(64, b"new", (0,)))
        self.assertEqual(cache.read(64, 4), (b"new\x01", True))
        snapshot = cache.snapshot()
        self.assertEqual([line["way"] for line in snapshot["lines"] if line["address"] == 64], [1])
        self.assertEqual(snapshot["stats"]["io_writes"]["allocated"], 0)
        self.assertTrue(cache.resident(0))

    def test_no_allocate_miss_writes_home_but_hit_still_updates_cache(self):
        cache = self.cache()
        self.assertFalse(cache.io_write(64, b"N" * 64, ()))
        self.assertFalse(cache.resident(64))
        stats = cache.snapshot()["stats"]
        self.assertEqual(stats["backing_read_bytes"], {"host": 0, "nic": 0})
        self.assertEqual(stats["backing_write_bytes"], {"host": 0, "nic": 64})
        self.assertEqual(cache.read(64, 64), (b"N" * 64, False))
        self.assertTrue(cache.io_write(64, b"X", ()))
        self.assertEqual(cache.read(64, 2), (b"XN", True))
        self.assertEqual(cache.snapshot()["stats"]["io_writes"]["bypassed"], 1)

    def test_admission_on_miss_cannot_evict_an_ineligible_way(self):
        cache = self.cache()
        cache.read(0, 64)  # way 0, oldest
        cache.read(64, 64)  # way 1
        cache.io_write(128, b"x" * 64, (1,))
        self.assertTrue(cache.resident(0))
        self.assertFalse(cache.resident(64))
        self.assertEqual(cache.events[-1]["way"], 1)

    def test_partial_cpu_and_io_stores_preserve_uncovered_bytes_after_eviction(self):
        cache = self.cache(ways=1)
        self.assertFalse(cache.cpu_write(64 + 7, b"CPU"))
        self.assertTrue(cache.io_write(64 + 9, b"IO", (0,)))
        expected = b"\x01" * 7 + b"CPIO" + b"\x01" * 53
        self.assertEqual(cache.read(64, 64), (expected, True))
        cache.read(0, 64)
        self.assertEqual(cache.read(64, 64), (expected, False))
        self.assertEqual(cache.snapshot()["stats"]["dirty_eviction_bytes"]["nic"], 64)

    def test_partial_miss_fetches_backing_but_full_line_io_write_does_not(self):
        cache = self.cache(ways=1)
        cache.io_write(0, b"F" * 64, (0,))
        self.assertEqual(cache.snapshot()["stats"]["backing_read_bytes"]["host"], 0)
        cache.io_write(64 + 63, b"P", (0,))
        self.assertEqual(cache.snapshot()["stats"]["backing_read_bytes"]["nic"], 64)
        self.assertEqual(cache.read(64, 64), (b"\x01" * 63 + b"P", True))
        cache.io_write(128 + 1, b"Q", ())
        self.assertEqual(cache.snapshot()["stats"]["backing_read_bytes"]["host"], 64)
        self.assertEqual(cache.read(128, 3), (b"\x02Q\x02", False))

    def test_full_bypass_prevents_stale_dirty_writeback_overwriting_new_packet(self):
        cache = self.cache(ways=1)
        cache.io_write(0, b"old" + bytes(61), (0,))
        cache.cpu_write(4, b"dirty")
        cache.bypass_write(0, b"NEW" * 21 + b"!")
        self.assertFalse(cache.resident(0))
        before = cache.snapshot()["stats"]
        self.assertEqual(before["dirty_eviction_bytes"]["host"], 0)
        self.assertEqual(before["bypass"]["discarded_dirty"], 1)
        cache.read(64, 64)
        cache.flush()
        self.assertEqual(cache.read(0, 64), (b"NEW" * 21 + b"!", False))
        self.assertEqual(cache.snapshot()["stats"]["flush_writeback_bytes"]["host"], 0)

    def test_partial_bypass_retains_current_dirty_cpu_bytes(self):
        cache = self.cache(ways=1)
        cache.cpu_write(64 + 8, b"CPU")
        cache.bypass_write(64, b"NIC")
        self.assertFalse(cache.resident(64))
        expected = b"NIC" + b"\x01" * 5 + b"CPU" + b"\x01" * 53
        self.assertEqual(cache.read(64, 64), (expected, False))

    def test_polling_and_background_reads_compete_but_have_separate_counters(self):
        cache = self.cache(ways=1)
        cache.io_write(64, b"p" * 64, (0,))
        cache.read(0, 8, category="poll")
        cache.read(0, 8, category="poll")
        self.assertEqual(cache.read(64, 64, category="payload"), (b"p" * 64, False))
        cache.read(128, 64, category="background")
        reads = cache.snapshot()["stats"]["reads"]
        self.assertEqual((reads["poll"]["hits"], reads["poll"]["misses"]), (1, 1))
        self.assertEqual((reads["payload"]["hits"], reads["payload"]["misses"]), (0, 1))
        self.assertEqual(reads["payload"]["backing_misses"], {"host": 0, "nic": 1})
        self.assertEqual(reads["background"]["misses"], 1)

    def test_flush_accounts_writebacks_without_resetting_or_invalidating(self):
        cache = self.cache()
        cache.io_write(0, b"h" * 64, (0, 1))
        cache.io_write(64, b"n" * 64, (0, 1))
        cache.read(0, 1)
        before = cache.snapshot()
        cache.flush()
        after = cache.snapshot()
        self.assertEqual(after["stats"]["reads"], before["stats"]["reads"])
        self.assertEqual(after["stats"]["flush_writeback_bytes"], {"host": 64, "nic": 64})
        self.assertEqual(after["stats"]["dirty_eviction_bytes"], {"host": 0, "nic": 0})
        self.assertEqual(after["occupancy"], 2)
        self.assertTrue(all(not line["dirty"] for line in after["lines"]))
        self.assertEqual([line["touched"] for line in before["lines"]],
                         [line["touched"] for line in after["lines"]])
        cache.flush()
        self.assertEqual(cache.snapshot()["stats"], after["stats"])

    def test_invalid_accesses_and_admission_cannot_change_cache(self):
        cache = self.cache()
        before = cache.snapshot()
        operations = (
            lambda: cache.read(63, 2), lambda: cache.read(0, 0),
            lambda: cache.read(-1, 1), lambda: cache.read(4096, 1),
            lambda: cache.read(0, True), lambda: cache.cpu_write(63, b"xx"),
            lambda: cache.cpu_write(0, bytearray(b"x")),
            lambda: cache.io_write(0, b"x", (2,)),
            lambda: cache.io_write(0, b"x", (0, 0)),
            lambda: cache.io_write(0, b"x", (True,)),
            lambda: cache.bypass_write(1, bytes(64)),
            lambda: cache.define(0, "nic"), lambda: cache.define(513, "host"),
            lambda: cache.define(512, "unknown"), lambda: cache.define(512, "host", bytes(63)),
        )
        for operation in operations:
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                operation()
            self.assertEqual(cache.snapshot(), before)

    def test_snapshot_is_detached_from_cache_state(self):
        cache = self.cache()
        cache.read(0, 1)
        snapshot = cache.snapshot()
        snapshot["stats"]["reads"]["payload"]["hits"] = 999
        snapshot["lines"][0]["address"] = 999
        current = cache.snapshot()
        self.assertEqual(current["stats"]["reads"]["payload"]["hits"], 0)
        self.assertEqual(current["lines"][0]["address"], 0)

    def test_resident_line_count_tracks_all_sets_without_snapshotting(self):
        cache = self.cache(sets=2, ways=2)
        self.assertEqual(cache.resident_lines(), 0)
        cache.read(0, 1)
        cache.io_write(64, b"N" * 64, (0, 1))
        self.assertEqual(cache.resident_lines(), 2)
        cache.bypass_write(64, b"B" * 64)
        self.assertEqual(cache.resident_lines(), 1)


if __name__ == "__main__":
    unittest.main()
