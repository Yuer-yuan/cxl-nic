"""Audit the claims made by the matched integration matrix."""

import copy
import unittest

from cxl_nic.integration import PINS
from cxl_nic.integration_matrix import ARMS, compare_results


def result(name):
    path, sets, ways, case_selection = ARMS[name]
    pressure = name.endswith("pressure")
    cases = [{"mode": "adversarial", "status": "passed",
              path: {"configured_sets": sets, "configured_ways": ways,
                     "pushes": 220, "push_bytes": 12288, "first_demands": 220,
                     "first_demand_hits": 2 if pressure else 220,
                     "first_demand_misses": 218 if pressure else 0,
                     "evictions": 900 if pressure else 1,
                     "writebacks": 220 if pressure and path == "ncp" else 0,
                     "resident": 1 if pressure else 128}}]
    if case_selection == "all":
        cases.extend(({"mode": "early-ready", "status": "expected_rejection"},
                      {"mode": "corrupt-payload", "status": "expected_rejection"}))
    return {"status": "passed", "device_type": "type2", "data_path": path,
            "pins": dict(PINS), "cases": cases}


class IntegrationMatrixTests(unittest.TestCase):
    def setUp(self):
        self.results = {name: result(name) for name in ARMS}

    def stats(self, name):
        path = ARMS[name][0]
        return self.results[name]["cases"][0][path]

    def test_accepts_matched_functional_and_pressure_evidence(self):
        summary = compare_results(self.results)
        self.assertEqual(summary["status"], "passed")
        self.assertEqual(summary["checks"]["matched_work_volume"], "passed")

    def test_rejects_unmatched_work_volume(self):
        self.stats("ddio_default")["push_bytes"] += 64
        with self.assertRaisesRegex(ValueError, "work volumes"):
            compare_results(self.results)

    def test_rejects_a_default_first_demand_miss(self):
        stats = self.stats("ncp_default")
        stats["first_demand_hits"] -= 1
        stats["first_demand_misses"] += 1
        with self.assertRaisesRegex(ValueError, "preserve every line"):
            compare_results(self.results)

    def test_rejects_pressure_without_misses(self):
        stats = self.stats("ddio_pressure")
        stats["first_demand_hits"] = stats["first_demands"]
        stats["first_demand_misses"] = 0
        with self.assertRaisesRegex(ValueError, "exercise LLC pressure"):
            compare_results(self.results)

    def test_rejects_ddio_dirty_writeback(self):
        self.stats("ddio_pressure")["writebacks"] = 1
        with self.assertRaisesRegex(ValueError, "clean eviction"):
            compare_results(self.results)

    def test_rejects_inconsistent_first_demand_accounting(self):
        self.stats("ncp_pressure")["first_demands"] += 1
        with self.assertRaisesRegex(ValueError, "denominator"):
            compare_results(self.results)

    def test_rejects_missing_negative_control(self):
        changed = copy.deepcopy(self.results)
        changed["ncp_default"]["cases"].pop()
        with self.assertRaisesRegex(ValueError, "case outcomes"):
            compare_results(changed)


if __name__ == "__main__":
    unittest.main()
