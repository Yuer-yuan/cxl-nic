"""Contract checks for the controlled timing sensitivity matrix."""

from copy import deepcopy
import unittest

from cxl_nic.timing import TimingConfig, generate_workload, run_matrix
from cxl_nic.timing_sweep import (CASES, POLICY_NAMES, SweepCase,
                                  _validate_result, validate_cases)


class TimingSweepTests(unittest.TestCase):
    def test_cases_are_unique_keep_work_fixed_and_cover_planned_axes(self):
        cases = validate_cases()
        self.assertEqual(len({case.name for case in cases}), len(cases))
        self.assertTrue(all(case.flows * case.packets_per_flow == 64 for case in cases))
        self.assertEqual({case.axis for case in cases},
                         {"gate_threshold_lines", "llc_capacity_lines", "cpu_base_ns",
                          "packet_size_bytes", "flows"})
        thresholds = [case.value for case in cases if case.axis == "gate_threshold_lines"]
        self.assertEqual(thresholds, [0, 128, 256, 384, 513])

    def test_case_validation_rejects_changed_work_or_mislabeled_capacity(self):
        with self.assertRaisesRegex(ValueError, "64 total packets"):
            validate_cases((SweepCase("bad-work", "flows", 1,
                                      flows=1, packets_per_flow=63),))
        with self.assertRaisesRegex(ValueError, "cache capacity"):
            validate_cases((SweepCase("bad-cache", "llc_capacity_lines", 128),))

    def test_result_validation_checks_gate_and_link_conservation(self):
        case = SweepCase("small", "flows", 1, flows=1, packets_per_flow=64,
                         sizes=(64,), config_changes=(("cache_sets", 8),
                                                     ("background_working_set_lines", 4),
                                                     ("ncp_gate_resident_lines", 32)))
        packets = generate_workload(flows=1, packets_per_flow=64, sizes=(64,), seed=1)
        config = TimingConfig(cache_sets=8, background_interval_ns=20,
                              background_working_set_lines=4,
                              ncp_gate_resident_lines=32)
        result = run_matrix(packets, config, POLICY_NAMES)
        _validate_result(case, result)
        broken = deepcopy(result)
        broken["arms"]["D1-gated"]["adaptive_gate"]["nc_write_lines"] += 1
        with self.assertRaisesRegex(ValueError, "gate accounting"):
            _validate_result(case, broken)


if __name__ == "__main__":
    unittest.main()
