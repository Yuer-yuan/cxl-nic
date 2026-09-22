"""Deterministic checks for reliable finite-reordering virtual time."""

import unittest

from cxl_nic.timing import (POLICIES, Packet, Simulation, TimingConfig,
                            TimingError, generate_workload, payload_for,
                            run_matrix, validate_workload)


def packet(serial, arrival, size=64, flow=0):
    return Packet(flow, serial, arrival, payload_for(flow, serial, size))


def config(**changes):
    values = dict(cache_sets=8, cache_ways=8, link_bandwidth_gbps=64,
                  link_latency_ns=20, cpu_base_ns=10, llc_hit_ns=2,
                  host_miss_ns=20, nic_miss_ns=60,
                  push_credit_bytes_per_flow=256, nic_buffer_bytes=1 << 20,
                  max_time_ns=100_000)
    values.update(changes)
    return TimingConfig(**values)


class WorkloadTests(unittest.TestCase):
    def test_reliable_workload_requires_unique_contiguous_serials(self):
        good, initial = validate_workload((packet(2, 30), packet(0, 20), packet(1, 10)))
        self.assertEqual(len(good), 3)
        self.assertEqual(initial, {0: 0})
        for bad in ((), (packet(0, 0), packet(0, 1)),
                    (packet(0, 0), packet(2, 1)), ("not a packet",)):
            with self.subTest(bad=bad), self.assertRaises(TimingError):
                validate_workload(bad)

    def test_generator_is_reproducible_out_of_order_and_has_no_loss(self):
        first = generate_workload(flows=2, packets_per_flow=12, seed=7,
                                  reorder_jitter_ns=0, gap_every=4, gap_delay_ns=500)
        second = generate_workload(flows=2, packets_per_flow=12, seed=7,
                                   reorder_jitter_ns=0, gap_every=4, gap_delay_ns=500)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 24)
        for flow in (0, 1):
            arrivals = [item.serial for item in first if item.flow == flow]
            self.assertEqual(sorted(arrivals), list(range(12)))
            self.assertNotEqual(arrivals, sorted(arrivals))

    def test_invalid_configuration_rejects_zero_time_background_loop(self):
        for changes in ({"cache_sets": 0}, {"cache_ways": True},
                        {"background_interval_ns": 0,
                         "background_working_set_lines": 4},
                        {"background_interval_ns": 10,
                         "background_working_set_lines": 0},
                        {"packet_stride_lines": 27},
                        {"ncp_ways": (0, 0)}, {"ddio_ways": (8,)},
                        {"ncp_withdraw_ns": -1},
                        {"ncp_gate_resident_lines": -1},
                        {"ncp_gate_resident_lines": True}):
            with self.subTest(changes=changes), self.assertRaises(TimingError):
                config(**changes)


class TimingPolicyTests(unittest.TestCase):
    def test_default_packet_bases_do_not_all_alias_one_modulo_cache_set(self):
        simulation = Simulation(tuple(packet(serial, 0) for serial in range(8)),
                                "D1", config())
        sets = {(state.base // 64) % simulation.config.cache_sets
                for state in simulation.states.values()}
        self.assertEqual(len(sets), 8)

    def test_all_architectural_arms_deliver_each_flow_in_sender_order(self):
        workload = (packet(1, 0, 65, 0), packet(1, 5, 64, 1),
                    packet(0, 100, 63, 0), packet(0, 90, 1500, 1))
        result = run_matrix(workload, config(push_credit_bytes_per_flow=1600))
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["assumptions"]["reliable_delivery"], True)
        for name, arm in result["arms"].items():
            with self.subTest(policy=name):
                self.assertEqual(arm["status"], "passed")
                self.assertEqual(arm["packets"], 4)
                for flow in (0, 1):
                    serials = [item["serial"] for item in arm["delivery_order"]
                               if item["flow"] == flow]
                    self.assertEqual(serials, [0, 1])
                demands = arm["payload_first_demand"]
                self.assertEqual(demands["hits"] + demands["misses"], 28)

    def test_matched_b1_and_ncp_label_control_are_identical(self):
        workload = (packet(1, 0, 65), packet(0, 200, 65), packet(2, 210, 65))
        result = run_matrix(workload, config(), ("B1", "D1-host-control"))
        self.assertEqual(result["fairness_control"], "passed")
        left, right = result["arms"]["B1"], result["arms"]["D1-host-control"]
        for key in ("duration_ns", "delivery_latency_ns", "sequence_wait_ns",
                    "payload_first_demand", "link_bytes", "payload_push_bytes",
                    "credit_stall_ns", "packet_records"):
            self.assertEqual(left[key], right[key])

    def test_arrival_pushes_future_packet_while_sequence_aware_policy_waits(self):
        workload = (packet(1, 0), packet(0, 500))
        early = Simulation(workload, "C", config()).run()
        ordered = Simulation(workload, "D1", config()).run()
        early_record = next(item for item in early["packet_records"] if item["serial"] == 1)
        ordered_record = next(item for item in ordered["packet_records"] if item["serial"] == 1)
        self.assertEqual(early_record["issue_ns"], 0)
        self.assertEqual(ordered_record["issue_ns"], 500)
        self.assertGreater(early["push_to_first_demand_ns"]["max"],
                           ordered["push_to_first_demand_ns"]["max"])

    def test_a_models_software_reorder_before_ordered_application_delivery(self):
        result = Simulation((packet(1, 0), packet(0, 500)), "A", config()).run()
        records = {item["serial"]: item for item in result["packet_records"]}
        self.assertLess(records[1]["consume_ns"], records[0]["consume_ns"])
        self.assertEqual([item["serial"] for item in result["delivery_order"]], [0, 1])
        self.assertEqual(records[0]["delivery_ns"], records[1]["delivery_ns"])
        self.assertEqual(result["cpu_reorder_buffer_peak_bytes"], 64)

    def test_a_cpu_reorder_buffer_capacity_is_a_hard_failure(self):
        with self.assertRaisesRegex(TimingError, "CPU reorder buffer capacity"):
            Simulation((packet(1, 0, 64), packet(0, 500, 64)), "A",
                       config(cpu_reorder_buffer_bytes=63)).run()

    def test_credit_bounds_pushed_unconsumed_data_and_records_stall(self):
        workload = tuple(packet(serial, 0) for serial in range(4))
        result = Simulation(workload, "D1", config(push_credit_bytes_per_flow=64)).run()
        self.assertEqual(result["credit_peak_bytes"], {"0": 64})
        self.assertGreaterEqual(result["credit_stall_events"]["0"], 1)
        self.assertGreater(result["credit_stall_ns"]["0"], 0)
        issues = [item["issue_ns"] for item in result["packet_records"]]
        self.assertEqual(issues, sorted(issues))
        self.assertEqual(len(set(issues)), 4)

    def test_demand_only_arm_fetches_correct_bytes_from_nic_home(self):
        result = Simulation((packet(0, 0, 65),), "E", config()).run()
        self.assertEqual(result["payload_push_bytes"], 0)
        self.assertEqual(result["producer_link_bytes"], 128)
        self.assertEqual(result["cpu_nic_read_bytes"], 128)
        self.assertEqual(result["link_bytes"], 256)
        self.assertEqual(result["payload_first_demand"],
                         {"hits": 0, "misses": 2, "lines": 2, "hit_rate": 0.0})
        reads = result["cache_before_final_flush"]["stats"]["reads"]["payload"]
        self.assertEqual(reads["backing_misses"], {"host": 0, "nic": 2})

    def test_immediate_nc_write_withdrawal_removes_push_benefit(self):
        baseline = Simulation((packet(0, 0),), "D1", config()).run()
        withdrawn = Simulation((packet(0, 0),), "D1",
                               config(ncp_withdraw_ns=0)).run()
        self.assertEqual(baseline["payload_first_demand"]["hits"], 1)
        self.assertEqual(withdrawn["payload_first_demand"]["misses"], 1)
        self.assertEqual(withdrawn["withdrawn_payload_lines"], 1)

    def test_adaptive_gate_endpoints_and_mixed_choice_preserve_delivery(self):
        workload = tuple(packet(serial, 0) for serial in range(4))
        all_nc_write = Simulation(
            workload, "D1-gated", config(ncp_gate_resident_lines=0)).run()
        mixed = Simulation(
            workload, "D1-gated", config(ncp_gate_resident_lines=1)).run()
        all_ncp = Simulation(
            workload, "D1-gated", config(ncp_gate_resident_lines=513)).run()
        baseline = Simulation(
            workload, "D1", config(ncp_gate_resident_lines=513)).run()
        lines = all_nc_write["payload_first_demand"]["lines"]
        self.assertEqual(all_nc_write["adaptive_gate"],
                         {"threshold_resident_lines": 0,
                          "ncp_lines": 0, "nc_write_lines": lines,
                          "nc_write_bytes": lines * 64})
        self.assertEqual(all_nc_write["payload_first_demand"]["misses"], lines)
        self.assertGreater(mixed["adaptive_gate"]["ncp_lines"], 0)
        self.assertGreater(mixed["adaptive_gate"]["nc_write_lines"], 0)
        self.assertEqual(all_ncp["adaptive_gate"],
                         {"threshold_resident_lines": 513,
                          "ncp_lines": lines, "nc_write_lines": 0,
                          "nc_write_bytes": 0})
        expected = [0, 1, 2, 3]
        for result in (all_nc_write, mixed, all_ncp):
            self.assertEqual([item["serial"] for item in result["delivery_order"]], expected)
        for key in ("duration_ns", "delivery_latency_ns", "sequence_wait_ns",
                    "push_to_first_demand_ns", "payload_first_demand", "link_bytes",
                    "producer_link_bytes", "cpu_nic_read_bytes", "payload_push_bytes",
                    "credit_stall_ns", "packet_records", "cache_before_final_flush"):
            with self.subTest(key=key):
                self.assertEqual(all_ncp[key], baseline[key])

    def test_adaptive_gate_and_post_push_withdrawal_are_separate_policies(self):
        with self.assertRaisesRegex(TimingError, "separate policies"):
            Simulation((packet(0, 0),), "D1-gated",
                       config(ncp_withdraw_ns=0)).run()

    def test_no_allocate_exposes_host_vs_nic_fallback_cost(self):
        workload = (packet(0, 0, 65),)
        cfg = config(ddio_ways=(), ncp_ways=())
        result = run_matrix(workload, cfg, ("B1", "D1"))
        host = result["arms"]["B1"]
        nic = result["arms"]["D1"]
        self.assertEqual(host["payload_first_demand"]["misses"], 2)
        self.assertEqual(nic["payload_first_demand"]["misses"], 2)
        self.assertLess(host["delivery_latency_ns"]["max"], nic["delivery_latency_ns"]["max"])

    def test_single_packet_link_accounting_distinguishes_push_and_demand(self):
        pushed = Simulation((packet(0, 0),), "B1", config()).run()
        demand = Simulation((packet(0, 0),), "E", config()).run()
        self.assertEqual(pushed["payload_push_bytes"], 64)
        self.assertEqual(pushed["link_bytes"], 192)
        self.assertEqual(demand["payload_push_bytes"], 0)
        self.assertEqual(demand["producer_link_bytes"], 128)
        self.assertEqual(demand["cpu_nic_read_bytes"], 64)
        self.assertEqual(demand["link_bytes"], 192)

    def test_buffer_capacity_is_a_hard_failure_not_silent_packet_loss(self):
        with self.assertRaisesRegex(TimingError, "buffer capacity"):
            Simulation((packet(0, 0, 65),), "D1", config(nic_buffer_bytes=64)).run()

    def test_unknown_policy_is_rejected(self):
        with self.assertRaisesRegex(TimingError, "unknown policy"):
            Simulation((packet(0, 0),), "not-a-policy", config())
        self.assertEqual(set(POLICIES), {"A", "B0", "B1", "C", "D0", "D1",
                                         "D1-gated", "E", "D1-host-control"})


if __name__ == "__main__":
    unittest.main()
