"""Paired LLC hypotheses on independently checked publication traces."""

from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cxl_nic.cache_replay import Replay, ReplayConfig, ReplayError, paired_replay
from cxl_nic.checker import TraceViolation
from cxl_nic.model import Config, Protocol
from cxl_nic.verify import random_schedule


def finish_writes(protocol):
    while protocol.pending:
        protocol.complete(next(iter(protocol.pending)))


def consume_and_release(protocol, flow, serial, payload):
    """Log explicit consumer observations rather than deriving test bytes from cache."""
    token = next(event["token"] for event in protocol.trace
                 if event["event"] == "receive" and event["token"]["flow"] == flow
                 and event["token"]["serial"] == serial)
    descriptor = {**token, "length": len(payload)}
    delivery = protocol.observe_consumption(flow, descriptor, payload)
    protocol.release(delivery.token)


def sequential_trace(payloads, *, window=1, initial=254):
    maximum = max(map(len, payloads))
    protocol = Protocol(Config(window=window, max_packet_bytes=maximum,
                               per_flow_credit_bytes=((maximum + 63) // 64) * 64),
                        {0: initial})
    for serial, payload in enumerate(payloads, start=initial):
        if protocol.receive(0, serial & 255, serial >> 8, payload) != "accepted":
            raise AssertionError("fixture packet was rejected")
        protocol.pump()
        finish_writes(protocol)
        consume_and_release(protocol, 0, serial, payload)
    return protocol.trace


def reordered_trace():
    protocol = Protocol(Config(window=4, max_packet_bytes=129, per_flow_credit_bytes=512),
                        {0: 254, 7: 510})
    payloads = {(0, 254): b"A" * 65, (0, 255): bytes(range(129)),
                (7, 510): b"C" * 63, (7, 511): b"D" * 64}
    for flow, serial in ((0, 255), (7, 511), (0, 254), (7, 510)):
        if protocol.receive(flow, serial & 255, serial >> 8, payloads[flow, serial]) != "accepted":
            raise AssertionError("fixture packet was rejected")
    protocol.pump()
    # Reverse physical completions while preserving the publication contract.
    while protocol.pending:
        protocol.complete(max(protocol.pending))
    for flow, serial in ((7, 510), (0, 254), (0, 255), (7, 511)):
        consume_and_release(protocol, flow, serial, payloads[flow, serial])
    return protocol.trace


class CacheReplayTests(unittest.TestCase):
    def test_equal_policy_label_invariance_with_reordering_and_background(self):
        events = reordered_trace()
        original = deepcopy(events)
        result = paired_replay(events, config=ReplayConfig(sets=2, ways=3, background_lines=5),
                               ddio_admission=(0, 2), ncp_admission=(0, 2))
        arms = result["arms"]
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["label_invariance"], "passed")
        self.assertEqual(arms["ddio-host"], arms["ncp-host-control"])
        self.assertEqual(arms["ddio-host"]["counts"], arms["ncp-nic"]["counts"])
        self.assertEqual(arms["ddio-host"]["counts"]["packets"], 4)
        self.assertEqual(events, original)

    def test_permuted_admission_masks_are_the_same_policy(self):
        events = sequential_trace([b"p" * 129])
        result = paired_replay(events, config=ReplayConfig(sets=1, ways=4),
                               ddio_admission=(2, 0), ncp_admission=(0, 2))
        self.assertEqual(result["label_invariance"], "passed")
        self.assertEqual(result["arms"]["ddio-host"], result["arms"]["ncp-host-control"])

    def test_conflict_eviction_preserves_bytes_and_uses_the_declared_home(self):
        payload = bytes(range(129))
        events = sequential_trace([payload])
        for home, other in (("host", "nic"), ("nic", "host")):
            with self.subTest(home=home):
                replay = Replay(events, home=home, config=ReplayConfig(sets=1, ways=1))
                result = replay.run()
                self.assertEqual(result["counts"]["payload_first_hits"], 0)
                self.assertEqual(result["counts"]["payload_first_misses"], 3)
                self.assertEqual({demand["source"] for demand in replay.demands}, {home})
                stats = result["cache_after_final_flush"]["stats"]
                self.assertEqual(stats["reads"]["payload"]["backing_misses"],
                                 {home: 3, other: 0})
                self.assertGreater(stats["dirty_eviction_bytes"][home], 0)
                self.assertEqual(stats["backing_write_bytes"][other], 0)
                # The release line is the only resident line after the replay.
                # Force real backing reads and verify the final partial-line padding.
                observed = bytearray()
                for demand in replay.demands:
                    data, hit = replay.cache.read(demand["address"], 64, category="verify")
                    self.assertFalse(hit)
                    observed.extend(data)
                self.assertEqual(bytes(observed), payload.ljust(192, b"\0"))

    def test_denominator_counts_payload_lines_once_and_excludes_metadata(self):
        replay = Replay(sequential_trace([b"x" * 65]), config=ReplayConfig(sets=1, ways=8))
        result = replay.run()
        self.assertEqual(result["counts"]["payload_first_hits"], 2)
        self.assertEqual(result["counts"]["payload_first_misses"], 0)
        self.assertEqual(result["counts"]["payload_push_lines"], 2)
        self.assertEqual(len(replay.demands), 2)
        stats = result["cache_before_final_flush"]["stats"]
        self.assertEqual(stats["reads"]["payload"]["bytes"], 65)
        self.assertEqual(stats["reads"]["payload"]["hits"], 2)
        self.assertEqual(stats["reads"]["ready"]["hits"], 1)
        self.assertEqual(stats["reads"]["descriptor"]["hits"], 1)
        self.assertEqual(stats["io_writes"]["hits"] + stats["io_writes"]["misses"], 8)
        self.assertEqual(result["payload_first_demand_hit_rate"], 1.0)

    def test_admission_sensitivity_follows_policy_in_either_label_direction(self):
        events = sequential_trace([b"p" * 192])
        config = ReplayConfig(sets=1, ways=8)
        restricted_ddio = paired_replay(events, config=config, ddio_admission=(0,))
        restricted_ncp = paired_replay(events, config=config, ncp_admission=(0,))
        self.assertEqual(restricted_ddio["label_invariance"], "not_applicable_different_policy")
        self.assertEqual(restricted_ncp["label_invariance"], "not_applicable_different_policy")
        for result, winner, loser in ((restricted_ddio, "ncp-nic", "ddio-host"),
                                      (restricted_ncp, "ddio-host", "ncp-nic")):
            with self.subTest(winner=winner):
                arms = result["arms"]
                self.assertEqual(arms[winner]["counts"]["payload_first_hits"], 3)
                self.assertEqual(arms[loser]["counts"]["payload_first_hits"], 0)
                self.assertEqual(arms[loser]["counts"]["payload_first_misses"], 3)

    def test_no_allocate_policy_never_counts_bypassed_lines_as_admitted(self):
        replay = Replay(sequential_trace([b"n" * 65]), admission=(),
                        config=ReplayConfig(sets=1, ways=8))
        result = replay.run()
        self.assertEqual(result["counts"]["payload_push_lines"], 2)
        self.assertEqual(result["counts"]["admitted_push_lines"], 0)
        self.assertEqual(result["counts"]["admitted_absent_at_first_demand"], 0)
        self.assertEqual(result["counts"]["payload_first_misses"], 2)
        self.assertEqual({demand["source"] for demand in replay.demands}, {"host"})

    def test_background_references_compete_with_payload_capacity(self):
        events = sequential_trace([b"b" * 192])
        quiet = Replay(events, config=ReplayConfig(sets=1, ways=8)).run()
        crowded = Replay(events, config=ReplayConfig(sets=1, ways=8, background_lines=8)).run()
        self.assertEqual(quiet["counts"]["payload_first_hits"], 3)
        self.assertEqual(crowded["counts"]["payload_first_hits"], 0)
        self.assertEqual(crowded["counts"]["admitted_absent_at_first_demand"], 3)
        self.assertEqual(crowded["cache_before_final_flush"]["stats"]["reads"]["background"]["misses"], 8)

    def test_immediate_withdrawal_forces_correct_nic_fallback(self):
        replay = Replay(sequential_trace([b"w" * 65]), home="nic",
                        config=ReplayConfig(sets=1, ways=8, withdraw_after_events=0))
        result = replay.run()
        counts = result["counts"]
        self.assertEqual(counts["withdrawals_scheduled"], 1)
        self.assertEqual(counts["withdrawals_applied"], 1)
        self.assertEqual(counts["withdrawals_stale"], 0)
        self.assertEqual(counts["withdrawn_lines"], 2)
        self.assertEqual(counts["payload_first_hits"], 0)
        self.assertEqual(counts["payload_first_misses"], 2)
        self.assertEqual(counts["admitted_absent_at_first_demand"], 2)
        self.assertEqual({demand["source"] for demand in replay.demands}, {"nic"})
        self.assertEqual(result["cache_after_final_flush"]["stats"]["bypass"]["discarded_dirty"], 2)

    def test_old_timer_cannot_invalidate_or_overwrite_reused_slot(self):
        events = sequential_trace([b"OLD" * 22, b"NEW" * 22], window=1)
        ready_steps = [step for step, event in enumerate(events)
                       if event["event"] == "visible" and event["kind"] == "ready"]
        consume_steps = [step for step, event in enumerate(events) if event["event"] == "consume"]
        # Old generation's timer expires immediately before the new generation
        # is consumed, after its payload and ready have both become visible.
        delay = consume_steps[1] - ready_steps[0]
        baseline = Replay(events, home="nic", config=ReplayConfig(sets=1, ways=8))
        baseline.run()
        replay = Replay(events, home="nic",
                        config=ReplayConfig(sets=1, ways=8, withdraw_after_events=delay))
        result = replay.run()
        self.assertEqual(result["counts"]["withdrawals_applied"], 0)
        self.assertEqual(result["counts"]["withdrawals_stale"], 2)
        self.assertEqual(result["counts"]["withdrawn_lines"], 0)
        self.assertEqual(replay.demands, baseline.demands)
        stale = [operation for operation in replay.operations if operation["operation"] == "withdraw_stale"]
        self.assertEqual(stale[0]["step"], consume_steps[1])
        self.assertEqual(stale[0]["token"]["generation"], 1)
        self.assertEqual(replay.demands[-1]["token"]["generation"], 2)
        first_address = replay.demands[-2]["address"]
        self.assertEqual(replay.cache.read(first_address, 64, category="verify")[0], (b"NEW" * 22)[:64])

    def test_withdrawal_is_recorded_as_a_different_arm_policy(self):
        events = sequential_trace([b"x" * 64])
        result = paired_replay(events, config=ReplayConfig(sets=1, ways=8, withdraw_after_events=0))
        self.assertEqual(result["label_invariance"], "not_applicable_different_policy")
        self.assertIsNone(result["arms"]["ddio-host"]["config"]["withdraw_after_events"])
        self.assertEqual(result["arms"]["ddio-host"]["counts"]["payload_first_hits"], 1)
        self.assertEqual(result["arms"]["ncp-nic"]["counts"]["payload_first_misses"], 1)
        self.assertEqual(result["arms"]["ncp-host-control"]["counts"]["payload_first_misses"], 1)

    def test_corrupt_observed_payload_is_refused_before_replay(self):
        events = sequential_trace([b"expected"])
        next(event for event in events if event["event"] == "consume")["payload"] = b"corrupt!".hex()
        with self.assertRaisesRegex(TraceViolation, "CPU payload differs"):
            Replay(events)

    def test_early_publication_trace_is_refused_before_replay(self):
        events = sequential_trace([b"x" * 65])
        held = next(event for event in events if event["event"] == "visible" and event["kind"] == "payload")
        events.remove(held)
        ready = next(index for index, event in enumerate(events)
                     if event["event"] == "visible" and event["kind"] == "ready")
        events.insert(ready + 1, held)
        with self.assertRaisesRegex(TraceViolation, "before all payload and descriptor"):
            Replay(events)

    def test_invalid_policy_configuration_is_rejected(self):
        events = sequential_trace([b"x"])
        for changes in ({"sets": 0}, {"ways": True}, {"background_lines": -1},
                        {"withdraw_after_events": -1}, {"withdraw_after_events": True}):
            with self.subTest(changes=changes), self.assertRaises(ReplayError):
                ReplayConfig(**changes)
        for admission in ((0, 0), (8,), (-1,), (True,)):
            with self.subTest(admission=admission), self.assertRaises(ReplayError):
                Replay(events, admission=admission)

    def test_bounded_random_schedules_preserve_reuse_and_partial_line_data(self):
        with TemporaryDirectory() as temporary:
            trace_path = Path(temporary) / "protocol.jsonl"
            for seed in (0, 5):
                summary = random_schedule(seed, packets_per_flow=8, trace_path=trace_path)
                events = [json.loads(line) for line in trace_path.read_text().splitlines()]
                received = [event for event in events if event["event"] == "receive"]
                expected_lines = sum((len(bytes.fromhex(event["payload"])) + 63) // 64
                                     for event in received)
                self.assertTrue(any(event["token"]["generation"] > 1 for event in received))
                self.assertTrue(any(len(bytes.fromhex(event["payload"])) % 64 for event in received))
                for withdrawal in (None, 0, 7):
                    with self.subTest(seed=seed, withdrawal=withdrawal):
                        result = paired_replay(events, config=ReplayConfig(
                            sets=3, ways=4, background_lines=3, withdraw_after_events=withdrawal))
                        self.assertEqual(result["status"], "passed")
                        for arm in result["arms"].values():
                            counts = arm["counts"]
                            self.assertEqual(counts["packets"], summary["consumed"])
                            self.assertEqual(counts["payload_first_hits"] + counts["payload_first_misses"],
                                             expected_lines)
                            self.assertEqual(counts["payload_push_lines"], expected_lines)


if __name__ == "__main__":
    unittest.main()
