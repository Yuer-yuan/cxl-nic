"""Adversarial schedules for packet reordering and atomic publication.

These tests control when individual writes become visible.  They exercise the
protocol interface, without depending on the implementation's flow state.
"""

from copy import deepcopy
from dataclasses import replace
import hashlib
import unittest

from cxl_nic.checker import TraceViolation, validate_trace
from cxl_nic.model import Config, Protocol, ProtocolError


class ProtocolTests(unittest.TestCase):
    def make_protocol(self, *, credit=3072, initial_serials=None, window=4):
        return Protocol(
            Config(
                window=window,
                sequence_bits=8,
                max_packet_bytes=1500,
                per_flow_credit_bytes=credit,
            ),
            initial_serials={0: 0, 1: 0}
            if initial_serials is None
            else initial_serials,
        )

    @staticmethod
    def payload(length, salt=0):
        return b"".join(hashlib.sha256(f"{salt}:{block}".encode()).digest()
                        for block in range((length + 31) // 32))[:length]

    def receive(self, protocol, serial, payload, flow=0, expected="accepted"):
        self.assertEqual(
            protocol.receive(flow, serial & 255, serial >> 8, payload),
            expected,
        )
        protocol.check_invariants()

    @staticmethod
    def writes(protocol, *, flow=0, serial=None, kind=None):
        return sorted(
            (
                write
                for write in protocol.pending.values()
                if write.token.flow == flow
                and (serial is None or write.token.serial == serial)
                and (kind is None or write.kind == kind)
            ),
            key=lambda write: write.op_id,
        )

    def complete(self, protocol, write):
        self.assertTrue(protocol.complete(write.op_id))
        protocol.check_invariants()
        protocol.pump()
        protocol.check_invariants()

    def complete_data(self, protocol, serial, *, flow=0, hold=()):
        for write in reversed(self.writes(protocol, flow=flow, serial=serial)):
            if write.kind != "ready" and write.op_id not in hold:
                self.complete(protocol, write)

    def complete_ready(self, protocol, serial, *, flow=0):
        ready = self.writes(protocol, flow=flow, serial=serial, kind="ready")
        self.assertEqual(len(ready), 1)
        self.complete(protocol, ready[0])
        return ready[0].token

    def assert_delivery(self, protocol, serial, payload, *, flow=0):
        delivery = protocol.acquire(flow)
        self.assertIsNotNone(delivery)
        self.assertEqual(delivery.token.flow, flow)
        self.assertEqual(delivery.token.serial, serial)
        self.assertEqual(delivery.token.slot, serial % protocol.config.window)
        self.assertEqual(delivery.payload, payload)
        self.assertEqual(
            delivery.descriptor,
            {
                "flow": flow,
                "serial": serial,
                "slot": delivery.token.slot,
                "generation": delivery.token.generation,
                "length": len(payload),
            },
        )
        protocol.check_invariants()
        return delivery

    def publish(self, protocol, serial, *, flow=0):
        self.complete_data(protocol, serial, flow=flow)
        return self.complete_ready(protocol, serial, flow=flow)

    def test_invalid_window_and_insufficient_packet_credit_are_rejected(self):
        for changes in (
            {"window": 0},
            {"window": 128},
            {"window": 129},
            {"sequence_bits": 1},
            {"sequence_bits": 65},
            {"max_packet_bytes": 0},
            {"per_flow_credit_bytes": 1500},
            {"per_flow_credit_bytes": 1535},
            {"global_push_credit_bytes": 1535},
            {"global_push_credit_bytes": True},
        ):
            with self.subTest(changes=changes), self.assertRaises(ProtocolError):
                Config(**changes)

    def test_global_push_budget_blocks_other_flow_until_release(self):
        protocol = Protocol(Config(global_push_credit_bytes=1536), {0: 0, 1: 0})
        for flow in (0, 1):
            self.receive(protocol, 0, self.payload(1500, flow), flow=flow)
        self.assertEqual(protocol.pump(), 1)
        self.assertEqual({write.token.flow for write in protocol.pending.values()}, {0})
        self.publish(protocol, 0, flow=0)
        first = self.assert_delivery(protocol, 0, self.payload(1500, 0), flow=0)
        self.assertEqual(protocol.pump(), 0)
        protocol.release(first.token)
        self.assertEqual(protocol.pump(), 1)
        self.publish(protocol, 0, flow=1)
        second = self.assert_delivery(protocol, 0, self.payload(1500, 1), flow=1)
        protocol.release(second.token)
        checked = validate_trace(protocol.trace)
        self.assertEqual(checked["global_credit_peak_bytes"], 1536)
        self.assertEqual(checked["global_credit_bytes"], 0)
        too_small = deepcopy(protocol.trace)
        too_small[0]["global_push_credit_bytes"] = 1535
        with self.assertRaisesRegex(TraceViolation, "global_push_credit_bytes"):
            validate_trace(too_small)
        unconstrained = Protocol(Config(), {0: 0, 1: 0})
        for flow in (0, 1):
            unconstrained.receive(flow, 0, 0, self.payload(1500, flow))
        self.assertEqual(unconstrained.pump(), 2)
        over_budget = deepcopy(unconstrained.trace)
        over_budget[0]["global_push_credit_bytes"] = 1536
        with self.assertRaisesRegex(TraceViolation, "global push credit exceeded"):
            validate_trace(over_budget, require_drained=False)

    def test_malformed_packet_does_not_reserve_or_publish_a_slot(self):
        protocol = self.make_protocol()
        for arguments in (
            (0, 0, 0, b""),
            (0, 0, 0, self.payload(1501)),
            (0, 0, 0, bytearray(b"mutable")),
            (0, 256, 0, b"sequence too large"),
            (0, -1, 0, b"negative sequence"),
            (0, 0, -1, b"negative epoch"),
            (2, 0, 0, b"unknown flow"),
        ):
            with self.subTest(arguments=arguments[:3]), self.assertRaises(ProtocolError):
                protocol.receive(*arguments)
            self.assertEqual(protocol.pending, {})
            self.assertEqual(protocol.pump(), 0)
            protocol.check_invariants()
        self.receive(protocol, 0, b"valid packet")
        self.assertEqual(protocol.pump(), 1)
        self.publish(protocol, 0)
        self.assert_delivery(protocol, 0, b"valid packet")

    def test_last_payload_line_blocks_publication_for_boundary_lengths(self):
        for length in (63, 64, 65, 1500):
            with self.subTest(length=length):
                protocol = self.make_protocol()
                payload = self.payload(length)
                self.receive(protocol, 0, payload)
                self.assertEqual(protocol.pump(), 1)
                lines = self.writes(protocol, serial=0, kind="payload")
                self.assertEqual(
                    sorted(write.offset for write in lines),
                    list(range(0, length, 64)),
                )
                held = max(lines, key=lambda write: write.offset)
                self.complete_data(protocol, 0, hold=(held.op_id,))
                self.assertEqual(self.writes(protocol, kind="ready"), [])
                self.assertIsNone(protocol.acquire(0))

                self.complete(protocol, held)
                self.assertEqual(len(self.writes(protocol, kind="ready")), 1)
                self.assertIsNone(protocol.acquire(0))
                self.complete_ready(protocol, 0)
                delivery = self.assert_delivery(protocol, 0, payload)
                protocol.release(delivery.token)
                protocol.check_invariants()

    def test_every_descriptor_field_must_be_visible_before_ready(self):
        fields = {"flow", "serial", "slot", "generation", "length"}
        for field in sorted(fields):
            with self.subTest(field=field):
                protocol = self.make_protocol()
                payload = self.payload(65)
                self.receive(protocol, 0, payload)
                protocol.pump()
                descriptors = self.writes(protocol, serial=0, kind="descriptor")
                self.assertEqual({write.field for write in descriptors}, fields)
                self.assertEqual(len(descriptors), len(fields))
                held = next(write for write in descriptors if write.field == field)
                self.complete_data(protocol, 0, hold=(held.op_id,))
                self.assertEqual(self.writes(protocol, kind="ready"), [])
                self.assertIsNone(protocol.acquire(0))
                self.complete(protocol, held)
                self.assertIsNone(protocol.acquire(0))
                self.complete_ready(protocol, 0)
                self.assert_delivery(protocol, 0, payload)

    def test_later_packet_cannot_commit_before_earlier_packet(self):
        protocol = self.make_protocol()
        first, second = self.payload(65), self.payload(63, 9)
        self.receive(protocol, 1, second)
        self.receive(protocol, 0, first)
        self.assertEqual(protocol.pump(), 2)

        self.complete_data(protocol, 1)
        self.assertEqual(self.writes(protocol, kind="ready"), [])
        self.assertIsNone(protocol.acquire(0))

        self.complete_data(protocol, 0)
        self.assertEqual(len(self.writes(protocol, serial=0, kind="ready")), 1)
        self.assertEqual(self.writes(protocol, serial=1, kind="ready"), [])
        self.assertIsNone(protocol.acquire(0))

        self.complete_ready(protocol, 0)
        self.assertIsNotNone(protocol.acquire(0))
        self.assertIsNone(protocol.acquire(0))
        self.complete_ready(protocol, 1)
        self.assert_delivery(protocol, 1, second)

    def test_acquire_returns_each_packet_once_and_can_precede_release(self):
        protocol = self.make_protocol()
        for serial in (0, 1):
            self.receive(protocol, serial, self.payload(64, serial))
        protocol.pump()
        self.publish(protocol, 0)
        first = self.assert_delivery(protocol, 0, self.payload(64))
        self.assertIsNone(protocol.acquire(0))
        self.publish(protocol, 1)
        second = self.assert_delivery(protocol, 1, self.payload(64, 1))
        self.assertIsNone(protocol.acquire(0))
        protocol.release(second.token)
        protocol.release(first.token)
        protocol.check_invariants()

    def test_credit_is_held_until_release(self):
        protocol = self.make_protocol(credit=1536)
        payload = self.payload(1500)
        self.receive(protocol, 0, payload)
        self.receive(protocol, 1, payload)
        self.assertEqual(protocol.pump(), 1)
        self.assertEqual(self.writes(protocol, serial=1), [])
        self.publish(protocol, 0)
        self.assertEqual(protocol.pump(), 0)
        delivery = self.assert_delivery(protocol, 0, payload)
        self.assertEqual(protocol.pump(), 0)
        self.assertEqual(self.writes(protocol, serial=1), [])
        protocol.release(delivery.token)
        self.assertEqual(protocol.pump(), 1)
        self.assertTrue(self.writes(protocol, serial=1))
        protocol.check_invariants()

    def test_credit_charges_cache_lines_and_never_part_of_a_packet(self):
        protocol = self.make_protocol(credit=1536)
        # 1500 B occupies all 24 lines; the following byte cannot fit yet.
        self.receive(protocol, 0, self.payload(1500))
        self.receive(protocol, 1, b"x")
        self.assertEqual(protocol.pump(), 1)
        self.assertEqual(self.writes(protocol, serial=1), [])
        self.assertEqual(len(self.writes(protocol, serial=0, kind="payload")), 24)
        protocol.check_invariants()

    def test_each_flow_can_spend_its_credit_while_other_flow_is_stalled(self):
        protocol = self.make_protocol(credit=1536)
        payload = self.payload(1500)
        for flow in (0, 1):
            self.receive(protocol, 0, payload, flow=flow)
            self.receive(protocol, 1, payload, flow=flow)
        self.assertEqual(protocol.pump(), 2)
        held_first_flow = {write.op_id for write in self.writes(protocol, flow=0)}

        self.publish(protocol, 0, flow=1)
        delivery = self.assert_delivery(protocol, 0, payload, flow=1)
        protocol.release(delivery.token)
        self.assertEqual(protocol.pump(), 1)
        self.publish(protocol, 1, flow=1)
        self.assert_delivery(protocol, 1, payload, flow=1)
        self.assertEqual(
            {write.op_id for write in self.writes(protocol, flow=0)},
            held_first_flow,
        )
        self.assertIsNone(protocol.acquire(0))
        self.assertEqual(self.writes(protocol, flow=0, serial=1), [])

    def test_missing_packet_blocks_only_its_own_flow(self):
        protocol = self.make_protocol()
        self.receive(protocol, 1, b"later", flow=0)
        self.receive(protocol, 0, b"independent", flow=1)
        self.assertEqual(protocol.pump(), 1)
        self.assertEqual(self.writes(protocol, flow=0), [])
        self.publish(protocol, 0, flow=1)
        self.assert_delivery(protocol, 0, b"independent", flow=1)
        self.assertIsNone(protocol.acquire(0))
        self.receive(protocol, 0, b"missing", flow=0)
        self.assertEqual(protocol.pump(), 2)
        self.publish(protocol, 0)
        self.assert_delivery(protocol, 0, b"missing")
        self.publish(protocol, 1)
        self.assert_delivery(protocol, 1, b"later")

    def test_window_preserves_room_for_gap_and_waits_for_release(self):
        protocol = self.make_protocol()
        self.receive(protocol, 3, b"at upper edge")
        self.receive(protocol, 4, b"too far", expected="outside_window")
        self.assertEqual(protocol.pump(), 0)
        self.receive(protocol, 0, b"fills first gap")
        self.assertEqual(protocol.pump(), 1)
        self.publish(protocol, 0)
        delivery = self.assert_delivery(protocol, 0, b"fills first gap")
        self.receive(protocol, 4, b"still too far", expected="outside_window")
        protocol.release(delivery.token)
        self.receive(protocol, 4, b"now inside")
        self.assertEqual(protocol.pump(), 0)
        self.assertIsNone(protocol.acquire(0))

    def test_out_of_order_release_does_not_advance_window_past_live_slot(self):
        protocol = self.make_protocol()
        for serial in (0, 1):
            self.receive(protocol, serial, bytes([serial]))
        protocol.pump()
        self.publish(protocol, 0)
        first = self.assert_delivery(protocol, 0, b"\x00")
        self.publish(protocol, 1)
        second = self.assert_delivery(protocol, 1, b"\x01")
        protocol.release(second.token)
        self.receive(protocol, 1, b"\x01", expected="late")
        self.receive(protocol, 4, b"blocked by slot zero", expected="outside_window")
        protocol.release(first.token)
        self.receive(protocol, 4, b"slot zero reusable")
        self.receive(protocol, 5, b"slot one reusable")
        self.receive(protocol, 6, b"beyond new window", expected="outside_window")

    def test_duplicate_has_no_effect_and_conflicting_duplicate_is_rejected(self):
        protocol = self.make_protocol()
        payload = b"original"
        self.receive(protocol, 0, payload)
        self.receive(protocol, 0, payload, expected="duplicate")
        with self.assertRaises(ProtocolError):
            protocol.receive(0, 0, 0, b"conflict before issue")
        self.assertEqual(protocol.pump(), 1)
        pending_ids = set(protocol.pending)
        self.receive(protocol, 0, payload, expected="duplicate")
        self.assertEqual(set(protocol.pending), pending_ids)
        with self.assertRaises(ProtocolError):
            protocol.receive(0, 0, 0, b"conflict after issue")
        self.publish(protocol, 0)
        delivery = self.assert_delivery(protocol, 0, payload)
        self.receive(protocol, 0, payload, expected="duplicate")
        protocol.release(delivery.token)
        self.receive(protocol, 0, payload, expected="late")
        protocol.check_invariants()

    def test_epoch_disambiguates_wire_sequence_wrap(self):
        protocol = self.make_protocol(initial_serials={0: 254})
        for serial in (256, 255, 257, 254):
            self.receive(protocol, serial, str(serial).encode("ascii"))
        self.assertEqual(protocol.pump(), 4)
        for serial in (257, 256, 255):
            self.complete_data(protocol, serial)
        self.assertEqual(self.writes(protocol, kind="ready"), [])
        self.complete_data(protocol, 254)
        for serial in range(254, 258):
            self.complete_ready(protocol, serial)
            delivery = self.assert_delivery(
                protocol, serial, str(serial).encode("ascii")
            )
            self.assertEqual(delivery.token.generation, 1)
            protocol.release(delivery.token)
        self.receive(protocol, 0, b"from old epoch", expected="late")
        self.receive(protocol, 256, b"256", expected="late")
        self.receive(protocol, 258, b"next epoch packet")

    def test_slot_reuse_increments_generation_and_ignores_old_completions(self):
        protocol = self.make_protocol()
        stale_ids = []
        first_token = None
        for serial in range(4):
            payload = bytes([serial])
            self.receive(protocol, serial, payload)
            protocol.pump()
            if serial == 0:
                stale_ids.extend(protocol.pending)
            self.complete_data(protocol, serial)
            if serial == 0:
                stale_ids.extend(protocol.pending)
            self.complete_ready(protocol, serial)
            delivery = self.assert_delivery(protocol, serial, payload)
            if serial == 0:
                first_token = delivery.token
            protocol.release(delivery.token)

        self.receive(protocol, 4, b"new occupant")
        protocol.pump()
        writes = self.writes(protocol, serial=4)
        self.assertTrue(writes)
        self.assertTrue(all(write.token.slot == first_token.slot for write in writes))
        self.assertTrue(
            all(write.token.generation == first_token.generation + 1 for write in writes)
        )
        pending_ids = set(protocol.pending)
        for op_id in stale_ids:
            self.assertFalse(protocol.complete(op_id))
            self.assertEqual(set(protocol.pending), pending_ids)
        self.assertIsNone(protocol.acquire(0))
        with self.assertRaises(ProtocolError):
            protocol.release(first_token)
        self.publish(protocol, 4)
        self.assert_delivery(protocol, 4, b"new occupant")

    def test_unknown_and_duplicate_completions_are_idempotent(self):
        protocol = self.make_protocol()
        self.receive(protocol, 0, b"packet")
        protocol.pump()
        pending_ids = set(protocol.pending)
        self.assertFalse(protocol.complete(-1))
        self.assertEqual(set(protocol.pending), pending_ids)
        write = self.writes(protocol, serial=0, kind="payload")[0]
        self.complete(protocol, write)
        pending_ids = set(protocol.pending)
        self.assertFalse(protocol.complete(write.op_id))
        self.assertEqual(set(protocol.pending), pending_ids)
        self.assertIsNone(protocol.acquire(0))
        protocol.check_invariants()

    def test_release_requires_acquire_and_exact_token_and_is_not_repeatable(self):
        protocol = self.make_protocol()
        self.receive(protocol, 0, b"owned")
        protocol.pump()
        token = self.publish(protocol, 0)
        with self.assertRaises(ProtocolError):
            protocol.release(token)
        delivery = self.assert_delivery(protocol, 0, b"owned")
        for changes in (
            {"generation": token.generation + 1},
            {"serial": token.serial + 1},
            {"slot": (token.slot + 1) % 4},
            {"flow": 1},
        ):
            with self.subTest(changes=changes), self.assertRaises(ProtocolError):
                protocol.release(replace(token, **changes))
        protocol.release(delivery.token)
        with self.assertRaises(ProtocolError):
            protocol.release(delivery.token)
        protocol.check_invariants()

    def test_permanent_gap_requires_explicit_failure_without_skipping(self):
        protocol = self.make_protocol()
        self.receive(protocol, 1, b"cannot pass missing zero")
        for _ in range(10):
            self.assertEqual(protocol.pump(), 0)
            self.assertIsNone(protocol.acquire(0))
        protocol.fail_gap(0)
        self.receive(protocol, 0, b"arrived after termination", expected="halted")
        self.receive(protocol, 2, b"later packet", expected="halted")
        self.assertEqual(protocol.pump(), 0)
        self.assertIsNone(protocol.acquire(0))
        self.assertEqual(self.writes(protocol, flow=0), [])
        self.receive(protocol, 0, b"unaffected flow", flow=1)
        self.assertEqual(protocol.pump(), 1)
        self.publish(protocol, 0, flow=1)
        self.assert_delivery(protocol, 0, b"unaffected flow", flow=1)
        protocol.check_invariants()

    def test_gap_failure_allows_preceding_inflight_packet_to_finish(self):
        protocol = self.make_protocol()
        first = self.payload(65)
        self.receive(protocol, 0, first)
        self.receive(protocol, 2, b"blocked behind missing one")
        self.assertEqual(protocol.pump(), 1)
        self.assertTrue(self.writes(protocol, serial=0, kind="payload"))
        self.assertEqual(self.writes(protocol, serial=0, kind="ready"), [])

        protocol.fail_gap(0)
        halt = [event for event in protocol.trace if event["event"] == "halt"]
        self.assertEqual(len(halt), 1)
        self.assertEqual(halt[0]["flow"], 0)
        self.assertEqual(halt[0]["serial"], 1)

        # The ready write is first issued after the halt, when packet 0's
        # preceding writes finish.  This drains the valid prefix of the flow.
        self.complete_data(protocol, 0)
        self.assertEqual(len(self.writes(protocol, serial=0, kind="ready")), 1)
        self.complete_ready(protocol, 0)
        delivery = self.assert_delivery(protocol, 0, first)
        protocol.release(delivery.token)

        self.receive(protocol, 1, b"arrived too late", expected="halted")
        self.assertEqual(protocol.pump(), 0)
        self.assertEqual(self.writes(protocol, serial=2), [])
        self.assertEqual(protocol.pending, {})
        self.assertIsNone(protocol.acquire(0))
        protocol.check_invariants()
        checked = validate_trace(protocol.trace, require_drained=False)
        self.assertEqual(checked["consumed"], 1)
        self.assertEqual(checked["released"], 1)

    def test_mutating_delivery_descriptor_cannot_rewrite_trace_history(self):
        protocol = self.make_protocol()
        payload = b"immutable history"
        self.receive(protocol, 0, payload)
        protocol.pump()
        self.publish(protocol, 0)
        delivery = self.assert_delivery(protocol, 0, payload)
        history = deepcopy(protocol.trace)

        delivery.descriptor["length"] = 1500
        delivery.descriptor["generation"] += 100
        delivery.descriptor["application_annotation"] = "changed by caller"
        self.assertEqual(protocol.trace, history)
        protocol.check_invariants()
        checked = validate_trace(protocol.trace, require_drained=False)
        self.assertEqual(checked["consumed"], 1)

        protocol.release(delivery.token)
        checked = validate_trace(protocol.trace)
        self.assertEqual(checked["released"], 1)


if __name__ == "__main__":
    unittest.main()
