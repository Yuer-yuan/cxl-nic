"""Checker tests build their traces directly, without importing the model."""

from __future__ import annotations

from copy import deepcopy
import unittest

from cxl_nic.checker import TraceViolation, validate_trace


class TraceBuilder:
    """Small fixture writer; deliberately contains no protocol enforcement."""

    def __init__(self, *, window=4, credit=512, initial=None):
        self.events = [{
            "event": "config", "window": window, "sequence_bits": 8,
            "max_packet_bytes": min(512, credit), "per_flow_credit_bytes": credit,
            "initial_serials": initial or {"0": 0},
        }]
        self.window = window
        self.op_id = 0
        self.tokens = {}
        self.payloads = {}

    def receive(self, serial, payload=b"packet", *, flow=0, generation=1):
        token = {"flow": flow, "serial": serial, "slot": serial % self.window, "generation": generation}
        self.tokens[flow, serial] = token
        self.payloads[flow, serial] = payload
        self.events.append({"event": "receive", "token": token, "payload": payload.hex()})
        return token

    def write(self, serial, kind, *, flow=0, **fields):
        result = {"event": "issue", "token": self.tokens[flow, serial], "op_id": self.op_id,
                  "kind": kind, **fields}
        self.op_id += 1
        self.events.append(result)
        return result

    def visible(self, issue):
        self.events.append({**issue, "event": "visible"})

    def data(self, serial, *, flow=0, complete=True):
        payload = self.payloads[flow, serial]
        issues = []
        for offset in range(0, len(payload), 64):
            issues.append(self.write(serial, "payload", flow=flow, offset=offset,
                                     data=payload[offset:offset + 64].ljust(64, b"\0").hex()))
        for name, value in {**self.tokens[flow, serial], "length": len(payload)}.items():
            issues.append(self.write(serial, "descriptor", flow=flow, field=name, value=value))
        if complete:
            for issue in reversed(issues):
                self.visible(issue)
        return issues

    def ready(self, serial, *, flow=0, complete=True):
        issue = self.write(serial, "ready", flow=flow)
        if complete:
            self.visible(issue)
        return issue

    def consume(self, serial, *, flow=0):
        payload = self.payloads[flow, serial]
        self.events.append({"event": "consume", "token": self.tokens[flow, serial],
                            "descriptor": {**self.tokens[flow, serial], "length": len(payload)},
                            "payload": payload.hex()})

    def release(self, serial, *, flow=0):
        self.events.append({"event": "release", "token": self.tokens[flow, serial]})

    def packet(self, serial, payload=b"packet", *, flow=0, generation=1):
        self.receive(serial, payload, flow=flow, generation=generation)
        self.data(serial, flow=flow)
        self.ready(serial, flow=flow)
        self.consume(serial, flow=flow)
        self.release(serial, flow=flow)


def two_packets():
    builder = TraceBuilder()
    builder.receive(1, b"second")
    builder.receive(0, bytes(range(97)))
    first_issues = builder.data(0, complete=False)
    builder.data(1)
    for issue in reversed(first_issues):
        builder.visible(issue)
    builder.ready(0)
    builder.ready(1)
    builder.consume(0)
    builder.consume(1)
    builder.release(1)
    builder.release(0)
    return builder


class TraceCheckerTests(unittest.TestCase):
    def test_out_of_order_arrival_and_visibility_in_order_delivery(self):
        result = validate_trace(two_packets().events)
        self.assertEqual(result["received"], 2)
        self.assertEqual(result["consumed"], 2)
        self.assertEqual(result["released"], 2)
        self.assertEqual(result["peak_credit_bytes"], {"0": 192})
        self.assertEqual(result["release_bases"], {"0": 2})
        self.assertEqual(result["pending_writes"], 0)

    def test_slot_reuse_after_release_and_sequence_wrap(self):
        builder = TraceBuilder(initial={"0": 254})
        for serial in range(254, 262):
            builder.packet(serial, bytes([serial % 256]), generation=1 + (serial - 254) // 4)
        result = validate_trace(builder.events)
        self.assertEqual(result["consumed"], 8)
        self.assertEqual(result["release_bases"], {"0": 262})

    def test_credit_is_per_flow(self):
        builder = TraceBuilder(credit=64, initial={"0": 0, "1": 0})
        for flow in (0, 1):
            builder.receive(0, flow=flow)
            builder.data(0, flow=flow)
            builder.ready(0, flow=flow)
        for flow in (1, 0):
            builder.consume(0, flow=flow)
            builder.release(0, flow=flow)
        self.assertEqual(validate_trace(builder.events)["peak_credit_bytes"], {"0": 64, "1": 64})

    def test_trace_snapshot_can_be_checked_without_drain(self):
        builder = TraceBuilder()
        builder.receive(0)
        builder.data(0, complete=False)
        result = validate_trace(builder.events, require_drained=False)
        self.assertEqual(result["outstanding_packets"], 1)
        self.assertEqual(result["pending_writes"], 6)
        with self.assertRaisesRegex(TraceViolation, "not drained"):
            validate_trace(builder.events)

    def test_negative_control_ready_before_payload_visible(self):
        builder = TraceBuilder()
        builder.receive(0)
        issues = builder.data(0, complete=False)
        for issue in issues:
            if issue["kind"] != "payload":
                builder.visible(issue)
        builder.ready(0)
        with self.assertRaisesRegex(TraceViolation, "before all payload and descriptor"):
            validate_trace(builder.events, require_drained=False)

    def test_negative_control_metadata_visible_after_ready_issue(self):
        builder = TraceBuilder()
        builder.receive(0)
        issues = builder.data(0, complete=False)
        for issue in issues:
            if issue.get("field") != "length":
                builder.visible(issue)
        builder.ready(0)
        builder.visible(next(issue for issue in issues if issue.get("field") == "length"))
        with self.assertRaisesRegex(TraceViolation, "before all payload and descriptor"):
            validate_trace(builder.events)

    def test_negative_control_cpu_out_of_order(self):
        events = two_packets().events
        indexes = [i for i, event in enumerate(events) if event["event"] == "consume"]
        events[indexes[0]], events[indexes[1]] = events[indexes[1]], events[indexes[0]]
        with self.assertRaisesRegex(TraceViolation, "CPU consumed packets out of order"):
            validate_trace(events)

    def test_negative_control_wrong_payload(self):
        events = two_packets().events
        next(event for event in events if event["event"] == "consume")["payload"] = b"corrupted".hex()
        with self.assertRaisesRegex(TraceViolation, "CPU payload differs"):
            validate_trace(events)

    def test_negative_control_swapped_payload_lines(self):
        builder = TraceBuilder()
        builder.packet(0, bytes(range(128)))
        for event in builder.events:
            if event.get("kind") == "payload":
                offset = event["offset"]
                other = 64 if offset == 0 else 0
                event["data"] = bytes(range(128))[other:other + 64].hex()
        with self.assertRaisesRegex(TraceViolation, "payload write differs"):
            validate_trace(builder.events)

    def test_negative_control_slot_reuse_before_release(self):
        builder = TraceBuilder()
        builder.receive(0)
        builder.receive(0, b"replacement", generation=2)
        with self.assertRaisesRegex(TraceViolation, "slot reused before release"):
            validate_trace(builder.events, require_drained=False)

    def test_negative_control_stale_write_after_release(self):
        builder = TraceBuilder()
        builder.packet(0)
        old_visible = next(event for event in builder.events if event["event"] == "visible")
        builder.events.append(deepcopy(old_visible))
        with self.assertRaisesRegex(TraceViolation, "stale access after release"):
            validate_trace(builder.events)

    def test_negative_control_early_credit_reuse_after_consume(self):
        builder = TraceBuilder(credit=64)
        builder.receive(0)
        builder.data(0)
        builder.ready(0)
        builder.consume(0)
        builder.receive(1)
        builder.data(1)
        with self.assertRaisesRegex(TraceViolation, "credit exceeded before release"):
            validate_trace(builder.events, require_drained=False)

    def test_ready_issue_waits_for_predecessor_ready_visibility(self):
        builder = TraceBuilder()
        for serial in (0, 1):
            builder.receive(serial)
            builder.data(serial)
        builder.ready(0, complete=False)
        builder.ready(1)
        with self.assertRaisesRegex(TraceViolation, "preceding serial's ready"):
            validate_trace(builder.events, require_drained=False)

    def test_release_base_advances_only_through_contiguous_releases(self):
        builder = two_packets()
        builder.events.pop()  # serial 1 released, serial 0 still owns its slot.
        builder.receive(4, generation=2)
        with self.assertRaisesRegex(TraceViolation, "outside the window"):
            validate_trace(builder.events, require_drained=False)

    def test_negative_control_reaccept_released_serial_before_base_advances(self):
        builder = two_packets()
        builder.events.pop()  # serial 1 released, serial 0 still owns its slot.
        builder.receive(1, b"second", generation=2)
        with self.assertRaisesRegex(TraceViolation, "already released serial"):
            validate_trace(builder.events, require_drained=False)

    def test_negative_control_first_issue_skips_missing_packet(self):
        builder = TraceBuilder()
        builder.receive(1)
        builder.data(1)
        with self.assertRaisesRegex(TraceViolation, "outside the contiguous packet prefix"):
            validate_trace(builder.events, require_drained=False)

    def test_negative_control_first_issue_reorders_accepted_packets(self):
        builder = TraceBuilder()
        builder.receive(0)
        builder.receive(1)
        builder.data(1)
        with self.assertRaisesRegex(TraceViolation, "outside the contiguous packet prefix"):
            validate_trace(builder.events, require_drained=False)

    def test_components_can_be_issued_in_any_order(self):
        builder = TraceBuilder()
        builder.receive(0)
        issues = builder.data(0, complete=False)
        del builder.events[-len(issues):]
        builder.events.extend(reversed(issues))
        for issue in issues:
            builder.visible(issue)
        builder.ready(0)
        builder.consume(0)
        builder.release(0)
        self.assertEqual(validate_trace(builder.events)["released"], 1)

    def test_duplicate_issue_is_rejected(self):
        builder = TraceBuilder()
        builder.receive(0)
        issue = builder.data(0, complete=False)[0]
        builder.events.append(deepcopy(issue))
        with self.assertRaisesRegex(TraceViolation, "duplicate issued op_id"):
            validate_trace(builder.events, require_drained=False)

    def test_duplicate_visibility_is_rejected(self):
        builder = TraceBuilder()
        builder.receive(0)
        issue = builder.data(0)[0]
        builder.visible(issue)
        with self.assertRaisesRegex(TraceViolation, "duplicate write visibility"):
            validate_trace(builder.events, require_drained=False)

    def test_completion_must_match_issued_identity(self):
        builder = TraceBuilder()
        builder.receive(0)
        builder.receive(1)
        issue = builder.data(0, complete=False)[0]
        # The other packet has identical bytes, so only identity validation catches it.
        builder.visible({**issue, "token": builder.tokens[0, 1]})
        with self.assertRaisesRegex(TraceViolation, "identity/content differs"):
            validate_trace(builder.events, require_drained=False)

    def test_tail_zero_padding_is_checked(self):
        builder = TraceBuilder()
        builder.receive(0, b"short")
        builder.write(0, "payload", offset=0, data=b"short".ljust(64, b"x").hex())
        with self.assertRaisesRegex(TraceViolation, "zero padding"):
            validate_trace(builder.events, require_drained=False)

    def test_wrong_descriptor_is_rejected(self):
        builder = TraceBuilder()
        builder.receive(0)
        builder.write(0, "descriptor", field="length", value=123)
        with self.assertRaisesRegex(TraceViolation, "descriptor.length differs"):
            validate_trace(builder.events, require_drained=False)

    def test_cpu_cannot_consume_before_ready_visibility(self):
        builder = TraceBuilder()
        builder.receive(0)
        builder.data(0)
        builder.ready(0, complete=False)
        builder.consume(0)
        with self.assertRaisesRegex(TraceViolation, "before ready was visible"):
            validate_trace(builder.events, require_drained=False)

    def test_cpu_cannot_release_before_consume(self):
        builder = TraceBuilder()
        builder.receive(0)
        builder.data(0)
        builder.ready(0)
        builder.release(0)
        with self.assertRaisesRegex(TraceViolation, "before CPU consumed"):
            validate_trace(builder.events, require_drained=False)

    def test_halt_is_failure_and_reject_is_counted_without_delivery(self):
        builder = TraceBuilder()
        builder.receive(1)
        builder.events.extend([
            {"event": "reject", "flow": 0, "serial": 100, "reason": "outside window"},
            {"event": "halt", "flow": 0, "serial": 0, "reason": "gap timeout"},
        ])
        result = validate_trace(builder.events, require_drained=False)
        self.assertEqual((result["rejected"], result["halted"], result["consumed"]), (1, 1, 0))
        with self.assertRaisesRegex(TraceViolation, "halted flows"):
            validate_trace(builder.events)

    def test_halt_allows_preceding_issued_prefix_to_finish_and_release(self):
        builder = TraceBuilder()
        builder.receive(0)
        builder.receive(2)
        issues = builder.data(0, complete=False)
        builder.events.append({"event": "halt", "flow": 0, "serial": 1, "reason": "missing_packet"})
        for issue in reversed(issues):
            builder.visible(issue)
        builder.ready(0)
        builder.consume(0)
        builder.release(0)
        result = validate_trace(builder.events, require_drained=False)
        self.assertEqual(result["released"], 1)
        self.assertEqual(result["release_bases"], {"0": 1})
        self.assertEqual(result["pending_writes"], 0)
        self.assertEqual(result["outstanding_packets"], 1)
        self.assertEqual(result["credit_bytes"], {"0": 0})
        with self.assertRaisesRegex(TraceViolation, "halted flows"):
            validate_trace(builder.events)

    def test_negative_control_halt_cannot_misidentify_next_issue(self):
        builder = TraceBuilder()
        builder.receive(2)
        builder.events.append({"event": "halt", "flow": 0, "serial": 1, "reason": "missing_packet"})
        with self.assertRaisesRegex(TraceViolation, "next unissued serial"):
            validate_trace(builder.events, require_drained=False)

    def test_negative_control_halt_cannot_treat_accepted_packet_as_missing(self):
        builder = TraceBuilder()
        builder.receive(0)
        builder.receive(1)
        builder.events.append({"event": "halt", "flow": 0, "serial": 0, "reason": "missing_packet"})
        with self.assertRaisesRegex(TraceViolation, "already accepted"):
            validate_trace(builder.events, require_drained=False)

    def test_negative_control_halt_requires_later_accepted_packet(self):
        builder = TraceBuilder()
        builder.events.append({"event": "halt", "flow": 0, "serial": 0, "reason": "missing_packet"})
        with self.assertRaisesRegex(TraceViolation, "later accepted packet"):
            validate_trace(builder.events, require_drained=False)

    def test_negative_control_halt_blocks_receive(self):
        builder = TraceBuilder()
        builder.receive(1)
        builder.events.append({"event": "halt", "flow": 0, "serial": 0, "reason": "missing_packet"})
        builder.receive(0)
        with self.assertRaisesRegex(TraceViolation, "receive after flow halt"):
            validate_trace(builder.events, require_drained=False)

    def test_negative_control_halt_blocks_new_packet_issue(self):
        builder = TraceBuilder()
        builder.receive(1)
        builder.events.append({"event": "halt", "flow": 0, "serial": 0, "reason": "missing_packet"})
        builder.data(1)
        with self.assertRaisesRegex(TraceViolation, "before the halted gap may issue ready"):
            validate_trace(builder.events, require_drained=False)

    def test_negative_control_halt_blocks_additional_payload_issue(self):
        builder = TraceBuilder()
        builder.receive(0, bytes(range(97)))
        builder.receive(2)
        builder.write(0, "payload", offset=0, data=bytes(range(64)).hex())
        builder.events.append({"event": "halt", "flow": 0, "serial": 1, "reason": "missing_packet"})
        builder.write(0, "payload", offset=64, data=bytes(range(64, 97)).ljust(64, b"\0").hex())
        with self.assertRaisesRegex(TraceViolation, "before the halted gap may issue ready"):
            validate_trace(builder.events, require_drained=False)

    def test_negative_control_credit_config_must_cover_aligned_maximum_packet(self):
        builder = TraceBuilder(credit=64)
        builder.events[0]["max_packet_bytes"] = 65
        with self.assertRaisesRegex(TraceViolation, "complete maximum-size packet"):
            validate_trace(builder.events)

    def test_negative_control_sequence_bits_cannot_exceed_64(self):
        builder = TraceBuilder()
        builder.events[0]["sequence_bits"] = 65
        with self.assertRaisesRegex(TraceViolation, "sequence_bits must be <= 64"):
            validate_trace(builder.events)

    def test_malformed_configuration_and_events_raise_trace_violation(self):
        with self.assertRaises(TraceViolation):
            validate_trace([])
        for key, value in (("window", 128), ("sequence_bits", True), ("initial_serials", {"00": 0})):
            events = TraceBuilder().events
            events[0][key] = value
            with self.subTest(key=key), self.assertRaises(TraceViolation):
                validate_trace(events)
        with self.assertRaises(TraceViolation):
            validate_trace([*TraceBuilder().events, None])


if __name__ == "__main__":
    unittest.main()
