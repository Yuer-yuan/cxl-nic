"""Check the guest ABI and that external observations remain independent."""

from dataclasses import asdict
import struct
import unittest

from cxl_nic.checker import TraceViolation, validate_trace
from cxl_nic.integration import (backend_address, pattern, qemu_command,
                                 run_case, slot_address, write_address)
from cxl_nic.model import Config, Protocol, ProtocolError, Token, Write


class GuestPatternTests(unittest.TestCase):
    def test_type2_backend_avoids_the_bar4_command_register_aperture(self):
        self.assertEqual(backend_address(0, "type3"), 0)
        self.assertEqual(backend_address(0, "type2"), 0x200000)
        self.assertEqual(backend_address(0x16000, "type2"), 0x216000)
        with self.assertRaises(ValueError):
            backend_address(0, "invalid")

    def test_qemu_command_selects_one_explicit_endpoint_type(self):
        type3 = qemu_command("qemu", "guest")
        self.assertTrue(any(value.startswith("cxl-type3,") for value in type3))
        self.assertFalse(any(value.startswith("cxl-type2,") for value in type3))
        type2 = qemu_command("qemu", "guest", "type2", 12345)
        devices = [value for value in type2 if value.startswith("cxl-type2,")]
        self.assertEqual(len(devices), 1)
        self.assertIn("cxlmemsim-port=12345", devices[0])
        self.assertIn("gpu-mode=0", devices[0])
        self.assertFalse(any(value.startswith("cxl-type3,") for value in type2))
        for device, port in (("invalid", 12345), ("type2", None), ("type2", True),
                             ("type2", 0), ("type2", 65536)):
            with self.subTest(device=device, port=port), self.assertRaises(ValueError):
                qemu_command("qemu", "guest", device, port)

    def test_cache_injection_data_paths_require_type2(self):
        arguments = (None, None, None, None, None, "adversarial", 4, 1)
        with self.assertRaisesRegex(ValueError, "data_path"):
            run_case(*arguments, device_type="type2", data_path="unknown")
        for data_path in ("ncp", "ddio"):
            with self.subTest(data_path=data_path), self.assertRaisesRegex(ValueError, "Type2"):
                run_case(*arguments, device_type="type3", data_path=data_path)

    def test_post_push_nc_write_is_scoped_to_adversarial_ncp(self):
        arguments = (None, None, None, None, None, "adversarial", 4, 1)
        with self.assertRaisesRegex(ValueError, "ncp_post_push"):
            run_case(*arguments, device_type="type2", data_path="ncp", ncp_post_push="invalid")
        with self.assertRaisesRegex(ValueError, "adversarial NC-P"):
            run_case(*arguments, device_type="type2", data_path="ddio",
                     ncp_post_push="before-ready")
        other = (*arguments[:5], "early-ready", *arguments[6:])
        with self.assertRaisesRegex(ValueError, "adversarial NC-P"):
            run_case(*other, device_type="type2", data_path="ncp",
                     ncp_post_push="before-ready")

    def test_adaptive_gate_is_scoped_and_separate_from_post_push(self):
        arguments = (None, None, None, None, None, "adversarial", 4, 1)
        for value in (-1, True, 1.5):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "ncp_gate_resident_lines"):
                run_case(*arguments, device_type="type2", data_path="ncp",
                         ncp_gate_resident_lines=value)
        with self.assertRaisesRegex(ValueError, "adversarial NC-P"):
            run_case(*arguments, device_type="type2", data_path="ddio",
                     ncp_gate_resident_lines=8)
        with self.assertRaisesRegex(ValueError, "separate policies"):
            run_case(*arguments, device_type="type2", data_path="ncp",
                     ncp_gate_resident_lines=8, ncp_post_push="before-ready")

    def test_pattern_golden_vectors_cover_endianness_flow_and_partial_word(self):
        vectors = (
            ((0, 0, 0, 16), "0000000000000000737a5367a08f5ab5"),
            ((1, 0, 0, 8), "e5050b101d169256"),
            ((0x0123456789ABCDEF, 0, 254, 33),
             "e58675f96a2921ff28c6e80c7b78c9a7562cc1d6a48a2535237a0e34178fe1a411"),
            ((0xFEDCBA9876543210, 1, 510, 65),
             "d4303c4df79f9bce3339a10de5690ceeba99d8df0348f91ba489dd38f7b37bdf8"
             "e2992412eb15bd5a9622904925e2b901543833f4b99ee5509d2830ee1494f8e5b"),
        )
        for arguments, expected in vectors:
            with self.subTest(arguments=arguments):
                self.assertEqual(pattern(*arguments), bytes.fromhex(expected))

    def test_descriptor_ready_and_payload_use_separate_abi_locations(self):
        token = Token(flow=1, serial=510, slot=2, generation=3)
        self.assertEqual(slot_address(token), 0x16000)
        fields = ("flow", "serial", "slot", "generation", "length")
        values = (1, 510, 2, 3, 1500)
        for offset, (field, value) in enumerate(zip(fields, values)):
            with self.subTest(field=field):
                write = Write(offset, token, "descriptor", field=field, value=value)
                self.assertEqual(write_address(write),
                                 (0x16000 + offset * 8, struct.pack("<Q", value)))
        self.assertEqual(write_address(Write(10, token, "ready")),
                         (0x16040, b"\x03" + bytes(7)))
        last = bytes(range(64))
        self.assertEqual(write_address(Write(11, token, "payload", offset=1472, data=last)),
                         (0x166C0, last))


class ExternalObservationTests(unittest.TestCase):
    @staticmethod
    def published(payload=b"MODEL"):
        protocol = Protocol(Config(), {0: 254})
        protocol.receive(0, 254, 0, payload)
        protocol.pump()
        while protocol.pending:
            protocol.complete(next(iter(protocol.pending)))
        descriptor = {"flow": 0, "serial": 254, "slot": 2,
                      "generation": 1, "length": len(payload)}
        return protocol, descriptor

    def test_external_payload_is_logged_even_when_model_shadow_is_correct(self):
        protocol, descriptor = self.published()
        observation = b"GUEST"
        delivery = protocol.observe_consumption(0, descriptor, observation)
        self.assertEqual(delivery.payload, observation)
        self.assertEqual(protocol.trace[-1]["payload"], observation.hex())
        # A shadow-based acquisition would have returned MODEL and passed.
        with self.assertRaises(TraceViolation):
            validate_trace(protocol.trace, require_drained=False)

    def test_external_descriptor_fields_are_not_replaced_by_model_metadata(self):
        for field, wrong in (("flow", 1), ("serial", 255), ("slot", 3),
                             ("generation", 2), ("length", 4)):
            with self.subTest(field=field):
                protocol, descriptor = self.published()
                descriptor[field] = wrong
                delivery = protocol.observe_consumption(0, descriptor, b"MODEL")
                self.assertEqual(delivery.descriptor[field], wrong)
                self.assertEqual(protocol.trace[-1]["descriptor"][field], wrong)
                with self.assertRaises(TraceViolation):
                    validate_trace(protocol.trace, require_drained=False)

    def test_observed_truncation_cannot_pass_using_shadow_payload(self):
        protocol, descriptor = self.published()
        delivery = protocol.observe_consumption(0, descriptor, b"MOD")
        self.assertEqual(delivery.payload, b"MOD")
        with self.assertRaises(TraceViolation):
            validate_trace(protocol.trace, require_drained=False)

    def test_external_observation_requires_completed_publication(self):
        protocol = Protocol(Config(), {0: 254})
        protocol.receive(0, 254, 0, b"MODEL")
        protocol.pump()
        descriptor = {"flow": 0, "serial": 254, "slot": 2,
                      "generation": 1, "length": 5}
        for write in list(protocol.pending.values()):
            protocol.complete(write.op_id)
        self.assertEqual([write.kind for write in protocol.pending.values()], ["ready"])
        with self.assertRaises(ProtocolError):
            protocol.observe_consumption(0, descriptor, b"MODEL")
        self.assertFalse(any(event["event"] == "consume" for event in protocol.trace))

    def test_valid_observation_is_snapshotted_and_accepted_exactly_once(self):
        payload = pattern(0x0123456789ABCDEF, 0, 254, 33)
        protocol, descriptor = self.published(payload)
        delivery = protocol.observe_consumption(0, descriptor, payload)
        self.assertEqual(delivery.descriptor, {**asdict(delivery.token), "length": 33})
        descriptor["serial"] = 999
        self.assertEqual(delivery.descriptor["serial"], 254)
        self.assertEqual(protocol.trace[-1]["descriptor"]["serial"], 254)
        with self.assertRaises(ProtocolError):
            protocol.observe_consumption(0, delivery.descriptor, payload)
        protocol.release(delivery.token)
        result = validate_trace(protocol.trace)
        self.assertEqual(result["consumed"], 1)
        self.assertEqual(result["released"], 1)


if __name__ == "__main__":
    unittest.main()
