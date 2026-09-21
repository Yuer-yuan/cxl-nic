"""Wire compatibility and fail-closed checks for CXLMemSim TCP requests."""

import socket
import unittest
from unittest.mock import patch

from cxl_nic.transport import Client, TransportError


def response(data=b"", *, status=0, latency=0, old_value=0):
    # Encode independently of transport.RESPONSE to check its actual wire layout.
    return (bytes([status]) + latency.to_bytes(8, "little")
            + old_value.to_bytes(8, "little") + data.ljust(64, b"\0"))


class ScriptedSocket:
    """A socket with exact short reads and errors, independent of TCP buffering."""

    def __init__(self, fragments=(), send_error=None):
        self.fragments = list(fragments)
        self.send_error = send_error
        self.sent = []
        self.recv_sizes = []
        self.close_count = 0
        self.options = []

    def setsockopt(self, *option):
        self.options.append(option)

    def sendall(self, data):
        self.sent.append(data)
        if self.send_error is not None:
            raise self.send_error

    def recv(self, size):
        self.recv_sizes.append(size)
        if not self.fragments:
            return b""
        fragment = self.fragments.pop(0)
        if isinstance(fragment, BaseException):
            raise fragment
        if len(fragment) > size:
            self.fragments.insert(0, fragment[size:])
        return fragment[:size]

    def close(self):
        self.close_count += 1


class TransportTests(unittest.TestCase):
    def make_client(self, fragments=(), *, capacity=128, send_error=None):
        stream = ScriptedSocket(fragments, send_error)
        with patch("cxl_nic.transport.socket.create_connection", return_value=stream) as connect:
            client = Client(("127.0.0.1", 9999), capacity=capacity, timeout=0.75)
        connect.assert_called_once_with(("127.0.0.1", 9999), timeout=0.75)
        self.assertEqual(stream.options, [(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)])
        self.addCleanup(client.close)
        return client, stream

    def test_write_wire_layout_and_zero_padding(self):
        client, stream = self.make_client([response()])
        with patch("cxl_nic.transport.time.monotonic_ns", return_value=0x0102030405060708):
            client.write(0x48, b"\x91\x82\x73")
        expected = bytes.fromhex(
            "01"                  # WRITE
            "4800000000000000"    # DPA
            "0300000000000000"    # byte count
            "0807060504030201"    # monotonic timestamp
            "0000000000000000"    # atomic value
            "0000000000000000"    # atomic expected
        ) + b"\x91\x82\x73" + bytes(61)
        self.assertEqual(stream.sent, [expected])
        self.assertEqual(len(expected), 105)
        self.assertEqual((client.reads, client.writes), (0, 1))

    def test_read_decodes_fragmented_response_without_metadata_leaking(self):
        payload = bytes(range(64))
        reply = response(payload, latency=0x8877665544332211, old_value=0xA1B2C3D4)
        fragments = [reply[:1], reply[1:4], reply[4:16], reply[16:18], reply[18:]]
        client, stream = self.make_client(fragments)
        with patch("cxl_nic.transport.time.monotonic_ns", return_value=0):
            self.assertEqual(client.read(64, 64), payload)
        self.assertEqual(stream.recv_sizes, [81, 80, 77, 65, 63])
        self.assertEqual(stream.sent[0], b"\0" + (64).to_bytes(8, "little")
                         + (64).to_bytes(8, "little") + bytes(24 + 64))
        self.assertEqual((client.reads, client.writes), (1, 0))

    def test_back_to_back_replies_do_not_cross_request_boundary(self):
        client, stream = self.make_client([response(b"first") + response(b"second")])
        self.assertEqual(client.read(0, 5), b"first")
        self.assertEqual(client.read(8, 6), b"second")
        self.assertEqual(stream.recv_sizes, [81, 81])
        self.assertEqual(client.reads, 2)

    def test_u64_round_trip_uses_little_endian_bytes(self):
        encoded = bytes.fromhex("efcdab8967452301")
        client, stream = self.make_client([response(), response(encoded)])
        client.write_u64(64, 0x0123456789ABCDEF)
        self.assertEqual(stream.sent[0][41:49], encoded)
        self.assertEqual(client.read_u64(64), 0x0123456789ABCDEF)
        self.assertEqual((client.reads, client.writes), (1, 1))

    def test_status_error_closes_stream_and_does_not_count_write(self):
        client, stream = self.make_client([response(status=7)])
        with self.assertRaisesRegex(TransportError, "status 7 for op 1"):
            client.write(0, b"payload")
        self.assertTrue(client.closed)
        self.assertEqual(stream.close_count, 1)
        self.assertEqual(client.writes, 0)
        with self.assertRaisesRegex(TransportError, "transport is closed"):
            client.read(0, 8)
        self.assertEqual(len(stream.sent), 1)

    def test_truncated_response_closes_stream_at_every_wire_section(self):
        for length in (0, 1, 8, 16, 17, 40, 80):
            with self.subTest(length=length):
                client, stream = self.make_client([response(b"data")[:length]])
                with self.assertRaisesRegex(TransportError, "complete response"):
                    client.read(0, 4)
                self.assertEqual((client.reads, client.writes), (0, 0))
                self.assertTrue(client.closed)
                self.assertEqual(stream.close_count, 1)

    def test_timeout_after_partial_reply_prevents_retry(self):
        client, stream = self.make_client([response()[:20], socket.timeout("deadline")])
        with self.assertRaisesRegex(TransportError, "deadline") as caught:
            client.read(0, 8)
        self.assertIsInstance(caught.exception.__cause__, OSError)
        self.assertTrue(client.closed)
        with self.assertRaisesRegex(TransportError, "closed"):
            client.write(0, b"retry")
        self.assertEqual(len(stream.sent), 1)
        self.assertEqual(stream.close_count, 1)

    def test_send_failure_closes_stream_without_reading(self):
        client, stream = self.make_client(send_error=BrokenPipeError("broken"))
        with self.assertRaisesRegex(TransportError, "broken"):
            client.write(0, b"payload")
        self.assertTrue(client.closed)
        self.assertEqual(stream.recv_sizes, [])
        self.assertEqual((client.reads, client.writes), (0, 0))

    def test_rejects_invalid_read_before_sending_and_remains_usable(self):
        invalid = ((-1, 1), (True, 1), (0.5, 1), (0, 0), (0, -1),
                   (0, True), (0, 1.0), (0, 65), (63, 2), (127, 2),
                   (128, 1), (1 << 64, 1))
        client, stream = self.make_client([response(b"x")])
        for address, size in invalid:
            with self.subTest(address=address, size=size), self.assertRaises(ValueError):
                client.read(address, size)
        self.assertEqual(stream.sent, [])
        self.assertFalse(client.closed)
        self.assertEqual(client.read(127, 1), b"x")

    def test_rejects_invalid_write_before_sending(self):
        invalid = ((0, b""), (0, bytearray(b"x")), (0, "x"), (0, None),
                   (0, bytes(65)), (63, b"xx"), (128, b"x"), (-1, b"x"))
        client, stream = self.make_client()
        for address, payload in invalid:
            with self.subTest(address=address, payload=payload), self.assertRaises(ValueError):
                client.write(address, payload)
        self.assertEqual(stream.sent, [])
        self.assertFalse(client.closed)
        self.assertEqual(client.writes, 0)

    def test_context_manager_closes_once_even_when_body_fails(self):
        client, stream = self.make_client()
        with self.assertRaisesRegex(RuntimeError, "consumer failure"):
            with client:
                raise RuntimeError("consumer failure")
        client.close()
        self.assertTrue(client.closed)
        self.assertEqual(stream.close_count, 1)


if __name__ == "__main__":
    unittest.main()
