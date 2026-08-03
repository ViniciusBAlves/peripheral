from __future__ import annotations

import sys
import unittest
from pathlib import Path


BENCHMARKING = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKING))

from benchmarklib.transfer import (  # noqa: E402
    PAYLOAD_SIZES,
    build_transfer_rounds,
    encode_remaining_length,
    mqtt_publish_header,
    operations_for_round,
    payload_bytes,
    payload_sha256,
)


class TransferBenchmarkTests(unittest.TestCase):
    def test_seeded_round_order_is_reproducible(self) -> None:
        cases = [
            {"case_id": "case-a", "iterations": "2"},
            {"case_id": "case-b", "iterations": "2"},
        ]
        self.assertEqual(
            build_transfer_rounds(cases, seed=123),
            build_transfer_rounds(cases, seed=123),
        )
        self.assertNotEqual(
            build_transfer_rounds(cases, seed=123),
            build_transfer_rounds(cases, seed=124),
        )

    def test_iterations_are_rounds_not_sessions(self) -> None:
        cases = [
            {"case_id": "case-a", "iterations": "3"},
            {"case_id": "case-b", "iterations": "2"},
        ]
        rounds = build_transfer_rounds(cases, seed=123)
        self.assertEqual(len(rounds), 5)
        self.assertEqual(
            sorted((item.case_id, item.round_index) for item in rounds),
            [
                ("case-a", 1), ("case-a", 2), ("case-a", 3),
                ("case-b", 1), ("case-b", 2),
            ],
        )

    def test_every_round_contains_each_size_and_direction_once(self) -> None:
        operations = operations_for_round(123, "case-a", 1)
        self.assertEqual(len(operations), 6)
        self.assertEqual(
            {(item.direction, item.payload_bytes) for item in operations},
            {
                (direction, size)
                for size in PAYLOAD_SIZES
                for direction in ("server_to_device", "device_to_server")
            },
        )

    def test_payload_hash_is_streaming_and_deterministic(self) -> None:
        import hashlib

        payload = payload_bytes(1234, 1024)
        self.assertEqual(payload_sha256(1234, 1024), hashlib.sha256(payload).hexdigest())

    def test_mqtt_remaining_length_supports_100_kib(self) -> None:
        encoded = encode_remaining_length(102_421)
        value = 0
        multiplier = 1
        for digit in encoded:
            value += (digit & 0x7F) * multiplier
            multiplier *= 128
        self.assertEqual(value, 102_421)
        header = mqtt_publish_header("bench/down", 7, 100 * 1024)
        self.assertEqual(header[0], 0x32)
        self.assertLess(len(header), 32)


if __name__ == "__main__":
    unittest.main()
