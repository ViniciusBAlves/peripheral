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
    payload_byte,
    payload_slice,
    payload_sha256,
    timeout_for_payload,
)
from run_benchmarks import parse_args  # noqa: E402


class TransferBenchmarkTests(unittest.TestCase):
    def test_power_profiler_is_opt_in_without_negative_flag(self) -> None:
        cases = BENCHMARKING / "cases" / "simple_cases.csv"
        self.assertFalse(parse_args(["--cases", str(cases)]).power_profiler)
        self.assertTrue(
            parse_args(["--cases", str(cases), "--power-profiler"]).power_profiler
        )
        with self.assertRaises(SystemExit):
            parse_args(["--cases", str(cases), "--no-power-profiler"])

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

    def test_iterations_share_one_connection_per_case(self) -> None:
        cases = [
            {"case_id": "case-a", "iterations": "3"},
            {"case_id": "case-b", "iterations": "2"},
        ]
        rounds = build_transfer_rounds(cases, seed=123)
        self.assertEqual(len(rounds), 2)
        self.assertEqual(
            sorted((item.case_id, len(item.operations)) for item in rounds),
            [("case-a", 18), ("case-b", 12)],
        )
        for item in rounds:
            iterations = 3 if item.case_id == "case-a" else 2
            self.assertEqual(
                {operation.iteration for operation in item.operations},
                set(range(1, iterations + 1)),
            )
            for iteration in range(1, iterations + 1):
                repeated = {
                    (operation.direction, operation.payload_bytes)
                    for operation in item.operations
                    if operation.iteration == iteration
                }
                self.assertEqual(repeated, {
                    (direction, size)
                    for size in PAYLOAD_SIZES
                    for direction in ("server_to_device", "device_to_server")
                })

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

    def test_periodic_payload_generation_matches_byte_formula(self) -> None:
        for seed in (0, 1234, 0xFFFFFFFF):
            for offset, size in ((0, 1024), (65500, 1000), (131071, 4097)):
                expected = bytes(
                    payload_byte(seed, index)
                    for index in range(offset, offset + size)
                )
                self.assertEqual(payload_slice(seed, offset, size), expected)

    def test_mqtt_remaining_length_supports_16_kib(self) -> None:
        encoded = encode_remaining_length(16 * 1024 + 21)
        value = 0
        multiplier = 1
        for digit in encoded:
            value += (digit & 0x7F) * multiplier
            multiplier *= 128
        self.assertEqual(value, 16 * 1024 + 21)
        header = mqtt_publish_header("bench/down", 7, 16 * 1024)
        self.assertEqual(header[0], 0x32)
        self.assertLess(len(header), 32)

    def test_transfer_payloads_and_deadlines(self) -> None:
        self.assertEqual(PAYLOAD_SIZES, (128, 1024, 16 * 1024))
        for size in PAYLOAD_SIZES:
            self.assertEqual(timeout_for_payload(size), 30.0)


if __name__ == "__main__":
    unittest.main()
