from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarklib.metrics import parse_bench_line
from benchmarklib.scheduler import build_jobs
from generate_cases import build_cases
from run_benchmarks import (
    ATTEMPT_FIELDS,
    load_config,
    parse_args,
    resolve_pi_workdir,
    resolve_serial_device,
    summarize,
    timeout_for_case,
)


class BenchmarkTests(unittest.TestCase):
    def test_schedule_is_reproducible(self) -> None:
        cases = build_cases(2, 1, True)[:2]
        first = build_jobs(cases, seed=123, sessions_per_case=2)
        second = build_jobs(cases, seed=123, sessions_per_case=2)
        self.assertEqual(first, second)
        self.assertNotEqual(first, build_jobs(cases, seed=124, sessions_per_case=2))

    def test_each_attempt_is_an_independent_job(self) -> None:
        cases = build_cases(2, 1, True)[:1]
        jobs = build_jobs(cases, seed=123, sessions_per_case=2)
        self.assertEqual(len(jobs), 6)
        self.assertEqual(sum(job.warmup for job in jobs), 2)

    def test_known_unsupported_cases_are_grouped_at_schedule_end(self) -> None:
        cases = build_cases(2, 1, False)
        normal = next(
            case for case in cases
            if case["expected_support"] != "known_unsupported"
        )
        unsupported = [
            case for case in cases
            if case["expected_support"] == "known_unsupported"
        ][:2]
        jobs = build_jobs(
            [normal, *unsupported], seed=123, sessions_per_case=2
        )
        normal_count = 2 * (
            int(normal["warmup_iterations"]) + int(normal["iterations"])
        )
        self.assertTrue(all(
            job.case_id == normal["case_id"] for job in jobs[:normal_count]
        ))
        deferred_ids = [job.case_id for job in jobs[normal_count:]]
        for case in unsupported:
            positions = [
                index for index, case_id in enumerate(deferred_ids)
                if case_id == case["case_id"]
            ]
            self.assertEqual(
                positions,
                list(range(min(positions), max(positions) + 1)),
            )

    def test_config_supplies_hardware_defaults_and_cli_overrides(self) -> None:
        config = load_config(ROOT / "config.json")
        args = parse_args(["--cases", "cases.csv"])
        self.assertEqual(
            args.serial_device,
            resolve_serial_device(config["serial-device"]),
        )
        self.assertEqual(args.pi_host, config["pi-host"])
        self.assertEqual(args.ble_addr, config["ble-addr"])
        self.assertEqual(args.mlkem_backend, "pqm4-m4fstack")
        self.assertTrue(args.reflash_known_unsupported_rsa)

        overridden = parse_args([
            "--cases", "cases.csv", "--serial-device", "/dev/ttyUSB9",
            "--no-reflash-known-unsupported-rsa",
        ])
        self.assertEqual(overridden.serial_device, "/dev/ttyUSB9")
        self.assertFalse(overridden.reflash_known_unsupported_rsa)

    def test_structured_metric_parser(self) -> None:
        parsed = parse_bench_line(
            "[BENCH_RESULT] status=success raw_handshake_ms=12.5 mqtt_connect_ms=3"
        )
        self.assertEqual(
            parsed,
            ("RESULT", {"status": "success", "raw_handshake_ms": "12.5",
                        "mqtt_connect_ms": "3"}),
        )

    def test_hardware_metrics_are_aggregated(self) -> None:
        case = build_cases(1, 0, True)[0]
        attempt = {field: "" for field in ATTEMPT_FIELDS}
        attempt.update({
            "warmup": 0,
            "status": "success",
            "raw_handshake_ms": "100",
            "client_cpu_ms": "40",
            "client_cpu_usage_percent": "40.00",
            "system_cpu_usage_percent": "55.00",
            "client_heap_peak_bytes": "4096",
            "firmware_flash_used_bytes": "600000",
            "firmware_flash_capacity_bytes": "1048576",
            "firmware_static_ram_used_bytes": "250000",
            "firmware_ram_capacity_bytes": "262144",
            "thread_stack_used_bytes": "5000",
            "thread_stack_capacity_bytes": "12000",
            "thread_stack_peak_percent": "72.50",
            "l2cap_tx_retries": "2",
            "l2cap_tx_wait_ms": "20.5",
            "l2cap_rx_overflows": "0",
        })
        summary = summarize(case, [attempt])
        self.assertEqual(summary["mean_client_cpu_usage_percent"], "40.000")
        self.assertEqual(summary["mean_system_cpu_usage_percent"], "55.000")
        self.assertEqual(summary["firmware_flash_used_bytes"], "600000")
        self.assertEqual(summary["max_thread_stack_peak_percent"], "72.50")

    def test_pi_workdir_follows_ssh_user(self) -> None:
        self.assertEqual(
            resolve_pi_workdir("thiago@10.12.194.1", ""),
            "/home/thiago/peripheral-benchmark",
        )

    def test_heavier_signatures_receive_longer_timeouts(self) -> None:
        classic = {"kex_group": "ECDHE-P-256", "cert_sig_alg": "ECDSA-P-256"}
        hybrid = {
            "kex_group": "X25519MLKEM768",
            "cert_sig_alg": "SLH-DSA-SHAKE-256s",
        }
        self.assertEqual(timeout_for_case(classic, None), 60.0)
        self.assertEqual(timeout_for_case(hybrid, None), 210.0)
        self.assertEqual(timeout_for_case(hybrid, 12.0), 12.0)


if __name__ == "__main__":
    unittest.main()
