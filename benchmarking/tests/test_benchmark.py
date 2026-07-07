from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarklib.metrics import parse_bench_line
from benchmarklib.certificates import write_case_configs
from benchmarklib.gateway import PiGateway
from benchmarklib.scheduler import build_jobs
from benchmarklib.server_backends import server_backend_for_case
from generate_cases import build_cases
from run_benchmarks import (
    ATTEMPT_FIELDS,
    client_kex_metric_keys,
    classify_gateway_start_failure,
    load_config,
    normalize_ble_addr,
    parse_args,
    needs_large_rsa_firmware,
    resolve_pi_workdir,
    resolve_serial_device,
    read_checkpoint,
    run_job,
    summarize,
    timeout_for_case,
    wait_for_result,
    write_checkpoint,
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
        normal = {
            "case_id": "normal",
            "warmup_iterations": "1",
            "iterations": "2",
            "expected_support": "required",
        }
        unsupported = [
            {
                "case_id": f"unsupported_{index}",
                "warmup_iterations": "1",
                "iterations": "2",
                "expected_support": "known_unsupported",
            }
            for index in range(2)
        ]
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

    def test_hash_based_signatures_are_generated_as_cases(self) -> None:
        cases = build_cases(1, 0, True)
        signatures = {
            case["cert_sig_alg"]: case
            for case in cases
            if case["cert_sig_alg"] in {"LMS-HSS-L2-H10-W4", "XMSS-SHA2_20_256"}
        }
        self.assertEqual(set(signatures), {"LMS-HSS-L2-H10-W4", "XMSS-SHA2_20_256"})
        self.assertTrue(all(
            case["expected_support"] == "required"
            for case in signatures.values()
        ))
        self.assertTrue(all(
            "CertificateVerify uses ECDSA" in case["notes"]
            for case in signatures.values()
        ))

    def test_config_supplies_hardware_defaults_and_cli_overrides(self) -> None:
        config = load_config(ROOT / "config.json")
        args = parse_args(["--cases", "cases.csv"])
        self.assertEqual(
            args.serial_device,
            resolve_serial_device(config["serial-device"]),
        )
        self.assertEqual(args.pi_host, config["pi-host"])
        self.assertEqual(args.ble_addr, normalize_ble_addr(config["ble-addr"]))
        self.assertEqual(args.mlkem_backend, "pqm4-m4fstack")
        self.assertEqual(args.server_backend, "auto")

        overridden = parse_args([
            "--cases", "cases.csv", "--serial-device", "/dev/ttyUSB9",
            "--server-backend", "wolfssl",
        ])
        self.assertEqual(overridden.serial_device, "/dev/ttyUSB9")
        self.assertEqual(overridden.server_backend, "wolfssl")

    def test_resume_cli_does_not_require_cases(self) -> None:
        args = parse_args(["--resume", "run-123"])
        self.assertEqual(args.resume, "run-123")
        self.assertIsNone(args.cases)

    def test_checkpoint_advances_only_to_committed_execution(self) -> None:
        job = build_jobs(
            build_cases(1, 0, True)[:1],
            seed=123,
            sessions_per_case=1,
        )[0]
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            write_checkpoint(
                run_dir,
                execution_order=3,
                total_jobs=7,
                job=job,
            )
            checkpoint = read_checkpoint(run_dir)

        self.assertEqual(checkpoint["last_completed_execution_order"], 3)
        self.assertEqual(checkpoint["next_execution_order"], 4)
        self.assertEqual(checkpoint["case_id"], job.case_id)
        self.assertEqual(checkpoint["status"], "running")

    def test_placeholder_ble_addr_enables_name_discovery(self) -> None:
        self.assertEqual(normalize_ble_addr("00:00:00:00:00:00"), "")
        self.assertEqual(normalize_ble_addr("00.00.00.00.00"), "")
        self.assertEqual(normalize_ble_addr("000000000000"), "")
        self.assertEqual(
            normalize_ble_addr("F9:79:AE:2A:9A:1E"),
            "F9:79:AE:2A:9A:1E",
        )

    def test_gateway_start_failure_is_classified_from_bridge_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log = Path(tmpdir) / "gateway.log"
            log.write_text("[-] L2CAP Channel failed to open: timed out\n")
            final = {
                "status": "fail",
                "stage": "gateway_start",
                "error": "CalledProcessError",
            }
            classified = classify_gateway_start_failure(log, final)
        self.assertEqual(classified["stage"], "ble_l2cap_ready_timeout")

    def test_wait_for_result_fails_fast_on_fatal_server_log(self) -> None:
        class QuietSerial:
            def readline(self) -> bytes:
                return b""

        with tempfile.TemporaryDirectory() as tmpdir:
            result = wait_for_result(
                QuietSerial(),
                Path(tmpdir) / "board.log",
                timeout=30.0,
                fatal_detector=lambda: "OpenSSL Error[0]: tlsv1 alert unknown ca",
            )

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["stage"], "server_certificate_trust")
        self.assertEqual(result["error"], "fatal_server_log")
        self.assertEqual(result["fatal"], "1")
        self.assertIn("unknown ca", result["fatal_message"])

    def test_server_certificate_trust_failure_does_not_retry(self) -> None:
        class QuietSerial:
            name = "fake-serial"

            def reset_input_buffer(self) -> None:
                pass

            def readline(self) -> bytes:
                return b""

        class FakeGateway(PiGateway):
            def __init__(self) -> None:
                super().__init__("pi", "/remote")
                self.starts = 0
                self.workdir = "/remote"

            def start_session(self, **kwargs):  # type: ignore[no-untyped-def]
                self.starts += 1

            def stop_session(self, log, *, reset_adapter=False):  # type: ignore[no-untyped-def]
                pass

            def collect_session_logs(self, case_id, broker_log, gateway_log, log):  # type: ignore[no-untyped-def]
                broker_log.write_text("tlsv1 alert unknown ca\n")
                gateway_log.write_text("")

            def remote_file_contains(self, path, patterns):  # type: ignore[no-untyped-def]
                return "tlsv1 alert unknown ca"

        case = {
            "case_id": "ecdhe_p_256__ecdsa_p_256",
            "kex_group": "ECDHE-P-256",
            "kex_nist_level": "1",
            "kex_public_key_bytes": "65",
            "kex_ciphertext_bytes": "65",
            "kex_shared_secret_bytes": "32",
            "cert_sig_alg": "ECDSA-P-256",
            "sig_nist_level": "1",
            "sig_public_key_bytes": "65",
            "sig_private_key_bytes": "32",
            "sig_signature_bytes": "64",
            "certificate_verify_alg": "ECDSA-P-256",
        }
        args = type("Args", (), {
            "attempt_timeout_sec": 30.0,
            "reconnect_retries": 3,
            "reconnect_delay_sec": 0.0,
            "ble_addr": "",
            "ble_name": "PQC52840",
            "ble_addr_type": "random",
            "psm": "0x0080",
            "mtu": 672,
            "pi_adapter": "hci0",
            "disable_pi_wifi": True,
            "gateway_ready_timeout_sec": 1.0,
            "board_rearm_timeout_sec": 0.0,
        })()

        with tempfile.TemporaryDirectory() as tmpdir:
            gateway = FakeGateway()
            row = run_job(
                build_jobs([{**case, "warmup_iterations": "0", "iterations": "1"}],
                           seed=1, sessions_per_case=1)[0],
                case,
                Path(tmpdir),
                "/remote/cases/ecdhe_p_256__ecdsa_p_256",
                "openssl-mosquitto",
                gateway,
                QuietSerial(),
                args,
                attempt_index=1,
            )

        self.assertEqual(row["status"], "fail")
        self.assertEqual(row["reconnect_count"], 0)
        self.assertEqual(row["message"], "tlsv1 alert unknown ca")
        self.assertEqual(gateway.starts, 1)

    def test_openssl_server_requests_board_client_signature_algorithm(self) -> None:
        case = {
            "kex_group": "ECDHE-P-521",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir)
            write_case_configs(case, output)
            openssl_config = (output / "openssl.cnf").read_text()

        self.assertIn("Groups = P-521\n", openssl_config)
        self.assertIn("ClientSignatureAlgorithms = ECDSA+SHA256\n", openssl_config)
        self.assertNotIn("MaxSendFragment", openssl_config)

    def test_slh_openssl_server_uses_smaller_tls_records(self) -> None:
        case = {
            "kex_group": "ECDHE-P-521",
            "cert_sig_alg": "SLH-DSA-SHAKE-256s",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir)
            write_case_configs(case, output)
            openssl_config = (output / "openssl.cnf").read_text()

        self.assertIn("Groups = P-521\n", openssl_config)
        self.assertIn("MaxSendFragment = 2048\n", openssl_config)

    def test_server_backend_policy_routes_hash_based_signatures(self) -> None:
        classic = {"cert_sig_alg": "ECDSA-P-256"}
        lms = {"cert_sig_alg": "LMS-HSS-L2-H10-W4"}
        xmss = {"cert_sig_alg": "XMSS-SHA2_20_256"}
        slh = {"cert_sig_alg": "SLH-DSA-SHAKE-256s"}

        self.assertEqual(
            server_backend_for_case(classic, "auto"), "openssl-mosquitto"
        )
        self.assertEqual(server_backend_for_case(lms, "auto"), "wolfssl")
        self.assertEqual(server_backend_for_case(xmss, "auto"), "wolfssl")
        self.assertEqual(server_backend_for_case(slh, "auto"), "openssl-mosquitto")
        self.assertEqual(server_backend_for_case(classic, "wolfssl"), "wolfssl")
        self.assertEqual(
            server_backend_for_case(classic, "openssl-mosquitto"),
            "openssl-mosquitto",
        )
        self.assertIsNone(server_backend_for_case(lms, "openssl-mosquitto"))
        self.assertIsNone(server_backend_for_case(xmss, "openssl-mosquitto"))
        self.assertEqual(
            server_backend_for_case(slh, "openssl-mosquitto"),
            "openssl-mosquitto",
        )

    def test_rsa_pss_uses_fast_math_firmware(self) -> None:
        self.assertFalse(needs_large_rsa_firmware({"cert_sig_alg": "RSA-PSS-3072"}))
        self.assertFalse(needs_large_rsa_firmware({"cert_sig_alg": "RSA-PSS-7680"}))
        self.assertFalse(needs_large_rsa_firmware({"cert_sig_alg": "RSA-PSS-15360"}))

    def test_structured_metric_parser(self) -> None:
        parsed = parse_bench_line(
            "[BENCH_RESULT] status=success raw_handshake_ms=12.5 mqtt_connect_ms=3"
        )
        self.assertEqual(
            parsed,
            ("RESULT", {"status": "success", "raw_handshake_ms": "12.5",
                        "mqtt_connect_ms": "3"}),
        )

    def test_client_kex_total_uses_only_selected_group_components(self) -> None:
        mlkem = {"kex_group": "MLKEM512"}
        hybrid = {"kex_group": "X25519MLKEM768"}
        classical = {"kex_group": "ECDHE-P-256"}
        self.assertNotIn(
            "classical_kex_keygen_us", client_kex_metric_keys(mlkem)
        )
        self.assertIn(
            "classical_kex_keygen_us", client_kex_metric_keys(hybrid)
        )
        self.assertNotIn("kem_keygen_us", client_kex_metric_keys(classical))

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
            "client_icache_hits": "900",
            "client_icache_misses": "100",
            "client_icache_requests": "1000",
            "client_icache_hit_percent": "90.0000",
            "client_icache_miss_percent": "10.0000",
            "client_memory_access_counters_supported": "0",
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
        self.assertEqual(summary["mean_client_icache_hits"], "900.000")
        self.assertEqual(summary["mean_client_icache_hit_percent"], "90.0000")
        self.assertEqual(
            summary["client_memory_access_counters_supported"], "0"
        )
        self.assertEqual(summary["firmware_flash_used_bytes"], "600000")
        self.assertEqual(summary["max_thread_stack_peak_percent"], "72.50")

    def test_heavier_signatures_receive_longer_timeouts(self) -> None:
        classic = {"kex_group": "ECDHE-P-256", "cert_sig_alg": "ECDSA-P-256"}
        hybrid = {
            "kex_group": "X25519MLKEM768",
            "cert_sig_alg": "SLH-DSA-SHAKE-256s",
        }
        self.assertEqual(timeout_for_case(classic, None), 60.0)
        self.assertEqual(timeout_for_case(hybrid, None), 210.0)
        self.assertEqual(
            timeout_for_case({"kex_group": "ECDHE-P-256", "cert_sig_alg": "LMS-HSS-L2-H10-W4"}, None),
            180.0,
        )
        self.assertEqual(
            timeout_for_case({"kex_group": "ECDHE-P-256", "cert_sig_alg": "XMSS-SHA2_20_256"}, None),
            210.0,
        )
        self.assertEqual(timeout_for_case(hybrid, 12.0), 12.0)

    def test_gateway_start_does_not_evict_bluez_cache(self) -> None:
        class FakeGateway(PiGateway):
            def __init__(self) -> None:
                super().__init__("pi", "/remote")
                self.commands: list[str] = []

            def command(self, script, log, *, check=True):  # type: ignore[no-untyped-def]
                self.commands.append(script)
                return None

        gateway = FakeGateway()
        with tempfile.TemporaryDirectory() as tmp:
            gateway.start_session(
                case_id="case",
                remote_case_dir="/remote/cases/case",
                ble_addr="",
                ble_name="PQC52840",
                ble_addr_type="random",
                psm="0x0080",
                mtu=672,
                adapter="hci0",
                disable_wifi=True,
                ready_timeout=1,
                log=Path(tmp) / "gateway.log",
            )
        launch = next(command for command in gateway.commands if "--name PQC52840" in command)
        self.assertNotIn("--forget-cache", launch)
        self.assertNotIn("--addr ", launch)
        self.assertIn("--disable-wifi", launch)
        self.assertIn("--name PQC52840", launch)

    def test_gateway_command_creates_log_parent(self) -> None:
        class TrueGateway(PiGateway):
            def ssh_base(self) -> list[str]:
                return ["true"]

        gateway = TrueGateway("pi", "/remote")
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "missing" / "gateway-control.log"
            gateway.command("ignored", log)
            self.assertTrue(log.exists())


if __name__ == "__main__":
    unittest.main()
