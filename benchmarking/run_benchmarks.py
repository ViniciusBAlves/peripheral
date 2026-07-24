#!/usr/bin/env python3
"""Run seeded TLS/MQTT benchmarks over raw BLE L2CAP through a Raspberry Pi."""

from __future__ import annotations

import argparse
import atexit
import csv
import json
import os
import random
import re
import shutil
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from benchmarklib.algorithms import KEMS_BY_NAME, SIGNATURES_BY_NAME, slug
from benchmarklib.certificates import (
    ensure_image,
    generate_client_identity,
    generate_server_case,
    generate_universal_header,
    write_case_configs,
)
from benchmarklib.firmware import build as build_firmware
from benchmarklib.firmware import ensure_pqm4
from benchmarklib.firmware import flash as flash_firmware
from benchmarklib.firmware import reset as reset_firmware
from benchmarklib.gateway import PiGateway
from benchmarklib.metrics import aggregate, number, parse_bench_line
from benchmarklib.power_profiler import (
    PowerProfilerCapture,
    PowerProfilerSession,
)
from benchmarklib.scheduler import SessionJob, build_jobs
from benchmarklib.server_backends import (
    SERVER_BACKEND_CHOICES,
    server_backend_for_case,
    unsupported_backend_reason,
)
from generate_cases import FIELDS as INPUT_FIELDS


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
WORK = ROOT / "work"
DEFAULT_CONFIG = ROOT / "config.json"
DEFAULT_NCS_VERSION = "v3.3.0"
POWER_WINDOWS = (
    "client_kem", "client_signature", "handshake", "total_execution",
)
POWER_METRICS = (
    "duration_ms", "charge_uc", "energy_uj", "avg_current_ua",
    "peak_current_ua",
)
POWER_ATTEMPT_FIELDS = [
    f"{window}_{metric}"
    for window in POWER_WINDOWS for metric in POWER_METRICS
]
FATAL_SERVER_LOG_PATTERNS = (
    r"unknown ca",
    r"certificate verify failed",
)

ATTEMPT_FIELDS = [
    "attempt_index", "schedule_index", "session", "attempt_in_session", "warmup",
    "status", "reconnect_count", "mlkem_backend", "rsa_profile",
    "kex_group", "kex_nist_level",
    "kex_public_key_bytes", "kex_ciphertext_bytes", "kex_shared_secret_bytes",
    "cert_sig_alg", "sig_nist_level", "sig_public_key_bytes",
    "sig_private_key_bytes", "sig_signature_bytes", "certificate_verify_alg",
    "ble_l2cap_connect_ms", "gateway_tcp_connect_ms", "tls_setup_ms",
    "raw_handshake_ms", "mqtt_connect_ms", "full_connect_ms", "end_to_end_ms",
    "communication_overhead_ms", "kem_keygen_ms", "kem_encapsulation_ms",
    "kem_decapsulation_ms", "classical_kex_keygen_ms",
    "classical_kex_shared_secret_ms", "kem_client_total_ms",
    "certificate_signature_verify_ms", "x509_chain_signature_verify_ms",
    "tls_certificate_verify_signature_verify_ms",
    "mtls_signature_generate_ms", "client_signature_total_ms",
    "server_kem_encapsulation_ms", "server_certificate_verify_sign_ms",
    "l2cap_tx_packets", "l2cap_tx_bytes", "l2cap_rx_packets", "l2cap_rx_bytes",
    "l2cap_tx_retries", "l2cap_tx_wait_ms", "l2cap_rx_overflows",
    "client_cpu_cycles", "client_cycle_hz", "client_cpu_ms",
    "client_cpu_usage_percent", "system_cpu_usage_percent",
    "client_icache_hits", "client_icache_misses", "client_icache_requests",
    "client_icache_hit_percent", "client_icache_miss_percent",
    "client_memory_access_counters_supported",
    "client_heap_current_bytes", "client_heap_peak_bytes",
    "client_heap_free_bytes", "client_heap_capacity_bytes",
    "client_heap_peak_usage_percent",
    "firmware_flash_used_bytes", "firmware_flash_capacity_bytes",
    "firmware_flash_usage_percent",
    "firmware_static_ram_used_bytes", "firmware_ram_capacity_bytes",
    "firmware_static_ram_usage_percent",
    "thread_stack_used_bytes", "thread_stack_capacity_bytes",
    "thread_stack_peak_percent",
    "l2cap_rx_ring_peak_bytes", "l2cap_rx_ring_capacity_bytes",
    "l2cap_rx_ring_peak_percent",
    *POWER_ATTEMPT_FIELDS,
    "power_status", "power_profiler_sample_count",
    "power_profiler_window_count", "power_profiler_vdd_mv",
    "power_profiler_output_samples_per_second",
    "error_code", "message",
]

SUMMARY_FIELDS = [
    "case_id", "mlkem_backend", "rsa_profile", "kex_group", "kex_nist_level",
    "kex_public_key_bytes",
    "kex_ciphertext_bytes", "kex_shared_secret_bytes", "cert_sig_alg",
    "sig_nist_level", "sig_public_key_bytes", "sig_private_key_bytes",
    "sig_signature_bytes", "certificate_verify_alg", "status",
    "success_count", "fail_count", "timeout_count", "unsupported_count",
    "mean_raw_handshake_ms", "median_raw_handshake_ms", "p95_raw_handshake_ms",
    "min_raw_handshake_ms", "max_raw_handshake_ms", "stddev_raw_handshake_ms",
    "handshake_throughput_hps", "mean_mqtt_connect_ms", "mean_full_connect_ms",
    "mean_end_to_end_ms", "connections_per_second", "mean_client_cpu_ms",
    "mean_client_cpu_usage_percent", "mean_system_cpu_usage_percent",
    "mean_client_icache_hits", "mean_client_icache_misses",
    "mean_client_icache_requests", "mean_client_icache_hit_percent",
    "mean_client_icache_miss_percent",
    "client_memory_access_counters_supported",
    "max_client_heap_peak_bytes", "min_client_heap_free_bytes",
    "client_heap_capacity_bytes", "max_client_heap_peak_usage_percent",
    "mean_communication_overhead_ms",
    "mean_kem_keygen_ms", "mean_kem_encapsulation_ms",
    "mean_kem_decapsulation_ms", "mean_classical_kex_keygen_ms",
    "mean_classical_kex_shared_secret_ms", "mean_kem_client_total_ms",
    "mean_certificate_signature_verify_ms",
    "mean_x509_chain_signature_verify_ms",
    "mean_tls_certificate_verify_signature_verify_ms",
    "mean_mtls_signature_generate_ms", "mean_client_signature_total_ms",
    "mean_server_kem_encapsulation_ms",
    "mean_server_certificate_verify_sign_ms",
    "mean_l2cap_tx_packets", "mean_l2cap_tx_bytes",
    "mean_l2cap_rx_packets", "mean_l2cap_rx_bytes",
    "mean_l2cap_tx_retries", "mean_l2cap_tx_wait_ms",
    "total_l2cap_rx_overflows",
    "firmware_flash_used_bytes", "firmware_flash_capacity_bytes",
    "firmware_flash_usage_percent",
    "firmware_static_ram_used_bytes", "firmware_ram_capacity_bytes",
    "firmware_static_ram_usage_percent",
    "max_thread_stack_used_bytes", "thread_stack_capacity_bytes",
    "max_thread_stack_peak_percent",
    "max_l2cap_rx_ring_peak_bytes", "l2cap_rx_ring_capacity_bytes",
    "max_l2cap_rx_ring_peak_percent",
    *[
        f"mean_{window}_{metric}"
        for window in POWER_WINDOWS
        for metric in ("duration_ms", "charge_uc", "energy_uj", "avg_current_ua")
    ],
    *[f"max_{window}_peak_current_ua" for window in POWER_WINDOWS],
]


def write_csv(path: Path, fields: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def read_cases(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as stream:
        reader = csv.DictReader(stream)
        missing = set(INPUT_FIELDS) - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"case CSV is missing fields: {', '.join(sorted(missing))}")
        rows = [dict(row) for row in reader if row.get("enabled", "").lower() in {"1", "true", "yes"}]
    seen: set[str] = set()
    for row in rows:
        case_id = row["case_id"]
        if not case_id or case_id in seen:
            raise ValueError(f"empty or duplicate case_id: {case_id!r}")
        seen.add(case_id)
        if row["kex_group"] not in KEMS_BY_NAME:
            raise ValueError(f"{case_id}: unknown KEM {row['kex_group']}")
        if row["cert_sig_alg"] not in SIGNATURES_BY_NAME:
            raise ValueError(f"{case_id}: unknown signature {row['cert_sig_alg']}")
        if int(row["iterations"]) < 1 or int(row["warmup_iterations"]) < 0:
            raise ValueError(f"{case_id}: invalid iteration counts")
    if not rows:
        raise ValueError("case CSV has no enabled cases")
    return rows


def resolve_resume_dir(value: str) -> Path:
    path = Path(value).expanduser()
    if path.is_dir():
        return path.resolve()
    candidate = RESULTS / value
    if candidate.is_dir():
        return candidate.resolve()
    raise FileNotFoundError(f"benchmark run to resume was not found: {value}")


def load_manifest_cases(run_dir: Path) -> list[dict[str, str]]:
    with (run_dir / "run_manifest.csv").open(newline="") as stream:
        rows = sorted(
            csv.DictReader(stream),
            key=lambda row: int(row["sequence"]),
        )
    return [{field: row[field] for field in INPUT_FIELDS} for row in rows]


def load_session_jobs(run_dir: Path) -> list[SessionJob]:
    with (run_dir / "session_manifest.csv").open(newline="") as stream:
        rows = sorted(
            csv.DictReader(stream),
            key=lambda row: int(row["execution_order"]),
        )
    return [
        SessionJob(
            sequence=int(row["source_sequence"]),
            case_id=row["case_id"],
            session=int(row["session"]),
            attempt_in_session=int(row["attempt_in_session"]),
            warmup=int(row["warmup"]),
            measured_index=int(row["measured_index"]),
        )
        for row in rows
    ]


def load_attempts(
    case_dirs: dict[str, Path],
) -> dict[str, list[dict[str, object]]]:
    attempts: dict[str, list[dict[str, object]]] = defaultdict(list)
    for case_id, directory in case_dirs.items():
        path = directory / "attempts.csv"
        if not path.exists():
            continue
        with path.open(newline="") as stream:
            attempts[case_id].extend(dict(row) for row in csv.DictReader(stream))
    return attempts


def read_checkpoint(run_dir: Path) -> dict[str, object]:
    path = run_dir / "checkpoint.json"
    if not path.exists():
        raise FileNotFoundError(
            f"{run_dir} has no checkpoint.json; only checkpoint-enabled runs "
            "can be resumed safely"
        )
    return json.loads(path.read_text())


def write_checkpoint(
    run_dir: Path,
    *,
    execution_order: int,
    total_jobs: int,
    job: SessionJob,
) -> None:
    path = run_dir / "checkpoint.json"
    temporary = path.with_suffix(".json.tmp")
    payload = {
        "version": 1,
        "status": "complete" if execution_order >= total_jobs else "running",
        "last_completed_execution_order": execution_order,
        "next_execution_order": (
            execution_order + 1 if execution_order < total_jobs else None
        ),
        "case_id": job.case_id,
        "session": job.session,
        "attempt_in_session": job.attempt_in_session,
        "updated_at": datetime.now().astimezone().isoformat(),
    }
    temporary.write_text(json.dumps(payload, indent=2) + "\n")
    temporary.replace(path)


def case_metadata(case: dict[str, str]) -> dict[str, str]:
    return {
        key: case[key] for key in (
            "kex_group", "kex_nist_level", "kex_public_key_bytes",
            "kex_ciphertext_bytes", "kex_shared_secret_bytes", "cert_sig_alg",
            "sig_nist_level", "sig_public_key_bytes", "sig_private_key_bytes",
            "sig_signature_bytes", "certificate_verify_alg",
        )
    }


def needs_large_rsa_firmware(case: dict[str, str]) -> bool:
    return False


def certificate_verify_profile(case: dict[str, str]) -> str:
    return case.get("certificate_verify_alg") or case["cert_sig_alg"]


def is_rsa_pss_case(case: dict[str, str]) -> bool:
    return bool(re.fullmatch(r"RSA-PSS-\d+", case["cert_sig_alg"]))


def parse_gateway_metrics(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(errors="replace").splitlines():
        parsed = parse_bench_line(line)
        if parsed and parsed[0] == "GATEWAY":
            values.update(parsed[1])
    return values


def parse_server_metrics(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(errors="replace").splitlines():
        parsed = parse_bench_line(line)
        if parsed and parsed[0] == "SERVER":
            values.update(parsed[1])
    return values


def microseconds_as_milliseconds(values: dict[str, str], key: str) -> str:
    value = number(values, key)
    return f"{value / 1000.0:.3f}" if value is not None else ""


def summed_microseconds_as_milliseconds(
    values: dict[str, str], keys: tuple[str, ...]
) -> str:
    parts = [number(values, key) for key in keys]
    present = [value for value in parts if value is not None]
    return f"{sum(present) / 1000.0:.3f}" if present else ""


def client_kex_metric_keys(case: dict[str, str]) -> tuple[str, ...]:
    mlkem = ("kem_keygen_us", "kem_encapsulation_us", "kem_decapsulation_us")
    classical = (
        "classical_kex_keygen_us",
        "classical_kex_shared_secret_us",
    )
    group = case["kex_group"]
    if group.startswith("MLKEM"):
        return mlkem
    if "MLKEM" in group:
        return (*mlkem, *classical)
    return classical

def usage_percent(values: dict[str, str], used_key: str, capacity_key: str) -> str:
    used = number(values, used_key)
    capacity = number(values, capacity_key)
    return f"{used * 100.0 / capacity:.2f}" if used is not None and capacity else ""


def wait_for_result(
    serial_port,
    board_log: Path,
    timeout: float,
    fatal_detector=None,
) -> dict[str, str]:
    deadline = time.monotonic() + timeout
    next_fatal_check = time.monotonic()

    def check_fatal_server_log() -> dict[str, str] | None:
        nonlocal next_fatal_check
        now = time.monotonic()
        if fatal_detector is None or now < next_fatal_check:
            return None
        fatal_line = fatal_detector()
        next_fatal_check = now + 1.0
        if not fatal_line:
            return None
        return {
            "status": "fail",
            "stage": "server_certificate_trust",
            "error": "fatal_server_log",
            "fatal": "1",
            "fatal_message": fatal_line,
        }

    with board_log.open("a") as stream:
        while time.monotonic() < deadline:
            fatal_result = check_fatal_server_log()
            if fatal_result is not None:
                return fatal_result
            raw = serial_port.readline()
            if not raw:
                continue
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            stream.write(line + "\n")
            stream.flush()
            parsed = parse_bench_line(line)
            if parsed and parsed[0] == "RESULT":
                return parsed[1]
    return {"status": "timeout", "stage": "serial_wait", "error": "timeout"}


def wait_for_board_ready(serial_port, board_log: Path, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    with board_log.open("a") as stream:
        while time.monotonic() < deadline:
            raw = serial_port.readline()
            if not raw:
                continue
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            stream.write(line + "\n")
            stream.flush()
            if line.startswith("[BENCH_READY]"):
                return
    raise TimeoutError(
        f"board did not print BENCH_READY on {serial_port.name} within {timeout:g}s"
    )


def timeout_for_case(case: dict[str, str], override: float | None) -> float:
    if override is not None:
        return override
    signature = case["cert_sig_alg"]
    if signature.startswith("SLH-DSA-SHAKE-256"):
        timeout = 180.0
    elif signature.startswith("SLH-DSA-SHAKE-192"):
        timeout = 120.0
    elif signature.startswith("SLH-DSA-SHAKE-128"):
        timeout = 75.0
    elif signature == "RSA-PSS-15360":
        timeout = 240.0
    elif signature == "RSA-PSS-7680":
        timeout = 120.0
    elif signature == "RSA-PSS-3072":
        timeout = 45.0
    elif signature == "LMS-HSS-L2-H10-W4":
        timeout = 180.0
    elif signature == "XMSS-SHA2_20_256":
        timeout = 210.0
    elif signature.startswith("ML-DSA"):
        timeout = 45.0
    else:
        timeout = 60.0
    group = case["kex_group"].upper()
    if "MLKEM1024" in group:
        timeout += 45.0
    elif "MLKEM768" in group:
        timeout += 30.0
    elif "MLKEM512" in group:
        timeout += 20.0
    return timeout


def classify_gateway_start_failure(
    gateway_log: Path,
    final: dict[str, str],
) -> dict[str, str]:
    if final.get("stage") != "gateway_start":
        return final
    try:
        text = gateway_log.read_text(errors="replace")
    except OSError:
        return final
    if "Device named" in text and "was not found" in text:
        final["stage"] = "ble_discovery"
    elif "L2CAP Channel failed to open" in text:
        if final.get("error") == "CalledProcessError":
            final["stage"] = "ble_l2cap_ready_timeout"
        else:
            final["stage"] = "ble_l2cap_connect"
    elif "TCP connect failed" in text:
        final["stage"] = "gateway_tcp_connect"
    return final


def run_job(
    job: SessionJob,
    case: dict[str, str],
    case_dir: Path,
    remote_case: str,
    server_backend: str,
    gateway: PiGateway,
    serial_port,
    args: argparse.Namespace,
    attempt_index: int,
) -> dict[str, object]:
    board_log = case_dir / "board.log"
    broker_log = case_dir / "broker.log"
    gateway_log = case_dir / "gateway.log"
    final: dict[str, str] = {}
    reconnect_count = 0
    attempt_timeout = timeout_for_case(case, args.attempt_timeout_sec)
    power_capture = None
    power_values: dict[str, object] = {}
    if getattr(args, "power_profiler", False):
        power_session = getattr(args, "power_profiler_session", None)
        power_capture = (
            power_session.capture()
            if power_session is not None
            else PowerProfilerCapture(
                args.power_profiler_serial_device,
                args.power_profiler_vdd_mv,
                args.power_profiler_output_samples_per_second,
            )
        )
        power_capture.start()
    try:
        for retry in range(args.reconnect_retries + 1):
            reconnect_count = retry
            serial_port.reset_input_buffer()
            try:
                gateway.start_session(
                case_id=case["case_id"],
                remote_case_dir=remote_case,
                ble_addr=args.ble_addr,
                ble_name=args.ble_name,
                ble_addr_type=args.ble_addr_type,
                psm=args.psm,
                mtu=args.mtu,
                adapter=args.pi_adapter,
                disable_wifi=args.disable_pi_wifi,
                ready_timeout=args.gateway_ready_timeout_sec,
                log=case_dir / "gateway-control.log",
                server_backend=server_backend,
                wolfssl_group=KEMS_BY_NAME[case["kex_group"]].wolfssl_group,
                )
                remote_broker_log = f"{gateway.workdir}/logs/{case['case_id']}.broker.log"
                final = wait_for_result(
                serial_port,
                board_log,
                attempt_timeout,
                fatal_detector=lambda: gateway.remote_file_contains(
                    remote_broker_log, FATAL_SERVER_LOG_PATTERNS
                ),
                )
            except Exception as error:
                final = {
                    "status": "fail",
                    "stage": "gateway_start",
                    "error": type(error).__name__,
                }
            finally:
                gateway.stop_session(
                    case_dir / "gateway-control.log", reset_adapter=False
                )
                gateway.collect_session_logs(
                    case["case_id"], broker_log, gateway_log,
                    case_dir / "gateway-control.log",
                )
                final = classify_gateway_start_failure(gateway_log, final)
                try:
                    wait_for_board_ready(
                        serial_port, board_log, args.board_rearm_timeout_sec
                    )
                except TimeoutError:
                    if final.get("fatal") != "1":
                        final = {
                            "status": "fail",
                            "stage": "board_rearm",
                            "error": "timeout",
                        }
            if final.get("status") == "success":
                break
            if final.get("fatal") == "1":
                break
            if retry < args.reconnect_retries:
                time.sleep(args.reconnect_delay_sec)
    finally:
        if power_capture is not None:
            power_values = power_capture.stop(
                case_dir / f"power_trace_{attempt_index:03d}.csv.gz"
            )

    gateway_values = parse_gateway_metrics(gateway_log)
    server_values = parse_server_metrics(broker_log)
    cpu_us = number(final, "client_cpu_us")
    client_cpu_usage_bp = number(final, "client_cpu_usage_bp")
    system_cpu_usage_bp = number(final, "system_cpu_usage_bp")
    stack_peak_bp = number(final, "thread_stack_peak_percent_bp")
    icache_hits = number(final, "client_icache_hits")
    icache_misses = number(final, "client_icache_misses")
    icache_requests = (
        icache_hits + icache_misses
        if icache_hits is not None and icache_misses is not None else None
    )
    status = final.get("status", "fail").lower()
    return {
        "attempt_index": attempt_index,
        "schedule_index": job.sequence,
        "session": job.session,
        "attempt_in_session": job.attempt_in_session,
        "warmup": job.warmup,
        "status": status,
        "reconnect_count": reconnect_count,
        **case_metadata(case),
        "ble_l2cap_connect_ms": gateway_values.get("ble_l2cap_connect_ms", ""),
        "gateway_tcp_connect_ms": gateway_values.get("gateway_tcp_connect_ms", ""),
        "tls_setup_ms": final.get("tls_setup_ms", ""),
        "raw_handshake_ms": final.get("raw_handshake_ms", ""),
        "mqtt_connect_ms": final.get("mqtt_connect_ms", ""),
        "full_connect_ms": final.get("full_connect_ms", ""),
        "end_to_end_ms": final.get("end_to_end_ms", ""),
        "communication_overhead_ms": microseconds_as_milliseconds(
            final, "communication_overhead_us"
        ),
        "kem_keygen_ms": microseconds_as_milliseconds(final, "kem_keygen_us"),
        "kem_encapsulation_ms": microseconds_as_milliseconds(
            final, "kem_encapsulation_us"
        ),
        "kem_decapsulation_ms": microseconds_as_milliseconds(
            final, "kem_decapsulation_us"
        ),
        "classical_kex_keygen_ms": microseconds_as_milliseconds(
            final, "classical_kex_keygen_us"
        ),
        "classical_kex_shared_secret_ms": microseconds_as_milliseconds(
            final, "classical_kex_shared_secret_us"
        ),
        "kem_client_total_ms": summed_microseconds_as_milliseconds(
            final, client_kex_metric_keys(case),
        ),
        "certificate_signature_verify_ms": microseconds_as_milliseconds(
            final, "certificate_signature_verify_us"
        ),
        "x509_chain_signature_verify_ms": microseconds_as_milliseconds(
            final, "certificate_signature_verify_us"
        ),
        "tls_certificate_verify_signature_verify_ms":
            microseconds_as_milliseconds(final, "tls_certificate_verify_us"),
        "mtls_signature_generate_ms": microseconds_as_milliseconds(
            final, "mtls_signature_generate_us"
        ),
        "client_signature_total_ms": summed_microseconds_as_milliseconds(
            final,
            (
                "certificate_signature_verify_us",
                "tls_certificate_verify_us",
                "mtls_signature_generate_us",
            ),
        ),
        "server_kem_encapsulation_ms": microseconds_as_milliseconds(
            server_values, "server_kem_encapsulation_us"
        ),
        "server_certificate_verify_sign_ms": microseconds_as_milliseconds(
            server_values, "server_certificate_verify_sign_us"
        ),
        "l2cap_tx_packets": final.get("l2cap_tx_packets", ""),
        "l2cap_tx_bytes": final.get("l2cap_tx_bytes", ""),
        "l2cap_rx_packets": final.get("l2cap_rx_packets", ""),
        "l2cap_rx_bytes": final.get("l2cap_rx_bytes", ""),
        "l2cap_tx_retries": final.get("l2cap_tx_retries", ""),
        "l2cap_tx_wait_ms": microseconds_as_milliseconds(
            final, "l2cap_tx_wait_us"
        ),
        "l2cap_rx_overflows": final.get("l2cap_rx_overflows", ""),
        "client_cpu_cycles": final.get("client_cpu_cycles", ""),
        "client_cycle_hz": final.get("client_cycle_hz", ""),
        "client_cpu_ms": f"{cpu_us / 1000.0:.3f}" if cpu_us is not None else "",
        "client_cpu_usage_percent": (
            f"{client_cpu_usage_bp / 100.0:.2f}"
            if client_cpu_usage_bp is not None else ""
        ),
        "system_cpu_usage_percent": (
            f"{system_cpu_usage_bp / 100.0:.2f}"
            if system_cpu_usage_bp is not None else ""
        ),
        "client_icache_hits": final.get("client_icache_hits", ""),
        "client_icache_misses": final.get("client_icache_misses", ""),
        "client_icache_requests": (
            f"{icache_requests:.0f}" if icache_requests is not None else ""
        ),
        "client_icache_hit_percent": (
            f"{100.0 * icache_hits / icache_requests:.4f}"
            if icache_requests else ""
        ),
        "client_icache_miss_percent": (
            f"{100.0 * icache_misses / icache_requests:.4f}"
            if icache_requests else ""
        ),
        "client_memory_access_counters_supported": final.get(
            "client_memory_access_counters_supported", "0"
        ),
        "client_heap_current_bytes": final.get("client_heap_current_bytes", ""),
        "client_heap_peak_bytes": final.get("client_heap_peak_bytes", ""),
        "client_heap_free_bytes": final.get("client_heap_free_bytes", ""),
        "client_heap_capacity_bytes": final.get("client_heap_capacity_bytes", ""),
        "client_heap_peak_usage_percent": usage_percent(
            final, "client_heap_peak_bytes", "client_heap_capacity_bytes"
        ),
        "firmware_flash_used_bytes": final.get("firmware_flash_used_bytes", ""),
        "firmware_flash_capacity_bytes": final.get(
            "firmware_flash_capacity_bytes", ""
        ),
        "firmware_flash_usage_percent": usage_percent(
            final, "firmware_flash_used_bytes", "firmware_flash_capacity_bytes"
        ),
        "firmware_static_ram_used_bytes": final.get(
            "firmware_static_ram_used_bytes", ""
        ),
        "firmware_ram_capacity_bytes": final.get(
            "firmware_ram_capacity_bytes", ""
        ),
        "firmware_static_ram_usage_percent": usage_percent(
            final, "firmware_static_ram_used_bytes", "firmware_ram_capacity_bytes"
        ),
        "thread_stack_used_bytes": final.get("thread_stack_used_bytes", ""),
        "thread_stack_capacity_bytes": final.get(
            "thread_stack_capacity_bytes", ""
        ),
        "thread_stack_peak_percent": (
            f"{stack_peak_bp / 100.0:.2f}" if stack_peak_bp is not None else ""
        ),
        "l2cap_rx_ring_peak_bytes": final.get(
            "l2cap_rx_ring_peak_bytes", ""
        ),
        "l2cap_rx_ring_capacity_bytes": final.get(
            "l2cap_rx_ring_capacity_bytes", ""
        ),
        "l2cap_rx_ring_peak_percent": usage_percent(
            final, "l2cap_rx_ring_peak_bytes", "l2cap_rx_ring_capacity_bytes"
        ),
        **power_values,
        "error_code": final.get("error", ""),
        "message": final.get("fatal_message", final.get("stage", "")),
        "_fatal": final.get("fatal", ""),
        "_fatal_message": final.get("fatal_message", ""),
    }


def summarize(case: dict[str, str], attempts: list[dict[str, object]]) -> dict[str, object]:
    measured = [row for row in attempts if not int(row["warmup"])]
    success = [row for row in measured if row["status"] == "success"]
    raw = [float(row["raw_handshake_ms"]) for row in success if row["raw_handshake_ms"] != ""]
    mqtt = [float(row["mqtt_connect_ms"]) for row in success if row["mqtt_connect_ms"] != ""]
    full = [float(row["full_connect_ms"]) for row in success if row["full_connect_ms"] != ""]
    end = [float(row["end_to_end_ms"]) for row in success if row["end_to_end_ms"] != ""]
    cpu = [float(row["client_cpu_ms"]) for row in success if row["client_cpu_ms"] != ""]
    heap = [int(row["client_heap_peak_bytes"]) for row in success if row["client_heap_peak_bytes"] != ""]

    def successful_numbers(field: str) -> list[float]:
        return [float(row[field]) for row in success if row[field] != ""]

    client_cpu_usage = successful_numbers("client_cpu_usage_percent")
    system_cpu_usage = successful_numbers("system_cpu_usage_percent")
    icache_hits = successful_numbers("client_icache_hits")
    icache_misses = successful_numbers("client_icache_misses")
    icache_requests = successful_numbers("client_icache_requests")
    icache_hit_percent = successful_numbers("client_icache_hit_percent")
    icache_miss_percent = successful_numbers("client_icache_miss_percent")
    communication = successful_numbers("communication_overhead_ms")
    keygen = successful_numbers("kem_keygen_ms")
    encapsulation = successful_numbers("kem_encapsulation_ms")
    decapsulation = successful_numbers("kem_decapsulation_ms")
    classical_keygen = successful_numbers("classical_kex_keygen_ms")
    classical_shared = successful_numbers("classical_kex_shared_secret_ms")
    kem_total = successful_numbers("kem_client_total_ms")
    cert_verify = successful_numbers("certificate_signature_verify_ms")
    x509_verify = successful_numbers("x509_chain_signature_verify_ms")
    tls_cert_verify = successful_numbers(
        "tls_certificate_verify_signature_verify_ms"
    )
    mtls_sign = successful_numbers("mtls_signature_generate_ms")
    signature_total = successful_numbers("client_signature_total_ms")
    server_encapsulation = successful_numbers("server_kem_encapsulation_ms")
    server_sign = successful_numbers("server_certificate_verify_sign_ms")
    tx_packets = successful_numbers("l2cap_tx_packets")
    tx_bytes = successful_numbers("l2cap_tx_bytes")
    rx_packets = successful_numbers("l2cap_rx_packets")
    rx_bytes = successful_numbers("l2cap_rx_bytes")
    tx_retries = successful_numbers("l2cap_tx_retries")
    tx_wait = successful_numbers("l2cap_tx_wait_ms")
    rx_overflows = successful_numbers("l2cap_rx_overflows")
    stack_used = successful_numbers("thread_stack_used_bytes")
    stack_peak = successful_numbers("thread_stack_peak_percent")
    heap_free = successful_numbers("client_heap_free_bytes")
    heap_peak_percent = successful_numbers("client_heap_peak_usage_percent")
    rx_ring_peak = successful_numbers("l2cap_rx_ring_peak_bytes")
    rx_ring_percent = successful_numbers("l2cap_rx_ring_peak_percent")

    def first_successful(field: str) -> object:
        return success[0][field] if success and success[0][field] != "" else ""
    stats = aggregate(raw)
    if success and len(success) == len(measured):
        status = "success"
    elif success:
        status = "mixed"
    elif any(row["status"] == "unsupported" for row in measured):
        status = "unsupported"
    elif any(row["status"] == "timeout" for row in measured):
        status = "timeout"
    else:
        status = "fail"
    mean_raw = float(stats["mean"]) if stats["mean"] else None
    mean_full = sum(full) / len(full) if full else None
    power_summary: dict[str, str] = {}
    power_success = [
        row for row in success if row.get("power_status") == "success"
    ]
    for window in POWER_WINDOWS:
        for metric in ("duration_ms", "charge_uc", "energy_uj", "avg_current_ua"):
            field = f"{window}_{metric}"
            values = [
                float(row[field]) for row in power_success
                if row.get(field, "") != ""
            ]
            power_summary[f"mean_{field}"] = (
                f"{sum(values) / len(values):.6f}" if values else ""
            )
        peak_field = f"{window}_peak_current_ua"
        peaks = [
            float(row[peak_field]) for row in power_success
            if row.get(peak_field, "") != ""
        ]
        power_summary[f"max_{peak_field}"] = (
            f"{max(peaks):.3f}" if peaks else ""
        )
    return {
        "case_id": case["case_id"],
        **case_metadata(case),
        "status": status,
        "success_count": len(success),
        "fail_count": sum(row["status"] == "fail" for row in measured),
        "timeout_count": sum(row["status"] == "timeout" for row in measured),
        "unsupported_count": sum(row["status"] == "unsupported" for row in measured),
        "mean_raw_handshake_ms": stats["mean"],
        "median_raw_handshake_ms": stats["median"],
        "p95_raw_handshake_ms": stats["p95"],
        "min_raw_handshake_ms": stats["min"],
        "max_raw_handshake_ms": stats["max"],
        "stddev_raw_handshake_ms": stats["stddev"],
        "handshake_throughput_hps": f"{1000.0 / mean_raw:.6f}" if mean_raw else "",
        "mean_mqtt_connect_ms": f"{sum(mqtt) / len(mqtt):.3f}" if mqtt else "",
        "mean_full_connect_ms": f"{mean_full:.3f}" if mean_full else "",
        "mean_end_to_end_ms": f"{sum(end) / len(end):.3f}" if end else "",
        "connections_per_second": f"{1000.0 / mean_full:.6f}" if mean_full else "",
        "mean_client_cpu_ms": f"{sum(cpu) / len(cpu):.3f}" if cpu else "",
        "mean_client_cpu_usage_percent": (
            f"{sum(client_cpu_usage) / len(client_cpu_usage):.3f}"
            if client_cpu_usage else ""
        ),
        "mean_system_cpu_usage_percent": (
            f"{sum(system_cpu_usage) / len(system_cpu_usage):.3f}"
            if system_cpu_usage else ""
        ),
        "mean_client_icache_hits": (
            f"{sum(icache_hits) / len(icache_hits):.3f}" if icache_hits else ""
        ),
        "mean_client_icache_misses": (
            f"{sum(icache_misses) / len(icache_misses):.3f}"
            if icache_misses else ""
        ),
        "mean_client_icache_requests": (
            f"{sum(icache_requests) / len(icache_requests):.3f}"
            if icache_requests else ""
        ),
        "mean_client_icache_hit_percent": (
            f"{sum(icache_hit_percent) / len(icache_hit_percent):.4f}"
            if icache_hit_percent else ""
        ),
        "mean_client_icache_miss_percent": (
            f"{sum(icache_miss_percent) / len(icache_miss_percent):.4f}"
            if icache_miss_percent else ""
        ),
        "client_memory_access_counters_supported": first_successful(
            "client_memory_access_counters_supported"
        ),
        "max_client_heap_peak_bytes": max(heap) if heap else "",
        "min_client_heap_free_bytes": (
            f"{min(heap_free):.0f}" if heap_free else ""
        ),
        "client_heap_capacity_bytes": first_successful(
            "client_heap_capacity_bytes"
        ),
        "max_client_heap_peak_usage_percent": (
            f"{max(heap_peak_percent):.2f}" if heap_peak_percent else ""
        ),
        "mean_communication_overhead_ms": (
            f"{sum(communication) / len(communication):.3f}" if communication else ""
        ),
        "mean_kem_keygen_ms": f"{sum(keygen) / len(keygen):.3f}" if keygen else "",
        "mean_kem_encapsulation_ms": (
            f"{sum(encapsulation) / len(encapsulation):.3f}"
            if encapsulation else ""
        ),
        "mean_kem_decapsulation_ms": (
            f"{sum(decapsulation) / len(decapsulation):.3f}"
            if decapsulation else ""
        ),
        "mean_classical_kex_keygen_ms": (
            f"{sum(classical_keygen) / len(classical_keygen):.3f}"
            if classical_keygen else ""
        ),
        "mean_classical_kex_shared_secret_ms": (
            f"{sum(classical_shared) / len(classical_shared):.3f}"
            if classical_shared else ""
        ),
        "mean_kem_client_total_ms": (
            f"{sum(kem_total) / len(kem_total):.3f}" if kem_total else ""
        ),
        "mean_certificate_signature_verify_ms": (
            f"{sum(cert_verify) / len(cert_verify):.3f}" if cert_verify else ""
        ),
        "mean_x509_chain_signature_verify_ms": (
            f"{sum(x509_verify) / len(x509_verify):.3f}" if x509_verify else ""
        ),
        "mean_tls_certificate_verify_signature_verify_ms": (
            f"{sum(tls_cert_verify) / len(tls_cert_verify):.3f}"
            if tls_cert_verify else ""
        ),
        "mean_mtls_signature_generate_ms": (
            f"{sum(mtls_sign) / len(mtls_sign):.3f}" if mtls_sign else ""
        ),
        "mean_client_signature_total_ms": (
            f"{sum(signature_total) / len(signature_total):.3f}"
            if signature_total else ""
        ),
        "mean_server_kem_encapsulation_ms": (
            f"{sum(server_encapsulation) / len(server_encapsulation):.3f}"
            if server_encapsulation else ""
        ),
        "mean_server_certificate_verify_sign_ms": (
            f"{sum(server_sign) / len(server_sign):.3f}"
            if server_sign else ""
        ),
        "mean_l2cap_tx_packets": (
            f"{sum(tx_packets) / len(tx_packets):.3f}" if tx_packets else ""
        ),
        "mean_l2cap_tx_bytes": (
            f"{sum(tx_bytes) / len(tx_bytes):.3f}" if tx_bytes else ""
        ),
        "mean_l2cap_rx_packets": (
            f"{sum(rx_packets) / len(rx_packets):.3f}" if rx_packets else ""
        ),
        "mean_l2cap_rx_bytes": (
            f"{sum(rx_bytes) / len(rx_bytes):.3f}" if rx_bytes else ""
        ),
        "mean_l2cap_tx_retries": (
            f"{sum(tx_retries) / len(tx_retries):.3f}" if tx_retries else ""
        ),
        "mean_l2cap_tx_wait_ms": (
            f"{sum(tx_wait) / len(tx_wait):.3f}" if tx_wait else ""
        ),
        "total_l2cap_rx_overflows": (
            f"{sum(rx_overflows):.0f}" if rx_overflows else ""
        ),
        "firmware_flash_used_bytes": first_successful(
            "firmware_flash_used_bytes"
        ),
        "firmware_flash_capacity_bytes": first_successful(
            "firmware_flash_capacity_bytes"
        ),
        "firmware_flash_usage_percent": first_successful(
            "firmware_flash_usage_percent"
        ),
        "firmware_static_ram_used_bytes": first_successful(
            "firmware_static_ram_used_bytes"
        ),
        "firmware_ram_capacity_bytes": first_successful(
            "firmware_ram_capacity_bytes"
        ),
        "firmware_static_ram_usage_percent": first_successful(
            "firmware_static_ram_usage_percent"
        ),
        "max_thread_stack_used_bytes": (
            f"{max(stack_used):.0f}" if stack_used else ""
        ),
        "thread_stack_capacity_bytes": first_successful(
            "thread_stack_capacity_bytes"
        ),
        "max_thread_stack_peak_percent": (
            f"{max(stack_peak):.2f}" if stack_peak else ""
        ),
        "max_l2cap_rx_ring_peak_bytes": (
            f"{max(rx_ring_peak):.0f}" if rx_ring_peak else ""
        ),
        "l2cap_rx_ring_capacity_bytes": first_successful(
            "l2cap_rx_ring_capacity_bytes"
        ),
        "max_l2cap_rx_ring_peak_percent": (
            f"{max(rx_ring_percent):.2f}" if rx_ring_percent else ""
        ),
        **power_summary,
    }


def load_config(path: Path) -> dict[str, object]:
    if not path.exists():
        raise FileNotFoundError(f"benchmark configuration not found: {path}")
    with path.open() as stream:
        values = json.load(stream)
    if not isinstance(values, dict):
        raise ValueError(f"{path}: top-level JSON value must be an object")
    required = {"serial-device", "pi-host", "ssh-key", "ble-addr"}
    optional = {
        "power-profiler-serial-device",
        "power-profiler-vdd-mv",
        "power-profiler-output-samples-per-second",
    }
    expected = required | optional
    unknown = set(values) - expected
    if unknown:
        raise ValueError(
            f"{path}: unknown configuration fields: {', '.join(sorted(unknown))}"
        )
    for key in required:
        if key not in values or not isinstance(values[key], str):
            raise ValueError(f"{path}: {key!r} must be a string")
    values.setdefault("power-profiler-serial-device", "/dev/ttyACM0")
    values.setdefault("power-profiler-vdd-mv", 3000)
    values.setdefault("power-profiler-output-samples-per-second", 100)
    if not isinstance(values["power-profiler-serial-device"], str):
        raise ValueError(f"{path}: 'power-profiler-serial-device' must be a string")
    for key in ("power-profiler-vdd-mv", "power-profiler-output-samples-per-second"):
        if not isinstance(values[key], int) or isinstance(values[key], bool):
            raise ValueError(f"{path}: {key!r} must be an integer")
    return values


def default_nrfutil() -> str:
    discovered = shutil.which("nrfutil")
    if discovered:
        return discovered
    for candidate in (
        str(Path.home() / ".local/bin/nrfutil"),
        "/opt/nordic/ncs/toolchains/0c0f19d91c/nrfutil/bin/nrfutil",
        "/opt/nordic/ncs/toolchains/0c0f19d91c/nrfutil/home/bin/nrfutil",
    ):
        if Path(candidate).exists():
            return candidate
    return "nrfutil"


def default_ncs_chdir(ncs_version: str = DEFAULT_NCS_VERSION) -> str:
    candidate = Path("/opt/nordic/ncs") / ncs_version / "nrf"
    if candidate.exists():
        return str(candidate)
    return f"/home/thiago/Documents/ncs/{ncs_version}/nrf"


def resolve_serial_device(configured: str) -> str:
    if Path(configured).exists() or configured != "/dev/ttyACM0":
        return configured
    candidates = sorted(Path("/dev").glob("tty.usbmodem*"))
    if candidates:
        return str(candidates[0])
    return configured


def resolve_power_profiler_device(configured: str, board_device: str) -> str:
    path = Path(configured)
    board = Path(board_device)
    collision = (
        path.exists() and board.exists() and path.resolve() == board.resolve()
    )
    if path.exists() and not collision:
        return configured
    candidates = sorted(Path("/dev/serial/by-id").glob("*PPK2*-if01"))
    if candidates:
        return str(candidates[0])
    return configured


def normalize_ble_addr(address: str) -> str:
    compact = re.sub(r"[^0-9a-fA-F]", "", address)
    if compact and set(compact) == {"0"}:
        return ""
    return address


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    config_parser = argparse.ArgumentParser(add_help=False)
    config_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    config_args, _ = config_parser.parse_known_args(argv)
    config = load_config(config_args.config)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=config_args.config,
        help="JSON file containing serial-device, pi-host, ssh-key and ble-addr",
    )
    parser.add_argument("--cases", type=Path)
    parser.add_argument(
        "--resume",
        metavar="RUN_ID",
        help=(
            "resume an existing result directory from its last atomically "
            "committed session"
        ),
    )
    parser.add_argument("--seed", type=int)
    parser.add_argument("--run-id")
    parser.add_argument(
        "--limit",
        type=int,
        help="maximum number of shuffled benchmark cases to execute",
    )
    parser.add_argument("--only-case", action="append", default=[])
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-flash", action="store_true")
    parser.add_argument("--sessions-per-case", type=int, default=2)
    parser.add_argument("--reconnect-retries", type=int, default=3)
    parser.add_argument("--reconnect-delay-sec", type=float, default=5.0)
    parser.add_argument(
        "--attempt-timeout-sec",
        type=float,
        default=None,
        help="override the adaptive per-case TLS/MQTT timeout",
    )
    parser.add_argument("--gateway-ready-timeout-sec", type=float, default=20.0)
    parser.add_argument("--board-ready-timeout-sec", type=float, default=20.0)
    parser.add_argument("--board-rearm-timeout-sec", type=float, default=30.0)
    parser.add_argument("--serial-device", default=config["serial-device"])
    parser.add_argument("--serial-baud", type=int, default=115200)
    parser.add_argument(
        "--power-profiler",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="capture PPK2 current synchronized with benchmark GPIO markers",
    )
    parser.add_argument(
        "--power-profiler-serial-device",
        default=config["power-profiler-serial-device"],
    )
    parser.add_argument(
        "--power-profiler-vdd-mv", type=int,
        default=config["power-profiler-vdd-mv"],
        help="measured DUT voltage used for energy calculation only",
    )
    parser.add_argument(
        "--power-profiler-output-samples-per-second", type=int,
        default=config["power-profiler-output-samples-per-second"],
        help="downsampled trace rate; native integration remains at 100 kS/s",
    )
    parser.add_argument("--pi-host", default=config["pi-host"])
    parser.add_argument(
        "--pi-workdir",
        default="",
        help="remote workspace; defaults to /home/<SSH user>/peripheral-benchmark",
    )
    parser.add_argument("--ssh-key", default=config["ssh-key"])
    parser.add_argument("--pi-adapter", default="hci0")
    parser.add_argument("--ble-addr", default=config["ble-addr"])
    parser.add_argument("--ble-name", default="PQC52840")
    parser.add_argument("--ble-addr-type", choices=("public", "random"), default="random")
    parser.add_argument("--psm", default="0x0080")
    parser.add_argument("--mtu", type=int, default=672)
    parser.add_argument(
        "--disable-pi-wifi",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="disable Raspberry Pi Wi-Fi while each BLE bridge session runs",
    )
    parser.add_argument("--nrfutil", default=default_nrfutil())
    parser.add_argument("--ncs-version", default=DEFAULT_NCS_VERSION)
    parser.add_argument("--ncs-chdir", default=default_ncs_chdir())
    parser.add_argument("--board", default="nrf52840dk/nrf52840")
    parser.add_argument(
        "--mlkem-backend",
        choices=("wolfssl", "pqm4-m4fstack"),
        default="pqm4-m4fstack",
        help="ML-KEM implementation used by the nRF52840 TLS client",
    )
    parser.add_argument(
        "--server-backend",
        choices=SERVER_BACKEND_CHOICES,
        default="auto",
        help="server TLS backend selection",
    )
    args = parser.parse_args(argv)
    if bool(args.cases) == bool(args.resume):
        parser.error("provide exactly one of --cases or --resume")
    args.ssh_key = os.path.expandvars(os.path.expanduser(args.ssh_key))
    args.serial_device = resolve_serial_device(args.serial_device)
    args.power_profiler_serial_device = os.path.expanduser(
        args.power_profiler_serial_device
    )
    args.power_profiler_serial_device = resolve_power_profiler_device(
        args.power_profiler_serial_device, args.serial_device
    )
    args.ble_addr = normalize_ble_addr(args.ble_addr)
    return args


def resolve_pi_workdir(pi_host: str, configured: str) -> str:
    if configured:
        return configured
    if "@" not in pi_host:
        raise ValueError("--pi-workdir is required when --pi-host has no SSH username")
    username = pi_host.rsplit("@", 1)[0]
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*", username):
        raise ValueError(f"cannot derive a safe home directory from SSH user {username!r}")
    return f"/home/{username}/peripheral-benchmark"


def main() -> int:
    args = parse_args()
    args.pi_workdir = resolve_pi_workdir(args.pi_host, args.pi_workdir)
    if args.sessions_per_case < 1 or args.reconnect_retries < 0:
        raise ValueError("sessions and reconnect retries must be non-negative")
    if args.limit is not None and args.limit < 1:
        raise ValueError("--limit must be at least 1")
    if args.power_profiler_vdd_mv <= 0:
        raise ValueError("--power-profiler-vdd-mv must be positive")
    if not 1 <= args.power_profiler_output_samples_per_second <= 100_000:
        raise ValueError(
            "--power-profiler-output-samples-per-second must be between 1 and 100000"
        )
    power_profiler_session = None
    if args.power_profiler:
        board_device = Path(args.serial_device)
        power_device = Path(args.power_profiler_serial_device)
        if board_device.exists() and power_device.exists():
            if board_device.resolve() == power_device.resolve():
                raise ValueError("board and PPK2 serial devices must be different")
    resuming = args.resume is not None
    if resuming:
        if args.limit is not None or args.only_case or args.run_id:
            raise ValueError(
                "--resume cannot be combined with --limit, --only-case, or --run-id"
            )
        run_dir = resolve_resume_dir(args.resume)
        run_id = run_dir.name
        cases = load_manifest_cases(run_dir)
        seed = int((run_dir / "seed.txt").read_text().strip())
        jobs = load_session_jobs(run_dir)
        saved_config_path = run_dir / "run_config.json"
        if saved_config_path.exists():
            saved_config = json.loads(saved_config_path.read_text())
            args.mlkem_backend = saved_config["mlkem_backend"]
            args.server_backend = saved_config["server_backend"]
            args.power_profiler = saved_config.get("power_profiler", False)
            args.power_profiler_serial_device = saved_config.get(
                "power_profiler_serial_device", args.power_profiler_serial_device
            )
            args.power_profiler_vdd_mv = saved_config.get(
                "power_profiler_vdd_mv", args.power_profiler_vdd_mv
            )
            args.power_profiler_output_samples_per_second = saved_config.get(
                "power_profiler_output_samples_per_second",
                args.power_profiler_output_samples_per_second,
            )
        checkpoint = read_checkpoint(run_dir)
        last_completed_execution_order = int(
            checkpoint.get("last_completed_execution_order", 0)
        )
        print(
            f"[resume] run={run_id} completed={last_completed_execution_order}/"
            f"{len(jobs)} next={last_completed_execution_order + 1}",
            flush=True,
        )
    else:
        cases = read_cases(args.cases)
        if args.only_case:
            selected = set(args.only_case)
            cases = [case for case in cases if case["case_id"] in selected]
        seed = (
            args.seed if args.seed is not None
            else random.SystemRandom().randint(1, 2**31 - 1)
        )
        random.Random(seed).shuffle(cases)
        if args.limit is not None:
            cases = cases[:args.limit]
        if not cases:
            raise ValueError("no cases selected")
        run_id = args.run_id or f"{datetime.now():%Y%m%d_%H%M%S}_{seed}"
        run_dir = RESULTS / run_id
        if run_dir.exists():
            raise FileExistsError(f"refusing to overwrite {run_dir}")
        run_dir.mkdir(parents=True)
        (run_dir / "seed.txt").write_text(f"{seed}\n")
        (run_dir / "mlkem_backend.txt").write_text(f"{args.mlkem_backend}\n")
        (run_dir / "run_config.json").write_text(json.dumps({
            "sessions_per_case": args.sessions_per_case,
            "mlkem_backend": args.mlkem_backend,
            "server_backend": args.server_backend,
            "power_profiler": args.power_profiler,
            "power_profiler_serial_device": args.power_profiler_serial_device,
            "power_profiler_vdd_mv": args.power_profiler_vdd_mv,
            "power_profiler_output_samples_per_second":
                args.power_profiler_output_samples_per_second,
        }, indent=2) + "\n")
        shutil.copy2(args.cases, run_dir / "input_cases.csv")
        manifest = [
            {"sequence": index, **case, "seed": seed, "run_id": run_id}
            for index, case in enumerate(cases, 1)
        ]
        write_csv(
            run_dir / "run_manifest.csv",
            ["sequence", *INPUT_FIELDS, "seed", "run_id"],
            manifest,
        )
        jobs = build_jobs(
            cases, seed=seed, sessions_per_case=args.sessions_per_case
        )
        session_rows = [
            {
                "execution_order": order,
                "source_sequence": job.sequence,
                "case_id": job.case_id,
                "session": job.session,
                "attempt_in_session": job.attempt_in_session,
                "warmup": job.warmup,
                "measured_index": job.measured_index,
                "seed": seed,
            }
            for order, job in enumerate(jobs, 1)
        ]
        write_csv(
            run_dir / "session_manifest.csv",
            ["execution_order", "source_sequence", "case_id", "session",
             "attempt_in_session", "warmup", "measured_index", "seed"],
            session_rows,
        )
        (run_dir / "checkpoint.json").write_text(json.dumps({
            "version": 1,
            "status": "new",
            "last_completed_execution_order": 0,
            "next_execution_order": 1,
            "case_id": None,
            "session": None,
            "attempt_in_session": None,
            "updated_at": datetime.now().astimezone().isoformat(),
        }, indent=2) + "\n")
        last_completed_execution_order = 0
    print(
        f"[selection] cases={len(cases)}"
        + (f" limit={args.limit}" if args.limit is not None else ""),
        flush=True,
    )

    case_sequence = {case["case_id"]: index for index, case in enumerate(cases, 1)}
    case_by_id = {case["case_id"]: case for case in cases}
    case_dirs = {
        case_id: run_dir / "cases" / f"{case_sequence[case_id]:03d}_{case_id}"
        for case_id in case_by_id
    }
    for directory in case_dirs.values():
        (directory / "generated").mkdir(parents=True, exist_ok=True)
    attempts = load_attempts(case_dirs) if resuming else defaultdict(list)
    scheduled_jobs = [
        (execution_order, job)
        for execution_order, job in enumerate(jobs, 1)
        if execution_order > last_completed_execution_order
    ]

    if args.dry_run:
        summaries = [
            {
                "case_id": case["case_id"], "mlkem_backend": args.mlkem_backend,
                "rsa_profile": "fast-math",
                **case_metadata(case),
                "status": "dry_run", "success_count": 0, "fail_count": 0,
                "timeout_count": 0, "unsupported_count": 0,
            }
            for case in cases
        ]
        write_csv(run_dir / "summary.csv", SUMMARY_FIELDS, summaries)
        print("[dry-run] Schedule validation completed; no hardware actions were performed.")
        print(f"[dry-run] cases={len(cases)} blocks={len(jobs)} seed={seed}")
        print(f"[dry-run] schedule={run_dir / 'session_manifest.csv'}")
        print("[dry-run] Remove --dry-run to build, flash, connect to the Pi, and execute.")
        print(f"results={run_dir}")
        return 0
    if not scheduled_jobs:
        print(f"[resume] Run {run_id} is already complete.", flush=True)
        print(f"results={run_dir}")
        return 0

    docker_log = run_dir / "docker.log"
    print(f"[setup] Checking Docker OpenSSL/OQS image; log={docker_log}", flush=True)
    ensure_image(ROOT / "docker" / "Dockerfile.pqc", docker_log)
    client_root = run_dir / "generated-client"
    print("[setup] Generating client identities and server roots...", flush=True)
    client_dirs: dict[str, Path] = {}

    def client_dir_for(case: dict[str, str]) -> Path:
        profile = certificate_verify_profile(case)
        client_dir = client_dirs.get(profile)
        if client_dir is None:
            client_dir = client_root / slug(profile)
            generate_client_identity(client_dir, docker_log, profile)
            client_dirs[profile] = client_dir
        return client_dir

    supported: list[dict[str, str]] = []
    unsupported: dict[str, str] = {}
    server_backends: dict[str, str] = {}
    signature_templates: dict[tuple[str, str], Path] = {}
    for case in cases:
        server_backend = server_backend_for_case(case, args.server_backend)
        if server_backend is None:
            unsupported[case["case_id"]] = unsupported_backend_reason(
                case, args.server_backend
            )
            continue
        server_backends[case["case_id"]] = server_backend
        try:
            generated = case_dirs[case["case_id"]] / "generated"
            profile = certificate_verify_profile(case)
            template_key = (case["cert_sig_alg"], profile)
            client_dir = client_dir_for(case)
            template = signature_templates.get(template_key)
            if template is None:
                print(
                    f"[certificates] Generating server chain for "
                    f"{case['cert_sig_alg']} with client auth {profile}...",
                    flush=True,
                )
                generate_server_case(
                    case, generated, client_dir,
                    case_dirs[case["case_id"]] / "build.log",
                )
                signature_templates[template_key] = generated
            else:
                shutil.copytree(template, generated, dirs_exist_ok=True)
                write_case_configs(case, generated)
            supported.append(case)
        except Exception as error:
            unsupported[case["case_id"]] = str(error)

    if not supported:
        raise RuntimeError("none of the selected cases passed certificate preparation")
    generated_root = WORK / "generated" / run_id
    all_case_dirs = [
        (case["case_id"], case_dirs[case["case_id"]] / "generated")
        for case in supported
    ]
    profiles = sorted({certificate_verify_profile(case) for case in supported})
    profile_generated_dirs: dict[str, Path] = {}
    profile_build_dirs: dict[str, Path] = {}
    for profile in profiles:
        profile_generated_dir = generated_root / f"fast-math-{slug(profile)}"
        generate_universal_header(
            client_dirs[profile],
            all_case_dirs,
            profile_generated_dir / "benchmark_credentials.h",
        )
        profile_generated_dirs[profile] = profile_generated_dir
        profile_build_dirs[profile] = WORK / "firmware-build" / f"{run_id}-{slug(profile)}"
    pqm4_dir = None
    if args.mlkem_backend.startswith("pqm4-"):
        pqm4_dir = WORK / "pqm4"
        print(f"[firmware] Preparing pinned pqm4 sources in {pqm4_dir}...", flush=True)
        ensure_pqm4(pqm4_dir, run_dir / "build.log")
    normal_build_ready = (build_dir / "zephyr/zephyr.hex").exists()
    if (
        supported
        and not args.skip_build
        and not (resuming and normal_build_ready)
    ):
        print(f"[firmware] Building universal image; log={run_dir / 'build.log'}", flush=True)
        build_firmware(
            firmware_dir=ROOT / "firmware", build_dir=build_dir,
            generated_dir=normal_generated_dir, log=run_dir / "build.log",
            nrfutil=args.nrfutil, ncs_version=args.ncs_version,
            ncs_chdir=args.ncs_chdir, board=args.board,
            mlkem_backend=args.mlkem_backend, pqm4_dir=pqm4_dir,
            large_rsa=False,
            power_markers=args.power_profiler,
        )
    if supported and not args.skip_build:
        for profile in profiles:
            build_dir = profile_build_dirs[profile]
            build_ready = (build_dir / "zephyr/zephyr.hex").exists()
            if resuming and build_ready:
                continue
            print(
                f"[firmware] Building image client-auth={profile}; "
                f"log={run_dir / 'build.log'}",
                flush=True,
            )
            build_firmware(
                firmware_dir=ROOT / "firmware", build_dir=build_dir,
                generated_dir=profile_generated_dirs[profile],
                log=run_dir / "build.log",
                nrfutil=args.nrfutil, ncs_version=args.ncs_version,
                ncs_chdir=args.ncs_chdir, board=args.board,
                mlkem_backend=args.mlkem_backend, pqm4_dir=pqm4_dir,
                large_rsa=False,
            )
        print("[firmware] Build completed.", flush=True)
    first_build_dir = profile_build_dirs[profiles[0]]
    if not args.skip_flash and len(profiles) == 1:
        profile = profiles[0]
        print(
            f"[firmware] Flashing nRF52840 profile=fast-math "
            f"client-auth={profile}; log={run_dir / 'flash.log'}",
            flush=True,
        )
        flash_firmware(
            build_dir=first_build_dir, log=run_dir / "flash.log",
            nrfutil=args.nrfutil, ncs_version=args.ncs_version,
            ncs_chdir=args.ncs_chdir,
        )
        print("[firmware] Flash completed.", flush=True)
    elif not args.skip_flash:
        print(
            f"[firmware] Prepared {len(profiles)} client-auth images; "
            "flashing will follow the schedule.",
            flush=True,
        )

    if args.power_profiler:
        print(
            "\n[power] Prepare the PPK2 in Ampere Meter mode:\n"
            "  1. Disconnect the nRF52840DK USB cable.\n"
            "  2. Remove the P22 jumper and insert PPK2 IN/OUT in series.\n"
            "  3. Connect DK GND/VDD to PPK2 logic GND/VCC.\n"
            "  4. Connect A0/P0.03->D7, A1/P0.04->D6, "
            "A2/P0.28->D5, A3/P0.29->D4.\n"
            "  5. Reconnect DK USB and close the nRF Connect Power Profiler app.",
            flush=True,
        )
        input("[power] Press Enter when the wiring is ready...")
        print("[power] Opening the persistent PPK2 Ampere Meter session...", flush=True)
        power_profiler_session = PowerProfilerSession(
            args.power_profiler_serial_device,
            args.power_profiler_vdd_mv,
            args.power_profiler_output_samples_per_second,
        )
        power_profiler_session.open()
        atexit.register(power_profiler_session.close)
        args.power_profiler_session = power_profiler_session
        idle_mean_ua, idle_peak_ua = power_profiler_session.probe_current()
        print(
            f"[power] DUT path enabled: mean={idle_mean_ua:.2f} uA "
            f"peak={idle_peak_ua:.2f} uA; no source voltage was configured.",
            flush=True,
        )
        if idle_peak_ua < 100.0:
            raise RuntimeError(
                "PPK2 sees only leakage current after enabling DUT power "
                f"(mean={idle_mean_ua:.2f} uA, peak={idle_peak_ua:.2f} uA). "
                "The nRF52840 is not powered through P22. Connect PPK2 VIN to "
                "the P22 supply side and PPK2 VOUT to the upper VDD_nRF pin."
            )
        print("[power] Resetting the powered nRF52840 target...", flush=True)
        try:
            reset_firmware(log=run_dir / "power-reset.log", nrfutil=args.nrfutil)
        except Exception as error:
            raise RuntimeError(
                "The PPK2 reports current, but nrfutil cannot access the "
                "nRF52840 over SWD. The target VDD rail is absent or below a "
                "usable level; the measured current is likely back-power. "
                "Verify approximately 3 V between VDD_nRF and GND, PPK2 VIN "
                "on the P22 supply side, and PPK2 VOUT on the upper VDD_nRF pin."
            ) from error

    gateway = PiGateway(args.pi_host, args.pi_workdir, args.ssh_key)
    print(
        f"[gateway] Opening SSH connection to {args.pi_host}; "
        f"remote workspace={args.pi_workdir}",
        flush=True,
    )
    gateway.start_master(run_dir / "gateway.log")
    atexit.register(gateway.stop_master)
    print(f"[gateway] Preparing Raspberry Pi bridge; log={run_dir / 'gateway.log'}", flush=True)
    wolfssl_archives = list(
        (first_build_dir / "_deps" / "wolfssl_upstream-subbuild").glob(
            "**/dd6da70d395a0cb26446326f329678fe3bfb212c.tar.gz"
        )
    )
    gateway.prepare(
        ROOT / "gateway" / "ble_mqtt_bridge.c",
        ROOT / "gateway" / "wolfssl_tls_server.c",
        run_dir / "gateway.log",
        wolfssl_archives[0] if wolfssl_archives else None,
    )
    print("[gateway] Raspberry Pi bridge is ready.", flush=True)
    remote_cases = {
        case["case_id"]: gateway.deploy_case(
            case["case_id"], case_dirs[case["case_id"]] / "generated",
            case_dirs[case["case_id"]] / "gateway-control.log",
        )
        for case in supported
    }

    try:
        import serial
    except ImportError as error:
        raise RuntimeError("pyserial is required: python -m pip install pyserial") from error
    if not hasattr(serial, "Serial"):
        module_path = getattr(serial, "__file__", "unknown")
        raise RuntimeError(
            "The imported 'serial' module is not pyserial "
            f"(loaded from {module_path}). Remove the package named 'serial' "
            "and install 'pyserial>=3.5'."
        )

    interrupted = False
    serial_port = None
    current_firmware_profile: str | None = profiles[0] if len(profiles) == 1 else None

    def open_serial_and_wait(profile: str):
        port = serial.Serial(
            args.serial_device, args.serial_baud, timeout=0.25
        )
        port.reset_input_buffer()
        print(
            f"[board] Waiting for BENCH_READY on {args.serial_device} "
            f"client-auth={profile}...",
            flush=True,
        )
        wait_for_board_ready(
            port, run_dir / "board.log", args.board_ready_timeout_sec
        )
        print("[board] Firmware is ready.", flush=True)
        return port

    try:
        if args.skip_flash:
            serial_port = open_serial_and_wait("current")
            current_firmware_profile = None
        elif len(profiles) == 1:
            serial_port = open_serial_and_wait(profiles[0])
        try:
            for execution_order, job in scheduled_jobs:
                case = case_by_id[job.case_id]
                timeout = timeout_for_case(case, args.attempt_timeout_sec)
                print(
                    f"[{execution_order}/{len(jobs)}] {job.case_id} "
                    f"session={job.session} attempt={job.attempt_in_session} "
                    f"timeout={timeout:g}s",
                    flush=True,
                )
                if job.case_id in unsupported:
                    row = {
                        "attempt_index": len(attempts[job.case_id]) + 1,
                        "schedule_index": job.sequence,
                        "session": job.session,
                        "attempt_in_session": job.attempt_in_session,
                        "warmup": job.warmup,
                        "status": "unsupported",
                        "reconnect_count": 0,
                        **case_metadata(case),
                        "message": unsupported[job.case_id],
                    }
                else:
                    profile = certificate_verify_profile(case)
                    if not args.skip_flash and current_firmware_profile != profile:
                        if serial_port is not None and serial_port.is_open:
                            serial_port.close()
                        flash_log = run_dir / f"flash-{slug(profile)}.log"
                        print(
                            f"[firmware] Flashing nRF52840 profile=fast-math "
                            f"client-auth={profile}; log={flash_log}",
                            flush=True,
                        )
                        flash_firmware(
                            build_dir=profile_build_dirs[profile],
                            log=flash_log,
                            nrfutil=args.nrfutil,
                            ncs_version=args.ncs_version,
                            ncs_chdir=args.ncs_chdir,
                        )
                        print("[firmware] Flash completed.", flush=True)
                        serial_port = open_serial_and_wait(profile)
                        current_firmware_profile = profile
                    if serial_port is None:
                        raise RuntimeError("serial port was not opened")
                    row = run_job(
                        job, case, case_dirs[job.case_id],
                        remote_cases[job.case_id],
                        server_backends[job.case_id],
                        gateway, serial_port, args,
                        len(attempts[job.case_id]) + 1,
                    )
                row["mlkem_backend"] = args.mlkem_backend
                row["rsa_profile"] = "fast-math"
                attempts[job.case_id].append(row)
                write_csv(
                    case_dirs[job.case_id] / "attempts.csv",
                    ATTEMPT_FIELDS, attempts[job.case_id],
                )
                write_checkpoint(
                    run_dir,
                    execution_order=execution_order,
                    total_jobs=len(jobs),
                    job=job,
                )
        finally:
            if serial_port is not None and serial_port.is_open:
                serial_port.close()
    except KeyboardInterrupt:
        interrupted = True
        print("\n[interrupt] Stopping broker and BLE bridge; partial results will be saved.",
              flush=True)
    finally:
        gateway.stop_session(run_dir / "gateway.log")
        if power_profiler_session is not None:
            power_profiler_session.close()

    summaries = [summarize(case, attempts[case["case_id"]]) for case in cases]
    for row in summaries:
        row["mlkem_backend"] = args.mlkem_backend
        row["rsa_profile"] = "fast-math"
    write_csv(run_dir / "summary.csv", SUMMARY_FIELDS, summaries)
    print(f"results={run_dir}")
    return 130 if interrupted else 0


if __name__ == "__main__":
    raise SystemExit(main())
