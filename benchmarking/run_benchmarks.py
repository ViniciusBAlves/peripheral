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

from benchmarklib.algorithms import KEMS_BY_NAME, SIGNATURES_BY_NAME
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
from benchmarklib.gateway import PiGateway
from benchmarklib.metrics import aggregate, number, parse_bench_line
from benchmarklib.scheduler import SessionJob, build_jobs
from generate_cases import FIELDS as INPUT_FIELDS


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
WORK = ROOT / "work"
DEFAULT_CONFIG = ROOT / "config.json"

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
    "kem_decapsulation_ms", "certificate_signature_verify_ms",
    "l2cap_tx_packets", "l2cap_tx_bytes", "l2cap_rx_packets", "l2cap_rx_bytes",
    "l2cap_tx_retries", "l2cap_tx_wait_ms", "l2cap_rx_overflows",
    "client_cpu_cycles", "client_cycle_hz", "client_cpu_ms",
    "client_cpu_usage_percent", "system_cpu_usage_percent",
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
    "max_client_heap_peak_bytes", "min_client_heap_free_bytes",
    "client_heap_capacity_bytes", "max_client_heap_peak_usage_percent",
    "mean_communication_overhead_ms",
    "mean_kem_keygen_ms", "mean_kem_encapsulation_ms",
    "mean_kem_decapsulation_ms", "mean_certificate_signature_verify_ms",
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
    return case["cert_sig_alg"] == "RSA-PSS-15360"


def parse_gateway_metrics(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(errors="replace").splitlines():
        parsed = parse_bench_line(line)
        if parsed and parsed[0] == "GATEWAY":
            values.update(parsed[1])
    return values


def microseconds_as_milliseconds(values: dict[str, str], key: str) -> str:
    value = number(values, key)
    return f"{value / 1000.0:.3f}" if value is not None else ""

def usage_percent(values: dict[str, str], used_key: str, capacity_key: str) -> str:
    used = number(values, used_key)
    capacity = number(values, capacity_key)
    return f"{used * 100.0 / capacity:.2f}" if used is not None and capacity else ""


def wait_for_result(serial_port, board_log: Path, timeout: float) -> dict[str, str]:
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


def run_job(
    job: SessionJob,
    case: dict[str, str],
    case_dir: Path,
    remote_case: str,
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
                ready_timeout=args.gateway_ready_timeout_sec,
                log=case_dir / "gateway-control.log",
            )
            final = wait_for_result(serial_port, board_log, attempt_timeout)
        except Exception as error:
            final = {
                "status": "fail",
                "stage": "gateway_start",
                "error": type(error).__name__,
            }
        finally:
            gateway.stop_session(
                case_dir / "gateway-control.log", reset_adapter=True
            )
            gateway.collect_session_logs(
                case["case_id"], broker_log, gateway_log,
                case_dir / "gateway-control.log",
            )
            try:
                wait_for_board_ready(
                    serial_port, board_log, args.board_rearm_timeout_sec
                )
            except TimeoutError:
                final = {
                    "status": "fail",
                    "stage": "board_rearm",
                    "error": "timeout",
                }
        if final.get("status") == "success":
            break
        if retry < args.reconnect_retries:
            time.sleep(args.reconnect_delay_sec)

    gateway_values = parse_gateway_metrics(gateway_log)
    cpu_us = number(final, "client_cpu_us")
    client_cpu_usage_bp = number(final, "client_cpu_usage_bp")
    system_cpu_usage_bp = number(final, "system_cpu_usage_bp")
    stack_peak_bp = number(final, "thread_stack_peak_percent_bp")
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
        "certificate_signature_verify_ms": microseconds_as_milliseconds(
            final, "certificate_signature_verify_us"
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
        "error_code": final.get("error", ""),
        "message": final.get("stage", ""),
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
    communication = successful_numbers("communication_overhead_ms")
    keygen = successful_numbers("kem_keygen_ms")
    encapsulation = successful_numbers("kem_encapsulation_ms")
    decapsulation = successful_numbers("kem_decapsulation_ms")
    cert_verify = successful_numbers("certificate_signature_verify_ms")
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
        "mean_certificate_signature_verify_ms": (
            f"{sum(cert_verify) / len(cert_verify):.3f}" if cert_verify else ""
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
    }


def load_config(path: Path) -> dict[str, str]:
    if not path.exists():
        raise FileNotFoundError(f"benchmark configuration not found: {path}")
    with path.open() as stream:
        values = json.load(stream)
    if not isinstance(values, dict):
        raise ValueError(f"{path}: top-level JSON value must be an object")
    expected = {"serial-device", "pi-host", "ssh-key", "ble-addr"}
    unknown = set(values) - expected
    if unknown:
        raise ValueError(
            f"{path}: unknown configuration fields: {', '.join(sorted(unknown))}"
        )
    for key in expected:
        if key not in values or not isinstance(values[key], str):
            raise ValueError(f"{path}: {key!r} must be a string")
    return values


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
    parser.add_argument("--cases", type=Path, required=True)
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
    parser.add_argument("--board-rearm-timeout-sec", type=float, default=15.0)
    parser.add_argument("--serial-device", default=config["serial-device"])
    parser.add_argument("--serial-baud", type=int, default=115200)
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
    parser.add_argument("--nrfutil", default="/home/thiago/.local/bin/nrfutil")
    parser.add_argument("--ncs-version", default="v3.3.0")
    parser.add_argument("--ncs-chdir", default="/home/thiago/Documents/ncs/v3.3.0/nrf")
    parser.add_argument("--board", default="nrf52840dk/nrf52840")
    parser.add_argument(
        "--mlkem-backend",
        choices=("wolfssl", "pqm4-m4fstack"),
        default="pqm4-m4fstack",
        help="ML-KEM implementation used by the nRF52840 TLS client",
    )
    parser.add_argument(
        "--reflash-known-unsupported-rsa",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "attempt RSA-PSS-15360 cases using a separately built firmware "
            "with heap integer math (enabled by default)"
        ),
    )
    args = parser.parse_args(argv)
    args.ssh_key = os.path.expandvars(os.path.expanduser(args.ssh_key))
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
    cases = read_cases(args.cases)
    if args.only_case:
        selected = set(args.only_case)
        cases = [case for case in cases if case["case_id"] in selected]
    seed = args.seed if args.seed is not None else random.SystemRandom().randint(1, 2**31 - 1)
    random.Random(seed).shuffle(cases)
    if args.limit is not None:
        cases = cases[:args.limit]
    if not cases:
        raise ValueError("no cases selected")
    has_large_rsa = any(needs_large_rsa_firmware(case) for case in cases)
    if (
        args.reflash_known_unsupported_rsa
        and has_large_rsa
        and (args.skip_build or args.skip_flash)
    ):
        raise ValueError(
            "selected RSA-PSS-15360 cases require the default large-RSA "
            "firmware fallback; do not use --skip-build or --skip-flash, or "
            "disable execution with --no-reflash-known-unsupported-rsa"
        )
    print(
        f"[selection] cases={len(cases)}"
        + (f" limit={args.limit}" if args.limit is not None else ""),
        flush=True,
    )

    run_id = args.run_id or f"{datetime.now():%Y%m%d_%H%M%S}_{seed}"
    run_dir = RESULTS / run_id
    if run_dir.exists():
        raise FileExistsError(f"refusing to overwrite {run_dir}")
    run_dir.mkdir(parents=True)
    (run_dir / "seed.txt").write_text(f"{seed}\n")
    (run_dir / "mlkem_backend.txt").write_text(f"{args.mlkem_backend}\n")
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
    jobs = build_jobs(cases, seed=seed, sessions_per_case=args.sessions_per_case)
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
    case_sequence = {case["case_id"]: index for index, case in enumerate(cases, 1)}
    case_by_id = {case["case_id"]: case for case in cases}
    case_dirs = {
        case_id: run_dir / "cases" / f"{case_sequence[case_id]:03d}_{case_id}"
        for case_id in case_by_id
    }
    for directory in case_dirs.values():
        (directory / "generated").mkdir(parents=True)

    if args.dry_run:
        summaries = [
            {
                "case_id": case["case_id"], "mlkem_backend": args.mlkem_backend,
                "rsa_profile": (
                    "integer-heap-16384"
                    if args.reflash_known_unsupported_rsa
                    and needs_large_rsa_firmware(case)
                    else "fast-math"
                ),
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

    docker_log = run_dir / "docker.log"
    print(f"[setup] Checking Docker OpenSSL/OQS image; log={docker_log}", flush=True)
    ensure_image(ROOT / "docker" / "Dockerfile.pqc", docker_log)
    client_dir = run_dir / "generated-client"
    print("[setup] Generating the fixed client identity and universal server root...", flush=True)
    generate_client_identity(client_dir, docker_log)
    supported: list[dict[str, str]] = []
    unsupported: dict[str, str] = {}
    signature_templates: dict[str, Path] = {}
    for case in cases:
        retry_large_rsa = (
            args.reflash_known_unsupported_rsa
            and needs_large_rsa_firmware(case)
        )
        if case["expected_support"] == "known_unsupported" and not retry_large_rsa:
            unsupported[case["case_id"]] = case["notes"] or "known unsupported case"
            continue
        try:
            generated = case_dirs[case["case_id"]] / "generated"
            template = signature_templates.get(case["cert_sig_alg"])
            if template is None:
                print(
                    f"[certificates] Generating server chain for {case['cert_sig_alg']}...",
                    flush=True,
                )
                generate_server_case(
                    case, generated, client_dir,
                    case_dirs[case["case_id"]] / "build.log",
                )
                signature_templates[case["cert_sig_alg"]] = generated
            else:
                shutil.copytree(template, generated, dirs_exist_ok=True)
                write_case_configs(case, generated)
            supported.append(case)
        except Exception as error:
            unsupported[case["case_id"]] = str(error)

    if not supported:
        raise RuntimeError("none of the selected cases passed certificate preparation")
    normal_cases = [
        case for case in supported if not needs_large_rsa_firmware(case)
    ]
    large_rsa_cases = [
        case for case in supported if needs_large_rsa_firmware(case)
    ]
    generated_root = WORK / "generated" / run_id
    normal_generated_dir = generated_root / "fast-math"
    large_rsa_generated_dir = generated_root / "integer-heap-16384"
    if normal_cases:
        generate_universal_header(
            client_dir,
            [
                (case["case_id"], case_dirs[case["case_id"]] / "generated")
                for case in normal_cases
            ],
            normal_generated_dir / "benchmark_credentials.h",
        )
    if large_rsa_cases:
        generate_universal_header(
            client_dir,
            [
                (case["case_id"], case_dirs[case["case_id"]] / "generated")
                for case in large_rsa_cases
            ],
            large_rsa_generated_dir / "benchmark_credentials.h",
        )
    build_dir = WORK / "firmware-build" / run_id
    pqm4_dir = None
    if args.mlkem_backend.startswith("pqm4-"):
        pqm4_dir = WORK / "pqm4"
        print(f"[firmware] Preparing pinned pqm4 sources in {pqm4_dir}...", flush=True)
        ensure_pqm4(pqm4_dir, run_dir / "build.log")
    if normal_cases and not args.skip_build:
        print(f"[firmware] Building universal image; log={run_dir / 'build.log'}", flush=True)
        build_firmware(
            firmware_dir=ROOT / "firmware", build_dir=build_dir,
            generated_dir=normal_generated_dir, log=run_dir / "build.log",
            nrfutil=args.nrfutil, ncs_version=args.ncs_version,
            ncs_chdir=args.ncs_chdir, board=args.board,
            mlkem_backend=args.mlkem_backend, pqm4_dir=pqm4_dir,
            large_rsa=False,
        )
        print("[firmware] Build completed.", flush=True)
    large_rsa_build_dir = WORK / "firmware-build" / f"{run_id}-large-rsa"
    if args.reflash_known_unsupported_rsa and large_rsa_cases and not args.skip_build:
        print(
            f"[firmware] Building RSA-16384 image; log={run_dir / 'build-large-rsa.log'}",
            flush=True,
        )
        build_firmware(
            firmware_dir=ROOT / "firmware", build_dir=large_rsa_build_dir,
            generated_dir=large_rsa_generated_dir,
            log=run_dir / "build-large-rsa.log",
            nrfutil=args.nrfutil, ncs_version=args.ncs_version,
            ncs_chdir=args.ncs_chdir, board=args.board,
            mlkem_backend=args.mlkem_backend, pqm4_dir=pqm4_dir,
            large_rsa=True,
        )
        print("[firmware] RSA-16384 build completed.", flush=True)
    initial_large_rsa = (
        args.reflash_known_unsupported_rsa
        and needs_large_rsa_firmware(case_by_id[jobs[0].case_id])
        and jobs[0].case_id not in unsupported
    )
    initial_build_dir = large_rsa_build_dir if initial_large_rsa else build_dir
    if not args.skip_flash:
        print(
            f"[firmware] Flashing nRF52840 profile="
            f"{'integer-heap-16384' if initial_large_rsa else 'fast-math'}; "
            f"log={run_dir / 'flash.log'}",
            flush=True,
        )
        flash_firmware(
            build_dir=initial_build_dir, log=run_dir / "flash.log",
            nrfutil=args.nrfutil, ncs_version=args.ncs_version,
            ncs_chdir=args.ncs_chdir,
        )
        print("[firmware] Flash completed.", flush=True)

    gateway = PiGateway(args.pi_host, args.pi_workdir, args.ssh_key)
    print(
        f"[gateway] Opening SSH connection to {args.pi_host}; "
        f"remote workspace={args.pi_workdir}",
        flush=True,
    )
    gateway.start_master(run_dir / "gateway.log")
    atexit.register(gateway.stop_master)
    print(f"[gateway] Preparing Raspberry Pi bridge; log={run_dir / 'gateway.log'}", flush=True)
    gateway.prepare(ROOT / "gateway" / "ble_mqtt_bridge.c", run_dir / "gateway.log")
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

    attempts: dict[str, list[dict[str, object]]] = defaultdict(list)
    interrupted = False
    serial_port = None
    active_large_rsa = initial_large_rsa
    try:
        serial_port = serial.Serial(
            args.serial_device, args.serial_baud, timeout=0.25
        )
        try:
            print(
                f"[board] Waiting for BENCH_READY on {args.serial_device}...",
                flush=True,
            )
            wait_for_board_ready(
                serial_port, run_dir / "board.log", args.board_ready_timeout_sec
            )
            print("[board] Firmware is ready.", flush=True)
            for execution_order, job in enumerate(jobs, 1):
                case = case_by_id[job.case_id]
                desired_large_rsa = (
                    args.reflash_known_unsupported_rsa
                    and needs_large_rsa_firmware(case)
                    and job.case_id not in unsupported
                )
                if desired_large_rsa != active_large_rsa:
                    profile = (
                        "integer-heap-16384" if desired_large_rsa else "fast-math"
                    )
                    print(
                        f"[firmware] Schedule profile changed; reflashing {profile}...",
                        flush=True,
                    )
                    gateway.stop_session(run_dir / "gateway.log")
                    serial_port.close()
                    flash_firmware(
                        build_dir=(
                            large_rsa_build_dir if desired_large_rsa else build_dir
                        ),
                        log=run_dir / f"flash-{profile}.log",
                        nrfutil=args.nrfutil,
                        ncs_version=args.ncs_version,
                        ncs_chdir=args.ncs_chdir,
                    )
                    time.sleep(1.0)
                    serial_port = serial.Serial(
                        args.serial_device, args.serial_baud, timeout=0.25
                    )
                    wait_for_board_ready(
                        serial_port, run_dir / "board.log",
                        args.board_ready_timeout_sec,
                    )
                    active_large_rsa = desired_large_rsa
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
                    row = run_job(
                        job, case, case_dirs[job.case_id],
                        remote_cases[job.case_id], gateway, serial_port, args,
                        len(attempts[job.case_id]) + 1,
                    )
                row["mlkem_backend"] = args.mlkem_backend
                row["rsa_profile"] = (
                    "integer-heap-16384" if desired_large_rsa else "fast-math"
                )
                attempts[job.case_id].append(row)
                write_csv(
                    case_dirs[job.case_id] / "attempts.csv",
                    ATTEMPT_FIELDS, attempts[job.case_id],
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

    summaries = [summarize(case, attempts[case["case_id"]]) for case in cases]
    for row in summaries:
        row["mlkem_backend"] = args.mlkem_backend
        case = case_by_id[row["case_id"]]
        row["rsa_profile"] = (
            "integer-heap-16384"
            if args.reflash_known_unsupported_rsa
            and needs_large_rsa_firmware(case)
            else "fast-math"
        )
    write_csv(run_dir / "summary.csv", SUMMARY_FIELDS, summaries)
    print(f"results={run_dir}")
    return 130 if interrupted else 0


if __name__ == "__main__":
    raise SystemExit(main())
