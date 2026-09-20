#!/usr/bin/env python3
"""Estimate battery lifetime from measured handshake and transfer energy."""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

from generate_transfer_energy_table import resolve_run_dir


BATTERY_VOLTAGE_V = 3.6
BATTERY_CAPACITY_AH = 1.2
BATTERY_USABLE_FRACTION = 0.70
SLEEP_CURRENT_UA = 2.5
TRANSFERS_PER_COMMUNICATION = 100
SECONDS_PER_DAY = 86400.0
DAYS_PER_YEAR = 365.25
PAYLOADS = (128, 1024, 8192, 16384, 32768, 65536)


@dataclass(frozen=True)
class SelectedCase:
    case_id: str
    label: str


CASES = (
    SelectedCase(
        "mlkem1024__homogeneous_lms_hss_l2_h10_w4",
        "Fastest NIST L5 PQC: LMS-HSS / MLKEM1024",
    ),
    SelectedCase(
        "mlkem512__homogeneous_slh_dsa_shake_128s",
        "Fastest hash-based PQC transition: SLH-DSA-SHAKE-128s / MLKEM512",
    ),
    SelectedCase(
        "mlkem512__root_slh_dsa_shake_128s__leaf_ml_dsa_44",
        "Fastest heterogeneous hash-based transition: "
        "SLH-DSA-SHAKE-128s -> ML-DSA-44 / MLKEM512",
    ),
    SelectedCase(
        "secp384r1mlkem1024__homogeneous_slh_dsa_shake_256f",
        "Board stress: SLH-DSA-SHAKE-256f / SecP384r1MLKEM1024",
    ),
    SelectedCase(
        "mlkem1024__homogeneous_ml_dsa_87",
        "High-security lattice PQC: ML-DSA-87 / MLKEM1024",
    ),
    SelectedCase(
        "ecdhe_p_256__homogeneous_ecdsa_p_256",
        "Fastest overall: ECDSA-P-256 / ECDHE-P-256",
    ),
)


def read_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def transfer_energy_by_case(
    rows: list[dict[str, str]], direction: str,
) -> dict[tuple[str, int], float]:
    grouped: dict[tuple[str, int], dict[str, float]] = {}
    for row in rows:
        value = row.get("mean_transfer_energy_uj", "")
        if not value:
            continue
        key = (row["case_id"], int(row["payload_bytes"]))
        grouped.setdefault(key, {})[row["direction"]] = float(value)

    result: dict[tuple[str, int], float] = {}
    for key, values in grouped.items():
        if direction == "balanced":
            required = ("server_to_device", "device_to_server")
            if all(item in values for item in required):
                result[key] = sum(values[item] for item in required) / 2.0
        elif direction in values:
            result[key] = values[direction]
    return result


def battery_lifetime_years(
    communications_per_day: np.ndarray, event_energy_uj: float,
) -> np.ndarray:
    battery_energy_j = (
        BATTERY_VOLTAGE_V * BATTERY_CAPACITY_AH * 3600.0
        * BATTERY_USABLE_FRACTION
    )
    sleep_power_w = BATTERY_VOLTAGE_V * SLEEP_CURRENT_UA / 1_000_000.0
    sleep_energy_per_day_j = sleep_power_w * SECONDS_PER_DAY
    event_energy_j = event_energy_uj / 1_000_000.0
    daily_energy_j = (
        sleep_energy_per_day_j + communications_per_day * event_energy_j
    )
    return battery_energy_j / daily_energy_j / DAYS_PER_YEAR


def plot_payload(
    payload: int, communications_per_day: np.ndarray,
    handshake_energy: dict[str, float], transfer_energy: dict[tuple[str, int], float],
    output: Path, source_label: str, direction: str,
) -> int:
    fig, ax = plt.subplots(figsize=(12.5, 7.5), constrained_layout=True)
    colors = plt.colormaps["turbo"](np.linspace(0.05, 0.92, len(CASES)))
    plotted = 0
    for selected, color in zip(CASES, colors, strict=True):
        handshake = handshake_energy.get(selected.case_id)
        transfer = transfer_energy.get((selected.case_id, payload))
        if handshake is None or transfer is None:
            print(f"warning: missing energy for {selected.case_id}, payload={payload}")
            continue
        event_energy = handshake + TRANSFERS_PER_COMMUNICATION * transfer
        lifetime = battery_lifetime_years(communications_per_day, event_energy)
        ax.plot(
            communications_per_day, lifetime, color=color, linewidth=2.0,
            label=selected.label,
        )
        plotted += 1

    if not plotted:
        plt.close(fig)
        return 0
    payload_label = f"{payload} B" if payload < 1024 else f"{payload // 1024} KiB"
    direction_label = {
        "balanced": "50 server-to-device + 50 device-to-server transfers",
        "server_to_device": "100 server-to-device transfers",
        "device_to_server": "100 device-to-server transfers",
    }[direction]
    ax.set_xscale("log")
    ax.set_xlim(communications_per_day[0], communications_per_day[-1])
    ax.set_ylim(bottom=0)
    ax.set_title(
        f"Idealized 1/2 AA Li-SOCl2 battery lifetime - {payload_label}\n"
        f"70% usable capacity; {source_label}"
    )
    ax.set_xlabel("Communication bundles per day (1 handshake + 100 transfers)")
    ax.set_ylabel("Estimated battery lifetime (years)")
    ax.grid(which="both", linestyle=":", alpha=0.35)
    ax.legend(
        title=f"{direction_label}; sleep current = {SLEEP_CURRENT_UA:g} µA",
        fontsize=7.5, loc="upper right",
    )
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return plotted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("handshake_run", help="handshake benchmark directory or run id")
    parser.add_argument("transfer_run", help="transfer benchmark directory or run id")
    parser.add_argument("--out-dir", type=Path, help="output directory")
    parser.add_argument(
        "--direction",
        choices=("balanced", "server_to_device", "device_to_server"),
        default="balanced",
        help="direction represented by the 100 transfers (default: balanced)",
    )
    parser.add_argument("--min-per-day", type=float, default=0.01)
    parser.add_argument("--max-per-day", type=float, default=10000.0)
    parser.add_argument("--generate-png", action="store_true")
    args = parser.parse_args()
    if args.min_per_day <= 0 or args.max_per_day <= args.min_per_day:
        parser.error("communication range must satisfy 0 < min-per-day < max-per-day")

    handshake_run = resolve_run_dir(args.handshake_run)
    transfer_run = resolve_run_dir(args.transfer_run)
    handshake_path = handshake_run / "handshake_summary.csv"
    if not handshake_path.exists():
        handshake_path = handshake_run / "summary.csv"
    handshake_energy = {
        row["case_id"]: float(row["mean_handshake_energy_uj"])
        for row in read_rows(handshake_path)
        if row.get("case_id") and row.get("mean_handshake_energy_uj")
    }
    transfer_energy = transfer_energy_by_case(
        read_rows(transfer_run / "transfer_summary.csv"), args.direction,
    )
    out_dir = (args.out_dir or (
        Path(__file__).resolve().parent / "out" /
        f"battery_lifetime_{handshake_run.name}_{transfer_run.name}"
    )).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    communications = np.geomspace(args.min_per_day, args.max_per_day, 600)
    extension = "png" if args.generate_png else "pdf"
    generated = 0
    for payload in PAYLOADS:
        output = out_dir / f"battery_lifetime_{payload}_bytes.{extension}"
        generated += int(plot_payload(
            payload, communications, handshake_energy, transfer_energy,
            output,
            f"handshake={handshake_run.name}, transfer={transfer_run.name}",
            args.direction,
        ) > 0)
        print(f"output={output}")
    print(f"plots={generated}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
