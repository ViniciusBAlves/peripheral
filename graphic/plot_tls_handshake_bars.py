#!/usr/bin/env python3
"""Plot TLS handshake bar charts from a benchmark result directory."""

from __future__ import annotations

import argparse
import csv
import statistics
from pathlib import Path

try:
    import matplotlib.pyplot as plt
    import numpy as np
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Missing Python plotting dependency. On Arch/CachyOS, install it with:\n"
        "  sudo pacman -S python-matplotlib python-numpy\n"
        "or use a virtualenv with:\n"
        "  python -m pip install matplotlib numpy"
    ) from exc


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS_ROOT = PROJECT_ROOT / "benchmarking" / "results"

PQC_KEM_PREFIXES = ("MLKEM", "SecP", "X25519MLKEM")
PQC_SIG_PREFIXES = ("ML-DSA", "SLH-DSA")


def resolve_run_dir(value: str) -> Path:
    path = Path(value).expanduser()
    if path.exists():
        return path.resolve()

    candidate = DEFAULT_RESULTS_ROOT / value
    if candidate.exists():
        return candidate.resolve()

    raise FileNotFoundError(
        f"Benchmark result directory not found: {value}. "
        f"Tried {path} and {candidate}."
    )


def is_pqc_or_hybrid_kem(kex_group: str) -> bool:
    return kex_group.startswith(PQC_KEM_PREFIXES)


def is_pqc_signature(cert_sig_alg: str) -> bool:
    return cert_sig_alg.startswith(PQC_SIG_PREFIXES)


def is_pqc_or_hybrid_case(row: dict[str, str]) -> bool:
    return is_pqc_or_hybrid_kem(row.get("kex_group", "")) or is_pqc_signature(
        row.get("cert_sig_alg", "")
    )


def float_or_none(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def load_from_summary(summary_csv: Path) -> list[dict[str, str]]:
    if not summary_csv.exists():
        return []
    with summary_csv.open(newline="") as fp:
        rows = list(csv.DictReader(fp))
    return [row for row in rows if float_or_none(row.get("mean_handshake_ms")) is not None]


def load_from_attempts(run_dir: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for attempts_csv in sorted((run_dir / "cases").glob("*/attempts.csv")):
        with attempts_csv.open(newline="") as fp:
            attempts = list(csv.DictReader(fp))
        successes = [
            row
            for row in attempts
            if row.get("status") == "success"
            and row.get("warmup") != "1"
            and float_or_none(row.get("tls_handshake_ms")) is not None
        ]
        if not successes:
            continue

        first = successes[0]
        values = [float(row["tls_handshake_ms"]) for row in successes]
        rows.append(
            {
                "case_id": attempts_csv.parent.name.split("_", 1)[-1],
                "kex_group": first.get("kex_group", ""),
                "cert_sig_alg": first.get("cert_sig_alg", ""),
                "mean_handshake_ms": f"{statistics.mean(values):.3f}",
                "success_count": str(len(successes)),
            }
        )
    return rows


def load_rows(run_dir: Path) -> list[dict[str, str]]:
    rows = load_from_summary(run_dir / "pqc_benchmark_results.csv")
    if rows:
        return rows
    return load_from_attempts(run_dir)


def short_label(row: dict[str, str]) -> str:
    kex = row.get("kex_group", "")
    sig = row.get("cert_sig_alg", "")
    return f"{kex}\n{sig}"


def plot_group(rows: list[dict[str, str]], title: str, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = sorted(rows, key=lambda row: float(row["mean_handshake_ms"]), reverse=True)

    fig_width = max(12, len(rows) * 0.62)
    fig, ax = plt.subplots(figsize=(fig_width, 7.5), constrained_layout=True)

    labels = [short_label(row) for row in rows]
    values = [float(row["mean_handshake_ms"]) for row in rows]
    colors = plt.cm.inferno(np.linspace(0.15, 0.9, len(values)))
    bars = ax.bar(range(len(values)), values, color=colors, edgecolor="#1a1a1a", linewidth=0.4)

    ax.set_title(title)
    ax.set_ylabel("TLS handshake mean (ms)")
    ax.set_xlabel("KEM / certificate signature")
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=65, ha="right", fontsize=8)
    ax.grid(axis="y", linestyle=":", alpha=0.35)

    for bar, value in zip(bars, values):
        ax.annotate(
            f"{value:.0f}",
            xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
            xytext=(0, 3),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=7,
        )

    fig.savefig(output, dpi=180)
    plt.close(fig)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "run_dir",
        help="Benchmark result directory or run id under benchmarking/results, e.g. 20260620_230500_123",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory for PNG files. Defaults to graphic/out/<run_id>.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run_dir = resolve_run_dir(args.run_dir)
    rows = load_rows(run_dir)
    if not rows:
        raise SystemExit(f"No successful TLS handshake rows found in {run_dir}")

    pqc_rows = [row for row in rows if is_pqc_or_hybrid_case(row)]
    classical_rows = [row for row in rows if not is_pqc_or_hybrid_case(row)]

    out_dir = args.out_dir or (PROJECT_ROOT / "graphic" / "out" / run_dir.name)
    if pqc_rows:
        plot_group(
            pqc_rows,
            f"PQC / hybrid TLS handshakes - {run_dir.name}",
            out_dir / "tls_handshake_pqc_hybrid.png",
        )
    if classical_rows:
        plot_group(
            classical_rows,
            f"Classical TLS handshakes - {run_dir.name}",
            out_dir / "tls_handshake_classical.png",
        )

    print(f"rows={len(rows)}")
    print(f"pqc_hybrid={len(pqc_rows)}")
    print(f"classical={len(classical_rows)}")
    print(f"out_dir={out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())