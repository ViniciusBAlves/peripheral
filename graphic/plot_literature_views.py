#!/usr/bin/env python3
"""Create literature-inspired plots for KEM, certificate, and TLS benchmark runs."""

from __future__ import annotations

import argparse
import csv
import math
import sys
import textwrap
from pathlib import Path

try:
    import matplotlib.pyplot as plt
    import numpy as np
    from matplotlib.colors import LogNorm
except ImportError as exc:  # pragma: no cover - depends on local environment
    raise SystemExit(
        "Missing Python plotting dependency. Install matplotlib and numpy with:\n"
        "  python -m pip install matplotlib numpy"
    ) from exc


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "benchmarking" / "results"
sys.path.insert(0, str(ROOT / "benchmarking"))
sys.path.insert(0, str(ROOT / "graphic"))

from benchmarklib.algorithms import KEMS_BY_NAME, SIGNATURES_BY_NAME  # noqa: E402
from plot_kem_literature_views import (  # noqa: E402
    REFERENCES as KEM_REFERENCES,
    load_rows as load_kem_rows,
    plot_dwt_density as plot_kem_dwt_density,
    plot_efficiency as plot_kem_efficiency,
    plot_memory_budget as plot_kem_memory_budget,
    plot_normalized_overhead as plot_kem_normalized_overhead,
    plot_operation_costs as plot_kem_operation_costs,
    plot_resource_tradeoff as plot_kem_resource_tradeoff,
    write_reference_file as write_kem_reference_file,
)


REFERENCES = (
    *KEM_REFERENCES,
    {
        "short": "PQ auth TLS",
        "title": "Sikeridis et al., Post-Quantum Authentication in TLS 1.3: A Performance Study",
        "url": "https://www.ndss-symposium.org/ndss-paper/post-quantum-authentication-in-tls-1-3-a-performance-study/",
        "used_for": "certificate-chain signature cost, TLS latency, and server throughput tradeoffs",
    },
    {
        "short": "data-heavy PQ TLS",
        "title": "The impact of data-heavy, post-quantum TLS 1.3 on real-world connections",
        "url": "https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/the-impact-of-data-heavy-post-quantum.pdf",
        "used_for": "handshake size, tail latency, and traffic-volume views",
    },
    {
        "short": "layered PQ TLS",
        "title": "Gomez-Cambronero et al., Layered Performance Analysis of TLS 1.3 Handshakes",
        "url": "https://arxiv.org/abs/2603.11006",
        "used_for": "layered TLS phase views across classical, hybrid, and pure PQ key exchange",
    },
)

FAMILY_COLORS = {
    "classic": "#475569",
    "pqc": "#0f766e",
    "hybrid": "#7c3aed",
    "server": "#2563eb",
    "board": "#dc2626",
}

SIG_BASELINES = {
    "L1": "ECDSA-P-256",
    "L3": "ECDSA-P-384",
    "L5": "ECDSA-P-521",
}

PHASES = (
    ("keygen", "Keygen"),
    ("make_cert", "Make cert"),
    ("sign_cert", "Sign cert"),
    ("parse_cert", "Parse verify"),
    ("key_export", "Key export"),
)

TLS_CRYPTO_FIELDS = (
    ("mean_kem_keygen_ms", "KEM keygen"),
    ("mean_kem_encapsulation_ms", "KEM encaps"),
    ("mean_kem_decapsulation_ms", "KEM decaps"),
    ("mean_classical_kex_keygen_ms", "Classic keygen"),
    ("mean_classical_kex_shared_secret_ms", "Classic secret"),
    ("mean_certificate_signature_verify_ms", "Chain verify"),
    ("mean_tls_certificate_verify_signature_verify_ms", "TLS verify"),
    ("mean_mtls_signature_generate_ms", "mTLS sign"),
    ("mean_server_kem_encapsulation_ms", "Server KEM"),
    ("mean_server_certificate_verify_sign_ms", "Server sign"),
)


def resolve_run_dir(value: str) -> Path:
    path = Path(value).expanduser()
    if path.is_dir():
        return path.resolve()
    candidate = RESULTS / value
    if candidate.is_dir():
        return candidate.resolve()
    raise FileNotFoundError(f"Benchmark result directory not found: {value}")


def number(row: dict[str, str], field: str) -> float | None:
    value = row.get(field, "")
    if value == "":
        return None
    try:
        result = float(value)
    except ValueError:
        return None
    return result if math.isfinite(result) else None


def read_summary(run_dir: Path) -> tuple[list[dict[str, str]], list[str]]:
    summary = run_dir / "summary.csv"
    if not summary.exists():
        raise FileNotFoundError(f"summary.csv not found in {run_dir}")
    with summary.open(newline="") as stream:
        reader = csv.DictReader(stream)
        rows = list(reader)
        fields = reader.fieldnames or []
    if not rows:
        raise ValueError(f"no rows found in {summary}")
    return rows, fields


def successful(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return [
        row for row in rows
        if row.get("success_count", "0") not in {"", "0"}
        or row.get("status") == "success"
    ]


def detect_run_type(fields: list[str]) -> str:
    field_set = set(fields)
    if {"mean_kem_total_ms", "kex_group"} <= field_set and "case_id" not in field_set:
        return "kem"
    if {"component", "cert_sig_alg", "mean_wall_ms"} <= field_set:
        return "certificate"
    if {"case_id", "kex_group", "cert_sig_alg"} <= field_set and (
        "mean_raw_handshake_ms" in field_set or "mean_handshake_ms" in field_set
    ):
        return "full"
    raise ValueError("could not detect benchmark type from summary.csv fields")


def sig_level(row: dict[str, str]) -> str:
    try:
        level = int(float(row.get("sig_nist_level", "")))
    except ValueError:
        known = SIGNATURES_BY_NAME.get(row.get("cert_sig_alg", ""))
        level = known.nist_level if known is not None else 0
    if level <= 2 and level > 0:
        return "L1"
    if level <= 3 and level > 0:
        return "L3"
    if level >= 4:
        return "L5"
    return "?"


def kem_level(row: dict[str, str]) -> str:
    try:
        level = int(float(row.get("kex_nist_level", "")))
    except ValueError:
        known = KEMS_BY_NAME.get(row.get("kex_group", ""))
        level = known.nist_level if known is not None else 0
    if level <= 2 and level > 0:
        return "L1"
    if level <= 3 and level > 0:
        return "L3"
    if level >= 4:
        return "L5"
    return "?"


def sig_family(row: dict[str, str]) -> str:
    known = SIGNATURES_BY_NAME.get(row.get("cert_sig_alg", ""))
    return row.get("sig_family") or (known.family if known is not None else "unknown")


def kem_family(row: dict[str, str]) -> str:
    name = row.get("kex_group", "")
    if "MLKEM" in name and not name.startswith("MLKEM"):
        return "hybrid"
    known = KEMS_BY_NAME.get(name)
    return row.get("kex_family") or (known.family if known is not None else "unknown")


def sig_sort_key(name: str) -> tuple[int, int, str]:
    known = SIGNATURES_BY_NAME.get(name)
    family = known.family if known is not None else "unknown"
    level = known.nist_level if known is not None else 99
    family_rank = 0 if family == "classic" else 1
    return family_rank, level, name


def kem_sort_key(name: str) -> tuple[int, int, int, str]:
    known = KEMS_BY_NAME.get(name)
    if known is None:
        return 99, 99, 99, name
    family_rank = 0 if known.family == "classic" else 1 if name.startswith("MLKEM") else 2
    return family_rank, known.nist_level, list(KEMS_BY_NAME).index(name), name


def certificate_sort_key(row: dict[str, str]) -> tuple[int, int, int, str]:
    owner_rank = 0 if board_row(row) else 1
    name = row.get("cert_sig_alg", "")
    family_rank, level, _ = sig_sort_key(name)
    return owner_rank, family_rank, level, name


def tls_sort_key(row: dict[str, str]) -> tuple[int, str, str]:
    return (
        int(number(row, "p95_raw_handshake_ms") or number(row, "mean_raw_handshake_ms") or 0.0),
        row.get("kex_group", ""),
        row.get("cert_sig_alg", ""),
    )


def board_row(row: dict[str, str]) -> bool:
    return row.get("owner") == "client" or row.get("component") in {
        "client_certificate", "client_identity",
    }


def role_label(row: dict[str, str]) -> str:
    return "Board" if board_row(row) else "Server"


def cert_label(row: dict[str, str]) -> str:
    return f"{role_label(row)} {sig_level(row)} {row.get('cert_sig_alg', '')}"


def cert_output_bytes(row: dict[str, str]) -> float:
    direct = number(row, "mean_output_total_bytes")
    if direct is not None and direct > 0:
        return direct
    fields = (
        "server_chain_crt_bytes", "server_key_bytes",
        "client_cert_crt_bytes", "client_key_bytes",
        "client_csr_der_bytes", "client_csr_pem_bytes",
        "client_cert_der_bytes", "client_key_der_bytes",
    )
    return sum(number(row, field) or 0.0 for field in fields)


def total_tls_bytes(row: dict[str, str]) -> float:
    direct = number(row, "mean_l2cap_tx_bytes")
    if direct is not None and direct > 0:
        return direct
    return sum(
        number(row, field) or 0.0
        for field in (
            "kex_public_key_bytes", "kex_ciphertext_bytes",
            "sig_public_key_bytes", "sig_signature_bytes",
        )
    )


def positive(values: list[float]) -> list[float]:
    return [value for value in values if value > 0 and math.isfinite(value)]


def save(fig, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    print(output)


def add_note(fig, sources: list[str]) -> None:
    fig.text(
        0.01, 0.01,
        textwrap.fill("Inspired by: " + "; ".join(sources), width=155),
        ha="left", va="bottom", fontsize=7, color="#334155",
    )


def set_log_x(ax, values: list[float]) -> None:
    vals = positive(values)
    if not vals:
        return
    ax.set_xscale("log")
    ax.set_xlim(left=max(min(vals) * 0.65, 0.001), right=max(vals) * 1.8)


def annotate_bars(ax, bars, values: list[float], fmt: str = "{:.2f}") -> None:
    for bar, value in zip(bars, values):
        if value <= 0:
            continue
        ax.text(
            bar.get_width(), bar.get_y() + bar.get_height() / 2,
            " " + fmt.format(value), ha="left", va="center", fontsize=7,
        )


def write_reference_file(out_dir: Path) -> None:
    lines = ["# Literature References", ""]
    for reference in REFERENCES:
        lines.extend([
            f"- {reference['short']}: {reference['title']}",
            f"  URL: {reference['url']}",
            f"  Used for: {reference['used_for']}",
            "",
        ])
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "literature_references.md").write_text("\n".join(lines))


def matrix_for(
    rows: list[dict[str, str]], value_field: str
) -> tuple[list[str], list[str], np.ndarray]:
    kems = sorted({row.get("kex_group", "") for row in rows if row.get("kex_group")}, key=kem_sort_key)
    sigs = sorted({row.get("cert_sig_alg", "") for row in rows if row.get("cert_sig_alg")}, key=sig_sort_key)
    values: dict[tuple[str, str], list[float]] = {}
    for row in rows:
        value = number(row, value_field)
        if value is None:
            continue
        key = (row.get("kex_group", ""), row.get("cert_sig_alg", ""))
        if key[0] and key[1]:
            values.setdefault(key, []).append(value)
    matrix = np.full((len(sigs), len(kems)), np.nan)
    for y, sig in enumerate(sigs):
        for x, kem in enumerate(kems):
            cell = values.get((kem, sig), [])
            if cell:
                matrix[y, x] = sum(cell) / len(cell)
    return kems, sigs, matrix


def plot_heatmap(
    rows: list[dict[str, str]],
    field: str,
    output: Path,
    run_id: str,
    title: str,
    units: str,
    *,
    log_scale: bool = False,
) -> None:
    kems, sigs, matrix = matrix_for(rows, field)
    if matrix.size == 0 or np.all(np.isnan(matrix)):
        print(f"warning: no values found for {field}")
        return
    masked = np.ma.masked_invalid(matrix)
    fig, ax = plt.subplots(
        figsize=(max(10, len(kems) * 0.75), max(6, len(sigs) * 0.45)),
        constrained_layout=True,
    )
    vals = matrix[np.isfinite(matrix) & (matrix > 0)]
    norm = LogNorm(vmin=max(vals.min(), 0.001), vmax=vals.max()) if log_scale and vals.size else None
    image = ax.imshow(masked, cmap="viridis", aspect="auto", norm=norm)
    ax.set_title(f"{title} - {run_id}")
    ax.set_xlabel("KEM / key exchange")
    ax.set_ylabel("Certificate signature")
    ax.set_xticks(range(len(kems)))
    ax.set_yticks(range(len(sigs)))
    ax.set_xticklabels(kems, rotation=55, ha="right", fontsize=7)
    ax.set_yticklabels(sigs, fontsize=7)
    for y in range(len(sigs)):
        for x in range(len(kems)):
            value = matrix[y, x]
            if not math.isfinite(value):
                continue
            ax.text(x, y, f"{value:.1f}", ha="center", va="center", fontsize=5, color="white")
    fig.colorbar(image, ax=ax, label=units)
    add_note(fig, ["layered PQ TLS", "data-heavy PQ TLS", "PQ TLS embedded"])
    save(fig, output)


def plot_certificate_phase_costs(
    rows: list[dict[str, str]], output: Path, run_id: str
) -> None:
    board = [
        row for row in rows
        if board_row(row) and any(number(row, f"mean_{phase}_wall_ms") for phase, _ in PHASES)
    ]
    if not board:
        print("warning: no board certificate phase timings found")
        return
    board = sorted(board, key=certificate_sort_key)
    y = np.arange(len(board))
    height = 0.16
    offsets = np.linspace(-height * 2, height * 2, len(PHASES))
    colors = ["#2563eb", "#64748b", "#dc2626", "#0f766e", "#9333ea"]
    all_values: list[float] = []
    fig, ax = plt.subplots(
        figsize=(12.5, max(6, len(board) * 0.44)), constrained_layout=True
    )
    for offset, (phase, label), color in zip(offsets, PHASES, colors):
        values = [number(row, f"mean_{phase}_wall_ms") or 0.0 for row in board]
        all_values.extend(values)
        ax.barh(
            y + offset, values, height=height, label=label,
            color=color, edgecolor="#111827", linewidth=0.25,
        )
    ax.set_title(f"Board certificate phase cost - {run_id}")
    ax.set_xlabel("Mean phase wall time (ms, log scale)")
    ax.set_yticks(y)
    ax.set_yticklabels([cert_label(row) for row in board], fontsize=7)
    ax.grid(axis="x", color="#e5e7eb", linewidth=0.8)
    ax.legend(loc="lower right", fontsize=8)
    set_log_x(ax, all_values)
    add_note(fig, ["pqm4 operation-level timing", "PQ auth TLS certificate signature cost"])
    save(fig, output)


def plot_certificate_time_size_tradeoff(
    rows: list[dict[str, str]], output: Path, run_id: str
) -> None:
    rows = [
        row for row in rows
        if (number(row, "mean_wall_ms") or 0.0) > 0 and cert_output_bytes(row) > 0
    ]
    if not rows:
        print("warning: no certificate size/time rows found")
        return
    fig, ax = plt.subplots(figsize=(11.5, 7.4), constrained_layout=True)
    offsets = [(6, 5), (6, -10), (-5, 8), (-7, -12)]
    for index, row in enumerate(sorted(rows, key=certificate_sort_key)):
        color = FAMILY_COLORS["board"] if board_row(row) else FAMILY_COLORS["server"]
        marker = "o" if board_row(row) else "s"
        memory = (
            number(row, "max_client_heap_peak_bytes")
            or (number(row, "max_rss_kb") or 0.0) * 1024.0
            or 1.0
        )
        ax.scatter(
            cert_output_bytes(row), number(row, "mean_wall_ms") or 0.0,
            s=max(45, min(320, memory / 512.0)), marker=marker,
            color=color, edgecolor="#111827", linewidth=0.45, alpha=0.86,
        )
        offset = offsets[index % len(offsets)]
        ax.annotate(
            cert_label(row), (cert_output_bytes(row), number(row, "mean_wall_ms") or 0.0),
            xytext=offset, textcoords="offset points", fontsize=7,
            ha="left" if offset[0] >= 0 else "right",
        )
    ax.set_title(f"Certificate size vs generation time - {run_id}")
    ax.set_xlabel("Generated certificate/key material bytes")
    ax.set_ylabel("Mean wall time (ms, log scale)")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.grid(True, color="#e5e7eb", linewidth=0.8)
    ax.legend(
        handles=[
            plt.Line2D([0], [0], marker="o", color="w", markerfacecolor=FAMILY_COLORS["board"], label="Board", markersize=8),
            plt.Line2D([0], [0], marker="s", color="w", markerfacecolor=FAMILY_COLORS["server"], label="Server", markersize=8),
        ],
        loc="lower right", fontsize=8,
    )
    add_note(fig, ["PQ auth TLS certificate-chain cost", "data-heavy PQ TLS traffic-size framing"])
    save(fig, output)


def plot_certificate_normalized_overhead(
    rows: list[dict[str, str]], output: Path, run_id: str
) -> None:
    by_role_alg = {(role_label(row), row.get("cert_sig_alg", "")): row for row in rows}
    selected = [
        row for row in rows
        if (number(row, "mean_wall_ms") or 0.0) > 0
        and (role_label(row), SIG_BASELINES.get(sig_level(row), "")) in by_role_alg
    ]
    if not selected:
        print("warning: no certificate baselines found for normalized overhead")
        return
    selected = sorted(selected, key=certificate_sort_key)
    y = np.arange(len(selected))
    metrics = (
        ("mean_wall_ms", "Time", "#2563eb"),
        ("_bytes", "Bytes", "#0f766e"),
        ("_memory", "Memory", "#f97316"),
    )
    width = 0.24
    fig, ax = plt.subplots(
        figsize=(12, max(6, len(selected) * 0.42)), constrained_layout=True
    )
    all_values: list[float] = []
    for offset, (field, name, color) in zip((-width, 0.0, width), metrics):
        values = []
        for row in selected:
            baseline = by_role_alg[(role_label(row), SIG_BASELINES[sig_level(row)])]
            if field == "_bytes":
                value = cert_output_bytes(row)
                base_value = cert_output_bytes(baseline)
            elif field == "_memory":
                value = number(row, "max_client_heap_peak_bytes") or number(row, "max_rss_kb") or 0.0
                base_value = number(baseline, "max_client_heap_peak_bytes") or number(baseline, "max_rss_kb") or 0.0
            else:
                value = number(row, field) or 0.0
                base_value = number(baseline, field) or 0.0
            values.append(value / base_value if base_value > 0 else 0.0)
        all_values.extend(values)
        bars = ax.barh(
            y + offset, values, height=width, label=name,
            color=color, edgecolor="#111827", linewidth=0.3,
        )
        if len(selected) <= 36:
            annotate_bars(ax, bars, values, "{:.2f}x")
    ax.axvline(1.0, linestyle="--", linewidth=0.8, color="#111827")
    ax.set_title(f"Certificate overhead vs same-level ECDSA - {run_id}")
    ax.set_xlabel("Multiple of same-role ECDSA baseline (log scale)")
    ax.set_yticks(y)
    ax.set_yticklabels([cert_label(row) for row in selected], fontsize=7)
    ax.grid(axis="x", color="#e5e7eb", linewidth=0.8)
    ax.legend(loc="lower right", fontsize=8)
    set_log_x(ax, all_values)
    add_note(fig, ["PQ auth TLS classical/PQ authentication comparison", "KEMTLS embedded memory/runtime framing"])
    save(fig, output)


def plot_certificate_cpu_wall_gap(
    rows: list[dict[str, str]], output: Path, run_id: str
) -> None:
    rows = [
        row for row in rows
        if (number(row, "mean_wall_ms") or 0.0) > 0 and (number(row, "mean_cpu_ms") or number(row, "mean_client_cpu_ms") or 0.0) > 0
    ]
    if not rows:
        print("warning: no certificate CPU/wall rows found")
        return
    rows = sorted(rows, key=certificate_sort_key)
    wall = [number(row, "mean_wall_ms") or 0.0 for row in rows]
    cpu = [
        number(row, "mean_cpu_ms") or number(row, "mean_client_cpu_ms") or 0.0
        for row in rows
    ]
    unexplained_us = [max(w - c, 0.0) * 1000.0 for w, c in zip(wall, cpu)]
    ratio = [min(100.0, 100.0 * c / w) if w > 0 else 0.0 for w, c in zip(wall, cpu)]
    y = np.arange(len(rows))
    fig, axes = plt.subplots(
        1, 2, figsize=(14, max(6, len(rows) * 0.42)), constrained_layout=True
    )
    bars = axes[0].barh(y, ratio, color=["#dc2626" if board_row(row) else "#2563eb" for row in rows])
    axes[0].set_title("Measured CPU occupancy")
    axes[0].set_xlabel("CPU time / wall time (%)")
    axes[0].set_xlim(0, 100)
    axes[0].set_yticks(y)
    axes[0].set_yticklabels([cert_label(row) for row in rows], fontsize=7)
    axes[0].grid(axis="x", color="#e5e7eb", linewidth=0.8)
    annotate_bars(axes[0], bars, ratio, "{:.2f}%")
    bars = axes[1].barh(y, unexplained_us, color=["#dc2626" if board_row(row) else "#2563eb" for row in rows])
    axes[1].set_title("Wall time not accounted for by CPU")
    axes[1].set_xlabel("Wall - CPU time (us, log scale)")
    axes[1].set_yticks(y)
    axes[1].set_yticklabels([])
    axes[1].grid(axis="x", color="#e5e7eb", linewidth=0.8)
    set_log_x(axes[1], unexplained_us)
    fig.suptitle(f"Certificate CPU vs wall time - {run_id}", fontsize=14)
    add_note(fig, ["resource-constrained PQ TLS time/memory evaluation"])
    save(fig, output)


def plot_certificate_server_os_pressure(
    rows: list[dict[str, str]], output: Path, run_id: str
) -> None:
    server = [row for row in rows if not board_row(row) and (number(row, "mean_wall_ms") or 0.0) > 0]
    if not server:
        print("warning: no server certificate rows found")
        return
    server = sorted(server, key=lambda row: number(row, "mean_wall_ms") or 0.0)
    labels = [f"{sig_level(row)} {row.get('cert_sig_alg', '')}" for row in server]
    y = np.arange(len(server))
    panels = (
        ("max_rss_kb", "Max RSS (KiB)", "#2563eb"),
        ("mean_voluntary_context_switches", "Voluntary context switches", "#0f766e"),
        ("mean_involuntary_context_switches", "Involuntary context switches", "#dc2626"),
        ("mean_major_page_faults", "Major page faults", "#f97316"),
        ("mean_block_input_ops", "Block input ops", "#7c3aed"),
        ("mean_block_output_ops", "Block output ops", "#64748b"),
    )
    fig, axes = plt.subplots(
        2, 3, figsize=(16, max(8, len(server) * 0.36)),
        constrained_layout=True,
    )
    for ax, (field, title, color) in zip(axes.flat, panels):
        values = [number(row, field) or 0.0 for row in server]
        ax.barh(y, values, color=color, edgecolor="#111827", linewidth=0.25)
        ax.set_title(title)
        ax.set_yticks(y)
        ax.set_yticklabels(labels if ax is axes.flat[0] else [], fontsize=7)
        ax.grid(axis="x", color="#e5e7eb", linewidth=0.8)
        set_log_x(ax, values)
    fig.suptitle(f"Server certificate OS/resource pressure - {run_id}", fontsize=14)
    add_note(fig, ["PQ TLS embedded memory/resource framing", "PQ auth TLS server-side throughput tradeoff"])
    save(fig, output)


def plot_certificate_board_dwt_density(
    rows: list[dict[str, str]], output: Path, run_id: str
) -> None:
    board = [
        row for row in rows
        if board_row(row) and any((number(row, f"mean_{phase}_core_cycles") or 0.0) > 0 for phase, _ in PHASES)
    ]
    if not board:
        print("warning: no board certificate DWT rows found")
        return
    labels = [cert_label(row) for row in sorted(board, key=certificate_sort_key)]
    board = sorted(board, key=certificate_sort_key)
    phase_labels = [label for _, label in PHASES]
    lsu = np.zeros((len(board), len(PHASES)))
    cpi = np.zeros_like(lsu)
    for y, row in enumerate(board):
        for x, (phase, _) in enumerate(PHASES):
            core = number(row, f"mean_{phase}_core_cycles") or 0.0
            if core > 0:
                lsu[y, x] = 1000.0 * (number(row, f"mean_{phase}_lsu_cycles") or 0.0) / core
                cpi[y, x] = 1000.0 * (number(row, f"mean_{phase}_cpi_cycles") or 0.0) / core
    fig, axes = plt.subplots(
        1, 2, figsize=(14, max(6, len(board) * 0.42)),
        constrained_layout=True,
    )
    for ax, matrix, title in (
        (axes[0], lsu, "LSU per 1k core cycles"),
        (axes[1], cpi, "CPI per 1k core cycles"),
    ):
        masked = np.ma.masked_where(matrix <= 0, matrix)
        image = ax.imshow(masked, aspect="auto", cmap="magma")
        ax.set_title(title)
        ax.set_xticks(range(len(PHASES)))
        ax.set_xticklabels(phase_labels, rotation=35, ha="right", fontsize=8)
        ax.set_yticks(range(len(board)))
        ax.set_yticklabels(labels if ax is axes[0] else [], fontsize=7)
        fig.colorbar(image, ax=ax)
    fig.suptitle(f"Board certificate DWT event density - {run_id}", fontsize=14)
    add_note(fig, ["pqm4 cycle-count benchmarking; event counters are modulo diagnostic values"])
    save(fig, output)


def plot_certificate(rows: list[dict[str, str]], out_dir: Path, run_id: str, ext: str) -> None:
    rows = successful(rows)
    plot_certificate_phase_costs(rows, out_dir / f"certificate_literature_phase_costs.{ext}", run_id)
    plot_certificate_time_size_tradeoff(rows, out_dir / f"certificate_literature_time_size_tradeoff.{ext}", run_id)
    plot_certificate_normalized_overhead(rows, out_dir / f"certificate_literature_normalized_overhead.{ext}", run_id)
    plot_certificate_cpu_wall_gap(rows, out_dir / f"certificate_literature_cpu_wall_gap.{ext}", run_id)
    plot_certificate_server_os_pressure(rows, out_dir / f"certificate_literature_server_os_pressure.{ext}", run_id)
    plot_certificate_board_dwt_density(rows, out_dir / f"certificate_literature_board_dwt_density.{ext}", run_id)


def plot_full_latency_heatmaps(rows: list[dict[str, str]], out_dir: Path, run_id: str, ext: str) -> None:
    plot_heatmap(
        rows, "mean_raw_handshake_ms",
        out_dir / f"full_literature_mean_handshake_heatmap.{ext}",
        run_id, "Mean TLS handshake time", "ms", log_scale=True,
    )
    plot_heatmap(
        rows, "p95_raw_handshake_ms",
        out_dir / f"full_literature_p95_handshake_heatmap.{ext}",
        run_id, "P95 TLS handshake time", "ms", log_scale=True,
    )
    plot_heatmap(
        rows, "mean_l2cap_tx_bytes",
        out_dir / f"full_literature_l2cap_tx_bytes_heatmap.{ext}",
        run_id, "L2CAP transmitted bytes", "bytes", log_scale=True,
    )
    plot_heatmap(
        rows, "max_client_heap_peak_usage_percent",
        out_dir / f"full_literature_heap_usage_heatmap.{ext}",
        run_id, "Board heap peak usage", "%", log_scale=False,
    )


def plot_full_size_latency(rows: list[dict[str, str]], output: Path, run_id: str) -> None:
    rows = [
        row for row in rows
        if (number(row, "mean_raw_handshake_ms") or 0.0) > 0 and total_tls_bytes(row) > 0
    ]
    if not rows:
        print("warning: no full benchmark size/latency rows found")
        return
    fig, ax = plt.subplots(figsize=(11.5, 7.5), constrained_layout=True)
    for row in rows:
        color = FAMILY_COLORS.get(kem_family(row), "#64748b")
        marker = "o" if sig_family(row) == "classic" else "s"
        ax.scatter(
            total_tls_bytes(row), number(row, "mean_raw_handshake_ms") or 0.0,
            s=max(35, min(260, (number(row, "max_client_heap_peak_usage_percent") or 1.0) * 3.0)),
            marker=marker, color=color, edgecolor="#111827", linewidth=0.35,
            alpha=0.72,
        )
    ax.set_title(f"TLS traffic size vs handshake latency - {run_id}")
    ax.set_xlabel("L2CAP tx bytes, or crypto material bytes when unavailable")
    ax.set_ylabel("Mean raw handshake time (ms, log scale)")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.grid(True, color="#e5e7eb", linewidth=0.8)
    ax.legend(
        handles=[
            plt.Line2D([0], [0], marker="o", color="w", markerfacecolor=FAMILY_COLORS["classic"], label="Classic KEX", markersize=8),
            plt.Line2D([0], [0], marker="o", color="w", markerfacecolor=FAMILY_COLORS["pqc"], label="PQC KEX", markersize=8),
            plt.Line2D([0], [0], marker="o", color="w", markerfacecolor=FAMILY_COLORS["hybrid"], label="Hybrid KEX", markersize=8),
            plt.Line2D([0], [0], marker="o", color="#111827", markerfacecolor="white", label="Classic cert", markersize=8),
            plt.Line2D([0], [0], marker="s", color="#111827", markerfacecolor="white", label="PQC cert", markersize=8),
        ],
        loc="lower right", fontsize=8,
    )
    add_note(fig, ["data-heavy PQ TLS handshake-size/tail-latency framing", "PQ auth TLS signature-size tradeoff"])
    save(fig, output)


def plot_full_layered_latency(rows: list[dict[str, str]], output: Path, run_id: str) -> None:
    rows = sorted(rows, key=lambda row: number(row, "p95_raw_handshake_ms") or number(row, "mean_raw_handshake_ms") or 0.0)[-30:]
    if not rows:
        print("warning: no full benchmark latency rows found")
        return
    labels = [f"{kem_level(row)} {row.get('kex_group','')} / {sig_level(row)} {row.get('cert_sig_alg','')}" for row in rows]
    fields = (
        ("mean_raw_handshake_ms", "TLS handshake", "#2563eb"),
        ("mean_mqtt_connect_ms", "MQTT connect", "#0f766e"),
        ("mean_full_connect_ms", "Full connect", "#f97316"),
        ("mean_end_to_end_ms", "End-to-end", "#7c3aed"),
    )
    y = np.arange(len(rows))
    height = 0.18
    offsets = np.linspace(-0.27, 0.27, len(fields))
    fig, ax = plt.subplots(figsize=(14, max(7, len(rows) * 0.36)), constrained_layout=True)
    all_values: list[float] = []
    for offset, (field, label, color) in zip(offsets, fields):
        values = [number(row, field) or 0.0 for row in rows]
        all_values.extend(values)
        ax.barh(y + offset, values, height=height, label=label, color=color, edgecolor="#111827", linewidth=0.25)
    p95 = [number(row, "p95_raw_handshake_ms") or 0.0 for row in rows]
    if any(p95):
        ax.scatter(p95, y + offsets[0], marker="|", s=120, color="#111827", label="Handshake p95")
        all_values.extend(p95)
    ax.set_title(f"Layered TLS timing for slowest successful cases - {run_id}")
    ax.set_xlabel("Time (ms, log scale)")
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=7)
    ax.grid(axis="x", color="#e5e7eb", linewidth=0.8)
    ax.legend(loc="lower right", fontsize=8)
    set_log_x(ax, all_values)
    add_note(fig, ["layered PQ TLS phase analysis", "data-heavy PQ TLS handshake percentile framing"])
    save(fig, output)


def plot_full_crypto_phase_heatmap(rows: list[dict[str, str]], output: Path, run_id: str) -> None:
    rows = [
        row for row in rows
        if any((number(row, field) or 0.0) > 0 for field, _ in TLS_CRYPTO_FIELDS)
    ]
    if not rows:
        print("warning: no full benchmark crypto phase rows found")
        return
    rows = sorted(rows, key=lambda row: number(row, "mean_raw_handshake_ms") or 0.0)[-40:]
    labels = [f"{row.get('kex_group','')} / {row.get('cert_sig_alg','')}" for row in rows]
    phases = [label for _, label in TLS_CRYPTO_FIELDS]
    matrix = np.array([
        [number(row, field) or 0.0 for field, _ in TLS_CRYPTO_FIELDS]
        for row in rows
    ])
    masked = np.ma.masked_where(matrix <= 0, matrix)
    vals = matrix[matrix > 0]
    norm = LogNorm(vmin=max(vals.min(), 0.001), vmax=vals.max()) if vals.size else None
    fig, ax = plt.subplots(figsize=(14, max(7, len(rows) * 0.30)), constrained_layout=True)
    image = ax.imshow(masked, aspect="auto", cmap="magma", norm=norm)
    ax.set_title(f"Measured cryptographic work inside TLS cases - {run_id}")
    ax.set_xlabel("Measured crypto operation")
    ax.set_ylabel("Slowest successful KEM / certificate combinations")
    ax.set_xticks(range(len(phases)))
    ax.set_xticklabels(phases, rotation=45, ha="right", fontsize=8)
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels(labels, fontsize=6)
    fig.colorbar(image, ax=ax, label="ms, log scale")
    add_note(fig, ["layered PQ TLS per-stage analysis", "PQ auth TLS signature verification/signing cost"])
    save(fig, output)


def plot_full_pi_perf(rows: list[dict[str, str]], output: Path, run_id: str) -> None:
    prefixes = [prefix for prefix in ("pi_broker", "pi_bridge") if f"mean_{prefix}_perf_cycles" in rows[0]]
    if not prefixes:
        print("warning: no Raspberry Pi perf fields found")
        return
    rows = sorted(rows, key=lambda row: number(row, "mean_raw_handshake_ms") or 0.0)[-30:]
    labels = [f"{row.get('kex_group','')} / {row.get('cert_sig_alg','')}" for row in rows]
    metrics = []
    for prefix in prefixes:
        ipc = []
        cache_miss = []
        backend_stall = []
        for row in rows:
            cycles = number(row, f"mean_{prefix}_perf_cycles") or 0.0
            instructions = number(row, f"mean_{prefix}_perf_instructions") or 0.0
            cache_refs = number(row, f"mean_{prefix}_perf_cache_references") or 0.0
            cache_misses = number(row, f"mean_{prefix}_perf_cache_misses") or 0.0
            stalls = number(row, f"mean_{prefix}_perf_stalled_cycles_backend") or 0.0
            ipc.append(instructions / cycles if cycles > 0 else 0.0)
            cache_miss.append(100.0 * cache_misses / cache_refs if cache_refs > 0 else 0.0)
            backend_stall.append(100.0 * stalls / cycles if cycles > 0 else 0.0)
        metrics.extend([
            (f"{prefix} IPC", ipc),
            (f"{prefix} cache miss %", cache_miss),
            (f"{prefix} backend stall %", backend_stall),
        ])
    y = np.arange(len(rows))
    fig, axes = plt.subplots(
        1, len(metrics), figsize=(max(12, len(metrics) * 4.2), max(7, len(rows) * 0.33)),
        constrained_layout=True, squeeze=False,
    )
    for ax, (title, values) in zip(axes.flat, metrics):
        ax.barh(y, values, color="#2563eb", edgecolor="#111827", linewidth=0.25)
        ax.set_title(title)
        ax.set_yticks(y)
        ax.set_yticklabels(labels if ax is axes.flat[0] else [], fontsize=6)
        ax.grid(axis="x", color="#e5e7eb", linewidth=0.8)
    fig.suptitle(f"Raspberry Pi perf counters for slowest successful cases - {run_id}", fontsize=14)
    add_note(fig, ["resource-constrained PQ TLS server-side resource evaluation"])
    save(fig, output)


def plot_full(rows: list[dict[str, str]], out_dir: Path, run_id: str, ext: str) -> None:
    rows = successful(rows)
    rows = [row for row in rows if number(row, "mean_raw_handshake_ms") is not None]
    plot_full_latency_heatmaps(rows, out_dir, run_id, ext)
    plot_full_size_latency(rows, out_dir / f"full_literature_size_latency.{ext}", run_id)
    plot_full_layered_latency(rows, out_dir / f"full_literature_layered_latency.{ext}", run_id)
    plot_full_crypto_phase_heatmap(rows, out_dir / f"full_literature_crypto_phase_heatmap.{ext}", run_id)
    if rows:
        plot_full_pi_perf(rows, out_dir / f"full_literature_pi_perf.{ext}", run_id)


def plot_kem(run_dir: Path, out_dir: Path, run_id: str, ext: str) -> None:
    rows = load_kem_rows(run_dir)
    plot_kem_operation_costs(rows, out_dir / f"kem_literature_operation_costs.{ext}", run_id)
    plot_kem_resource_tradeoff(rows, out_dir / f"kem_literature_resource_tradeoff.{ext}", run_id)
    plot_kem_normalized_overhead(rows, out_dir / f"kem_literature_normalized_overhead.{ext}", run_id)
    plot_kem_efficiency(rows, out_dir / f"kem_literature_efficiency.{ext}", run_id)
    plot_kem_memory_budget(rows, out_dir / f"kem_literature_memory_budget.{ext}", run_id)
    plot_kem_dwt_density(rows, out_dir / f"kem_literature_dwt_density.{ext}", run_id)
    write_kem_reference_file(out_dir)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", help="Benchmark result run id or path containing summary.csv.")
    parser.add_argument("--out-dir", type=Path, help="Defaults to graphic/out/<run_id>.")
    parser.add_argument("--format", default="png", choices=("png", "pdf", "svg"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    run_dir = resolve_run_dir(args.run)
    run_id = run_dir.name
    out_dir = args.out_dir or ROOT / "graphic" / "out" / run_id
    rows, fields = read_summary(run_dir)
    run_type = detect_run_type(fields)
    if run_type == "kem":
        plot_kem(run_dir, out_dir, run_id, args.format)
    elif run_type == "certificate":
        plot_certificate(rows, out_dir, run_id, args.format)
    elif run_type == "full":
        plot_full(rows, out_dir, run_id, args.format)
    write_reference_file(out_dir)
    print(out_dir / "literature_references.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
