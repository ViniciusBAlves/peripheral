#!/usr/bin/env python3
"""Generate the final-dataset figures used by benchmarking/main.tex."""

from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from scipy.stats import spearmanr

from plot_tls_handshake_bars import add_total_memory_metrics, pki_category


ROOT = Path(__file__).resolve().parents[1]
HANDSHAKE = ROOT / "benchmarking/results/final_bench_results"
TRANSFER = ROOT / "benchmarking/results/final_transfer_bench_results"
OUT = ROOT / "benchmarking/presentation_graphics"
KEX = [
    "ECDHE-P-256", "ECDHE-P-384", "ECDHE-P-521", "MLKEM512", "MLKEM768",
    "MLKEM1024", "SecP256r1MLKEM768", "X25519MLKEM768", "SecP384r1MLKEM1024",
]
KEX_LABELS = [
    "ECDHE\nP-256", "ECDHE\nP-384", "ECDHE\nP-521", "ML-KEM\n512",
    "ML-KEM\n768", "ML-KEM\n1024", "P256 +\nML768", "X25519 +\nML768",
    "P384 +\nML1024",
]
HOM = [
    ("homogeneous_ecdsa_p_256", "ECDSA-P-256"),
    ("homogeneous_ecdsa_p_521", "ECDSA-P-521"),
    ("homogeneous_ml_dsa_44", "ML-DSA-44"),
    ("homogeneous_ml_dsa_87", "ML-DSA-87"),
    ("homogeneous_slh_dsa_shake_128s", "SLH-SHAKE-128s"),
    ("homogeneous_slh_dsa_shake_256s", "SLH-SHAKE-256s"),
    ("homogeneous_slh_dsa_shake_256f", "SLH-SHAKE-256f"),
    ("homogeneous_lms_hss_l2_h10_w4", "LMS-HSS"),
    ("homogeneous_xmss_sha2_20_256", "XMSS"),
]
HET = [
    ("root_rsa_pss_3072__leaf_ml_dsa_44", "RSA-3072 / ML-DSA-44"),
    ("root_rsa_pss_15360__leaf_ml_dsa_87", "RSA-15360 / ML-DSA-87"),
    ("root_slh_dsa_shake_128s__leaf_ecdsa_p_256", "SLH-128s / ECDSA-256"),
    ("root_slh_dsa_shake_128s__leaf_ml_dsa_44", "SLH-128s / ML-DSA-44"),
    ("root_slh_dsa_shake_256f__leaf_ecdsa_p_521", "SLH-256f / ECDSA-521"),
    ("root_slh_dsa_shake_256f__leaf_ml_dsa_87", "SLH-256f / ML-DSA-87"),
    ("root_lms_hss_l2_h10_w4__leaf_ml_dsa_87", "LMS-HSS / ML-DSA-87"),
    ("root_xmss_sha2_20_256__leaf_ml_dsa_87", "XMSS / ML-DSA-87"),
]
# IDs A--G are shared by the resource, CPU and workload figures and slides.
CANDIDATES = [
    ("A", "ecdhe_p_256__homogeneous_ecdsa_p_256", "Classical baseline"),
    ("B", "mlkem512__homogeneous_ml_dsa_44", "Lattice baseline"),
    ("C", "mlkem1024__homogeneous_lms_hss_l2_h10_w4", "Stateful X.509"),
    ("D", "mlkem512__homogeneous_slh_dsa_shake_128s", "Stateless X.509"),
    ("E", "mlkem512__root_slh_dsa_shake_128s__leaf_ml_dsa_44", "Heavy-root transition"),
    ("F", "secp384r1mlkem1024__homogeneous_slh_dsa_shake_256f", "Stress case"),
    ("G", "mlkem1024__homogeneous_ml_dsa_87", "Higher lattice parameters"),
]
COLORS = ["#626b73", "#197c78", "#467bad", "#b28521", "#76629b", "#ba4943", "#337f46"]


def read_rows(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def value(row, key):
    return float(row[key])


def validate_raw(rows, transfers):
    """Reject stale summaries before producing presentation claims."""
    by_id = {r["case_id"]: r for r in rows}
    statuses = Counter()
    valid_count = 0
    for path in sorted(HANDSHAKE.glob("cases/*/attempts.csv")):
        case = path.parent.name.split("_", 1)[1]
        attempts = read_rows(path)
        assert len(attempts) == 50, case
        statuses.update(r["status"] for r in attempts)
        valid = [r for r in attempts if r["status"] == "success" and r["warmup"] == "0"]
        assert len(valid) == int(by_id[case]["success_count"]), case
        assert all(r["power_status"] == "success" for r in valid), case
        valid_count += len(valid)
        for metric in ("raw_handshake_ms", "handshake_energy_uj", "client_cpu_ms"):
            actual = mean(value(r, metric) for r in valid)
            assert abs(actual - value(by_id[case], f"mean_{metric}")) < 0.001, (case, metric)
    groups = defaultdict(list)
    transfer_statuses = Counter()
    for path in sorted(TRANSFER.glob("cases/*/transmissions.csv")):
        case = path.parent.name.split("_", 1)[1]
        for row in read_rows(path):
            transfer_statuses[row["status"]] += 1
            if row["status"] == "success" and row["round_complete"] == "1":
                assert row["power_status"] == "success" and row["integrity_match"] == "1"
                groups[case, row["direction"], row["payload_bytes"]].append(row)
    assert len(groups) == len(transfers) == 4212
    for row in transfers:
        group = groups[row["case_id"], row["direction"], row["payload_bytes"]]
        assert len(group) == int(row["success_count"]) == 10
        for metric in ("end_to_end_ms", "transfer_energy_uj"):
            assert abs(mean(value(r, metric) for r in group) - value(row, f"mean_{metric}")) < 0.001
    return {"handshake_statuses": dict(statuses), "valid_handshakes": valid_count,
            "transfer_statuses": dict(transfer_statuses), "transfers_per_cell": 10}


def save(fig, name, note):
    fig.text(0.02, 0.02, note, fontsize=9, color="#444444")
    fig.canvas.draw()
    renderer = fig.canvas.get_renderer()
    box = fig.get_tightbbox(renderer)
    width, height = fig.get_size_inches()
    assert box.x0 >= 0 and box.y0 >= 0 and box.x1 <= width and box.y1 <= height, name
    fig.savefig(OUT / f"{name}.pdf", facecolor="white")
    fig.savefig(OUT / f"{name}.png", dpi=160, facecolor="white")
    plt.close(fig)


def heatmap(rows, profiles, metric, scale, vmax, title, filename):
    lookup = {(r["pki_chain_id"], r["kex_group"]): r for r in rows}
    data = np.array([
        [value(lookup[p, k], metric) / scale for k in KEX] for p, _ in profiles
    ])
    assert np.isfinite(data).all() and data.min() >= 0 and data.max() <= vmax
    fig, ax = plt.subplots(figsize=(12, 6.4))
    fig.subplots_adjust(left=0.27, right=0.93, bottom=0.17, top=0.91)
    im = ax.imshow(data, cmap="YlGnBu", vmin=0, vmax=vmax, aspect="auto")
    ax.set_xticks(range(len(KEX)), KEX_LABELS, fontsize=10)
    ax.set_yticks(range(len(profiles)), [label for _, label in profiles], fontsize=11)
    ax.tick_params(length=0)
    for y in range(data.shape[0]):
        for x in range(data.shape[1]):
            ax.text(x, y, f"{data[y, x]:.1f}", ha="center", va="center",
                    fontsize=10, color="white" if data[y, x] > vmax * 0.55 else "#16232c")
    ax.set_title(title, loc="left", pad=12, fontsize=15)
    fig.colorbar(im, ax=ax, fraction=0.028, pad=0.02)
    save(fig, filename, "Selected PKIs; all 9 KEX groups. Means of successful attempts; shared scales across PKI layouts.")


def comparisons(by_id):
    ids = [CANDIDATES[0][1], CANDIDATES[1][1],
           "secp256r1mlkem768__homogeneous_ml_dsa_44",
           "ecdhe_p_521__homogeneous_ecdsa_p_521", CANDIDATES[6][1]]
    labels = ["ECDHE-P-256 / ECDSA-P-256", "MLKEM512 / ML-DSA-44",
              "P256+MLKEM768 / ML-DSA-44", "ECDHE-P-521 / ECDSA-P-521",
              "MLKEM1024 / ML-DSA-87"]
    fig, axes = plt.subplots(1, 2, figsize=(12, 6.4), sharey=True)
    fig.subplots_adjust(left=0.32, right=0.95, bottom=0.16, top=0.9, wspace=0.22)
    for ax, metric, title in zip(axes, ("mean_raw_handshake_ms", "mean_handshake_energy_uj"),
                               ("Handshake time (s)", "Handshake energy (mJ)")):
        vals = [value(by_id[i], metric) / 1000 for i in ids]
        ax.barh(range(5), vals, color=[COLORS[i] for i in (0, 1, 4, 0, 6)], height=0.58)
        if metric == "mean_raw_handshake_ms":
            ax.errorbar(vals, range(5), xerr=[value(by_id[i], "stddev_raw_handshake_ms") / 1000 for i in ids],
                        fmt="none", ecolor="#222222", capsize=3)
        ax.set_yticks(range(5), labels, fontsize=11)
        ax.set_xlim(0, max(vals) * 1.23)
        ax.set_title(title, fontsize=14)
        ax.grid(axis="x", alpha=0.2)
        ax.set_axisbelow(True)
        for y, v in enumerate(vals):
            ax.text(v + max(vals) * 0.025, y, f"{v:.2f}", va="center", fontsize=12)
    axes[0].invert_yaxis()
    save(fig, "switching_cost", "Homogeneous X.509; case means. Time whiskers: 1 SD, not CI. Parameter sets are not identical security categories.")


def resources(by_id):
    rows = [by_id[c] for _, c, _ in CANDIDATES]
    labels = [f"{a}  {label}" for a, _, label in CANDIDATES]
    fig, axes = plt.subplots(1, 2, figsize=(12, 6.4), sharey=True)
    fig.subplots_adjust(left=0.25, right=0.96, bottom=0.16, top=0.9, wspace=0.2)
    for ax, metric, scale, title, limit in zip(
        axes, ("max_client_heap_peak_bytes", "max_thread_stack_peak_percent"),
        (1024, 1), ("wolfSSL heap peak (KiB)", "Worst thread stack peak (%)"), (225, 110),
    ):
        vals = [value(r, metric) / scale for r in rows]
        ax.barh(range(7), vals, color=COLORS, height=0.62)
        ax.set_yticks(range(7), labels, fontsize=11)
        ax.set_xlim(0, limit)
        ax.set_title(title, fontsize=14)
        ax.grid(axis="x", alpha=0.2)
        ax.set_axisbelow(True)
        for y, v in enumerate(vals):
            ax.text(v + limit * 0.012, y, f"{v:.1f}", va="center", fontsize=11)
    axes[0].invert_yaxis()
    axes[1].axvline(100, color="#555555", linestyle="--", linewidth=1)
    save(fig, "selected_resources", "Maxima over successful attempts. Stack = highest individual thread percentage, not total stack occupancy. IDs: slides.")


def cpu_scatter(rows, layout):
    fig, ax = plt.subplots(figsize=(12, 6.4))
    fig.subplots_adjust(left=0.1, right=0.97, bottom=0.16, top=0.9)
    for prefix, label, color in (("ECDHE", "ECDHE", COLORS[0]), ("MLKEM", "ML-KEM", COLORS[1]),
                                  (None, "Hybrid", COLORS[4])):
        group = [r for r in rows if (r["kex_group"].startswith(prefix) if prefix else
                 not r["kex_group"].startswith(("ECDHE", "MLKEM")))]
        ax.scatter([value(r, "mean_raw_handshake_ms") / 1000 for r in group],
                   [value(r, "mean_client_cpu_ms") / 1000 for r in group],
                   color=color, label=label, s=32, alpha=0.75, edgecolors="white", linewidth=0.3)
    ax.plot([0, 24], [0, 24], "--", color="#555555", linewidth=1, label="CPU time = elapsed time")
    ax.set(xlim=(0, 24), ylim=(0, 12), xlabel="Mean TLS handshake elapsed time (s)",
           ylabel="Mean benchmark-thread CPU time (s)", title=f"{layout.capitalize()} PKI: one point per case")
    ax.legend(loc="upper left", frameon=False, fontsize=11)
    for letter, case, _ in CANDIDATES:
        found = next((r for r in rows if r["case_id"] == case), None)
        if found and letter in ("A", "D", "E", "F", "G"):
            ax.annotate(letter, (value(found, "mean_raw_handshake_ms") / 1000,
                                value(found, "mean_client_cpu_ms") / 1000),
                        xytext=(5, 8), textcoords="offset points", fontsize=12, fontweight="bold")
    ax.grid(alpha=0.2)
    save(fig, f"cpu_{layout}", "All cases in this layout; successful-attempt means. Distance from the identity line is not a radio-airtime measurement.")


def workload(by_id, transfers):
    index = {(r["case_id"], int(r["payload_bytes"]), r["direction"]): r for r in transfers}
    fig, axes = plt.subplots(1, 2, figsize=(12, 6.4))
    fig.subplots_adjust(left=0.08, right=0.97, bottom=0.17, top=0.84, wspace=0.26)
    shares = {}
    for ax, size in zip(axes, (128, 65536)):
        h = np.array([value(by_id[c], "mean_handshake_energy_uj") / 1000 for _, c, _ in CANDIDATES])
        t = np.array([50 * sum(value(index[c, size, d], "mean_transfer_energy_uj") for d in
                              ("device_to_server", "server_to_device")) / 1000 for _, c, _ in CANDIDATES])
        ax.bar(range(7), h, color=COLORS[4], label="One handshake")
        ax.bar(range(7), t, bottom=h, color=COLORS[1], label="100 transfers (50 + 50)")
        ax.set_xticks(range(7), [c[0] for c in CANDIDATES])
        ax.set_title("128 B per transfer" if size == 128 else "64 KiB per transfer", fontsize=14)
        ax.set_ylabel("Bundle energy (mJ)")
        ax.set_ylim(0, max(h + t) * 1.17)
        ax.grid(axis="y", alpha=0.2)
        ax.set_axisbelow(True)
        for i, (hv, tv) in enumerate(zip(h, t)):
            share = 100 * hv / (hv + tv)
            shares[f"{CANDIDATES[i][0]}_{size}"] = float(share)
            ax.text(i, hv + tv + max(h + t) * 0.025, f"{share:.1f}%", ha="center", fontsize=10)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 0.98),
               ncols=2, frameon=False, fontsize=11)
    save(fig, "handshake_amortization", "Labels = handshake share. Case-paired final datasets; 100 transfers is a workload assumption, not the repetition count.")
    return shares


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 12,
                         "axes.spines.top": False, "axes.spines.right": False,
                         "pdf.fonttype": 42})
    rows = read_rows(HANDSHAKE / "summary.csv")
    transfers = read_rows(TRANSFER / "transfer_summary.csv")
    assert len(rows) == 351 and len(transfers) == 4212
    add_total_memory_metrics(rows)
    by_id = {r["case_id"]: r for r in rows}
    assert len(by_id) == 351
    audit = {"handshake_cases": len(rows), "transfer_cells": len(transfers),
             "raw_validation": validate_raw(rows, transfers), "layouts": {}}
    for layout, profiles in (("homogeneous", HOM), ("heterogeneous", HET)):
        group = [r for r in rows if pki_category(r) == layout]
        metrics = ("mean_raw_handshake_ms", "mean_handshake_energy_uj", "max_client_heap_peak_usage_percent")
        audit["layouts"][layout] = {
            "cases": len(group), "plotted_profiles": [p for p, _ in profiles],
            "ranges": {m: [min(value(r, m) for r in group), max(value(r, m) for r in group)] for m in metrics},
            "spearman_case_mean_time_energy": float(spearmanr(
                [value(r, metrics[0]) for r in group], [value(r, metrics[1]) for r in group]).statistic),
        }
        heatmap(group, profiles, metrics[0], 1000, 24, f"{layout.capitalize()} X.509: handshake time (s)", f"time_{layout}")
        heatmap(group, profiles, metrics[1], 1000, 185, f"{layout.capitalize()} X.509: handshake energy (mJ)", f"energy_{layout}")
        cpu_scatter(group, layout)
    comparisons(by_id)
    resources(by_id)
    audit["handshake_share_percent"] = workload(by_id, transfers)
    # Keep the existing transfer section self-contained in the same asset folder.
    for direction in ("device_to_server", "server_to_device"):
        group = [dict(r, pki_chain_id=by_id[r["case_id"]]["pki_chain_id"],
                      kex_group=by_id[r["case_id"]]["kex_group"]) for r in transfers
                 if r["direction"] == direction and r["payload_bytes"] == "65536"]
        heatmap(group, HOM, "mean_end_to_end_ms", 1000, 7,
                f"64 KiB: {direction.replace('_', ' ')} time (s)", f"transfer_65536_{direction}")
    selected = [dict(by_id[c], slide_id=a, role=label) for a, c, label in CANDIDATES]
    with (OUT / "selected_cases.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(selected[0]))
        writer.writeheader()
        writer.writerows(selected)
    sources = [HANDSHAKE / "summary.csv", HANDSHAKE / "merge_sources.json",
               TRANSFER / "transfer_summary.csv", TRANSFER / "merge_manifest.json"]
    audit["source_sha256"] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    (OUT / "audit.json").write_text(json.dumps(audit, indent=2) + "\n")
    print(json.dumps(audit, indent=2))


if __name__ == "__main__":
    main()
