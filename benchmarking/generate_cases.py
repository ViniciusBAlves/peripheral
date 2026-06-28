#!/usr/bin/env python3
"""Generate reproducible raw BLE TLS/MQTT benchmark cases."""

from __future__ import annotations

import argparse
import csv
import random
from datetime import datetime
from pathlib import Path

from benchmarklib.algorithms import KEMS, SIGNATURES, slug


ROOT = Path(__file__).resolve().parent
FIELDS = [
    "case_id", "enabled",
    "kex_group", "kex_family", "kex_nist_level",
    "kex_public_key_bytes", "kex_ciphertext_bytes", "kex_shared_secret_bytes",
    "cert_sig_alg", "sig_family", "sig_nist_level",
    "sig_public_key_bytes", "sig_private_key_bytes", "sig_signature_bytes",
    "certificate_verify_alg", "iterations", "warmup_iterations",
    "expected_support", "notes",
]


def build_cases(iterations: int, warmups: int, separate: bool) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for kem in KEMS:
        for signature in SIGNATURES:
            if separate and kem.family != signature.family:
                continue
            rows.append(
                {
                    "case_id": f"{slug(kem.name)}__{slug(signature.name)}",
                    "enabled": "1",
                    "kex_group": kem.name,
                    "kex_family": kem.family,
                    "kex_nist_level": str(kem.nist_level),
                    "kex_public_key_bytes": str(kem.public_key_bytes),
                    "kex_ciphertext_bytes": str(kem.ciphertext_bytes),
                    "kex_shared_secret_bytes": str(kem.shared_secret_bytes),
                    "cert_sig_alg": signature.name,
                    "sig_family": signature.family,
                    "sig_nist_level": str(signature.nist_level),
                    "sig_public_key_bytes": str(signature.public_key_bytes),
                    "sig_private_key_bytes": str(signature.private_key_bytes),
                    "sig_signature_bytes": str(signature.signature_bytes),
                    "certificate_verify_alg": signature.certificate_verify,
                    "iterations": str(iterations),
                    "warmup_iterations": str(warmups),
                    "expected_support": signature.expected_support,
                    "notes": signature.notes or (
                        "SLH-DSA signs the chain; TLS CertificateVerify uses ECDSA"
                        if signature.name.startswith("SLH-DSA") else ""
                    ),
                }
            )
    return rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--warmup-iterations", type=int, default=1)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--no-shuffle", action="store_true")
    parser.add_argument("--separate-pqc-classic", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.iterations < 1 or args.warmup_iterations < 0:
        raise ValueError("iterations must be positive and warmups cannot be negative")
    seed = args.seed if args.seed is not None else random.SystemRandom().randint(1, 2**31 - 1)
    rows = build_cases(args.iterations, args.warmup_iterations, args.separate_pqc_classic)
    if not args.no_shuffle:
        random.Random(seed).shuffle(rows)
    output = args.output or ROOT / "cases" / f"{datetime.now():%Y%m%d_%H%M%S}_benchmark_cases.csv"
    if output.exists():
        raise FileExistsError(f"refusing to overwrite {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"seed={seed}")
    print(f"cases={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
