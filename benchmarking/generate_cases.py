#!/usr/bin/env python3
"""Generate reproducible raw BLE TLS/MQTT benchmark cases."""

from __future__ import annotations

import argparse
import csv
import random
from datetime import datetime
from pathlib import Path

from benchmarklib.algorithms import (
    HEAVY_HOMOGENEOUS_CHAINS,
    KEMS,
    PKI_CHAINS,
    SIGNATURES_BY_NAME,
    slug,
)


ROOT = Path(__file__).resolve().parent
FIELDS = [
    "case_id", "enabled",
    "pki_chain_id", "pki_kind", "root_sig_alg",
    "intermediate_sig_alg", "leaf_sig_alg",
    "kex_group", "kex_family", "kex_nist_level",
    "kex_public_key_bytes", "kex_ciphertext_bytes", "kex_shared_secret_bytes",
    "cert_sig_alg", "sig_family", "sig_nist_level",
    "sig_public_key_bytes", "sig_private_key_bytes", "sig_signature_bytes",
    "certificate_verify_alg", "iterations", "warmup_iterations",
    "expected_support", "notes",
]


def build_cases(
    iterations: int,
    warmups: int,
    separate: bool,
    include_heavy_homogeneous: bool = False,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    chains = PKI_CHAINS + (
        HEAVY_HOMOGENEOUS_CHAINS if include_heavy_homogeneous else ()
    )
    for kem in KEMS:
        for chain in chains:
            signature = SIGNATURES_BY_NAME[chain.leaf_sig_alg]
            if separate and kem.family != signature.family:
                continue
            rows.append(
                {
                    "case_id": f"{slug(kem.name)}__{chain.id}",
                    "enabled": "1",
                    "pki_chain_id": chain.id,
                    "pki_kind": chain.kind,
                    "root_sig_alg": chain.root_sig_alg,
                    "intermediate_sig_alg": chain.intermediate_sig_alg,
                    "leaf_sig_alg": chain.leaf_sig_alg,
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
                    "certificate_verify_alg": signature.tls_signature_scheme,
                    "iterations": str(iterations),
                    "warmup_iterations": str(warmups),
                    "expected_support": signature.expected_support,
                    "notes": (
                        f"{signature.name} signs all X.509 certificates; "
                        "TLS CertificateVerify uses ECDSA"
                        if chain.kind == "homogeneous_x509" and
                        signature.name.startswith(("SLH-DSA", "LMS-", "XMSS-"))
                        else signature.notes
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
    parser.add_argument(
        "--include-heavy-homogeneous",
        action="store_true",
        help=("also generate homogeneous X.509 chains for SLH-DSA-SHAKE, "
              "RSA-PSS, LMS and XMSS"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.iterations < 1 or args.warmup_iterations < 0:
        raise ValueError("iterations must be positive and warmups cannot be negative")
    seed = args.seed if args.seed is not None else random.SystemRandom().randint(1, 2**31 - 1)
    rows = build_cases(
        args.iterations,
        args.warmup_iterations,
        args.separate_pqc_classic,
        args.include_heavy_homogeneous,
    )
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
