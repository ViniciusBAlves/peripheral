from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Kem:
    name: str
    nist_level: int
    public_key_bytes: int
    ciphertext_bytes: int
    shared_secret_bytes: int
    family: str
    wolfssl_group: str
    openssl_group: str


@dataclass(frozen=True)
class Signature:
    name: str
    nist_level: int
    public_key_bytes: int
    private_key_bytes: int
    signature_bytes: int
    family: str
    issuer_key_type: str
    leaf_key_type: str
    certificate_verify: str
    tls_signature_scheme: str
    tls_signature_scheme_id: int
    expected_support: str = "required"
    notes: str = ""


@dataclass(frozen=True)
class PkiChain:
    id: str
    kind: str
    root_sig_alg: str
    intermediate_sig_alg: str
    leaf_sig_alg: str


KEMS = (
    Kem("ECDHE-P-256", 1, 65, 65, 32, "classic", "WOLFSSL_ECC_SECP256R1", "P-256"),
    Kem("ECDHE-P-384", 3, 97, 97, 48, "classic", "WOLFSSL_ECC_SECP384R1", "P-384"),
    Kem("ECDHE-P-521", 5, 133, 133, 66, "classic", "WOLFSSL_ECC_SECP521R1", "P-521"),
    Kem("MLKEM512", 1, 800, 768, 32, "pqc", "WOLFSSL_ML_KEM_512", "MLKEM512"),
    Kem("MLKEM768", 3, 1184, 1088, 32, "pqc", "WOLFSSL_ML_KEM_768", "MLKEM768"),
    Kem("MLKEM1024", 5, 1568, 1568, 32, "pqc", "WOLFSSL_ML_KEM_1024", "MLKEM1024"),
    Kem(
        "SecP256r1MLKEM768", 3, 1249, 1153, 64, "pqc",
        "WOLFSSL_SECP256R1MLKEM768", "SecP256r1MLKEM768",
    ),
    Kem(
        "X25519MLKEM768", 3, 1216, 1120, 64, "pqc",
        "WOLFSSL_X25519MLKEM768", "X25519MLKEM768",
    ),
    Kem(
        "SecP384r1MLKEM1024", 5, 1665, 1665, 80, "pqc",
        "WOLFSSL_SECP384R1MLKEM1024", "SecP384r1MLKEM1024",
    ),
)

SIGNATURES = (
    Signature("ECDSA-P-256", 1, 65, 32, 64, "classic",
              "ec:prime256v1", "ec:prime256v1", "ECDSA-P-256",
              "ecdsa_secp256r1_sha256", 0x0403),
    Signature("ECDSA-P-384", 3, 97, 48, 96, "classic",
              "ec:secp384r1", "ec:secp384r1", "ECDSA-P-384",
              "ecdsa_secp384r1_sha384", 0x0503),
    Signature("ECDSA-P-521", 5, 133, 66, 132, "classic",
              "ec:secp521r1", "ec:secp521r1", "ECDSA-P-521",
              "ecdsa_secp521r1_sha512", 0x0603),
    Signature("RSA-PSS-3072", 1, 384, 384, 384, "classic",
              "RSA-PSS-3072", "RSA-PSS-3072", "RSA-PSS-3072",
              "rsa_pss_rsae_sha256", 0x0804),
    Signature("RSA-PSS-7680", 3, 960, 960, 960, "classic",
              "RSA-PSS-7680", "RSA-PSS-7680", "RSA-PSS-7680",
              "rsa_pss_rsae_sha384", 0x0805),
    Signature("RSA-PSS-15360", 5, 1920, 1920, 1920, "classic",
              "RSA-PSS-15360", "RSA-PSS-15360", "RSA-PSS-15360",
              "rsa_pss_rsae_sha512", 0x0806),
    Signature("ML-DSA-44", 2, 1312, 2560, 2420, "pqc",
              "ML-DSA-44", "ML-DSA-44", "ML-DSA-44",
              "mldsa44", 0x0904),
    Signature("ML-DSA-65", 3, 1952, 4032, 3309, "pqc",
              "ML-DSA-65", "ML-DSA-65", "ML-DSA-65",
              "mldsa65", 0x0905),
    Signature("ML-DSA-87", 5, 2592, 4896, 4627, "pqc",
              "ML-DSA-87", "ML-DSA-87", "ML-DSA-87",
              "mldsa87", 0x0906),
    # Current OpenSSL/wolfSSL TLS stacks use an ECDSA leaf for CertificateVerify.
    Signature("SLH-DSA-SHAKE-128s", 1, 32, 64, 7856, "pqc",
              "SLH-DSA-SHAKE-128s", "ec:prime256v1", "ECDSA-P-256",
              "ecdsa_secp256r1_sha256", 0x0403),
    Signature("SLH-DSA-SHAKE-128f", 1, 32, 64, 17088, "pqc",
              "SLH-DSA-SHAKE-128f", "ec:prime256v1", "ECDSA-P-256",
              "ecdsa_secp256r1_sha256", 0x0403),
    Signature("SLH-DSA-SHAKE-192s", 3, 48, 96, 16224, "pqc",
              "SLH-DSA-SHAKE-192s", "ec:secp384r1", "ECDSA-P-384",
              "ecdsa_secp384r1_sha384", 0x0503),
    Signature("SLH-DSA-SHAKE-192f", 3, 48, 96, 35664, "pqc",
              "SLH-DSA-SHAKE-192f", "ec:secp384r1", "ECDSA-P-384",
              "ecdsa_secp384r1_sha384", 0x0503),
    Signature("SLH-DSA-SHAKE-256s", 5, 64, 128, 29792, "pqc",
              "SLH-DSA-SHAKE-256s", "ec:secp521r1", "ECDSA-P-521",
              "ecdsa_secp521r1_sha512", 0x0603),
    Signature("SLH-DSA-SHAKE-256f", 5, 64, 128, 49856, "pqc",
              "SLH-DSA-SHAKE-256f", "ec:secp521r1", "ECDSA-P-521",
              "ecdsa_secp521r1_sha512", 0x0603),
    Signature("LMS-HSS-L2-H10-W4", 5, 60, 64, 5076, "pqc",
              "LMS-HSS-L2-H10-W4", "ec:prime256v1", "ECDSA-P-256",
              "ecdsa_secp256r1_sha256", 0x0403,
              notes="LMS/HSS signs the chain; TLS CertificateVerify uses ECDSA"),
    Signature("XMSS-SHA2_20_256", 5, 68, 2573, 2820, "pqc",
              "XMSS-SHA2_20_256", "ec:prime256v1", "ECDSA-P-256",
              "ecdsa_secp256r1_sha256", 0x0403,
              notes="XMSS signs the chain; TLS CertificateVerify uses ECDSA"),
)

KEMS_BY_NAME = {item.name: item for item in KEMS}
SIGNATURES_BY_NAME = {item.name: item for item in SIGNATURES}


def slug(value: str) -> str:
    return re.sub(r"_+", "_", re.sub(r"[^a-z0-9]+", "_", value.lower())).strip("_")


LIGHT_SIGNATURES_BY_LEVEL = {
    1: ("ECDSA-P-256", "ML-DSA-44"),
    3: ("ECDSA-P-384", "ML-DSA-65"),
    5: ("ECDSA-P-521", "ML-DSA-87"),
}

HEAVY_ROOTS_BY_LEVEL = {
    1: ("SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f", "RSA-PSS-3072"),
    3: ("SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "RSA-PSS-7680"),
    5: (
        "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f", "RSA-PSS-15360",
        "LMS-HSS-L2-H10-W4", "XMSS-SHA2_20_256",
    ),
}


def _pki_chains() -> tuple[PkiChain, ...]:
    chains: list[PkiChain] = []
    for signatures in LIGHT_SIGNATURES_BY_LEVEL.values():
        for signature in signatures:
            chains.append(PkiChain(
                id=f"homogeneous_{slug(signature)}",
                kind="homogeneous",
                root_sig_alg=signature,
                intermediate_sig_alg=signature,
                leaf_sig_alg=signature,
            ))
    for level, roots in HEAVY_ROOTS_BY_LEVEL.items():
        for root in roots:
            for leaf in LIGHT_SIGNATURES_BY_LEVEL[level]:
                chains.append(PkiChain(
                    id=f"root_{slug(root)}__leaf_{slug(leaf)}",
                    kind="heavy_root",
                    root_sig_alg=root,
                    intermediate_sig_alg=leaf,
                    leaf_sig_alg=leaf,
                ))
    return tuple(chains)


PKI_CHAINS = _pki_chains()

# These opt-in profiles use one algorithm for every X.509 signature in the
# chain. SLH-DSA, LMS and XMSS still use an ECDSA leaf public key because the
# installed TLS stacks do not expose those algorithms as CertificateVerify
# SignatureSchemes. RSA-PSS is homogeneous for both X.509 and TLS.
HEAVY_HOMOGENEOUS_CHAINS = tuple(
    PkiChain(
        id=f"homogeneous_{slug(signature)}",
        kind="homogeneous_x509",
        root_sig_alg=signature,
        intermediate_sig_alg=signature,
        leaf_sig_alg=signature,
    )
    for signatures in HEAVY_ROOTS_BY_LEVEL.values()
    for signature in signatures
)
ALL_PKI_CHAINS = PKI_CHAINS + HEAVY_HOMOGENEOUS_CHAINS
PKI_CHAINS_BY_ID = {item.id: item for item in ALL_PKI_CHAINS}


SIGNATURE_SCHEME_NAMES = {
    item.tls_signature_scheme_id: item.tls_signature_scheme
    for item in SIGNATURES
}


def expected_signature_scheme(signature_name: str) -> str:
    return SIGNATURES_BY_NAME[signature_name].tls_signature_scheme


def normalize_signature_scheme(value: str, signature_name: str) -> str:
    """Map legacy CSV labels to the exact negotiated TLS SignatureScheme."""
    signature = SIGNATURES_BY_NAME[signature_name]
    if not value or value in {
        signature.name,
        signature.certificate_verify,
        signature.leaf_key_type,
    }:
        return signature.tls_signature_scheme
    return value
