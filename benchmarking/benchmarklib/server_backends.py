from __future__ import annotations

OPENSSL_MOSQUITTO = "openssl-mosquitto"
WOLFSSL = "wolfssl"
AUTO = "auto"

SERVER_BACKEND_CHOICES = (AUTO, OPENSSL_MOSQUITTO, WOLFSSL)
HASH_BASED_SIGNATURES = {"LMS-HSS-L2-H10-W4", "XMSS-SHA2_20_256"}
LONG_RSA_SIGNATURES = {"RSA-PSS-7680", "RSA-PSS-15360"}


def server_backend_for_case(
    case: dict[str, str],
    requested: str,
) -> str | None:
    signature = case["cert_sig_alg"]
    if requested == AUTO:
        return (
            WOLFSSL
            if signature in HASH_BASED_SIGNATURES | LONG_RSA_SIGNATURES
            else OPENSSL_MOSQUITTO
        )
    if requested == OPENSSL_MOSQUITTO and signature in HASH_BASED_SIGNATURES:
        return None
    return requested


def unsupported_backend_reason(case: dict[str, str], requested: str) -> str:
    return (
        f"{requested} cannot load or verify {case['cert_sig_alg']} certificate "
        "chains; use --server-backend auto or --server-backend wolfssl"
    )
