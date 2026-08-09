from __future__ import annotations

OPENSSL_MOSQUITTO = "openssl-mosquitto"
WOLFSSL = "wolfssl"
AUTO = "auto"

SERVER_BACKEND_CHOICES = (AUTO, OPENSSL_MOSQUITTO, WOLFSSL)
WOLFSSL_CERTIFICATE_SIGNATURES = {"LMS-HSS-L2-H10-W4", "XMSS-SHA2_20_256"}
HASH_BASED_SIGNATURES = WOLFSSL_CERTIFICATE_SIGNATURES


def server_backend_for_case(
    case: dict[str, str],
    requested: str,
) -> str | None:
    signature = case["cert_sig_alg"]
    requires_wolfssl = signature in WOLFSSL_CERTIFICATE_SIGNATURES
    if requested == AUTO:
        return WOLFSSL if requires_wolfssl else OPENSSL_MOSQUITTO
    if requested == OPENSSL_MOSQUITTO and requires_wolfssl:
        return None
    return requested


def unsupported_backend_reason(case: dict[str, str], requested: str) -> str:
    return (
        f"{requested} cannot load or verify {case['cert_sig_alg']} certificate "
        "chains; use --server-backend auto or --server-backend wolfssl"
    )
