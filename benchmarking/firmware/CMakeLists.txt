cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(peripheral)

set(BENCH_MLKEM_BACKEND "pqm4-m4fstack" CACHE STRING "ML-KEM implementation")
set_property(CACHE BENCH_MLKEM_BACKEND PROPERTY STRINGS wolfssl pqm4-m4fstack)
option(BENCH_LARGE_RSA "Use heap integer math for RSA keys above 8192 bits" OFF)

if(NOT DEFINED BENCH_GENERATED_DIR)
    message(FATAL_ERROR "BENCH_GENERATED_DIR must contain benchmark_credentials.h")
endif()
if(NOT EXISTS "${BENCH_GENERATED_DIR}/benchmark_credentials.h")
    message(FATAL_ERROR "Missing ${BENCH_GENERATED_DIR}/benchmark_credentials.h")
endif()

# SLH-DSA X.509 support landed after wolfSSL 5.9.1. Pin the reviewed upstream
# revision so pristine builds are reproducible while avoiding changes to NCS.
include(FetchContent)
if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()
set(FETCHCONTENT_BASE_DIR "${CMAKE_BINARY_DIR}/_deps")
FetchContent_Declare(wolfssl_upstream
    URL https://github.com/wolfSSL/wolfssl/archive/dd6da70d395a0cb26446326f329678fe3bfb212c.tar.gz
    URL_HASH SHA256=087ac84de980da83e7f1a3014dd241358f64d9a330dec74c6eb1404495ad2cf7
    DOWNLOAD_EXTRACT_TIMESTAMP FALSE
)
FetchContent_GetProperties(wolfssl_upstream)
if(NOT wolfssl_upstream_POPULATED)
    FetchContent_Populate(wolfssl_upstream)
endif()
set(WOLFSSL_ROOT_DIR "${wolfssl_upstream_SOURCE_DIR}")

# Add benchmark-only timing hooks to the disposable wolfSSL source copy.
set(WOLFSSL_ASN_C "${WOLFSSL_ROOT_DIR}/wolfcrypt/src/asn.c")
file(READ "${WOLFSSL_ASN_C}" WOLFSSL_ASN_TEXT)
string(REPLACE
    "    WOLFSSL_ENTER(\"ConfirmSignature\");"
    "    benchmark_timepoint_t benchmark_verify_start = benchmark_metric_start();\n    WOLFSSL_ENTER(\"ConfirmSignature\");"
    WOLFSSL_ASN_TEXT "${WOLFSSL_ASN_TEXT}"
)
string(REPLACE
    "    WOLFSSL_LEAVE(\"ConfirmSignature\", ret);"
    "    WOLFSSL_LEAVE(\"ConfirmSignature\", ret);\n    benchmark_metric_stop(BENCH_CRYPTO_CERT_VERIFY, benchmark_verify_start);"
    WOLFSSL_ASN_TEXT "${WOLFSSL_ASN_TEXT}"
)
string(REPLACE
    "#include <wolfssl/wolfcrypt/asn.h>"
    "#include <wolfssl/wolfcrypt/asn.h>\n#include \"benchmark_metrics.h\""
    WOLFSSL_ASN_TEXT "${WOLFSSL_ASN_TEXT}"
)
file(WRITE "${WOLFSSL_ASN_C}" "${WOLFSSL_ASN_TEXT}")

set(WOLFSSL_MLKEM_C "${WOLFSSL_ROOT_DIR}/wolfcrypt/src/wc_mlkem.c")
file(READ "${WOLFSSL_MLKEM_C}" WOLFSSL_MLKEM_TEXT)
string(REPLACE
    "#include <wolfssl/wolfcrypt/wc_mlkem.h>"
    "#include <wolfssl/wolfcrypt/wc_mlkem.h>\n#include \"benchmark_metrics.h\""
    WOLFSSL_MLKEM_TEXT "${WOLFSSL_MLKEM_TEXT}"
)
string(REPLACE
    "    unsigned char rand[WC_ML_KEM_MAKEKEY_RAND_SZ];"
    "    unsigned char rand[WC_ML_KEM_MAKEKEY_RAND_SZ];\n    benchmark_timepoint_t benchmark_kem_start = benchmark_metric_start();"
    WOLFSSL_MLKEM_TEXT "${WOLFSSL_MLKEM_TEXT}"
)
string(REPLACE
    "    /* Step 4: return ret != 0 on falsum or internal key generation failure. */\n    return ret;"
    "    /* Step 4: return ret != 0 on falsum or internal key generation failure. */\n    benchmark_metric_stop(BENCH_CRYPTO_KEM_KEYGEN, benchmark_kem_start);\n    return ret;"
    WOLFSSL_MLKEM_TEXT "${WOLFSSL_MLKEM_TEXT}"
)
string(REPLACE
    "    unsigned char m[WC_ML_KEM_ENC_RAND_SZ];"
    "    unsigned char m[WC_ML_KEM_ENC_RAND_SZ];\n    benchmark_timepoint_t benchmark_kem_start = benchmark_metric_start();"
    WOLFSSL_MLKEM_TEXT "${WOLFSSL_MLKEM_TEXT}"
)
string(REPLACE
    "    /* Step 3: return ret != 0 on falsum or internal key generation failure. */\n    return ret;"
    "    /* Step 3: return ret != 0 on falsum or internal key generation failure. */\n    benchmark_metric_stop(BENCH_CRYPTO_KEM_ENCAPSULATE, benchmark_kem_start);\n    return ret;"
    WOLFSSL_MLKEM_TEXT "${WOLFSSL_MLKEM_TEXT}"
)
string(REPLACE
    "    int ret = 0;\n    unsigned int ctSz = 0;"
    "    int ret = 0;\n    benchmark_timepoint_t benchmark_kem_start = benchmark_metric_start();\n    unsigned int ctSz = 0;"
    WOLFSSL_MLKEM_TEXT "${WOLFSSL_MLKEM_TEXT}"
)
string(REPLACE
    "    ForceZero(msg, sizeof(msg));\n    ForceZero(kr, sizeof(kr));\n\n    return ret;"
    "    ForceZero(msg, sizeof(msg));\n    ForceZero(kr, sizeof(kr));\n\n    benchmark_metric_stop(BENCH_CRYPTO_KEM_DECAPSULATE, benchmark_kem_start);\n    return ret;"
    WOLFSSL_MLKEM_TEXT "${WOLFSSL_MLKEM_TEXT}"
)
file(WRITE "${WOLFSSL_MLKEM_C}" "${WOLFSSL_MLKEM_TEXT}")

# This pinned wolfSSL revision sizes two classic RSA ASN/TLS buffers for
# RSA-4096 when fast math is disabled. Patch only the disposable FetchContent
# copy used by the large-RSA image; the normal image and NCS stay untouched.
if(BENCH_LARGE_RSA)
    set(WOLFSSL_TYPES_H "${WOLFSSL_ROOT_DIR}/wolfssl/wolfcrypt/types.h")
    file(READ "${WOLFSSL_TYPES_H}" WOLFSSL_TYPES_TEXT)
    string(REPLACE
        "MAX_ENCODED_CLASSIC_SIG_SZ = 512,     /* Supports 4096 bit keys */"
        "MAX_ENCODED_CLASSIC_SIG_SZ = RSA_MAX_SIZE / 8,"
        WOLFSSL_TYPES_TEXT "${WOLFSSL_TYPES_TEXT}"
    )
    string(REPLACE
        "MAX_RSA_INT_SZ      = (512 + 1 + MAX_LENGTH_SZ), /* RSA raw sz 4096 for bits + tag + len(5) */"
        "MAX_RSA_INT_SZ      = (RSA_MAX_SIZE / 8 + 1 + MAX_LENGTH_SZ),"
        WOLFSSL_TYPES_TEXT "${WOLFSSL_TYPES_TEXT}"
    )
    file(WRITE "${WOLFSSL_TYPES_H}" "${WOLFSSL_TYPES_TEXT}")
endif()

# 1. Bind EVERYTHING directly to the 'app' target
target_sources(app PRIVATE src/main.c src/benchmark_metrics.c
    # --- Post Quantum Math ---
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/wc_mlkem.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/wc_mlkem_poly.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/wc_mldsa.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/wc_slhdsa.c
    
    # --- Core Cryptography & Hashes ---
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/random.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/hash.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/sha.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/sha256.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/sha512.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/sha3.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/hmac.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/aes.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/ecc.c
    # Keep ECC on wolfSSL's Cortex-M SP backend. TFM remains available below
    # with FP_MAX_BITS=16384 for the intentionally oversized RSA cases.
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/sp_cortexm.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/curve25519.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/rsa.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/kdf.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/ed25519.c
    
    # --- Legacy Support ---
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/md5.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/des3.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/dh.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/dsa.c

    # --- Math Helpers & Decoding ---
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/coding.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/misc.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/wolfmath.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/fe_operations.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/ge_operations.c
    
    # --- Memory & System ---
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/tfm.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/integer.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/memory.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/asn.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/wc_port.c
    ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/logging.c
    
    # --- TLS Engine ---
    ${WOLFSSL_ROOT_DIR}/src/ssl.c
    ${WOLFSSL_ROOT_DIR}/src/tls.c
    ${WOLFSSL_ROOT_DIR}/src/tls13.c
    ${WOLFSSL_ROOT_DIR}/src/keys.c
    ${WOLFSSL_ROOT_DIR}/src/internal.c
    ${WOLFSSL_ROOT_DIR}/src/wolfio.c
)

target_include_directories(app PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${BENCH_GENERATED_DIR}
    ${WOLFSSL_ROOT_DIR}
    ${WOLFSSL_ROOT_DIR}/wolfssl
)

# CRITICAL FIX: Target-specific definitions and includes (NOT Global)
target_compile_definitions(app PRIVATE
    WOLFSSL_USER_SETTINGS
    FP_MAX_BITS=16384
    BENCHMARK_CLOSE_AFTER_TLS=0
)
target_compile_options(app PRIVATE -include ${CMAKE_CURRENT_SOURCE_DIR}/user_settings.h)

if(BENCH_LARGE_RSA)
    target_compile_definitions(app PRIVATE
        BENCH_LARGE_RSA
        BENCH_RSA_PROFILE_NAME="integer-heap-16384"
    )
else()
    target_compile_definitions(app PRIVATE
        BENCH_RSA_PROFILE_NAME="fast-math"
    )
endif()

if(BENCH_MLKEM_BACKEND STREQUAL "pqm4-m4fstack")
    if(NOT DEFINED PQM4_ROOT OR
       NOT EXISTS "${PQM4_ROOT}/crypto_kem/ml-kem-512/m4fstack/kem.c")
        message(FATAL_ERROR "PQM4_ROOT must point to a complete pqm4 checkout")
    endif()

    set(PQM4_COMMON "${PQM4_ROOT}/mupq/common")
    add_library(pqm4_fips202 OBJECT
        "${PQM4_COMMON}/fips202.c"
        "${PQM4_ROOT}/common/keccakf1600.S"
        src/pqm4_randombytes.c
    )
    target_include_directories(pqm4_fips202 PRIVATE "${PQM4_COMMON}")
    target_link_libraries(pqm4_fips202 PRIVATE zephyr_interface)

    function(add_pqm4_mlkem target level)
        set(src "${PQM4_ROOT}/crypto_kem/ml-kem-${level}/m4fstack")
        add_library(${target} OBJECT
            "${src}/cbd.c"
            "${src}/cmov_int16.S"
            "${src}/fastaddsub.S"
            "${src}/fastbasemul.S"
            "${src}/fastinvntt.S"
            "${src}/fastntt.S"
            "${src}/indcpa.c"
            "${src}/kem.c"
            "${src}/matacc.c"
            "${src}/matacc_asm.S"
            "${src}/ntt.c"
            "${src}/poly.c"
            "${src}/poly_asm.S"
            "${src}/polyvec.c"
            "${src}/reduce.S"
            "${src}/symmetric-fips202.c"
            "${src}/verify.c"
        )
        target_include_directories(${target} PRIVATE
            "${src}" "${PQM4_COMMON}" "${CMAKE_CURRENT_SOURCE_DIR}/src"
        )
        target_compile_definitions(${target} PRIVATE
            PQM4_PREFIX=pqm4_mlkem${level}_
            asm=__asm__
        )
        target_compile_options(${target} PRIVATE
            -include ${CMAKE_CURRENT_SOURCE_DIR}/src/pqm4_namespace.h
            $<$<COMPILE_LANGUAGE:C>:-std=gnu17>
        )
        target_link_libraries(${target} PRIVATE zephyr_interface)
    endfunction()

    add_pqm4_mlkem(pqm4_mlkem512 512)
    add_pqm4_mlkem(pqm4_mlkem768 768)
    add_pqm4_mlkem(pqm4_mlkem1024 1024)
    target_sources(app PRIVATE
        src/pqm4_mlkem_backend.c
        ${WOLFSSL_ROOT_DIR}/wolfcrypt/src/cryptocb.c
        $<TARGET_OBJECTS:pqm4_fips202>
        $<TARGET_OBJECTS:pqm4_mlkem512>
        $<TARGET_OBJECTS:pqm4_mlkem768>
        $<TARGET_OBJECTS:pqm4_mlkem1024>
    )
    target_compile_definitions(app PRIVATE
        BENCH_USE_PQM4_MLKEM
        BENCH_MLKEM_BACKEND_NAME="pqm4-m4fstack"
    )
else()
    target_compile_definitions(app PRIVATE
        BENCH_MLKEM_BACKEND_NAME="wolfssl"
    )
endif()
