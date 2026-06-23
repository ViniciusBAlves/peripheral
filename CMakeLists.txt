cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(peripheral)

# SLH-DSA X.509 support landed after wolfSSL 5.9.1. Pin the reviewed upstream
# revision so pristine builds are reproducible while avoiding changes to NCS.
include(FetchContent)
if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()
set(FETCHCONTENT_BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/.cache")
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

# 1. Bind EVERYTHING directly to the 'app' target
target_sources(app PRIVATE src/main.c
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
    ${WOLFSSL_ROOT_DIR}
    ${WOLFSSL_ROOT_DIR}/wolfssl
)

# CRITICAL FIX: Target-specific definitions and includes (NOT Global)
target_compile_definitions(app PRIVATE WOLFSSL_USER_SETTINGS)
target_compile_options(app PRIVATE -include ${CMAKE_CURRENT_SOURCE_DIR}/user_settings.h)
