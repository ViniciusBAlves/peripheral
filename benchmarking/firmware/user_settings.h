#ifndef MY_MASTER_WOLFSSL_SETTINGS_H
#define MY_MASTER_WOLFSSL_SETTINGS_H

#ifndef _ASMLANGUAGE
#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
#include <time.h> 

/* ========================================================
 * 1. THE BARE-METAL KILL SWITCH
 * ======================================================== */
#define WOLFSSL_USER_IO
#define SINGLE_THREADED
#define WOLFSSL_SMALL_STACK
#define NO_FILESYSTEM
#define WOLFSSL_NO_SOCK
#define NO_WRITEV            /* KILLS sys/uio.h completely */
#define WOLFSSL_IGNORE_FILE_WARN

/* ========================================================
 * 2. ZEPHYR HOOKS
 * ======================================================== */
#define NO_DEV_RANDOM
#define CUSTOM_RAND_GENERATE_BLOCK(buf, len) (sys_rand_get((void*)(buf), (len)), 0)
#define XTIME time_sec
#define XTIME_MS time_ms

/* ========================================================
 * 4. TLS 1.3 & MODERN CRYPTO
 * ======================================================== */
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_AESGCM
#define HAVE_ECC
#define HAVE_CURVE25519
/* Do not make ECC inherit TFM's RSA-15360-sized arithmetic. */
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_ARM_CORTEX_M_ASM
#define WOLFSSL_SP_384
#define WOLFSSL_SP_521
#define SP_WORD_SIZE 32
#define WOLFSSL_SHA256
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define HAVE_HKDF
#define WC_RSA_PSS
#define USE_FAST_MATH
#define RSA_MAX_SIZE 16384
#define WC_MAX_RSA_BITS 16384
#ifndef WOLFSSL_DISABLE_TFM_TIMING_RESISTANT
#define TFM_TIMING_RESISTANT
#endif
#define HAVE_FFDHE_2048

/* ========================================================
 * 5. POST-QUANTUM (ML-KEM / ML-DSA)
 * ======================================================== */
#define WOLFSSL_EXPERIMENTAL_SETTINGS
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM
#define WOLFSSL_PQC_HYBRIDS
#define WOLFSSL_HAVE_DILITHIUM
#define WOLFSSL_WC_DILITHIUM
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

#ifdef BENCH_USE_PQM4_MLKEM
#define WOLF_CRYPTO_CB
#define WOLF_CRYPTO_CB_FIND
#define WOLF_CRYPTO_CB_ONLY_PQC
#define MAX_CRYPTO_DEVID_CALLBACKS 16
#endif

/* ========================================================
 * 6. MISC FIXES
 * ======================================================== */
#define XSTRCASECMP wc_strcasecmp
#define USE_WOLF_STRCASECMP
#define NO_ASN_TIME

#define LARGE_STATIC_BUFFERS

/* Fix Error -463: Ensure all standard cert algorithms are recognized */
#undef NO_RSA
#undef NO_SHA
#define HAVE_RSA
#define WOLFSSL_SHA1
/* #define HAVE_ED25519 */
#define HAVE_ECC521

#define HAVE_PQC
#define HAVE_DILITHIUM
#define HAVE_MLDSA
#define WOLFSSL_HAVE_MLDSA
#define WOLFSSL_MLDSA
#define WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM
#define WOLFSSL_DILITHIUM_SIGN_SMALL_MEM
#define WOLFSSL_HAVE_SLHDSA
#define WOLFSSL_WC_SLHDSA
#define WOLFSSL_WC_SLHDSA_SMALL
#define WOLFSSL_WC_SLHDSA_SMALL_MEM
#define WOLFSSL_HAVE_LMS
#define WOLFSSL_LMS_VERIFY_ONLY
#define WOLFSSL_WC_LMS_SMALL
#define WOLFSSL_HAVE_XMSS
#define WOLFSSL_XMSS_VERIFY_ONLY
#define WOLFSSL_WC_XMSS_SMALL
#define WOLFSSL_WC_XMSS_MIN_HASH_SIZE 256
#define WOLFSSL_WC_XMSS_MAX_HASH_SIZE 256
#define WOLFSSL_XMSS_MIN_HEIGHT 20
#define WOLFSSL_XMSS_MAX_HEIGHT 20
#define HAVE_SNI

#undef min
#undef max

#endif /* _ASMLANGUAGE */
#endif /* MY_MASTER_WOLFSSL_SETTINGS_H */
