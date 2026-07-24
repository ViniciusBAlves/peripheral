#include <zephyr/console/console.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/sys_heap.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>

#ifdef BENCH_USE_PQM4_MLKEM
#include "pqm4_mlkem_backend.h"
#endif
#include "benchmark_dwt.h"

#define KEM_BENCH_HEAP_SIZE (160 * 1024)
#define KEM_MAX_CIPHERTEXT_BYTES 1665
#define KEM_MAX_SHARED_SECRET_BYTES 80

K_HEAP_DEFINE(kem_bench_heap, KEM_BENCH_HEAP_SIZE);

static WC_RNG rng;
static MlKemKey mlkem;
static ecc_key ecc_recipient;
static ecc_key ecc_ephemeral;
static curve25519_key x25519_recipient;
static curve25519_key x25519_ephemeral;
static byte ciphertext[KEM_MAX_CIPHERTEXT_BYTES];
static byte encapsulated_secret[KEM_MAX_SHARED_SECRET_BYTES];
static byte decapsulated_secret[KEM_MAX_SHARED_SECRET_BYTES];

enum kem_kind {
    KEM_ECDH,
    KEM_MLKEM,
    KEM_HYBRID_ECDH,
    KEM_HYBRID_X25519,
};

struct kem_algorithm {
    const char *name;
    enum kem_kind kind;
    int nist_level;
    int mlkem_type;
    int curve_id;
    int curve_bytes;
    int public_bytes;
    int private_bytes;
    int ciphertext_bytes;
    int shared_secret_bytes;
};

static const struct kem_algorithm algorithms[] = {
    {"ECDHE-P-256", KEM_ECDH, 1, -1, ECC_SECP256R1, 32,
     65, 32, 65, 32},
    {"ECDHE-P-384", KEM_ECDH, 3, -1, ECC_SECP384R1, 48,
     97, 48, 97, 48},
    {"ECDHE-P-521", KEM_ECDH, 5, -1, ECC_SECP521R1, 66,
     133, 66, 133, 66},
    {"MLKEM512", KEM_MLKEM, 1, WC_ML_KEM_512, 0, 0,
     800, 1632, 768, 32},
    {"MLKEM768", KEM_MLKEM, 3, WC_ML_KEM_768, 0, 0,
     1184, 2400, 1088, 32},
    {"MLKEM1024", KEM_MLKEM, 5, WC_ML_KEM_1024, 0, 0,
     1568, 3168, 1568, 32},
    {"SecP256r1MLKEM768", KEM_HYBRID_ECDH, 3, WC_ML_KEM_768,
     ECC_SECP256R1, 32, 1249, 2432, 1153, 64},
    {"X25519MLKEM768", KEM_HYBRID_X25519, 3, WC_ML_KEM_768,
     0, 32, 1216, 2432, 1120, 64},
    {"SecP384r1MLKEM1024", KEM_HYBRID_ECDH, 5, WC_ML_KEM_1024,
     ECC_SECP384R1, 48, 1665, 3216, 1665, 80},
};

time_t time_sec(time_t *timer)
{
    time_t now = 1893456000;

    if (timer != NULL) {
        *timer = now;
    }
    return now;
}

int time_ms(int64_t *timer)
{
    if (timer != NULL) {
        *timer = k_uptime_get();
    }
    return 0;
}

static void *bench_malloc(size_t size)
{
    return k_heap_alloc(&kem_bench_heap, size, K_NO_WAIT);
}

static void bench_free(void *ptr)
{
    k_heap_free(&kem_bench_heap, ptr);
}

static void *bench_realloc(void *ptr, size_t size)
{
    return k_heap_realloc(&kem_bench_heap, ptr, size, K_NO_WAIT);
}

static const struct kem_algorithm *find_algorithm(const char *name)
{
    for (size_t i = 0; i < ARRAY_SIZE(algorithms); ++i) {
        if (strcmp(name, algorithms[i].name) == 0) {
            return &algorithms[i];
        }
    }
    return NULL;
}

static bool uses_mlkem(const struct kem_algorithm *algorithm)
{
    return algorithm->kind != KEM_ECDH;
}

static bool uses_ecc(const struct kem_algorithm *algorithm)
{
    return algorithm->kind == KEM_ECDH ||
           algorithm->kind == KEM_HYBRID_ECDH;
}

static word32 mlkem_ciphertext_bytes(const struct kem_algorithm *algorithm)
{
    switch (algorithm->mlkem_type) {
    case WC_ML_KEM_512:
        return WC_ML_KEM_512_CIPHER_TEXT_SIZE;
    case WC_ML_KEM_768:
        return WC_ML_KEM_768_CIPHER_TEXT_SIZE;
    case WC_ML_KEM_1024:
        return WC_ML_KEM_1024_CIPHER_TEXT_SIZE;
    default:
        return 0;
    }
}

static int init_keys(const struct kem_algorithm *algorithm)
{
    int ret = 0;

    if (uses_mlkem(algorithm)) {
#ifdef BENCH_USE_PQM4_MLKEM
        int dev_id = pqm4_mlkem_backend_dev_id();
#else
        int dev_id = INVALID_DEVID;
#endif
        ret = wc_MlKemKey_Init(&mlkem, algorithm->mlkem_type, NULL, dev_id);
    }
    if (ret == 0 && uses_ecc(algorithm)) {
        ret = wc_ecc_init(&ecc_recipient);
        if (ret == 0) {
            ret = wc_ecc_init(&ecc_ephemeral);
        }
    }
    if (ret == 0 && algorithm->kind == KEM_HYBRID_X25519) {
        ret = wc_curve25519_init(&x25519_recipient);
        if (ret == 0) {
            ret = wc_curve25519_init(&x25519_ephemeral);
        }
    }
    return ret;
}

static void free_keys(const struct kem_algorithm *algorithm)
{
    if (uses_mlkem(algorithm)) {
        wc_MlKemKey_Free(&mlkem);
    }
    if (uses_ecc(algorithm)) {
        wc_ecc_free(&ecc_recipient);
        wc_ecc_free(&ecc_ephemeral);
    }
    if (algorithm->kind == KEM_HYBRID_X25519) {
        wc_curve25519_free(&x25519_recipient);
        wc_curve25519_free(&x25519_ephemeral);
    }
}

static int generate_recipient_key(const struct kem_algorithm *algorithm)
{
    int ret = 0;

    if (uses_mlkem(algorithm)) {
        ret = wc_MlKemKey_MakeKey(&mlkem, &rng);
    }
    if (ret == 0 && uses_ecc(algorithm)) {
        ret = wc_ecc_make_key_ex(&rng, algorithm->curve_bytes,
                                 &ecc_recipient, algorithm->curve_id);
    }
    if (ret == 0 && algorithm->kind == KEM_HYBRID_X25519) {
        ret = wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE,
                                     &x25519_recipient);
    }
    return ret;
}

static int encapsulate(const struct kem_algorithm *algorithm)
{
    int ret = 0;
    word32 secret_len;
    size_t offset = 0;

    if (uses_mlkem(algorithm)) {
        ret = wc_MlKemKey_Encapsulate(&mlkem, ciphertext,
                                      encapsulated_secret, &rng);
        offset = WC_ML_KEM_SS_SZ;
    }
    if (ret == 0 && uses_ecc(algorithm)) {
        ret = wc_ecc_make_key_ex(&rng, algorithm->curve_bytes,
                                 &ecc_ephemeral, algorithm->curve_id);
        secret_len = algorithm->curve_bytes;
        if (ret == 0) {
            ret = wc_ecc_shared_secret(
                &ecc_ephemeral, &ecc_recipient,
                encapsulated_secret + offset, &secret_len);
        }
    }
    if (ret == 0 && algorithm->kind == KEM_HYBRID_X25519) {
        ret = wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE,
                                     &x25519_ephemeral);
        secret_len = CURVE25519_KEYSIZE;
        if (ret == 0) {
            ret = wc_curve25519_shared_secret_ex(
                &x25519_ephemeral, &x25519_recipient,
                encapsulated_secret + offset, &secret_len,
                EC25519_LITTLE_ENDIAN);
        }
    }
    return ret;
}

static int decapsulate(const struct kem_algorithm *algorithm)
{
    int ret = 0;
    word32 secret_len;
    size_t offset = 0;

    if (uses_mlkem(algorithm)) {
        ret = wc_MlKemKey_Decapsulate(
            &mlkem, decapsulated_secret, ciphertext,
            mlkem_ciphertext_bytes(algorithm));
        offset = WC_ML_KEM_SS_SZ;
    }
    if (ret == 0 && uses_ecc(algorithm)) {
        secret_len = algorithm->curve_bytes;
        ret = wc_ecc_shared_secret(
            &ecc_recipient, &ecc_ephemeral,
            decapsulated_secret + offset, &secret_len);
    }
    if (ret == 0 && algorithm->kind == KEM_HYBRID_X25519) {
        secret_len = CURVE25519_KEYSIZE;
        ret = wc_curve25519_shared_secret_ex(
            &x25519_recipient, &x25519_ephemeral,
            decapsulated_secret + offset, &secret_len,
            EC25519_LITTLE_ENDIAN);
    }
    return ret;
}

static uint64_t elapsed_us(int64_t start_ticks)
{
    return k_ticks_to_us_floor64(k_uptime_ticks() - start_ticks);
}

static void emit_result(const char *case_id,
                        const struct kem_algorithm *algorithm,
                        const char *status, const char *stage, int error,
                        uint64_t keygen_us, uint64_t encaps_us,
                        uint64_t decaps_us, uint64_t cycles,
                        bool secrets_match,
                        const struct benchmark_dwt_delta *dwt)
{
    struct sys_memory_stats heap = {0};
    uint64_t total_us = keygen_us + encaps_us + decaps_us;

    (void)sys_heap_runtime_stats_get(&kem_bench_heap.heap, &heap);
    printk("[BENCH_KEM_RESULT] case_id=%s status=%s stage=%s error=%d "
           "kex_group=%s operation_model=%s kem_keygen_us=%llu "
           "kem_encapsulation_us=%llu kem_decapsulation_us=%llu "
           "kem_total_us=%llu kex_public_key_bytes=%d "
           "kex_private_key_bytes=%d kex_ciphertext_bytes=%d "
           "kex_shared_secret_bytes=%d secrets_match=%d "
           "client_cpu_cycles=%llu client_cycle_hz=%u "
           BENCHMARK_DWT_FORMAT " "
           "client_heap_current_bytes=%u client_heap_peak_bytes=%u "
           "client_heap_free_bytes=%u client_heap_capacity_bytes=%u "
           "mlkem_backend=%s\n",
           case_id, status, stage, error,
           algorithm != NULL ? algorithm->name : "unknown",
           algorithm != NULL && algorithm->kind == KEM_ECDH
               ? "dh_key_agreement" :
           algorithm != NULL && algorithm->kind != KEM_MLKEM
               ? "hybrid_kem" : "kem",
           keygen_us, encaps_us, decaps_us, total_us,
           algorithm != NULL ? algorithm->public_bytes : 0,
           algorithm != NULL ? algorithm->private_bytes : 0,
           algorithm != NULL ? algorithm->ciphertext_bytes : 0,
           algorithm != NULL ? algorithm->shared_secret_bytes : 0,
           secrets_match, cycles, sys_clock_hw_cycles_per_sec(),
           BENCHMARK_DWT_VALUES(
               dwt != NULL ? *dwt : (struct benchmark_dwt_delta){0}),
           (unsigned int)heap.allocated_bytes,
           (unsigned int)heap.max_allocated_bytes,
           (unsigned int)heap.free_bytes, KEM_BENCH_HEAP_SIZE,
           algorithm != NULL && algorithm->kind == KEM_ECDH
               ? "none" : BENCH_MLKEM_BACKEND_NAME);
}

static void run_case(const char *case_id, const char *algorithm_name)
{
    const struct kem_algorithm *algorithm = find_algorithm(algorithm_name);
    uint64_t keygen_us = 0, encaps_us = 0, decaps_us = 0;
    k_thread_runtime_stats_t cpu_start = {0};
    k_thread_runtime_stats_t cpu_end = {0};
    uint64_t cycles = 0;
    struct benchmark_dwt_snapshot dwt_start = {0};
    struct benchmark_dwt_delta dwt = {0};
    int64_t started;
    int ret;
    bool secrets_match = false;
    const char *stage = "algorithm";

    if (algorithm == NULL) {
        emit_result(case_id, NULL, "unsupported", stage, BAD_FUNC_ARG,
                    0, 0, 0, 0, false, NULL);
        return;
    }

    memset(&mlkem, 0, sizeof(mlkem));
    memset(&ecc_recipient, 0, sizeof(ecc_recipient));
    memset(&ecc_ephemeral, 0, sizeof(ecc_ephemeral));
    memset(&x25519_recipient, 0, sizeof(x25519_recipient));
    memset(&x25519_ephemeral, 0, sizeof(x25519_ephemeral));
    memset(ciphertext, 0, sizeof(ciphertext));
    memset(encapsulated_secret, 0, sizeof(encapsulated_secret));
    memset(decapsulated_secret, 0, sizeof(decapsulated_secret));
    (void)sys_heap_runtime_stats_reset_max(&kem_bench_heap.heap);

    ret = init_keys(algorithm);
    if (ret != 0) {
        emit_result(case_id, algorithm, "fail", "init", ret,
                    0, 0, 0, 0, false, NULL);
        return;
    }
    dwt_start = benchmark_dwt_snapshot_get();
    (void)k_thread_runtime_stats_get(k_current_get(), &cpu_start);

    stage = "keygen";
    started = k_uptime_ticks();
    ret = generate_recipient_key(algorithm);
    keygen_us = elapsed_us(started);
    if (ret != 0) {
        goto done;
    }

    stage = "encapsulation";
    started = k_uptime_ticks();
    ret = encapsulate(algorithm);
    encaps_us = elapsed_us(started);
    if (ret != 0) {
        goto done;
    }

    stage = "decapsulation";
    started = k_uptime_ticks();
    ret = decapsulate(algorithm);
    decaps_us = elapsed_us(started);
    if (ret != 0) {
        goto done;
    }

    stage = "shared_secret_compare";
    secrets_match = memcmp(encapsulated_secret, decapsulated_secret,
                           algorithm->shared_secret_bytes) == 0;
    if (!secrets_match) {
        ret = SIG_VERIFY_E;
    }

done:
    dwt = benchmark_dwt_delta_get(&dwt_start);
    if (k_thread_runtime_stats_get(k_current_get(), &cpu_end) == 0 &&
        cpu_end.execution_cycles >= cpu_start.execution_cycles) {
        cycles = cpu_end.execution_cycles - cpu_start.execution_cycles;
    }
    emit_result(case_id, algorithm,
                ret == 0 && secrets_match ? "success" : "fail",
                ret == 0 && secrets_match ? "done" : stage, ret,
                keygen_us, encaps_us, decaps_us, cycles, secrets_match, &dwt);
    free_keys(algorithm);
}

int main(void)
{
    wolfSSL_SetAllocators(bench_malloc, bench_free, bench_realloc);
    wolfSSL_Init();
    console_getline_init();

    if (wc_InitRng(&rng) != 0) {
        printk("[BENCH_FATAL] stage=rng\n");
        return 0;
    }
#ifdef BENCH_USE_PQM4_MLKEM
    if (pqm4_mlkem_backend_init() != 0) {
        printk("[BENCH_FATAL] stage=pqm4_backend_init\n");
        return 0;
    }
#endif
    printk("[BENCH_READY] mode=kem-operations algorithms=%u backend=%s\n",
           (unsigned int)ARRAY_SIZE(algorithms), BENCH_MLKEM_BACKEND_NAME);

    while (1) {
        char *line = console_getline();
        char command[16] = {0};
        char case_id[96] = {0};
        char algorithm[64] = {0};
        int attempt = 0;

        if (line == NULL) {
            continue;
        }
        if (sscanf(line, "%15s %95s %63s %d",
                   command, case_id, algorithm, &attempt) != 4 ||
            strcmp(command, "KEMBENCH") != 0) {
            printk("[BENCH_KEM_RESULT] status=fail stage=command error=%d\n",
                   BAD_FUNC_ARG);
            continue;
        }
        ARG_UNUSED(attempt);
        run_case(case_id, algorithm);
        printk("[BENCH_READY] mode=kem-operations algorithms=%u backend=%s\n",
               (unsigned int)ARRAY_SIZE(algorithms), BENCH_MLKEM_BACKEND_NAME);
    }
    return 0;
}
