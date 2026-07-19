#include <zephyr/console/console.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/sys_heap.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/wc_lms.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/wolfcrypt/wc_slhdsa.h>
#include <wolfssl/wolfcrypt/wc_xmss.h>

#define CERTGEN_DER_CAP (40 * 1024)
#define CERTGEN_STATE_CAP (8 * 1024)
#define CERTGEN_HEAP_SIZE (280 * 1024)
#define CERT_NOT_BEFORE "\x18\x0f""20200101000000Z"
#define CERT_NOT_AFTER  "\x18\x0f""20360101000000Z"

K_HEAP_DEFINE(certgen_heap, CERTGEN_HEAP_SIZE);

static byte cert_der[CERTGEN_DER_CAP];
static byte state_data[CERTGEN_STATE_CAP];
static word32 state_size;
static Cert cert;
static WC_RNG rng;
static ecc_key ecc;
static RsaKey rsa;
static wc_MlDsaKey mldsa;
static SlhDsaKey slhdsa;
static LmsKey lms;
static XmssKey xmss;

enum key_kind {
    KEY_ECC,
    KEY_RSA,
    KEY_MLDSA,
    KEY_SLHDSA,
    KEY_LMS,
    KEY_XMSS,
};

struct certgen_algorithm {
    const char *name;
    enum key_kind kind;
    int key_type;
    int sig_type;
    int parameter;
    int public_bytes;
    int private_bytes;
    int signature_bytes;
};

static const struct certgen_algorithm algorithms[] = {
    {"ECDSA-P-256", KEY_ECC, ECC_TYPE, CTC_SHA256wECDSA, ECC_SECP256R1,
     65, 32, 64},
    {"ECDSA-P-384", KEY_ECC, ECC_TYPE, CTC_SHA384wECDSA, ECC_SECP384R1,
     97, 48, 96},
    {"ECDSA-P-521", KEY_ECC, ECC_TYPE, CTC_SHA512wECDSA, ECC_SECP521R1,
     133, 66, 132},
    {"RSA-PSS-3072", KEY_RSA, RSA_TYPE, CTC_RSASSAPSS, 3072,
     384, 384, 384},
    {"RSA-PSS-7680", KEY_RSA, RSA_TYPE, CTC_RSASSAPSS, 7680,
     960, 960, 960},
    {"RSA-PSS-15360", KEY_RSA, RSA_TYPE, CTC_RSASSAPSS, 15360,
     1920, 1920, 1920},
    {"ML-DSA-44", KEY_MLDSA, ML_DSA_44_TYPE, CTC_ML_DSA_44, WC_ML_DSA_44,
     1312, 2560, 2420},
    {"ML-DSA-65", KEY_MLDSA, ML_DSA_65_TYPE, CTC_ML_DSA_65, WC_ML_DSA_65,
     1952, 4032, 3309},
    {"ML-DSA-87", KEY_MLDSA, ML_DSA_87_TYPE, CTC_ML_DSA_87, WC_ML_DSA_87,
     2592, 4896, 4627},
    {"SLH-DSA-SHAKE-128s", KEY_SLHDSA, SLH_DSA_SHAKE_128S_TYPE,
     CTC_SLH_DSA_SHAKE_128S, SLHDSA_SHAKE128S, 32, 64, 7856},
    {"SLH-DSA-SHAKE-192s", KEY_SLHDSA, SLH_DSA_SHAKE_192S_TYPE,
     CTC_SLH_DSA_SHAKE_192S, SLHDSA_SHAKE192S, 48, 96, 16224},
    {"SLH-DSA-SHAKE-256s", KEY_SLHDSA, SLH_DSA_SHAKE_256S_TYPE,
     CTC_SLH_DSA_SHAKE_256S, SLHDSA_SHAKE256S, 64, 128, 29792},
    {"LMS-HSS-L2-H10-W4", KEY_LMS, LMS_TYPE, CTC_HSS_LMS, 0,
     60, 64, 5076},
    {"XMSS-SHA2_20_256", KEY_XMSS, XMSS_TYPE, CTC_XMSS, 0,
     68, 2573, 2820},
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
    return k_heap_alloc(&certgen_heap, size, K_NO_WAIT);
}

static void bench_free(void *ptr)
{
    k_heap_free(&certgen_heap, ptr);
}

static void *bench_realloc(void *ptr, size_t size)
{
    return k_heap_realloc(&certgen_heap, ptr, size, K_NO_WAIT);
}

static int lms_write(const byte *data, word32 size, void *context)
{
    ARG_UNUSED(context);
    if (size > sizeof(state_data)) {
        return WC_LMS_RC_WRITE_FAIL;
    }
    memcpy(state_data, data, size);
    state_size = size;
    return WC_LMS_RC_SAVED_TO_NV_MEMORY;
}

static int lms_read(byte *data, word32 size, void *context)
{
    ARG_UNUSED(context);
    if (state_size != size) {
        return WC_LMS_RC_READ_FAIL;
    }
    memcpy(data, state_data, size);
    return WC_LMS_RC_READ_TO_MEMORY;
}

static enum wc_XmssRc xmss_write(const byte *data, word32 size, void *context)
{
    ARG_UNUSED(context);
    if (size > sizeof(state_data)) {
        return WC_XMSS_RC_WRITE_FAIL;
    }
    memcpy(state_data, data, size);
    state_size = size;
    return WC_XMSS_RC_SAVED_TO_NV_MEMORY;
}

static enum wc_XmssRc xmss_read(byte *data, word32 size, void *context)
{
    ARG_UNUSED(context);
    if (state_size != size) {
        return WC_XMSS_RC_READ_FAIL;
    }
    memcpy(data, state_data, size);
    return WC_XMSS_RC_READ_TO_MEMORY;
}

static const struct certgen_algorithm *find_algorithm(const char *name)
{
    for (size_t i = 0; i < ARRAY_SIZE(algorithms); ++i) {
        if (strcmp(name, algorithms[i].name) == 0) {
            return &algorithms[i];
        }
    }
    return NULL;
}

static void *key_pointer(enum key_kind kind)
{
    switch (kind) {
    case KEY_ECC: return &ecc;
    case KEY_RSA: return &rsa;
    case KEY_MLDSA: return &mldsa;
    case KEY_SLHDSA: return &slhdsa;
    case KEY_LMS: return &lms;
    case KEY_XMSS: return &xmss;
    }
    return NULL;
}

static int generate_key(const struct certgen_algorithm *algorithm)
{
    int ret;

    switch (algorithm->kind) {
    case KEY_ECC:
        ret = wc_ecc_init(&ecc);
        if (ret == 0) {
            int key_size = algorithm->parameter == ECC_SECP256R1 ? 32 :
                           algorithm->parameter == ECC_SECP384R1 ? 48 : 66;
            ret = wc_ecc_make_key_ex(&rng, key_size, &ecc, algorithm->parameter);
        }
        return ret;
    case KEY_RSA:
        ret = wc_InitRsaKey_ex(&rsa, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_RsaSetRNG(&rsa, &rng);
        }
        if (ret == 0) {
            ret = wc_MakeRsaKey(&rsa, algorithm->parameter, 65537, &rng);
        }
        return ret;
    case KEY_MLDSA:
        ret = wc_MlDsaKey_Init(&mldsa, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_MlDsaKey_SetParams(&mldsa, (byte)algorithm->parameter);
        }
        if (ret == 0) {
            ret = wc_MlDsaKey_MakeKey(&mldsa, &rng);
        }
        return ret;
    case KEY_SLHDSA:
        ret = wc_SlhDsaKey_Init(&slhdsa,
                                (enum SlhDsaParam)algorithm->parameter,
                                NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_SlhDsaKey_MakeKey(&slhdsa, &rng);
        }
        return ret;
    case KEY_LMS:
        state_size = 0;
        ret = wc_LmsKey_Init(&lms, NULL, INVALID_DEVID);
        if (ret == 0) ret = wc_LmsKey_SetParameters(&lms, 2, 10, 4);
        if (ret == 0) ret = wc_LmsKey_SetWriteCb(&lms, lms_write);
        if (ret == 0) ret = wc_LmsKey_SetReadCb(&lms, lms_read);
        if (ret == 0) ret = wc_LmsKey_SetContext(&lms, state_data);
        if (ret == 0) ret = wc_LmsKey_MakeKey(&lms, &rng);
        return ret;
    case KEY_XMSS:
        state_size = 0;
        ret = wc_XmssKey_Init(&xmss, NULL, INVALID_DEVID);
        if (ret == 0) ret = wc_XmssKey_SetParamStr(&xmss, "XMSS-SHA2_20_256");
        if (ret == 0) ret = wc_XmssKey_SetWriteCb(&xmss, xmss_write);
        if (ret == 0) ret = wc_XmssKey_SetReadCb(&xmss, xmss_read);
        if (ret == 0) ret = wc_XmssKey_SetContext(&xmss, state_data);
        if (ret == 0) ret = wc_XmssKey_MakeKey(&xmss, &rng);
        return ret;
    }
    return BAD_FUNC_ARG;
}

static void free_key(enum key_kind kind)
{
    switch (kind) {
    case KEY_ECC: wc_ecc_free(&ecc); break;
    case KEY_RSA: wc_FreeRsaKey(&rsa); break;
    case KEY_MLDSA: wc_MlDsaKey_Free(&mldsa); break;
    case KEY_SLHDSA: wc_SlhDsaKey_Free(&slhdsa); break;
    case KEY_LMS: wc_LmsKey_Free(&lms); break;
    case KEY_XMSS: wc_XmssKey_Free(&xmss); break;
    }
}

static int make_certificate(const struct certgen_algorithm *algorithm,
                            const char *case_id)
{
    int ret = wc_InitCert(&cert);

    if (ret != 0) {
        return ret;
    }
    XSTRNCPY(cert.subject.country, "CA", CTC_NAME_SIZE);
    XSTRNCPY(cert.subject.state, "QC", CTC_NAME_SIZE);
    XSTRNCPY(cert.subject.locality, "Montreal", CTC_NAME_SIZE);
    XSTRNCPY(cert.subject.org, "Peripheral Benchmark", CTC_NAME_SIZE);
    XSTRNCPY(cert.subject.unit, "On-device Certificate Generation",
             CTC_NAME_SIZE);
    XSTRNCPY(cert.subject.commonName, case_id, CTC_NAME_SIZE);
    XMEMCPY(cert.beforeDate, CERT_NOT_BEFORE, sizeof(CERT_NOT_BEFORE) - 1);
    cert.beforeDateSz = sizeof(CERT_NOT_BEFORE) - 1;
    XMEMCPY(cert.afterDate, CERT_NOT_AFTER, sizeof(CERT_NOT_AFTER) - 1);
    cert.afterDateSz = sizeof(CERT_NOT_AFTER) - 1;
    cert.isCA = 1;
    cert.selfSigned = 1;
    cert.daysValid = 3650;
    cert.sigType = algorithm->sig_type;
    ret = wc_SetKeyUsage(&cert, "digitalSignature,keyCertSign,cRLSign");
    if (ret != 0) {
        return ret;
    }
    ret = wc_MakeCert_ex(&cert, cert_der, sizeof(cert_der),
                         algorithm->key_type, key_pointer(algorithm->kind), &rng);
    return ret > 0 ? 0 : ret;
}

static int verify_certificate(int certificate_size)
{
    WOLFSSL_CERT_MANAGER *manager = wolfSSL_CertManagerNew();
    int ret;

    if (manager == NULL) {
        return MEMORY_E;
    }
    ret = wolfSSL_CertManagerLoadCABuffer(manager, cert_der, certificate_size,
                                          WOLFSSL_FILETYPE_ASN1);
    if (ret == WOLFSSL_SUCCESS) {
        ret = wolfSSL_CertManagerVerifyBuffer(manager, cert_der,
                                               certificate_size,
                                               WOLFSSL_FILETYPE_ASN1);
    }
    wolfSSL_CertManagerFree(manager);
    return ret == WOLFSSL_SUCCESS ? 0 : ret;
}

static uint64_t elapsed_us(int64_t start_ticks)
{
    return k_ticks_to_us_floor64(k_uptime_ticks() - start_ticks);
}

static void emit_result(const char *case_id,
                        const struct certgen_algorithm *algorithm,
                        const char *status, const char *stage, int error,
                        uint64_t keygen_us, uint64_t body_us,
                        uint64_t sign_us, uint64_t verify_us,
                        int certificate_size, uint64_t cycles)
{
    struct sys_memory_stats heap = {0};
    uint64_t total_us = keygen_us + body_us + sign_us + verify_us;

    (void)sys_heap_runtime_stats_get(&certgen_heap.heap, &heap);
    printk("[BENCH_CERT_RESULT] case_id=%s status=%s stage=%s error=%d "
           "cert_sig_alg=%s certificate_keygen_us=%llu "
           "certificate_make_body_us=%llu certificate_sign_us=%llu "
           "certificate_verify_us=%llu certificate_total_us=%llu "
           "certificate_der_bytes=%d sig_public_key_bytes=%d "
           "sig_private_key_bytes=%d sig_signature_bytes=%d "
           "client_cpu_cycles=%llu client_cycle_hz=%u "
           "client_heap_current_bytes=%u client_heap_peak_bytes=%u "
           "client_heap_free_bytes=%u client_heap_capacity_bytes=%u\n",
           case_id, status, stage, error,
           algorithm != NULL ? algorithm->name : "unknown",
           keygen_us, body_us, sign_us, verify_us, total_us, certificate_size,
           algorithm != NULL ? algorithm->public_bytes : 0,
           algorithm != NULL ? algorithm->private_bytes : 0,
           algorithm != NULL ? algorithm->signature_bytes : 0,
           cycles, sys_clock_hw_cycles_per_sec(),
           (unsigned int)heap.allocated_bytes,
           (unsigned int)heap.max_allocated_bytes,
           (unsigned int)heap.free_bytes, CERTGEN_HEAP_SIZE);
}

static void run_case(const char *case_id, const char *algorithm_name)
{
    const struct certgen_algorithm *algorithm = find_algorithm(algorithm_name);
    uint64_t keygen_us = 0, body_us = 0, sign_us = 0, verify_us = 0;
    k_thread_runtime_stats_t cpu_start = {0};
    k_thread_runtime_stats_t cpu_end = {0};
    uint64_t cycles = 0;
    int64_t started;
    int certificate_size = 0;
    int ret;
    const char *stage = "algorithm";

    if (algorithm == NULL) {
        emit_result(case_id, NULL, "unsupported", stage, BAD_FUNC_ARG,
                    0, 0, 0, 0, 0, 0);
        return;
    }

    memset(cert_der, 0, sizeof(cert_der));
    memset(state_data, 0, sizeof(state_data));
    memset(&cert, 0, sizeof(cert));
    memset(&ecc, 0, sizeof(ecc));
    memset(&rsa, 0, sizeof(rsa));
    memset(&mldsa, 0, sizeof(mldsa));
    memset(&slhdsa, 0, sizeof(slhdsa));
    memset(&lms, 0, sizeof(lms));
    memset(&xmss, 0, sizeof(xmss));
    (void)sys_heap_runtime_stats_reset_max(&certgen_heap.heap);
    (void)k_thread_runtime_stats_get(k_current_get(), &cpu_start);

    stage = "keygen";
    started = k_uptime_ticks();
    ret = generate_key(algorithm);
    keygen_us = elapsed_us(started);
    if (ret != 0) {
        goto done;
    }

    stage = "certificate_body";
    started = k_uptime_ticks();
    ret = make_certificate(algorithm, case_id);
    body_us = elapsed_us(started);
    if (ret != 0) {
        goto done;
    }

    stage = "certificate_sign";
    started = k_uptime_ticks();
    certificate_size = wc_SignCert_ex(
        cert.bodySz, algorithm->sig_type, cert_der, sizeof(cert_der),
        algorithm->key_type, key_pointer(algorithm->kind), &rng);
    sign_us = elapsed_us(started);
    if (certificate_size <= 0) {
        ret = certificate_size;
        certificate_size = 0;
        goto done;
    }

    stage = "certificate_verify";
    started = k_uptime_ticks();
    ret = verify_certificate(certificate_size);
    verify_us = elapsed_us(started);

done:
    if (k_thread_runtime_stats_get(k_current_get(), &cpu_end) == 0 &&
        cpu_end.execution_cycles >= cpu_start.execution_cycles) {
        cycles = cpu_end.execution_cycles - cpu_start.execution_cycles;
    }
    emit_result(case_id, algorithm, ret == 0 ? "success" : "fail",
                ret == 0 ? "done" : stage, ret, keygen_us, body_us, sign_us,
                verify_us, certificate_size, cycles);
    free_key(algorithm->kind);
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
    printk("[BENCH_READY] mode=certificate-gen algorithms=%u\n",
           (unsigned int)ARRAY_SIZE(algorithms));

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
            strcmp(command, "CERTGEN") != 0) {
            printk("[BENCH_CERT_RESULT] status=fail stage=command error=%d\n",
                   BAD_FUNC_ARG);
            continue;
        }
        ARG_UNUSED(attempt);
        run_case(case_id, algorithm);
        printk("[BENCH_READY] mode=certificate-gen algorithms=%u\n",
               (unsigned int)ARRAY_SIZE(algorithms));
    }
    return 0;
}
