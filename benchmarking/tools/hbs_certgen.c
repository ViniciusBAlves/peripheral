#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <time.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_lms.h>
#include <wolfssl/wolfcrypt/wc_xmss.h>

#define DER_CAP 32768
#define KEY_CAP 8192
#define CERT_NOT_BEFORE "\x18\x0f""20200101000000Z"
#define CERT_NOT_AFTER  "\x18\x0f""20360101000000Z"

static const char* g_state_path = NULL;

struct PhaseSample {
    struct timespec wall;
    struct rusage usage;
};

static long long timeval_us(struct timeval tv)
{
    return (long long)tv.tv_sec * 1000000LL + tv.tv_usec;
}

static long long elapsed_us(struct timespec start, struct timespec end)
{
    return (long long)(end.tv_sec - start.tv_sec) * 1000000LL +
           (end.tv_nsec - start.tv_nsec) / 1000LL;
}

static void phase_begin(struct PhaseSample* sample)
{
    clock_gettime(CLOCK_MONOTONIC, &sample->wall);
    getrusage(RUSAGE_SELF, &sample->usage);
}

static void phase_end(const char* name, const struct PhaseSample* start, int status)
{
    struct timespec wall;
    struct rusage usage;
    long long user_us;
    long long sys_us;

    clock_gettime(CLOCK_MONOTONIC, &wall);
    getrusage(RUSAGE_SELF, &usage);
    user_us = timeval_us(usage.ru_utime) - timeval_us(start->usage.ru_utime);
    sys_us = timeval_us(usage.ru_stime) - timeval_us(start->usage.ru_stime);
    printf("[CERT_PHASE] name=%s status=%d wall_us=%lld user_cpu_us=%lld "
           "sys_cpu_us=%lld cpu_us=%lld max_rss_kb=%ld "
           "voluntary_context_switches=%ld involuntary_context_switches=%ld "
           "minor_page_faults=%ld major_page_faults=%ld "
           "block_input_ops=%ld block_output_ops=%ld\n",
           name, status, elapsed_us(start->wall, wall), user_us, sys_us,
           user_us + sys_us, usage.ru_maxrss,
           usage.ru_nvcsw - start->usage.ru_nvcsw,
           usage.ru_nivcsw - start->usage.ru_nivcsw,
           usage.ru_minflt - start->usage.ru_minflt,
           usage.ru_majflt - start->usage.ru_majflt,
           usage.ru_inblock - start->usage.ru_inblock,
           usage.ru_oublock - start->usage.ru_oublock);
    fflush(stdout);
}

static int write_file(const char* path, const unsigned char* data, int len)
{
    FILE* f = fopen(path, "wb");
    if (f == NULL) {
        perror(path);
        return -1;
    }
    if (fwrite(data, 1, (size_t)len, f) != (size_t)len) {
        perror(path);
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static int read_file(const char* path, unsigned char* data, int cap)
{
    long len;
    FILE* f = fopen(path, "rb");
    if (f == NULL) {
        perror(path);
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    len = ftell(f);
    if (len < 0 || len > cap) {
        fclose(f);
        return -1;
    }
    rewind(f);
    if (fread(data, 1, (size_t)len, f) != (size_t)len) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return (int)len;
}

static int write_pem_cert(const char* path, const unsigned char* der, int derSz)
{
    unsigned char pem[DER_CAP * 2];
    int pemSz = wc_DerToPem(der, derSz, pem, sizeof(pem), CERT_TYPE);
    if (pemSz <= 0)
        return pemSz;
    return write_file(path, pem, pemSz);
}

static int write_pem_key(const char* path, const unsigned char* der, int derSz)
{
    unsigned char pem[KEY_CAP * 2];
    int pemSz = wc_DerToPem(der, derSz, pem, sizeof(pem), ECC_PRIVATEKEY_TYPE);
    if (pemSz <= 0)
        return pemSz;
    return write_file(path, pem, pemSz);
}

static int hbs_write_key(const unsigned char* priv, unsigned int privSz, void* context)
{
    (void)context;
    return write_file(g_state_path, priv, (int)privSz) == 0
        ? WC_LMS_RC_SAVED_TO_NV_MEMORY : WC_LMS_RC_WRITE_FAIL;
}

static int hbs_read_key(unsigned char* priv, unsigned int privSz, void* context)
{
    int len;
    (void)context;
    len = read_file(g_state_path, priv, (int)privSz);
    return len > 0 ? WC_LMS_RC_READ_TO_MEMORY : WC_LMS_RC_READ_FAIL;
}

static enum wc_XmssRc xmss_write_key(const unsigned char* priv, unsigned int privSz,
    void* context)
{
    (void)context;
    return write_file(g_state_path, priv, (int)privSz) == 0
        ? WC_XMSS_RC_SAVED_TO_NV_MEMORY : WC_XMSS_RC_WRITE_FAIL;
}

static enum wc_XmssRc xmss_read_key(unsigned char* priv, unsigned int privSz,
    void* context)
{
    int len;
    (void)context;
    len = read_file(g_state_path, priv, (int)privSz);
    return len > 0 ? WC_XMSS_RC_READ_TO_MEMORY : WC_XMSS_RC_READ_FAIL;
}

static void set_root_name(Cert* cert, const char* cn)
{
    XSTRNCPY(cert->subject.country, "US", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.state, "OR", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.locality, "Portland", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.org, "Peripheral Benchmark", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.unit, "Hash Based Signatures", CTC_NAME_SIZE);
    snprintf(cert->subject.commonName, sizeof(cert->subject.commonName), "%s", cn);
}

static void set_leaf_name(Cert* cert)
{
    XSTRNCPY(cert->subject.country, "US", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.state, "OR", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.locality, "Portland", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.org, "Peripheral Benchmark", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.unit, "TLS Leaf", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.commonName, "localhost", CTC_NAME_SIZE);
}

static void set_fixed_validity(Cert* cert)
{
    XMEMCPY(cert->beforeDate, CERT_NOT_BEFORE, sizeof(CERT_NOT_BEFORE) - 1);
    cert->beforeDateSz = sizeof(CERT_NOT_BEFORE) - 1;
    XMEMCPY(cert->afterDate, CERT_NOT_AFTER, sizeof(CERT_NOT_AFTER) - 1);
    cert->afterDateSz = sizeof(CERT_NOT_AFTER) - 1;
}

static int make_root(void* key, int keyType, int sigType, WC_RNG* rng,
    const char* cn, unsigned char* rootDer)
{
    Cert cert;
    int rootSz;

    if (wc_InitCert(&cert) != 0)
        return -1;
    set_root_name(&cert, cn);
    cert.sigType = sigType;
    cert.isCA = 1;
    cert.selfSigned = 1;
    cert.daysValid = 3650;
    set_fixed_validity(&cert);
    if (wc_SetKeyUsage(&cert, "keyCertSign,cRLSign") != 0)
        return -1;
    if (wc_MakeCert_ex(&cert, rootDer, DER_CAP, keyType, key, rng) <= 0)
        return -1;
    rootSz = wc_SignCert_ex(cert.bodySz, sigType, rootDer, DER_CAP,
        keyType, key, rng);
    return rootSz;
}

static int make_leaf(void* caKey, int caKeyType, int caSigType, WC_RNG* rng,
    const unsigned char* rootDer, int rootSz, unsigned char* leafDer,
    unsigned char* leafKeyDer, int* leafKeySzOut)
{
    Cert leaf;
    ecc_key leafKey;
    int leafSz;
    int leafKeySz;
    int ret;

    ret = wc_ecc_init(&leafKey);
    if (ret != 0)
        return ret;
    ret = wc_ecc_make_key(rng, 32, &leafKey);
    if (ret != 0) {
        wc_ecc_free(&leafKey);
        return ret;
    }

    leafKeySz = wc_EccKeyToDer(&leafKey, leafKeyDer, KEY_CAP);
    if (leafKeySz <= 0) {
        wc_ecc_free(&leafKey);
        return leafKeySz;
    }
    *leafKeySzOut = leafKeySz;

    if (wc_InitCert(&leaf) != 0) {
        wc_ecc_free(&leafKey);
        return -1;
    }
    set_leaf_name(&leaf);
    leaf.sigType = caSigType;
    leaf.daysValid = 3650;
    set_fixed_validity(&leaf);
    if (wc_SetIssuerBuffer(&leaf, rootDer, rootSz) != 0) {
        wc_ecc_free(&leafKey);
        return -1;
    }
    if (wc_SetKeyUsage(&leaf, "digitalSignature") != 0) {
        wc_ecc_free(&leafKey);
        return -1;
    }
    if (wc_MakeCert_ex(&leaf, leafDer, DER_CAP, ECC_TYPE, &leafKey, rng) <= 0) {
        wc_ecc_free(&leafKey);
        return -1;
    }
    leafSz = wc_SignCert_ex(leaf.bodySz, caSigType, leafDer, DER_CAP,
        caKeyType, caKey, rng);
    wc_ecc_free(&leafKey);
    return leafSz;
}

static int verify_leaf(const unsigned char* rootDer, int rootSz,
    const unsigned char* leafDer, int leafSz)
{
    WOLFSSL_CERT_MANAGER* cm;
    int ret;

    cm = wolfSSL_CertManagerNew();
    if (cm == NULL)
        return MEMORY_E;
    ret = wolfSSL_CertManagerLoadCABuffer(cm, rootDer, rootSz,
        WOLFSSL_FILETYPE_ASN1);
    if (ret == WOLFSSL_SUCCESS)
        ret = wolfSSL_CertManagerVerifyBuffer(cm, leafDer, leafSz,
            WOLFSSL_FILETYPE_ASN1);
    wolfSSL_CertManagerFree(cm);
    return ret == WOLFSSL_SUCCESS ? 0 : ret;
}

static int generate_lms(const char* outdir, WC_RNG* rng,
    unsigned char* rootDer, int* rootSzOut, unsigned char* leafDer,
    int* leafSzOut, unsigned char* leafKeyDer, int* leafKeySzOut)
{
    LmsKey key;
    int rootSz;
    int leafSz;
    int ret = -1;
    int keyInitialized = 0;
    struct PhaseSample phase;

    phase_begin(&phase);
    XMEMSET(&key, 0, sizeof(key));
    g_state_path = "/tmp/peripheral-benchmark-lms.key";
    remove(g_state_path);
    if (wc_LmsKey_Init(&key, NULL, INVALID_DEVID) != 0)
        goto keygen_done;
    keyInitialized = 1;
    if (wc_LmsKey_SetParameters(&key, 2, 10, 4) != 0)
        goto keygen_done;
    if (wc_LmsKey_SetWriteCb(&key, hbs_write_key) != 0)
        goto keygen_done;
    if (wc_LmsKey_SetReadCb(&key, hbs_read_key) != 0)
        goto keygen_done;
    if (wc_LmsKey_SetContext(&key, (void*)g_state_path) != 0)
        goto keygen_done;
    if (wc_LmsKey_MakeKey(&key, rng) != 0)
        goto keygen_done;
    ret = 0;

keygen_done:
    phase_end("keygen", &phase, ret);
    if (ret != 0) {
        if (keyInitialized)
            wc_LmsKey_Free(&key);
        remove(g_state_path);
        return ret;
    }

    phase_begin(&phase);
    rootSz = make_root(&key, LMS_TYPE, CTC_HSS_LMS, rng,
        "LMS-HSS-L2-H10-W4 Root", rootDer);
    ret = rootSz > 0 ? 0 : rootSz;
    if (ret == 0) {
        leafSz = make_leaf(&key, LMS_TYPE, CTC_HSS_LMS, rng, rootDer, rootSz,
            leafDer, leafKeyDer, leafKeySzOut);
        ret = leafSz > 0 ? 0 : leafSz;
    }
    phase_end("sign_cert", &phase, ret);
    wc_LmsKey_Free(&key);
    remove(g_state_path);
    (void)outdir;
    if (ret != 0)
        return ret;
    *rootSzOut = rootSz;
    *leafSzOut = leafSz;
    return 0;
}

static int generate_xmss(const char* outdir, WC_RNG* rng,
    unsigned char* rootDer, int* rootSzOut, unsigned char* leafDer,
    int* leafSzOut, unsigned char* leafKeyDer, int* leafKeySzOut)
{
    XmssKey key;
    int rootSz;
    int leafSz;
    int ret = -1;
    int keyInitialized = 0;
    struct PhaseSample phase;

    phase_begin(&phase);
    XMEMSET(&key, 0, sizeof(key));
    g_state_path = "/tmp/peripheral-benchmark-xmss.key";
    remove(g_state_path);
    if (wc_XmssKey_Init(&key, NULL, INVALID_DEVID) != 0)
        goto keygen_done;
    keyInitialized = 1;
    if (wc_XmssKey_SetParamStr(&key, "XMSS-SHA2_20_256") != 0)
        goto keygen_done;
    if (wc_XmssKey_SetWriteCb(&key, xmss_write_key) != 0)
        goto keygen_done;
    if (wc_XmssKey_SetReadCb(&key, xmss_read_key) != 0)
        goto keygen_done;
    if (wc_XmssKey_SetContext(&key, (void*)g_state_path) != 0)
        goto keygen_done;
    if (wc_XmssKey_MakeKey(&key, rng) != 0)
        goto keygen_done;
    ret = 0;

keygen_done:
    phase_end("keygen", &phase, ret);
    if (ret != 0) {
        if (keyInitialized)
            wc_XmssKey_Free(&key);
        remove(g_state_path);
        return ret;
    }

    phase_begin(&phase);
    rootSz = make_root(&key, XMSS_TYPE, CTC_XMSS, rng,
        "XMSS-SHA2_20_256 Root", rootDer);
    ret = rootSz > 0 ? 0 : rootSz;
    if (ret == 0) {
        leafSz = make_leaf(&key, XMSS_TYPE, CTC_XMSS, rng, rootDer, rootSz,
            leafDer, leafKeyDer, leafKeySzOut);
        ret = leafSz > 0 ? 0 : leafSz;
    }
    phase_end("sign_cert", &phase, ret);
    wc_XmssKey_Free(&key);
    remove(g_state_path);
    (void)outdir;
    if (ret != 0)
        return ret;
    *rootSzOut = rootSz;
    *leafSzOut = leafSz;
    return 0;
}

int main(int argc, char** argv)
{
    const char* alg;
    const char* outdir;
    char path[1024];
    unsigned char* rootDer;
    unsigned char* leafDer;
    unsigned char* leafKeyDer;
    int rootSz = 0;
    int leafSz = 0;
    int leafKeySz = 0;
    int genRet;
    int phaseRet;
    int ret = 1;
    struct PhaseSample phase;
    WC_RNG rng;

    if (argc != 3) {
        fprintf(stderr, "usage: %s LMS-HSS-L2-H10-W4|XMSS-SHA2_20_256 OUTDIR\n", argv[0]);
        return 2;
    }
    alg = argv[1];
    outdir = argv[2];

    rootDer = malloc(DER_CAP);
    leafDer = malloc(DER_CAP);
    leafKeyDer = malloc(KEY_CAP);
    if (rootDer == NULL || leafDer == NULL || leafKeyDer == NULL)
        goto exit;

    wolfSSL_Init();
    if (wc_InitRng(&rng) != 0)
        goto exit;

    if (strcmp(alg, "LMS-HSS-L2-H10-W4") == 0) {
        genRet = generate_lms(outdir, &rng, rootDer, &rootSz, leafDer,
            &leafSz, leafKeyDer, &leafKeySz);
    }
    else if (strcmp(alg, "XMSS-SHA2_20_256") == 0) {
        genRet = generate_xmss(outdir, &rng, rootDer, &rootSz, leafDer,
            &leafSz, leafKeyDer, &leafKeySz);
    }
    else {
        fprintf(stderr, "unsupported algorithm: %s\n", alg);
        goto free_rng;
    }
    if (genRet != 0) {
        fprintf(stderr, "hash-based certificate generation failed: %d\n", genRet);
        goto free_rng;
    }

    snprintf(path, sizeof(path), "%s/server_root.der", outdir);
    phaseRet = write_file(path, rootDer, rootSz);
    if (phaseRet == 0) {
        snprintf(path, sizeof(path), "%s/server_root.crt", outdir);
        phaseRet = write_pem_cert(path, rootDer, rootSz);
    }
    if (phaseRet == 0) {
        snprintf(path, sizeof(path), "%s/server.crt", outdir);
        phaseRet = write_pem_cert(path, leafDer, leafSz);
    }
    if (phaseRet == 0) {
        snprintf(path, sizeof(path), "%s/server_chain.crt", outdir);
        phaseRet = write_pem_cert(path, leafDer, leafSz);
    }
    if (phaseRet == 0) {
        snprintf(path, sizeof(path), "%s/server.key", outdir);
        phaseRet = write_pem_key(path, leafKeyDer, leafKeySz);
    }
    if (phaseRet != 0)
        goto free_rng;

    phase_begin(&phase);
    phaseRet = verify_leaf(rootDer, rootSz, leafDer, leafSz);
    phase_end("verify_cert", &phase, phaseRet);
    if (phaseRet != 0)
        goto free_rng;

    ret = 0;

free_rng:
    wc_FreeRng(&rng);
exit:
    free(rootDer);
    free(leafDer);
    free(leafKeyDer);
    wolfSSL_Cleanup();
    return ret;
}
