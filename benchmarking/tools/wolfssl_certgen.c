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
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/wolfcrypt/wc_slhdsa.h>

#define DER_CAP 65536
#define KEY_CAP 32768
#define CERT_NOT_BEFORE "\x18\x0f""20200101000000Z"
#define CERT_NOT_AFTER  "\x18\x0f""20360101000000Z"

enum KeyKind {
    KEY_ECC,
    KEY_RSA,
    KEY_MLDSA,
    KEY_SLHDSA
};

struct Algorithm {
    const char* name;
    enum KeyKind kind;
    int curve_id;
    int rsa_bits;
    int key_type;
    int sig_type;
    int mldsa_level;
    enum SlhDsaParam slhdsa_param;
};

struct PhaseSample {
    struct timespec wall;
    struct rusage usage;
};

static const struct Algorithm ALGORITHMS[] = {
    {
        "ECDSA-P-256", KEY_ECC, ECC_SECP256R1, 0, ECC_TYPE,
        CTC_SHA256wECDSA, 0, SLHDSA_SHAKE128S
    },
    {
        "ECDSA-P-384", KEY_ECC, ECC_SECP384R1, 0, ECC_TYPE,
        CTC_SHA384wECDSA, 0, SLHDSA_SHAKE128S
    },
    {
        "ECDSA-P-521", KEY_ECC, ECC_SECP521R1, 0, ECC_TYPE,
        CTC_SHA512wECDSA, 0, SLHDSA_SHAKE128S
    },
    {
        "RSA-PSS-3072", KEY_RSA, 0, 3072, RSA_TYPE,
        CTC_SHA256wRSA, 0, SLHDSA_SHAKE128S
    },
    {
        "RSA-PSS-7680", KEY_RSA, 0, 7680, RSA_TYPE,
        CTC_SHA384wRSA, 0, SLHDSA_SHAKE128S
    },
    {
        "RSA-PSS-15360", KEY_RSA, 0, 15360, RSA_TYPE,
        CTC_SHA512wRSA, 0, SLHDSA_SHAKE128S
    },
    {
        "ML-DSA-44", KEY_MLDSA, 0, 0, ML_DSA_44_TYPE,
        CTC_ML_DSA_44, WC_ML_DSA_44, SLHDSA_SHAKE128S
    },
    {
        "ML-DSA-65", KEY_MLDSA, 0, 0, ML_DSA_65_TYPE,
        CTC_ML_DSA_65, WC_ML_DSA_65, SLHDSA_SHAKE128S
    },
    {
        "ML-DSA-87", KEY_MLDSA, 0, 0, ML_DSA_87_TYPE,
        CTC_ML_DSA_87, WC_ML_DSA_87, SLHDSA_SHAKE128S
    },
    {
        "SLH-DSA-SHAKE-128s", KEY_SLHDSA, 0, 0,
        SLH_DSA_SHAKE_128S_TYPE, CTC_SLH_DSA_SHAKE_128S,
        0, SLHDSA_SHAKE128S
    },
    {
        "SLH-DSA-SHAKE-128f", KEY_SLHDSA, 0, 0,
        SLH_DSA_SHAKE_128F_TYPE, CTC_SLH_DSA_SHAKE_128F,
        0, SLHDSA_SHAKE128F
    },
    {
        "SLH-DSA-SHAKE-192s", KEY_SLHDSA, 0, 0,
        SLH_DSA_SHAKE_192S_TYPE, CTC_SLH_DSA_SHAKE_192S,
        0, SLHDSA_SHAKE192S
    },
    {
        "SLH-DSA-SHAKE-192f", KEY_SLHDSA, 0, 0,
        SLH_DSA_SHAKE_192F_TYPE, CTC_SLH_DSA_SHAKE_192F,
        0, SLHDSA_SHAKE192F
    },
    {
        "SLH-DSA-SHAKE-256s", KEY_SLHDSA, 0, 0,
        SLH_DSA_SHAKE_256S_TYPE, CTC_SLH_DSA_SHAKE_256S,
        0, SLHDSA_SHAKE256S
    },
    {
        "SLH-DSA-SHAKE-256f", KEY_SLHDSA, 0, 0,
        SLH_DSA_SHAKE_256F_TYPE, CTC_SLH_DSA_SHAKE_256F,
        0, SLHDSA_SHAKE256F
    },
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

static int write_pem_cert(const char* path, const unsigned char* der, int derSz)
{
    unsigned char* pem;
    int pemSz;
    int ret;

    pem = (unsigned char*)malloc(DER_CAP * 2);
    if (pem == NULL)
        return MEMORY_E;
    pemSz = wc_DerToPem(der, derSz, pem, DER_CAP * 2, CERT_TYPE);
    ret = pemSz > 0 ? write_file(path, pem, pemSz) : pemSz;
    free(pem);
    return ret;
}

static int write_pem_key(
    const char* path, const unsigned char* der, int derSz, int pemType)
{
    unsigned char* pem;
    int pemSz;
    int ret;

    pem = (unsigned char*)malloc(KEY_CAP * 2);
    if (pem == NULL)
        return MEMORY_E;
    pemSz = wc_DerToPem(der, derSz, pem, KEY_CAP * 2, pemType);
    ret = pemSz > 0 ? write_file(path, pem, pemSz) : pemSz;
    free(pem);
    return ret;
}

static void set_fixed_validity(Cert* cert)
{
    XMEMCPY(cert->beforeDate, CERT_NOT_BEFORE, sizeof(CERT_NOT_BEFORE) - 1);
    cert->beforeDateSz = sizeof(CERT_NOT_BEFORE) - 1;
    XMEMCPY(cert->afterDate, CERT_NOT_AFTER, sizeof(CERT_NOT_AFTER) - 1);
    cert->afterDateSz = sizeof(CERT_NOT_AFTER) - 1;
}

static void set_name(Cert* cert, const char* unit, const char* common_name)
{
    XSTRNCPY(cert->subject.country, "US", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.state, "OR", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.locality, "Portland", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.org, "Peripheral Benchmark", CTC_NAME_SIZE);
    snprintf(cert->subject.unit, sizeof(cert->subject.unit), "%s", unit);
    snprintf(cert->subject.commonName, sizeof(cert->subject.commonName), "%s",
        common_name);
}

static const struct Algorithm* find_algorithm(const char* name)
{
    size_t i;

    for (i = 0; i < sizeof(ALGORITHMS) / sizeof(ALGORITHMS[0]); i++) {
        if (strcmp(ALGORITHMS[i].name, name) == 0)
            return &ALGORITHMS[i];
    }
    return NULL;
}

static int make_key(const struct Algorithm* alg, WC_RNG* rng, void** key_out)
{
    int ret;

    if (alg->kind == KEY_ECC) {
        ecc_key* key = (ecc_key*)malloc(sizeof(*key));
        if (key == NULL)
            return MEMORY_E;
        ret = wc_ecc_init(key);
        if (ret == 0)
            ret = wc_ecc_make_key_ex(rng, 0, key, alg->curve_id);
        if (ret != 0) {
            wc_ecc_free(key);
            free(key);
            return ret;
        }
        *key_out = key;
        return 0;
    }

    if (alg->kind == KEY_RSA) {
        RsaKey* key = (RsaKey*)malloc(sizeof(*key));
        if (key == NULL)
            return MEMORY_E;
        ret = wc_InitRsaKey(key, NULL);
        if (ret == 0)
            ret = wc_MakeRsaKey(key, alg->rsa_bits, 65537, rng);
        if (ret != 0) {
            wc_FreeRsaKey(key);
            free(key);
            return ret;
        }
        *key_out = key;
        return 0;
    }

    if (alg->kind == KEY_MLDSA) {
        wc_MlDsaKey* key = (wc_MlDsaKey*)malloc(sizeof(*key));
        if (key == NULL)
            return MEMORY_E;
        ret = wc_MlDsaKey_Init(key, NULL, INVALID_DEVID);
        if (ret == 0)
            ret = wc_MlDsaKey_SetParams(key, (byte)alg->mldsa_level);
        if (ret == 0)
            ret = wc_MlDsaKey_MakeKey(key, rng);
        if (ret != 0) {
            wc_MlDsaKey_Free(key);
            free(key);
            return ret;
        }
        *key_out = key;
        return 0;
    }

    if (alg->kind == KEY_SLHDSA) {
        SlhDsaKey* key = (SlhDsaKey*)malloc(sizeof(*key));
        if (key == NULL)
            return MEMORY_E;
        ret = wc_SlhDsaKey_Init(key, alg->slhdsa_param, NULL, INVALID_DEVID);
        if (ret == 0)
            ret = wc_SlhDsaKey_MakeKey(key, rng);
        if (ret != 0) {
            wc_SlhDsaKey_Free(key);
            free(key);
            return ret;
        }
        *key_out = key;
        return 0;
    }

    return BAD_FUNC_ARG;
}

static void free_key(const struct Algorithm* alg, void* key)
{
    if (key == NULL)
        return;
    if (alg->kind == KEY_ECC)
        wc_ecc_free((ecc_key*)key);
    else if (alg->kind == KEY_RSA)
        wc_FreeRsaKey((RsaKey*)key);
    else if (alg->kind == KEY_MLDSA)
        wc_MlDsaKey_Free((wc_MlDsaKey*)key);
    else if (alg->kind == KEY_SLHDSA)
        wc_SlhDsaKey_Free((SlhDsaKey*)key);
    free(key);
}

static int key_to_der(
    const struct Algorithm* alg, void* key, unsigned char* der, int derCap)
{
    if (alg->kind == KEY_ECC)
        return wc_EccKeyToDer((ecc_key*)key, der, derCap);
    if (alg->kind == KEY_RSA)
        return wc_RsaKeyToDer((RsaKey*)key, der, derCap);
    if (alg->kind == KEY_MLDSA)
        return wc_MlDsaKey_KeyToDer((wc_MlDsaKey*)key, der, derCap);
    if (alg->kind == KEY_SLHDSA)
        return wc_SlhDsaKey_KeyToDer((SlhDsaKey*)key, der, derCap);
    return BAD_FUNC_ARG;
}

static int key_pem_type(const struct Algorithm* alg)
{
    if (alg->kind == KEY_ECC)
        return ECC_PRIVATEKEY_TYPE;
    if (alg->kind == KEY_RSA)
        return PRIVATEKEY_TYPE;
    return PKCS8_PRIVATEKEY_TYPE;
}

static int write_key_file(
    const struct Algorithm* alg, const char* path,
    const unsigned char* der, int derSz)
{
    int ret = write_pem_key(path, der, derSz, key_pem_type(alg));
    if (ret != 0 && (alg->kind == KEY_MLDSA || alg->kind == KEY_SLHDSA))
        ret = write_file(path, der, derSz);
    return ret;
}

static int make_root(
    const struct Algorithm* alg, void* rootKey, WC_RNG* rng,
    unsigned char* rootDer)
{
    Cert root;
    int ret;

    ret = wc_InitCert(&root);
    if (ret != 0)
        return ret;
    set_name(&root, "wolfSSL Root", "Peripheral Benchmark wolfSSL Root");
    root.sigType = alg->sig_type;
    root.isCA = 1;
    root.selfSigned = 1;
    root.daysValid = 3650;
    set_fixed_validity(&root);
    ret = wc_SetKeyUsage(&root, "keyCertSign,cRLSign");
    if (ret != 0)
        return ret;
    ret = wc_MakeCert_ex(&root, rootDer, DER_CAP, alg->key_type, rootKey, rng);
    if (ret <= 0)
        return ret;
    return wc_SignCert_ex(root.bodySz, alg->sig_type, rootDer, DER_CAP,
        alg->key_type, rootKey, rng);
}

static int make_leaf(
    const struct Algorithm* alg, void* rootKey, const unsigned char* rootDer,
    int rootSz, void* leafKey, WC_RNG* rng, unsigned char* leafDer)
{
    Cert leaf;
    int ret;

    ret = wc_InitCert(&leaf);
    if (ret != 0)
        return ret;
    set_name(&leaf, "TLS Server", "localhost");
    leaf.sigType = alg->sig_type;
    leaf.daysValid = 3650;
    set_fixed_validity(&leaf);
    ret = wc_SetIssuerBuffer(&leaf, rootDer, rootSz);
    if (ret != 0)
        return ret;
    ret = wc_SetKeyUsage(&leaf, "digitalSignature,keyEncipherment");
    if (ret != 0)
        return ret;
    ret = wc_SetExtKeyUsage(&leaf, "serverAuth");
    if (ret != 0)
        return ret;
    ret = wc_MakeCert_ex(&leaf, leafDer, DER_CAP, alg->key_type, leafKey, rng);
    if (ret <= 0)
        return ret;
    return wc_SignCert_ex(leaf.bodySz, alg->sig_type, leafDer, DER_CAP,
        alg->key_type, rootKey, rng);
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

int main(int argc, char** argv)
{
    const struct Algorithm* alg;
    const char* outdir;
    char path[1024];
    unsigned char* rootDer = NULL;
    unsigned char* leafDer = NULL;
    unsigned char* leafKeyDer = NULL;
    void* rootKey = NULL;
    void* leafKey = NULL;
    int rootSz;
    int leafSz;
    int leafKeySz;
    int phaseRet;
    int ret = 1;
    struct PhaseSample phase;
    WC_RNG rng;

    if (argc != 3) {
        fprintf(stderr, "usage: %s SIGNATURE_ALGORITHM OUTDIR\n", argv[0]);
        return 2;
    }
    alg = find_algorithm(argv[1]);
    if (alg == NULL) {
        fprintf(stderr, "unsupported wolfSSL certificate algorithm: %s\n", argv[1]);
        return 2;
    }
    outdir = argv[2];

    rootDer = (unsigned char*)malloc(DER_CAP);
    leafDer = (unsigned char*)malloc(DER_CAP);
    leafKeyDer = (unsigned char*)malloc(KEY_CAP);
    if (rootDer == NULL || leafDer == NULL || leafKeyDer == NULL)
        goto exit;

    wolfSSL_Init();
    if (wc_InitRng(&rng) != 0)
        goto cleanup_ssl;

    phase_begin(&phase);
    phaseRet = make_key(alg, &rng, &rootKey);
    if (phaseRet == 0)
        phaseRet = make_key(alg, &rng, &leafKey);
    phase_end("keygen", &phase, phaseRet);
    if (phaseRet != 0)
        goto cleanup_rng;

    phase_begin(&phase);
    rootSz = make_root(alg, rootKey, &rng, rootDer);
    phaseRet = rootSz > 0 ? 0 : rootSz;
    if (phaseRet == 0) {
        leafSz = make_leaf(alg, rootKey, rootDer, rootSz, leafKey, &rng, leafDer);
        phaseRet = leafSz > 0 ? 0 : leafSz;
    }
    phase_end("sign_cert", &phase, phaseRet);
    if (phaseRet != 0)
        goto cleanup_rng;

    leafKeySz = key_to_der(alg, leafKey, leafKeyDer, KEY_CAP);
    phaseRet = leafKeySz > 0 ? 0 : leafKeySz;
    if (phaseRet == 0) {
        snprintf(path, sizeof(path), "%s/server_root.der", outdir);
        phaseRet = write_file(path, rootDer, rootSz);
    }
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
        phaseRet = write_key_file(alg, path, leafKeyDer, leafKeySz);
    }
    if (phaseRet != 0)
        goto cleanup_rng;

    phase_begin(&phase);
    phaseRet = verify_leaf(rootDer, rootSz, leafDer, leafSz);
    phase_end("verify_cert", &phase, phaseRet);
    if (phaseRet != 0)
        goto cleanup_rng;

    ret = 0;

cleanup_rng:
    free_key(alg, leafKey);
    free_key(alg, rootKey);
    wc_FreeRng(&rng);
cleanup_ssl:
    wolfSSL_Cleanup();
exit:
    free(rootDer);
    free(leafDer);
    free(leafKeyDer);
    return ret;
}
