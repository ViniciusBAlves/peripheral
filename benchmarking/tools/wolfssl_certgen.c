#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>

#define DER_CAP 32768
#define KEY_CAP 32768
#define CERT_NOT_BEFORE "\x18\x0f""20200101000000Z"
#define CERT_NOT_AFTER  "\x18\x0f""20360101000000Z"

enum KeyKind {
    KEY_ECC,
    KEY_RSA
};

struct Algorithm {
    const char* name;
    enum KeyKind kind;
    int curve_id;
    int rsa_bits;
    int key_type;
    int sig_type;
};

static const struct Algorithm ALGORITHMS[] = {
    {
        "ECDSA-P-256", KEY_ECC, ECC_SECP256R1, 0, ECC_TYPE,
        CTC_SHA256wECDSA
    },
    {
        "ECDSA-P-384", KEY_ECC, ECC_SECP384R1, 0, ECC_TYPE,
        CTC_SHA384wECDSA
    },
    {
        "ECDSA-P-521", KEY_ECC, ECC_SECP521R1, 0, ECC_TYPE,
        CTC_SHA512wECDSA
    },
    {
        "RSA-PSS-3072", KEY_RSA, 0, 3072, RSA_TYPE,
        CTC_SHA256wRSA
    },
    {
        "RSA-PSS-7680", KEY_RSA, 0, 7680, RSA_TYPE,
        CTC_SHA384wRSA
    },
    {
        "RSA-PSS-15360", KEY_RSA, 0, 15360, RSA_TYPE,
        CTC_SHA512wRSA
    },
};

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
    free(key);
}

static int key_to_der(
    const struct Algorithm* alg, void* key, unsigned char* der, int derCap)
{
    if (alg->kind == KEY_ECC)
        return wc_EccKeyToDer((ecc_key*)key, der, derCap);
    if (alg->kind == KEY_RSA)
        return wc_RsaKeyToDer((RsaKey*)key, der, derCap);
    return BAD_FUNC_ARG;
}

static int key_pem_type(const struct Algorithm* alg)
{
    return alg->kind == KEY_ECC ? ECC_PRIVATEKEY_TYPE : PRIVATEKEY_TYPE;
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
    int ret = 1;
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

    if (make_key(alg, &rng, &rootKey) != 0)
        goto cleanup_rng;
    if (make_key(alg, &rng, &leafKey) != 0)
        goto cleanup_rng;

    rootSz = make_root(alg, rootKey, &rng, rootDer);
    if (rootSz <= 0)
        goto cleanup_rng;
    leafSz = make_leaf(alg, rootKey, rootDer, rootSz, leafKey, &rng, leafDer);
    if (leafSz <= 0)
        goto cleanup_rng;
    leafKeySz = key_to_der(alg, leafKey, leafKeyDer, KEY_CAP);
    if (leafKeySz <= 0)
        goto cleanup_rng;

    snprintf(path, sizeof(path), "%s/server_root.der", outdir);
    if (write_file(path, rootDer, rootSz) != 0)
        goto cleanup_rng;
    snprintf(path, sizeof(path), "%s/server_root.crt", outdir);
    if (write_pem_cert(path, rootDer, rootSz) != 0)
        goto cleanup_rng;
    snprintf(path, sizeof(path), "%s/server.crt", outdir);
    if (write_pem_cert(path, leafDer, leafSz) != 0)
        goto cleanup_rng;
    snprintf(path, sizeof(path), "%s/server_chain.crt", outdir);
    if (write_pem_cert(path, leafDer, leafSz) != 0)
        goto cleanup_rng;
    snprintf(path, sizeof(path), "%s/server.key", outdir);
    if (write_pem_key(path, leafKeyDer, leafKeySz, key_pem_type(alg)) != 0)
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
