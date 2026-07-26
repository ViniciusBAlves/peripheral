#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static void set_leaf_name(Cert* cert, const char* commonName)
{
    XSTRNCPY(cert->subject.country, "US", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.state, "OR", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.locality, "Portland", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.org, "Peripheral Benchmark", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.unit, "TLS Leaf", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.commonName, commonName, CTC_NAME_SIZE);
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
    unsigned char* leafKeyDer, int* leafKeySzOut, const char* commonName)
{
    Cert leaf;
    ecc_key leafKey;
    int leafSz;
    int leafKeySz;
    int ret;

    ret = wc_ecc_init(&leafKey);
    if (ret != 0)
        return ret;
    if (*leafKeySzOut > 0) {
        word32 keyIdx = 0;
        ret = wc_EccPrivateKeyDecode(
            leafKeyDer, &keyIdx, &leafKey, (word32)*leafKeySzOut);
        if (ret != 0) {
            wc_ecc_free(&leafKey);
            return ret;
        }
    } else {
        ret = wc_ecc_make_key(rng, 32, &leafKey);
        if (ret != 0) {
            wc_ecc_free(&leafKey);
            return ret;
        }
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
    set_leaf_name(&leaf, commonName);
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

static int generate_lms(const char* outdir, WC_RNG* rng,
    unsigned char* rootDer, int* rootSzOut, unsigned char* leafDer,
    int* leafSzOut, unsigned char* leafKeyDer, int* leafKeySzOut,
    unsigned char* clientDer, int* clientSzOut,
    unsigned char* clientKeyDer, int* clientKeySzOut)
{
    LmsKey key;
    int rootSz;
    int leafSz;

    XMEMSET(&key, 0, sizeof(key));
    g_state_path = "/tmp/peripheral-benchmark-lms.key";
    remove(g_state_path);
    if (wc_LmsKey_Init(&key, NULL, INVALID_DEVID) != 0)
        return -1;
    if (wc_LmsKey_SetParameters(&key, 2, 10, 4) != 0)
        return -1;
    if (wc_LmsKey_SetWriteCb(&key, hbs_write_key) != 0)
        return -1;
    if (wc_LmsKey_SetReadCb(&key, hbs_read_key) != 0)
        return -1;
    if (wc_LmsKey_SetContext(&key, (void*)g_state_path) != 0)
        return -1;
    if (wc_LmsKey_MakeKey(&key, rng) != 0)
        return -1;

    rootSz = make_root(&key, LMS_TYPE, CTC_HSS_LMS, rng,
        "LMS-HSS-L2-H10-W4 Root", rootDer);
    if (rootSz <= 0)
        return rootSz;
    leafSz = make_leaf(&key, LMS_TYPE, CTC_HSS_LMS, rng, rootDer, rootSz,
        leafDer, leafKeyDer, leafKeySzOut, "localhost");
    if (leafSz > 0) {
        *clientSzOut = make_leaf(&key, LMS_TYPE, CTC_HSS_LMS, rng,
            rootDer, rootSz, clientDer, clientKeyDer, clientKeySzOut,
            "nrf5340-benchmark");
    }
    wc_LmsKey_Free(&key);
    remove(g_state_path);
    (void)outdir;
    if (leafSz <= 0 || *clientSzOut <= 0)
        return leafSz;
    *rootSzOut = rootSz;
    *leafSzOut = leafSz;
    return 0;
}

static int generate_xmss(const char* outdir, WC_RNG* rng,
    unsigned char* rootDer, int* rootSzOut, unsigned char* leafDer,
    int* leafSzOut, unsigned char* leafKeyDer, int* leafKeySzOut,
    unsigned char* clientDer, int* clientSzOut,
    unsigned char* clientKeyDer, int* clientKeySzOut)
{
    XmssKey key;
    int rootSz;
    int leafSz;

    XMEMSET(&key, 0, sizeof(key));
    g_state_path = "/tmp/peripheral-benchmark-xmss.key";
    remove(g_state_path);
    if (wc_XmssKey_Init(&key, NULL, INVALID_DEVID) != 0)
        return -1;
    if (wc_XmssKey_SetParamStr(&key, "XMSS-SHA2_20_256") != 0)
        return -1;
    if (wc_XmssKey_SetWriteCb(&key, xmss_write_key) != 0)
        return -1;
    if (wc_XmssKey_SetReadCb(&key, xmss_read_key) != 0)
        return -1;
    if (wc_XmssKey_SetContext(&key, (void*)g_state_path) != 0)
        return -1;
    if (wc_XmssKey_MakeKey(&key, rng) != 0)
        return -1;

    rootSz = make_root(&key, XMSS_TYPE, CTC_XMSS, rng,
        "XMSS-SHA2_20_256 Root", rootDer);
    if (rootSz <= 0)
        return rootSz;
    leafSz = make_leaf(&key, XMSS_TYPE, CTC_XMSS, rng, rootDer, rootSz,
        leafDer, leafKeyDer, leafKeySzOut, "localhost");
    if (leafSz > 0) {
        *clientSzOut = make_leaf(&key, XMSS_TYPE, CTC_XMSS, rng,
            rootDer, rootSz, clientDer, clientKeyDer, clientKeySzOut,
            "nrf5340-benchmark");
    }
    wc_XmssKey_Free(&key);
    remove(g_state_path);
    (void)outdir;
    if (leafSz <= 0 || *clientSzOut <= 0)
        return leafSz;
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
    unsigned char* clientDer;
    unsigned char* clientKeyDer;
    int rootSz = 0;
    int leafSz = 0;
    int leafKeySz = 0;
    int clientSz = 0;
    int clientKeySz = 0;
    int genRet;
    int ret = 1;
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
    clientDer = malloc(DER_CAP);
    clientKeyDer = malloc(KEY_CAP);
    if (rootDer == NULL || leafDer == NULL || leafKeyDer == NULL ||
        clientDer == NULL || clientKeyDer == NULL)
        goto exit;

    wolfSSL_Init();
    if (wc_InitRng(&rng) != 0)
        goto exit;
    snprintf(path, sizeof(path), "%s/client_key.der", outdir);
    clientKeySz = read_file(path, clientKeyDer, KEY_CAP);
    if (clientKeySz <= 0) {
        fprintf(stderr, "shared client key is missing: %s\n", path);
        goto free_rng;
    }

    if (strcmp(alg, "LMS-HSS-L2-H10-W4") == 0) {
        genRet = generate_lms(outdir, &rng, rootDer, &rootSz, leafDer,
            &leafSz, leafKeyDer, &leafKeySz, clientDer, &clientSz,
            clientKeyDer, &clientKeySz);
    }
    else if (strcmp(alg, "XMSS-SHA2_20_256") == 0) {
        genRet = generate_xmss(outdir, &rng, rootDer, &rootSz, leafDer,
            &leafSz, leafKeyDer, &leafKeySz, clientDer, &clientSz,
            clientKeyDer, &clientKeySz);
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
    if (write_file(path, rootDer, rootSz) != 0)
        goto free_rng;
    snprintf(path, sizeof(path), "%s/server_root.crt", outdir);
    if (write_pem_cert(path, rootDer, rootSz) != 0)
        goto free_rng;

    snprintf(path, sizeof(path), "%s/server.crt", outdir);
    if (write_pem_cert(path, leafDer, leafSz) != 0)
        goto free_rng;
    snprintf(path, sizeof(path), "%s/server_chain.crt", outdir);
    if (write_pem_cert(path, leafDer, leafSz) != 0)
        goto free_rng;
    {
        FILE* chain = fopen(path, "ab");
        unsigned char pem[DER_CAP * 2];
        int pemSz = wc_DerToPem(rootDer, rootSz, pem, sizeof(pem), CERT_TYPE);
        if (chain == NULL || pemSz <= 0 ||
            fwrite(pem, 1, (size_t)pemSz, chain) != (size_t)pemSz) {
            if (chain != NULL)
                fclose(chain);
            goto free_rng;
        }
        fclose(chain);
    }
    snprintf(path, sizeof(path), "%s/server.key", outdir);
    if (write_pem_key(path, leafKeyDer, leafKeySz) != 0)
        goto free_rng;
    snprintf(path, sizeof(path), "%s/client.crt", outdir);
    if (write_pem_cert(path, clientDer, clientSz) != 0)
        goto free_rng;
    snprintf(path, sizeof(path), "%s/client.key", outdir);
    if (write_pem_key(path, clientKeyDer, clientKeySz) != 0)
        goto free_rng;
    snprintf(path, sizeof(path), "%s/client_cert.der", outdir);
    if (write_file(path, clientDer, clientSz) != 0)
        goto free_rng;
    snprintf(path, sizeof(path), "%s/client_key.der", outdir);
    if (write_file(path, clientKeyDer, clientKeySz) != 0)
        goto free_rng;

    ret = 0;

free_rng:
    wc_FreeRng(&rng);
exit:
    free(rootDer);
    free(leafDer);
    free(leafKeyDer);
    free(clientDer);
    free(clientKeyDer);
    wolfSSL_Cleanup();
    return ret;
}
