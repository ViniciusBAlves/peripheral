#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_lms.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/wolfcrypt/wc_xmss.h>

#define DER_CAP 65536
#define KEY_CAP 16384
#define CERT_NOT_BEFORE "\x18\x0f""20200101000000Z"
#define CERT_NOT_AFTER  "\x18\x0f""20360101000000Z"

struct light_key {
    int key_type;
    int sig_type;
    int pem_type;
    union {
        ecc_key ecc;
        MlDsaKey mldsa;
    } key;
};

static int write_file(const char *path, const unsigned char *data, int len)
{
    FILE *stream = fopen(path, "wb");
    if (stream == NULL || fwrite(data, 1, (size_t)len, stream) != (size_t)len) {
        if (stream != NULL)
            fclose(stream);
        return -1;
    }
    return fclose(stream);
}

static int read_file(const char *path, unsigned char *data, int capacity)
{
    long length;
    FILE *stream = fopen(path, "rb");
    if (stream == NULL || fseek(stream, 0, SEEK_END) != 0)
        return -1;
    length = ftell(stream);
    if (length < 0 || length > capacity) {
        fclose(stream);
        return -1;
    }
    rewind(stream);
    if (fread(data, 1, (size_t)length, stream) != (size_t)length) {
        fclose(stream);
        return -1;
    }
    fclose(stream);
    return (int)length;
}

static int path_join(char *path, size_t size, const char *directory,
                     const char *name)
{
    int length = snprintf(path, size, "%s/%s", directory, name);
    return length > 0 && (size_t)length < size ? 0 : -1;
}

static int write_pem(const char *path, const unsigned char *der, int der_size,
                     int type)
{
    unsigned char *pem = malloc((size_t)der_size * 2U + 1024U);
    int pem_size;
    int result;
    if (pem == NULL)
        return -1;
    pem_size = wc_DerToPem(der, der_size, pem,
                           (word32)((size_t)der_size * 2U + 1024U), type);
    result = pem_size > 0 ? write_file(path, pem, pem_size) : pem_size;
    free(pem);
    return result;
}

static int append_pem_cert(const char *path, const unsigned char *der, int der_size)
{
    unsigned char *pem = malloc((size_t)der_size * 2U + 1024U);
    FILE *stream;
    int pem_size;
    int result = -1;
    if (pem == NULL)
        return -1;
    pem_size = wc_DerToPem(der, der_size, pem,
                           (word32)((size_t)der_size * 2U + 1024U), CERT_TYPE);
    stream = pem_size > 0 ? fopen(path, "ab") : NULL;
    if (stream != NULL && fwrite(pem, 1, (size_t)pem_size, stream) == (size_t)pem_size)
        result = fclose(stream);
    else if (stream != NULL)
        fclose(stream);
    free(pem);
    return result;
}

static int lms_write(const unsigned char *private_key, unsigned int size, void *context)
{
    return write_file((const char *)context, private_key, (int)size) == 0
        ? WC_LMS_RC_SAVED_TO_NV_MEMORY : WC_LMS_RC_WRITE_FAIL;
}

static int lms_read(unsigned char *private_key, unsigned int size, void *context)
{
    return read_file((const char *)context, private_key, (int)size) > 0
        ? WC_LMS_RC_READ_TO_MEMORY : WC_LMS_RC_READ_FAIL;
}

static enum wc_XmssRc xmss_write(const unsigned char *private_key,
                                 unsigned int size, void *context)
{
    return write_file((const char *)context, private_key, (int)size) == 0
        ? WC_XMSS_RC_SAVED_TO_NV_MEMORY : WC_XMSS_RC_WRITE_FAIL;
}

static enum wc_XmssRc xmss_read(unsigned char *private_key,
                                unsigned int size, void *context)
{
    return read_file((const char *)context, private_key, (int)size) > 0
        ? WC_XMSS_RC_READ_TO_MEMORY : WC_XMSS_RC_READ_FAIL;
}

static void set_name(Cert *certificate, const char *unit, const char *common_name)
{
    XSTRNCPY(certificate->subject.country, "CA", CTC_NAME_SIZE);
    XSTRNCPY(certificate->subject.state, "QC", CTC_NAME_SIZE);
    XSTRNCPY(certificate->subject.locality, "Montreal", CTC_NAME_SIZE);
    XSTRNCPY(certificate->subject.org, "Peripheral Benchmark", CTC_NAME_SIZE);
    snprintf(certificate->subject.unit, CTC_NAME_SIZE, "%s", unit);
    snprintf(certificate->subject.commonName, CTC_NAME_SIZE, "%s", common_name);
}

static void set_validity(Cert *certificate)
{
    XMEMCPY(certificate->beforeDate, CERT_NOT_BEFORE, sizeof(CERT_NOT_BEFORE) - 1);
    certificate->beforeDateSz = sizeof(CERT_NOT_BEFORE) - 1;
    XMEMCPY(certificate->afterDate, CERT_NOT_AFTER, sizeof(CERT_NOT_AFTER) - 1);
    certificate->afterDateSz = sizeof(CERT_NOT_AFTER) - 1;
    certificate->daysValid = 3650;
}

static int make_certificate(void *subject_key, int subject_key_type,
                            void *signing_key, int signing_key_type,
                            int signature_type, const unsigned char *issuer_der,
                            int issuer_size, int is_ca, const char *unit,
                            const char *common_name, WC_RNG *rng,
                            unsigned char *certificate_der)
{
    Cert certificate;
    int result = wc_InitCert(&certificate);
    if (result != 0)
        return result;
    set_name(&certificate, unit, common_name);
    set_validity(&certificate);
    certificate.sigType = signature_type;
    certificate.isCA = is_ca;
    certificate.selfSigned = issuer_der == NULL;
    if (issuer_der != NULL) {
        result = wc_SetIssuerBuffer(&certificate, issuer_der, issuer_size);
        if (result != 0)
            return result;
    }
    result = wc_SetKeyUsage(&certificate,
        is_ca ? "keyCertSign,cRLSign" : "digitalSignature");
    if (result != 0)
        return result;
    result = wc_MakeCert_ex(&certificate, certificate_der, DER_CAP,
                            subject_key_type, subject_key, rng);
    if (result <= 0)
        return result;
    return wc_SignCert_ex(certificate.bodySz, signature_type, certificate_der,
                          DER_CAP, signing_key_type, signing_key, rng);
}

static int light_key_init(struct light_key *key, const char *algorithm, WC_RNG *rng)
{
    int result;
    XMEMSET(key, 0, sizeof(*key));
    if (strncmp(algorithm, "ECDSA-P-", 8) == 0) {
        int key_size;
        int curve_id;
        key->key_type = ECC_TYPE;
        key->pem_type = ECC_PRIVATEKEY_TYPE;
        if (strcmp(algorithm, "ECDSA-P-256") == 0) {
            key_size = 32;
            curve_id = ECC_SECP256R1;
            key->sig_type = CTC_SHA256wECDSA;
        }
        else if (strcmp(algorithm, "ECDSA-P-384") == 0) {
            key_size = 48;
            curve_id = ECC_SECP384R1;
            key->sig_type = CTC_SHA384wECDSA;
        }
        else if (strcmp(algorithm, "ECDSA-P-521") == 0) {
            key_size = 66;
            curve_id = ECC_SECP521R1;
            key->sig_type = CTC_SHA512wECDSA;
        }
        else {
            fprintf(stderr, "unsupported ECDSA algorithm: %s\n", algorithm);
            return -1;
        }
        result = wc_ecc_init(&key->key.ecc);
        if (result == 0)
            result = wc_ecc_make_key_ex(rng, key_size, &key->key.ecc, curve_id);
        return result;
    }
    if (strcmp(algorithm, "ML-DSA-87") == 0) {
        key->key_type = ML_DSA_87_TYPE;
        key->sig_type = CTC_ML_DSA_87;
        key->pem_type = PKCS8_PRIVATEKEY_TYPE;
        result = wc_MlDsaKey_Init(&key->key.mldsa, NULL, INVALID_DEVID);
        if (result == 0)
            result = wc_MlDsaKey_SetParams(&key->key.mldsa, WC_ML_DSA_87);
        if (result == 0)
            result = wc_MlDsaKey_MakeKey(&key->key.mldsa, rng);
        return result;
    }
    fprintf(stderr, "unsupported subordinate algorithm: %s\n", algorithm);
    return -1;
}

static void *light_key_pointer(struct light_key *key)
{
    return key->key_type == ECC_TYPE ? (void *)&key->key.ecc
                                     : (void *)&key->key.mldsa;
}

static int light_key_der(struct light_key *key, unsigned char *der)
{
    return key->key_type == ECC_TYPE
        ? wc_EccKeyToDer(&key->key.ecc, der, KEY_CAP)
        : wc_MlDsaKey_KeyToDer(&key->key.mldsa, der, KEY_CAP);
}

static void light_key_free(struct light_key *key)
{
    if (key->key_type == ECC_TYPE)
        wc_ecc_free(&key->key.ecc);
    else
        wc_MlDsaKey_Free(&key->key.mldsa);
}

static int configure_lms(LmsKey *key, const char *state_path, int create, WC_RNG *rng)
{
    int result;
    XMEMSET(key, 0, sizeof(*key));
    result = wc_LmsKey_Init(key, NULL, INVALID_DEVID);
    if (result == 0) result = wc_LmsKey_SetParameters(key, 2, 10, 4);
    if (result == 0) result = wc_LmsKey_SetWriteCb(key, lms_write);
    if (result == 0) result = wc_LmsKey_SetReadCb(key, lms_read);
    if (result == 0) result = wc_LmsKey_SetContext(key, (void *)state_path);
    if (result == 0)
        result = create ? wc_LmsKey_MakeKey(key, rng) : wc_LmsKey_Reload(key);
    return result;
}

static int configure_xmss(XmssKey *key, const char *state_path, int create, WC_RNG *rng)
{
    int result;
    XMEMSET(key, 0, sizeof(*key));
    result = wc_XmssKey_Init(key, NULL, INVALID_DEVID);
    if (result == 0) result = wc_XmssKey_SetParamStr(key, "XMSS-SHA2_20_256");
    if (result == 0) result = wc_XmssKey_SetWriteCb(key, xmss_write);
    if (result == 0) result = wc_XmssKey_SetReadCb(key, xmss_read);
    if (result == 0) result = wc_XmssKey_SetContext(key, (void *)state_path);
    if (result == 0)
        result = create ? wc_XmssKey_MakeKey(key, rng) : wc_XmssKey_Reload(key);
    return result;
}

int main(int argc, char **argv)
{
    const char *root_algorithm;
    const char *intermediate_algorithm;
    const char *leaf_algorithm;
    const char *root_cache;
    const char *output;
    char state_path[1024];
    char root_der_path[1024];
    char intermediate_state_path[1024];
    char path[1024];
    unsigned char *root_der = NULL;
    unsigned char *intermediate_der = NULL;
    unsigned char *leaf_der = NULL;
    unsigned char *leaf_key_der = NULL;
    int root_size;
    int intermediate_size;
    int leaf_size;
    int leaf_key_size;
    int root_key_type;
    int root_sig_type;
    int intermediate_key_type;
    int intermediate_sig_type;
    int intermediate_is_hbs = 0;
    int create_root;
    int result = 1;
    void *root_key;
    void *intermediate_key_ptr;
    LmsKey lms;
    XmssKey xmss;
    LmsKey intermediate_lms;
    XmssKey intermediate_xmss;
    struct light_key intermediate_key;
    struct light_key leaf_key;
    WC_RNG rng;

    if (argc != 6) {
        fprintf(stderr,
            "usage: %s ROOT_ALG INTERMEDIATE_ALG LEAF_ALG ROOT_CACHE OUTDIR\n",
            argv[0]);
        return 2;
    }
    root_algorithm = argv[1];
    intermediate_algorithm = argv[2];
    leaf_algorithm = argv[3];
    root_cache = argv[4];
    output = argv[5];
    if (path_join(state_path, sizeof(state_path), root_cache, "root_state.key") != 0 ||
        path_join(root_der_path, sizeof(root_der_path), root_cache, "server_root.der") != 0 ||
        path_join(intermediate_state_path, sizeof(intermediate_state_path), output,
                  "intermediate_state.key") != 0)
        return 2;

    root_der = malloc(DER_CAP);
    intermediate_der = malloc(DER_CAP);
    leaf_der = malloc(DER_CAP);
    leaf_key_der = malloc(KEY_CAP);
    if (root_der == NULL || intermediate_der == NULL || leaf_der == NULL ||
        leaf_key_der == NULL)
        goto cleanup;
    wolfSSL_Init();
    if (wc_InitRng(&rng) != 0)
        goto cleanup_ssl;
    create_root = read_file(root_der_path, root_der, DER_CAP) <= 0;

    if (strcmp(root_algorithm, "LMS-HSS-L2-H10-W4") == 0) {
        if (configure_lms(&lms, state_path, create_root, &rng) != 0)
            goto cleanup_rng;
        root_key = &lms;
        root_key_type = LMS_TYPE;
        root_sig_type = CTC_HSS_LMS;
    }
    else if (strcmp(root_algorithm, "XMSS-SHA2_20_256") == 0) {
        if (configure_xmss(&xmss, state_path, create_root, &rng) != 0)
            goto cleanup_rng;
        root_key = &xmss;
        root_key_type = XMSS_TYPE;
        root_sig_type = CTC_XMSS;
    }
    else {
        fprintf(stderr, "unsupported root algorithm: %s\n", root_algorithm);
        goto cleanup_rng;
    }

    if (create_root) {
        root_size = make_certificate(root_key, root_key_type, root_key,
            root_key_type, root_sig_type, NULL, 0, 1, "Root CA",
            root_algorithm, &rng, root_der);
        if (root_size <= 0 || write_file(root_der_path, root_der, root_size) != 0)
            goto cleanup_root;
        if (path_join(path, sizeof(path), root_cache, "server_root.crt") != 0 ||
            write_pem(path, root_der, root_size, CERT_TYPE) != 0)
            goto cleanup_root;
    }
    else {
        root_size = read_file(root_der_path, root_der, DER_CAP);
        if (root_size <= 0)
            goto cleanup_root;
    }

    if (strcmp(intermediate_algorithm, "LMS-HSS-L2-H10-W4") == 0) {
        if (configure_lms(&intermediate_lms, intermediate_state_path, 1, &rng) != 0)
            goto cleanup_root;
        intermediate_key_ptr = &intermediate_lms;
        intermediate_key_type = LMS_TYPE;
        intermediate_sig_type = CTC_HSS_LMS;
        intermediate_is_hbs = 1;
    }
    else if (strcmp(intermediate_algorithm, "XMSS-SHA2_20_256") == 0) {
        if (configure_xmss(&intermediate_xmss, intermediate_state_path, 1, &rng) != 0)
            goto cleanup_root;
        intermediate_key_ptr = &intermediate_xmss;
        intermediate_key_type = XMSS_TYPE;
        intermediate_sig_type = CTC_XMSS;
        intermediate_is_hbs = 1;
    }
    else {
        if (light_key_init(&intermediate_key, intermediate_algorithm, &rng) != 0)
            goto cleanup_root;
        intermediate_key_ptr = light_key_pointer(&intermediate_key);
        intermediate_key_type = intermediate_key.key_type;
        intermediate_sig_type = intermediate_key.sig_type;
    }
    intermediate_size = make_certificate(intermediate_key_ptr,
        intermediate_key_type, root_key, root_key_type, root_sig_type,
        root_der, root_size, 1, "Intermediate CA", intermediate_algorithm, &rng,
        intermediate_der);
    if (intermediate_size <= 0)
        goto cleanup_intermediate;
    /* LMS/XMSS are valid X.509 signers here, but are not available as TLS 1.3
     * CertificateVerify schemes. Keep the TLS leaf key ECDSA P-256. */
    if (light_key_init(&leaf_key,
            (strcmp(leaf_algorithm, "LMS-HSS-L2-H10-W4") == 0 ||
             strcmp(leaf_algorithm, "XMSS-SHA2_20_256") == 0)
                ? "ECDSA-P-256" : leaf_algorithm,
            &rng) != 0)
        goto cleanup_intermediate;
    leaf_size = make_certificate(light_key_pointer(&leaf_key), leaf_key.key_type,
        intermediate_key_ptr, intermediate_key_type,
        intermediate_sig_type, intermediate_der, intermediate_size, 0,
        "TLS Server", "localhost", &rng, leaf_der);
    if (leaf_size <= 0)
        goto cleanup_leaf;
    leaf_key_size = light_key_der(&leaf_key, leaf_key_der);
    if (leaf_key_size <= 0)
        goto cleanup_leaf;

#define WRITE_DER_AND_PEM(base, data, size) \
    do { \
        if (path_join(path, sizeof(path), output, base ".der") != 0 || \
            write_file(path, data, size) != 0 || \
            path_join(path, sizeof(path), output, base ".crt") != 0 || \
            write_pem(path, data, size, CERT_TYPE) != 0) \
            goto cleanup_leaf; \
    } while (0)
    WRITE_DER_AND_PEM("server_root", root_der, root_size);
    WRITE_DER_AND_PEM("server_intermediate", intermediate_der, intermediate_size);
    WRITE_DER_AND_PEM("server", leaf_der, leaf_size);
#undef WRITE_DER_AND_PEM
    if (path_join(path, sizeof(path), output, "server.key") != 0 ||
        write_pem(path, leaf_key_der, leaf_key_size, leaf_key.pem_type) != 0)
        goto cleanup_leaf;
    if (path_join(path, sizeof(path), output, "server_chain.crt") != 0 ||
        write_pem(path, leaf_der, leaf_size, CERT_TYPE) != 0 ||
        append_pem_cert(path, intermediate_der, intermediate_size) != 0)
        goto cleanup_leaf;
    result = 0;

cleanup_leaf:
    light_key_free(&leaf_key);
cleanup_intermediate:
    if (intermediate_is_hbs) {
        if (intermediate_key_type == LMS_TYPE)
            wc_LmsKey_Free(&intermediate_lms);
        else
            wc_XmssKey_Free(&intermediate_xmss);
    }
    else {
        light_key_free(&intermediate_key);
    }
cleanup_root:
    if (root_key_type == LMS_TYPE)
        wc_LmsKey_Free(&lms);
    else
        wc_XmssKey_Free(&xmss);
cleanup_rng:
    wc_FreeRng(&rng);
cleanup_ssl:
    wolfSSL_Cleanup();
cleanup:
    free(root_der);
    free(intermediate_der);
    free(leaf_der);
    free(leaf_key_der);
    return result;
}
