#include "pqm4_mlkem_backend.h"
#include "benchmark_metrics.h"

#include <stdint.h>

#include <zephyr/sys/util.h>

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>

#define PQM4_MLKEM_DEV_ID 42040

/*
 * Generate an ML-KEM-512 key pair with the pqm4 implementation.
 */
int pqm4_mlkem512_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
/*
 * Encapsulate an ML-KEM-512 shared secret with pqm4.
 */
int pqm4_mlkem512_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
/*
 * Decapsulate an ML-KEM-512 shared secret with pqm4.
 */
int pqm4_mlkem512_crypto_kem_dec(uint8_t *ss, const uint8_t *ct,
                                const uint8_t *sk);
/*
 * Generate an ML-KEM-768 key pair with the pqm4 implementation.
 */
int pqm4_mlkem768_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
/*
 * Encapsulate an ML-KEM-768 shared secret with pqm4.
 */
int pqm4_mlkem768_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
/*
 * Decapsulate an ML-KEM-768 shared secret with pqm4.
 */
int pqm4_mlkem768_crypto_kem_dec(uint8_t *ss, const uint8_t *ct,
                                const uint8_t *sk);
/*
 * Generate an ML-KEM-1024 key pair with the pqm4 implementation.
 */
int pqm4_mlkem1024_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
/*
 * Encapsulate an ML-KEM-1024 shared secret with pqm4.
 */
int pqm4_mlkem1024_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
/*
 * Decapsulate an ML-KEM-1024 shared secret with pqm4.
 */
int pqm4_mlkem1024_crypto_kem_dec(uint8_t *ss, const uint8_t *ct,
                                 const uint8_t *sk);

struct pqm4_level {
    int wolf_type;
    word32 public_len;
    word32 private_len;
    word32 ciphertext_len;
    int (*keypair)(uint8_t *, uint8_t *);
    int (*encapsulate)(uint8_t *, uint8_t *, const uint8_t *);
    int (*decapsulate)(uint8_t *, const uint8_t *, const uint8_t *);
};

static const struct pqm4_level levels[] = {
    {
        WC_ML_KEM_512, WC_ML_KEM_512_PUBLIC_KEY_SIZE,
        WC_ML_KEM_512_PRIVATE_KEY_SIZE, WC_ML_KEM_512_CIPHER_TEXT_SIZE,
        pqm4_mlkem512_crypto_kem_keypair,
        pqm4_mlkem512_crypto_kem_enc,
        pqm4_mlkem512_crypto_kem_dec,
    },
    {
        WC_ML_KEM_768, WC_ML_KEM_768_PUBLIC_KEY_SIZE,
        WC_ML_KEM_768_PRIVATE_KEY_SIZE, WC_ML_KEM_768_CIPHER_TEXT_SIZE,
        pqm4_mlkem768_crypto_kem_keypair,
        pqm4_mlkem768_crypto_kem_enc,
        pqm4_mlkem768_crypto_kem_dec,
    },
    {
        WC_ML_KEM_1024, WC_ML_KEM_1024_PUBLIC_KEY_SIZE,
        WC_ML_KEM_1024_PRIVATE_KEY_SIZE, WC_ML_KEM_1024_CIPHER_TEXT_SIZE,
        pqm4_mlkem1024_crypto_kem_keypair,
        pqm4_mlkem1024_crypto_kem_enc,
        pqm4_mlkem1024_crypto_kem_dec,
    },
};

/*
 * Resolve pqm4 size parameters from a wolfSSL ML-KEM key type.
 */
static const struct pqm4_level *level_from_key(const MlKemKey *key)
{
    int type;

    if (!key) {
        return NULL;
    }
    type = key->type;
    if (type & MLKEM_KYBER) {
        type &= ~MLKEM_KYBER;
    }
    for (size_t i = 0; i < ARRAY_SIZE(levels); i++) {
        if (levels[i].wolf_type == type) {
            return &levels[i];
        }
    }
    return NULL;
}

/*
 * Generate and import a pqm4 ML-KEM private key into wolfSSL.
 */
static int make_key(MlKemKey *key)
{
    const struct pqm4_level *level = level_from_key(key);
    benchmark_timepoint_t metric_start;
    uint8_t *pk = NULL;
    uint8_t *sk = NULL;
    int ret = CRYPTOCB_UNAVAILABLE;

    if (!level) {
        return ret;
    }
    metric_start = benchmark_crypto_metric_start(BENCH_CRYPTO_KEM_KEYGEN);
    pk = XMALLOC(level->public_len, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    sk = XMALLOC(level->private_len, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (!pk || !sk) {
        ret = MEMORY_E;
        goto out;
    }
    ret = level->keypair(pk, sk);
    if (ret == 0) {
        ret = wc_MlKemKey_DecodePrivateKey(key, sk, level->private_len);
    }
out:
    if (pk) {
        XMEMSET(pk, 0, level->public_len);
        XFREE(pk, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    if (sk) {
        XMEMSET(sk, 0, level->private_len);
        XFREE(sk, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    benchmark_metric_stop(BENCH_CRYPTO_KEM_KEYGEN, metric_start);
    return ret;
}

/*
 * Encapsulate through pqm4 using a wolfSSL public key.
 */
static int encapsulate(MlKemKey *key, uint8_t *ct, word32 ct_len,
                       uint8_t *ss, word32 ss_len)
{
    const struct pqm4_level *level = level_from_key(key);
    benchmark_timepoint_t metric_start;
    uint8_t *pk;
    int ret;

    if (!level) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (!ct || !ss || ct_len != level->ciphertext_len ||
        ss_len != WC_ML_KEM_SS_SZ) {
        return BUFFER_E;
    }
    metric_start = benchmark_crypto_metric_start(BENCH_CRYPTO_KEM_ENCAPSULATE);
    pk = XMALLOC(level->public_len, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (!pk) {
        ret = MEMORY_E;
        goto out;
    }
    ret = wc_MlKemKey_EncodePublicKey(key, pk, level->public_len);
    if (ret == 0) {
        ret = level->encapsulate(ct, ss, pk);
    }
out:
    if (pk) {
        XMEMSET(pk, 0, level->public_len);
        XFREE(pk, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    benchmark_metric_stop(BENCH_CRYPTO_KEM_ENCAPSULATE, metric_start);
    return ret;
}

/*
 * Decapsulate through pqm4 using a wolfSSL private key.
 */
static int decapsulate(MlKemKey *key, const uint8_t *ct, word32 ct_len,
                       uint8_t *ss, word32 ss_len)
{
    const struct pqm4_level *level = level_from_key(key);
    benchmark_timepoint_t metric_start;
    uint8_t *sk;
    int ret;

    if (!level) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (!ct || !ss || ct_len != level->ciphertext_len ||
        ss_len != WC_ML_KEM_SS_SZ) {
        return BUFFER_E;
    }
    metric_start = benchmark_crypto_metric_start(BENCH_CRYPTO_KEM_DECAPSULATE);
    sk = XMALLOC(level->private_len, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (!sk) {
        ret = MEMORY_E;
        goto out;
    }
    ret = wc_MlKemKey_EncodePrivateKey(key, sk, level->private_len);
    if (ret == 0) {
        ret = level->decapsulate(ss, ct, sk);
    }
out:
    if (sk) {
        XMEMSET(sk, 0, level->private_len);
        XFREE(sk, key->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    benchmark_metric_stop(BENCH_CRYPTO_KEM_DECAPSULATE, metric_start);
    return ret;
}

/*
 * Dispatch wolfSSL ML-KEM callback requests to pqm4 operations.
 */
static int crypto_cb(int dev_id, wc_CryptoInfo *info, void *ctx)
{
    ARG_UNUSED(dev_id);
    ARG_UNUSED(ctx);

    if (!info || info->algo_type != WC_ALGO_TYPE_PK) {
        return CRYPTOCB_UNAVAILABLE;
    }
    switch (info->pk.type) {
    case WC_PK_TYPE_PQC_KEM_KEYGEN:
        if (info->pk.pqc_kem_kg.type == WC_PQC_KEM_TYPE_MLKEM) {
            return make_key((MlKemKey *)info->pk.pqc_kem_kg.key);
        }
        break;
    case WC_PK_TYPE_PQC_KEM_ENCAPS:
        if (info->pk.pqc_encaps.type == WC_PQC_KEM_TYPE_MLKEM) {
            return encapsulate(
                (MlKemKey *)info->pk.pqc_encaps.key,
                info->pk.pqc_encaps.ciphertext,
                info->pk.pqc_encaps.ciphertextLen,
                info->pk.pqc_encaps.sharedSecret,
                info->pk.pqc_encaps.sharedSecretLen);
        }
        break;
    case WC_PK_TYPE_PQC_KEM_DECAPS:
        if (info->pk.pqc_decaps.type == WC_PQC_KEM_TYPE_MLKEM) {
            return decapsulate(
                (MlKemKey *)info->pk.pqc_decaps.key,
                info->pk.pqc_decaps.ciphertext,
                info->pk.pqc_decaps.ciphertextLen,
                info->pk.pqc_decaps.sharedSecret,
                info->pk.pqc_decaps.sharedSecretLen);
        }
        break;
    default:
        break;
    }
    return CRYPTOCB_UNAVAILABLE;
}

/*
 * Register the pqm4 ML-KEM callback backend with wolfSSL.
 */
int pqm4_mlkem_backend_init(void)
{
    wc_CryptoCb_UnRegisterDevice(PQM4_MLKEM_DEV_ID);
    return wc_CryptoCb_RegisterDevice(PQM4_MLKEM_DEV_ID, crypto_cb, NULL);
}

/*
 * Return the wolfSSL device identifier assigned to pqm4 ML-KEM.
 */
int pqm4_mlkem_backend_dev_id(void)
{
    return PQM4_MLKEM_DEV_ID;
}
