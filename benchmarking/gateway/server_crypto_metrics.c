#define _GNU_SOURCE

#include <dlfcn.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

static _Thread_local unsigned int signature_depth;

static uint64_t monotonic_us(void)
{
    struct timespec value;

    clock_gettime(CLOCK_MONOTONIC_RAW, &value);
    return (uint64_t)value.tv_sec * 1000000ULL +
           (uint64_t)value.tv_nsec / 1000ULL;
}

static void report_metric(const char *name, uint64_t start)
{
    fprintf(stderr, "[BENCH_SERVER] %s=%llu\n", name,
            (unsigned long long)(monotonic_us() - start));
    fflush(stderr);
}

int EVP_PKEY_encapsulate(EVP_PKEY_CTX *ctx,
                         unsigned char *wrappedkey, size_t *wrappedkeylen,
                         unsigned char *genkey, size_t *genkeylen)
{
    typedef int (*function_type)(EVP_PKEY_CTX *, unsigned char *, size_t *,
                                 unsigned char *, size_t *);
    static function_type real_function;
    bool measure = wrappedkey != NULL && genkey != NULL;
    uint64_t start = measure ? monotonic_us() : 0;

    if (real_function == NULL) {
        real_function = (function_type)dlsym(RTLD_NEXT, "EVP_PKEY_encapsulate");
    }
    int result = real_function(ctx, wrappedkey, wrappedkeylen, genkey, genkeylen);
    if (measure) {
        report_metric("server_kem_encapsulation_us", start);
    }
    return result;
}

int EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen,
                   const unsigned char *tbs, size_t tbslen)
{
    typedef int (*function_type)(EVP_MD_CTX *, unsigned char *, size_t *,
                                 const unsigned char *, size_t);
    static function_type real_function;
    bool outer = signature_depth++ == 0;
    bool measure = outer && sigret != NULL;
    uint64_t start = measure ? monotonic_us() : 0;

    if (real_function == NULL) {
        real_function = (function_type)dlsym(RTLD_NEXT, "EVP_DigestSign");
    }
    int result = real_function(ctx, sigret, siglen, tbs, tbslen);
    signature_depth--;
    if (measure) {
        report_metric("server_certificate_verify_sign_us", start);
    }
    return result;
}

int EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen)
{
    typedef int (*function_type)(EVP_MD_CTX *, unsigned char *, size_t *);
    static function_type real_function;
    bool outer = signature_depth++ == 0;
    bool measure = outer && sigret != NULL;
    uint64_t start = measure ? monotonic_us() : 0;

    if (real_function == NULL) {
        real_function = (function_type)dlsym(RTLD_NEXT, "EVP_DigestSignFinal");
    }
    int result = real_function(ctx, sigret, siglen);
    signature_depth--;
    if (measure) {
        report_metric("server_certificate_verify_sign_us", start);
    }
    return result;
}

int EVP_PKEY_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                  const unsigned char *tbs, size_t tbslen)
{
    typedef int (*function_type)(EVP_PKEY_CTX *, unsigned char *, size_t *,
                                 const unsigned char *, size_t);
    static function_type real_function;
    bool outer = signature_depth++ == 0;
    bool measure = outer && sig != NULL;
    uint64_t start = measure ? monotonic_us() : 0;

    if (real_function == NULL) {
        real_function = (function_type)dlsym(RTLD_NEXT, "EVP_PKEY_sign");
    }
    int result = real_function(ctx, sig, siglen, tbs, tbslen);
    signature_depth--;
    if (measure) {
        report_metric("server_certificate_verify_sign_us", start);
    }
    return result;
}
