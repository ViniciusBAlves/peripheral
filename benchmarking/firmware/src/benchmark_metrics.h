#pragma once

#include <stdint.h>

enum benchmark_crypto_operation {
    BENCH_CRYPTO_KEM_KEYGEN,
    BENCH_CRYPTO_KEM_ENCAPSULATE,
    BENCH_CRYPTO_KEM_DECAPSULATE,
    BENCH_CRYPTO_CERT_VERIFY,
    BENCH_CRYPTO_CLASSICAL_KEX_KEYGEN,
    BENCH_CRYPTO_CLASSICAL_KEX_SHARED_SECRET,
    BENCH_CRYPTO_TLS_CERT_VERIFY,
    BENCH_CRYPTO_MTLS_SIGN,
};

typedef int64_t benchmark_timepoint_t;

struct benchmark_metrics {
    uint64_t communication_us;
    uint64_t kem_keygen_us;
    uint64_t kem_encapsulation_us;
    uint64_t kem_decapsulation_us;
    uint64_t certificate_verify_us;
    uint64_t classical_kex_keygen_us;
    uint64_t classical_kex_shared_secret_us;
    uint64_t tls_certificate_verify_us;
    uint64_t mtls_signature_generate_us;
    uint32_t l2cap_tx_packets;
    uint32_t l2cap_tx_bytes;
    uint32_t l2cap_rx_packets;
    uint32_t l2cap_rx_bytes;
    uint32_t l2cap_tx_retries;
    uint64_t l2cap_tx_wait_us;
    uint32_t l2cap_rx_overflows;
    uint32_t l2cap_rx_ring_peak_bytes;
    uint32_t instruction_cache_hits;
    uint32_t instruction_cache_misses;
    uint16_t server_certificate_verify_scheme;
    uint8_t server_certificate_verify_scheme_seen;
};

void benchmark_metrics_reset(void);
void benchmark_metrics_stop(void);
void benchmark_crypto_reschedule(void);
void benchmark_hardware_counters_start(void);
void benchmark_hardware_counters_stop(void);
benchmark_timepoint_t benchmark_metric_start(void);
benchmark_timepoint_t benchmark_crypto_metric_start(
    enum benchmark_crypto_operation operation);
void benchmark_metric_stop(enum benchmark_crypto_operation operation,
                           benchmark_timepoint_t start);
void benchmark_communication_stop(benchmark_timepoint_t start);
void benchmark_l2cap_tx(uint32_t bytes);
void benchmark_l2cap_rx(uint32_t bytes);
void benchmark_l2cap_tx_retry(void);
void benchmark_l2cap_tx_wait_stop(benchmark_timepoint_t start);
void benchmark_l2cap_rx_overflow(void);
void benchmark_l2cap_rx_ring_usage(uint32_t bytes);
void benchmark_record_server_certificate_verify_scheme(uint16_t scheme);
const char *benchmark_signature_scheme_name(uint16_t scheme);
const struct benchmark_metrics *benchmark_metrics_get(void);
