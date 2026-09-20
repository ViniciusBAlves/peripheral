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

/*
 * Clear all metrics and begin recording a benchmark interval.
 */
void benchmark_metrics_reset(void);
/*
 * Stop accepting updates to the current metrics snapshot.
 */
void benchmark_metrics_stop(void);
/*
 * Yield between expensive cryptographic operations.
 */
void benchmark_crypto_reschedule(void);
/*
 * Start the available hardware cache counters.
 */
void benchmark_hardware_counters_start(void);
/*
 * Stop hardware counters and save their deltas.
 */
void benchmark_hardware_counters_stop(void);
/*
 * Return a monotonic timestamp for a measured interval.
 */
benchmark_timepoint_t benchmark_metric_start(void);
/*
 * Start timing a cryptographic operation and its power marker.
 */
benchmark_timepoint_t benchmark_crypto_metric_start(
    enum benchmark_crypto_operation operation);
/*
 * Finish and accumulate one cryptographic operation interval.
 */
void benchmark_metric_stop(enum benchmark_crypto_operation operation,
                           benchmark_timepoint_t start);
/*
 * Accumulate time spent inside transport callbacks.
 */
void benchmark_communication_stop(benchmark_timepoint_t start);
/*
 * Record one successfully transmitted L2CAP SDU.
 */
void benchmark_l2cap_tx(uint32_t bytes);
/*
 * Record one received L2CAP SDU.
 */
void benchmark_l2cap_rx(uint32_t bytes);
/*
 * Count an L2CAP transmit retry.
 */
void benchmark_l2cap_tx_retry(void);
/*
 * Accumulate time waiting to transmit over L2CAP.
 */
void benchmark_l2cap_tx_wait_stop(benchmark_timepoint_t start);
/*
 * Count an L2CAP receive-buffer overflow.
 */
void benchmark_l2cap_rx_overflow(void);
/*
 * Update the maximum observed L2CAP receive-ring occupancy.
 */
void benchmark_l2cap_rx_ring_usage(uint32_t bytes);
/*
 * Save the SignatureScheme observed in server CertificateVerify.
 */
void benchmark_record_server_certificate_verify_scheme(uint16_t scheme);
/*
 * Map a TLS SignatureScheme identifier to its benchmark name.
 */
const char *benchmark_signature_scheme_name(uint16_t scheme);
/*
 * Return the current read-only metrics snapshot.
 */
const struct benchmark_metrics *benchmark_metrics_get(void);
