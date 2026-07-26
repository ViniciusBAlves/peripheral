#include "benchmark_metrics.h"

#include <zephyr/kernel.h>
#include <hal/nrf_nvmc.h>
#include "power_markers.h"

static struct benchmark_metrics metrics;
static bool metrics_active;
static uint32_t icache_hits_start;
static uint32_t icache_misses_start;

void benchmark_metrics_reset(void)
{
    metrics = (struct benchmark_metrics){0};
    metrics_active = true;
}

void benchmark_metrics_stop(void)
{
    metrics_active = false;
}

void benchmark_crypto_reschedule(void)
{
    k_yield();
}

void benchmark_hardware_counters_start(void)
{
#if defined(NVMC_FEATURE_CACHE_PRESENT)
    nrf_nvmc_icache_config_set(NRF_NVMC, NRF_NVMC_ICACHE_ENABLE_WITH_PROFILING);
    icache_hits_start = nrf_nvmc_icache_hit_get(NRF_NVMC);
    icache_misses_start = nrf_nvmc_icache_miss_get(NRF_NVMC);
#endif
}

void benchmark_hardware_counters_stop(void)
{
#if defined(NVMC_FEATURE_CACHE_PRESENT)
    uint32_t hits_end = nrf_nvmc_icache_hit_get(NRF_NVMC);
    uint32_t misses_end = nrf_nvmc_icache_miss_get(NRF_NVMC);

    metrics.instruction_cache_hits = hits_end - icache_hits_start;
    metrics.instruction_cache_misses = misses_end - icache_misses_start;
#endif
}

benchmark_timepoint_t benchmark_metric_start(void)
{
    return k_uptime_ticks();
}

benchmark_timepoint_t benchmark_crypto_metric_start(
    enum benchmark_crypto_operation operation)
{
    benchmark_power_crypto_start(operation);
    return benchmark_metric_start();
}

static uint64_t elapsed_us(benchmark_timepoint_t start)
{
    int64_t elapsed_ticks = k_uptime_ticks() - start;

    return elapsed_ticks > 0 ? k_ticks_to_us_floor64(elapsed_ticks) : 0;
}

void benchmark_metric_stop(enum benchmark_crypto_operation operation,
                           benchmark_timepoint_t start)
{
    uint64_t elapsed;

    benchmark_power_crypto_stop(operation);
    if (!metrics_active) {
        return;
    }
    elapsed = elapsed_us(start);
    switch (operation) {
    case BENCH_CRYPTO_KEM_KEYGEN:
        metrics.kem_keygen_us += elapsed;
        break;
    case BENCH_CRYPTO_KEM_ENCAPSULATE:
        metrics.kem_encapsulation_us += elapsed;
        break;
    case BENCH_CRYPTO_KEM_DECAPSULATE:
        metrics.kem_decapsulation_us += elapsed;
        break;
    case BENCH_CRYPTO_CERT_VERIFY:
        metrics.certificate_verify_us += elapsed;
        break;
    case BENCH_CRYPTO_CLASSICAL_KEX_KEYGEN:
        metrics.classical_kex_keygen_us += elapsed;
        break;
    case BENCH_CRYPTO_CLASSICAL_KEX_SHARED_SECRET:
        metrics.classical_kex_shared_secret_us += elapsed;
        break;
    case BENCH_CRYPTO_TLS_CERT_VERIFY:
        metrics.tls_certificate_verify_us += elapsed;
        break;
    case BENCH_CRYPTO_MTLS_SIGN:
        metrics.mtls_signature_generate_us += elapsed;
        break;
    }
}

void benchmark_communication_stop(benchmark_timepoint_t start)
{
    if (metrics_active) {
        metrics.communication_us += elapsed_us(start);
    }
}

void benchmark_l2cap_tx(uint32_t bytes)
{
    if (metrics_active) {
        metrics.l2cap_tx_packets++;
        metrics.l2cap_tx_bytes += bytes;
    }
}

void benchmark_l2cap_rx(uint32_t bytes)
{
    if (metrics_active) {
        metrics.l2cap_rx_packets++;
        metrics.l2cap_rx_bytes += bytes;
    }
}

void benchmark_l2cap_tx_retry(void)
{
    if (metrics_active) {
        metrics.l2cap_tx_retries++;
    }
}

void benchmark_l2cap_tx_wait_stop(benchmark_timepoint_t start)
{
    if (metrics_active) {
        metrics.l2cap_tx_wait_us += elapsed_us(start);
    }
}

void benchmark_l2cap_rx_overflow(void)
{
    if (metrics_active) {
        metrics.l2cap_rx_overflows++;
    }
}

void benchmark_l2cap_rx_ring_usage(uint32_t bytes)
{
    if (metrics_active) {
        metrics.l2cap_rx_ring_peak_bytes =
            MAX(metrics.l2cap_rx_ring_peak_bytes, bytes);
    }
}

void benchmark_record_server_certificate_verify_scheme(uint16_t scheme)
{
    if (metrics_active) {
        metrics.server_certificate_verify_scheme = scheme;
        metrics.server_certificate_verify_scheme_seen = 1;
    }
}

const char *benchmark_signature_scheme_name(uint16_t scheme)
{
    switch (scheme) {
    case 0x0403: return "ecdsa_secp256r1_sha256";
    case 0x0503: return "ecdsa_secp384r1_sha384";
    case 0x0603: return "ecdsa_secp521r1_sha512";
    case 0x0804: return "rsa_pss_rsae_sha256";
    case 0x0805: return "rsa_pss_rsae_sha384";
    case 0x0806: return "rsa_pss_rsae_sha512";
    case 0x0904: return "mldsa44";
    case 0x0905: return "mldsa65";
    case 0x0906: return "mldsa87";
    default: return "unknown";
    }
}

const struct benchmark_metrics *benchmark_metrics_get(void)
{
    return &metrics;
}
