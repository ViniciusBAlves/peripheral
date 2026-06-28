#include "benchmark_metrics.h"

#include <zephyr/kernel.h>

static struct benchmark_metrics metrics;
static bool metrics_active;

void benchmark_metrics_reset(void)
{
    metrics = (struct benchmark_metrics){0};
    metrics_active = true;
}

void benchmark_metrics_stop(void)
{
    metrics_active = false;
}

benchmark_timepoint_t benchmark_metric_start(void)
{
    return k_uptime_ticks();
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

const struct benchmark_metrics *benchmark_metrics_get(void)
{
    return &metrics;
}
