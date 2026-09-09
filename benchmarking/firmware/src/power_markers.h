#pragma once

#include <stdbool.h>
#include "benchmark_metrics.h"

/*
 * Configure all benchmark power-marker GPIO outputs.
 */
void benchmark_power_markers_init(void);
/*
 * Clear marker GPIOs and nested-operation counters.
 */
void benchmark_power_markers_reset(void);
/*
 * Set the total-execution power marker.
 */
void benchmark_power_total_set(bool active);
/*
 * Set the TLS-handshake power marker.
 */
void benchmark_power_handshake_set(bool active);
/*
 * Enter a marked cryptographic operation region.
 */
void benchmark_power_crypto_start(enum benchmark_crypto_operation operation);
/*
 * Leave a marked cryptographic operation region.
 */
void benchmark_power_crypto_stop(enum benchmark_crypto_operation operation);
