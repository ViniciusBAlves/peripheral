#pragma once

#include <stdbool.h>
#include "benchmark_metrics.h"

void benchmark_power_markers_init(void);
void benchmark_power_markers_reset(void);
void benchmark_power_total_set(bool active);
void benchmark_power_handshake_set(bool active);
void benchmark_power_crypto_start(enum benchmark_crypto_operation operation);
void benchmark_power_crypto_stop(enum benchmark_crypto_operation operation);
