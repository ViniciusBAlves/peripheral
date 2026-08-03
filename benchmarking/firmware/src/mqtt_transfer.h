#pragma once

#include <zephyr/kernel.h>
#include <wolfssl/ssl.h>

int benchmark_mqtt_transfer_run(WOLFSSL *ssl, struct k_heap *heap,
                                uint32_t heap_capacity);
