#pragma once

#include <zephyr/kernel.h>
#include <wolfssl/ssl.h>

/*
 * Run the bidirectional MQTT payload-transfer benchmark over TLS.
 */
int benchmark_mqtt_transfer_run(WOLFSSL *ssl, struct k_heap *heap,
                                uint32_t heap_capacity);
