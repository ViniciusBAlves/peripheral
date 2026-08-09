#include "power_markers.h"

#include <zephyr/drivers/gpio.h>
#include <zephyr/sys/util.h>

#ifdef BENCH_POWER_MARKERS
#define MARKER_TOTAL_PIN 3      /* Arduino A0, SoC P0.03 -> PPK2 D7 */
#define MARKER_HANDSHAKE_PIN 4  /* Arduino A1, SoC P0.04 -> PPK2 D6 */
#define MARKER_KEM_PIN 28       /* Arduino A2, SoC P0.28 -> PPK2 D5 */
#define MARKER_SIGNATURE_PIN 29 /* Arduino A3, SoC P0.29 -> PPK2 D4 */

static const struct device *const gpio0 = DEVICE_DT_GET(DT_NODELABEL(gpio0));
static bool markers_ready;
static unsigned int mlkem_depth;
static unsigned int classical_kex_depth;
static unsigned int signature_depth;

static bool is_mlkem(enum benchmark_crypto_operation operation)
{
    return operation == BENCH_CRYPTO_KEM_KEYGEN ||
           operation == BENCH_CRYPTO_KEM_ENCAPSULATE ||
           operation == BENCH_CRYPTO_KEM_DECAPSULATE;
}

static bool is_classical_kex(enum benchmark_crypto_operation operation)
{
    return operation == BENCH_CRYPTO_CLASSICAL_KEX_KEYGEN ||
           operation == BENCH_CRYPTO_CLASSICAL_KEX_SHARED_SECRET;
}

static bool is_signature(enum benchmark_crypto_operation operation)
{
    return operation == BENCH_CRYPTO_CERT_VERIFY ||
           operation == BENCH_CRYPTO_TLS_CERT_VERIFY ||
           operation == BENCH_CRYPTO_MTLS_SIGN;
}

void benchmark_power_markers_init(void)
{
    if (!device_is_ready(gpio0)) {
        return;
    }
    gpio_pin_configure(gpio0, MARKER_TOTAL_PIN, GPIO_OUTPUT_INACTIVE);
    gpio_pin_configure(gpio0, MARKER_HANDSHAKE_PIN, GPIO_OUTPUT_INACTIVE);
    gpio_pin_configure(gpio0, MARKER_KEM_PIN, GPIO_OUTPUT_INACTIVE);
    gpio_pin_configure(gpio0, MARKER_SIGNATURE_PIN, GPIO_OUTPUT_INACTIVE);
    markers_ready = true;
}

void benchmark_power_markers_reset(void)
{
    if (!markers_ready) {
        return;
    }
    mlkem_depth = 0;
    classical_kex_depth = 0;
    signature_depth = 0;
    gpio_port_clear_bits_raw(gpio0, BIT(MARKER_TOTAL_PIN) |
        BIT(MARKER_HANDSHAKE_PIN) | BIT(MARKER_KEM_PIN) |
        BIT(MARKER_SIGNATURE_PIN));
}

void benchmark_power_total_set(bool active)
{
    if (markers_ready) {
        gpio_pin_set_raw(gpio0, MARKER_TOTAL_PIN, active);
    }
}

void benchmark_power_handshake_set(bool active)
{
    if (markers_ready) {
        gpio_pin_set_raw(gpio0, MARKER_HANDSHAKE_PIN, active);
    }
}

void benchmark_power_crypto_start(enum benchmark_crypto_operation operation)
{
    if (!markers_ready) {
        return;
    }
    if (is_mlkem(operation) && mlkem_depth++ == 0) {
        gpio_pin_set_raw(gpio0, MARKER_KEM_PIN, 1);
    }
    /* D5 marks every KEX operation. D5+D4 identifies the classical
     * ECDHE/X25519 component without requiring a fifth PPK2 wire. */
    if (is_classical_kex(operation) && classical_kex_depth++ == 0) {
        gpio_pin_set_raw(gpio0, MARKER_KEM_PIN, 1);
        gpio_pin_set_raw(gpio0, MARKER_SIGNATURE_PIN, 1);
    }
    if (is_signature(operation) && signature_depth++ == 0) {
        gpio_pin_set_raw(gpio0, MARKER_SIGNATURE_PIN, 1);
    }
}

void benchmark_power_crypto_stop(enum benchmark_crypto_operation operation)
{
    if (!markers_ready) {
        return;
    }
    if (is_mlkem(operation) && mlkem_depth > 0 && --mlkem_depth == 0 &&
        classical_kex_depth == 0) {
        gpio_pin_set_raw(gpio0, MARKER_KEM_PIN, 0);
    }
    if (is_classical_kex(operation) && classical_kex_depth > 0 &&
        --classical_kex_depth == 0) {
        if (mlkem_depth == 0) {
            gpio_pin_set_raw(gpio0, MARKER_KEM_PIN, 0);
        }
        if (signature_depth == 0) {
            gpio_pin_set_raw(gpio0, MARKER_SIGNATURE_PIN, 0);
        }
    }
    if (is_signature(operation) && signature_depth > 0 && --signature_depth == 0) {
        if (classical_kex_depth == 0) {
            gpio_pin_set_raw(gpio0, MARKER_SIGNATURE_PIN, 0);
        }
    }
}
#else
void benchmark_power_markers_init(void) {}
void benchmark_power_markers_reset(void) {}
void benchmark_power_total_set(bool active) { ARG_UNUSED(active); }
void benchmark_power_handshake_set(bool active) { ARG_UNUSED(active); }
void benchmark_power_crypto_start(enum benchmark_crypto_operation operation) { ARG_UNUSED(operation); }
void benchmark_power_crypto_stop(enum benchmark_crypto_operation operation) { ARG_UNUSED(operation); }
#endif
