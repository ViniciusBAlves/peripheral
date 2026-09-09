#include "mqtt_transfer.h"

#define BENCH_TRANSFER_MAX_OPERATIONS 4096U
#define BENCH_TRANSFER_TIMEOUT_MS 30000

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <zephyr/debug/thread_analyzer.h>
#include <zephyr/sys/sys_heap.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/error-ssl.h>

#include "benchmark_dwt.h"
#include "benchmark_metrics.h"
#include "power_markers.h"

#define MQTT_RX_CHUNK 512
#define MQTT_TX_CHUNK (16 * 1024)
#define MQTT_TIMEOUT_MS BENCH_TRANSFER_TIMEOUT_MS
#define TOPIC_CONTROL "bench/control"
#define TOPIC_DOWN "bench/down"
#define TOPIC_UP "bench/up"
#define TOPIC_DEVICE_ACK "bench/device_ack"
#define TOPIC_METRICS "bench/metrics"

struct mqtt_packet {
    uint8_t type;
    uint32_t remaining;
};

struct cpu_snapshot {
    uint64_t thread_cycles;
    uint64_t all_cycles;
    uint64_t non_idle_cycles;
    bool valid;
};

static uint16_t next_packet_id = 10;
static int32_t mqtt_timeout_ms = MQTT_TIMEOUT_MS;

/*
 * Capture current-thread and whole-system runtime counters.
 */
static struct cpu_snapshot cpu_snapshot_get(void)
{
    k_thread_runtime_stats_t thread = {0};
    k_thread_runtime_stats_t all = {0};
    struct cpu_snapshot result = {0};

    if (k_thread_runtime_stats_get(k_current_get(), &thread) == 0 &&
        k_thread_runtime_stats_all_get(&all) == 0) {
        result.thread_cycles = thread.execution_cycles;
        result.all_cycles = all.execution_cycles;
        result.non_idle_cycles = all.total_cycles;
        result.valid = true;
    }
    return result;
}

/*
 * Read an exact byte count from TLS before the transfer deadline.
 */
static int tls_read_exact(WOLFSSL *ssl, uint8_t *data, size_t size)
{
    size_t offset = 0;
    int64_t deadline = k_uptime_get() + mqtt_timeout_ms;

    while (offset < size && k_uptime_get() < deadline) {
        int ret = wolfSSL_read(ssl, data + offset, (int)(size - offset));
        if (ret > 0) {
            offset += (size_t)ret;
            continue;
        }
        int error = wolfSSL_get_error(ssl, ret);
        if (error != WOLFSSL_ERROR_WANT_READ &&
            error != WOLFSSL_ERROR_WANT_WRITE && error != INCOMPLETE_DATA) {
            return -error;
        }
        k_sleep(K_MSEC(1));
    }
    return offset == size ? 0 : -ETIMEDOUT;
}

/*
 * Write a complete buffer to TLS before the transfer deadline.
 */
static int tls_write_all(WOLFSSL *ssl, const uint8_t *data, size_t size)
{
    size_t offset = 0;
    int64_t deadline = k_uptime_get() + mqtt_timeout_ms;

    while (offset < size && k_uptime_get() < deadline) {
        int ret = wolfSSL_write(ssl, data + offset, (int)(size - offset));
        if (ret > 0) {
            offset += (size_t)ret;
            continue;
        }
        int error = wolfSSL_get_error(ssl, ret);
        if (error != WOLFSSL_ERROR_WANT_READ &&
            error != WOLFSSL_ERROR_WANT_WRITE) {
            return -error;
        }
        k_sleep(K_MSEC(1));
    }
    return offset == size ? 0 : -ETIMEDOUT;
}

/*
 * Encode an MQTT variable-length Remaining Length field.
 */
static size_t encode_remaining(uint32_t value, uint8_t output[4])
{
    size_t count = 0;
    do {
        uint8_t digit = value % 128U;
        value /= 128U;
        if (value != 0U) {
            digit |= 0x80U;
        }
        output[count++] = digit;
    } while (value != 0U && count < 4);
    return count;
}

/*
 * Parse an MQTT fixed header from the TLS stream.
 */
static int read_packet_header(WOLFSSL *ssl, struct mqtt_packet *packet)
{
    uint32_t multiplier = 1;
    uint8_t digit;

    if (tls_read_exact(ssl, &packet->type, 1) != 0) {
        return -EIO;
    }
    packet->remaining = 0;
    for (int i = 0; i < 4; i++) {
        if (tls_read_exact(ssl, &digit, 1) != 0) {
            return -EIO;
        }
        packet->remaining += (digit & 0x7FU) * multiplier;
        if ((digit & 0x80U) == 0U) {
            return 0;
        }
        multiplier *= 128U;
    }
    return -EINVAL;
}

/*
 * Send an MQTT QoS 1 PUBACK for a packet identifier.
 */
static int send_puback(WOLFSSL *ssl, uint16_t packet_id)
{
    uint8_t packet[] = {0x40, 0x02, packet_id >> 8, packet_id & 0xff};
    return tls_write_all(ssl, packet, sizeof(packet));
}

/*
 * Wait for and validate an MQTT QoS 1 PUBACK.
 */
static int wait_puback(WOLFSSL *ssl, uint16_t packet_id)
{
    struct mqtt_packet packet;
    uint8_t body[2];
    if (read_packet_header(ssl, &packet) != 0 || packet.type != 0x40 ||
        packet.remaining != 2 || tls_read_exact(ssl, body, sizeof(body)) != 0) {
        return -EINVAL;
    }
    return (((uint16_t)body[0] << 8) | body[1]) == packet_id ? 0 : -EINVAL;
}

/*
 * Generate one deterministic payload byte for integrity checks.
 */
static uint8_t pattern_byte(uint32_t seed, uint32_t offset)
{
    return (uint8_t)(seed + offset * 31U + (offset >> 8) * 17U);
}

/*
 * Convert a SHA-256 digest to lowercase hexadecimal text.
 */
static void hash_to_hex(const uint8_t hash[WC_SHA256_DIGEST_SIZE], char hex[65])
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < WC_SHA256_DIGEST_SIZE; i++) {
        hex[i * 2] = digits[hash[i] >> 4];
        hex[i * 2 + 1] = digits[hash[i] & 0x0f];
    }
    hex[64] = '\0';
}

/*
 * Publish an in-memory MQTT payload with QoS 1.
 */
static int publish_memory(WOLFSSL *ssl, const char *topic,
                          const uint8_t *payload, size_t payload_size,
                          uint16_t *packet_id_out)
{
    uint8_t header[64];
    uint8_t remaining[4];
    size_t topic_size = strlen(topic);
    uint16_t packet_id = next_packet_id++;
    uint32_t body_size = 2U + topic_size + 2U + payload_size;
    size_t rem_size = encode_remaining(body_size, remaining);
    size_t offset = 0;

    header[offset++] = 0x32;
    memcpy(header + offset, remaining, rem_size);
    offset += rem_size;
    header[offset++] = topic_size >> 8;
    header[offset++] = topic_size & 0xff;
    memcpy(header + offset, topic, topic_size);
    offset += topic_size;
    header[offset++] = packet_id >> 8;
    header[offset++] = packet_id & 0xff;
    if (tls_write_all(ssl, header, offset) != 0 ||
        tls_write_all(ssl, payload, payload_size) != 0) {
        return -EIO;
    }
    *packet_id_out = packet_id;
    return 0;
}

/*
 * Stream a deterministic MQTT payload while computing its digest.
 */
static int publish_pattern(WOLFSSL *ssl, const char *topic, uint32_t seed,
                           uint32_t payload_size, uint16_t *packet_id_out,
                           char hash_hex[65])
{
    void *heap = wolfSSL_CTX_GetHeap(NULL, ssl);
    uint8_t *chunk = XMALLOC(
        MQTT_TX_CHUNK, heap, DYNAMIC_TYPE_TMP_BUFFER);
    uint8_t digest[WC_SHA256_DIGEST_SIZE];
    wc_Sha256 sha;
    uint16_t packet_id;
    uint32_t sent = 0;

    if (chunk == NULL || wc_InitSha256(&sha) != 0) {
        XFREE(chunk, heap, DYNAMIC_TYPE_TMP_BUFFER);
        return -EIO;
    }
    packet_id = next_packet_id++;
    uint8_t header[64], remaining[4];
    size_t topic_size = strlen(topic), offset = 0;
    size_t rem_size = encode_remaining(2U + topic_size + 2U + payload_size,
                                       remaining);
    header[offset++] = 0x32;
    memcpy(header + offset, remaining, rem_size); offset += rem_size;
    header[offset++] = topic_size >> 8; header[offset++] = topic_size & 0xff;
    memcpy(header + offset, topic, topic_size); offset += topic_size;
    header[offset++] = packet_id >> 8; header[offset++] = packet_id & 0xff;
    int ret = tls_write_all(ssl, header, offset);
    if (ret != 0) {
        wc_Sha256Free(&sha);
        XFREE(chunk, heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }
    while (sent < payload_size) {
        size_t count = MIN((size_t)MQTT_TX_CHUNK, payload_size - sent);
        for (size_t i = 0; i < count; i++) {
            chunk[i] = pattern_byte(seed, sent + i);
        }
        if (wc_Sha256Update(&sha, chunk, count) != 0) {
            wc_Sha256Free(&sha);
            XFREE(chunk, heap, DYNAMIC_TYPE_TMP_BUFFER);
            return -EIO;
        }
        ret = tls_write_all(ssl, chunk, count);
        if (ret != 0) {
            wc_Sha256Free(&sha);
            XFREE(chunk, heap, DYNAMIC_TYPE_TMP_BUFFER);
            return ret;
        }
        sent += count;
    }
    if (wc_Sha256Final(&sha, digest) != 0) {
        wc_Sha256Free(&sha);
        XFREE(chunk, heap, DYNAMIC_TYPE_TMP_BUFFER);
        return -EIO;
    }
    wc_Sha256Free(&sha);
    XFREE(chunk, heap, DYNAMIC_TYPE_TMP_BUFFER);
    hash_to_hex(digest, hash_hex);
    *packet_id_out = packet_id;
    return 0;
}

/*
 * Stream, hash, and validate one incoming MQTT PUBLISH packet.
 */
static int read_publish(WOLFSSL *ssl, char *topic, size_t topic_capacity,
                        uint8_t *small_payload, size_t small_capacity,
                        uint32_t expected_size, uint32_t expected_seed,
                        uint32_t *payload_size_out, uint16_t *packet_id_out,
                        bool *integrity_out, char hash_hex[65])
{
    struct mqtt_packet packet;
    uint8_t prefix[2], chunk[MQTT_RX_CHUNK], digest[WC_SHA256_DIGEST_SIZE];
    uint16_t topic_size;
    uint32_t consumed = 0;
    wc_Sha256 sha;
    bool valid = true;

    if (read_packet_header(ssl, &packet) != 0 || packet.type >> 4 != 3 ||
        tls_read_exact(ssl, prefix, 2) != 0) {
        return -EINVAL;
    }
    topic_size = ((uint16_t)prefix[0] << 8) | prefix[1];
    if (topic_size + 1 > topic_capacity ||
        tls_read_exact(ssl, (uint8_t *)topic, topic_size) != 0) {
        return -EMSGSIZE;
    }
    topic[topic_size] = '\0';
    consumed = 2U + topic_size;
    if (((packet.type >> 1) & 3U) != 0U) {
        if (tls_read_exact(ssl, prefix, 2) != 0) return -EIO;
        *packet_id_out = ((uint16_t)prefix[0] << 8) | prefix[1];
        consumed += 2;
    } else {
        *packet_id_out = 0;
    }
    if (packet.remaining < consumed) return -EINVAL;
    *payload_size_out = packet.remaining - consumed;
    if (wc_InitSha256(&sha) != 0) return -EIO;
    uint32_t received = 0;
    while (received < *payload_size_out) {
        size_t count = MIN(sizeof(chunk), *payload_size_out - received);
        if (tls_read_exact(ssl, chunk, count) != 0) {
            wc_Sha256Free(&sha); return -EIO;
        }
        if (small_payload && received + count <= small_capacity) {
            memcpy(small_payload + received, chunk, count);
        }
        if (expected_size != 0U) {
            for (size_t i = 0; i < count; i++) {
                valid &= chunk[i] == pattern_byte(expected_seed, received + i);
            }
        }
        wc_Sha256Update(&sha, chunk, count);
        received += count;
    }
    wc_Sha256Final(&sha, digest);
    wc_Sha256Free(&sha);
    hash_to_hex(digest, hash_hex);
    *integrity_out = valid &&
        (expected_size == 0U || *payload_size_out == expected_size);
    return 0;
}

/*
 * Subscribe the device to benchmark control and download topics.
 */
static int subscribe_topics(WOLFSSL *ssl)
{
    uint8_t packet[96], remaining[4];
    const char *topics[] = {TOPIC_CONTROL, TOPIC_DOWN};
    uint16_t packet_id = next_packet_id++;
    size_t body = 2, offset = 0;
    for (size_t i = 0; i < ARRAY_SIZE(topics); i++) body += 3 + strlen(topics[i]);
    packet[offset++] = 0x82;
    size_t rem = encode_remaining(body, remaining);
    memcpy(packet + offset, remaining, rem); offset += rem;
    packet[offset++] = packet_id >> 8; packet[offset++] = packet_id & 0xff;
    for (size_t i = 0; i < ARRAY_SIZE(topics); i++) {
        size_t length = strlen(topics[i]);
        packet[offset++] = length >> 8; packet[offset++] = length & 0xff;
        memcpy(packet + offset, topics[i], length); offset += length;
        packet[offset++] = 1;
    }
    if (tls_write_all(ssl, packet, offset) != 0) return -EIO;
    struct mqtt_packet response;
    uint8_t body_bytes[4];
    if (read_packet_header(ssl, &response) != 0 || response.type != 0x90 ||
        response.remaining > sizeof(body_bytes) ||
        tls_read_exact(ssl, body_bytes, response.remaining) != 0) return -EINVAL;
    return 0;
}

#ifndef BENCH_POWER_MARKERS
/*
 * Emit transfer timing and resource records over the board console.
 */
static void emit_transfer_result(uint32_t sequence, const char *direction,
                                 uint32_t payload_size, bool success,
                                 int error_code, uint16_t packet_id,
                                 const char *hash,
                                 int64_t data_us, int64_t ack_us,
                                 int64_t end_to_end_us,
                                 const struct cpu_snapshot *cpu_start,
                                 const struct cpu_snapshot *cpu_end,
                                 const struct benchmark_dwt_delta *dwt,
                                 const struct sys_memory_stats *heap)
{
    const struct benchmark_metrics *metrics = benchmark_metrics_get();
    uint64_t cycles = 0;
    uint32_t cpu_bp = 0, system_bp = 0;
    if (cpu_start->valid && cpu_end->valid &&
        cpu_end->all_cycles > cpu_start->all_cycles) {
        uint64_t all = cpu_end->all_cycles - cpu_start->all_cycles;
        cycles = cpu_end->thread_cycles - cpu_start->thread_cycles;
        cpu_bp = (uint32_t)MIN(cycles * 10000ULL / all, 10000ULL);
        system_bp = (uint32_t)MIN(
            (cpu_end->non_idle_cycles - cpu_start->non_idle_cycles) *
            10000ULL / all, 10000ULL);
    }
    printk("[BENCH_TRANSFER_RESULT] sequence=%u direction=%s payload_bytes=%u "
           "status=%s error=%d integrity_match=%u sha256=%s transfer_us=%lld "
           "ack_us=%lld end_to_end_us=%lld packet_id=%u\n",
           sequence, direction, payload_size, success ? "success" : "fail",
           error_code, success, hash, data_us, ack_us, end_to_end_us, packet_id);
    k_sleep(K_MSEC(300));
    printk("[BENCH_TRANSFER_RESOURCE] sequence=%u client_cpu_cycles=%llu "
           "client_cycle_hz=%u client_cpu_usage_bp=%u system_cpu_usage_bp=%u "
           "client_heap_current_bytes=%u client_heap_peak_bytes=%u "
           "client_heap_free_bytes=%u\n",
           sequence, cycles,
           sys_clock_hw_cycles_per_sec(), cpu_bp, system_bp,
           (unsigned int)heap->allocated_bytes,
           (unsigned int)heap->max_allocated_bytes,
           (unsigned int)heap->free_bytes);
    k_sleep(K_MSEC(300));
    printk("[BENCH_TRANSFER_TRANSPORT] sequence=%u l2cap_tx_packets=%u "
           "l2cap_tx_bytes=%u l2cap_rx_packets=%u l2cap_rx_bytes=%u "
           "l2cap_tx_retries=%u l2cap_tx_wait_us=%llu l2cap_rx_overflows=%u "
           BENCHMARK_DWT_FORMAT "\n",
           sequence,
           metrics->l2cap_tx_packets, metrics->l2cap_tx_bytes,
           metrics->l2cap_rx_packets, metrics->l2cap_rx_bytes,
           metrics->l2cap_tx_retries, metrics->l2cap_tx_wait_us,
           metrics->l2cap_rx_overflows, BENCHMARK_DWT_VALUES(*dwt));
}
#endif

/*
 * Publish structured transfer metrics back through MQTT.
 */
static int publish_transfer_metrics(
    WOLFSSL *ssl, uint32_t sequence, const char *direction,
    uint32_t payload_size, bool success, int error_code,
    uint16_t data_packet_id,
    const char *hash, int64_t data_us, int64_t ack_us, int64_t end_to_end_us,
    const struct cpu_snapshot *cpu_start, const struct cpu_snapshot *cpu_end,
    const struct benchmark_dwt_delta *dwt,
    const struct sys_memory_stats *heap)
{
    const struct benchmark_metrics *metrics = benchmark_metrics_get();
    char payload[1024];
    uint64_t cycles = 0;
    uint32_t cpu_bp = 0, system_bp = 0;
    if (cpu_start->valid && cpu_end->valid &&
        cpu_end->all_cycles > cpu_start->all_cycles) {
        uint64_t all = cpu_end->all_cycles - cpu_start->all_cycles;
        cycles = cpu_end->thread_cycles - cpu_start->thread_cycles;
        cpu_bp = (uint32_t)MIN(cycles * 10000ULL / all, 10000ULL);
        system_bp = (uint32_t)MIN(
            (cpu_end->non_idle_cycles - cpu_start->non_idle_cycles) *
            10000ULL / all, 10000ULL);
    }
    int length = snprintk(
        payload, sizeof(payload),
        "sequence=%u direction=%s payload_bytes=%u status=%s error=%d "
        "integrity_match=%u sha256=%s transfer_us=%lld ack_us=%lld "
        "end_to_end_us=%lld packet_id=%u client_cpu_cycles=%llu "
        "client_cycle_hz=%u client_cpu_usage_bp=%u system_cpu_usage_bp=%u "
        "client_heap_current_bytes=%u client_heap_peak_bytes=%u "
        "client_heap_free_bytes=%u l2cap_tx_packets=%u l2cap_tx_bytes=%u "
        "l2cap_rx_packets=%u l2cap_rx_bytes=%u l2cap_tx_retries=%u "
        "l2cap_tx_wait_us=%llu l2cap_rx_overflows=%u " BENCHMARK_DWT_FORMAT,
        sequence, direction, payload_size, success ? "success" : "fail",
        error_code, success, hash, data_us, ack_us, end_to_end_us,
        data_packet_id, cycles,
        sys_clock_hw_cycles_per_sec(), cpu_bp, system_bp,
        (unsigned int)heap->allocated_bytes,
        (unsigned int)heap->max_allocated_bytes,
        (unsigned int)heap->free_bytes,
        metrics->l2cap_tx_packets, metrics->l2cap_tx_bytes,
        metrics->l2cap_rx_packets, metrics->l2cap_rx_bytes,
        metrics->l2cap_tx_retries, metrics->l2cap_tx_wait_us,
        metrics->l2cap_rx_overflows, BENCHMARK_DWT_VALUES(*dwt));
    uint16_t metrics_packet_id;
    if (length <= 0 || length >= sizeof(payload) ||
        publish_memory(ssl, TOPIC_METRICS, (uint8_t *)payload,
                       (size_t)length, &metrics_packet_id) != 0) {
        return -EIO;
    }
    return wait_puback(ssl, metrics_packet_id);
}

/*
 * Execute the ordered bidirectional MQTT transfer operations.
 */
int benchmark_mqtt_transfer_run(WOLFSSL *ssl, struct k_heap *heap,
                                uint32_t heap_capacity)
{
    ARG_UNUSED(heap_capacity);
    uint16_t packet_id;
    if (subscribe_topics(ssl) != 0 ||
        publish_memory(ssl, TOPIC_UP, (const uint8_t *)"READY", 5,
                       &packet_id) != 0 || wait_puback(ssl, packet_id) != 0) {
        return -EIO;
    }

    char begin_topic[32], begin_control[64] = {0}, begin_hash[65];
    uint32_t begin_size;
    uint16_t begin_id;
    bool begin_integrity;
    unsigned int operation_count;
    if (read_publish(ssl, begin_topic, sizeof(begin_topic),
                     (uint8_t *)begin_control, sizeof(begin_control) - 1,
                     0, 0, &begin_size, &begin_id, &begin_integrity,
                     begin_hash) != 0 ||
        strcmp(begin_topic, TOPIC_CONTROL) != 0 ||
        begin_size >= sizeof(begin_control) ||
        send_puback(ssl, begin_id) != 0) {
        return -EINVAL;
    }
    begin_control[begin_size] = '\0';
    if (sscanf(begin_control, "BEGIN %u", &operation_count) != 1 ||
        operation_count == 0 ||
        operation_count > BENCH_TRANSFER_MAX_OPERATIONS) {
        return -EINVAL;
    }

    for (unsigned int operation = 0; operation < operation_count;
         operation++) {
        char topic[32], control[192] = {0}, expected_hash[65] = {0};
        char actual_hash[65] = {0};
        uint32_t control_size, sequence, payload_size, payload_seed;
        uint16_t control_id;
        bool ignored_integrity;
        if (read_publish(ssl, topic, sizeof(topic), (uint8_t *)control,
                         sizeof(control) - 1, 0, 0, &control_size, &control_id,
                         &ignored_integrity, actual_hash) != 0 ||
            strcmp(topic, TOPIC_CONTROL) != 0 ||
            control_size >= sizeof(control) || send_puback(ssl, control_id) != 0) {
            return -EINVAL;
        }
        control[control_size] = '\0';
        char direction[8];
        if (sscanf(control, "%7s %u %u %u %64s", direction, &sequence,
                   &payload_size, &payload_seed, expected_hash) != 5) {
            return -EINVAL;
        }
        mqtt_timeout_ms = BENCH_TRANSFER_TIMEOUT_MS;

        benchmark_metrics_reset();
        benchmark_hardware_counters_start();
        (void)sys_heap_runtime_stats_reset_max(&heap->heap);
        struct cpu_snapshot cpu_start = cpu_snapshot_get();
        struct benchmark_dwt_snapshot dwt_start = benchmark_dwt_snapshot_get();
        int64_t started = k_uptime_ticks(), data_done = started;
        bool valid = false;
        int ret;
        uint16_t result_packet_id = 0;
        benchmark_power_total_set(true);
        if (strcmp(direction, "DOWN") == 0) {
            uint32_t received_size;
            ret = read_publish(ssl, topic, sizeof(topic), NULL, 0, payload_size,
                               payload_seed, &received_size, &packet_id, &valid,
                               actual_hash);
            data_done = k_uptime_ticks();
            result_packet_id = packet_id;
            if (ret == 0) ret = send_puback(ssl, packet_id);
            char ack[128];
            int ack_len = snprintk(ack, sizeof(ack), "ACK_DOWN %u %u %s",
                                   sequence, valid, actual_hash);
            if (ret == 0) ret = publish_memory(
                ssl, TOPIC_DEVICE_ACK, (uint8_t *)ack, ack_len, &packet_id);
            if (ret == 0) ret = wait_puback(ssl, packet_id);
        } else if (strcmp(direction, "UP") == 0) {
            ret = publish_pattern(ssl, TOPIC_UP, payload_seed, payload_size,
                                  &packet_id, actual_hash);
            result_packet_id = packet_id;
            data_done = k_uptime_ticks();
            if (ret == 0) ret = wait_puback(ssl, packet_id);
            if (ret == 0) {
                uint32_t ack_size;
                char ack_digest[65];
                ret = read_publish(ssl, topic, sizeof(topic), (uint8_t *)control,
                                   sizeof(control) - 1, 0, 0, &ack_size,
                                   &control_id, &ignored_integrity, ack_digest);
                if (ret == 0) ret = send_puback(ssl, control_id);
                if (ack_size < sizeof(control)) control[ack_size] = '\0';
                unsigned int ack_sequence, ack_valid;
                char ack_hash[65];
                valid = ret == 0 && sscanf(control, "ACK_UP %u %u %64s",
                    &ack_sequence, &ack_valid, ack_hash) == 3 &&
                    ack_sequence == sequence && ack_valid == 1 &&
                    strcmp(ack_hash, actual_hash) == 0;
            }
        } else {
            benchmark_power_total_set(false);
            return -EINVAL;
        }
        int64_t ended = k_uptime_ticks();
        benchmark_power_total_set(false);
        struct cpu_snapshot cpu_end = cpu_snapshot_get();
        benchmark_hardware_counters_stop();
        struct benchmark_dwt_delta dwt = benchmark_dwt_delta_get(&dwt_start);
        benchmark_metrics_stop();
        struct sys_memory_stats heap_stats = {0};
        (void)sys_heap_runtime_stats_get(&heap->heap, &heap_stats);
        valid = valid && ret == 0 && strcmp(actual_hash, expected_hash) == 0;
#ifndef BENCH_POWER_MARKERS
        /* Source Mode has no DK UART; MQTT carries the same structured metrics. */
        emit_transfer_result(
            sequence,
            strcmp(direction, "DOWN") == 0 ? "server_to_device" :
                                               "device_to_server",
            payload_size, valid, ret, result_packet_id, actual_hash,
            k_ticks_to_us_floor64(data_done - started),
            k_ticks_to_us_floor64(ended - data_done),
            k_ticks_to_us_floor64(ended - started),
            &cpu_start, &cpu_end, &dwt, &heap_stats);
#endif
        if (publish_transfer_metrics(
                ssl, sequence,
                strcmp(direction, "DOWN") == 0 ? "server_to_device" :
                                                   "device_to_server",
                payload_size, valid, ret, result_packet_id, actual_hash,
                k_ticks_to_us_floor64(data_done - started),
                k_ticks_to_us_floor64(ended - data_done),
                k_ticks_to_us_floor64(ended - started),
                &cpu_start, &cpu_end, &dwt, &heap_stats) != 0) {
            return -EIO;
        }
#ifndef BENCH_POWER_MARKERS
        /* Let the asynchronous UART backend drain the metrics records. */
        k_sleep(K_MSEC(300));
#endif
        if (!valid) return -EIO;
    }
    return 0;
}
