#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/l2cap.h>
#include <zephyr/sys/ring_buffer.h>
#include <zephyr/settings/settings.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/debug/thread_analyzer.h>
#include <zephyr/sys/reboot.h>
#include <time.h>
#include <string.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/memory.h>
#include "benchmark_metrics.h"
#include "power_markers.h"
#ifdef BENCH_USE_PQM4_MLKEM
#include "pqm4_mlkem_backend.h"
#endif
#include <zephyr/drivers/gpio.h>
#if defined(CONFIG_CPU_CORTEX_M_HAS_DWT)
#include <cmsis_core.h>
#endif
#include "benchmark_credentials.h"

#ifndef BENCHMARK_VERBOSE_LOGS
#define BENCHMARK_VERBOSE_LOGS 0
#endif

#ifndef BENCH_REBOOT_AFTER_SESSION
#define BENCH_REBOOT_AFTER_SESSION 1
#endif

#if BENCHMARK_VERBOSE_LOGS
#define BENCH_LOG(...) printk(__VA_ARGS__)
#else
#define BENCH_LOG(...) do { } while (0)
#endif
#define BENCH_OUT(...) printk(__VA_ARGS__)

#define L2CAP_SDU_MTU 672
#define TLS_RX_RINGBUF_SIZE 8192

/*
 * Keep wolfSSL's short-lived PQC allocations out of picolibc's process-wide
 * arena.  ML-DSA verification has a high transient peak and needs one large,
 * non-fragmented heap.  The nRF5340 application core has twice the SRAM of
 * the nRF52840 used by the development harness.
 */
#if defined(CONFIG_SOC_NRF5340_CPUAPP)
#define WOLFSSL_HEAP_SIZE (300 * 1024)
#else
#define WOLFSSL_HEAP_SIZE (170 * 1024)
#endif

K_HEAP_DEFINE(wolfssl_heap, WOLFSSL_HEAP_SIZE);

extern char _flash_used[];
extern char _image_ram_size[];

static volatile bool suppress_l2cap_rx_log;
static volatile bool tls_handshake_active;
static volatile int64_t tls_handshake_start_ms;
static volatile int64_t l2cap_connected_ms;

static void wolfssl_heap_report(const char *where)
{
    struct sys_memory_stats stats;

    if (sys_heap_runtime_stats_get(&wolfssl_heap.heap, &stats) == 0) {
        BENCH_LOG("[WOLFSSL HEAP] %s: used=%u peak=%u free=%u/%u\n",
               where, (unsigned int)stats.allocated_bytes,
               (unsigned int)stats.max_allocated_bytes,
               (unsigned int)stats.free_bytes, WOLFSSL_HEAP_SIZE);
    }
}

static void tls_handshake_progress(struct k_timer *timer)
{
    ARG_UNUSED(timer);

    if (!tls_handshake_active) {
        return;
    }

    int64_t elapsed_ms = k_uptime_get() - tls_handshake_start_ms;
    BENCH_LOG("[TLS] Handshake still running after %lld ms; RSA/PQC crypto is busy.\n",
           elapsed_ms);
}

K_TIMER_DEFINE(tls_progress_timer, tls_handshake_progress, NULL);

static uint32_t benchmark_cpu_cycles_per_sec(void)
{
    return sys_clock_hw_cycles_per_sec();
}

struct benchmark_cpu_snapshot {
    uint64_t thread_cycles;
    uint64_t system_cycles;
    uint64_t non_idle_cycles;
    bool valid;
};

struct benchmark_stack_snapshot {
    uint64_t used_bytes;
    uint64_t capacity_bytes;
    uint32_t peak_percent_bp;
};

static struct benchmark_stack_snapshot stack_snapshot;

static struct benchmark_cpu_snapshot benchmark_cpu_snapshot_get(void)
{
    k_thread_runtime_stats_t thread_stats = {0};
    k_thread_runtime_stats_t system_stats = {0};
    struct benchmark_cpu_snapshot snapshot = {0};

    if (k_thread_runtime_stats_get(k_current_get(), &thread_stats) != 0 ||
        k_thread_runtime_stats_all_get(&system_stats) != 0) {
        return snapshot;
    }
    snapshot.thread_cycles = thread_stats.execution_cycles;
    snapshot.system_cycles = system_stats.execution_cycles;
    snapshot.non_idle_cycles = system_stats.total_cycles;
    snapshot.valid = true;
    return snapshot;
}

static uint32_t benchmark_percent_bp(uint64_t part, uint64_t total)
{
    return total ? (uint32_t)MIN((part * 10000ULL) / total, 10000ULL) : 0;
}

static void benchmark_cpu_delta(
    const struct benchmark_cpu_snapshot *start,
    const struct benchmark_cpu_snapshot *end,
    uint64_t *thread_cycles,
    uint32_t *thread_usage_bp,
    uint32_t *system_usage_bp)
{
    if (!start->valid || !end->valid ||
        end->thread_cycles < start->thread_cycles ||
        end->system_cycles <= start->system_cycles ||
        end->non_idle_cycles < start->non_idle_cycles) {
        *thread_cycles = 0;
        *thread_usage_bp = 0;
        *system_usage_bp = 0;
        return;
    }

    uint64_t system_cycles = end->system_cycles - start->system_cycles;
    *thread_cycles = end->thread_cycles - start->thread_cycles;
    *thread_usage_bp = benchmark_percent_bp(*thread_cycles, system_cycles);
    *system_usage_bp = benchmark_percent_bp(
        end->non_idle_cycles - start->non_idle_cycles, system_cycles);
}

static void benchmark_stack_analyzer_cb(struct thread_analyzer_info *info)
{
    uint32_t percent_bp;

    stack_snapshot.used_bytes += info->stack_used;
    stack_snapshot.capacity_bytes += info->stack_size;
    percent_bp = benchmark_percent_bp(info->stack_used, info->stack_size);
    stack_snapshot.peak_percent_bp =
        MAX(stack_snapshot.peak_percent_bp, percent_bp);
}

static struct benchmark_stack_snapshot benchmark_stack_snapshot_get(void)
{
    stack_snapshot = (struct benchmark_stack_snapshot){0};
    thread_analyzer_run(benchmark_stack_analyzer_cb, 0);
    return stack_snapshot;
}

static void benchmark_runtime_report(const char *where)
{
    BENCH_LOG("[BENCHMARK_RESULT] Runtime_Report: %s\n", where);
    BENCH_LOG("[BENCHMARK_RESULT] Client_RAM_Total_Bytes: %u\n",
           (unsigned int)(CONFIG_SRAM_SIZE * 1024U));
    BENCH_LOG("[BENCHMARK_RESULT] Client_ROM_Total_Bytes: %u\n",
           (unsigned int)(CONFIG_FLASH_SIZE * 1024U));

    /*
     * Zephyr's Thread Analyzer reports per-thread stack usage and CPU
     * utilization.  The begin/end markers make the host-side CSV parser treat
     * the following lines as one clean benchmark snapshot.
     */
    BENCH_LOG("[BENCHMARK_RESULT] Thread_Analyzer_Begin\n");
    suppress_l2cap_rx_log = true;
    thread_analyzer_print(0);
    suppress_l2cap_rx_log = false;
    BENCH_LOG("[BENCHMARK_RESULT] Thread_Analyzer_End\n");
}

static void *wolfssl_malloc(size_t size)
{
    void *ptr = k_heap_alloc(&wolfssl_heap, size, K_NO_WAIT);

    if (ptr == NULL) {
        BENCH_LOG("[WOLFSSL HEAP] allocation failed: requested=%u\n",
               (unsigned int)size);
        wolfssl_heap_report("OOM");
    }
    return ptr;
}

static void wolfssl_free(void *ptr)
{
    k_heap_free(&wolfssl_heap, ptr);
}

static void *wolfssl_realloc(void *ptr, size_t size)
{
    void *new_ptr = k_heap_realloc(&wolfssl_heap, ptr, size, K_NO_WAIT);

    if (new_ptr == NULL && size != 0) {
        BENCH_LOG("[WOLFSSL HEAP] realloc failed: requested=%u\n",
               (unsigned int)size);
        wolfssl_heap_report("OOM");
    }
    return new_ptr;
}

RING_BUF_DECLARE(rx_ringbuf, TLS_RX_RINGBUF_SIZE);
K_SEM_DEFINE(rx_sem, 0, 1);
K_SEM_DEFINE(l2cap_connected_sem, 0, 1);
K_SEM_DEFINE(conn_params_ready_sem, 0, 1);

/* --- WOLFSSL TIME HOOKS --- */
time_t time_sec(time_t *timer) {
    /* * Unix timestamp for 2030-01-01.
     * This tricks wolfSSL into thinking it is the modern day
     * so it doesn't reject generated certificate activation dates.
     */
    time_t base_time = 1893456000;
    
    /* Add the board's uptime to the 2026 baseline */
    time_t t = base_time + (time_t)(k_uptime_get_32() / 1000);
    
    if (timer) *timer = t;
    return t;
}

int time_ms(int *timer) {
    int t = (int)k_uptime_get_32();
    if (timer) *timer = t;
    return t;
}

#define LED0_NODE DT_ALIAS(led0)

#if DT_NODE_HAS_STATUS(LED0_NODE, okay)
static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(LED0_NODE, gpios);
#define HAS_STATUS_LED 1
#else
#define HAS_STATUS_LED 0
#endif

#define HEARTBEAT_INTERVAL_MS 30000 // 30 Seconds
#define TIMEOUT_THRESHOLD_MS  45000 // 45 Seconds

#ifndef BENCHMARK_CLOSE_AFTER_TLS
#define BENCHMARK_CLOSE_AFTER_TLS 0
#endif

static void update_led(bool on)
{
#if HAS_STATUS_LED
	if (gpio_is_ready_dt(&led)) {
		(void)gpio_pin_set_dt(&led, on ? 1 : 0);
	}
#else
	ARG_UNUSED(on);
#endif
}

/* --- BLUETOOTH L2CAP BRIDGE --- */
/*
 * ML-KEM-768 and ML-KEM-1024 ClientHello records are larger than one or two
 * 672-byte LE CoC SDUs.  With only two TX buffers, the first TLS flight can be
 * truncated/stalled after the second chunk; Mosquitto then waits forever for
 * the rest of the TLS record and the board only sees WANT_READ until timeout.
 */
NET_BUF_POOL_DEFINE(l2cap_tx_pool, 5, BT_L2CAP_BUF_SIZE(L2CAP_SDU_MTU), 8, NULL);
NET_BUF_POOL_DEFINE(l2cap_rx_pool, 8, BT_L2CAP_BUF_SIZE(L2CAP_SDU_MTU), 8, NULL);

static struct bt_l2cap_le_chan l2cap_chan;
static volatile bool l2cap_rx_overflow;
static volatile bool l2cap_peer_disconnected;
static volatile bool acl_peer_disconnected = true;
static volatile bool disconnect_requested;
static struct bt_conn *active_conn;
static const struct bt_le_conn_param benchmark_conn_params =
    BT_LE_CONN_PARAM_INIT(9, 12, 0, 3200);

static void bt_connected(struct bt_conn *conn, uint8_t err)
{
    char addr[BT_ADDR_LE_STR_LEN];

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
    if (err) {
        BENCH_LOG("[BLE] ACL connection to %s failed: err=0x%02x\n", addr, err);
        return;
    }

    if (active_conn != NULL) {
        bt_conn_unref(active_conn);
    }
    active_conn = bt_conn_ref(conn);
    acl_peer_disconnected = false;
    BENCH_LOG("[BLE] ACL connected: %s\n", addr);
    int update_err = bt_conn_le_param_update(conn, &benchmark_conn_params);
    if (update_err != 0 && update_err != -EALREADY) {
        BENCH_LOG("[BLE] Connection parameter update failed: %d\n", update_err);
    }
}

static void bt_disconnected(struct bt_conn *conn, uint8_t reason)
{
    char addr[BT_ADDR_LE_STR_LEN];

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
    BENCH_LOG("[BLE] ACL disconnected: %s reason=0x%02x\n", addr, reason);
    acl_peer_disconnected = true;
    l2cap_peer_disconnected = true;
    if (active_conn == conn) {
        bt_conn_unref(active_conn);
        active_conn = NULL;
    }
    k_sem_give(&rx_sem);
}

static void bt_le_param_updated(struct bt_conn *conn, uint16_t interval,
                                uint16_t latency, uint16_t timeout)
{
    char addr[BT_ADDR_LE_STR_LEN];

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
    BENCH_LOG("[BLE] Params updated for %s: interval=%u latency=%u timeout=%u\n",
           addr, interval, latency, timeout);
    if (timeout >= 3000) {
        k_sem_give(&conn_params_ready_sem);
    }
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
    .connected = bt_connected,
    .disconnected = bt_disconnected,
    .le_param_updated = bt_le_param_updated,
};

/* FIX 2: Provide an allocation callback so Zephyr doesn't drop incoming data */
static struct net_buf *l2cap_alloc_buf(struct bt_l2cap_chan *chan) {
    return net_buf_alloc(&l2cap_rx_pool, K_MSEC(100));
}

static int l2cap_recv(struct bt_l2cap_chan *chan, struct net_buf *buf) {
    benchmark_l2cap_rx(buf->len);
    uint32_t written = ring_buf_put(&rx_ringbuf, buf->data, buf->len);
    benchmark_l2cap_rx_ring_usage(ring_buf_size_get(&rx_ringbuf));
    if (written < buf->len) {
        l2cap_rx_overflow = true;
        benchmark_l2cap_rx_overflow();
        BENCH_LOG("[L2CAP RX] RX ring buffer overflowed: kept %u/%u bytes\n",
               written, buf->len);
    } else if (!suppress_l2cap_rx_log) {
        BENCH_LOG("[L2CAP RX] queued %u bytes\n", buf->len);
    }
    k_sem_give(&rx_sem);
    return 0; /* Return 0 to indicate we consumed the data */
}

static void l2cap_connected(struct bt_l2cap_chan *chan) {
    struct bt_l2cap_le_chan *le_chan =
        CONTAINER_OF(chan, struct bt_l2cap_le_chan, chan);

    l2cap_peer_disconnected = false;
    l2cap_rx_overflow = false;
    disconnect_requested = false;
    l2cap_connected_ms = k_uptime_get();

    BENCH_LOG("[L2CAP] Channel connected. RX MTU=%u TX MTU=%u\n",
           le_chan->rx.mtu, le_chan->tx.mtu);
    k_sem_give(&l2cap_connected_sem);
}

static void l2cap_disconnected(struct bt_l2cap_chan *chan) {
    BENCH_LOG("[L2CAP] Disconnected.\n");
    l2cap_peer_disconnected = true;
    k_sem_give(&rx_sem); /* Wake up any waiting read operations to fail gracefully */
}

static struct bt_l2cap_chan_ops l2cap_ops = {
    .alloc_buf = l2cap_alloc_buf,
    .connected = l2cap_connected,
    .recv = l2cap_recv,
    .disconnected = l2cap_disconnected,
};

static const struct bt_data ad_l2cap_ok[] = {
    BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
    BT_DATA_BYTES(BT_DATA_NAME_COMPLETE, 'P', 'Q', 'C', '5', '2', '8', '4', '0')
};

static const struct bt_data ad_l2cap_error[] = {
    BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
    BT_DATA_BYTES(BT_DATA_NAME_COMPLETE, 'P', 'Q', 'C', '-', 'L', '2', 'E', 'R', 'R')
};

static void handle_command(const byte *payload, word32 len)
{
	char msg[64];
	size_t copy_len = MIN((size_t)len, sizeof(msg) - 1);

	memcpy(msg, payload, copy_len);
	msg[copy_len] = '\0';

	BENCH_LOG("MQTT command: %s\n", msg);

	if (strcmp(msg, "led:on") == 0) {
		update_led(true);
	} else if (strcmp(msg, "led:off") == 0) {
		update_led(false);
	} else if (strcmp(msg, "led:toggle") == 0) {
#if HAS_STATUS_LED
		if (gpio_is_ready_dt(&led)) {
			(void)gpio_pin_toggle_dt(&led);
		}
#endif
	} else if (strcmp(msg, "disconnect") == 0) {
        BENCH_LOG("Disconnect command received. Closing TLS session gracefully.\n");
        disconnect_requested = true;
	}
    // else if (strcmp(msg, "ping") == 0) {
	//	ping_requested = true;
	// }
}

static int l2cap_accept(struct bt_conn *conn, struct bt_l2cap_server *server, struct bt_l2cap_chan **chan);

static struct bt_l2cap_server l2cap_server = {
    .psm = 0x0080,
    .sec_level = BT_SECURITY_L1,
    .accept = l2cap_accept,
};

static int l2cap_accept(struct bt_conn *conn, struct bt_l2cap_server *server, struct bt_l2cap_chan **chan) {
    char addr[BT_ADDR_LE_STR_LEN];
    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
    BENCH_LOG("[L2CAP] Connection request received from: %s\n", addr);

    if (l2cap_chan.chan.conn) {
        BENCH_LOG("[-] Rejecting request: L2CAP channel is already in use!\n");
        return -ENOMEM; 
    }

    l2cap_chan.chan.ops = &l2cap_ops;
    
    l2cap_chan.rx.mtu = L2CAP_SDU_MTU;
    
    *chan = &l2cap_chan.chan;
    BENCH_LOG("[L2CAP] Connection accepted; waiting for channel setup.\n");
    return 0;
}

int l2cap_wolfssl_send(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
    struct bt_l2cap_chan *chan = (struct bt_l2cap_chan *)ctx;
    struct bt_l2cap_le_chan *le_chan = CONTAINER_OF(chan, struct bt_l2cap_le_chan, chan);
    int sent = 0;
    benchmark_timepoint_t io_start = benchmark_metric_start();
#define SEND_RETURN(value) do { \
    benchmark_communication_stop(io_start); \
    return (value); \
} while (0)

    if (l2cap_peer_disconnected && !ring_buf_is_empty(&rx_ringbuf)) {
        SEND_RETURN(WOLFSSL_CBIO_ERR_WANT_READ);
    }

    if (!chan || !chan->conn) { SEND_RETURN(WOLFSSL_CBIO_ERR_CONN_CLOSE); }

    uint16_t mtu = MIN(le_chan->tx.mtu, L2CAP_SDU_MTU);
    if (mtu == 0) mtu = 23; 

    while (sent < sz) {
        int chunk = sz - sent;
        if (chunk > mtu) { chunk = mtu; }

        int err = 0;
        do {
            /* 1. Abort if connection dropped during retry */
            if (l2cap_peer_disconnected && !ring_buf_is_empty(&rx_ringbuf)) {
                SEND_RETURN(sent > 0 ? sent : WOLFSSL_CBIO_ERR_WANT_READ);
            }
            if (!chan || !chan->conn) {
                SEND_RETURN(sent > 0 ? sent : WOLFSSL_CBIO_ERR_CONN_CLOSE);
            }

            /* 2. ALLOCATE FRESH EVERY TIME. 
               If it fails, wait 10ms for pool to drain and continue loop. */
            benchmark_timepoint_t wait_start = benchmark_metric_start();
            struct net_buf *tx_buf = net_buf_alloc(&l2cap_tx_pool, K_MSEC(10));
            benchmark_l2cap_tx_wait_stop(wait_start);
            if (!tx_buf) {
                benchmark_l2cap_tx_retry();
                wait_start = benchmark_metric_start();
                k_sleep(K_MSEC(10));
                benchmark_l2cap_tx_wait_stop(wait_start);
                continue; 
            }

            net_buf_reserve(tx_buf, BT_L2CAP_SDU_CHAN_SEND_RESERVE);
            net_buf_add_mem(tx_buf, buf + sent, chunk);

            /* 3. Send. Zephyr ALWAYS destroys tx_buf here, success or fail. */
            err = bt_l2cap_chan_send(chan, tx_buf);
            
            if (err == -EAGAIN || err == -ENOMEM) {
                /* The radio is full. We lost tx_buf. Sleep and rebuild it. */
                benchmark_l2cap_tx_retry();
                wait_start = benchmark_metric_start();
                k_sleep(K_MSEC(10));
                benchmark_l2cap_tx_wait_stop(wait_start);
            } else if (err < 0) {
                /* Fatal error, connection likely dead */
                SEND_RETURN(sent > 0 ? sent : WOLFSSL_CBIO_ERR_GENERAL);
            }
            
        } while (err == -EAGAIN || err == -ENOMEM);

        benchmark_l2cap_tx(chunk);
        sent += chunk;
    }
    SEND_RETURN(sent);
#undef SEND_RETURN
}

/* FIX 5: Safely wait for data without locking up wolfSSL */
int l2cap_wolfssl_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
    struct bt_l2cap_chan *chan = (struct bt_l2cap_chan *)ctx;
    benchmark_timepoint_t io_start = benchmark_metric_start();
#define RECV_RETURN(value) do { \
    benchmark_communication_stop(io_start); \
    return (value); \
} while (0)

    if (l2cap_rx_overflow) {
        BENCH_LOG("[WOLFSSL RX] Failing TLS session after L2CAP RX overflow.\n");
        RECV_RETURN(WOLFSSL_CBIO_ERR_GENERAL);
    }

    /*
     * Drain data that was already received before treating the transport as
     * closed.  Mosquitto often sends a final TLS alert/close_notify and then
     * closes TCP; the bridge forwards that last SDU and L2CAP disconnects right
     * after it.  If we check chan->conn first, wolfSSL only sees SOCKET_ERROR_E
     * (-308) and never gets the real TLS close/alert bytes.
     */
    uint32_t read_bytes = ring_buf_get(&rx_ringbuf, (uint8_t*)buf, sz);
    if (read_bytes > 0) {
        BENCH_LOG("[WOLFSSL RX] delivering %u bytes to wolfSSL\n", read_bytes);
        RECV_RETURN(read_bytes);
    }

    if (!chan || !chan->conn || l2cap_peer_disconnected) {
        RECV_RETURN(WOLFSSL_CBIO_ERR_CONN_CLOSE);
    }

    /* Wait briefly. If nothing arrives, tell wolfSSL we want to read later. */
    if (k_sem_take(&rx_sem, K_MSEC(50)) == 0) {
        read_bytes = ring_buf_get(&rx_ringbuf, (uint8_t*)buf, sz);
        if (read_bytes > 0) {
            BENCH_LOG("[WOLFSSL RX] delivering %u bytes to wolfSSL\n", read_bytes);
            RECV_RETURN(read_bytes);
        }
        if (!chan->conn || l2cap_peer_disconnected) {
            RECV_RETURN(WOLFSSL_CBIO_ERR_CONN_CLOSE);
        }
    }

    RECV_RETURN(WOLFSSL_CBIO_ERR_WANT_READ);
#undef RECV_RETURN
}

static void shutdown_tls_gracefully(WOLFSSL *ssl, struct bt_l2cap_chan *chan)
{
    if (!ssl || !chan) {
        return;
    }

    for (int attempt = 1; attempt <= 10; attempt++) {
        int shutdown_ret = wolfSSL_shutdown(ssl);

        if (shutdown_ret == WOLFSSL_SUCCESS) {
            BENCH_LOG("TLS shutdown complete.\n");
            return;
        }

        if (shutdown_ret == WOLFSSL_SHUTDOWN_NOT_DONE) {
            if (l2cap_peer_disconnected && ring_buf_is_empty(&rx_ringbuf)) {
                BENCH_LOG("TLS shutdown complete: peer closed after close_notify.\n");
                return;
            }
            BENCH_LOG("TLS shutdown waiting for peer close_notify (%d/10).\n",
                   attempt);
            k_sleep(K_MSEC(100));
            continue;
        }

        int err = wolfSSL_get_error(ssl, shutdown_ret);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            if (l2cap_peer_disconnected && ring_buf_is_empty(&rx_ringbuf)) {
                BENCH_LOG("TLS shutdown complete: peer closed transport.\n");
                return;
            }
            BENCH_LOG("TLS shutdown waiting for transport (%d/10).\n", attempt);
            k_sleep(K_MSEC(100));
            continue;
        }

        BENCH_LOG("TLS shutdown stopped with wolfSSL error: %d\n", err);
        return;
    }

    BENCH_LOG("TLS shutdown close_notify sent; peer did not finish shutdown in time.\n");
}

void start_secure_mqtt_session(struct bt_l2cap_chan *chan)
{
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;
    int ret;
    int64_t setup_start_ms = k_uptime_get();
    int64_t setup_done_ms = 0;
    int64_t handshake_done_ms = 0;
    uint64_t client_cpu_cycles = 0;
    uint64_t client_cpu_us = 0;
    uint32_t client_cpu_usage_bp = 0;
    uint32_t system_cpu_usage_bp = 0;
    uint32_t cpu_cycle_hz = benchmark_cpu_cycles_per_sec();

    benchmark_power_markers_reset();
    benchmark_power_total_set(true);
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx) {
        BENCH_OUT("[BENCH_RESULT] status=fail stage=tls_setup error=ctx_new\n");
        benchmark_power_markers_reset();
        return;
    }
#ifdef BENCH_USE_PQM4_MLKEM
    ret = wolfSSL_CTX_SetDevId(ctx, pqm4_mlkem_backend_dev_id());
    if (ret != WOLFSSL_SUCCESS) {
        BENCH_OUT("[BENCH_RESULT] status=fail stage=pqm4_device error=%d\n", ret);
        wolfSSL_CTX_free(ctx);
        benchmark_power_markers_reset();
        return;
    }
#endif
#if BENCHMARK_VERBOSE_LOGS
    wolfSSL_Debugging_ON();
#endif
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);

    for (size_t i = 0; i < BENCHMARK_CA_COUNT; i++) {
        ret = wolfSSL_CTX_load_verify_buffer(
            ctx, benchmark_ca_bundle[i].data, benchmark_ca_bundle[i].length,
            WOLFSSL_FILETYPE_ASN1);
        if (ret != WOLFSSL_SUCCESS) {
            BENCH_OUT("[BENCH_RESULT] status=fail stage=ca_load error=%d ca_index=%u\n",
                      ret, (unsigned int)i);
            wolfSSL_CTX_free(ctx);
            benchmark_power_markers_reset();
            return;
        }
    }

    int groups[] = {
        WOLFSSL_ECC_SECP256R1,
        WOLFSSL_ECC_SECP384R1,
        WOLFSSL_ECC_SECP521R1,
        WOLFSSL_ML_KEM_512,
        WOLFSSL_ML_KEM_768,
        WOLFSSL_ML_KEM_1024,
        WOLFSSL_SECP256R1MLKEM768,
        WOLFSSL_X25519MLKEM768,
        WOLFSSL_SECP384R1MLKEM1024,
    };
    ret = wolfSSL_CTX_set_groups(ctx, groups, ARRAY_SIZE(groups));
    if (ret != WOLFSSL_SUCCESS) {
        BENCH_OUT("[BENCH_RESULT] status=fail stage=group_setup error=%d\n", ret);
        wolfSSL_CTX_free(ctx);
        benchmark_power_markers_reset();
        return;
    }

    ret = wolfSSL_CTX_use_certificate_buffer(
        ctx, benchmark_client_cert, sizeof(benchmark_client_cert),
        WOLFSSL_FILETYPE_ASN1);
    if (ret != WOLFSSL_SUCCESS) {
        BENCH_OUT("[BENCH_RESULT] status=fail stage=client_cert error=%d\n", ret);
        wolfSSL_CTX_free(ctx);
        benchmark_power_markers_reset();
        return;
    }
    ret = wolfSSL_CTX_use_PrivateKey_buffer(
        ctx, benchmark_client_key, sizeof(benchmark_client_key),
        WOLFSSL_FILETYPE_ASN1);
    if (ret != WOLFSSL_SUCCESS) {
        BENCH_OUT("[BENCH_RESULT] status=fail stage=client_key error=%d\n", ret);
        wolfSSL_CTX_free(ctx);
        benchmark_power_markers_reset();
        return;
    }

    wolfSSL_CTX_SetIOSend(ctx, l2cap_wolfssl_send);
    wolfSSL_CTX_SetIORecv(ctx, l2cap_wolfssl_recv);
    ssl = wolfSSL_new(ctx);
    if (!ssl) {
        BENCH_OUT("[BENCH_RESULT] status=fail stage=tls_setup error=ssl_new\n");
        wolfSSL_CTX_free(ctx);
        benchmark_power_markers_reset();
        return;
    }
    wolfSSL_SetIOReadCtx(ssl, chan);
    wolfSSL_SetIOWriteCtx(ssl, chan);
    setup_done_ms = k_uptime_get();

    (void)sys_heap_runtime_stats_reset_max(&wolfssl_heap.heap);
    benchmark_metrics_reset();
    benchmark_hardware_counters_start();
    int64_t handshake_start_ms = setup_done_ms;
    tls_handshake_start_ms = handshake_start_ms;
    tls_handshake_active = true;
    benchmark_power_handshake_set(true);
    struct benchmark_cpu_snapshot cpu_start = benchmark_cpu_snapshot_get();
    do {
        ret = wolfSSL_connect(ssl);
        if (ret != WOLFSSL_SUCCESS) {
            int error = wolfSSL_get_error(ssl, ret);
            if (error == WOLFSSL_ERROR_WANT_READ || error == WOLFSSL_ERROR_WANT_WRITE) {
                if (l2cap_peer_disconnected && ring_buf_is_empty(&rx_ringbuf)) {
                    error = WOLFSSL_CBIO_ERR_CONN_CLOSE;
                } else {
                    k_sleep(K_MSEC(1));
                    continue;
                }
            }
            struct benchmark_cpu_snapshot cpu_end = benchmark_cpu_snapshot_get();
            benchmark_cpu_delta(
                &cpu_start, &cpu_end, &client_cpu_cycles,
                &client_cpu_usage_bp, &system_cpu_usage_bp);
            client_cpu_us = k_cyc_to_us_floor64(client_cpu_cycles);
            benchmark_hardware_counters_stop();
            tls_handshake_active = false;
            benchmark_power_handshake_set(false);
            BENCH_OUT(
                "[BENCH_RESULT] status=fail stage=tls_handshake error=%d "
                "tls_setup_ms=%lld client_cpu_cycles=%llu "
                "client_cpu_us=%llu client_cycle_hz=%u\n",
                error, setup_done_ms - setup_start_ms,
                client_cpu_cycles, client_cpu_us, cpu_cycle_hz);
            wolfSSL_free(ssl);
            wolfSSL_CTX_free(ctx);
            benchmark_power_markers_reset();
            return;
        }
    } while (ret != WOLFSSL_SUCCESS);
    struct benchmark_cpu_snapshot cpu_end = benchmark_cpu_snapshot_get();
    benchmark_cpu_delta(
        &cpu_start, &cpu_end, &client_cpu_cycles,
        &client_cpu_usage_bp, &system_cpu_usage_bp);
    client_cpu_us = k_cyc_to_us_floor64(client_cpu_cycles);
    benchmark_hardware_counters_stop();
    tls_handshake_active = false;
    benchmark_power_handshake_set(false);
    handshake_done_ms = k_uptime_get();

    static const unsigned char mqtt_connect[] = {
        0x10, 0x14, 0x00, 0x04, 'M', 'Q', 'T', 'T',
        0x04, 0x02, 0x00, 0x3c,
        0x00, 0x08, 'n', 'r', 'f', 'b', 'e', 'n', 'c', 'h',
    };
    int64_t mqtt_start_ms = k_uptime_get();
    ret = wolfSSL_write(ssl, mqtt_connect, sizeof(mqtt_connect));
    if (ret != sizeof(mqtt_connect)) {
        BENCH_OUT("[BENCH_RESULT] status=fail stage=mqtt_write error=%d\n",
                  wolfSSL_get_error(ssl, ret));
        goto cleanup;
    }

    unsigned char rx_buf[128];
    int64_t mqtt_deadline_ms = mqtt_start_ms + 30000;
    while (chan->conn && k_uptime_get() < mqtt_deadline_ms) {
        int bytes_read = wolfSSL_read(ssl, rx_buf, sizeof(rx_buf));
        if (bytes_read >= 4 && rx_buf[0] == 0x20 && rx_buf[1] == 0x02) {
            int64_t mqtt_done_ms = k_uptime_get();
            struct sys_memory_stats stats = {0};
            const struct benchmark_metrics *metrics;

            benchmark_metrics_stop();
            metrics = benchmark_metrics_get();
            (void)sys_heap_runtime_stats_get(&wolfssl_heap.heap, &stats);
            struct benchmark_stack_snapshot stacks =
                benchmark_stack_snapshot_get();
            benchmark_power_total_set(false);
            BENCH_OUT(
                "[BENCH_RESULT] status=success tls_setup_ms=%lld "
                "raw_handshake_ms=%lld mqtt_connect_ms=%lld full_connect_ms=%lld "
                "end_to_end_ms=%lld client_cpu_cycles=%llu client_cpu_us=%llu "
                "client_cycle_hz=%u client_cpu_usage_bp=%u "
                "system_cpu_usage_bp=%u "
                "client_heap_current_bytes=%u client_heap_peak_bytes=%u "
                "client_heap_free_bytes=%u client_heap_capacity_bytes=%u "
                "firmware_flash_used_bytes=%u firmware_flash_capacity_bytes=%u "
                "firmware_static_ram_used_bytes=%u firmware_ram_capacity_bytes=%u "
                "thread_stack_used_bytes=%llu thread_stack_capacity_bytes=%llu "
                "thread_stack_peak_percent_bp=%u "
                "communication_overhead_us=%llu kem_keygen_us=%llu "
                "kem_encapsulation_us=%llu kem_decapsulation_us=%llu "
                "certificate_signature_verify_us=%llu "
                "classical_kex_keygen_us=%llu "
                "classical_kex_shared_secret_us=%llu "
                "tls_certificate_verify_us=%llu "
                "mtls_signature_generate_us=%llu "
                "l2cap_tx_packets=%u l2cap_tx_bytes=%u "
                "l2cap_rx_packets=%u l2cap_rx_bytes=%u "
                "l2cap_tx_retries=%u l2cap_tx_wait_us=%llu "
                "l2cap_rx_overflows=%u l2cap_rx_ring_peak_bytes=%u "
                "l2cap_rx_ring_capacity_bytes=%u "
                "client_icache_hits=%u client_icache_misses=%u "
                "client_memory_access_counters_supported=0\n",
                setup_done_ms - setup_start_ms,
                handshake_done_ms - handshake_start_ms,
                mqtt_done_ms - mqtt_start_ms,
                mqtt_done_ms - setup_start_ms,
                mqtt_done_ms - l2cap_connected_ms,
                client_cpu_cycles, client_cpu_us, cpu_cycle_hz,
                client_cpu_usage_bp, system_cpu_usage_bp,
                (unsigned int)stats.allocated_bytes,
                (unsigned int)stats.max_allocated_bytes,
                (unsigned int)stats.free_bytes, WOLFSSL_HEAP_SIZE,
                (unsigned int)(uintptr_t)_flash_used,
                (unsigned int)(CONFIG_FLASH_SIZE * 1024U),
                (unsigned int)(uintptr_t)_image_ram_size,
                (unsigned int)(CONFIG_SRAM_SIZE * 1024U),
                stacks.used_bytes, stacks.capacity_bytes,
                stacks.peak_percent_bp,
                metrics->communication_us,
                metrics->kem_keygen_us,
                metrics->kem_encapsulation_us,
                metrics->kem_decapsulation_us,
                metrics->certificate_verify_us,
                metrics->classical_kex_keygen_us,
                metrics->classical_kex_shared_secret_us,
                metrics->tls_certificate_verify_us,
                metrics->mtls_signature_generate_us,
                metrics->l2cap_tx_packets, metrics->l2cap_tx_bytes,
                metrics->l2cap_rx_packets, metrics->l2cap_rx_bytes,
                metrics->l2cap_tx_retries, metrics->l2cap_tx_wait_us,
                metrics->l2cap_rx_overflows,
                metrics->l2cap_rx_ring_peak_bytes, TLS_RX_RINGBUF_SIZE,
                metrics->instruction_cache_hits,
                metrics->instruction_cache_misses);
            goto cleanup;
        }
        if (bytes_read < 0) {
            int error = wolfSSL_get_error(ssl, bytes_read);
            if (error != WOLFSSL_ERROR_WANT_READ && error != WOLFSSL_ERROR_WANT_WRITE) {
                BENCH_OUT("[BENCH_RESULT] status=fail stage=mqtt_read error=%d\n", error);
                goto cleanup;
            }
        }
        k_sleep(K_MSEC(1));
    }
    BENCH_OUT("[BENCH_RESULT] status=timeout stage=mqtt_connack error=timeout\n");

cleanup:
    benchmark_metrics_stop();
    benchmark_power_markers_reset();
    shutdown_tls_gracefully(ssl, chan);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
}

static const struct bt_le_adv_param adv_param = {
    .options = BT_LE_ADV_OPT_CONN | BT_LE_ADV_OPT_USE_IDENTITY,
    .interval_min = 0x0100,
    .interval_max = 0x0150,
};

static void print_local_identities(void)
{
    bt_addr_le_t addrs[CONFIG_BT_ID_MAX];
    size_t count = ARRAY_SIZE(addrs);

    bt_id_get(addrs, &count);
    for (size_t i = 0; i < count; i++) {
        char addr_str[BT_ADDR_LE_STR_LEN];

        bt_addr_le_to_str(&addrs[i], addr_str, sizeof(addr_str));
        BENCH_LOG("[BLE] Local identity %u: %s%s\n", (unsigned int)i, addr_str,
               i == BT_ID_DEFAULT ? " (advertising default)" : "");
    }
}

int main(void) {
    benchmark_power_markers_init();
    benchmark_power_markers_reset();
#if HAS_STATUS_LED
    if (!gpio_is_ready_dt(&led)) {
        BENCH_LOG("Error: LED device %s is not ready\n", led.port->name);
        return 0;
    }
    
    /* Configure the pin as an output and initialize it to OFF (0) */
    int ret = gpio_pin_configure_dt(&led, GPIO_OUTPUT_INACTIVE);
    if (ret < 0) {
        BENCH_LOG("Error: Failed to configure LED pin: %d\n", ret);
        return 0;
    }
    BENCH_LOG("LED initialized successfully.\n");
#endif

    bt_conn_auth_cb_register(NULL);

    if (bt_enable(NULL)) {
        BENCH_LOG("Bluetooth init failed\n");
        return 0;
    }

    wolfSSL_SetAllocators(wolfssl_malloc, wolfssl_free, wolfssl_realloc);
    wolfSSL_Init();
#ifdef BENCH_USE_PQM4_MLKEM
    if (pqm4_mlkem_backend_init() != 0) {
        BENCH_OUT("[BENCH_FATAL] stage=pqm4_backend_init\n");
        return 0;
    }
#endif
    wolfssl_heap_report("initialized");

    settings_load();
    print_local_identities();

    int l2cap_err = bt_l2cap_server_register(&l2cap_server);
    if (l2cap_err) {
        BENCH_LOG("L2CAP server registration failed for PSM 0x%04x: %d\n",
               l2cap_server.psm, l2cap_err);
    } else {
        BENCH_LOG("L2CAP server registered with PSM: 0x%04x\n",
               l2cap_server.psm);
    }
    BENCH_OUT("[BENCH_READY] psm=0x%04x mtu=%u ca_count=%u mlkem_backend=%s rsa_profile=%s\n",
              l2cap_server.psm, L2CAP_SDU_MTU,
              (unsigned int)BENCHMARK_CA_COUNT, BENCH_MLKEM_BACKEND_NAME,
              BENCH_RSA_PROFILE_NAME);
    
    k_msleep(100);

    /* FIX 6: The Infinite Reconnection Loop */
    while (1) {
        ring_buf_reset(&rx_ringbuf);
        k_sem_reset(&rx_sem);
        k_sem_reset(&l2cap_connected_sem);
        k_sem_reset(&conn_params_ready_sem);
        l2cap_peer_disconnected = false;
        l2cap_rx_overflow = false;
        disconnect_requested = false;
        
        const struct bt_data *active_ad = l2cap_err ? ad_l2cap_error : ad_l2cap_ok;
        size_t active_ad_len = l2cap_err ? ARRAY_SIZE(ad_l2cap_error) : ARRAY_SIZE(ad_l2cap_ok);
        int err = bt_le_adv_start(&adv_param, active_ad, active_ad_len, NULL, 0);
        if (err && err != -EALREADY) {
            BENCH_LOG("Advertising failed to start (err %d)\n", err);
        } else {
            BENCH_LOG("Advertising started! Waiting for Mac gateway...\n");
            BENCH_OUT("[BENCH_READY] psm=0x%04x mtu=%u ca_count=%u mlkem_backend=%s rsa_profile=%s\n",
                      l2cap_server.psm, L2CAP_SDU_MTU,
                      (unsigned int)BENCHMARK_CA_COUNT, BENCH_MLKEM_BACKEND_NAME,
                      BENCH_RSA_PROFILE_NAME);
        }

        /* Repeat the readiness marker while idle so a host opening UART after
         * boot can still validate the correct console before starting BLE. */
        while (k_sem_take(&l2cap_connected_sem, K_SECONDS(5)) != 0) {
            BENCH_OUT("[BENCH_READY] psm=0x%04x mtu=%u ca_count=%u mlkem_backend=%s rsa_profile=%s\n",
                      l2cap_server.psm, L2CAP_SDU_MTU,
                      (unsigned int)BENCHMARK_CA_COUNT, BENCH_MLKEM_BACKEND_NAME,
                      BENCH_RSA_PROFILE_NAME);
        }
        
        /* Stop advertising while connected to save power */
        bt_le_adv_stop();

        if (k_sem_take(&conn_params_ready_sem, K_SECONDS(2)) != 0) {
            BENCH_LOG("[BLE] Continuing after connection parameter wait timeout.\n");
        }
        start_secure_mqtt_session(&l2cap_chan.chan);
        
        BENCH_LOG("Session ended. Re-arming for next connection...\n");

        /*
         * Close the ACL before any reboot. Resetting the nRF controller while
         * BlueZ still owns an LE CoC can leave stale credits behind for the
         * next large TLS flight.
         */
        struct bt_conn *conn_to_disconnect =
            active_conn != NULL ? bt_conn_ref(active_conn) : NULL;
        if (conn_to_disconnect != NULL && !acl_peer_disconnected) {
            int disconnect_err = bt_conn_disconnect(
                conn_to_disconnect, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
            BENCH_LOG("ACL disconnect requested: %d\n", disconnect_err);
        }
        if (conn_to_disconnect != NULL) {
            bt_conn_unref(conn_to_disconnect);
        }

        /* Never let a missed controller callback poison every later block. */
        int64_t disconnect_deadline = k_uptime_get() + 5000;
        while (!acl_peer_disconnected &&
               k_uptime_get() < disconnect_deadline) {
            k_sleep(K_MSEC(100));
        }

#if BENCH_REBOOT_AFTER_SESSION
        BENCH_OUT("[BENCH_RECOVERY] reason=session_complete action=reboot\n");
        k_msleep(100);
        sys_reboot(SYS_REBOOT_COLD);
#endif

        if (!acl_peer_disconnected) {
            BENCH_OUT("[BENCH_RECOVERY] reason=disconnect_timeout action=reboot\n");
            k_sleep(K_MSEC(50));
            sys_reboot(SYS_REBOOT_COLD);
        }

        memset(&l2cap_chan, 0, sizeof(l2cap_chan));
        l2cap_chan.chan.ops = &l2cap_ops;
        l2cap_chan.rx.mtu = L2CAP_SDU_MTU;
        
        /* Brief cooldown before firing up the radio again. */
        k_sleep(K_MSEC(500));
    }
    
    return 0;
}
