#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/l2cap.h>
#include <zephyr/sys/ring_buffer.h>
#include <zephyr/settings/settings.h>
#include <zephyr/bluetooth/conn.h>
#include <time.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <zephyr/drivers/gpio.h>
#include "client_cert.h"
#include "client_key.h"
#include "ca_cert.h"

#define L2CAP_SDU_MTU 672
#define TLS_RX_RINGBUF_SIZE 16384

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

static void wolfssl_heap_report(const char *where)
{
    struct sys_memory_stats stats;

    if (sys_heap_runtime_stats_get(&wolfssl_heap.heap, &stats) == 0) {
        printk("[WOLFSSL HEAP] %s: used=%u peak=%u free=%u/%u\n",
               where, (unsigned int)stats.allocated_bytes,
               (unsigned int)stats.max_allocated_bytes,
               (unsigned int)stats.free_bytes, WOLFSSL_HEAP_SIZE);
    }
}

static void *wolfssl_malloc(size_t size)
{
    void *ptr = k_heap_alloc(&wolfssl_heap, size, K_NO_WAIT);

    if (ptr == NULL) {
        printk("[WOLFSSL HEAP] allocation failed: requested=%u\n",
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
        printk("[WOLFSSL HEAP] realloc failed: requested=%u\n",
               (unsigned int)size);
        wolfssl_heap_report("OOM");
    }
    return new_ptr;
}

RING_BUF_DECLARE(rx_ringbuf, TLS_RX_RINGBUF_SIZE);
K_SEM_DEFINE(rx_sem, 0, 1);
K_SEM_DEFINE(l2cap_connected_sem, 0, 1);

/* --- WOLFSSL TIME HOOKS --- */
time_t time_sec(time_t *timer) {
    /* * Unix timestamp for mid-2026. 
     * This tricks wolfSSL into thinking it is the modern day
     * so it doesn't reject the Mosquitto certificate's activation date.
     */
    time_t base_time = 1781350000; 
    
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
#define BENCHMARK_CLOSE_AFTER_TLS 1
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
NET_BUF_POOL_DEFINE(l2cap_rx_pool, 3, BT_L2CAP_BUF_SIZE(L2CAP_SDU_MTU), 8, NULL);

static struct bt_l2cap_le_chan l2cap_chan;
static volatile bool l2cap_rx_overflow;
static volatile bool l2cap_peer_disconnected;
static volatile bool disconnect_requested;

static void bt_connected(struct bt_conn *conn, uint8_t err)
{
    char addr[BT_ADDR_LE_STR_LEN];

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
    if (err) {
        printk("[BLE] ACL connection to %s failed: err=0x%02x\n", addr, err);
        return;
    }

    printk("[BLE] ACL connected: %s\n", addr);
}

static void bt_disconnected(struct bt_conn *conn, uint8_t reason)
{
    char addr[BT_ADDR_LE_STR_LEN];

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
    printk("[BLE] ACL disconnected: %s reason=0x%02x\n", addr, reason);
    l2cap_peer_disconnected = true;
    k_sem_give(&rx_sem);
}

static void bt_le_param_updated(struct bt_conn *conn, uint16_t interval,
                                uint16_t latency, uint16_t timeout)
{
    char addr[BT_ADDR_LE_STR_LEN];

    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
    printk("[BLE] Params updated for %s: interval=%u latency=%u timeout=%u\n",
           addr, interval, latency, timeout);
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
    uint32_t written = ring_buf_put(&rx_ringbuf, buf->data, buf->len);
    if (written < buf->len) {
        l2cap_rx_overflow = true;
        printk("[L2CAP RX] RX ring buffer overflowed: kept %u/%u bytes\n",
               written, buf->len);
    } else {
        printk("[L2CAP RX] queued %u bytes\n", buf->len);
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

    printk("[L2CAP] Channel connected. RX MTU=%u TX MTU=%u\n",
           le_chan->rx.mtu, le_chan->tx.mtu);
    k_sem_give(&l2cap_connected_sem);
}

static void l2cap_disconnected(struct bt_l2cap_chan *chan) {
    printk("[L2CAP] Disconnected.\n");
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

	printk("MQTT command: %s\n", msg);

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
        printk("Disconnect command received. Closing TLS session gracefully.\n");
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
    printk("[L2CAP] Connection request received from: %s\n", addr);

    if (l2cap_chan.chan.conn) {
        printk("[-] Rejecting request: L2CAP channel is already in use!\n");
        return -ENOMEM; 
    }

    l2cap_chan.chan.ops = &l2cap_ops;
    
    l2cap_chan.rx.mtu = L2CAP_SDU_MTU;
    
    *chan = &l2cap_chan.chan;
    printk("[L2CAP] Connection accepted; waiting for channel setup.\n");
    return 0;
}

int l2cap_wolfssl_send(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
    struct bt_l2cap_chan *chan = (struct bt_l2cap_chan *)ctx;
    struct bt_l2cap_le_chan *le_chan = CONTAINER_OF(chan, struct bt_l2cap_le_chan, chan);
    int sent = 0;

    if (l2cap_peer_disconnected && !ring_buf_is_empty(&rx_ringbuf)) {
        return WOLFSSL_CBIO_ERR_WANT_READ;
    }

    if (!chan || !chan->conn) { return WOLFSSL_CBIO_ERR_CONN_CLOSE; }

    uint16_t mtu = MIN(le_chan->tx.mtu, L2CAP_SDU_MTU);
    if (mtu == 0) mtu = 23; 

    while (sent < sz) {
        int chunk = sz - sent;
        if (chunk > mtu) { chunk = mtu; }

        int err = 0;
        do {
            /* 1. Abort if connection dropped during retry */
            if (l2cap_peer_disconnected && !ring_buf_is_empty(&rx_ringbuf)) {
                return sent > 0 ? sent : WOLFSSL_CBIO_ERR_WANT_READ;
            }
            if (!chan || !chan->conn) {
                return sent > 0 ? sent : WOLFSSL_CBIO_ERR_CONN_CLOSE;
            }

            /* 2. ALLOCATE FRESH EVERY TIME. 
               If it fails, wait 10ms for pool to drain and continue loop. */
            struct net_buf *tx_buf = net_buf_alloc(&l2cap_tx_pool, K_MSEC(10));
            if (!tx_buf) {
                k_sleep(K_MSEC(10));
                continue; 
            }

            net_buf_reserve(tx_buf, BT_L2CAP_SDU_CHAN_SEND_RESERVE);
            net_buf_add_mem(tx_buf, buf + sent, chunk);

            /* 3. Send. Zephyr ALWAYS destroys tx_buf here, success or fail. */
            err = bt_l2cap_chan_send(chan, tx_buf);
            
            if (err == -EAGAIN || err == -ENOMEM) {
                /* The radio is full. We lost tx_buf. Sleep and rebuild it. */
                k_sleep(K_MSEC(10));
            } else if (err < 0) {
                /* Fatal error, connection likely dead */
                return sent > 0 ? sent : WOLFSSL_CBIO_ERR_GENERAL;
            }
            
        } while (err == -EAGAIN || err == -ENOMEM);

        sent += chunk;
    }
    return sent; 
}

/* FIX 5: Safely wait for data without locking up wolfSSL */
int l2cap_wolfssl_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
    struct bt_l2cap_chan *chan = (struct bt_l2cap_chan *)ctx;

    if (l2cap_rx_overflow) {
        printk("[WOLFSSL RX] Failing TLS session after L2CAP RX overflow.\n");
        return WOLFSSL_CBIO_ERR_GENERAL;
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
        printk("[WOLFSSL RX] delivering %u bytes to wolfSSL\n", read_bytes);
        return read_bytes;
    }

    if (!chan || !chan->conn || l2cap_peer_disconnected) {
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }

    /* Wait briefly. If nothing arrives, tell wolfSSL we want to read later. */
    if (k_sem_take(&rx_sem, K_MSEC(50)) == 0) {
        read_bytes = ring_buf_get(&rx_ringbuf, (uint8_t*)buf, sz);
        if (read_bytes > 0) {
            printk("[WOLFSSL RX] delivering %u bytes to wolfSSL\n", read_bytes);
            return read_bytes;
        }
        if (!chan->conn || l2cap_peer_disconnected) {
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }
    }

    return WOLFSSL_CBIO_ERR_WANT_READ;
}

static void shutdown_tls_gracefully(WOLFSSL *ssl, struct bt_l2cap_chan *chan)
{
    if (!ssl || !chan) {
        return;
    }

    for (int attempt = 1; attempt <= 10; attempt++) {
        int shutdown_ret = wolfSSL_shutdown(ssl);

        if (shutdown_ret == WOLFSSL_SUCCESS) {
            printk("TLS shutdown complete.\n");
            return;
        }

        if (shutdown_ret == WOLFSSL_SHUTDOWN_NOT_DONE) {
            if (l2cap_peer_disconnected && ring_buf_is_empty(&rx_ringbuf)) {
                printk("TLS shutdown complete: peer closed after close_notify.\n");
                return;
            }
            printk("TLS shutdown waiting for peer close_notify (%d/10).\n",
                   attempt);
            k_sleep(K_MSEC(100));
            continue;
        }

        int err = wolfSSL_get_error(ssl, shutdown_ret);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            if (l2cap_peer_disconnected && ring_buf_is_empty(&rx_ringbuf)) {
                printk("TLS shutdown complete: peer closed transport.\n");
                return;
            }
            printk("TLS shutdown waiting for transport (%d/10).\n", attempt);
            k_sleep(K_MSEC(100));
            continue;
        }

        printk("TLS shutdown stopped with wolfSSL error: %d\n", err);
        return;
    }

    printk("TLS shutdown close_notify sent; peer did not finish shutdown in time.\n");
}

void start_secure_mqtt_session(struct bt_l2cap_chan *chan) {
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;
    int ret;

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx) {
        wolfssl_heap_report("wolfSSL_CTX_new failed");
        return;
    }

    wolfSSL_Debugging_ON();

    /* Security: Ensure we are using modern PQC/ECC ciphers */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);

    int ca_ret = wolfSSL_CTX_load_verify_buffer(ctx, ca_der, ca_der_len,
                                                WOLFSSL_FILETYPE_ASN1);
    if (ca_ret != WOLFSSL_SUCCESS) {
        printk("Failed to load CA Certificate! Error: %d\n", ca_ret);
        wolfSSL_CTX_free(ctx);
        return;
    }

    int pqc_groups[] = { TARGET_PQC_GROUP, WOLFSSL_ECC_SECP256R1 };

    ret = wolfSSL_CTX_set_groups(ctx, pqc_groups, 2);

    if (ret != WOLFSSL_SUCCESS) {
        printk("Failed to set PQC Key Exchange group!\n");
    } else {
        printk("Configured wolfSSL TLS group id: %d\n", pqc_groups[0]);
    }

/* 1. Load the binary DER array */
    int cert_ret = wolfSSL_CTX_use_certificate_buffer(ctx, 
                                                      client_der, 
                                                      client_der_len, // Use the generated length variable
                                                      WOLFSSL_FILETYPE_ASN1); 
    if (cert_ret != WOLFSSL_SUCCESS) {
        printk("Failed to load Client Certificate! Error: %d\n", cert_ret);
    }

    /* 2. Load the binary DER Private Key */
    int key_ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, 
                                                    client_key_der, 
                                                    client_key_der_len, // Use the generated length variable
                                                    WOLFSSL_FILETYPE_ASN1); 
    if (key_ret != WOLFSSL_SUCCESS) {
        printk("Failed to load Client Private Key! Error: %d\n", key_ret);
    }
    wolfssl_heap_report("certificate and key loaded");

    wolfSSL_CTX_SetIOSend(ctx, l2cap_wolfssl_send);
    wolfSSL_CTX_SetIORecv(ctx, l2cap_wolfssl_recv);
    
    ssl = wolfSSL_new(ctx);
    if (!ssl) { 
        printk("FATAL: wolfSSL_new failed! (Out of Memory)\n");
        wolfSSL_CTX_free(ctx);
        return;
    }

    wolfSSL_SetIOReadCtx(ssl, chan);
    wolfSSL_SetIOWriteCtx(ssl, chan);

    int wait_counter = 0;
    disconnect_requested = false;
    printk("Starting TLS 1.3 Handshake...\n");
    int64_t start_time = k_uptime_get();
    do {
        ret = wolfSSL_connect(ssl);
        if (ret != WOLFSSL_SUCCESS) {
            int err = wolfSSL_get_error(ssl, ret);
            printk("wolfSSL error = %d\n", err);
            if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
                if (l2cap_peer_disconnected && ring_buf_is_empty(&rx_ringbuf)) {
                    printk("TLS Handshake Failed: peer closed connection\n");
                    wolfSSL_free(ssl);
                    wolfSSL_CTX_free(ctx);
                    return;
                }
                wait_counter++;
                if (wait_counter % 20 == 0) {
                    /* Prints once per second if trapped in the waiting loop */
                    printk("[WOLFSSL] Still waiting for network data...\n"); 
                }
                k_sleep(K_MSEC(50));
                continue; 
            }
            printk("TLS Handshake Failed: %d\n", err);
            wolfSSL_free(ssl);
            wolfSSL_CTX_free(ctx);
            return;
        }
    } while (ret != WOLFSSL_SUCCESS);
    int64_t end_time = k_uptime_get();
    printk(">>> TLS Handshake Successful! <<<\n");
    wolfssl_heap_report("handshake complete");
    printk("\n[BENCHMARK_RESULT] Handshake_Time_MS: %lld\n", (end_time - start_time));

#if BENCHMARK_CLOSE_AFTER_TLS
    printk("Benchmark complete. Closing TLS session gracefully.\n");
    shutdown_tls_gracefully(ssl, chan);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    return;
#endif

    /* Send initial MQTT CONNECT packet */
    /* MQTT CONNECT Packet with Auth Flags */
/* * Flags: 0xC2 
 * C2 = 1100 0010 (Bit 7: Username, Bit 6: Password, Bit 1: Clean Session)
 */
    unsigned char mqtt_connect_pkt[] = {
    0x10, 0x1A,                         // Fixed Header: Type 0x10, Remaining Len 0x1A (26 bytes)
    0x00, 0x04, 'M', 'Q', 'T', 'T',     // Protocol Name: "MQTT"
    0x04,                               // Protocol Level: 4
    0xC2,                               // Connect Flags: User + Pass + Clean Session
    0x00, 0x3C,                         // Keep Alive: 60s
    0x00, 0x00,                         // Client ID (length 0, empty)
    0x00, 0x05, 'u', 's', 'e', 'r', '1',// Username (Length 5: "user1")
    0x00, 0x05, 'p', 'a', 's', 's', '1' // Password (Length 5: "pass1")
    };

    wolfSSL_write(ssl, mqtt_connect_pkt, sizeof(mqtt_connect_pkt));

    /* Active Application Loop */
    unsigned char rx_buf[128];
    int64_t last_activity = k_uptime_get();

    while (chan->conn && !disconnect_requested) {
        /* 1. Non-blocking Read */
        int bytes_read = wolfSSL_read(ssl, rx_buf, sizeof(rx_buf));
        
        if (bytes_read > 0) {
            last_activity = k_uptime_get(); // Reset timer on any data
            
            /* 1. Catch CONNACK and send SUBSCRIBE */
            if (rx_buf[0] == 0x20) {
                printk("Broker accepted connection! Subscribing to topic...\n");
                
                unsigned char mqtt_subscribe_pkt[] = {
                    0x82, 0x11,                 // Header: Subscribe (0x82), Length 17
                    0x00, 0x01,                 // Packet Identifier: 1
                    0x00, 0x0C,                 // Topic Length: 12
                    'n', 'r', 'f', '5', '2', '8', '4', '0', '/', 'c', 'm', 'd', // Topic String
                    0x00                        // Requested QoS: 0
                };
                wolfSSL_write(ssl, mqtt_subscribe_pkt, sizeof(mqtt_subscribe_pkt));
            } 
            /* 2. Catch PUBLISH (Incoming Commands) */
            else if (rx_buf[0] == 0x30) {
                printk("Received command from broker!\n");
                
                // Parse the payload out of the packet
                if (bytes_read >= 4) {
                    uint16_t topic_len = (rx_buf[2] << 8) | rx_buf[3];
                    uint16_t payload_offset = 4 + topic_len;
                    if (payload_offset <= bytes_read) {
                        uint16_t payload_len = bytes_read - payload_offset;
                        handle_command(&rx_buf[payload_offset], payload_len);
                    }
                }
            } 
            /* 3. Catch PINGRESP */
            else if (rx_buf[0] == 0xD0) {
                printk("Ping acknowledged.\n");
            }
        }
        else if (bytes_read < 0) {
            int err = wolfSSL_get_error(ssl, bytes_read);
            if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE) {
                printk("Session closed error: %d\n", err);
                break;
            }
        }

        /* 2. Heartbeat Check */
        int64_t now = k_uptime_get();
        if ((now - last_activity) > HEARTBEAT_INTERVAL_MS) {
            printk("Sending PINGREQ to keep connection alive...\n");
            unsigned char ping_req[] = {0xC0, 0x00};
            if (wolfSSL_write(ssl, ping_req, sizeof(ping_req)) > 0) {
                last_activity = now;
            }
        }

        /* 3. Safety Timeout (Optional) */
        if ((now - last_activity) > TIMEOUT_THRESHOLD_MS) {
            printk("Connection timed out! No heartbeat from server.\n");
            break;
        }

        k_sleep(K_MSEC(100));
    }

    if (disconnect_requested) {
        printk("Disconnect command received by application loop.\n");
    }

    printk("Closing Secure Session.\n");
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
        printk("[BLE] Local identity %u: %s%s\n", (unsigned int)i, addr_str,
               i == BT_ID_DEFAULT ? " (advertising default)" : "");
    }
}

int main(void) {
#if HAS_STATUS_LED
    if (!gpio_is_ready_dt(&led)) {
        printk("Error: LED device %s is not ready\n", led.port->name);
        return 0;
    }
    
    /* Configure the pin as an output and initialize it to OFF (0) */
    int ret = gpio_pin_configure_dt(&led, GPIO_OUTPUT_INACTIVE);
    if (ret < 0) {
        printk("Error: Failed to configure LED pin: %d\n", ret);
        return 0;
    }
    printk("LED initialized successfully.\n");
#endif

    bt_conn_auth_cb_register(NULL);

    if (bt_enable(NULL)) {
        printk("Bluetooth init failed\n");
        return 0;
    }

    wolfSSL_SetAllocators(wolfssl_malloc, wolfssl_free, wolfssl_realloc);
    wolfSSL_Init();
    wolfssl_heap_report("initialized");

    settings_load();
    print_local_identities();

    int l2cap_err = bt_l2cap_server_register(&l2cap_server);
    if (l2cap_err) {
        printk("L2CAP server registration failed for PSM 0x%04x: %d\n",
               l2cap_server.psm, l2cap_err);
    } else {
        printk("L2CAP server registered with PSM: 0x%04x\n",
               l2cap_server.psm);
    }
    
    k_msleep(100);

    /* FIX 6: The Infinite Reconnection Loop */
    while (1) {
        ring_buf_reset(&rx_ringbuf);
        k_sem_reset(&rx_sem);
        k_sem_reset(&l2cap_connected_sem);
        l2cap_peer_disconnected = false;
        l2cap_rx_overflow = false;
        disconnect_requested = false;
        
        const struct bt_data *active_ad = l2cap_err ? ad_l2cap_error : ad_l2cap_ok;
        size_t active_ad_len = l2cap_err ? ARRAY_SIZE(ad_l2cap_error) : ARRAY_SIZE(ad_l2cap_ok);
        int err = bt_le_adv_start(&adv_param, active_ad, active_ad_len, NULL, 0);
        if (err && err != -EALREADY) {
            printk("Advertising failed to start (err %d)\n", err);
        } else {
            printk("Advertising started! Waiting for Mac gateway...\n");
        }

        /* Sleep until the dynamic L2CAP channel is fully connected. */
        k_sem_take(&l2cap_connected_sem, K_FOREVER);
        
        /* Stop advertising while connected to save power */
        bt_le_adv_stop();

        start_secure_mqtt_session(&l2cap_chan.chan);
        
        printk("Session ended. Re-arming for next connection...\n");
        
        /* 1. Only request disconnect if the peer hasn't already dropped us */
        if (l2cap_chan.chan.conn && !l2cap_peer_disconnected) {
            bt_conn_disconnect(l2cap_chan.chan.conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
        }

        /* 2. Wait for the Zephyr BT stack to fully process the teardown */
        while (!l2cap_peer_disconnected) {
            k_sleep(K_MSEC(100));
        }

        /* 3. Erase the ghost pointer so Zephyr frees the Bluetooth context */
        l2cap_chan.chan.conn = NULL;
        
        /* 4. Brief cooldown before firing up the radio again */
        k_sleep(K_SECONDS(2));
    }
    
    return 0;
}
