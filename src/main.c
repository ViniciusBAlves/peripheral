#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/l2cap.h>
#include <zephyr/sys/ring_buffer.h>
#include <zephyr/settings/settings.h>
#include <zephyr/bluetooth/conn.h>
#include <time.h>
#include <wolfssl/ssl.h>
#include <zephyr/drivers/gpio.h>
#include "client_cert.h"
#include "client_key.h"

/* 1. Create a 4KB ring buffer and a Sleep Semaphore */
/* Change this from 4096 to 16384 */
RING_BUF_DECLARE(my_rx_ringbuf, 16384);
K_SEM_DEFINE(rx_sem, 0, 1);
K_SEM_DEFINE(l2cap_connected_sem, 0, 1);

/* --- WOLFSSL TIME HOOKS --- */
/* --- WOLFSSL TIME HOOKS --- */
time_t my_time_sec(time_t *timer) {
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

int my_time_ms(int *timer) {
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

#ifndef TARGET_PQC_GROUP
    #define TARGET_PQC_GROUP WOLFSSL_P384_MLKEM_768 // Default fallback
#endif

#define HEARTBEAT_INTERVAL_MS 30000 // 30 Seconds
#define TIMEOUT_THRESHOLD_MS  45000 // 45 Seconds

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
/* FIX 1: We need both TX and RX pools for large TLS records */
NET_BUF_POOL_DEFINE(my_l2cap_tx_pool, 10, BT_L2CAP_BUF_SIZE(2000), 8, NULL);
NET_BUF_POOL_DEFINE(my_l2cap_rx_pool, 10, BT_L2CAP_BUF_SIZE(2000), 8, NULL);

static struct bt_l2cap_le_chan my_chan;

/* FIX 2: Provide an allocation callback so Zephyr doesn't drop incoming data */
static struct net_buf *my_l2cap_alloc_buf(struct bt_l2cap_chan *chan) {
    return net_buf_alloc(&my_l2cap_rx_pool, K_NO_WAIT);
}

static int my_l2cap_recv(struct bt_l2cap_chan *chan, struct net_buf *buf) {
    printk("[L2CAP RX] Hardware received %d bytes from Mac!\n", buf->len);
    
    uint32_t written = ring_buf_put(&my_rx_ringbuf, buf->data, buf->len);
    if (written < buf->len) {
        printk(">>> WARNING: RX ring buffer overflowed! Lost %d bytes <<<\n", buf->len - written);
    }
    
    k_sem_give(&rx_sem);
    return 0; /* Return 0 to indicate we consumed the data */
}

static void my_l2cap_disconnected(struct bt_l2cap_chan *chan) {
    printk("[L2CAP] Disconnected.\n");
    k_sem_give(&rx_sem); /* Wake up any waiting read operations to fail gracefully */
}

static struct bt_l2cap_chan_ops my_l2cap_ops = {
    .alloc_buf = my_l2cap_alloc_buf,
    .recv = my_l2cap_recv,
    .disconnected = my_l2cap_disconnected,
};

static const struct bt_data ad[] = {
    BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
    BT_DATA_BYTES(BT_DATA_NAME_COMPLETE, 'n','R','F','-','P','Q','C')
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
	}
    else if (strcmp(msg, "disconnect") == 0) {
        printk(">>> Graceful disconnect command received. Closing L2CAP...\n");
        bt_l2cap_chan_disconnect(&my_chan.chan);

        if (my_chan.chan.conn) {
            bt_conn_disconnect(my_chan.chan.conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
        }
    }
}

static int my_l2cap_accept(struct bt_conn *conn, struct bt_l2cap_server *server, struct bt_l2cap_chan **chan);

static struct bt_l2cap_server my_l2cap_server = {
    .psm = 0x0080,
    .sec_level = BT_SECURITY_L1,
    .accept = my_l2cap_accept,
};

static int my_l2cap_accept(struct bt_conn *conn, struct bt_l2cap_server *server, struct bt_l2cap_chan **chan) {
    char addr[BT_ADDR_LE_STR_LEN];
    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
    printk("[L2CAP] Connection request received from: %s\n", addr);
    
    my_chan.chan.ops = &my_l2cap_ops;
    
    /* Change the RX MTU from 2048 to match the TX limit of 2000 */
    my_chan.rx.mtu = 2000; 
    
    *chan = &my_chan.chan;
    printk("[L2CAP] Connection accepted and channel assigned.\n");
    
    k_sem_give(&l2cap_connected_sem); 
    return 0;
}

int my_l2cap_wolfssl_send(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
    struct bt_l2cap_chan *chan = (struct bt_l2cap_chan *)ctx;
    struct bt_l2cap_le_chan *le_chan = CONTAINER_OF(chan, struct bt_l2cap_le_chan, chan);
    int sent = 0;

    if (!chan || !chan->conn) { return WOLFSSL_CBIO_ERR_CONN_CLOSE; }

    uint16_t mtu = le_chan->tx.mtu;
    if (mtu == 0) mtu = 23; 

    printk("[WOLFSSL TX] Attempting to send TLS payload of %d bytes...\n", sz);

    while (sent < sz) {
        int chunk = sz - sent;
        if (chunk > mtu) { chunk = mtu; }

        int err = 0;
        do {
            /* 1. Abort if connection dropped during retry */
            if (!chan || !chan->conn) {
                return sent > 0 ? sent : WOLFSSL_CBIO_ERR_CONN_CLOSE;
            }

            /* 2. ALLOCATE FRESH EVERY TIME. 
               If it fails, wait 10ms for pool to drain and continue loop. */
            struct net_buf *tx_buf = net_buf_alloc(&my_l2cap_tx_pool, K_MSEC(10));
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
                printk("[TX WARNING] BLE Queue Full. Waiting to retry...\n");
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
int my_l2cap_wolfssl_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
    struct bt_l2cap_chan *chan = (struct bt_l2cap_chan *)ctx;
    
    if (!chan || !chan->conn) { return WOLFSSL_CBIO_ERR_CONN_CLOSE; }

    uint32_t read_bytes = ring_buf_get(&my_rx_ringbuf, (uint8_t*)buf, sz);
    if (read_bytes > 0) {
        return read_bytes;
    }

    /* Wait briefly. If nothing arrives, tell wolfSSL we want to read later. */
    if (k_sem_take(&rx_sem, K_MSEC(50)) == 0) {
        read_bytes = ring_buf_get(&my_rx_ringbuf, (uint8_t*)buf, sz);
        if (read_bytes > 0) return read_bytes;
    }

    return WOLFSSL_CBIO_ERR_WANT_READ;
}

void start_secure_mqtt_session(struct bt_l2cap_chan *chan) {
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;
    int ret;

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx) return;

    //wolfSSL_Debugging_ON();

    /* Security: Ensure we are using modern PQC/ECC ciphers */
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);

    int pqc_groups[] = { TARGET_PQC_GROUP, WOLFSSL_ECC_SECP256R1 };

    ret = wolfSSL_CTX_set_groups(ctx, pqc_groups, 2);

    if (ret != WOLFSSL_SUCCESS) {
        printk("Failed to set PQC Key Exchange group!\n");
    }

    /* 1. Load the PEM string directly. Use sizeof() to get exact string length */
    int cert_ret = wolfSSL_CTX_use_certificate_buffer(ctx, 
                                                      (const unsigned char*)client_pem, 
                                                      sizeof(client_pem), 
                                                      WOLFSSL_FILETYPE_PEM);
    if (cert_ret != WOLFSSL_SUCCESS) {
        printk("Failed to load Client Certificate! Error: %d\n", cert_ret);
    }

    /* 2. Load the PEM Private Key */
    int key_ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, 
                                                    (const unsigned char*)client_key_pem, 
                                                    sizeof(client_key_pem), 
                                                    WOLFSSL_FILETYPE_PEM);
    if (key_ret != WOLFSSL_SUCCESS) {
        printk("Failed to load Client Private Key! Error: %d\n", key_ret);
    }

    wolfSSL_CTX_SetIOSend(ctx, my_l2cap_wolfssl_send);
    wolfSSL_CTX_SetIORecv(ctx, my_l2cap_wolfssl_recv);
    
    ssl = wolfSSL_new(ctx);
    if (!ssl) { wolfSSL_CTX_free(ctx); return; }

    wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, "localhost", 9);

    wolfSSL_SetIOReadCtx(ssl, chan);
    wolfSSL_SetIOWriteCtx(ssl, chan);

    printk("Starting TLS 1.3 Handshake...\n");
    do {
        ret = wolfSSL_connect(ssl);
        if (ret != WOLFSSL_SUCCESS) {
            int err = wolfSSL_get_error(ssl, ret);
            /* If waiting on the radio, sleep and retry */
            if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
                k_sleep(K_MSEC(50));
                continue; 
            }
            printk("TLS Handshake Failed: %d\n", err);
            wolfSSL_free(ssl);
            wolfSSL_CTX_free(ctx);
            return;
        }
    } while (ret != WOLFSSL_SUCCESS);
    printk(">>> TLS Handshake Successful! <<<\n");

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

    while (chan->conn) {
        /* 1. Non-blocking Read */
        int bytes_read = wolfSSL_read(ssl, rx_buf, sizeof(rx_buf));
        
        if (bytes_read > 0) {
            last_activity = k_uptime_get(); // Reset timer on any data
            
            printk("[MQTT RX] Decrypted %d bytes: [0x%02X 0x%02X 0x%02X 0x%02X]\n", 
                   bytes_read, rx_buf[0], rx_buf[1], rx_buf[2], rx_buf[3]);
            
            /* 1. Catch CONNACK (0x20) and send SUBSCRIBE */
            if (rx_buf[0] == 0x20) {
                printk(">>> Broker accepted connection! Subscribing to topic...\n");
                
                unsigned char mqtt_subscribe_pkt[] = {
                    0x82, 0x10,                 // Header: Subscribe (0x82), Length 16
                    0x00, 0x01,                 // Packet Identifier: 1
                    0x00, 0x0B,                 // Topic Length: 11
                    'n', 'r', 'f', '5', '3', '4', '0', '/', 'c', 'm', 'd', // Topic String
                    0x00                        // Requested QoS: 0
                };
                wolfSSL_write(ssl, mqtt_subscribe_pkt, sizeof(mqtt_subscribe_pkt));
            } 
            /* 2. Catch PUBLISH (Incoming Commands) */
            else if ((rx_buf[0] & 0xF0) == 0x30) {
                printk(">>> Received command from broker!\n");
                
                // Parse the payload out of the packet
                uint16_t topic_len = (rx_buf[2] << 8) | rx_buf[3];
                uint16_t payload_offset = 4 + topic_len;
                uint16_t payload_len = bytes_read - payload_offset;
                
                handle_command(&rx_buf[payload_offset], payload_len);
            } 
            /* 3. Catch PINGRESP */
            else if (rx_buf[0] == 0xD0) {
                printk(">>> Ping acknowledged by broker.\n");
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

        /* Yield the CPU to allow the BT stack to process incoming L2CAP frames */
        k_sleep(K_MSEC(50));
    }

    printk("Closing Secure Session.\n");
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
}

static const struct bt_le_adv_param adv_param = {
    .options = 0x0001 | 0x0002, /* CONNECTABLE | USE_NAME */
    .interval_min = 0x0100,
    .interval_max = 0x0150,
};

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

    wolfSSL_Init();

    settings_load();

    bt_addr_le_t addr;
    bt_addr_le_from_str("F8:69:5E:1E:CE:2F", "random", &addr);
    bt_id_create(&addr, NULL);

    bt_l2cap_server_register(&my_l2cap_server);
    printk("Registering L2CAP server with PSM: 0x%04x\n", my_l2cap_server.psm);    
    
    k_msleep(100);

    /* FIX 6: The Infinite Reconnection Loop */
    while (1) {
        ring_buf_reset(&my_rx_ringbuf);
        k_sem_reset(&rx_sem);
        
        int err = bt_le_adv_start(&adv_param, ad, ARRAY_SIZE(ad), NULL, 0);
        if (err && err != -EALREADY) {
            printk("Advertising failed to start (err %d)\n", err);
        } else {
            printk("Advertising started! Waiting for Mac gateway...\n");
        }

        /* Sleep until connection */
        k_sem_take(&l2cap_connected_sem, K_FOREVER);
        
        /* Stop advertising while connected to save power */
        bt_le_adv_stop();

        start_secure_mqtt_session(&my_chan.chan);
        
        printk("Session ended. Re-arming for next connection...\n");
        if (my_chan.chan.conn) {
            bt_conn_disconnect(my_chan.chan.conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
        }
        k_sleep(K_SECONDS(2));
    }
    
    return 0;
}