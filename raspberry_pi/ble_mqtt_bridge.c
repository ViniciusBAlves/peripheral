#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>

#ifndef SOL_BLUETOOTH
#define SOL_BLUETOOTH 274
#endif

#ifndef BT_MODE
#define BT_MODE 15
#endif

#ifndef BT_MODE_LE_FLOWCTL
#define BT_MODE_LE_FLOWCTL 0x03
#endif

#ifndef BT_SECURITY
#define BT_SECURITY 4
#endif

#ifndef BT_SECURITY_LOW
#define BT_SECURITY_LOW 1
#endif

#ifndef BT_SNDMTU
#define BT_SNDMTU 12
#endif

#ifndef BT_RCVMTU
#define BT_RCVMTU 13
#endif

#define DEFAULT_DEVICE_NAME "Zephyr"
#define DEFAULT_ADAPTER "hci0"
#define DEFAULT_TCP_HOST "127.0.0.1"
#define DEFAULT_TCP_PORT 8883
#define DEFAULT_PSM 0x0080
#define DEFAULT_MTU 2000
#define DEFAULT_SCAN_TIMEOUT_SEC 45
#define DEFAULT_CONNECT_TIMEOUT_MS 30000
#define DEFAULT_L2CAP_ATTEMPTS 6

static volatile sig_atomic_t keep_running = 1;

struct config {
    const char *adapter;
    const char *device_name;
    const char *device_addr;
    int device_addr_type; /* BDADDR_LE_PUBLIC or BDADDR_LE_RANDOM */
    uint16_t psm;
    const char *tcp_host;
    uint16_t tcp_port;
    size_t mtu;
    int scan_timeout_sec;
};

static void handle_signal(int sig)
{
    (void)sig;
    keep_running = 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [options]\n"
            "  --adapter hci0              Bluetooth adapter (default: hci0)\n"
            "  --name Zephyr               BLE advertised local name to scan for\n"
            "  --addr AA:BB:CC:DD:EE:FF    Skip scan and connect to this BLE address\n"
            "  --addr-type public|random    Address type when --addr is used\n"
            "  --psm 0x0080                 LE Credit-Based L2CAP PSM\n"
            "  --tcp-host 127.0.0.1         TCP target for Mosquitto\n"
            "  --tcp-port 8883              TCP target port\n"
            "  --mtu 2000                   Max chunk size written to BLE\n"
            "  --scan-timeout 45            Scan timeout in seconds\n",
            prog);
}

static int parse_u16(const char *text, uint16_t *out)
{
    char *end = NULL;
    unsigned long value = strtoul(text, &end, 0);

    if (!text[0] || (end && *end) || value > 0xffffUL) {
        return -1;
    }
    *out = (uint16_t)value;
    return 0;
}

static int parse_args(int argc, char **argv, struct config *cfg)
{
    cfg->adapter = DEFAULT_ADAPTER;
    cfg->device_name = DEFAULT_DEVICE_NAME;
    cfg->device_addr = NULL;
    cfg->device_addr_type = BDADDR_LE_RANDOM;
    cfg->psm = DEFAULT_PSM;
    cfg->tcp_host = DEFAULT_TCP_HOST;
    cfg->tcp_port = DEFAULT_TCP_PORT;
    cfg->mtu = DEFAULT_MTU;
    cfg->scan_timeout_sec = DEFAULT_SCAN_TIMEOUT_SEC;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--adapter") && i + 1 < argc) {
            cfg->adapter = argv[++i];
        } else if (!strcmp(argv[i], "--name") && i + 1 < argc) {
            cfg->device_name = argv[++i];
        } else if (!strcmp(argv[i], "--addr") && i + 1 < argc) {
            cfg->device_addr = argv[++i];
        } else if (!strcmp(argv[i], "--addr-type") && i + 1 < argc) {
            const char *type = argv[++i];
            if (!strcmp(type, "public")) {
                cfg->device_addr_type = BDADDR_LE_PUBLIC;
            } else if (!strcmp(type, "random")) {
                cfg->device_addr_type = BDADDR_LE_RANDOM;
            } else {
                fprintf(stderr, "Invalid --addr-type: %s\n", type);
                return -1;
            }
        } else if (!strcmp(argv[i], "--psm") && i + 1 < argc) {
            if (parse_u16(argv[++i], &cfg->psm) != 0) {
                fprintf(stderr, "Invalid --psm\n");
                return -1;
            }
        } else if (!strcmp(argv[i], "--tcp-host") && i + 1 < argc) {
            cfg->tcp_host = argv[++i];
        } else if (!strcmp(argv[i], "--tcp-port") && i + 1 < argc) {
            if (parse_u16(argv[++i], &cfg->tcp_port) != 0) {
                fprintf(stderr, "Invalid --tcp-port\n");
                return -1;
            }
        } else if (!strcmp(argv[i], "--mtu") && i + 1 < argc) {
            cfg->mtu = (size_t)strtoul(argv[++i], NULL, 0);
            if (cfg->mtu == 0 || cfg->mtu > 65535) {
                fprintf(stderr, "Invalid --mtu\n");
                return -1;
            }
        } else if (!strcmp(argv[i], "--scan-timeout") && i + 1 < argc) {
            cfg->scan_timeout_sec = atoi(argv[++i]);
            if (cfg->scan_timeout_sec <= 0) {
                fprintf(stderr, "Invalid --scan-timeout\n");
                return -1;
            }
        } else if (!strcmp(argv[i], "--help")) {
            usage(argv[0]);
            exit(0);
        } else {
            fprintf(stderr, "Unknown or incomplete argument: %s\n", argv[i]);
            return -1;
        }
    }

    return 0;
}

static int wait_socket_connected(int fd, const char *label, int timeout_ms)
{
    struct pollfd pfd = {
        .fd = fd,
        .events = POLLOUT,
    };

    printf("[%s] connect() is in progress; waiting up to %d ms...\n",
           label, timeout_ms);
    fflush(stdout);

    while (keep_running) {
        int ret = poll(&pfd, 1, timeout_ms);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("poll(connect)");
            return -1;
        }
        if (ret == 0) {
            fprintf(stderr, "[%s] connect timed out\n", label);
            return -1;
        }

        int so_error = 0;
        socklen_t so_error_len = sizeof(so_error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR,
                       &so_error, &so_error_len) < 0) {
            perror("getsockopt(SO_ERROR)");
            return -1;
        }

        if (so_error == 0) {
            return 0;
        }
        if (so_error == EINPROGRESS || so_error == EALREADY) {
            continue;
        }

        errno = so_error;
        perror(label);
        return -1;
    }

    return -1;
}

static bool adv_has_name(const uint8_t *data, uint8_t len, const char *target_name)
{
    uint8_t i = 0;

    while (i + 1 < len) {
        uint8_t field_len = data[i];
        if (field_len == 0) {
            break;
        }
        if (i + field_len >= len + 1) {
            break;
        }

        uint8_t type = data[i + 1];
        uint8_t value_len = field_len - 1;
        const uint8_t *value = &data[i + 2];

        if ((type == 0x08 || type == 0x09) &&
            strlen(target_name) == value_len &&
            memcmp(value, target_name, value_len) == 0) {
            return true;
        }

        i += field_len + 1;
    }

    return false;
}

static int discover_device(const struct config *cfg, char *addr_out,
                           size_t addr_out_len, int *addr_type_out)
{
    if (addr_out_len < 18) {
        fprintf(stderr, "Address output buffer is too small\n");
        return -1;
    }

    int dev_id = hci_devid(cfg->adapter);
    if (dev_id < 0) {
        perror("hci_devid");
        return -1;
    }

    int dd = hci_open_dev(dev_id);
    if (dd < 0) {
        perror("hci_open_dev");
        return -1;
    }

    struct hci_filter old_filter;
    socklen_t old_filter_len = sizeof(old_filter);
    if (getsockopt(dd, SOL_HCI, HCI_FILTER, &old_filter, &old_filter_len) < 0) {
        memset(&old_filter, 0, sizeof(old_filter));
    }

    if (hci_le_set_scan_parameters(dd, 0x01, htobs(0x0010), htobs(0x0010),
                                   0x00, 0x00, 1000) < 0) {
        perror("hci_le_set_scan_parameters");
        close(dd);
        return -1;
    }

    struct hci_filter new_filter;
    hci_filter_clear(&new_filter);
    hci_filter_set_ptype(HCI_EVENT_PKT, &new_filter);
    hci_filter_set_event(EVT_LE_META_EVENT, &new_filter);

    if (setsockopt(dd, SOL_HCI, HCI_FILTER, &new_filter,
                   sizeof(new_filter)) < 0) {
        perror("setsockopt(HCI_FILTER)");
        close(dd);
        return -1;
    }

    if (hci_le_set_scan_enable(dd, 0x01, 0x00, 1000) < 0) {
        perror("hci_le_set_scan_enable");
        (void)setsockopt(dd, SOL_HCI, HCI_FILTER, &old_filter,
                         old_filter_len);
        close(dd);
        return -1;
    }

    printf("[BLE] Scanning on %s for local name '%s'...\n",
           cfg->adapter, cfg->device_name);
    fflush(stdout);

    time_t deadline = time(NULL) + cfg->scan_timeout_sec;
    uint8_t buf[HCI_MAX_EVENT_SIZE];
    int ret = -1;

    while (keep_running && time(NULL) < deadline) {
        struct pollfd pfd = {.fd = dd, .events = POLLIN};
        int poll_ret = poll(&pfd, 1, 1000);
        if (poll_ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("poll(HCI)");
            break;
        }
        if (poll_ret == 0) {
            continue;
        }

        ssize_t len = read(dd, buf, sizeof(buf));
        if (len <= 0) {
            continue;
        }

        evt_le_meta_event *meta =
            (evt_le_meta_event *)(buf + (1 + HCI_EVENT_HDR_SIZE));
        if (meta->subevent != EVT_LE_ADVERTISING_REPORT) {
            continue;
        }

        uint8_t reports = meta->data[0];
        uint8_t offset = 1;

        for (uint8_t i = 0; i < reports; i++) {
            le_advertising_info *info =
                (le_advertising_info *)(meta->data + offset);

            if (adv_has_name(info->data, info->length, cfg->device_name)) {
                ba2str(&info->bdaddr, addr_out);
                *addr_type_out = (info->bdaddr_type == LE_RANDOM_ADDRESS) ?
                    BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC;
                printf("[BLE] Found %s at %s (%s)\n",
                       cfg->device_name, addr_out,
                       *addr_type_out == BDADDR_LE_RANDOM ? "random" : "public");
                ret = 0;
                goto done;
            }

            offset += sizeof(le_advertising_info) + info->length + 1;
            if (offset >= (uint8_t)len) {
                break;
            }
        }
    }

    fprintf(stderr, "[BLE] Timed out scanning for '%s'\n", cfg->device_name);

done:
    (void)hci_le_set_scan_enable(dd, 0x00, 0x00, 1000);
    (void)setsockopt(dd, SOL_HCI, HCI_FILTER, &old_filter, old_filter_len);
    close(dd);
    return ret;
}

static int connect_l2cap(const char *addr, int addr_type, uint16_t psm)
{
    int fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    if (fd < 0) {
        perror("socket(L2CAP)");
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("fcntl(L2CAP O_NONBLOCK)");
        close(fd);
        return -1;
    }

    int mtu = DEFAULT_MTU;
    if (setsockopt(fd, SOL_BLUETOOTH, BT_SNDMTU, &mtu, sizeof(mtu)) < 0 &&
        errno != ENOPROTOOPT && errno != EINVAL) {
        perror("setsockopt(L2CAP BT_SNDMTU)");
    }

    if (setsockopt(fd, SOL_BLUETOOTH, BT_RCVMTU, &mtu, sizeof(mtu)) < 0 &&
        errno != ENOPROTOOPT && errno != EINVAL) {
        perror("setsockopt(L2CAP BT_RCVMTU)");
    }

    int security = BT_SECURITY_LOW;
    if (setsockopt(fd, SOL_BLUETOOTH, BT_SECURITY,
                   &security, sizeof(security)) < 0) {
        perror("setsockopt(L2CAP BT_SECURITY_LOW)");
    }

    /* THE FIX: No bind(), no BT_MODE. Just tell BlueZ the target is LE! */
    struct sockaddr_l2 remote = {0};
    remote.l2_family = AF_BLUETOOTH;
    remote.l2_psm = htobs(psm);
    remote.l2_bdaddr_type = addr_type; /* This tells BlueZ to use LE CoC automatically */
    str2ba(addr, &remote.l2_bdaddr);

    printf("[BLE] Opening LE L2CAP PSM 0x%04x to %s (%s)...\n",
           psm, addr, addr_type == BDADDR_LE_RANDOM ? "random" : "public");
    fflush(stdout);

    if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
        if (errno != EINPROGRESS && errno != EALREADY) {
            perror("connect(L2CAP)");
            close(fd);
            return -1;
        }
        if (wait_socket_connected(fd, "L2CAP", DEFAULT_CONNECT_TIMEOUT_MS) != 0) {
            close(fd);
            return -1;
        }
    }

    if (flags >= 0 && fcntl(fd, F_SETFL, flags) < 0) {
        perror("fcntl(L2CAP restore blocking)");
    }

    printf("[BLE] L2CAP channel established.\n");
    return fd;
}

static int connect_tcp(const char *host, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket(TCP)");
        return -1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "Only IPv4 TCP targets are currently supported: %s\n",
                host);
        close(fd);
        return -1;
    }

    printf("[TCP] Connecting to Mosquitto at %s:%u...\n", host, port);
    fflush(stdout);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (errno != EINPROGRESS && errno != EALREADY) {
            perror("connect(TCP)");
            close(fd);
            return -1;
        }
        if (wait_socket_connected(fd, "TCP", DEFAULT_CONNECT_TIMEOUT_MS) != 0) {
            close(fd);
            return -1;
        }
    }

    printf("[TCP] Connected to Mosquitto.\n");
    return fd;
}

static int send_all(int fd, const uint8_t *buf, size_t len)
{
    size_t written = 0;

    while (written < len && keep_running) {
        ssize_t ret = send(fd, buf + written, len - written, 0);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("send");
            return -1;
        }
        if (ret == 0) {
            return -1;
        }
        written += (size_t)ret;
    }

    return 0;
}

static int relay_loop(int ble_fd, int tcp_fd, size_t mtu)
{
    uint8_t *buf = malloc(mtu);
    if (!buf) {
        perror("malloc");
        return -1;
    }

    printf("[Bridge] Relaying BLE L2CAP <-> TCP. Chunk size=%zu\n", mtu);
    fflush(stdout);

    while (keep_running) {
        struct pollfd fds[2] = {
            {.fd = ble_fd, .events = POLLIN},
            {.fd = tcp_fd, .events = POLLIN},
        };

        int ret = poll(fds, 2, 1000);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("poll(relay)");
            break;
        }
        if (ret == 0) {
            continue;
        }

        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t len = recv(ble_fd, buf, mtu, 0);
            if (len <= 0) {
                printf("[Bridge] BLE side closed.\n");
                break;
            }
            printf("[Bridge] BLE -> TCP %zd bytes\n", len);
            if (send_all(tcp_fd, buf, (size_t)len) != 0) {
                break;
            }
        }

        if (fds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t len = recv(tcp_fd, buf, mtu, 0);
            if (len <= 0) {
                printf("[Bridge] TCP side closed.\n");
                break;
            }
            printf("[Bridge] TCP -> BLE %zd bytes\n", len);
            if (send_all(ble_fd, buf, (size_t)len) != 0) {
                break;
            }
        }
    }

    free(buf);
    return keep_running ? -1 : 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    struct config cfg;
    if (parse_args(argc, argv, &cfg) != 0) {
        usage(argv[0]);
        return 2;
    }

    char discovered_addr[18] = {0};
    int discovered_addr_type = cfg.device_addr_type;
    const char *addr = cfg.device_addr;
    int ble_fd = -1;

    for (int attempt = 1; keep_running && attempt <= DEFAULT_L2CAP_ATTEMPTS;
         attempt++) {
        if (!cfg.device_addr) {
            discovered_addr[0] = '\0';
            if (discover_device(&cfg, discovered_addr, sizeof(discovered_addr),
                                &discovered_addr_type) != 0) {
                return 1;
            }
            addr = discovered_addr;
            // TODO
            printf("[BLE] Scan stopped. Allowing radio scheduler to reset...\n");
            sleep(1);
        }

        printf("[BLE] L2CAP attempt %d/%d using %s (%s)\n",
               attempt, DEFAULT_L2CAP_ATTEMPTS, addr,
               discovered_addr_type == BDADDR_LE_RANDOM ? "random" : "public");

        ble_fd = connect_l2cap(addr, discovered_addr_type, cfg.psm);
        if (ble_fd >= 0) {
            break;
        }

        if (attempt < DEFAULT_L2CAP_ATTEMPTS) {
            printf("[BLE] L2CAP open failed; waiting and trying again...\n");
            sleep(1);
        }
    }

    if (ble_fd < 0) {
        fprintf(stderr, "[BLE] Could not establish L2CAP after %d attempts\n",
                DEFAULT_L2CAP_ATTEMPTS);
        return 1;
    }

    int tcp_fd = connect_tcp(cfg.tcp_host, cfg.tcp_port);
    if (tcp_fd < 0) {
        close(ble_fd);
        return 1;
    }

    int ret = relay_loop(ble_fd, tcp_fd, cfg.mtu);

    close(ble_fd);
    close(tcp_fd);
    printf("[Bridge] Exiting.\n");
    return ret == 0 ? 0 : 1;
}
