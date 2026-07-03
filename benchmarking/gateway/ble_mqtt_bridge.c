#include <arpa/inet.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

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

#define DEFAULT_DEVICE_NAME "PQC52840"
#define DEFAULT_ADAPTER "hci0"
#define DEFAULT_TCP_HOST "127.0.0.1"
#define DEFAULT_TCP_PORT 8883
#define DEFAULT_PSM 0x0080
#define DEFAULT_MTU 672
#define DEFAULT_SCAN_TIMEOUT_SEC 5
#define DEFAULT_CONNECT_TIMEOUT_MS 2000
#define DEFAULT_L2CAP_ATTEMPTS 10
#define DEFAULT_ACL_ATTEMPTS 1
#define DEFAULT_DISCOVERY_ATTEMPTS 3
#define COMMAND_OUTPUT_MAX 8192
#define BRIDGE_RECV_BUFFER_SIZE 65535

static volatile sig_atomic_t keep_running = 1;

static double monotonic_ms(void)
{
    struct timespec value;
    clock_gettime(CLOCK_MONOTONIC, &value);
    return (double)value.tv_sec * 1000.0 + (double)value.tv_nsec / 1000000.0;
}

struct config {
    const char *adapter;
    const char *device_name;
    const char *device_addr;
    int device_addr_type;
    uint16_t psm;
    const char *tcp_host;
    uint16_t tcp_port;
    size_t mtu;
    int scan_timeout_sec;
    bool forget_cache;
    bool no_acl_prime;
    bool reset_adapter;
    bool disable_wifi;
    bool wifi_disabled;
};

struct command_result {
    int exit_code;
    char output[COMMAND_OUTPUT_MAX];
};

struct sdu_prefix_state {
    bool first_packet;
    bool framing_decided;
    bool strip_prefix;
    uint8_t *pending;
    size_t pending_len;
    size_t pending_cap;
    size_t expected_sdu_len;
};

static int send_stream(int fd, const uint8_t *data, size_t length);

static void handle_signal(int sig)
{
    (void)sig;
    keep_running = 0;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s [options]\n"
            "  --adapter hci0              Bluetooth adapter\n"
            "  --name PQC52840             BLE advertised name\n"
            "  --addr AA:BB:CC:DD:EE:FF    Skip name discovery\n"
            "  --addr-type public|random    BLE address type\n"
            "  --psm 0x0080                 LE Credit-Based L2CAP PSM\n"
            "  --tcp-host 127.0.0.1         TCP target for Mosquitto\n"
            "  --tcp-port 8883              TCP target port\n"
            "  --mtu 672                    BLE write chunk size\n"
            "  --scan-timeout 5             BlueZ scan duration\n"
            "  --forget-cache               Remove cached BlueZ device first\n"
            "  --no-acl-prime               Skip bluetoothctl connect before L2CAP\n"
            "  --reset-adapter              Power-cycle the adapter before scanning\n"
            "  --disable-wifi               Disable Pi Wi-Fi while BLE bridge runs\n",
            program);
}

static int parse_u16(const char *text, uint16_t *out)
{
    char *end = NULL;
    unsigned long value = strtoul(text, &end, 0);
    if (!text[0] || (end && *end) || value > UINT16_MAX) {
        return -1;
    }
    *out = (uint16_t)value;
    return 0;
}

static int parse_args(int argc, char **argv, struct config *cfg)
{
    *cfg = (struct config){
        .adapter = DEFAULT_ADAPTER,
        .device_name = DEFAULT_DEVICE_NAME,
        .device_addr = NULL,
        .device_addr_type = BDADDR_LE_RANDOM,
        .psm = DEFAULT_PSM,
        .tcp_host = DEFAULT_TCP_HOST,
        .tcp_port = DEFAULT_TCP_PORT,
        .mtu = DEFAULT_MTU,
        .scan_timeout_sec = DEFAULT_SCAN_TIMEOUT_SEC,
        .forget_cache = false,
        .no_acl_prime = false,
        .reset_adapter = false,
        .disable_wifi = false,
        .wifi_disabled = false,
    };

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
                return -1;
            }
        } else if (!strcmp(argv[i], "--psm") && i + 1 < argc) {
            if (parse_u16(argv[++i], &cfg->psm) != 0) {
                return -1;
            }
        } else if (!strcmp(argv[i], "--tcp-host") && i + 1 < argc) {
            cfg->tcp_host = argv[++i];
        } else if (!strcmp(argv[i], "--tcp-port") && i + 1 < argc) {
            if (parse_u16(argv[++i], &cfg->tcp_port) != 0) {
                return -1;
            }
        } else if (!strcmp(argv[i], "--mtu") && i + 1 < argc) {
            cfg->mtu = strtoul(argv[++i], NULL, 0);
            if (cfg->mtu == 0 || cfg->mtu > UINT16_MAX) {
                return -1;
            }
        } else if (!strcmp(argv[i], "--scan-timeout") && i + 1 < argc) {
            cfg->scan_timeout_sec = atoi(argv[++i]);
            if (cfg->scan_timeout_sec <= 0) {
                return -1;
            }
        } else if (!strcmp(argv[i], "--forget-cache")) {
            cfg->forget_cache = true;
        } else if (!strcmp(argv[i], "--no-acl-prime")) {
            cfg->no_acl_prime = true;
        } else if (!strcmp(argv[i], "--reset-adapter")) {
            cfg->reset_adapter = true;
        } else if (!strcmp(argv[i], "--disable-wifi")) {
            cfg->disable_wifi = true;
        } else if (!strcmp(argv[i], "--help")) {
            usage(argv[0]);
            exit(0);
        } else {
            return -1;
        }
    }

    return 0;
}

static int command_status(const char *command)
{
    int status = system(command);
    if (status >= 0 && WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return -1;
}

static struct command_result command_capture(const char *command)
{
    struct command_result result = {.exit_code = -1, .output = {0}};
    FILE *pipe = popen(command, "r");
    if (!pipe) {
        return result;
    }

    size_t used = 0;
    while (used + 1 < sizeof(result.output)) {
        size_t n = fread(result.output + used, 1,
                         sizeof(result.output) - used - 1, pipe);
        used += n;
        if (n == 0) {
            break;
        }
    }
    result.output[used] = '\0';

    int status = pclose(pipe);
    if (status >= 0 && WIFEXITED(status)) {
        result.exit_code = WEXITSTATUS(status);
    }
    return result;
}

static void set_wifi_enabled(bool enabled)
{
    if (enabled) {
        printf("[*] Restoring Raspberry Pi Wi-Fi.\n");
        (void)command_status("sudo -n nmcli radio wifi on >/dev/null 2>&1 || "
                             "sudo -n ip link set wlan0 up >/dev/null 2>&1 || true");
    } else {
        printf("[*] Disabling Raspberry Pi Wi-Fi during BLE benchmark.\n");
        (void)command_status("sudo -n nmcli radio wifi off >/dev/null 2>&1 || "
                             "sudo -n ip link set wlan0 down >/dev/null 2>&1 || true");
    }
}

static void recycle_adapter(bool full_reset)
{
    if (full_reset) {
        printf("[*] Bluetooth adapter reset before retrying.\n");
        (void)command_status("timeout -k 1 5 sudo -n btmgmt power off "
                             ">/dev/null 2>&1 || true");
        sleep(1);
        (void)command_status("timeout -k 1 5 sudo -n btmgmt bredr off "
                             ">/dev/null 2>&1 || true");
        (void)command_status("timeout -k 1 5 sudo -n btmgmt bondable off "
                             ">/dev/null 2>&1 || true");
        (void)command_status("timeout -k 1 5 sudo -n btmgmt sc off "
                             ">/dev/null 2>&1 || true");
        (void)command_status("timeout -k 1 5 sudo -n btmgmt privacy off "
                             ">/dev/null 2>&1 || true");
        (void)command_status("timeout -k 1 5 sudo -n btmgmt power on "
                             ">/dev/null 2>&1 || true");
    } else {
        (void)command_status("timeout -k 1 5 bluetoothctl power on "
                             ">/dev/null 2>&1 || true");
    }
}

static void scan_adapter(int seconds)
{
    if (seconds <= 0) {
        return;
    }
    char command[256];
    snprintf(command, sizeof(command),
             "timeout -k 1 %d bluetoothctl --timeout %d scan on "
             ">/dev/null 2>&1; "
             "timeout -k 1 3 bluetoothctl scan off >/dev/null 2>&1 || true",
             seconds + 2, seconds);
    printf("[*] Scanning for %ds before L2CAP connect\n", seconds);
    (void)command_status(command);
}

static int find_cached_device(const char *device_name, char address[18])
{
    FILE *devices = popen("bluetoothctl devices 2>/dev/null", "r");
    if (!devices) {
        fprintf(stderr, "[-] Bluetooth device list failed: %s\n",
                strerror(errno));
        return -1;
    }

    char line[512];
    int ret = -1;
    while (fgets(line, sizeof(line), devices)) {
        char found_address[18];
        char found_name[256];
        if (sscanf(line, "Device %17s %255[^\n]",
                   found_address, found_name) == 2 &&
            strcmp(found_name, device_name) == 0) {
            memcpy(address, found_address, 18);
            ret = 0;
            break;
        }
    }
    (void)pclose(devices);
    return ret;
}

static int discover_device(const struct config *cfg, char address[18])
{
    printf("[*] Raspberry Pi Bluetooth active. Discovering %s...\n",
           cfg->device_name);
    for (int attempt = 1; attempt <= DEFAULT_DISCOVERY_ATTEMPTS; attempt++) {
        printf("[*] Discovery attempt %d/%d for %s\n",
               attempt, DEFAULT_DISCOVERY_ATTEMPTS, cfg->device_name);
        scan_adapter(cfg->scan_timeout_sec);
        int ret = find_cached_device(cfg->device_name, address);
        if (ret == 0) {
            printf("[+] Found %s at %s. Attempting connection...\n",
                   cfg->device_name, address);
            return 0;
        }
        if (attempt < DEFAULT_DISCOVERY_ATTEMPTS) {
            usleep(500000);
        }
    }

    fprintf(stderr, "[-] Device named '%s' was not found\n",
            cfg->device_name);
    return -1;
}

static void prepare_bluetooth_adapter(const char *address,
                                      int scan_seconds,
                                      bool forget_cache,
                                      bool reset_adapter)
{
    char command[256];
    recycle_adapter(reset_adapter);

    snprintf(command, sizeof(command),
             "timeout -k 1 5 bluetoothctl disconnect %s "
             ">/dev/null 2>&1 || true", address);
    (void)command_status(command);

    if (forget_cache) {
        printf("[*] Removing cached BlueZ record for %s\n", address);
        snprintf(command, sizeof(command),
                 "timeout -k 1 5 bluetoothctl remove %s "
                 ">/dev/null 2>&1 || true", address);
        (void)command_status(command);
    }

    scan_adapter(scan_seconds);
}

static bool acl_connect_attempt(const char *address, int attempt, int total)
{
    char command[256];
    printf("[*] BLE connect %d/%d through BlueZ\n", attempt, total);
    snprintf(command, sizeof(command),
             "bluetoothctl --timeout 4 connect %s 2>&1", address);
    struct command_result result = command_capture(command);

    if ((result.exit_code == 0 ||
         strstr(result.output, "Connection successful") ||
         strstr(result.output, "already connected")) &&
        !strstr(result.output, "Failed to connect")) {
        printf("[+] Connected to hardware. Opening L2CAP Channel...\n");
        return true;
    }

    if (strstr(result.output, "le-connection-abort-by-local")) {
        printf("[-] BLE connect was aborted locally; raw L2CAP will retry.\n");
    } else {
        printf("[-] BLE connection attempt did not settle yet; raw L2CAP will retry.\n");
    }
    return false;
}

static void log_l2cap_open_error(int error_number)
{
    const char *message = strerror(error_number);
    if (error_number == ENOSYS) {
        message = "controller not ready for LE L2CAP yet; retrying";
    } else if (error_number == ETIMEDOUT || error_number == EALREADY ||
               error_number == EINPROGRESS) {
        message = "connection still in progress; retrying";
    } else if (error_number == ECONNREFUSED) {
        message = "channel refused by peripheral; retrying";
    } else if (error_number == ECONNRESET || error_number == ECONNABORTED) {
        message = "BLE link dropped during channel setup; retrying";
    } else if (error_number == EHOSTDOWN || error_number == EHOSTUNREACH) {
        message = "peripheral is not reachable yet; retrying";
    }
    fprintf(stderr, "[-] L2CAP Channel failed to open: %s\n", message);
}

static int wait_connected(int fd, int timeout_ms)
{
    while (keep_running) {
        fd_set write_fds;
        fd_set error_fds;
        FD_ZERO(&write_fds);
        FD_ZERO(&error_fds);
        FD_SET(fd, &write_fds);
        FD_SET(fd, &error_fds);

        struct timeval timeout = {
            .tv_sec = timeout_ms / 1000,
            .tv_usec = (timeout_ms % 1000) * 1000,
        };

        int ret = select(fd + 1, NULL, &write_fds, &error_fds, &timeout);
        if (ret < 0 && errno == EINTR) {
            continue;
        }
        if (ret <= 0) {
            fprintf(stderr,
                    "[-] L2CAP Channel failed to open: timed out; retrying\n");
            return -1;
        }

        int socket_error = 0;
        socklen_t length = sizeof(socket_error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR,
                       &socket_error, &length) < 0) {
            return -1;
        }
        if (socket_error == 0) {
            return 0;
        }
        log_l2cap_open_error(socket_error);
        return -1;
    }
    return -1;
}

static int connect_l2cap(const char *address, int address_type, uint16_t psm)
{
    int fd = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    if (fd < 0) {
        fprintf(stderr, "[-] L2CAP socket unavailable: %s\n",
                strerror(errno));
        return -1;
    }

    struct sockaddr_l2 local = {0};
    local.l2_family = AF_BLUETOOTH;
    bacpy(&local.l2_bdaddr, BDADDR_ANY);
    local.l2_bdaddr_type = BDADDR_LE_PUBLIC;
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        fprintf(stderr, "[-] L2CAP local bind failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    uint8_t mode = BT_MODE_LE_FLOWCTL;
    if (setsockopt(fd, SOL_BLUETOOTH, BT_MODE, &mode, sizeof(mode)) < 0) {
        fprintf(stderr, "[-] L2CAP flow-control setup failed: %s\n",
                strerror(errno));
        close(fd);
        return -1;
    }

    uint8_t security[2] = {BT_SECURITY_LOW, 0};
    if (setsockopt(fd, SOL_BLUETOOTH, BT_SECURITY,
                   security, sizeof(security)) < 0) {
        fprintf(stderr, "[-] L2CAP security setup failed: %s\n",
                strerror(errno));
        close(fd);
        return -1;
    }

    int original_flags = fcntl(fd, F_GETFL, 0);
    if (original_flags >= 0) {
        (void)fcntl(fd, F_SETFL, original_flags | O_NONBLOCK);
    }

    struct sockaddr_l2 remote = {0};
    remote.l2_family = AF_BLUETOOTH;
    remote.l2_psm = htobs(psm);
    remote.l2_bdaddr_type = address_type;
    str2ba(address, &remote.l2_bdaddr);

    if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
        if (errno != EINPROGRESS && errno != EALREADY) {
            log_l2cap_open_error(errno);
            close(fd);
            return -1;
        }
        if (wait_connected(fd, DEFAULT_CONNECT_TIMEOUT_MS) != 0) {
            close(fd);
            return -1;
        }
    }

    if (original_flags >= 0) {
        (void)fcntl(fd, F_SETFL, original_flags);
    }

    uint16_t receive_mtu = 0;
    uint16_t send_mtu = 0;
    socklen_t length = sizeof(uint16_t);
    (void)getsockopt(fd, SOL_BLUETOOTH, BT_RCVMTU, &receive_mtu, &length);
    length = sizeof(uint16_t);
    (void)getsockopt(fd, SOL_BLUETOOTH, BT_SNDMTU, &send_mtu, &length);
    printf("[+] L2CAP Channel Established! RX MTU=%u TX MTU=%u\n",
           receive_mtu, send_mtu);
    return fd;
}

static int connect_tcp(const char *host, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };
    if (inet_pton(AF_INET, host, &address.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        fprintf(stderr, "[-] TCP connection failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    printf("[+] TCP Bridge to Mosquitto Active. Pumping data.\n");
    return fd;
}

static int send_stream(int fd, const uint8_t *data, size_t length)
{
    size_t offset = 0;
    while (offset < length && keep_running) {
        ssize_t written = send(fd, data + offset, length - offset, 0);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return -1;
        }
        offset += (size_t)written;
    }
    return offset == length ? 0 : -1;
}

static int append_pending(struct sdu_prefix_state *state,
                          const uint8_t *data, size_t length)
{
    if (length == 0) {
        return 0;
    }
    if (state->pending_len + length > state->pending_cap) {
        size_t new_cap = state->pending_cap ? state->pending_cap : 1024;
        while (new_cap < state->pending_len + length) {
            new_cap *= 2;
        }
        uint8_t *new_pending = realloc(state->pending, new_cap);
        if (!new_pending) {
            return -1;
        }
        state->pending = new_pending;
        state->pending_cap = new_cap;
    }
    memcpy(state->pending + state->pending_len, data, length);
    state->pending_len += length;
    return 0;
}

static int drain_prefixed_sdu(struct sdu_prefix_state *state, int tcp_fd)
{
    while (state->pending_len > 0) {
        if (state->expected_sdu_len == 0) {
            if (state->pending_len < 2) {
                break;
            }
            state->expected_sdu_len =
                (size_t)state->pending[0] | ((size_t)state->pending[1] << 8);
            memmove(state->pending, state->pending + 2,
                    state->pending_len - 2);
            state->pending_len -= 2;
            if (state->expected_sdu_len == 0) {
                continue;
            }
        }

        size_t chunk = state->expected_sdu_len;
        if (chunk > state->pending_len) {
            chunk = state->pending_len;
        }
        if (chunk == 0) {
            break;
        }
        if (send_stream(tcp_fd, state->pending, chunk) != 0) {
            return -1;
        }
        memmove(state->pending, state->pending + chunk,
                state->pending_len - chunk);
        state->pending_len -= chunk;
        state->expected_sdu_len -= chunk;
    }
    return 0;
}

static int forward_ble_payload(struct sdu_prefix_state *state, int tcp_fd,
                               const uint8_t *data, size_t length)
{
    if (state->first_packet) {
        printf("[Bridge] First BLE receive: %zu bytes, prefix=", length);
        size_t preview = length < 12 ? length : 12;
        for (size_t i = 0; i < preview; i++) {
            printf("%s%02x", i ? " " : "", data[i]);
        }
        printf("\n");
        state->first_packet = false;
    }

    if (!state->framing_decided) {
        state->strip_prefix =
            length >= 5 &&
            (data[2] == 20 || data[2] == 21 ||
             data[2] == 22 || data[2] == 23) &&
            data[3] == 3;
        state->framing_decided = true;
        printf("[Bridge] BLE receive framing: %s\n",
               state->strip_prefix ?
                   "fragmented SDU prefix" :
                   "complete SDU");
    }

    if (!state->strip_prefix) {
        return send_stream(tcp_fd, data, length);
    }
    if (append_pending(state, data, length) != 0) {
        return -1;
    }
    return drain_prefixed_sdu(state, tcp_fd);
}

static int relay_loop(int ble_fd, int tcp_fd, size_t mtu)
{
    uint8_t *buffer = malloc(BRIDGE_RECV_BUFFER_SIZE);
    if (!buffer) {
        return -1;
    }
    struct sdu_prefix_state ble_rx_state = {
        .first_packet = true,
        .framing_decided = false,
        .strip_prefix = false,
        .pending = NULL,
        .pending_len = 0,
        .pending_cap = 0,
        .expected_sdu_len = 0,
    };
    printf("[Bridge] BLE L2CAP <-> TCP active. BLE write chunk=%zu read buffer=%u\n",
           mtu, BRIDGE_RECV_BUFFER_SIZE);

    while (keep_running) {
        struct pollfd descriptors[2] = {
            {.fd = ble_fd, .events = POLLIN},
            {.fd = tcp_fd, .events = POLLIN},
        };
        int result = poll(descriptors, 2, 1000);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result < 0) {
            break;
        }
        if (result == 0) {
            continue;
        }

        if (descriptors[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t length = recv(ble_fd, buffer, BRIDGE_RECV_BUFFER_SIZE, 0);
            if (length <= 0 ||
                forward_ble_payload(&ble_rx_state, tcp_fd, buffer,
                                    (size_t)length) != 0) {
                break;
            }
        }

        if (descriptors[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t length = recv(tcp_fd, buffer, BRIDGE_RECV_BUFFER_SIZE, 0);
            if (length <= 0) {
                break;
            }
            size_t offset = 0;
            while (offset < (size_t)length) {
                size_t chunk = (size_t)length - offset;
                if (chunk > mtu) {
                    chunk = mtu;
                }
                ssize_t written = send(ble_fd, buffer + offset, chunk, 0);
                if (written <= 0) {
                    result = -1;
                    break;
                }
                offset += (size_t)written;
                if (offset < (size_t)length) {
                    usleep(20000);
                }
            }
            if (result < 0) {
                break;
            }
        }
    }

    free(ble_rx_state.pending);
    free(buffer);
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

    if (cfg.disable_wifi) {
        set_wifi_enabled(false);
        cfg.wifi_disabled = true;
    }

    char discovered_address[18] = {0};
    const char *address = cfg.device_addr;
    if (!address) {
        recycle_adapter(false);
        if (discover_device(&cfg, discovered_address) != 0) {
            if (cfg.wifi_disabled) {
                set_wifi_enabled(true);
            }
            return 1;
        }
        address = discovered_address;
    }

    int prepare_scan_seconds = cfg.device_addr ? cfg.scan_timeout_sec : 0;
    prepare_bluetooth_adapter(address, prepare_scan_seconds,
                              cfg.forget_cache, cfg.reset_adapter);

    if (!cfg.no_acl_prime) {
        for (int attempt = 1; attempt <= DEFAULT_ACL_ATTEMPTS && keep_running;
             attempt++) {
            if (acl_connect_attempt(address, attempt, DEFAULT_ACL_ATTEMPTS)) {
                break;
            }
            usleep(250000);
        }
    } else {
        printf("[*] Opening raw L2CAP Channel directly on PSM 0x%04x...\n",
               cfg.psm);
    }

    int ble_fd = -1;
    double l2cap_start_ms = monotonic_ms();
    for (int attempt = 1;
         keep_running && attempt <= DEFAULT_L2CAP_ATTEMPTS;
         attempt++) {
        printf("[*] L2CAP open attempt %d/%d to %s, PSM 0x%04x\n",
               attempt, DEFAULT_L2CAP_ATTEMPTS, address, cfg.psm);
        ble_fd = connect_l2cap(address, cfg.device_addr_type, cfg.psm);
        if (ble_fd >= 0) {
            break;
        }

        if (!cfg.device_addr && attempt % 3 == 0 &&
            attempt < DEFAULT_L2CAP_ATTEMPTS) {
            char refreshed_address[18] = {0};
            scan_adapter(1);
            if (find_cached_device(cfg.device_name, refreshed_address) == 0 &&
                strcmp(refreshed_address, address) != 0) {
                memcpy(discovered_address, refreshed_address, 18);
                address = discovered_address;
                printf("[*] Refreshed %s address to %s after L2CAP retries.\n",
                       cfg.device_name, address);
            }
        }

        if (attempt % 5 == 0 && attempt < DEFAULT_L2CAP_ATTEMPTS) {
            recycle_adapter(true);
            scan_adapter(1);
            if (!cfg.no_acl_prime) {
                (void)acl_connect_attempt(address, 1, 1);
            }
        }
        usleep(250000);
    }
    if (ble_fd < 0) {
        if (cfg.wifi_disabled) {
            set_wifi_enabled(true);
        }
        return 1;
    }
    printf("[BENCH_GATEWAY] ble_l2cap_connect_ms=%.3f\n",
           monotonic_ms() - l2cap_start_ms);

    double tcp_start_ms = monotonic_ms();
    int tcp_fd = connect_tcp(cfg.tcp_host, cfg.tcp_port);
    if (tcp_fd < 0) {
        close(ble_fd);
        if (cfg.wifi_disabled) {
            set_wifi_enabled(true);
        }
        return 1;
    }
    printf("[BENCH_GATEWAY] gateway_tcp_connect_ms=%.3f\n",
           monotonic_ms() - tcp_start_ms);

    int result = relay_loop(ble_fd, tcp_fd, cfg.mtu);
    close(ble_fd);
    close(tcp_fd);
    if (cfg.wifi_disabled) {
        set_wifi_enabled(true);
    }
    return result == 0 ? 0 : 1;
}
