#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define MQTT_CONNECT_PACKET 0x10
#define DEFAULT_PORT 8883
#define LISTEN_BACKLOG 1

static volatile sig_atomic_t keep_running = 1;

struct config {
    const char* case_dir;
    const char* group;
    const char* sigalg;
    int port;
    bool mtls;
    int timeout_sec;
};

static void on_signal(int signo)
{
    (void)signo;
    keep_running = 0;
}

static int group_id(const char* group)
{
    struct group_entry {
        const char* name;
        int id;
    };
    static const struct group_entry groups[] = {
        { "WOLFSSL_ECC_SECP256R1", WOLFSSL_ECC_SECP256R1 },
        { "WOLFSSL_ECC_SECP384R1", WOLFSSL_ECC_SECP384R1 },
        { "WOLFSSL_ECC_SECP521R1", WOLFSSL_ECC_SECP521R1 },
        { "WOLFSSL_ML_KEM_512", WOLFSSL_ML_KEM_512 },
        { "WOLFSSL_ML_KEM_768", WOLFSSL_ML_KEM_768 },
        { "WOLFSSL_ML_KEM_1024", WOLFSSL_ML_KEM_1024 },
        { "WOLFSSL_SECP256R1MLKEM768", WOLFSSL_SECP256R1MLKEM768 },
        { "WOLFSSL_X25519MLKEM768", WOLFSSL_X25519MLKEM768 },
        { "WOLFSSL_SECP384R1MLKEM1024", WOLFSSL_SECP384R1MLKEM1024 },
    };

    for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); i++) {
        if (strcmp(group, groups[i].name) == 0)
            return groups[i].id;
    }
    return 0;
}

static int signature_scheme_id(const char* name)
{
    static const struct {
        const char* name;
        int id;
    } schemes[] = {
        { "ecdsa_secp256r1_sha256", 0x0403 },
        { "ecdsa_secp384r1_sha384", 0x0503 },
        { "ecdsa_secp521r1_sha512", 0x0603 },
        { "rsa_pss_rsae_sha256", 0x0804 },
        { "rsa_pss_rsae_sha384", 0x0805 },
        { "rsa_pss_rsae_sha512", 0x0806 },
        { "mldsa44", 0x0904 },
        { "mldsa65", 0x0905 },
        { "mldsa87", 0x0906 },
    };
    for (size_t i = 0; i < sizeof(schemes) / sizeof(schemes[0]); i++) {
        if (strcmp(name, schemes[i].name) == 0)
            return schemes[i].id;
    }
    return 0;
}

static const char* wolfssl_signature_list(const char* name)
{
    if (strcmp(name, "ecdsa_secp256r1_sha256") == 0)
        return "ECDSA+SHA256";
    if (strcmp(name, "ecdsa_secp384r1_sha384") == 0)
        return "ECDSA+SHA384";
    if (strcmp(name, "ecdsa_secp521r1_sha512") == 0)
        return "ECDSA+SHA512";
    if (strcmp(name, "rsa_pss_rsae_sha256") == 0)
        return "RSA-PSS+SHA256";
    if (strcmp(name, "rsa_pss_rsae_sha384") == 0)
        return "RSA-PSS+SHA384";
    if (strcmp(name, "rsa_pss_rsae_sha512") == 0)
        return "RSA-PSS+SHA512";
    return NULL;
}

static int join_path(char* out, size_t out_len, const char* dir, const char* name)
{
    int len = snprintf(out, out_len, "%s/%s", dir, name);
    if (len < 0 || (size_t)len >= out_len) {
        fprintf(stderr, "path too long: %s/%s\n", dir, name);
        return -1;
    }
    return 0;
}

static unsigned char* read_file(const char* path, long* size_out)
{
    FILE* file;
    unsigned char* data;
    long size;

    file = fopen(path, "rb");
    if (file == NULL)
        return NULL;
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }
    size = ftell(file);
    if (size <= 0) {
        fclose(file);
        return NULL;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }
    data = (unsigned char*)malloc((size_t)size);
    if (data == NULL) {
        fclose(file);
        return NULL;
    }
    if (fread(data, 1, (size_t)size, file) != (size_t)size) {
        free(data);
        fclose(file);
        return NULL;
    }
    fclose(file);
    *size_out = size;
    return data;
}

static void print_wolfssl_errors(const char* context)
{
    fprintf(stderr, "%s\n", context);
    wolfSSL_ERR_print_errors_fp(stderr, 0);
}

static int verify_callback(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    if (!preverify &&
        (store->error == ASN_BEFORE_DATE_E || store->error == ASN_AFTER_DATE_E)) {
        fprintf(stderr, "[wolfssl-server] ignoring peer certificate date error: %d\n",
            store->error);
        return 1;
    }
    return preverify;
}

static void usage(const char* program)
{
    fprintf(stderr,
        "usage: %s --case-dir DIR --group WOLFSSL_GROUP --sigalg NAME [--port PORT] "
        "[--mtls] [--timeout SECONDS]\n",
        program);
}

static int parse_args(int argc, char** argv, struct config* cfg)
{
    static const struct option options[] = {
        { "case-dir", required_argument, NULL, 'c' },
        { "group", required_argument, NULL, 'g' },
        { "sigalg", required_argument, NULL, 's' },
        { "port", required_argument, NULL, 'p' },
        { "mtls", no_argument, NULL, 'm' },
        { "timeout", required_argument, NULL, 't' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };

    cfg->case_dir = NULL;
    cfg->group = NULL;
    cfg->sigalg = NULL;
    cfg->port = DEFAULT_PORT;
    cfg->mtls = false;
    cfg->timeout_sec = 60;

    for (;;) {
        int opt = getopt_long(argc, argv, "c:g:s:p:mt:h", options, NULL);
        if (opt == -1)
            break;
        switch (opt) {
        case 'c':
            cfg->case_dir = optarg;
            break;
        case 'g':
            cfg->group = optarg;
            break;
        case 's':
            cfg->sigalg = optarg;
            break;
        case 'p':
            cfg->port = atoi(optarg);
            break;
        case 'm':
            cfg->mtls = true;
            break;
        case 't':
            cfg->timeout_sec = atoi(optarg);
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            usage(argv[0]);
            return -1;
        }
    }

    if (cfg->case_dir == NULL || cfg->group == NULL || cfg->sigalg == NULL ||
        cfg->port <= 0 ||
        cfg->port > 65535 || cfg->timeout_sec <= 0) {
        usage(argv[0]);
        return -1;
    }
    if (group_id(cfg->group) == 0) {
        fprintf(stderr, "unsupported wolfSSL group name: %s\n", cfg->group);
        return -1;
    }
    if (signature_scheme_id(cfg->sigalg) == 0) {
        fprintf(stderr, "unsupported wolfSSL signature scheme: %s\n",
            cfg->sigalg);
        return -1;
    }
    return 0;
}

static int make_listener(int port)
{
    int fd;
    int one = 1;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
        perror("setsockopt(SO_REUSEADDR)");
        close(fd);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(fd, (const struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    if (listen(fd, LISTEN_BACKLOG) != 0) {
        perror("listen");
        close(fd);
        return -1;
    }
    return fd;
}

static int configure_context(WOLFSSL_CTX* ctx, const struct config* cfg)
{
    char ca_file[1024];
    char ca_der_file[1024];
    char cert_file[1024];
    char key_file[1024];
    unsigned char* ca_der = NULL;
    long ca_der_size = 0;
    int groups[1];

    if (join_path(ca_file, sizeof(ca_file), cfg->case_dir, "client_ca.crt") != 0 ||
        join_path(ca_der_file, sizeof(ca_der_file), cfg->case_dir,
            "client_ca.der") != 0 ||
        join_path(cert_file, sizeof(cert_file), cfg->case_dir,
            "server_chain.crt") != 0 ||
        join_path(key_file, sizeof(key_file), cfg->case_dir, "server.key") != 0)
        return -1;

    if (cfg->mtls) {
        wolfSSL_CTX_set_verify(
            ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
            verify_callback);

        ca_der = read_file(ca_der_file, &ca_der_size);
        if (ca_der != NULL) {
            if (wolfSSL_CTX_load_verify_buffer_ex(
                    ctx, ca_der, ca_der_size, WOLFSSL_FILETYPE_ASN1, 0,
                    WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY) != WOLFSSL_SUCCESS) {
                free(ca_der);
                print_wolfssl_errors("failed to load DER client CA");
                return -1;
            }
            free(ca_der);
        }
        else if (wolfSSL_CTX_load_verify_locations(
                     ctx, ca_file, NULL) != WOLFSSL_SUCCESS) {
            print_wolfssl_errors("failed to load PEM client CA");
            fprintf(stderr, "client CA path: %s\n", ca_file);
            return -1;
        }
    }
    else
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
    if (wolfSSL_CTX_use_certificate_chain_file(ctx, cert_file) != WOLFSSL_SUCCESS) {
        print_wolfssl_errors("failed to load server certificate chain");
        fprintf(stderr, "server certificate chain path: %s\n", cert_file);
        return -1;
    }
    if (wolfSSL_CTX_use_PrivateKey_file(
            ctx, key_file, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
        print_wolfssl_errors("failed to load server private key");
        fprintf(stderr, "server private key path: %s\n", key_file);
        return -1;
    }

    groups[0] = group_id(cfg->group);
    if (wolfSSL_CTX_set_groups(ctx, groups, 1) != WOLFSSL_SUCCESS) {
        print_wolfssl_errors("failed to configure wolfSSL group");
        fprintf(stderr, "wolfSSL group: %s\n", cfg->group);
        return -1;
    }
    /* Some wolfSSL builds compile session tickets out and report failure here.
     * In that case tickets are already unavailable, so server startup must
     * continue instead of leaving the bridge with no listener on port 8883. */
    (void)wolfSSL_CTX_no_ticket_TLSv13(ctx);
    const char* sigalg_list = wolfssl_signature_list(cfg->sigalg);
    if (sigalg_list == NULL ||
        wolfSSL_CTX_set1_sigalgs_list(ctx, sigalg_list) != WOLFSSL_SUCCESS) {
        print_wolfssl_errors("failed to configure wolfSSL signature scheme");
        return -1;
    }
    return 0;
}

static int read_remaining_length(WOLFSSL* ssl, unsigned int* remaining)
{
    unsigned int multiplier = 1;
    unsigned int value = 0;

    for (int i = 0; i < 4; i++) {
        unsigned char encoded = 0;
        int ret = wolfSSL_read(ssl, &encoded, 1);
        if (ret != 1)
            return -1;
        value += (encoded & 127U) * multiplier;
        if ((encoded & 128U) == 0) {
            *remaining = value;
            return 0;
        }
        multiplier *= 128U;
    }
    return -1;
}

static int discard_bytes(WOLFSSL* ssl, unsigned int length)
{
    unsigned char buffer[256];
    while (length > 0) {
        int chunk = length > sizeof(buffer) ? (int)sizeof(buffer) : (int)length;
        int ret = wolfSSL_read(ssl, buffer, chunk);
        if (ret <= 0)
            return -1;
        length -= (unsigned int)ret;
    }
    return 0;
}

static int handle_mqtt_connect(WOLFSSL* ssl)
{
    unsigned char packet_type = 0;
    unsigned int remaining = 0;
    static const unsigned char connack[] = { 0x20, 0x02, 0x00, 0x00 };

    if (wolfSSL_read(ssl, &packet_type, 1) != 1) {
        fprintf(stderr, "failed to read MQTT packet type\n");
        return -1;
    }
    if (packet_type != MQTT_CONNECT_PACKET) {
        fprintf(stderr, "unexpected MQTT packet type: 0x%02x\n", packet_type);
        return -1;
    }
    if (read_remaining_length(ssl, &remaining) != 0 ||
        discard_bytes(ssl, remaining) != 0) {
        fprintf(stderr, "failed to read MQTT CONNECT body\n");
        return -1;
    }
    if (wolfSSL_write(ssl, connack, sizeof(connack)) != (int)sizeof(connack)) {
        fprintf(stderr, "failed to write MQTT CONNACK\n");
        return -1;
    }
    return 0;
}

int main(int argc, char** argv)
{
    struct config cfg;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    int listen_fd = -1;
    int client_fd = -1;
    int ret = 1;

    if (parse_args(argc, argv, &cfg) != 0)
        return 2;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    wolfSSL_Init();
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (ctx == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new failed\n");
        goto cleanup;
    }
    if (configure_context(ctx, &cfg) != 0)
        goto cleanup;

    listen_fd = make_listener(cfg.port);
    if (listen_fd < 0)
        goto cleanup;

    fprintf(stderr,
        "[wolfssl-server] listening on 127.0.0.1:%d group=%s sigalg=%s auth=%s\n",
        cfg.port, cfg.group, cfg.sigalg,
        cfg.mtls ? "mutual" : "server-only");
    fflush(stderr);

    while (keep_running) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        struct timeval timeout = {
            .tv_sec = cfg.timeout_sec,
            .tv_usec = 0,
        };

        client_fd = accept(listen_fd, (struct sockaddr*)&peer, &peer_len);
        if (client_fd < 0) {
            if (errno == EINTR)
                continue;
            perror("accept");
            goto cleanup;
        }
        (void)setsockopt(
            client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        (void)setsockopt(
            client_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        ssl = wolfSSL_new(ctx);
        if (ssl == NULL) {
            fprintf(stderr, "wolfSSL_new failed\n");
            goto cleanup;
        }
        wolfSSL_set_fd(ssl, client_fd);

        int accept_ret = wolfSSL_accept(ssl);
        if (accept_ret != WOLFSSL_SUCCESS) {
            int err = wolfSSL_get_error(ssl, accept_ret);
            fprintf(stderr, "wolfSSL_accept failed: %d\n", err);
            goto cleanup;
        }
        fprintf(stderr, "[wolfssl-server] TLS handshake complete\n");
        fflush(stderr);

        if (handle_mqtt_connect(ssl) != 0)
            goto cleanup;
        fprintf(stderr, "[wolfssl-server] MQTT CONNACK sent\n");
        fflush(stderr);

        (void)wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        ssl = NULL;
        close(client_fd);
        client_fd = -1;
    }
    ret = 0;

cleanup:
    if (ssl != NULL)
        wolfSSL_free(ssl);
    if (client_fd >= 0)
        close(client_fd);
    if (listen_fd >= 0)
        close(listen_fd);
    if (ctx != NULL)
        wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return ret;
}
