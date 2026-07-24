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
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/random.h>
#ifdef BENCH_CLIENT_CERTGEN
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/wc_lms.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/wolfcrypt/wc_slhdsa.h>
#include <wolfssl/wolfcrypt/wc_xmss.h>
#endif
#include "benchmark_metrics.h"
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
#define CERTGEN_DWT_SAMPLE_US 100
#define CERTGEN_DWT_WRAP_RISK_THRESHOLD 240

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

#define BENCHMARK_THREAD_CPU_MAX_THREADS 16

struct benchmark_thread_cpu_entry {
    const char *name;
    uint64_t cycles;
};

struct benchmark_thread_cpu_snapshot {
    struct benchmark_thread_cpu_entry threads[BENCHMARK_THREAD_CPU_MAX_THREADS];
    size_t count;
    uint64_t system_cycles;
    bool valid;
};

struct benchmark_thread_cpu_delta {
    uint64_t main_cycles;
    uint64_t sysworkq_cycles;
    uint64_t bt_rx_cycles;
    uint64_t bt_tx_cycles;
    uint64_t idle_cycles;
    uint64_t other_cycles;
    uint32_t main_bp;
    uint32_t sysworkq_bp;
    uint32_t bt_rx_bp;
    uint32_t bt_tx_bp;
    uint32_t idle_bp;
    uint32_t other_bp;
};

static struct benchmark_thread_cpu_snapshot thread_cpu_snapshot;

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

static void benchmark_thread_cpu_snapshot_cb(struct thread_analyzer_info *info)
{
#if defined(CONFIG_THREAD_RUNTIME_STATS) && defined(CONFIG_SCHED_THREAD_USAGE)
    size_t idx;

    idx = thread_cpu_snapshot.count;
    if (idx >= BENCHMARK_THREAD_CPU_MAX_THREADS) {
        return;
    }

    thread_cpu_snapshot.threads[idx].name = info->name;
    thread_cpu_snapshot.threads[idx].cycles = info->usage.execution_cycles;
    thread_cpu_snapshot.count++;
#else
    ARG_UNUSED(info);
#endif
}

static struct benchmark_thread_cpu_snapshot benchmark_thread_cpu_snapshot_get(void)
{
    k_thread_runtime_stats_t system_stats = {0};

    thread_cpu_snapshot = (struct benchmark_thread_cpu_snapshot){0};
#if defined(CONFIG_THREAD_RUNTIME_STATS) && defined(CONFIG_SCHED_THREAD_USAGE)
    if (k_thread_runtime_stats_all_get(&system_stats) != 0) {
        return thread_cpu_snapshot;
    }
    thread_cpu_snapshot.system_cycles = system_stats.execution_cycles;
    thread_cpu_snapshot.valid = true;
    thread_analyzer_run(benchmark_thread_cpu_snapshot_cb, 0);
#endif
    return thread_cpu_snapshot;
}

static bool benchmark_name_contains(const char *name, const char *needle)
{
    return name != NULL && strstr(name, needle) != NULL;
}

static void benchmark_add_thread_delta(
    struct benchmark_thread_cpu_delta *delta,
    const char *name,
    uint64_t cycles)
{
    if (benchmark_name_contains(name, "main")) {
        delta->main_cycles += cycles;
    } else if (benchmark_name_contains(name, "sysworkq")) {
        delta->sysworkq_cycles += cycles;
    } else if (benchmark_name_contains(name, "idle")) {
        delta->idle_cycles += cycles;
    } else if (benchmark_name_contains(name, "BT RX") ||
               benchmark_name_contains(name, "bt_rx")) {
        delta->bt_rx_cycles += cycles;
    } else if (benchmark_name_contains(name, "BT TX") ||
               benchmark_name_contains(name, "bt_tx")) {
        delta->bt_tx_cycles += cycles;
    } else {
        delta->other_cycles += cycles;
    }
}

static uint64_t benchmark_thread_start_cycles(
    const struct benchmark_thread_cpu_snapshot *start,
    const char *name)
{
    size_t i;

    if (name == NULL) {
        return 0;
    }
    for (i = 0; i < start->count; i++) {
        if (start->threads[i].name != NULL &&
            strcmp(start->threads[i].name, name) == 0) {
            return start->threads[i].cycles;
        }
    }
    return 0;
}

static struct benchmark_thread_cpu_delta benchmark_thread_cpu_delta_get(
    const struct benchmark_thread_cpu_snapshot *start,
    const struct benchmark_thread_cpu_snapshot *end)
{
    struct benchmark_thread_cpu_delta delta = {0};
    uint64_t system_delta;
    size_t i;

    if (!start->valid || !end->valid ||
        end->system_cycles <= start->system_cycles) {
        return delta;
    }

    system_delta = end->system_cycles - start->system_cycles;
    for (i = 0; i < end->count; i++) {
        uint64_t start_cycles;
        uint64_t thread_delta;

        start_cycles = benchmark_thread_start_cycles(
            start, end->threads[i].name);
        if (end->threads[i].cycles < start_cycles) {
            continue;
        }
        thread_delta = end->threads[i].cycles - start_cycles;
        benchmark_add_thread_delta(&delta, end->threads[i].name, thread_delta);
    }

    delta.main_bp = benchmark_percent_bp(delta.main_cycles, system_delta);
    delta.sysworkq_bp = benchmark_percent_bp(delta.sysworkq_cycles, system_delta);
    delta.bt_rx_bp = benchmark_percent_bp(delta.bt_rx_cycles, system_delta);
    delta.bt_tx_bp = benchmark_percent_bp(delta.bt_tx_cycles, system_delta);
    delta.idle_bp = benchmark_percent_bp(delta.idle_cycles, system_delta);
    delta.other_bp = benchmark_percent_bp(delta.other_cycles, system_delta);
    return delta;
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

#ifdef BENCH_CLIENT_CERTGEN
struct benchmark_cpu_phase {
    struct benchmark_cpu_snapshot start;
    uint64_t cycles;
    uint64_t us;
    uint64_t dwt_lsu_cycles;
    uint64_t dwt_cpi_cycles;
    uint32_t dwt_samples;
    bool dwt_supported;
    bool dwt_wrap_risk;
};

struct benchmark_dwt_sampler {
    struct benchmark_cpu_phase *phase;
    uint32_t last_cyccnt;
    uint8_t last_lsu;
    uint8_t last_cpi;
    bool active;
    bool supported;
};

static struct benchmark_dwt_sampler certgen_dwt_sampler;

static bool benchmark_dwt_supported(void)
{
#if defined(CONFIG_CPU_CORTEX_M_HAS_DWT) && defined(DWT_CTRL_NOPRFCNT_Msk)
    return (DWT->CTRL & DWT_CTRL_NOPRFCNT_Msk) == 0;
#else
    return false;
#endif
}

static void benchmark_dwt_enable(void)
{
#if defined(CONFIG_CPU_CORTEX_M_HAS_DWT)
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
#if defined(DWT_CTRL_CYCCNTENA_Msk)
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
#endif
#if defined(DWT_CTRL_CPIEVTENA_Msk)
    DWT->CTRL |= DWT_CTRL_CPIEVTENA_Msk;
#endif
#if defined(DWT_CTRL_LSUEVTENA_Msk)
    DWT->CTRL |= DWT_CTRL_LSUEVTENA_Msk;
#endif
#endif
}

static void benchmark_dwt_sampler_sample(void)
{
#if defined(CONFIG_CPU_CORTEX_M_HAS_DWT)
    struct benchmark_dwt_sampler *sampler = &certgen_dwt_sampler;
    uint8_t lsu;
    uint8_t cpi;
    uint32_t cyccnt;
    uint8_t lsu_delta;
    uint8_t cpi_delta;

    if (!sampler->active || !sampler->supported ||
        sampler->phase == NULL) {
        return;
    }

    lsu = (uint8_t)DWT->LSUCNT;
    cpi = (uint8_t)DWT->CPICNT;
    cyccnt = DWT->CYCCNT;
    lsu_delta = (uint8_t)(lsu - sampler->last_lsu);
    cpi_delta = (uint8_t)(cpi - sampler->last_cpi);

    sampler->phase->dwt_lsu_cycles += lsu_delta;
    sampler->phase->dwt_cpi_cycles += cpi_delta;
    sampler->phase->dwt_samples++;
    if (lsu_delta >= CERTGEN_DWT_WRAP_RISK_THRESHOLD ||
        cpi_delta >= CERTGEN_DWT_WRAP_RISK_THRESHOLD) {
        sampler->phase->dwt_wrap_risk = true;
    }

    sampler->last_lsu = lsu;
    sampler->last_cpi = cpi;
    sampler->last_cyccnt = cyccnt;
#endif
}

static void benchmark_dwt_sampler_timer(struct k_timer *timer)
{
    ARG_UNUSED(timer);
    benchmark_dwt_sampler_sample();
}

K_TIMER_DEFINE(certgen_dwt_timer, benchmark_dwt_sampler_timer, NULL);

static void benchmark_cpu_phase_begin(struct benchmark_cpu_phase *phase)
{
    phase->start = benchmark_cpu_snapshot_get();
    phase->cycles = 0;
    phase->us = 0;
    phase->dwt_lsu_cycles = 0;
    phase->dwt_cpi_cycles = 0;
    phase->dwt_samples = 0;
    phase->dwt_supported = false;
    phase->dwt_wrap_risk = false;

#if defined(CONFIG_CPU_CORTEX_M_HAS_DWT)
    benchmark_dwt_enable();
    certgen_dwt_sampler.phase = phase;
    certgen_dwt_sampler.supported = benchmark_dwt_supported();
    certgen_dwt_sampler.active = certgen_dwt_sampler.supported;
    phase->dwt_supported = certgen_dwt_sampler.supported;
    certgen_dwt_sampler.last_lsu = (uint8_t)DWT->LSUCNT;
    certgen_dwt_sampler.last_cpi = (uint8_t)DWT->CPICNT;
    certgen_dwt_sampler.last_cyccnt = DWT->CYCCNT;
    if (certgen_dwt_sampler.supported) {
        k_timer_start(
            &certgen_dwt_timer,
            K_USEC(CERTGEN_DWT_SAMPLE_US),
            K_USEC(CERTGEN_DWT_SAMPLE_US));
    }
#endif
}

static void benchmark_cpu_phase_end(struct benchmark_cpu_phase *phase)
{
    struct benchmark_cpu_snapshot end = benchmark_cpu_snapshot_get();

#if defined(CONFIG_CPU_CORTEX_M_HAS_DWT)
    if (certgen_dwt_sampler.phase == phase) {
        benchmark_dwt_sampler_sample();
        k_timer_stop(&certgen_dwt_timer);
        certgen_dwt_sampler.active = false;
        certgen_dwt_sampler.phase = NULL;
    }
#endif

    if (!phase->start.valid || !end.valid ||
        end.thread_cycles < phase->start.thread_cycles) {
        phase->cycles = 0;
        phase->us = 0;
        return;
    }

    phase->cycles = end.thread_cycles - phase->start.thread_cycles;
    phase->us = k_cyc_to_us_floor64(phase->cycles);
}
#endif

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

#ifdef BENCH_CLIENT_CERTGEN
#define CLIENT_CERTGEN_ECC_DER_CAP 2048
#define CLIENT_CERTGEN_ECC_KEY_CAP 1024
#define CLIENT_CERTGEN_RSA_3072_DER_CAP 4096
#define CLIENT_CERTGEN_RSA_3072_KEY_CAP 4096
#define CLIENT_CERTGEN_RSA_7680_DER_CAP 8192
#define CLIENT_CERTGEN_RSA_7680_KEY_CAP 12288
#define CLIENT_CERTGEN_RSA_15360_DER_CAP 12288
#define CLIENT_CERTGEN_RSA_15360_KEY_CAP 32768
#define CLIENT_CERTGEN_MLDSA_44_DER_CAP 8192
#define CLIENT_CERTGEN_MLDSA_44_KEY_CAP 8192
#define CLIENT_CERTGEN_MLDSA_65_DER_CAP 8192
#define CLIENT_CERTGEN_MLDSA_65_KEY_CAP 8192
#define CLIENT_CERTGEN_MLDSA_87_DER_CAP 12288
#define CLIENT_CERTGEN_MLDSA_87_KEY_CAP 12288
#define CLIENT_CERTGEN_SLHDSA_128_DER_CAP 16384
#define CLIENT_CERTGEN_SLHDSA_192_DER_CAP 28672
#define CLIENT_CERTGEN_SLHDSA_256_DER_CAP 49152
#define CLIENT_CERTGEN_SLHDSA_KEY_CAP 4096
#define CLIENT_CERTGEN_LMS_DER_CAP 8192
#define CLIENT_CERTGEN_LMS_KEY_CAP 4096
#define CLIENT_CERTGEN_LMS_STATE_CAP 4096
#define CLIENT_CERTGEN_XMSS_DER_CAP 8192
#define CLIENT_CERTGEN_XMSS_KEY_CAP 8192
#define CLIENT_CERTGEN_XMSS_STATE_CAP 8192
#define CLIENT_CERTGEN_NOT_BEFORE "\x18\x0f""20200101000000Z"
#define CLIENT_CERTGEN_NOT_AFTER  "\x18\x0f""20360101000000Z"

#ifndef BENCH_CLIENT_CERTGEN_SIG
#define BENCH_CLIENT_CERTGEN_SIG "ECDSA-P-256"
#endif

enum client_certgen_key_kind {
    CLIENT_CERTGEN_KEY_ECC,
    CLIENT_CERTGEN_KEY_RSA,
    CLIENT_CERTGEN_KEY_MLDSA,
    CLIENT_CERTGEN_KEY_SLHDSA,
    CLIENT_CERTGEN_KEY_LMS,
    CLIENT_CERTGEN_KEY_XMSS,
};

struct client_certgen_algorithm {
    const char *name;
    enum client_certgen_key_kind kind;
    int key_type;
    int sig_type;
    int ecc_curve;
    int rsa_bits;
    int mldsa_level;
    enum SlhDsaParam slhdsa_param;
    const char *xmss_param;
};

struct client_certgen_hbs_state {
    byte *data;
    word32 cap;
    word32 len;
};

static const struct client_certgen_algorithm client_certgen_algorithms[] = {
    {
        "ECDSA-P-256", CLIENT_CERTGEN_KEY_ECC, ECC_TYPE,
        CTC_SHA256wECDSA, ECC_SECP256R1, 0, 0, SLHDSA_SHAKE128S, NULL
    },
    {
        "ECDSA-P-384", CLIENT_CERTGEN_KEY_ECC, ECC_TYPE,
        CTC_SHA384wECDSA, ECC_SECP384R1, 0, 0, SLHDSA_SHAKE128S, NULL
    },
    {
        "ECDSA-P-521", CLIENT_CERTGEN_KEY_ECC, ECC_TYPE,
        CTC_SHA512wECDSA, ECC_SECP521R1, 0, 0, SLHDSA_SHAKE128S, NULL
    },
    {
        "LMS-HSS-L2-H10-W4", CLIENT_CERTGEN_KEY_LMS, LMS_TYPE,
        CTC_HSS_LMS, 0, 0, 0, SLHDSA_SHAKE128S, NULL
    },
    {
        "RSA-PSS-3072", CLIENT_CERTGEN_KEY_RSA, RSA_TYPE,
        CTC_SHA256wRSA, 0, 3072, 0, SLHDSA_SHAKE128S, NULL
    },
    {
        "RSA-PSS-7680", CLIENT_CERTGEN_KEY_RSA, RSA_TYPE,
        CTC_SHA384wRSA, 0, 7680, 0, SLHDSA_SHAKE128S, NULL
    },
    {
        "RSA-PSS-15360", CLIENT_CERTGEN_KEY_RSA, RSA_TYPE,
        CTC_SHA512wRSA, 0, 15360, 0, SLHDSA_SHAKE128S, NULL
    },
    {
        "ML-DSA-44", CLIENT_CERTGEN_KEY_MLDSA, ML_DSA_44_TYPE,
        CTC_ML_DSA_44, 0, 0, WC_ML_DSA_44, SLHDSA_SHAKE128S, NULL
    },
    {
        "ML-DSA-65", CLIENT_CERTGEN_KEY_MLDSA, ML_DSA_65_TYPE,
        CTC_ML_DSA_65, 0, 0, WC_ML_DSA_65, SLHDSA_SHAKE128S, NULL
    },
    {
        "ML-DSA-87", CLIENT_CERTGEN_KEY_MLDSA, ML_DSA_87_TYPE,
        CTC_ML_DSA_87, 0, 0, WC_ML_DSA_87, SLHDSA_SHAKE128S, NULL
    },
    {
        "SLH-DSA-SHAKE-128s", CLIENT_CERTGEN_KEY_SLHDSA,
        SLH_DSA_SHAKE_128S_TYPE, CTC_SLH_DSA_SHAKE_128S, 0, 0, 0,
        SLHDSA_SHAKE128S, NULL
    },
    {
        "SLH-DSA-SHAKE-192s", CLIENT_CERTGEN_KEY_SLHDSA,
        SLH_DSA_SHAKE_192S_TYPE, CTC_SLH_DSA_SHAKE_192S, 0, 0, 0,
        SLHDSA_SHAKE192S, NULL
    },
    {
        "SLH-DSA-SHAKE-256s", CLIENT_CERTGEN_KEY_SLHDSA,
        SLH_DSA_SHAKE_256S_TYPE, CTC_SLH_DSA_SHAKE_256S, 0, 0, 0,
        SLHDSA_SHAKE256S, NULL
    },
    {
        "XMSS-SHA2_20_256", CLIENT_CERTGEN_KEY_XMSS, XMSS_TYPE,
        CTC_XMSS, 0, 0, 0, SLHDSA_SHAKE128S, "XMSS-SHA2_20_256"
    },
};

static const struct client_certgen_algorithm *client_certgen_algorithm(void)
{
    for (size_t i = 0; i < ARRAY_SIZE(client_certgen_algorithms); i++) {
        if (strcmp(BENCH_CLIENT_CERTGEN_SIG,
                client_certgen_algorithms[i].name) == 0) {
            return &client_certgen_algorithms[i];
        }
    }
    return NULL;
}

static size_t client_certgen_key_struct_size(
    const struct client_certgen_algorithm *alg)
{
    switch (alg->kind) {
    case CLIENT_CERTGEN_KEY_ECC:
        return sizeof(ecc_key);
    case CLIENT_CERTGEN_KEY_RSA:
        return sizeof(RsaKey);
    case CLIENT_CERTGEN_KEY_MLDSA:
        return sizeof(wc_MlDsaKey);
    case CLIENT_CERTGEN_KEY_SLHDSA:
        return sizeof(SlhDsaKey);
    case CLIENT_CERTGEN_KEY_LMS:
        return sizeof(LmsKey);
    case CLIENT_CERTGEN_KEY_XMSS:
        return sizeof(XmssKey);
    }
    return 0;
}

static word32 client_certgen_cert_der_cap(
    const struct client_certgen_algorithm *alg)
{
    switch (alg->kind) {
    case CLIENT_CERTGEN_KEY_ECC:
        return CLIENT_CERTGEN_ECC_DER_CAP;
    case CLIENT_CERTGEN_KEY_RSA:
        if (alg->rsa_bits <= 3072)
            return CLIENT_CERTGEN_RSA_3072_DER_CAP;
        if (alg->rsa_bits <= 7680)
            return CLIENT_CERTGEN_RSA_7680_DER_CAP;
        return CLIENT_CERTGEN_RSA_15360_DER_CAP;
    case CLIENT_CERTGEN_KEY_MLDSA:
        if (alg->mldsa_level == WC_ML_DSA_44)
            return CLIENT_CERTGEN_MLDSA_44_DER_CAP;
        if (alg->mldsa_level == WC_ML_DSA_65)
            return CLIENT_CERTGEN_MLDSA_65_DER_CAP;
        return CLIENT_CERTGEN_MLDSA_87_DER_CAP;
    case CLIENT_CERTGEN_KEY_SLHDSA:
        if (alg->slhdsa_param == SLHDSA_SHAKE128S)
            return CLIENT_CERTGEN_SLHDSA_128_DER_CAP;
        if (alg->slhdsa_param == SLHDSA_SHAKE192S)
            return CLIENT_CERTGEN_SLHDSA_192_DER_CAP;
        return CLIENT_CERTGEN_SLHDSA_256_DER_CAP;
    case CLIENT_CERTGEN_KEY_LMS:
        return CLIENT_CERTGEN_LMS_DER_CAP;
    case CLIENT_CERTGEN_KEY_XMSS:
        return CLIENT_CERTGEN_XMSS_DER_CAP;
    }
    return 0;
}

static word32 client_certgen_key_der_cap(
    const struct client_certgen_algorithm *alg)
{
    switch (alg->kind) {
    case CLIENT_CERTGEN_KEY_ECC:
        return CLIENT_CERTGEN_ECC_KEY_CAP;
    case CLIENT_CERTGEN_KEY_RSA:
        if (alg->rsa_bits <= 3072)
            return CLIENT_CERTGEN_RSA_3072_KEY_CAP;
        if (alg->rsa_bits <= 7680)
            return CLIENT_CERTGEN_RSA_7680_KEY_CAP;
        return CLIENT_CERTGEN_RSA_15360_KEY_CAP;
    case CLIENT_CERTGEN_KEY_MLDSA:
        if (alg->mldsa_level == WC_ML_DSA_44)
            return CLIENT_CERTGEN_MLDSA_44_KEY_CAP;
        if (alg->mldsa_level == WC_ML_DSA_65)
            return CLIENT_CERTGEN_MLDSA_65_KEY_CAP;
        return CLIENT_CERTGEN_MLDSA_87_KEY_CAP;
    case CLIENT_CERTGEN_KEY_SLHDSA:
        return CLIENT_CERTGEN_SLHDSA_KEY_CAP;
    case CLIENT_CERTGEN_KEY_LMS:
        return CLIENT_CERTGEN_LMS_KEY_CAP;
    case CLIENT_CERTGEN_KEY_XMSS:
        return CLIENT_CERTGEN_XMSS_KEY_CAP;
    }
    return 0;
}

static word32 client_certgen_hbs_state_cap(
    const struct client_certgen_algorithm *alg)
{
    switch (alg->kind) {
    case CLIENT_CERTGEN_KEY_LMS:
        return CLIENT_CERTGEN_LMS_STATE_CAP;
    case CLIENT_CERTGEN_KEY_XMSS:
        return CLIENT_CERTGEN_XMSS_STATE_CAP;
    default:
        return 0;
    }
}

static int client_certgen_hbs_write(
    const byte *priv, word32 priv_sz, void *context)
{
    struct client_certgen_hbs_state *state = context;

    if (state == NULL || state->data == NULL || priv_sz > state->cap)
        return WC_LMS_RC_WRITE_FAIL;
    XMEMCPY(state->data, priv, priv_sz);
    state->len = priv_sz;
    return WC_LMS_RC_SAVED_TO_NV_MEMORY;
}

static int client_certgen_hbs_read(
    byte *priv, word32 priv_sz, void *context)
{
    struct client_certgen_hbs_state *state = context;

    if (state == NULL || state->data == NULL || state->len == 0 ||
        state->len > priv_sz) {
        return WC_LMS_RC_READ_FAIL;
    }
    XMEMCPY(priv, state->data, state->len);
    return WC_LMS_RC_READ_TO_MEMORY;
}

static enum wc_XmssRc client_certgen_xmss_write(
    const byte *priv, word32 priv_sz, void *context)
{
    return client_certgen_hbs_write(priv, priv_sz, context) ==
        WC_LMS_RC_SAVED_TO_NV_MEMORY
        ? WC_XMSS_RC_SAVED_TO_NV_MEMORY : WC_XMSS_RC_WRITE_FAIL;
}

static enum wc_XmssRc client_certgen_xmss_read(
    byte *priv, word32 priv_sz, void *context)
{
    return client_certgen_hbs_read(priv, priv_sz, context) ==
        WC_LMS_RC_READ_TO_MEMORY
        ? WC_XMSS_RC_READ_TO_MEMORY : WC_XMSS_RC_READ_FAIL;
}

static int client_certgen_init_key(
    const struct client_certgen_algorithm *alg, void *key,
    struct client_certgen_hbs_state *hbs_state)
{
    int ret;

    switch (alg->kind) {
    case CLIENT_CERTGEN_KEY_ECC:
        return wc_ecc_init((ecc_key *)key);
    case CLIENT_CERTGEN_KEY_RSA:
        return wc_InitRsaKey((RsaKey *)key, NULL);
    case CLIENT_CERTGEN_KEY_MLDSA:
        return wc_MlDsaKey_Init((wc_MlDsaKey *)key, NULL, INVALID_DEVID);
    case CLIENT_CERTGEN_KEY_SLHDSA:
        return wc_SlhDsaKey_Init(
            (SlhDsaKey *)key, alg->slhdsa_param, NULL, INVALID_DEVID);
    case CLIENT_CERTGEN_KEY_LMS:
        ret = wc_LmsKey_Init((LmsKey *)key, NULL, INVALID_DEVID);
        if (ret != 0)
            return ret;
        ret = wc_LmsKey_SetParameters((LmsKey *)key, 2, 10, 4);
        if (ret != 0)
            return ret;
        ret = wc_LmsKey_SetWriteCb(
            (LmsKey *)key, client_certgen_hbs_write);
        if (ret != 0)
            return ret;
        ret = wc_LmsKey_SetReadCb((LmsKey *)key, client_certgen_hbs_read);
        if (ret != 0)
            return ret;
        return wc_LmsKey_SetContext((LmsKey *)key, hbs_state);
    case CLIENT_CERTGEN_KEY_XMSS:
        ret = wc_XmssKey_Init((XmssKey *)key, NULL, INVALID_DEVID);
        if (ret != 0)
            return ret;
        ret = wc_XmssKey_SetParamStr((XmssKey *)key, alg->xmss_param);
        if (ret != 0)
            return ret;
        ret = wc_XmssKey_SetWriteCb(
            (XmssKey *)key, client_certgen_xmss_write);
        if (ret != 0)
            return ret;
        ret = wc_XmssKey_SetReadCb(
            (XmssKey *)key, client_certgen_xmss_read);
        if (ret != 0)
            return ret;
        return wc_XmssKey_SetContext((XmssKey *)key, hbs_state);
    }
    return BAD_FUNC_ARG;
}

static int client_certgen_make_key(
    const struct client_certgen_algorithm *alg, void *key, WC_RNG *rng)
{
    int ret;

    switch (alg->kind) {
    case CLIENT_CERTGEN_KEY_ECC:
        return wc_ecc_make_key_ex(rng, 0, (ecc_key *)key, alg->ecc_curve);
    case CLIENT_CERTGEN_KEY_RSA:
        return wc_MakeRsaKey((RsaKey *)key, alg->rsa_bits, 65537, rng);
    case CLIENT_CERTGEN_KEY_MLDSA:
        ret = wc_MlDsaKey_SetParams((wc_MlDsaKey *)key,
            (byte)alg->mldsa_level);
        if (ret != 0)
            return ret;
        return wc_MlDsaKey_MakeKey((wc_MlDsaKey *)key, rng);
    case CLIENT_CERTGEN_KEY_SLHDSA:
        return wc_SlhDsaKey_MakeKey((SlhDsaKey *)key, rng);
    case CLIENT_CERTGEN_KEY_LMS:
        return wc_LmsKey_MakeKey((LmsKey *)key, rng);
    case CLIENT_CERTGEN_KEY_XMSS:
        return wc_XmssKey_MakeKey((XmssKey *)key, rng);
    }
    return BAD_FUNC_ARG;
}

static int client_certgen_key_to_der(
    const struct client_certgen_algorithm *alg, void *key, byte *der,
    word32 der_cap, const struct client_certgen_hbs_state *hbs_state)
{
    switch (alg->kind) {
    case CLIENT_CERTGEN_KEY_ECC:
        return wc_EccKeyToDer((ecc_key *)key, der, der_cap);
    case CLIENT_CERTGEN_KEY_RSA:
        return wc_RsaKeyToDer((RsaKey *)key, der, der_cap);
    case CLIENT_CERTGEN_KEY_MLDSA:
        return wc_MlDsaKey_KeyToDer((wc_MlDsaKey *)key, der, der_cap);
    case CLIENT_CERTGEN_KEY_SLHDSA:
        return wc_SlhDsaKey_KeyToDer((SlhDsaKey *)key, der, der_cap);
    case CLIENT_CERTGEN_KEY_LMS:
    case CLIENT_CERTGEN_KEY_XMSS:
        if (hbs_state == NULL || hbs_state->data == NULL ||
            hbs_state->len == 0 || hbs_state->len > der_cap) {
            return BUFFER_E;
        }
        XMEMCPY(der, hbs_state->data, hbs_state->len);
        return (int)hbs_state->len;
    }
    return BAD_FUNC_ARG;
}

static void client_certgen_free_key(
    const struct client_certgen_algorithm *alg, void *key)
{
    if (key == NULL)
        return;
    switch (alg->kind) {
    case CLIENT_CERTGEN_KEY_ECC:
        wc_ecc_free((ecc_key *)key);
        break;
    case CLIENT_CERTGEN_KEY_RSA:
        wc_FreeRsaKey((RsaKey *)key);
        break;
    case CLIENT_CERTGEN_KEY_MLDSA:
        wc_MlDsaKey_Free((wc_MlDsaKey *)key);
        break;
    case CLIENT_CERTGEN_KEY_SLHDSA:
        wc_SlhDsaKey_Free((SlhDsaKey *)key);
        break;
    case CLIENT_CERTGEN_KEY_LMS:
        wc_LmsKey_Free((LmsKey *)key);
        break;
    case CLIENT_CERTGEN_KEY_XMSS:
        wc_XmssKey_Free((XmssKey *)key);
        break;
    }
}

static void client_certgen_set_validity(Cert *cert)
{
    XMEMCPY(cert->beforeDate, CLIENT_CERTGEN_NOT_BEFORE,
        sizeof(CLIENT_CERTGEN_NOT_BEFORE) - 1);
    cert->beforeDateSz = sizeof(CLIENT_CERTGEN_NOT_BEFORE) - 1;
    XMEMCPY(cert->afterDate, CLIENT_CERTGEN_NOT_AFTER,
        sizeof(CLIENT_CERTGEN_NOT_AFTER) - 1);
    cert->afterDateSz = sizeof(CLIENT_CERTGEN_NOT_AFTER) - 1;
}

static void client_certgen_set_name(Cert *cert)
{
    XSTRNCPY(cert->subject.country, "US", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.state, "OR", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.locality, "Portland", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.org, "Peripheral Benchmark", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.unit, "TLS Client", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.commonName, "nrf52840-benchmark", CTC_NAME_SIZE);
}

static void benchmark_client_certgen(void)
{
    WC_RNG rng;
    const struct client_certgen_algorithm *alg = client_certgen_algorithm();
    struct benchmark_cpu_snapshot cpu_start;
    struct benchmark_cpu_snapshot cpu_end;
    struct benchmark_thread_cpu_snapshot thread_cpu_start;
    struct benchmark_thread_cpu_snapshot thread_cpu_end;
    struct benchmark_thread_cpu_delta thread_cpu_delta;
    struct benchmark_cpu_phase keygen_phase;
    struct benchmark_cpu_phase make_cert_phase;
    struct benchmark_cpu_phase sign_cert_phase;
    struct benchmark_cpu_phase parse_cert_phase;
    struct benchmark_cpu_phase key_export_phase;
    struct benchmark_stack_snapshot stacks;
    struct sys_memory_stats stats = {0};
    uint64_t client_cpu_cycles = 0;
    uint64_t client_cpu_us = 0;
    uint64_t phase_cpu_total_us = 0;
    uint64_t phase_lsu_total_cycles = 0;
    uint64_t phase_cpi_total_cycles = 0;
    uint32_t phase_dwt_samples = 0;
    bool dwt_supported = false;
    bool dwt_wrap_risk = false;
    uint32_t client_cpu_usage_bp = 0;
    uint32_t system_cpu_usage_bp = 0;
    uint32_t cpu_cycle_hz = benchmark_cpu_cycles_per_sec();
    int64_t start_ms;
    int64_t done_ms;
    int cert_der_sz = 0;
    int key_der_sz = 0;
    int ret;
    size_t key_struct_size;
    word32 cert_der_cap;
    word32 key_der_cap;
    word32 hbs_state_cap;
    unsigned char *cert_der = NULL;
    unsigned char *key_der = NULL;
    unsigned char *hbs_state_data = NULL;
    Cert *cert = NULL;
    void *key = NULL;
    DecodedCert *decoded = NULL;
    struct client_certgen_hbs_state hbs_state = {0};
    bool key_initialized = false;

    if (alg == NULL) {
        BENCH_OUT(
            "[BENCH_CERTGEN_RESULT] status=unsupported "
            "algorithm=%s builder=wolfssl_board "
            "generation_scope=client_self_signed_cert stage=algorithm\n",
            BENCH_CLIENT_CERTGEN_SIG);
        return;
    }

    (void)sys_heap_runtime_stats_reset_max(&wolfssl_heap.heap);
    key_struct_size = client_certgen_key_struct_size(alg);
    cert_der_cap = client_certgen_cert_der_cap(alg);
    key_der_cap = client_certgen_key_der_cap(alg);
    hbs_state_cap = client_certgen_hbs_state_cap(alg);
    key = k_heap_alloc(&wolfssl_heap, key_struct_size, K_NO_WAIT);
    if (hbs_state_cap > 0) {
        hbs_state_data = k_heap_alloc(&wolfssl_heap, hbs_state_cap, K_NO_WAIT);
        hbs_state.data = hbs_state_data;
        hbs_state.cap = hbs_state_cap;
    }
    if (key == NULL) {
        BENCH_OUT("[BENCH_CERTGEN_RESULT] status=fail stage=alloc error=-125\n");
        goto cleanup_alloc;
    }
    if (hbs_state_cap > 0 && hbs_state_data == NULL) {
        BENCH_OUT(
            "[BENCH_CERTGEN_RESULT] status=fail algorithm=%s "
            "builder=wolfssl_board generation_scope=client_self_signed_cert "
            "stage=hbs_state_alloc error=-125\n",
            alg->name);
        goto cleanup_alloc;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        BENCH_OUT("[BENCH_CERTGEN_RESULT] status=fail stage=rng error=%d\n",
            ret);
        goto cleanup_alloc;
    }

    thread_cpu_start = benchmark_thread_cpu_snapshot_get();
    cpu_start = benchmark_cpu_snapshot_get();
    start_ms = k_uptime_get();

    benchmark_cpu_phase_begin(&keygen_phase);
    ret = client_certgen_init_key(alg, key, &hbs_state);
    if (ret != 0) {
        benchmark_cpu_phase_end(&keygen_phase);
        BENCH_OUT(
            "[BENCH_CERTGEN_RESULT] status=fail algorithm=%s "
            "builder=wolfssl_board generation_scope=client_self_signed_cert "
            "stage=key_init error=%d\n",
            alg->name, ret);
        goto cleanup_rng;
    }
    key_initialized = true;
    ret = client_certgen_make_key(alg, key, &rng);
    benchmark_cpu_phase_end(&keygen_phase);
    if (ret != 0) {
        BENCH_OUT(
            "[BENCH_CERTGEN_RESULT] status=fail algorithm=%s "
            "builder=wolfssl_board generation_scope=client_self_signed_cert "
            "stage=keygen error=%d\n",
            alg->name, ret);
        goto cleanup_key;
    }

    cert_der = k_heap_alloc(&wolfssl_heap, cert_der_cap, K_NO_WAIT);
    key_der = k_heap_alloc(&wolfssl_heap, key_der_cap, K_NO_WAIT);
    cert = k_heap_alloc(&wolfssl_heap, sizeof(*cert), K_NO_WAIT);
    decoded = k_heap_alloc(&wolfssl_heap, sizeof(*decoded), K_NO_WAIT);
    if (cert_der == NULL || key_der == NULL || cert == NULL ||
        decoded == NULL) {
        BENCH_OUT(
            "[BENCH_CERTGEN_RESULT] status=fail algorithm=%s "
            "builder=wolfssl_board generation_scope=client_self_signed_cert "
            "stage=cert_alloc error=-125\n",
            alg->name);
        goto cleanup_key;
    }

    benchmark_cpu_phase_begin(&make_cert_phase);
    ret = wc_InitCert(cert);
    if (ret != 0) {
        benchmark_cpu_phase_end(&make_cert_phase);
        BENCH_OUT("[BENCH_CERTGEN_RESULT] status=fail stage=cert_init error=%d\n",
            ret);
        goto cleanup_key;
    }
    client_certgen_set_name(cert);
    client_certgen_set_validity(cert);
    cert->sigType = alg->sig_type;
    cert->selfSigned = 1;
    cert->daysValid = 3650;
    ret = wc_SetKeyUsage(cert, "digitalSignature");
    if (ret != 0) {
        benchmark_cpu_phase_end(&make_cert_phase);
        BENCH_OUT("[BENCH_CERTGEN_RESULT] status=fail stage=key_usage error=%d\n",
            ret);
        goto cleanup_key;
    }
    ret = wc_SetExtKeyUsage(cert, "clientAuth");
    if (ret != 0) {
        benchmark_cpu_phase_end(&make_cert_phase);
        BENCH_OUT("[BENCH_CERTGEN_RESULT] status=fail stage=eku error=%d\n",
            ret);
        goto cleanup_key;
    }
    ret = wc_MakeCert_ex(cert, cert_der, cert_der_cap, alg->key_type, key,
        &rng);
    benchmark_cpu_phase_end(&make_cert_phase);
    if (ret <= 0) {
        BENCH_OUT("[BENCH_CERTGEN_RESULT] status=fail stage=make_cert error=%d\n",
            ret);
        goto cleanup_key;
    }
    benchmark_cpu_phase_begin(&sign_cert_phase);
    cert_der_sz = wc_SignCert_ex(cert->bodySz, alg->sig_type,
        cert_der, cert_der_cap, alg->key_type, key, &rng);
    benchmark_cpu_phase_end(&sign_cert_phase);
    if (cert_der_sz <= 0) {
        BENCH_OUT("[BENCH_CERTGEN_RESULT] status=fail stage=sign_cert error=%d\n",
            cert_der_sz);
        goto cleanup_key;
    }

    benchmark_cpu_phase_begin(&parse_cert_phase);
    wc_InitDecodedCert(decoded, cert_der, (word32)cert_der_sz, NULL);
    ret = wc_ParseCert(decoded, CERT_TYPE, NO_VERIFY, NULL);
    wc_FreeDecodedCert(decoded);
    benchmark_cpu_phase_end(&parse_cert_phase);
    if (ret != 0) {
        BENCH_OUT("[BENCH_CERTGEN_RESULT] status=fail stage=parse_cert error=%d\n",
            ret);
        goto cleanup_key;
    }

    benchmark_cpu_phase_begin(&key_export_phase);
    key_der_sz = client_certgen_key_to_der(
        alg, key, key_der, key_der_cap, &hbs_state);
    benchmark_cpu_phase_end(&key_export_phase);
    if (key_der_sz <= 0) {
        BENCH_OUT("[BENCH_CERTGEN_RESULT] status=fail stage=key_export error=%d\n",
            key_der_sz);
        goto cleanup_key;
    }

    done_ms = k_uptime_get();
    cpu_end = benchmark_cpu_snapshot_get();
    thread_cpu_end = benchmark_thread_cpu_snapshot_get();
    benchmark_cpu_delta(
        &cpu_start, &cpu_end, &client_cpu_cycles,
        &client_cpu_usage_bp, &system_cpu_usage_bp);
    thread_cpu_delta = benchmark_thread_cpu_delta_get(
        &thread_cpu_start, &thread_cpu_end);
    client_cpu_us = k_cyc_to_us_floor64(client_cpu_cycles);
    phase_cpu_total_us = keygen_phase.us + make_cert_phase.us +
        sign_cert_phase.us + parse_cert_phase.us + key_export_phase.us;
    phase_lsu_total_cycles = keygen_phase.dwt_lsu_cycles +
        make_cert_phase.dwt_lsu_cycles + sign_cert_phase.dwt_lsu_cycles +
        parse_cert_phase.dwt_lsu_cycles + key_export_phase.dwt_lsu_cycles;
    phase_cpi_total_cycles = keygen_phase.dwt_cpi_cycles +
        make_cert_phase.dwt_cpi_cycles + sign_cert_phase.dwt_cpi_cycles +
        parse_cert_phase.dwt_cpi_cycles + key_export_phase.dwt_cpi_cycles;
    phase_dwt_samples = keygen_phase.dwt_samples + make_cert_phase.dwt_samples +
        sign_cert_phase.dwt_samples + parse_cert_phase.dwt_samples +
        key_export_phase.dwt_samples;
    dwt_supported = keygen_phase.dwt_supported || make_cert_phase.dwt_supported ||
        sign_cert_phase.dwt_supported || parse_cert_phase.dwt_supported ||
        key_export_phase.dwt_supported;
    dwt_wrap_risk = keygen_phase.dwt_wrap_risk ||
        make_cert_phase.dwt_wrap_risk || sign_cert_phase.dwt_wrap_risk ||
        parse_cert_phase.dwt_wrap_risk || key_export_phase.dwt_wrap_risk;
    (void)sys_heap_runtime_stats_get(&wolfssl_heap.heap, &stats);
    stacks = benchmark_stack_snapshot_get();
    BENCH_OUT(
        "[BENCH_CERTGEN_RESULT] status=success algorithm=%s "
        "builder=wolfssl_board generation_scope=client_self_signed_cert "
        "wall_ms=%lld client_cpu_cycles=%llu client_cpu_us=%llu "
        "client_cycle_hz=%u client_cpu_usage_bp=%u system_cpu_usage_bp=%u "
        "thread_main_cpu_bp=%u thread_sysworkq_cpu_bp=%u "
        "thread_bt_rx_cpu_bp=%u thread_bt_tx_cpu_bp=%u "
        "thread_idle_cpu_bp=%u thread_other_cpu_bp=%u "
        "keygen_cpu_us=%llu make_cert_cpu_us=%llu "
        "sign_cert_cpu_us=%llu parse_cert_cpu_us=%llu "
        "key_export_cpu_us=%llu phase_cpu_total_us=%llu "
        "phase_cpu_verify=%s "
        "keygen_lsu_cycles=%llu make_cert_lsu_cycles=%llu "
        "sign_cert_lsu_cycles=%llu parse_cert_lsu_cycles=%llu "
        "key_export_lsu_cycles=%llu phase_lsu_total_cycles=%llu "
        "keygen_cpi_cycles=%llu make_cert_cpi_cycles=%llu "
        "sign_cert_cpi_cycles=%llu parse_cert_cpi_cycles=%llu "
        "key_export_cpi_cycles=%llu phase_cpi_total_cycles=%llu "
        "phase_dwt_samples=%u dwt_counters_supported=%u "
        "dwt_wrap_risk=%u "
        "client_heap_current_bytes=%u client_heap_peak_bytes=%u "
        "client_heap_free_bytes=%u client_heap_capacity_bytes=%u "
        "thread_stack_used_bytes=%llu thread_stack_capacity_bytes=%llu "
        "thread_stack_peak_percent_bp=%u client_cert_der_bytes=%d "
        "client_key_der_bytes=%d client_cert_der_capacity_bytes=%u "
        "client_key_der_capacity_bytes=%u client_hbs_state_capacity_bytes=%u\n",
        alg->name, done_ms - start_ms,
        client_cpu_cycles, client_cpu_us, cpu_cycle_hz,
        client_cpu_usage_bp, system_cpu_usage_bp,
        thread_cpu_delta.main_bp, thread_cpu_delta.sysworkq_bp,
        thread_cpu_delta.bt_rx_bp, thread_cpu_delta.bt_tx_bp,
        thread_cpu_delta.idle_bp, thread_cpu_delta.other_bp,
        keygen_phase.us, make_cert_phase.us, sign_cert_phase.us,
        parse_cert_phase.us, key_export_phase.us, phase_cpu_total_us,
        phase_cpu_total_us <= client_cpu_us ? "pass" : "fail",
        keygen_phase.dwt_lsu_cycles, make_cert_phase.dwt_lsu_cycles,
        sign_cert_phase.dwt_lsu_cycles, parse_cert_phase.dwt_lsu_cycles,
        key_export_phase.dwt_lsu_cycles, phase_lsu_total_cycles,
        keygen_phase.dwt_cpi_cycles, make_cert_phase.dwt_cpi_cycles,
        sign_cert_phase.dwt_cpi_cycles, parse_cert_phase.dwt_cpi_cycles,
        key_export_phase.dwt_cpi_cycles, phase_cpi_total_cycles,
        phase_dwt_samples, dwt_supported ? 1U : 0U,
        dwt_wrap_risk ? 1U : 0U,
        (unsigned int)stats.allocated_bytes,
        (unsigned int)stats.max_allocated_bytes,
        (unsigned int)stats.free_bytes, WOLFSSL_HEAP_SIZE,
        stacks.used_bytes, stacks.capacity_bytes, stacks.peak_percent_bp,
        cert_der_sz, key_der_sz, cert_der_cap, key_der_cap, hbs_state_cap);

cleanup_key:
    if (key_initialized)
        client_certgen_free_key(alg, key);
cleanup_rng:
    wc_FreeRng(&rng);
cleanup_alloc:
    if (decoded != NULL)
        k_heap_free(&wolfssl_heap, decoded);
    if (key != NULL)
        k_heap_free(&wolfssl_heap, key);
    if (hbs_state_data != NULL)
        k_heap_free(&wolfssl_heap, hbs_state_data);
    if (cert != NULL)
        k_heap_free(&wolfssl_heap, cert);
    if (key_der != NULL)
        k_heap_free(&wolfssl_heap, key_der);
    if (cert_der != NULL)
        k_heap_free(&wolfssl_heap, cert_der);
}
#endif

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

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx) {
        BENCH_OUT("[BENCH_RESULT] status=fail stage=tls_setup error=ctx_new\n");
        return;
    }
#ifdef BENCH_USE_PQM4_MLKEM
    ret = wolfSSL_CTX_SetDevId(ctx, pqm4_mlkem_backend_dev_id());
    if (ret != WOLFSSL_SUCCESS) {
        BENCH_OUT("[BENCH_RESULT] status=fail stage=pqm4_device error=%d\n", ret);
        wolfSSL_CTX_free(ctx);
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
        return;
    }

    ret = wolfSSL_CTX_use_certificate_buffer(
        ctx, benchmark_client_cert, sizeof(benchmark_client_cert),
        WOLFSSL_FILETYPE_ASN1);
    if (ret != WOLFSSL_SUCCESS) {
        BENCH_OUT("[BENCH_RESULT] status=fail stage=client_cert error=%d\n", ret);
        wolfSSL_CTX_free(ctx);
        return;
    }
    ret = wolfSSL_CTX_use_PrivateKey_buffer(
        ctx, benchmark_client_key, sizeof(benchmark_client_key),
        WOLFSSL_FILETYPE_ASN1);
    if (ret != WOLFSSL_SUCCESS) {
        BENCH_OUT("[BENCH_RESULT] status=fail stage=client_key error=%d\n", ret);
        wolfSSL_CTX_free(ctx);
        return;
    }

    wolfSSL_CTX_SetIOSend(ctx, l2cap_wolfssl_send);
    wolfSSL_CTX_SetIORecv(ctx, l2cap_wolfssl_recv);
    ssl = wolfSSL_new(ctx);
    if (!ssl) {
        BENCH_OUT("[BENCH_RESULT] status=fail stage=tls_setup error=ssl_new\n");
        wolfSSL_CTX_free(ctx);
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
            BENCH_OUT(
                "[BENCH_RESULT] status=fail stage=tls_handshake error=%d "
                "tls_setup_ms=%lld client_cpu_cycles=%llu "
                "client_cpu_us=%llu client_cycle_hz=%u\n",
                error, setup_done_ms - setup_start_ms,
                client_cpu_cycles, client_cpu_us, cpu_cycle_hz);
            wolfSSL_free(ssl);
            wolfSSL_CTX_free(ctx);
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

    wolfSSL_SetAllocators(wolfssl_malloc, wolfssl_free, wolfssl_realloc);
    wolfSSL_Init();
#ifdef BENCH_CLIENT_CERTGEN
    benchmark_client_certgen();
    wolfSSL_Cleanup();
    return 0;
#endif

    bt_conn_auth_cb_register(NULL);

    if (bt_enable(NULL)) {
        BENCH_LOG("Bluetooth init failed\n");
        return 0;
    }
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
