#define _GNU_SOURCE

#include <errno.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef PERF_COUNT_HW_STALLED_CYCLES_FRONTEND
#define PERF_COUNT_HW_STALLED_CYCLES_FRONTEND 7
#endif
#ifndef PERF_COUNT_HW_STALLED_CYCLES_BACKEND
#define PERF_COUNT_HW_STALLED_CYCLES_BACKEND 8
#endif

#define CACHE_CONFIG(cache, op, result) \
    ((cache) | ((op) << 8) | ((result) << 16))

struct counter_spec {
    const char *name;
    uint32_t type;
    uint64_t config;
    int exclude_kernel;
    int convert_ns_to_ms;
};

struct counter {
    const struct counter_spec *spec;
    int fd;
};

struct counter_value {
    uint64_t value;
    uint64_t time_enabled;
    uint64_t time_running;
};

static volatile sig_atomic_t stop_requested;

static const struct counter_spec counter_specs[] = {
    {"task_clock_ms", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_TASK_CLOCK, 0, 1},
    {"cpu_clock_ms", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_CLOCK, 0, 1},
    {"cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES, 1, 0},
    {"instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS, 1, 0},
    {"cache_references", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES, 1, 0},
    {"cache_misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES, 1, 0},
    {"branch_instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS, 1, 0},
    {"branch_misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES, 1, 0},
    {"stalled_cycles_frontend", PERF_TYPE_HARDWARE,
     PERF_COUNT_HW_STALLED_CYCLES_FRONTEND, 1, 0},
    {"stalled_cycles_backend", PERF_TYPE_HARDWARE,
     PERF_COUNT_HW_STALLED_CYCLES_BACKEND, 1, 0},
    {"l1_dcache_loads", PERF_TYPE_HW_CACHE,
     CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1D, PERF_COUNT_HW_CACHE_OP_READ,
                  PERF_COUNT_HW_CACHE_RESULT_ACCESS),
     1, 0},
    {"l1_dcache_load_misses", PERF_TYPE_HW_CACHE,
     CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1D, PERF_COUNT_HW_CACHE_OP_READ,
                  PERF_COUNT_HW_CACHE_RESULT_MISS),
     1, 0},
    {"l1_icache_load_misses", PERF_TYPE_HW_CACHE,
     CACHE_CONFIG(PERF_COUNT_HW_CACHE_L1I, PERF_COUNT_HW_CACHE_OP_READ,
                  PERF_COUNT_HW_CACHE_RESULT_MISS),
     1, 0},
    {"dtlb_load_misses", PERF_TYPE_HW_CACHE,
     CACHE_CONFIG(PERF_COUNT_HW_CACHE_DTLB, PERF_COUNT_HW_CACHE_OP_READ,
                  PERF_COUNT_HW_CACHE_RESULT_MISS),
     1, 0},
    {"itlb_load_misses", PERF_TYPE_HW_CACHE,
     CACHE_CONFIG(PERF_COUNT_HW_CACHE_ITLB, PERF_COUNT_HW_CACHE_OP_READ,
                  PERF_COUNT_HW_CACHE_RESULT_MISS),
     1, 0},
    {"crypto_spec", PERF_TYPE_RAW, 0x77, 1, 0},
    {"simd_spec", PERF_TYPE_RAW, 0x74, 1, 0},
    {"context_switches", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES, 0, 0},
    {"cpu_migrations", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_MIGRATIONS, 0, 0},
    {"minor_faults", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS_MIN, 0, 0},
    {"major_faults", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS_MAJ, 0, 0},
};

static long perf_event_open(struct perf_event_attr *attr, pid_t pid)
{
    return syscall(__NR_perf_event_open, attr, pid, -1, -1, 0);
}

static void signal_handler(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

static int open_counter(pid_t pid, const struct counter_spec *spec)
{
    struct perf_event_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.type = spec->type;
    attr.size = sizeof(attr);
    attr.config = spec->config;
    attr.disabled = 0;
    attr.inherit = 1;
    attr.exclude_kernel = spec->exclude_kernel;
    attr.exclude_hv = 1;
    attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED |
                       PERF_FORMAT_TOTAL_TIME_RUNNING;

    return (int)perf_event_open(&attr, pid);
}

static double scaled_counter_value(const struct counter_value *value)
{
    if (value->time_running == 0 || value->time_enabled == 0) {
        return 0.0;
    }
    if (value->time_running == value->time_enabled) {
        return (double)value->value;
    }
    return (double)value->value *
           ((double)value->time_enabled / (double)value->time_running);
}

static void report_counters(
    FILE *out,
    const char *tag,
    const char *prefix,
    struct counter *counters,
    size_t counter_count
)
{
    size_t emitted = 0;

    for (size_t i = 0; i < counter_count; i++) {
        struct counter_value value;
        ssize_t bytes = read(counters[i].fd, &value, sizeof(value));

        if (bytes != (ssize_t)sizeof(value)) {
            continue;
        }
        double scaled = scaled_counter_value(&value);
        if (counters[i].spec->convert_ns_to_ms) {
            fprintf(out, "[BENCH_%s] %s_perf_%s=%.3f\n",
                    tag, prefix, counters[i].spec->name, scaled / 1000000.0);
        } else {
            fprintf(out, "[BENCH_%s] %s_perf_%s=%.0f\n",
                    tag, prefix, counters[i].spec->name, scaled);
        }
        emitted++;
    }
    fprintf(out, "[BENCH_%s] %s_perf_metrics_collected=%d\n",
            tag, prefix, emitted > 0 ? 1 : 0);
    fflush(out);
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s PID TAG PREFIX LOG\n", argv[0]);
        return 2;
    }

    pid_t pid = (pid_t)strtol(argv[1], NULL, 10);
    const char *tag = argv[2];
    const char *prefix = argv[3];
    const char *log_path = argv[4];
    struct counter counters[sizeof(counter_specs) / sizeof(counter_specs[0])];
    size_t counter_count = 0;

    if (pid <= 0) {
        return 2;
    }

    for (size_t i = 0; i < sizeof(counter_specs) / sizeof(counter_specs[0]); i++) {
        int fd = open_counter(pid, &counter_specs[i]);
        if (fd < 0) {
            continue;
        }
        counters[counter_count].spec = &counter_specs[i];
        counters[counter_count].fd = fd;
        counter_count++;
    }

    FILE *out = fopen(log_path, "a");
    if (out == NULL) {
        for (size_t i = 0; i < counter_count; i++) {
            close(counters[i].fd);
        }
        return 1;
    }
    fprintf(out, "[BENCH_%s] %s_perf_available=%d\n",
            tag, prefix, counter_count > 0 ? 1 : 0);
    fflush(out);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    while (!stop_requested) {
        pause();
    }

    report_counters(out, tag, prefix, counters, counter_count);
    fclose(out);

    for (size_t i = 0; i < counter_count; i++) {
        ioctl(counters[i].fd, PERF_EVENT_IOC_DISABLE, 0);
        close(counters[i].fd);
    }
    return counter_count > 0 ? 0 : 1;
}
