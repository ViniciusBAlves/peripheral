#ifndef BENCHMARK_DWT_H
#define BENCHMARK_DWT_H

#include <cmsis_core.h>
#include <zephyr/types.h>

struct benchmark_dwt_snapshot {
    uint32_t cyccnt;
    uint8_t cpicnt;
    uint8_t exccnt;
    uint8_t sleepcnt;
    uint8_t lsucnt;
    uint8_t foldcnt;
    bool cycle_supported;
    bool event_supported;
};

struct benchmark_dwt_delta {
    uint32_t cyccnt;
    uint8_t cpicnt;
    uint8_t exccnt;
    uint8_t sleepcnt;
    uint8_t lsucnt;
    uint8_t foldcnt;
    bool cycle_supported;
    bool event_supported;
};

static inline struct benchmark_dwt_snapshot benchmark_dwt_snapshot_get(void)
{
    struct benchmark_dwt_snapshot snapshot = {0};

    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    snapshot.cycle_supported = (DWT->CTRL & DWT_CTRL_NOCYCCNT_Msk) == 0U;
    snapshot.event_supported = (DWT->CTRL & DWT_CTRL_NOPRFCNT_Msk) == 0U;
    if (snapshot.cycle_supported) {
        DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
    }
    if (snapshot.event_supported) {
        DWT->CTRL |= DWT_CTRL_CPIEVTENA_Msk |
                     DWT_CTRL_EXCEVTENA_Msk |
                     DWT_CTRL_SLEEPEVTENA_Msk |
                     DWT_CTRL_LSUEVTENA_Msk |
                     DWT_CTRL_FOLDEVTENA_Msk;
    }
    __DSB();
    __ISB();

    if (snapshot.cycle_supported) {
        snapshot.cyccnt = DWT->CYCCNT;
    }
    if (snapshot.event_supported) {
        snapshot.cpicnt = (uint8_t)DWT->CPICNT;
        snapshot.exccnt = (uint8_t)DWT->EXCCNT;
        snapshot.sleepcnt = (uint8_t)DWT->SLEEPCNT;
        snapshot.lsucnt = (uint8_t)DWT->LSUCNT;
        snapshot.foldcnt = (uint8_t)DWT->FOLDCNT;
    }
    return snapshot;
}

static inline struct benchmark_dwt_delta benchmark_dwt_delta_get(
    const struct benchmark_dwt_snapshot *start)
{
    struct benchmark_dwt_snapshot end = benchmark_dwt_snapshot_get();
    struct benchmark_dwt_delta delta = {
        .cycle_supported = start->cycle_supported && end.cycle_supported,
        .event_supported = start->event_supported && end.event_supported,
    };

    if (delta.cycle_supported) {
        delta.cyccnt = end.cyccnt - start->cyccnt;
    }
    if (delta.event_supported) {
        delta.cpicnt = (uint8_t)(end.cpicnt - start->cpicnt);
        delta.exccnt = (uint8_t)(end.exccnt - start->exccnt);
        delta.sleepcnt = (uint8_t)(end.sleepcnt - start->sleepcnt);
        delta.lsucnt = (uint8_t)(end.lsucnt - start->lsucnt);
        delta.foldcnt = (uint8_t)(end.foldcnt - start->foldcnt);
    }
    return delta;
}

#define BENCHMARK_DWT_FORMAT \
    "dwt_cycle_counter_supported=%u dwt_event_counters_supported=%u " \
    "dwt_cyccnt=%u dwt_cpicnt=%u dwt_exccnt=%u dwt_sleepcnt=%u " \
    "dwt_lsucnt=%u dwt_foldcnt=%u dwt_cycle_counter_width_bits=32 " \
    "dwt_event_counter_width_bits=8 dwt_counts_are_modulo=1"

#define BENCHMARK_DWT_VALUES(delta) \
    (unsigned int)(delta).cycle_supported, \
    (unsigned int)(delta).event_supported, \
    (unsigned int)(delta).cyccnt, \
    (unsigned int)(delta).cpicnt, \
    (unsigned int)(delta).exccnt, \
    (unsigned int)(delta).sleepcnt, \
    (unsigned int)(delta).lsucnt, \
    (unsigned int)(delta).foldcnt

#endif
