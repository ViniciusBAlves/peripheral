#!/usr/bin/env bash
set -u

DEFAULT_EVENTS=(
    task-clock
    cpu-clock
    cycles:u
    instructions:u
    cache-references:u
    cache-misses:u
    branch-instructions:u
    branch-misses:u
    stalled-cycles-frontend:u
    stalled-cycles-backend:u
    l1-dcache-loads:u
    l1-dcache-load-misses:u
    l1-icache-load-misses:u
    dtlb-load-misses:u
    itlb-load-misses:u
    r77:u
    r74:u
    context-switches
    cpu-migrations
    minor-faults
    major-faults
)

log_for_prefix() {
    local workdir="$1"
    local case_id="$2"
    local prefix="$3"

    if [[ "${prefix}" == "pi_broker" ]]; then
        printf '%s/logs/%s.broker.log\n' "${workdir}" "${case_id}"
    else
        printf '%s/logs/%s.gateway.log\n' "${workdir}" "${case_id}"
    fi
}

tag_for_prefix() {
    if [[ "$1" == "pi_broker" ]]; then
        printf 'SERVER\n'
    else
        printf 'GATEWAY\n'
    fi
}

setup_perf() {
    local workdir="$1"
    local out="${workdir}/perf-events.txt"
    local diag="${workdir}/logs/pi_hardware.log"
    local supported=()
    local event

    mkdir -p "${workdir}/logs"
    : > "${diag}"

    {
        printf '[BENCH_PI] uname='
        uname -a | tr ' ' '_'
        if grep -m1 '^Features' /proc/cpuinfo >/tmp/pi-features.$$ 2>/dev/null; then
            printf '[BENCH_PI] cpu_features=%s\n' \
                "$(cut -d: -f2- /tmp/pi-features.$$ | xargs | tr ' ' ',')"
            if grep -Eq '(^| )(aes|pmull|sha1|sha2|sha3)( |$)' /tmp/pi-features.$$; then
                printf '[BENCH_PI] cpu_crypto_features_present=1\n'
            else
                printf '[BENCH_PI] cpu_crypto_features_present=0\n'
            fi
            rm -f /tmp/pi-features.$$
        fi
    } >> "${diag}" 2>/dev/null || true

    if [[ -x "${workdir}/bin/pi_perf_counter" ]]; then
        printf '[BENCH_PI] perf_counter_helper_available=1\n' >> "${diag}"
    else
        printf '[BENCH_PI] perf_counter_helper_available=0\n' >> "${diag}"
    fi

    if ! command -v perf >/dev/null 2>&1; then
        printf '[BENCH_PI] perf_stat_available=0\n' >> "${diag}"
        : > "${out}"
        check_accelerated_instructions "${workdir}" >> "${diag}" 2>/dev/null || true
        return 0
    fi

    printf '[BENCH_PI] perf_stat_available=1\n' >> "${diag}"
    for event in "${DEFAULT_EVENTS[@]}"; do
        if timeout -k 1 2 perf stat --no-big-num -x, -e "${event}" \
            -- true >/dev/null 2>/dev/null; then
            supported+=("${event}")
        fi
    done

    (IFS=,; printf '%s\n' "${supported[*]}") > "${out}"
    printf '[BENCH_PI] perf_supported_events=%s\n' \
        "$(<"${out}")" >> "${diag}"

    check_accelerated_instructions "${workdir}" >> "${diag}" 2>/dev/null || true
}

check_accelerated_instructions() {
    local workdir="$1"
    local events_file="${workdir}/perf-events.txt"
    local tmp="${workdir}/logs/openssl-crypto-spec.perf"
    local helper_log="${workdir}/logs/openssl-crypto-helper.log"
    local openssl_pid helper_pid
    local count=""

    if [[ -x "${workdir}/bin/pi_perf_counter" ]] &&
        command -v openssl >/dev/null 2>&1; then
        : > "${helper_log}"
        openssl speed -elapsed -seconds 2 -evp aes-128-gcm \
            >/dev/null 2>/dev/null &
        openssl_pid=$!
        sleep 0.1
        setsid "${workdir}/bin/pi_perf_counter" \
            "${openssl_pid}" PI pi_accel "${helper_log}" \
            >/dev/null 2>/dev/null &
        helper_pid=$!
        wait "${openssl_pid}" 2>/dev/null || true
        kill -INT -- "-${helper_pid}" "${helper_pid}" 2>/dev/null || true
        sleep 0.2
        cat "${helper_log}" 2>/dev/null || true
        count=$(awk -F= '/pi_accel_perf_crypto_spec=/ {print $2; exit}' \
            "${helper_log}" 2>/dev/null)
        if [[ -n "${count}" ]]; then
            awk -v value="${count}" 'BEGIN {
                printf("[BENCH_PI] openssl_accelerated_instructions_executed=%d\n",
                    value > 0 ? 1 : 0)
            }'
            return 0
        fi
    fi

    if [[ ! -s "${events_file}" ]] || ! grep -q 'r77:u' "${events_file}"; then
        printf '[BENCH_PI] openssl_crypto_spec_check=unsupported\n'
        return 0
    fi
    if ! command -v openssl >/dev/null 2>&1; then
        printf '[BENCH_PI] openssl_crypto_spec_check=no_openssl\n'
        return 0
    fi

    perf stat --no-big-num -x, -e r77:u -o "${tmp}" \
        -- openssl speed -elapsed -seconds 1 -evp aes-128-gcm \
        >/dev/null 2>/dev/null || true
    count=$(awk -F, '$1 ~ /^[[:space:]]*[0-9]+([.][0-9]+)?[[:space:]]*$/ {
        gsub(/[[:space:]]/, "", $1); print $1; exit
    }' "${tmp}" 2>/dev/null)
    if [[ -n "${count}" ]]; then
        printf '[BENCH_PI] openssl_crypto_spec=%s\n' "${count}"
        awk -v value="${count}" 'BEGIN {
            printf("[BENCH_PI] openssl_accelerated_instructions_executed=%d\n",
                value > 0 ? 1 : 0)
        }'
    else
        printf '[BENCH_PI] openssl_crypto_spec_check=unavailable\n'
    fi
}

start_perf() {
    local workdir="$1"
    local case_id="$2"
    local prefix="$3"
    local pid="$4"
    local tag log events out err perf_pid
    local helper="${workdir}/bin/pi_perf_counter"

    tag="$(tag_for_prefix "${prefix}")"
    log="$(log_for_prefix "${workdir}" "${case_id}" "${prefix}")"
    events="$(cat "${workdir}/perf-events.txt" 2>/dev/null || true)"
    out="${workdir}/logs/${case_id}.${prefix}.perf.csv"
    err="${workdir}/logs/${case_id}.${prefix}.perf.err"
    perf_pid="${workdir}/logs/${case_id}.${prefix}.perf.pid"

    if [[ -x "${helper}" ]]; then
        setsid "${helper}" "${pid}" "${tag}" "${prefix}" "${log}" \
            >/dev/null 2>"${err}" < /dev/null &
        echo $! > "${perf_pid}"
        printf 'helper\n' > "${workdir}/logs/${case_id}.${prefix}.perf.mode"
        return 0
    fi

    if [[ -z "${events}" ]] || ! command -v perf >/dev/null 2>&1; then
        printf '[BENCH_%s] %s_perf_available=0\n' "${tag}" "${prefix}" >> "${log}"
        return 0
    fi

    : > "${out}"
    : > "${err}"
    setsid perf stat --no-big-num -x, -e "${events}" -p "${pid}" \
        -o "${out}" -- sleep 86400 >/dev/null 2>"${err}" < /dev/null &
    echo $! > "${perf_pid}"
    printf 'perf\n' > "${workdir}/logs/${case_id}.${prefix}.perf.mode"
    printf '[BENCH_%s] %s_perf_available=1\n' "${tag}" "${prefix}" >> "${log}"
}

stop_perf() {
    local workdir="$1"
    local case_id="$2"
    local prefix="$3"
    local tag log out err perf_pid pid metrics
    local mode_file mode

    tag="$(tag_for_prefix "${prefix}")"
    log="$(log_for_prefix "${workdir}" "${case_id}" "${prefix}")"
    out="${workdir}/logs/${case_id}.${prefix}.perf.csv"
    err="${workdir}/logs/${case_id}.${prefix}.perf.err"
    perf_pid="${workdir}/logs/${case_id}.${prefix}.perf.pid"
    mode_file="${workdir}/logs/${case_id}.${prefix}.perf.mode"
    mode="$(cat "${mode_file}" 2>/dev/null || true)"

    if [[ -f "${perf_pid}" ]]; then
        pid="$(cat "${perf_pid}" 2>/dev/null || true)"
        if [[ -n "${pid}" ]]; then
            kill -INT -- "-${pid}" "${pid}" 2>/dev/null || true
            sleep 0.2
            kill -TERM -- "-${pid}" "${pid}" 2>/dev/null || true
        fi
        rm -f "${perf_pid}"
    fi

    rm -f "${mode_file}"
    if [[ "${mode}" == "helper" ]]; then
        return 0
    fi

    metrics=$(awk -F, -v tag="${tag}" -v prefix="${prefix}" '
        function clean_metric(event) {
            sub(/:.*/, "", event)
            if (event == "task-clock") return "task_clock_ms"
            if (event == "cpu-clock") return "cpu_clock_ms"
            if (event == "r77") return "crypto_spec"
            if (event == "r74") return "simd_spec"
            gsub(/-/, "_", event)
            gsub(/[^A-Za-z0-9_]/, "", event)
            return tolower(event)
        }
        $1 ~ /^[[:space:]]*[0-9]+([.][0-9]+)?[[:space:]]*$/ {
            value=$1
            gsub(/[[:space:]]/, "", value)
            if ($3 ~ /(time elapsed|seconds user|seconds sys)/) {
                next
            }
            metric=clean_metric($3)
            if (metric != "") {
                printf("[BENCH_%s] %s_perf_%s=%s\n",
                    tag, prefix, metric, value)
                count++
            }
        }
        END {
            printf("[BENCH_%s] %s_perf_metrics_collected=%d\n",
                tag, prefix, count > 0 ? 1 : 0)
        }
    ' "${out}" 2>/dev/null)

    if [[ -n "${metrics}" ]]; then
        printf '%s\n' "${metrics}" >> "${log}"
    else
        printf '[BENCH_%s] %s_perf_metrics_collected=0\n' \
            "${tag}" "${prefix}" >> "${log}"
    fi
    if [[ -s "${err}" ]]; then
        tr '\n' ' ' < "${err}" |
            sed 's/[[:space:]][[:space:]]*/_/g; s/[^A-Za-z0-9_.,:;=-]/_/g' |
            awk -v tag="${tag}" -v prefix="${prefix}" '{
                if (length($0) > 0) {
                    printf("[BENCH_%s] %s_perf_error=%s\n",
                        tag, prefix, substr($0, 1, 160))
                }
            }' >> "${log}"
    fi
}

case "${1:-}" in
    setup)
        setup_perf "${2:?usage: pi_perf_metrics.sh setup WORKDIR}"
        ;;
    start)
        start_perf \
            "${2:?usage: pi_perf_metrics.sh start WORKDIR CASE_ID PREFIX PID}" \
            "${3:?usage: pi_perf_metrics.sh start WORKDIR CASE_ID PREFIX PID}" \
            "${4:?usage: pi_perf_metrics.sh start WORKDIR CASE_ID PREFIX PID}" \
            "${5:?usage: pi_perf_metrics.sh start WORKDIR CASE_ID PREFIX PID}"
        ;;
    stop)
        stop_perf \
            "${2:?usage: pi_perf_metrics.sh stop WORKDIR CASE_ID PREFIX}" \
            "${3:?usage: pi_perf_metrics.sh stop WORKDIR CASE_ID PREFIX}" \
            "${4:?usage: pi_perf_metrics.sh stop WORKDIR CASE_ID PREFIX}"
        ;;
    *)
        printf 'usage: pi_perf_metrics.sh setup|start|stop ...\n' >&2
        exit 2
        ;;
esac
