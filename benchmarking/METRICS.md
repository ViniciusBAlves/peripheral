# Benchmark Configuration and Metrics

This document describes the default execution environment and every metric
written by the handshake, transfer, certificate-generation, and standalone KEM
benchmarks. Values in `attempts.csv`, `handshakes.csv`, and
`transmissions.csv` are per execution. A `summary.csv` contains aggregates and
must not be used as if it contained independent observations.

## Default execution configuration

### Shared host and board configuration

The default local configuration is read from [`config.json`](config.json).
Command-line options override these values.

| Setting | Current default | Meaning |
|---|---:|---|
| Board console | `/dev/serial/by-id/usb-SEGGER_J-Link_001050210143-if00` | Structured board output when PPK2 mode is disabled. |
| Raspberry Pi | `thiago@10.12.194.1` | BLE L2CAP gateway and TLS server host. |
| SSH key | `~/.ssh/id_ed25519_pi_gateway` | Non-interactive gateway authentication. |
| BLE address | `E3:6A:17:06:2E:B5` | Configured random device address; a configured address skips BLE scanning. |
| PPK2 device | `/dev/serial/by-id/usb-Nordic_Semiconductor_PPK2_D80A67C3209D-if01` | PPK2 command/data CDC interface. |
| PPK2 voltage | `3000 mV` | Source Meter output and energy-integration voltage. |
| Saved power trace | `100 samples/s` | Downsampled CSV trace rate; integration remains at 100 ksample/s. |

The standard TLS/MQTT runner in [`run_benchmarks.py`](run_benchmarks.py) uses:

- nRF Connect SDK `v3.3.0` and board `nrf52840dk/nrf52840`;
- pqm4 `m4fstack` ML-KEM by default; `wolfssl` is optional;
- automatic server selection: OpenSSL/Mosquitto where supported and the
  wolfSSL server for cases that require it;
- two sessions per case;
- the `iterations` and `warmup_iterations` values from the case CSV in every
  session;
- three reconnect retries after the initial connection, with 5 seconds between
  retries;
- a hard 60-second TLS/MQTT attempt deadline;
- gateway readiness timeout 20 seconds, board readiness timeout 20 seconds,
  and board re-arm timeout 30 seconds;
- UART 115200 baud when the board console is used;
- Raspberry Pi adapter `hci0`, random BLE address type, PSM `0x0080`, and
  requested L2CAP MTU 672 bytes;
- Raspberry Pi Wi-Fi disabled for the complete run;
- server-only TLS authentication by default. `--mtls-mode` enables the fixed
  client identity;
- PPK2 disabled by default. `--power-profiler` enables Source Meter mode and
  BLE control telemetry.

[`generate_cases.py`](generate_cases.py) defaults to five measured iterations,
one warm-up iteration, and a random seed when `--seed` is omitted. The runner
uses the CSV seed unless a seed is explicitly supplied. Scheduling is shuffled
reproducibly with that seed.

### BLE, L2CAP, TLS, and MQTT firmware defaults

The firmware configuration comes from [`prj.conf`](firmware/prj.conf), the
nRF52840 board override, and [`main.c`](firmware/src/main.c):

| Setting | Default | Source |
|---|---:|---|
| BLE connection interval | 20 ms | `BT_LE_CONN_PARAM_INIT(16, 16, 0, 3200)`; each unit is 1.25 ms. |
| Peripheral latency | 0 | No skipped connection events. |
| Supervision timeout | 32 s | 3200 units of 10 ms. |
| L2CAP security level | `BT_SECURITY_L1` | No BLE link-layer authentication requirement; TLS provides application security. |
| L2CAP PSM | `0x0080` | Dynamic LE Credit-Based Channel. |
| Normal RX SDU MTU | 672 bytes | Eleven receive buffers, 7392 bytes total payload capacity. |
| Transfer RX/TX SDU MTU | 5120 bytes | One large receive buffer and one serialized transmit buffer. |
| ACL data size | 251 bytes | Controller ACL TX/RX buffers. |
| Main thread priority | 12 | Below Bluetooth servicing threads. |
| nRF52840 main stack | 6144 bytes | Board override. |
| nRF52840 system workqueue stack | 2048 bytes | Board override. |
| libc malloc arena | 0 bytes | wolfSSL uses a dedicated Zephyr heap. |
| wolfSSL heap | 201 KiB | Dedicated `K_HEAP_DEFINE` arena on nRF52840. |
| MQTT keepalive | 60 s | Encoded in the benchmark MQTT CONNECT packet. |
| MQTT CONNACK timeout | 30 s | Firmware wait after the TLS handshake. |
| Reboot after session | enabled | `BENCH_REBOOT_AFTER_SESSION=1`. |
| Verbose firmware logging | disabled | Structured benchmark records remain enabled. |

The transfer runner [`run_transfer_benchmarks.py`](run_transfer_benchmarks.py)
reuses the standard runner with transfer mode and a 5120-byte requested MTU.
Each case uses one TLS/MQTT connection containing all repetitions. The payload
set is 128 B, 1 KiB, 8 KiB, 16 KiB, 32 KiB, and 64 KiB in both directions,
with MQTT QoS 1. Each payload operation has a 30-second firmware deadline; the
complete round is capped at 600 seconds.

The on-device certificate runner defaults to one iteration, seed 123, UART
115200, 30-second board readiness, a 3600-second per-algorithm ceiling, NCS
`v3.3.0`, and board `nrf5340dk/nrf5340/cpuapp`. The standalone KEM runner
defaults to five iterations, seed 123, pqm4 `m4fstack`, UART 115200, 30-second
board readiness, a 900-second per-algorithm ceiling, NCS `v3.3.0`, and the same
nRF5340 board target. These are the literal defaults of
[`run_certificate_benchmarks.py`](run_certificate_benchmarks.py) and
[`run_kem_benchmarks.py`](run_kem_benchmarks.py), even when another board is
selected explicitly for a run.

## Common conventions

- Times ending in `_ms` are milliseconds. Firmware operation timers originate
  as Zephyr uptime ticks, are converted to microseconds in
  [`benchmark_metrics.c`](firmware/src/benchmark_metrics.c), then converted to
  milliseconds by Python.
- Cycles are raw hardware or Zephyr runtime counters and are not estimated from
  wall time.
- Byte counts are binary bytes. KiB means 1024 bytes.
- Percentages are in the range 0 to 100. Firmware basis-point fields are
  divided by 100 by the runner.
- Empty fields mean unavailable or not applicable. They must not be converted
  to zero.
- `status` is normally `success`, `fail`, `timeout`, `unsupported`, or
  `cancelled`. `message` names the failed stage; `error_code` carries the
  firmware, TLS, host-process, or timeout error.
- `mean`, `median`, `min`, `max`, and `stddev` have their usual meanings.
  Standard deviation is the sample standard deviation. Handshake p95 uses the
  rounded nearest-rank index implemented by
  [`aggregate()`](benchmarklib/metrics.py). Transfer p95 is linearly
  interpolated. Transfer `ci95` is `1.96 * sample_stddev / sqrt(n)`.
- Summary names preserve the source metric and prepend the aggregation:
  `mean_*`, `median_*`, `p95_*`, `min_*`, `max_*`, `stddev_*`, and `ci95_*`.
  Status totals use `success_count`, `fail_count`, `timeout_count`,
  `unsupported_count`, `cancelled_count`, or `not_run_count` where applicable.

## TLS/MQTT handshake benchmark

### Attempt identity, scheduling, and outcome

- `attempt_index`: monotonically increasing row index in the run.
- `schedule_index`: seeded job order identifier.
- `session`: session number for the case.
- `attempt_in_session`: position inside that session.
- `warmup`: 1 for a warm-up row and 0 for a measured row.
- `status`: final attempt outcome.
- `reconnect_count`: reconnect retry index; zero means the initial connection.
- `mtls_mode`: 1 when mutual TLS was requested.
- `mlkem_backend`: `pqm4-m4fstack`, `wolfssl`, or not applicable.
- `rsa_profile`, `firmware_profile`: selected build profiles.
- `error_code`, `message`: terminal error and stage.

Jobs are created by [`build_jobs()`](benchmarklib/scheduler.py). Numeric
summaries exclude warm-ups and unsuccessful rows.

### PKI and algorithm identity

- `pki_chain_id`: unique root/intermediate/leaf profile.
- `pki_kind`: homogeneous or heterogeneous PKI category.
- `root_sig_alg`, `intermediate_sig_alg`, `leaf_sig_alg`: algorithms used at
  each certificate-chain level.
- `root_cert_der_bytes`, `intermediate_cert_der_bytes`,
  `leaf_cert_der_bytes`: generated DER file sizes.
- `server_chain_bytes`: leaf DER plus intermediate DER. The root is provisioned
  on the client and is not transmitted by the server.
- `kex_group`, `kex_nist_level`: TLS key-exchange group and configured NIST
  security level.
- `kex_public_key_bytes`, `kex_ciphertext_bytes`,
  `kex_shared_secret_bytes`: algorithm metadata from
  [`algorithms.py`](benchmarklib/algorithms.py), not packet-capture estimates.
- `cert_sig_alg`, `sig_nist_level`: case signature and configured level.
- `sig_public_key_bytes`, `sig_private_key_bytes`, `sig_signature_bytes`:
  algorithm metadata for the selected signature.
- `certificate_verify_alg`: actual server TLS 1.3 `SignatureScheme` observed by
  the firmware.
- `certificate_verify_scheme_id`: raw two-byte TLS scheme identifier.
- `expected_certificate_verify_alg`: expected scheme from the case.
- `certificate_verify_match`: 1 only when observed and expected schemes match.
- `client_certificate_verify_alg`, `client_identity_id`: client scheme and
  identity used under mTLS; empty without mTLS.

The server scheme is recorded inside wolfSSL's TLS 1.3
`DoTls13CertificateVerify()` path and passed to
[`benchmark_record_server_certificate_verify_scheme()`](firmware/src/benchmark_metrics.c).

### Connection and handshake times

The board collects the main intervals in
[`start_secure_mqtt_session()`](firmware/src/main.c):

- `ble_l2cap_connect_ms`: gateway wall time to establish the BLE L2CAP CoC.
- `gateway_tcp_connect_ms`: gateway wall time to connect to the local server.
- `tls_setup_ms`: creation/configuration of wolfSSL context and session,
  loading the selected root, setting the key-share group, and allocations. It
  ends before `wolfSSL_connect()`.
- `raw_handshake_ms`: wall time from immediately before the first
  `wolfSSL_connect()` call until TLS success.
- `mqtt_connect_ms`: MQTT CONNECT write through validated CONNACK.
- `full_connect_ms`: TLS setup start through MQTT CONNACK.
- `end_to_end_ms`: established L2CAP channel through MQTT CONNACK.
- `communication_overhead_ms`: accumulated time inside wolfSSL L2CAP send and
  receive callbacks while metrics are active. It includes buffer/credit waits
  and can overlap `raw_handshake_ms`.
- `handshake_throughput_hps`: `1000 / mean_raw_handshake_ms`.
- `connections_per_second`: `1000 / mean_full_connect_ms`.

These intervals have different boundaries and must not be added together.

### Cryptographic operation times

wolfSSL operation hooks call
[`benchmark_crypto_metric_start()`](firmware/src/benchmark_metrics.c) and
[`benchmark_metric_stop()`](firmware/src/benchmark_metrics.c):

- `kem_keygen_ms`, `kem_encapsulation_ms`, `kem_decapsulation_ms`: ML-KEM
  primitive durations on the client. A TLS client normally decapsulates while
  the server encapsulates.
- `classical_kex_keygen_ms`: ECDHE/X25519 ephemeral key generation.
- `classical_kex_shared_secret_ms`: ECDHE/X25519 shared-secret derivation.
- `kem_client_total_ms`: ML-KEM fields for pure ML-KEM, classical fields for
  pure ECDHE, and both sets for a hybrid group.
- `certificate_signature_verify_ms`: accumulated X.509 chain signature
  verification timer.
- `x509_chain_signature_verify_ms`: compatibility alias for the same value.
- `tls_certificate_verify_signature_verify_ms`: processing and verification
  time for the server TLS `CertificateVerify` message.
- `mtls_signature_generate_ms`: client TLS `CertificateVerify` signature time;
  zero/empty without mTLS.
- `client_signature_total_ms`: X.509 verification plus server
  `CertificateVerify` verification plus optional mTLS signing.
- `server_kem_encapsulation_ms`: server OpenSSL EVP encapsulation hook time.
- `server_certificate_verify_sign_ms`: server OpenSSL EVP
  `CertificateVerify` signing hook time.

Suboperation timers can be nested in `raw_handshake_ms`. Their sum is not a
second measurement of the handshake.

### CPU and scheduler metrics

Snapshots are taken by `benchmark_cpu_snapshot_get()` and reduced by
`benchmark_cpu_delta()` in [`main.c`](firmware/src/main.c):

- `client_cpu_cycles`: current benchmark-thread execution-cycle delta during
  `wolfSSL_connect()`.
- `client_cycle_hz`: hardware cycle frequency.
- `client_cpu_ms`: board conversion of `client_cpu_cycles` to time.
- `client_cpu_usage_percent`: benchmark-thread cycles divided by total system
  cycles across the handshake, including communication waits.
- `system_cpu_usage_percent`: all non-idle system cycles divided by total
  system cycles across the handshake.
- `average_cpu_usage_percent`: benchmark processing CPU usage after subtracting
  measured L2CAP callback wall time.
- `peak_cpu_usage_percent`: largest processing-only CPU percentage among the
  measured wolfSSL processing intervals.

`average_cpu_usage_percent` is not peak CPU. Neither value isolates a single
cryptographic primitive unless its marker interval is analyzed separately.

### Instruction cache and ARM DWT

- `client_icache_hits`, `client_icache_misses`: nRF NVMC instruction-cache
  counter deltas.
- `client_icache_requests`: hits plus misses.
- `client_icache_hit_percent`: `100 * hits / requests`.
- `client_icache_miss_percent`: `100 * misses / requests`.
- `client_memory_access_counters_supported`: whether true read/write counters
  exist. Zero means no such metric was measured.
- `dwt_cycle_counter_supported`, `dwt_event_counters_supported`: DWT support
  flags.
- `dwt_cyccnt`: 32-bit elapsed core-cycle counter.
- `dwt_cpicnt`: extra cycles spent on multi-cycle instructions.
- `dwt_exccnt`: exception-processing overhead cycles.
- `dwt_sleepcnt`: cycles attributed to sleep.
- `dwt_lsucnt`: extra load/store-unit cycles, not a memory-access count.
- `dwt_foldcnt`: folded instructions.
- `dwt_cycle_counter_width_bits`, `dwt_event_counter_width_bits`: 32 and 8.
- `dwt_counts_are_modulo`: 1 because subtraction is modulo counter width.

The snapshot and delta helpers are in
[`benchmark_dwt.h`](firmware/src/benchmark_dwt.h). The 8-bit event counters can
wrap repeatedly in long operations and are diagnostic indicators, not complete
event totals.

### Heap, flash, RAM, stack, and receive ring

- `client_heap_current_bytes`: wolfSSL heap allocated at MQTT CONNACK.
- `client_heap_peak_bytes`: maximum simultaneous wolfSSL heap allocation since
  the pre-handshake peak reset.
- `client_heap_free_bytes`: free dedicated heap at collection time.
- `client_heap_capacity_bytes`: configured wolfSSL heap arena.
- `client_heap_peak_usage_percent`: `100 * peak / capacity`.
- `firmware_flash_used_bytes`: Zephyr linker symbol `_flash_used`.
- `firmware_flash_capacity_bytes`: `CONFIG_FLASH_SIZE * 1024`.
- `firmware_flash_usage_percent`: `100 * used / capacity`.
- `firmware_static_ram_used_bytes`: linker symbol `_image_ram_size`.
- `firmware_ram_capacity_bytes`: `CONFIG_SRAM_SIZE * 1024`.
- `firmware_static_ram_usage_percent`: `100 * image RAM / physical RAM`.
- `thread_stack_used_bytes`: sum of stack high-water usage across analyzed
  threads.
- `thread_stack_capacity_bytes`: sum of analyzed stack capacities.
- `thread_stack_peak_percent`: highest individual thread stack percentage, not
  total stack usage divided by total stack capacity.
- `l2cap_rx_ring_peak_bytes`: maximum queued TLS receive payload.
- `l2cap_rx_ring_capacity_bytes`: configured receive-pool payload capacity.
- `l2cap_rx_ring_peak_percent`: `100 * peak / capacity`.

`firmware_static_ram_used_bytes` already includes statically reserved heap and
stack capacity. A no-double-counting occupied-RAM estimate is:

```text
static_ram_used - heap_capacity - stack_capacity + heap_peak + stack_used
```

Heap peaks are global to wolfSSL and do not identify one algorithm's exclusive
allocation.

### L2CAP traffic

- `l2cap_tx_packets`, `l2cap_rx_packets`: successfully handled application
  SDUs while metrics are active.
- `l2cap_tx_bytes`, `l2cap_rx_bytes`: SDU payload bytes. They exclude BLE
  headers and link-layer retransmissions.
- `l2cap_tx_retries`: retries caused by buffer or credit pressure.
- `l2cap_tx_wait_ms`: accumulated allocation/retry wait; it does not include
  every radio completion wait.
- `l2cap_rx_overflows`: receive overflow events.

Updates are made by the L2CAP callbacks in [`main.c`](firmware/src/main.c) and
the counters in [`benchmark_metrics.c`](firmware/src/benchmark_metrics.c).

### Power and energy

Power fields exist for `client_kem`, `mlkem`, `classical_kex`,
`client_signature`, `handshake`, and `total_execution`. For each prefix:

- `*_duration_ms = sample_count / 100000 * 1000`;
- `*_avg_current_ua = sum(current_ua) / sample_count`;
- `*_peak_current_ua = max(current_ua)`;
- `*_charge_uc = sum(current_ua) / 100000`;
- `*_energy_uj = charge_uc * VDD_mV / 1000`.

Consequently, the energy columns are `client_kem_energy_uj`,
`mlkem_energy_uj`, `classical_kex_energy_uj`,
`client_signature_energy_uj`, `handshake_energy_uj`, and
`total_execution_energy_uj`. Each has matching `_duration_ms`, `_charge_uc`,
`_avg_current_ua`, and `_peak_current_ua` columns with the formulas above.

Additional fields are:

- `power_status`: `success`, `incomplete`, `error`, or `unsupported`;
- `power_profiler_sample_count`: native samples received;
- `power_profiler_window_count`: completed total-execution GPIO windows;
- `power_profiler_vdd_mv`: voltage used for energy integration;
- `power_profiler_output_samples_per_second`: saved trace rate, not integration
  rate.

GPIO decoding and integration are implemented by
[`PowerProfilerCapture._measurements()`](benchmarklib/power_profiler.py). D7
marks total execution, D6 handshake, D5 aggregate KEX, and D4 signature. D5
alone identifies ML-KEM, D5+D4 identifies classical ECDHE/X25519, and D4 alone
identifies signature processing. Disjoint pulses are combined without charging
the gaps.

## Bidirectional transfer benchmark

`handshakes.csv` uses the handshake metrics above. Each row in
`transmissions.csv` describes one MQTT QoS 1 transfer.

### Identity and integrity

- `case_id`, `round_index`, `round_try`, `attempt_index`, `schedule_index`:
  case, round, retry, and seeded-order identifiers.
- `round_complete`: 1 only when every operation in the round completed.
- `transfer_order`: seeded order within the TLS/MQTT connection.
- `iteration`: repetition from the input CSV.
- `direction`: `server_to_device` or `device_to_server`.
- `payload_bytes`: application payload only.
- `status`: `success`, `fail`, `timeout`, or `not_run`.
- `qos`: always 1.
- `packet_id`: MQTT packet identifier.
- `reconnect_count`: retry index for the enclosing connection.
- `expected_sha256`, `received_sha256`: deterministic payload digests.
- `integrity_match`: 1 only when size, pattern, and digest agree.
- `message`: transfer or enclosing-round failure information.

### Transfer time and goodput

- `client_transfer_ms`: device-side payload send/read interval.
- `server_transfer_ms`: corresponding server-side interval when reported.
- `ack_latency_ms`: interval after payload completion through QoS/application
  acknowledgment completion.
- `end_to_end_ms`: device payload start through all required acknowledgments.
- `goodput_kib_s`: currently calculated as
  `payload_bytes / end_to_end_ms`. Numerically this is decimal kB/s because
  bytes/ms equals kB/s with a 1000-byte kB; despite the historical field name,
  it is not an exact KiB/s value. Use the recorded `payload_bytes` and
  `end_to_end_ms` to convert to true KiB/s when required.

### Transfer resource and wire metrics

- `client_cpu_cycles`, `client_cycle_hz`, `client_cpu_ms`,
  `client_cpu_usage_percent`, `system_cpu_usage_percent`: transfer-window CPU
  metrics collected like the handshake equivalents.
- `client_heap_current_bytes`, `client_heap_peak_bytes`: dedicated heap state
  for the operation.
- `thread_stack_used_bytes`, `thread_stack_capacity_bytes`: stack telemetry if
  emitted by the active firmware path.
- L2CAP and DWT fields have the same definitions as the handshake fields, but
  cover one transfer operation.
- `mqtt_wire_bytes`: payload plus MQTT PUBLISH fixed/variable header bytes.
- `mqtt_protocol_overhead_bytes`: MQTT PUBLISH header only; it excludes TLS,
  L2CAP, BLE, PUBACK, and application ACK bytes.
- `transfer_duration_ms`, `transfer_charge_uc`, `transfer_energy_uj`,
  `transfer_avg_current_ua`, `transfer_peak_current_ua`: PPK2 GPIO window for
  that transfer. `power_status` indicates validity.

Transfer summaries group rows by `case_id + direction + payload_bytes` and
provide success/fail/timeout/not-run counts plus mean, median, p95, min, max,
sample standard deviation, and 95% confidence half-width for end-to-end time,
goodput, and energy. Only successful, complete rounds enter numeric aggregates;
energy additionally requires `power_status=success`.

## On-device certificate benchmark

The device flow in [`certgen_main.c`](firmware/src/certgen_main.c) performs key
generation, builds a self-signed X.509 body, signs it, and verifies it.

### Identity and host-process fields

- `attempt_index`, `component`, `owner`: attempt identity and execution owner.
- `cert_sig_alg`, `sig_family`, `sig_nist_level`: selected signature metadata.
- `sig_public_key_bytes`, `sig_private_key_bytes`, `sig_signature_bytes`:
  expected/reported algorithm sizes.
- `builder`, `generation_scope`: implementation and operations included.
- `status`, `error_code`, `message`: result and failed stage.
- `wall_ms`, `cpu_ms`: total wall and CPU time. On device, CPU time is derived
  from thread cycles; in host-only mode it comes from process usage.
- `user_cpu_ms`, `sys_cpu_ms`, `max_rss_kb`: host-only process user time,
  system time, and peak resident set size.

### Generated artifacts

- `server_root_der_bytes`, `server_root_crt_bytes`,
  `server_intermediate_crt_bytes`, `server_leaf_crt_bytes`,
  `server_chain_crt_bytes`, `server_key_bytes`: host-generated server artifact
  sizes.
- `client_ca_crt_bytes`, `client_cert_crt_bytes`, `client_key_bytes`,
  `client_csr_der_bytes`, `client_csr_pem_bytes`: host-generated client
  artifact sizes.
- `output_total_bytes`: total output selected by the active generation scope.
- `certificate_der_bytes`: on-device generated DER certificate size.

### On-device operation metrics

- `certificate_keygen_ms`: key-pair generation.
- `certificate_make_body_ms`: `wc_MakeCert_ex()` unsigned X.509 body creation.
- `certificate_sign_ms`: `wc_SignCert_ex()` certificate signature.
- `certificate_verify_ms`: generated certificate loading and verification.
- `certificate_total_ms`: sum of the four operation timers, also used as the
  on-device wall value.
- `client_cpu_cycles`, `client_cycle_hz`: certificate worker thread cycles and
  frequency.
- `client_active_cycles`, `client_idle_cycles`, `client_total_cycles`: Zephyr
  whole-system runtime deltas.
- `client_cpu_active_percent`: `100 * active_cycles / total_cycles`.
- `client_cpu_idle_percent`: `100 * idle_cycles / total_cycles`.
- DWT and heap fields have the common definitions above.
- `client_stack_used_bytes`, `client_stack_free_bytes`: high-water usage and
  remaining space of the certificate worker/main thread observed by the
  diagnostic path.
- `timeout_elapsed_ms`: elapsed attempt time from the latest progress report.
- `timeout_stage_elapsed_ms`: time spent in the stage active at timeout.
- `progress_reports`: number of periodic `[BENCH_CERT_PROGRESS]` records used
  to preserve diagnostics when the final result is absent.

Certificate summaries include status counts, host process means, artifact
sizes, means for all four operations and total, median/p95/stddev for signing,
last timeout stage, and maximum observed CPU, DWT, heap, and stack values.

## Standalone KEM benchmark

The device flow in [`kem_bench_main.c`](firmware/src/kem_bench_main.c) executes
recipient key generation, encapsulation/key agreement, decapsulation, and a
shared-secret comparison.

- `attempt_index`, `component`, `owner`: attempt identity and execution owner.
- `kex_group`, `kex_family`, `kex_nist_level`: selected KEM/group metadata.
- `kex_public_key_bytes`, `kex_private_key_bytes`,
  `kex_ciphertext_bytes`, `kex_shared_secret_bytes`: expected output sizes.
- `mlkem_backend`: pqm4 or wolfSSL implementation.
- `operation_model`: `kem`, `hybrid_kem`, or `dh_key_agreement`.
- `status`, `error_code`, `message`: result and failed stage.
- `wall_ms`: host-observed command-to-result time.
- `cpu_ms`: `client_cpu_cycles / client_cycle_hz * 1000`.
- `kem_keygen_ms`: recipient key generation.
- `kem_encapsulation_ms`: ML-KEM encapsulation and/or sender ephemeral key plus
  classical shared-secret calculation.
- `kem_decapsulation_ms`: ML-KEM decapsulation and/or recipient classical
  shared-secret calculation.
- `kem_total_ms`: sum of keygen, encapsulation, and decapsulation.
- `secrets_match`: 1 only when both generated shared secrets are identical.
- `client_cpu_cycles`, `client_cycle_hz`: worker-thread cycle delta and
  frequency.
- DWT and heap fields have the common definitions above.

KEM summaries provide status counts; mean, median, p95, and sample standard
deviation for keygen, encapsulation, decapsulation, and total; mean CPU time;
maximum heap peak; and mean DWT counters. After one timeout, remaining
iterations of that algorithm are recorded as `cancelled`.

## Summary interpretation

Handshake `summary.csv` uses only non-warmup successful attempts for numeric
aggregates. Resource peaks use the maximum successful attempt, free heap uses
the minimum, and `total_l2cap_rx_overflows` is a sum. A case is `success` only
when every measured attempt succeeds; otherwise it can be `mixed`, `fail`,
`timeout`, or `unsupported`.

Do not expect the cryptographic submetrics, communication overhead, and CPU
time to add exactly to `raw_handshake_ms`. They use nested intervals, different
clocks or ownership domains, and include scheduler, TLS record, transcript,
allocation, and protocol work not represented by a primitive-specific timer.
