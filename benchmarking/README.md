# Raw BLE TLS/MQTT Benchmark

This directory is an isolated benchmark workspace. It does not modify or use
the build products, generated certificates, or source files in the parent
`peripheral` application.

## Architecture

The nRF52840 runs wolfSSL and sends TLS records over a BLE LE Credit-Based
L2CAP channel on PSM `0x0080`. A Raspberry Pi bridges that channel to a local
Mosquitto TCP listener. Mosquitto uses OpenSSL 3.5+ and its available
post-quantum providers.

The firmware contains every supported TLS key-exchange group and a trust bundle
for the server CAs in the selected run. The server offers one group and one
certificate per case. The nRF52840 uses one fixed ECDSA client identity for
mutual TLS, so the benchmark signature algorithm describes the server side.

SLH-DSA signs the server certificate chain. Its TLS `CertificateVerify` leaf
remains ECDSA because the current TLS stacks do not negotiate SLH-DSA as a TLS
signature scheme. Both values are recorded explicitly in the CSV.

RSA-PSS-15360 cases are emitted as `known_unsupported` by default because the
normal wolfSSL `USE_FAST_MATH` profile caps TLS RSA keys at 8192 bits. They are
not silently substituted with RSA-PSS-7680. The runner handles them by default
with a separate RSA-16384 firmware profile that disables `USE_FAST_MATH`, as
described below.

## Connection Configuration

Before running a hardware benchmark, configure the four connection values in
`benchmarking/config.json`. The repository currently uses:

```json
{
  "serial-device": "/dev/ttyACM0",
  "pi-host": "user@ip",
  "ssh-key": "~/.ssh/[INSERT_SSH_KEY]",
  "ble-addr": "00:00:00:00:00:00"
}
```

- `serial-device`: nRF52840DK serial port used for `BENCH_*` telemetry.
- `pi-host`: Raspberry Pi SSH destination in `user@host` form.
- `ssh-key`: private SSH key; `~` and environment variables are expanded.
- `ble-addr`: BLE address advertised by the nRF52840DK.

`run_benchmarks.py` loads this file automatically. A different file can be
selected with `--config`:

```bash
python benchmarking/run_benchmarks.py \
  --config benchmarking/config-lab.json \
  --cases benchmarking/cases/<cases>.csv \
  --seed 123
```

The corresponding CLI options (`--serial-device`, `--pi-host`, `--ssh-key`,
and `--ble-addr`) remain available as one-run overrides and take precedence
over JSON values. The runner validates that all four JSON fields exist and
rejects unknown fields, which helps catch misspelled configuration names.

## Raspberry Pi

Configure SSH key authentication first. Then install the gateway dependencies:

```bash
ssh thiago@10.12.194.1 'bash -s' < benchmarking/gateway/setup_pi_gateway.sh
PI_HOST=thiago@10.12.194.1 \
SSH_KEY="$HOME/.ssh/id_ed25519_pi_gateway" \
benchmarking/gateway/deploy_pi_gateway.sh
```

These standalone gateway shell scripts use `PI_HOST` and `SSH_KEY`; the Python
benchmark runner uses the matching values from `config.json`.

The benchmark user must be able to start `ble_mqtt_bridge` with non-interactive
sudo. Add a narrow sudoers rule for the deployed binary if needed.

## Generate Cases

```bash
python benchmarking/generate_cases.py \
  --seed 123 \
  --iterations 5 \
  --warmup-iterations 1 \
  --separate-pqc-classic
```

The generator refuses to overwrite an existing CSV. The printed path is used
as `--cases` below.

## Schedule-Only Dry Run

`--dry-run` intentionally exits immediately after creating the manifests and
complete seeded schedule. It does **not** run Docker, build or flash firmware,
connect through SSH, open the serial device, or execute any benchmark attempt:

```bash
python benchmarking/run_benchmarks.py \
  --cases benchmarking/cases/<cases>.csv \
  --seed 123 \
  --dry-run
```

Two complete sessions are created per case by default. Every warmup or measured
attempt for normally supported cases is a separate block shuffled by the run
seed. Cases marked `known_unsupported` are moved to the end of the schedule.
Their case order is seeded, but every attempt belonging to one such case stays
contiguous so the large-RSA firmware profile is flashed only once.

Use `--limit N` to execute only the first `N` cases after seeded shuffling:

```bash
python benchmarking/run_benchmarks.py \
  --cases benchmarking/cases/<cases>.csv \
  --seed 123 \
  --limit 2
```

## Hardware Run

To execute the benchmark, use the same command **without `--dry-run`**:

```bash
# CachyOS / Arch Linux
sudo pacman -S --needed python-pyserial

# Portable fallback when a distro package is unavailable
python -m pip install --user --break-system-packages \
  -r benchmarking/requirements.txt

python benchmarking/run_benchmarks.py \
  --cases benchmarking/cases/<cases>.csv \
  --seed 123
```

The command automatically reads the serial device, Pi SSH destination, SSH
key, and board BLE address from `benchmarking/config.json`.

The runner generates every certificate first, builds and flashes one universal
firmware image, then executes the saved schedule. Use `--skip-build
--skip-flash` only when the already flashed image was built from the same
universal credential bundle.

Attempt timeouts are selected automatically from the KEM and signature cost.
`--attempt-timeout-sec N` overrides that policy. Gateway readiness has a
separate 20-second timeout, so a failed BLE channel does not consume a full
cryptographic timeout.

The adaptive base timeout is 60 seconds for ECDSA, 45 seconds for ML-DSA and
RSA-3072, 75/120/180 seconds for SLH-DSA-128/192/256, and 120/240 seconds for
RSA-7680/15360. ML-KEM-512/768/1024 adds 20/30/45 seconds respectively.
`--limit` limits cases, not the warmup and measured blocks inside each case.

Between blocks, the runner terminates the bridge and broker, resets the Pi
Bluetooth controller, and waits for a fresh `BENCH_READY` marker. The firmware
also bounds its disconnect wait and reboots itself only if the controller
teardown callback is lost. This recovery does not rebuild or reflash the board.

The firmware keeps TFM at `FP_MAX_BITS=16384` for RSA-15360 compatibility, but
routes P-256/P-384/P-521 through wolfSSL's Cortex-M SP-ECC backend. Without
that split, every ECC operation inherits the oversized TFM representation and
P-256 handshakes become tens of seconds slower.

### RSA-15360 reflash profile

RSA-PSS-15360 cases automatically use the separate large-RSA firmware profile.
This is equivalent to passing `--reflash-known-unsupported-rsa` and is enabled
by default:

```bash
python benchmarking/run_benchmarks.py \
  --cases benchmarking/cases/<cases>.csv \
  --seed 123
```

The runner creates independent CA bundles and firmware images for:

- `fast-math`: the normal image using `USE_FAST_MATH`;
- `integer-heap-16384`: disables fast math, enables
  `USE_INTEGER_HEAP_MATH`, and raises `RSA_MAX_SIZE`,
  `WC_MAX_RSA_BITS`, and the pinned wolfSSL ASN/TLS buffers to 16384 bits.

The runner executes the normal shuffled schedule first. It then flashes the
large-RSA image once and runs every RSA-PSS-15360 case at the end, with all
attempts of each case contiguous. The profile is recorded in `attempts.csv`,
`summary.csv`, and the serial readiness marker.

This fallback cannot be combined with `--skip-build` or `--skip-flash` when
large-RSA cases are selected. Pass `--no-reflash-known-unsupported-rsa` to
retain the old behavior of recording those cases as unsupported without
executing them.

### Default pqm4 ML-KEM backend

The nRF52840 uses pqm4's Cortex-M4F ML-KEM implementation by default, including
the ML-KEM component of hybrid groups. Use `--mlkem-backend wolfssl` only when
an explicit wolfSSL baseline is required:

```bash
python benchmarking/run_benchmarks.py \
  --cases benchmarking/cases/simple_cases.csv \
  --seed 123 \
  --limit 1 \
  --mlkem-backend wolfssl
```

The runner clones a pinned pqm4 revision into `benchmarking/work/pqm4`.
wolfSSL still owns TLS 1.3, X.509, signatures and the transcript; its
`CryptoCb` interface delegates ML-KEM-512/768/1024 key generation,
encapsulation and decapsulation to pqm4. The selected backend is saved in
`mlkem_backend.txt`, `attempts.csv`, `summary.csv`, and the serial
`BENCH_READY` marker. pqm4 replaces only ML-KEM operations; certificate
signatures and verification remain handled by wolfSSL.

The `m4fstack` implementation is intentionally used instead of `m4fspeed`.
Both use Cortex-M4F assembly, while `m4fstack` leaves more stack headroom for
the TLS call chain on the 256 KiB nRF52840.

## Measurements

`raw_handshake_ms` covers only `wolfSSL_connect()`. `tls_setup_ms` includes
context, CA, client certificate, key, group, and `WOLFSSL` object setup.
`mqtt_connect_ms` ends at MQTT CONNACK. `full_connect_ms` starts at TLS setup,
while `end_to_end_ms` starts when the firmware L2CAP channel becomes ready.
Gateway-side BLE and TCP setup durations are recorded separately.

The firmware also records the following per-attempt values:

- `client_cpu_cycles` is the Zephyr runtime-statistics delta for the main
  thread during `wolfSSL_connect()`. `client_cpu_ms` is converted by the
  firmware with Zephyr's kernel time API rather than calculated by Python.
  Runs produced before this change used the DWT handshake-span counter and are
  therefore not directly comparable with the new active-thread CPU values.
- `client_heap_peak_bytes` is the wolfSSL heap high-water mark. Its maximum is
  reset immediately before each handshake, making the value local to the
  attempt instead of cumulative since boot.
- `client_cpu_usage_percent` is the main benchmark thread's share of the
  processor during `wolfSSL_connect()`. `system_cpu_usage_percent` is the
  non-idle share across all Zephyr threads and interrupts over the same
  runtime-statistics window.
- `firmware_flash_used_bytes` and `firmware_static_ram_used_bytes` come from
  the Zephyr linker symbols `_flash_used` and `_image_ram_size`; their matching
  capacity columns come from the board configuration. Static RAM includes
  reserved stacks, buffers, BSS, and the wolfSSL heap arena, while the heap
  current/peak columns describe dynamic occupancy inside that arena.
- `thread_stack_used_bytes` is the aggregate stack high-water usage reported
  by Thread Analyzer, `thread_stack_capacity_bytes` is the monitored aggregate
  capacity, and `thread_stack_peak_percent` is the fullest individual thread.
- `communication_overhead_ms` is the cumulative wall time spent inside the
  wolfSSL L2CAP send and receive callbacks, from TLS handshake start through
  MQTT CONNACK. It and the cryptographic operation durations use Zephyr
  monotonic uptime ticks rather than CPU-cycle conversion.
- `kem_keygen_ms`, `kem_encapsulation_ms`, and `kem_decapsulation_ms` measure
  the ML-KEM primitive calls made on the client. In a normal TLS client
  handshake, key generation and decapsulation occur on the board while
  encapsulation occurs on the server, so client encapsulation can be zero.
- `classical_kex_keygen_ms` and `classical_kex_shared_secret_ms` measure the
  ECDHE/X25519 component. `kem_client_total_ms` includes only the primitives
  belonging to the selected group: ML-KEM for pure ML-KEM, classic operations
  for ECDHE, and both for hybrid groups. Speculative classic key generation by
  wolfSSL remains visible in the raw classic field but is excluded from a pure
  ML-KEM total.
- `x509_chain_signature_verify_ms` measures wolfSSL `ConfirmSignature()` calls
  while validating the server certificate chain. The legacy
  `certificate_signature_verify_ms` column contains the same value.
- `tls_certificate_verify_signature_verify_ms` measures processing and
  cryptographic verification of the server TLS 1.3 `CertificateVerify`.
- `mtls_signature_generate_ms` measures the signature primitive used by the
  nRF52840 to produce its client-authentication `CertificateVerify`.
  `client_signature_total_ms` is the sum of X.509 verification, server
  `CertificateVerify` verification, and client mTLS signing.
- `server_kem_encapsulation_ms` and `server_certificate_verify_sign_ms` are
  measured inside the Raspberry Pi OpenSSL EVP calls. The runner preloads
  `server_crypto_metrics.so` into Mosquitto, so these values exclude BLE/TCP
  transport and are read from `[BENCH_SERVER]` records in `broker.log`.
- `l2cap_tx_packets`, `l2cap_tx_bytes`, `l2cap_rx_packets`, and
  `l2cap_rx_bytes` cover TLS plus MQTT CONNECT/CONNACK. Packet counts are
  Zephyr L2CAP SDUs, not Bluetooth Link Layer packets or radio transmissions.
- `l2cap_tx_retries`, `l2cap_tx_wait_ms`, and `l2cap_rx_overflows` expose
  transport pressure caused by exhausted TX buffers, radio backpressure, and
  insufficient RX ring-buffer capacity.
- `client_icache_hits` and `client_icache_misses` come directly from the
  nRF52840 NVMC instruction-cache profiling registers over the
  `wolfSSL_connect()` interval. The runner derives requests and hit/miss
  percentages from those hardware counters.
- `client_memory_access_counters_supported` is `0` on the nRF52840. Its
  Cortex-M4 has no PMU event counters for globally retired data-memory reads
  and writes. The DWT `LSUCNT` register counts extra load/store-unit cycles,
  saturates at eight bits, and is therefore deliberately not mislabeled as
  read/write operations. Use the exact L2CAP byte counters above when the
  quantity of interest is communication data moved during the attempt.

`summary.csv` contains the mean of these fields for successful measured
attempts. The raw values remain available in each case's `attempts.csv`.

Each run writes immutable artifacts below `results/<timestamp>_<seed>/`,
including the input CSV, run and session manifests, per-case attempts and logs,
and the aggregate `summary.csv`.

## Tests

```bash
python -m unittest discover -s benchmarking/tests -v
python -m py_compile benchmarking/*.py benchmarking/benchmarklib/*.py
```
