# Raw BLE TLS/MQTT Benchmark

This directory is an isolated benchmark workspace. It does not modify or use
the build products, generated certificates, or source files in the parent
`peripheral` application.

## Architecture

The nRF5340 application core runs wolfSSL and sends TLS records over a BLE LE Credit-Based
L2CAP channel on PSM `0x0080`. A Raspberry Pi bridges that channel to a local
TLS server on `127.0.0.1:8883`. By default, normal cases use a Mosquitto TCP
listener backed by OpenSSL 3.5+ and its available post-quantum providers, while
LMS/HSS and XMSS cases use a small wolfSSL TLS server with a minimal MQTT
CONNACK responder.

The Bluetooth controller runs on the nRF5340 network core using Zephyr's
`hci_ipc` child image. The runner therefore builds and flashes the application
and network cores together with sysbuild.

The firmware contains every supported TLS key-exchange group and all 17 public
roots used by the suite. Each PKI is `root -> intermediate -> leaf`.
The root remains on the nRF5340 and Raspberry Pi; the TLS server transmits only
`leaf + intermediate`. Authentication is server-only by default. The optional
`--mtls-mode` build additionally embeds one fixed ECDSA P-256 client identity
and makes the selected server backend require its certificate.

The generator creates six homogeneous chains (ECDSA P-256/384/521 and ML-DSA
44/65/87) and 22 heterogeneous chains. In heterogeneous chains a heavier
SLH-DSA, RSA-PSS, LMS, or XMSS root signs a lighter intermediate, and that
intermediate signs a leaf using the same light algorithm. `cert_sig_alg`
therefore always describes the leaf and the real TLS 1.3 `CertificateVerify`.

By default, LMS/HSS and XMSS act only as roots; their intermediate and leaf use
either ECDSA P-521 or ML-DSA-87. OpenSSL/Mosquitto cannot load chains rooted in
these stateful algorithms, so the runner uses wolfSSL for those cases when
`--server-backend auto` is selected.

Pass `--include-heavy-homogeneous` to add 11 opt-in homogeneous X.509 chains:
all six SLH-DSA-SHAKE variants, all three RSA-PSS sizes, LMS, and XMSS. In
these profiles one algorithm signs the root, intermediate, and leaf
certificates. RSA-PSS also supplies the TLS leaf key and `CertificateVerify`.
SLH-DSA, LMS, and XMSS keep an ECDSA TLS leaf key because the installed TLS
stacks do not expose those algorithms as TLS 1.3 `SignatureScheme` values.

RSA-PSS-3072, RSA-PSS-7680, and RSA-PSS-15360 all run in the normal wolfSSL
`USE_FAST_MATH` firmware profile. RSA-PSS-15360 is not silently substituted
with RSA-PSS-7680.

The runner first tries one universal root bundle and requires 32 KiB of free
flash. If needed, it packs roots largest-first into the minimum practical set
of firmware profiles and executes each profile contiguously to minimize
reflashing.

## Connection Configuration

Before running a hardware benchmark, configure the four connection values in
`benchmarking/config.json`. The repository currently uses:

```json
{
  "serial-device": "/dev/serial/by-id/usb-SEGGER_J-Link_001050032722-if02",
  "pi-host": "user@ip",
  "ssh-key": "~/.ssh/[INSERT_SSH_KEY]",
  "ble-addr": "00:00:00:00:00:00"
}
```

- `serial-device`: nRF5340DK application-core VCOM used for `BENCH_*` telemetry.
- `pi-host`: Raspberry Pi SSH destination in `user@host` form.
- `ssh-key`: private SSH key; `~` and environment variables are expanded.
- `ble-addr`: BLE address advertised by the nRF5340DK.

`run_benchmarks.py` loads this file automatically. A different file can be
selected with `--config`:

```bash
python benchmarking/run_benchmarks.py \
  --config benchmarking/config-lab.json \
  --cases benchmarking/cases/<cases>.csv \
  --seed 123
```

The corresponding CLI options remain available as one-run overrides and take
precedence over JSON values. The four connection fields are required.

## Certificate Generation Benchmark

`run_certificate_benchmarks.py` builds and flashes a dedicated nRF5340
firmware that generates a self-signed X.509 certificate on the application
core for every signature algorithm enabled by the input CSV:

```bash
python benchmarking/run_certificate_benchmarks.py \
  --cases benchmarking/cases/20260703_220208_benchmark_cases.csv \
  --iterations 5 \
  --seed 123
```

Each attempt reports separate `certificate_keygen_ms`,
`certificate_make_body_ms`, `certificate_sign_ms`, and
`certificate_verify_ms` values, plus total time, DER size, CPU cycles, and
wolfSSL heap usage. The firmware supports ECDSA, RSA-PSS, ML-DSA,
SLH-DSA-SHAKE `128s/128f`, `192s/192f`, and `256s/256f`, LMS/HSS, and XMSS
cases from `benchmarklib/algorithms.py`. Large RSA key
generation and the small-memory SLH/LMS/XMSS implementations can take many
minutes. Every attempt has a hard 15-minute ceiling; after a timeout, the
remaining iterations of that signature are recorded as `cancelled` and the
runner advances to the next algorithm.

This mode measures a fresh key pair and a self-signed CA certificate whose
X.509 signature uses the selected algorithm. It does not reproduce the normal
benchmark's three-level server chain.
ML-DSA signing uses randomized FIPS 204 signing and rejection sampling, so its
signing distribution is expected to be wider than ECDSA. The summary includes
median, p95, and standard deviation for `certificate_sign_ms`.

Use `--skip-build --skip-flash` to reuse the certificate firmware already on
the board. The runner resets the DK after opening its VCOM so `BENCH_READY`
is not lost. The previous Docker/OpenSSL server-chain benchmark remains
available with `--host-only`.

## KEM Operations Benchmark

`run_kem_benchmarks.py` builds a separate nRF5340 image and measures recipient
key generation, encapsulation and decapsulation directly on the application
core. It validates that both sides derive the same secret and reports operation
times, public/private key sizes, ciphertext and shared-secret sizes, CPU
cycles, CPU time, and wolfSSL heap usage.

```bash
python benchmarking/run_kem_benchmarks.py \
  --cases benchmarking/cases/all_kem_cases.csv \
  --iterations 5 \
  --seed 123
```

The default ML-KEM backend is the pinned `pqm4-m4fstack` implementation. Use
`--mlkem-backend wolfssl` for a direct wolfSSL comparison. For ECDHE groups,
the CSV labels the operation model as `dh_key_agreement`: encapsulation means
ephemeral-key generation plus the initiator's shared-secret derivation, while
decapsulation means the recipient's shared-secret derivation. Hybrid cases
measure both their ML-KEM and classical components in each stage.

As in the certificate benchmark, each attempt is capped at 15 minutes. A
timeout cancels the remaining iterations of that KEM and advances to the next
group.

## Raspberry Pi

Configure SSH key authentication first. Install the system build and Bluetooth
dependencies on the Pi:

```bash
ssh thiago@10.12.194.1 \
  'sudo apt update && sudo apt install -y build-essential bluez cmake git \
   libbluetooth-dev libcap2-bin libssl-dev mosquitto ninja-build perl pkg-config'
```

The Python runner deploys and compiles the bridge automatically using the SSH
values from `config.json`. It also builds the pinned wolfSSL revision once
under `/home/<user>/peripheral-benchmark/deps/wolfssl`; subsequent runs reuse
that user-local installation and do not require a system wolfSSL package.

The benchmark user must be able to start `ble_mqtt_bridge` with non-interactive
sudo. Add a narrow sudoers rule for the deployed binary if needed.

## Generate Cases

```bash
python benchmarking/generate_cases.py \
  --seed 123 \
  --iterations 5 \
  --warmup-iterations 1 \
  --include-heavy-homogeneous \
  --separate-pqc-classic
```

The generator refuses to overwrite an existing CSV. The printed path is used
as `--cases` below. A full generation contains 28 PKI chains crossed with nine
KEM groups, for 252 unique cases. The CSV records `pki_chain_id`, root,
intermediate, leaf, PKI kind, and the expected leaf `CertificateVerify` scheme.
With `--include-heavy-homogeneous`, the output contains 39 PKI chains and 351
cases before `--separate-pqc-classic` filtering.

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
contiguous.

Use `--limit N` to execute only the first `N` cases after seeded shuffling:

```bash
python benchmarking/run_benchmarks.py \
  --cases benchmarking/cases/<cases>.csv \
  --seed 123 \
  --limit 2
```

Add mutual client authentication without changing the case CSV:

```bash
python benchmarking/run_benchmarks.py \
  --cases benchmarking/cases/<cases>.csv \
  --seed 123 \
  --mtls-mode
```

The flag produces a distinct firmware build containing the fixed client
identity. Do not reuse a server-only image with `--skip-build` or
`--skip-flash` for the first mTLS run.

## Server Backend

The runner supports three server backend modes:

- `--server-backend auto`: use OpenSSL/Mosquitto for ordinary cases and wolfSSL
  for LMS/HSS or XMSS certificate chains.
- `--server-backend openssl-mosquitto`: use OpenSSL/Mosquitto for every case it
  can run; LMS/HSS and XMSS are recorded as unsupported instead of attempted.
- `--server-backend wolfssl`: use the wolfSSL TLS server for every selected
  case.

The wolfSSL server is not a full MQTT broker. It accepts one TLS connection
through the existing BLE bridge, reads the benchmark firmware's MQTT CONNECT
packet, sends CONNACK, and closes cleanly. The attempts output records the raw
two-byte scheme ID, observed server scheme, expected leaf scheme, and whether
they matched. A mismatch is a benchmark failure rather than a silent fallback.

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

Hardware connection defaults are read from `benchmarking/config.json`:

```json
{
  "serial-device": "/dev/ttyACM0",
  "pi-host": "user@ip",
  "ssh-key": "~/.ssh/[INSERT_SSH_KEY]",
  "ble-addr": "00:00:00:00:00:00"
}
```

Use `--config path/to/config.json` to select another configuration. The four
corresponding command-line options remain available and override JSON values.
The placeholder BLE address `00:00:00:00:00:00` means "discover by
`--ble-name`"; set a real BLE address only when you want to skip discovery.

The runner generates every certificate first, builds and flashes one universal
firmware image, then executes the saved schedule. Use `--skip-build
--skip-flash` only when the already flashed image was built from the same
universal credential bundle.

## PPK2 Energy Measurement

Power-profiler integration is disabled in the nRF5340DK port. Passing
`--power-profiler` is rejected before build or hardware access. The historical
energy columns remain in the CSV schema so existing result-processing scripts
continue to read old runs.

### Save and resume

Every completed schedule block is committed to its case `attempts.csv` and
then to an atomic `checkpoint.json`. If the process is interrupted during a
block, that block is absent from the checkpoint and is executed again.

Resume using the run ID printed after `results=`:

```bash
python benchmarking/run_benchmarks.py \
  --resume 20260704_004453_123
```

The saved seed, shuffled `session_manifest.csv`, client ML-KEM backend, server
backend, and RSA fallback policy are reused. Existing attempts are loaded and
new rows are appended without overwriting completed work. `--resume` cannot be
combined with `--cases`, `--run-id`, `--limit`, or `--only-case`.

Generated certificate identities are cached across runs in
`benchmarking/work/certificate-cache`. Cached certificates are reused while
they remain valid for at least seven more days; per-case OpenSSL and Mosquitto
configuration files are still regenerated inside each run directory.

Attempt timeouts are selected automatically from the KEM and signature cost.
`--attempt-timeout-sec N` overrides that policy. Gateway readiness has a
separate 90-second timeout, giving the raw BLE L2CAP bridge enough time to
retry controller setup without consuming a full cryptographic timeout.

The adaptive base timeout is 60 seconds for ECDSA, 45 seconds for ML-DSA and
RSA-3072, 75/120/180 seconds for SLH-DSA-128/192/256, and 120/240 seconds for
RSA-7680/15360. ML-KEM-512/768/1024 adds 20/30/45 seconds respectively.
`--limit` limits cases, not the warmup and measured blocks inside each case.

Between blocks, the runner terminates the bridge and broker, resets the Pi
Bluetooth controller, and waits for a fresh `BENCH_READY` marker. The firmware
also bounds its disconnect wait and reboots itself only if the controller
teardown callback is lost. This recovery does not rebuild or reflash the board.

The firmware keeps `FP_MAX_BITS=32768` and patches wolfSSL's disposable
FetchContent copy so the single `fast-math` image can parse and encode
RSA-PSS-15360 material. P-256/P-384/P-521 continue to route through wolfSSL's
Cortex-M SP-ECC backend so ECC does not inherit oversized TFM arithmetic.

### Default pqm4 ML-KEM backend

The nRF5340 application core uses pqm4's Cortex-M4F ML-KEM implementation by
default, including
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
Its instructions are compatible with the nRF5340 Cortex-M33/FPU, while its
smaller stack demand leaves more headroom for the TLS call chain.

## Measurements

`raw_handshake_ms` covers only `wolfSSL_connect()`. `tls_setup_ms` includes
context, selected root, group, and `WOLFSSL` object setup.
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
- `root_cert_der_bytes`, `intermediate_cert_der_bytes`, and
  `leaf_cert_der_bytes` are the individual DER sizes. `server_chain_bytes` is
  the transmitted DER payload size, computed as leaf plus intermediate; the
  root is excluded from the TLS chain.
- `tls_certificate_verify_signature_verify_ms` measures processing and
  cryptographic verification of the server TLS 1.3 `CertificateVerify`.
- By default the benchmark authenticates only the server. Add `--mtls-mode`
  to make the server require a fixed ECDSA P-256 client certificate signed by
  the benchmark client CA. In that mode, `mtls_signature_generate_ms` measures
  the client's TLS 1.3 `CertificateVerify` signature and
  `client_signature_total_ms` also includes that operation.
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
- `client_icache_hits` and `client_icache_misses` are populated only when the
  selected Nordic SoC exposes NVMC instruction-cache profiling registers; the
  runner derives requests and hit/miss percentages from those counters.
- `client_memory_access_counters_supported` is `0` on this nRF5340 build. Its
  Cortex-M33 configuration has no enabled PMU event counters for globally retired data-memory reads
  and writes. The DWT `LSUCNT` register counts extra load/store-unit cycles,
  saturates at eight bits, and is therefore deliberately not mislabeled as
  read/write operations. Use the exact L2CAP byte counters above when the
  quantity of interest is communication data moved during the attempt.

`summary.csv` contains the mean of these fields for successful measured
attempts. The raw values remain available in each case's `attempts.csv`.

Each run writes immutable artifacts below `results/<timestamp>_<seed>/`,
including the input CSV, run and session manifests, per-case attempts and logs,
and the aggregate `summary.csv`.

To require every recorded execution, including warmups, to have succeeded:

```bash
python benchmarking/check_results.py <run_id>
```

The checker prints `PASS` or `FAIL` for every case and exits with status `1`
when at least one case is missing attempts or contains a non-success status.

## Tests

```bash
python -m unittest discover -s benchmarking/tests -v
python -m py_compile benchmarking/*.py benchmarking/benchmarklib/*.py
```
