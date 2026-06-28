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

RSA-PSS-15360 cases are emitted as `known_unsupported`: the pinned wolfSSL
`USE_FAST_MATH` backend caps TLS RSA keys at 8192 bits. They are recorded
without silently substituting RSA-PSS-7680.

## Raspberry Pi

Configure SSH key authentication first. Then install the gateway dependencies:

```bash
ssh thiago@10.12.194.1 'bash -s' < benchmarking/gateway/setup_pi_gateway.sh
PI_HOST=thiago@10.12.194.1 \
SSH_KEY="$HOME/.ssh/id_ed25519_pi" \
benchmarking/gateway/deploy_pi_gateway.sh
```

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
attempt is a separate block, and all blocks are shuffled by the run seed.

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
  --seed 123 \
  --serial-device /dev/ttyACM0 \
  --pi-host thiago@10.12.194.1 \
  --ssh-key "$HOME/.ssh/id_ed25519_pi_gateway" \
  --ble-addr F9:79:AE:2A:9A:1E
```

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

## Measurements

`raw_handshake_ms` covers only `wolfSSL_connect()`. `tls_setup_ms` includes
context, CA, client certificate, key, group, and `WOLFSSL` object setup.
`mqtt_connect_ms` ends at MQTT CONNACK. `full_connect_ms` starts at TLS setup,
while `end_to_end_ms` starts when the firmware L2CAP channel becomes ready.
Gateway-side BLE and TCP setup durations are recorded separately.

Each run writes immutable artifacts below `results/<timestamp>_<seed>/`,
including the input CSV, run and session manifests, per-case attempts and logs,
and the aggregate `summary.csv`.

## Tests

```bash
python -m unittest discover -s benchmarking/tests -v
python -m py_compile benchmarking/*.py benchmarking/benchmarklib/*.py
```
