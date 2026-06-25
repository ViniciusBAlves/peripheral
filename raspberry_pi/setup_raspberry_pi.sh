#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

need_sudo=false
for cmd in mosquitto_pub gcc pkg-config; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        need_sudo=true
    fi
done

if [ ! -x /usr/sbin/mosquitto ]; then
    need_sudo=true
fi

if ! pkg-config --exists bluez; then
    need_sudo=true
fi

if "$need_sudo"; then
    echo "[Pi setup] Installing Mosquitto, BlueZ headers, and build tools..."
    sudo apt-get update
    sudo apt-get install -y \
        bluez \
        libbluetooth-dev \
        mosquitto \
        mosquitto-clients \
        openssl \
        build-essential \
        pkg-config
fi

echo "[Pi setup] OpenSSL version:"
openssl version

echo "[Pi setup] Checking native OpenSSL PQC algorithms..."
openssl list -kem-algorithms | grep -Eq '(^|[[:space:]])MLKEM512([[:space:]]|$)|ML-KEM-512|ML-KEM512' || {
    echo "OpenSSL on this Pi does not list ML-KEM/MLKEM KEM algorithms." >&2
    exit 1
}
openssl list -signature-algorithms | grep -q 'SLH-DSA-SHAKE-256s' || {
    echo "OpenSSL on this Pi does not list SLH-DSA-SHAKE-256s." >&2
    exit 1
}

echo "[Pi setup] Building BLE L2CAP <-> TCP bridge..."
gcc -O2 -Wall -Wextra -o ble_mqtt_bridge ble_mqtt_bridge.c $(pkg-config --cflags --libs bluez)

echo "[Pi setup] Done."
