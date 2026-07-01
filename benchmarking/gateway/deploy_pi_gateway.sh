#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PI_HOST="${PI_HOST:-thiago@10.12.194.1}"
PI_WORKDIR="${PI_WORKDIR:-/home/thiago/peripheral-benchmark}"
SSH_KEY="${SSH_KEY:-}"

ssh_args=(-o BatchMode=yes)
if [[ -n "${SSH_KEY}" ]]; then
    ssh_args+=(-i "${SSH_KEY}")
fi

ssh "${ssh_args[@]}" "${PI_HOST}" "mkdir -p '${PI_WORKDIR}/bin'"
rsync -a -e "ssh ${ssh_args[*]}" \
    "${ROOT}/gateway/ble_mqtt_bridge.c" \
    "${ROOT}/gateway/server_crypto_metrics.c" \
    "${ROOT}/gateway/setup_pi_gateway.sh" \
    "${PI_HOST}:${PI_WORKDIR}/bin/"
ssh "${ssh_args[@]}" "${PI_HOST}" \
    "cd '${PI_WORKDIR}' && gcc -O2 -Wall -Wextra -o bin/ble_mqtt_bridge \
     bin/ble_mqtt_bridge.c \$(pkg-config --cflags --libs bluez) && \
     gcc -O2 -Wall -Wextra -shared -fPIC \
     -o bin/server_crypto_metrics.so bin/server_crypto_metrics.c -ldl -lcrypto"

printf 'Gateway deployed to %s:%s\n' "${PI_HOST}" "${PI_WORKDIR}"
