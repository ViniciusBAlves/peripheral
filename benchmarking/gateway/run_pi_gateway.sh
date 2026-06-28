#!/usr/bin/env bash
set -euo pipefail

PI_HOST="${PI_HOST:-thiago@10.12.194.1}"
PI_WORKDIR="${PI_WORKDIR:-/home/thiago/peripheral-benchmark}"
BLE_ADDR="${BLE_ADDR:-}"
BLE_NAME="${BLE_NAME:-PQC52840}"
BLE_ADDR_TYPE="${BLE_ADDR_TYPE:-random}"
PSM="${PSM:-0x0080}"
MTU="${MTU:-672}"
SSH_KEY="${SSH_KEY:-}"

ssh_args=(-t)
if [[ -n "${SSH_KEY}" ]]; then
    ssh_args+=(-i "${SSH_KEY}")
fi

addr_args=""
if [[ -n "${BLE_ADDR}" ]]; then
    addr_args="--addr '${BLE_ADDR}'"
fi

ssh "${ssh_args[@]}" "${PI_HOST}" \
    "sudo '${PI_WORKDIR}/bin/ble_mqtt_bridge' \
     ${addr_args} --name '${BLE_NAME}' --addr-type '${BLE_ADDR_TYPE}' \
     --psm '${PSM}' --mtu '${MTU}' --tcp-host 127.0.0.1 --tcp-port 8883"
