#!/usr/bin/env bash
set -euo pipefail

PI_SSH="${PI_SSH:-vini@10.12.194.1}"
PI_DIR="${PI_DIR:-/home/vini/pqc_ble_mqtt}"
BROKER_HOST="${BROKER_HOST:-127.0.0.1}"
BROKER_PORT="${BROKER_PORT:-8883}"
BLE_ADDR="${BLE_ADDR:-}"
BLE_NAME="${BLE_NAME:-PQC52840}"
BLE_ADDR_TYPE="${BLE_ADDR_TYPE:-random}"
BLE_L2CAP_PSM="${BLE_L2CAP_PSM:-0x0080}"
BLE_L2CAP_MTU="${BLE_L2CAP_MTU:-2000}"
SCAN_SECONDS="${SCAN_SECONDS:-4}"
RETRIES="${RETRIES:-60}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-10}"

remote_cmd=$(cat <<EOF
cd ${PI_DIR} &&
sudo python3 -u ./ble_l2cap_gateway.py \
  --addr=${BLE_ADDR} \
  --name ${BLE_NAME} \
  --addr-type ${BLE_ADDR_TYPE} \
  --psm ${BLE_L2CAP_PSM} \
  --l2cap-mtu ${BLE_L2CAP_MTU} \
  --broker-host ${BROKER_HOST} \
  --broker-port ${BROKER_PORT} \
  --scan-seconds ${SCAN_SECONDS} \
  --retries ${RETRIES} \
  --connect-timeout ${CONNECT_TIMEOUT}
EOF
)

printf '[pi-run] Running gateway on %s; broker=%s:%s\n' "${PI_SSH}" "${BROKER_HOST}" "${BROKER_PORT}"
ssh -o ServerAliveInterval=10 -o ServerAliveCountMax=3 "${PI_SSH}" "${remote_cmd}"
