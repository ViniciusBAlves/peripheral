#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

PI_SSH="${PI_SSH:-vini@10.12.194.1}"
PI_DIR="${PI_DIR:-/home/vini/pqc_ble_mqtt}"
BROKER_HOST="${BROKER_HOST:-127.0.0.1}"
BROKER_PORT="${BROKER_PORT:-8883}"
BLE_ADDR="${BLE_ADDR:-}"
BLE_NAME="${BLE_NAME:-PQC52840}"
BLE_ADDR_TYPE="${BLE_ADDR_TYPE:-random}"
BLE_L2CAP_PSM="${BLE_L2CAP_PSM:-0x0080}"
BLE_L2CAP_MTU="${BLE_L2CAP_MTU:-2000}"
INSTALL_SERVICE="${INSTALL_SERVICE:-1}"
START_SERVICE="${START_SERVICE:-0}"

broker_host="${BROKER_HOST}"

printf '[pi-deploy] Pi SSH target: %s\n' "${PI_SSH}"
printf '[pi-deploy] Pi gateway dir: %s\n' "${PI_DIR}"
printf '[pi-deploy] Broker host from Pi: %s:%s\n' "${broker_host}" "${BROKER_PORT}"

ssh "${PI_SSH}" "mkdir -p ${PI_DIR}"
scp \
	"${ROOT_DIR}/scripts/ble_l2cap_gateway.py" \
	"${ROOT_DIR}/scripts/pi_gateway_setup.sh" \
	"${PI_SSH}:${PI_DIR}/"

ssh "${PI_SSH}" "chmod +x ${PI_DIR}/ble_l2cap_gateway.py ${PI_DIR}/pi_gateway_setup.sh"
ssh "${PI_SSH}" \
	"GATEWAY_DIR=${PI_DIR} INSTALL_SERVICE=${INSTALL_SERVICE} ${PI_DIR}/pi_gateway_setup.sh"

ssh "${PI_SSH}" "cat > ${PI_DIR}/gateway.env" <<EOF
BLE_ADDR=${BLE_ADDR}
BLE_NAME=${BLE_NAME}
BLE_ADDR_TYPE=${BLE_ADDR_TYPE}
BLE_L2CAP_PSM=${BLE_L2CAP_PSM}
BLE_L2CAP_MTU=${BLE_L2CAP_MTU}
BROKER_HOST=${broker_host}
BROKER_PORT=${BROKER_PORT}
SCAN_SECONDS=4
RETRIES=60
CONNECT_TIMEOUT=10
EOF

printf '[pi-deploy] Wrote remote gateway.env\n'

if [ "${START_SERVICE}" = "1" ]; then
	ssh "${PI_SSH}" "sudo systemctl enable --now peripheral-ble-gateway.service"
	ssh "${PI_SSH}" "systemctl --no-pager --full status peripheral-ble-gateway.service || true"
else
	printf '[pi-deploy] Service not started. Start it with:\n'
	printf '  ssh %s "sudo systemctl enable --now peripheral-ble-gateway.service"\n' "${PI_SSH}"
fi

printf '[pi-deploy] Manual foreground run:\n'
printf '  ssh %s "cd %s && set -a && . ./gateway.env && set +a && sudo python3 -u ./ble_l2cap_gateway.py --addr=\${BLE_ADDR} --name \${BLE_NAME} --addr-type \${BLE_ADDR_TYPE} --psm \${BLE_L2CAP_PSM} --l2cap-mtu \${BLE_L2CAP_MTU} --broker-host \${BROKER_HOST} --broker-port \${BROKER_PORT}"\n' "${PI_SSH}" "${PI_DIR}"
