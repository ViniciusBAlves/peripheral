#!/usr/bin/env bash
set -euo pipefail

GATEWAY_DIR="${GATEWAY_DIR:-${HOME}/pqc_ble_mqtt}"
ENV_FILE="${ENV_FILE:-${GATEWAY_DIR}/gateway.env}"
SERVICE_NAME="${SERVICE_NAME:-peripheral-ble-gateway.service}"
INSTALL_SERVICE="${INSTALL_SERVICE:-1}"

if ! command -v python3 >/dev/null 2>&1; then
	printf '[pi-setup] python3 is required.\n' >&2
	exit 1
fi

if ! command -v bluetoothctl >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
	printf '[pi-setup] Installing Raspberry Pi gateway dependencies...\n'
	sudo apt-get update
	sudo apt-get install -y bluez python3
else
	printf '[pi-setup] apt-get not found; skipping package installation.\n'
fi

sudo systemctl enable --now bluetooth.service

mkdir -p "${GATEWAY_DIR}"

if [ ! -f "${ENV_FILE}" ]; then
	cat >"${ENV_FILE}" <<'EOF'
# Raspberry Pi BLE L2CAP gateway defaults.
# BROKER_HOST must be reachable from the Pi. Over USB gadget this is usually
# the host-side USB network IP, for example 10.12.194.2.
BLE_ADDR=
BLE_NAME=PQC52840
BLE_ADDR_TYPE=random
BLE_L2CAP_PSM=0x0080
BLE_L2CAP_MTU=2000
BROKER_HOST=127.0.0.1
BROKER_PORT=8883
SCAN_SECONDS=4
RETRIES=60
CONNECT_TIMEOUT=10
EOF
	printf '[pi-setup] Wrote %s\n' "${ENV_FILE}"
fi

if [ "${INSTALL_SERVICE}" = "1" ]; then
	sudo tee "/etc/systemd/system/${SERVICE_NAME}" >/dev/null <<EOF
[Unit]
Description=Peripheral BLE L2CAP to MQTT/TLS TCP gateway
After=bluetooth.service network-online.target
Wants=bluetooth.service network-online.target

[Service]
Type=simple
User=${USER}
WorkingDirectory=${GATEWAY_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=/usr/bin/python3 -u ${GATEWAY_DIR}/ble_l2cap_gateway.py --addr=\${BLE_ADDR} --name \${BLE_NAME} --addr-type \${BLE_ADDR_TYPE} --psm \${BLE_L2CAP_PSM} --l2cap-mtu \${BLE_L2CAP_MTU} --broker-host \${BROKER_HOST} --broker-port \${BROKER_PORT} --scan-seconds \${SCAN_SECONDS} --retries \${RETRIES} --connect-timeout \${CONNECT_TIMEOUT}
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
	sudo systemctl daemon-reload
	printf '[pi-setup] Installed systemd service %s\n' "${SERVICE_NAME}"
	printf '[pi-setup] Start it with: sudo systemctl enable --now %s\n' "${SERVICE_NAME}"
fi

printf '[pi-setup] Done. Gateway directory: %s\n' "${GATEWAY_DIR}"
