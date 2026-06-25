#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CERT_DIR="${CERT_DIR:-${ROOT_DIR}/generated_certs}"
CONTAINER_NAME="${CONTAINER_NAME:-mosquitto_pqc}"
IMAGE="${IMAGE:-openquantumsafe/mosquitto}"
PORT="${PORT:-8883}"
DOCKER_NETWORK="${DOCKER_NETWORK:-host}"

required_files=(
	"mosquitto.conf"
	"openssl.cnf"
	"passwd"
	"ca.crt"
	"server.crt"
	"server.key"
)

missing=()
for file in "${required_files[@]}"; do
	if [ ! -f "${CERT_DIR}/${file}" ]; then
		missing+=("${CERT_DIR}/${file}")
	fi
done

if [ "${#missing[@]}" -gt 0 ]; then
	printf 'Missing server certificate/config files:\n' >&2
	printf '  %s\n' "${missing[@]}" >&2
	printf '\nGenerate them first, for example with:\n' >&2
	printf '  python peripheral/generate_pqc.py\n' >&2
	exit 1
fi

chmod 0644 \
	"${CERT_DIR}/mosquitto.conf" \
	"${CERT_DIR}/openssl.cnf" \
	"${CERT_DIR}/passwd" \
	"${CERT_DIR}/ca.crt" \
	"${CERT_DIR}/server.crt" \
	"${CERT_DIR}/server.key"

docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

docker_args=(
	--rm
	--name "${CONTAINER_NAME}"
	--network "${DOCKER_NETWORK}"
	-e OPENSSL_CONF=/mosquitto/config/openssl.cnf \
	-v "${CERT_DIR}/mosquitto.conf:/mosquitto/config/mosquitto.conf:ro" \
	-v "${CERT_DIR}/passwd:/mosquitto/config/passwd:ro" \
	-v "${CERT_DIR}/ca.crt:/mosquitto/config/ca.crt:ro" \
	-v "${CERT_DIR}/server.crt:/mosquitto/config/server.crt:ro" \
	-v "${CERT_DIR}/server.key:/mosquitto/config/server.key:ro" \
	-v "${CERT_DIR}/openssl.cnf:/mosquitto/config/openssl.cnf:ro"
)

if [ "${DOCKER_NETWORK}" != "host" ] && [ "${DOCKER_NETWORK}" != "none" ]; then
	docker_args+=(-p "${PORT}:8883")
fi

exec docker run "${docker_args[@]}" \
	"${IMAGE}" \
	mosquitto -c /mosquitto/config/mosquitto.conf -v
