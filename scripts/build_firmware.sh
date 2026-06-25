#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

NRFUTIL="${NRFUTIL:-/home/thiago/.local/bin/nrfutil}"
NCS_VERSION="${NCS_VERSION:-v3.3.0}"
NCS_ROOT="${NCS_ROOT:-/home/thiago/Documents/ncs/v3.3.0}"
if [ ! -d "${NCS_ROOT}" ] && [ -d "/home/thiago/ncs/v3.3.0" ]; then
	NCS_ROOT="/home/thiago/ncs/v3.3.0"
fi
NCS_CHDIR="${NCS_CHDIR:-${NCS_ROOT}/nrf}"
ZEPHYR_BASE="${ZEPHYR_BASE:-${NCS_ROOT}/zephyr}"
BOARD="${BOARD:-nrf52840dk/nrf52840}"
BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build}"
PQC_GROUP="${PQC_GROUP:-WOLFSSL_ML_KEM_512}"

if [ ! -x "${NRFUTIL}" ]; then
	printf 'nrfutil not found at %s\n' "${NRFUTIL}" >&2
	printf 'Set NRFUTIL=/path/to/nrfutil and retry.\n' >&2
	exit 1
fi
if [ ! -d "${NCS_CHDIR}" ]; then
	printf 'NCS_CHDIR not found: %s\n' "${NCS_CHDIR}" >&2
	printf 'Set NCS_ROOT or NCS_CHDIR to your NCS v3.3.0 checkout.\n' >&2
	exit 1
fi
if [ ! -d "${ZEPHYR_BASE}" ]; then
	printf 'ZEPHYR_BASE not found: %s\n' "${ZEPHYR_BASE}" >&2
	printf 'Set NCS_ROOT or ZEPHYR_BASE to your NCS v3.3.0 checkout.\n' >&2
	exit 1
fi

printf '[build] NCS_VERSION=%s\n' "${NCS_VERSION}"
printf '[build] NCS_CHDIR=%s\n' "${NCS_CHDIR}"
printf '[build] ZEPHYR_BASE=%s\n' "${ZEPHYR_BASE}"
printf '[build] BOARD=%s\n' "${BOARD}"
printf '[build] PQC_GROUP=%s\n' "${PQC_GROUP}"

env SHELL=/bin/bash ZEPHYR_BASE="${ZEPHYR_BASE}" "${NRFUTIL}" sdk-manager toolchain launch \
	--ncs-version "${NCS_VERSION}" \
	--chdir "${NCS_CHDIR}" \
	-- west build \
	-d "${BUILD_DIR}" \
	-p always \
	-b "${BOARD}" \
	"${ROOT_DIR}" \
	-- \
	-DEXTRA_CFLAGS="-DTARGET_PQC_GROUP=${PQC_GROUP}" \
	"$@"
