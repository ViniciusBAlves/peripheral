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
BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build}"

if [ ! -x "${NRFUTIL}" ]; then
	printf 'nrfutil not found at %s\n' "${NRFUTIL}" >&2
	printf 'Set NRFUTIL=/path/to/nrfutil and retry.\n' >&2
	exit 1
fi
if [ ! -d "${BUILD_DIR}" ]; then
	printf 'Build directory not found: %s\n' "${BUILD_DIR}" >&2
	printf 'Run peripheral/scripts/build_firmware.sh first.\n' >&2
	exit 1
fi

env SHELL=/bin/bash ZEPHYR_BASE="${ZEPHYR_BASE}" "${NRFUTIL}" sdk-manager toolchain launch \
	--ncs-version "${NCS_VERSION}" \
	--chdir "${NCS_CHDIR}" \
	-- west flash \
	-d "${BUILD_DIR}" \
	--runner nrfutil \
	"$@"
