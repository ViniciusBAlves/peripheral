#!/usr/bin/env bash
set -euo pipefail

prefix="${1:?usage: setup_pi_mosquitto.sh INSTALL_PREFIX [SOURCE_ARCHIVE]}"
source_archive="${2:-}"
mkdir -p "${prefix}"
prefix="$(cd "${prefix}" && pwd)"
revision="v2.0.21"
profile="preconnect-keepalive-900"
source_dir="${prefix%/}/src"
build_dir="${source_dir}/build"
profile_file="${prefix}/.benchmark-profile"

if [[ -x "${prefix}/bin/mosquitto" ]] \
    && [[ -f "${profile_file}" ]] \
    && [[ "$(<"${profile_file}")" == "${revision}:${profile}" ]]; then
    exit 0
fi

for command in cmake ninja gcc perl; do
    command -v "${command}" >/dev/null || {
        printf 'missing Raspberry Pi build dependency: %s\n' "${command}" >&2
        exit 1
    }
done

rm -rf "${source_dir}"
mkdir -p "${source_dir}"
if [[ -n "${source_archive}" && -f "${source_archive}" ]]; then
    tar --touch --warning=no-timestamp -xzf "${source_archive}" \
        --strip-components=1 -C "${source_dir}"
else
    command -v git >/dev/null || {
        printf 'missing Raspberry Pi build dependency: git\n' >&2
        exit 1
    }
    git -C "${source_dir}" init
    git -C "${source_dir}" remote add origin https://github.com/eclipse-mosquitto/mosquitto.git
    git -C "${source_dir}" fetch --depth 1 origin "${revision}"
    git -C "${source_dir}" checkout --detach FETCH_HEAD
fi

perl -0pi -e \
    's/context->keepalive = 60; \/\* Default to 60s \*\//context->keepalive = 900; \/\* Benchmark pre-CONNECT TLS timeout \*\//' \
    "${source_dir}/src/context.c"

cmake -S "${source_dir}" -B "${build_dir}" -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="${prefix}" \
    -DWITH_TESTS=OFF \
    -DWITH_CJSON=OFF \
    -DWITH_WEBSOCKETS=OFF \
    -DWITH_STATIC_LIBRARIES=OFF \
    -DWITH_LIB_CPP=OFF \
    -DWITH_SRV=OFF \
    -DWITH_CLIENTS=OFF \
    -DWITH_APPS=OFF \
    -DWITH_PLUGINS=OFF \
    -DDOCUMENTATION=OFF \
    -DWITH_TLS=ON
cmake --build "${build_dir}" --target mosquitto

mkdir -p "${prefix}/bin"
cp "${build_dir}/src/mosquitto" "${prefix}/bin/mosquitto"
printf '%s\n' "${revision}:${profile}" > "${profile_file}"
