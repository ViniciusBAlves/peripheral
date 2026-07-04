#!/usr/bin/env bash
set -euo pipefail

prefix="${1:?usage: setup_pi_wolfssl.sh INSTALL_PREFIX}"
mkdir -p "${prefix}"
prefix="$(cd "${prefix}" && pwd)"
revision="dd6da70d395a0cb26446326f329678fe3bfb212c"
profile="tls13-mlkem-mldsa-slhdsa-lms-xmss-v1"
source_dir="${prefix%/}/src"
build_dir="${source_dir}/build"
profile_file="${prefix}/.benchmark-profile"

if PKG_CONFIG_PATH="${prefix}/lib/pkgconfig" pkg-config --exists wolfssl \
    && [[ -f "${profile_file}" ]] \
    && [[ "$(<"${profile_file}")" == "${revision}:${profile}" ]]; then
    exit 0
fi

for command in git cmake ninja gcc pkg-config perl; do
    command -v "${command}" >/dev/null || {
        printf 'missing Raspberry Pi build dependency: %s\n' "${command}" >&2
        exit 1
    }
done

rm -rf "${source_dir}"
mkdir -p "${source_dir}"
git -C "${source_dir}" init
git -C "${source_dir}" remote add origin https://github.com/wolfSSL/wolfssl.git
git -C "${source_dir}" fetch --depth 1 origin "${revision}"
git -C "${source_dir}" checkout --detach FETCH_HEAD

perl -0pi -e \
    's/# SLH-DSA/if (WOLFSSL_XMSS)\n    list(APPEND WOLFSSL_DEFINITIONS "-DWOLFSSL_HAVE_XMSS")\n    set_wolfssl_definitions("WOLFSSL_HAVE_XMSS" RESULT)\nendif()\n\n# SLH-DSA/' \
    "${source_dir}/CMakeLists.txt"

cmake -S "${source_dir}" -B "${build_dir}" -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="${prefix}" \
    -DCMAKE_C_FLAGS=-Wno-error=maybe-uninitialized \
    -DWOLFSSL_TLS13=yes \
    -DWOLFSSL_ECC=yes \
    -DWOLFSSL_TLS_NO_MLKEM_STANDALONE=no \
    -DWOLFSSL_MLDSA=yes \
    -DWOLFSSL_SLHDSA=yes \
    -DWOLFSSL_LMS=yes \
    -DWOLFSSL_XMSS=yes \
    -DWOLFSSL_CERTGEN=yes \
    -DWOLFSSL_CERTREQ=yes \
    -DWOLFSSL_CERTEXT=yes \
    -DWOLFSSL_KEYGEN=yes \
    -DWOLFSSL_OPENSSLEXTRA=yes
cmake --build "${build_dir}"
cmake --install "${build_dir}"

PKG_CONFIG_PATH="${prefix}/lib/pkgconfig" pkg-config --modversion wolfssl
printf '%s\n' "${revision}:${profile}" > "${profile_file}"
