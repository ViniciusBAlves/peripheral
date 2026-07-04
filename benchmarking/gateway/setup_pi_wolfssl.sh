#!/usr/bin/env bash
set -euo pipefail

prefix="${1:?usage: setup_pi_wolfssl.sh INSTALL_PREFIX}"
mkdir -p "${prefix}"
prefix="$(cd "${prefix}" && pwd)"
revision="dd6da70d395a0cb26446326f329678fe3bfb212c"
profile="tls13-mlkem-hybrids-curve25519-mldsa-slhdsa-lms-xmss-v2"
source_dir="${prefix%/}/src"
build_dir="${source_dir}/build"
profile_file="${prefix}/.benchmark-profile"
source_archive="${prefix%/}/wolfssl-clean-source.tar.gz"

if PKG_CONFIG_PATH="${prefix}/lib/pkgconfig" pkg-config --exists wolfssl \
    && [[ -f "${profile_file}" ]] \
    && [[ "$(<"${profile_file}")" == "${revision}:${profile}" ]]; then
    exit 0
fi

for command in cmake ninja gcc pkg-config perl; do
    command -v "${command}" >/dev/null || {
        printf 'missing Raspberry Pi build dependency: %s\n' "${command}" >&2
        exit 1
    }
done

rm -rf "${source_dir}"
if [[ -f "${source_archive}" ]]; then
    command -v tar >/dev/null || {
        printf 'missing Raspberry Pi build dependency: tar\n' >&2
        exit 1
    }
    mkdir -p "${source_dir}"
    tar --touch --warning=no-timestamp -xzf "${source_archive}" \
        --strip-components=1 -C "${source_dir}"
else
    command -v git >/dev/null || {
        printf 'missing Raspberry Pi build dependency: git\n' >&2
        exit 1
    }
    mkdir -p "${source_dir}"
    git -C "${source_dir}" init
    git -C "${source_dir}" remote add origin https://github.com/wolfSSL/wolfssl.git
    git -C "${source_dir}" fetch --depth 1 origin "${revision}"
    git -C "${source_dir}" checkout --detach FETCH_HEAD
fi

perl -0pi -e \
    's/# SLH-DSA/if (WOLFSSL_XMSS)\n    list(APPEND WOLFSSL_DEFINITIONS "-DWOLFSSL_HAVE_XMSS")\n    set_wolfssl_definitions("WOLFSSL_HAVE_XMSS" RESULT)\nendif()\n\n# SLH-DSA/' \
    "${source_dir}/CMakeLists.txt"
touch "${source_dir}/CMakeLists.txt"

cmake -S "${source_dir}" -B "${build_dir}" -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="${prefix}" \
    -DCMAKE_C_FLAGS=-Wno-error=maybe-uninitialized \
    -DWOLFSSL_TLS13=yes \
    -DWOLFSSL_ECC=yes \
    -DWOLFSSL_CURVE25519=yes \
    -DWOLFSSL_PQC_HYBRIDS=yes \
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
