#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y \
    bluez \
    build-essential \
    ca-certificates \
    cmake \
    git \
    libbluetooth-dev \
    libcap2-bin \
    libssl-dev \
    mosquitto \
    mosquitto-clients \
    openssl \
    pkg-config \
    rsync \
    ninja-build

if ! find /usr/lib /usr/local/lib -name oqsprovider.so -print -quit 2>/dev/null |
    grep -q .; then
    workdir="$(mktemp -d)"
    trap 'rm -rf "${workdir}"' EXIT
    git clone --depth 1 --branch 0.15.0 \
        https://github.com/open-quantum-safe/liboqs.git "${workdir}/liboqs"
    cmake -S "${workdir}/liboqs" -B "${workdir}/liboqs-build" -GNinja \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_ALGS_ENABLED=STD
    cmake --build "${workdir}/liboqs-build"
    sudo cmake --install "${workdir}/liboqs-build"

    git clone --depth 1 --branch 0.11.0 \
        https://github.com/open-quantum-safe/oqs-provider.git "${workdir}/oqs-provider"
    cmake -S "${workdir}/oqs-provider" -B "${workdir}/oqs-provider-build" -GNinja \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local \
        -Dliboqs_DIR=/usr/local/lib/cmake/liboqs
    cmake --build "${workdir}/oqs-provider-build"
    sudo cmake --install "${workdir}/oqs-provider-build"
    module="$(find /usr/lib /usr/local -name oqsprovider.so -print -quit)"
    sudo mkdir -p /usr/local/lib/ossl-modules
    sudo cp "${module}" /usr/local/lib/ossl-modules/oqsprovider.so
    sudo ldconfig
fi

sudo systemctl enable --now bluetooth
OPENSSL_CONF=/dev/null OPENSSL_MODULES=/usr/local/lib/ossl-modules \
    openssl list -providers -provider default -provider oqsprovider |
    grep -q oqsprovider
printf 'Raspberry Pi gateway dependencies are ready.\n'
