#!/usr/bin/env bash
# Run on giga after prepare_thirdparty.sh (or after copying its checkouts).
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
    echo "Build integration on a Linux server, not the local workstation." >&2
    exit 1
fi

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
build_root="$repo_root/build/integration"
jobs=${JOBS:-8}
mkdir -p "$build_root"
exec > >(tee -a "$build_root/build.log") 2>&1

packages=(build-essential cmake ninja-build pkg-config python3-venv meson
    libglib2.0-dev libpixman-1-dev zlib1g-dev libfdt-dev libspdlog-dev
    libcxxopts-dev liburing-dev gcc-riscv64-linux-gnu)
if [[ ${1:-} == --install-deps ]]; then
    if [[ $EUID != 0 ]]; then
        echo "--install-deps requires root on the build server." >&2
        exit 1
    fi
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
elif [[ $# != 0 ]]; then
    echo "Usage: $0 [--install-deps]" >&2
    exit 1
fi
dpkg-query -W "${packages[@]}" > "$build_root/system-packages.txt"
"$repo_root/scripts/prepare_thirdparty.sh" > "$build_root/thirdparty-revisions.txt"

mkdir -p "$build_root/qemu"
cd "$build_root/qemu"
"$repo_root/thirdparty/qemu/configure" \
    --target-list=riscv64-softmmu \
    --disable-docs --disable-werror --disable-gtk --disable-sdl \
    --disable-vnc --disable-spice --disable-opengl --disable-virglrenderer \
    --disable-rust --disable-slirp --disable-tools --disable-guest-agent \
    --enable-download
ninja -j "$jobs" qemu-system-riscv64

cmake -S "$repo_root/thirdparty/cxlmemsim" -B "$build_root/cxlmemsim" \
    -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCXLMEMSIM_BUILD_MICROBENCHMARKS=OFF \
    -DCXLMEMSIM_ENABLE_RDMA=OFF -DCXLMEMSIM_ENABLE_SLUGALLOCATOR=OFF
cmake --build "$build_root/cxlmemsim" --target cxlmemsim_server -j "$jobs"

sha256sum "$build_root/qemu/qemu-system-riscv64" \
    "$build_root/cxlmemsim/cxlmemsim_server" > "$build_root/binaries.sha256"
printf 'QEMU: %s\nServer: %s\n' "$build_root/qemu/qemu-system-riscv64" \
    "$build_root/cxlmemsim/cxlmemsim_server"
