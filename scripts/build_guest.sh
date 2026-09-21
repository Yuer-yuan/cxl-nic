#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${CXL_NIC_GUEST_OUT:-${ROOT}/build/integration/guest}"
CROSS_COMPILE="${CROSS_COMPILE:-riscv64-linux-gnu-}"

if [[ "$(uname -s)" != Linux ]]; then
    printf '%s\n' 'Build this guest on the Linux server (giga); local builds are disabled.' >&2
    exit 2
fi
command -v "${CROSS_COMPILE}gcc" >/dev/null
command -v "${CROSS_COMPILE}readelf" >/dev/null
mkdir -p "${OUT}"

"${CROSS_COMPILE}gcc" \
    -O2 -g -std=c11 -Wall -Wextra -Werror \
    -static -nostdlib -ffreestanding -fno-builtin -fno-stack-protector \
    -fno-pie -no-pie -mcmodel=medany -msmall-data-limit=0 \
    -march=rv64imac_zicsr -mabi=lp64 \
    -Wl,--build-id=none -Wl,-T,"${ROOT}/guest/integration.ld" \
    "${ROOT}/guest/integration_start.S" "${ROOT}/guest/integration.c" \
    -o "${OUT}/consumer.elf"
"${CROSS_COMPILE}readelf" -h "${OUT}/consumer.elf"
sha256sum "${OUT}/consumer.elf"
