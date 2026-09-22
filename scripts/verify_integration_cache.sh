#!/usr/bin/env bash
# Run the matched Type2 NC-P/DDIO guest matrix on a Linux server.
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
    echo 'Run integration cache verification on a Linux server.' >&2
    exit 1
fi
if [[ $# != 1 ]]; then
    echo 'Usage: scripts/verify_integration_cache.sh NEW_RESULT_DIRECTORY' >&2
    exit 2
fi
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

python3 -m cxl_nic.integration_matrix --output "$1"
