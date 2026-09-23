#!/usr/bin/env bash
# Run matched sampled-gate Type2 guest integrations on a Linux server.
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
    echo 'Run Type2 gate verification on a Linux server.' >&2
    exit 1
fi
if [[ $# != 1 ]]; then
    echo 'Usage: scripts/verify_integration_gate_sweep.sh NEW_RESULT_DIRECTORY' >&2
    exit 2
fi
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
python3 -m cxl_nic.integration_gate_sweep --output "$1"
