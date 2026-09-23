#!/usr/bin/env bash
# Run on a Linux build/staging server. No recursive submodule checkout is needed.
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
    echo "Prepare thirdparty on a Linux server, not the local workstation." >&2
    exit 1
fi

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source_root=${CXLMEMSIM_REFERENCE_COMPONENTS:-}
mkdir -p "$repo_root/thirdparty"

prepare() {
    local name=$1 revision=$2 origin=$3 source=$3
    local destination="$repo_root/thirdparty/$name"
    if [[ -n "$source_root" ]]; then
        source="file://$source_root/$name"
    fi
    if [[ ! -e "$destination/.git" ]]; then
        git clone --depth 1 --no-local --no-checkout "$source" "$destination"
        if ! git -C "$destination" cat-file -e "$revision^{commit}"; then
            if ! git -C "$destination" fetch --depth 1 origin "$revision"; then
                git -C "$destination" fetch --depth 1 "$origin" "$revision"
            fi
        fi
        git -C "$destination" checkout --detach "$revision"
        git -C "$destination" remote set-url origin "$origin"
        if [[ "$name" == cxlmemsim ]]; then
            # Tracked benchmark datasets and paper artifacts are not build inputs.
            git -C "$destination" sparse-checkout set --no-cone \
                '/*' '!/artifact/' '!/workloads/'
        fi
    fi
    if [[ $(git -C "$destination" rev-parse HEAD) != "$revision" ]]; then
        echo "Refusing to replace unexpected revision in $destination" >&2
        exit 1
    fi
    if [[ -n $(git -C "$destination" status --porcelain --untracked-files=no) ]]; then
        echo "Refusing modified tracked sources in $destination" >&2
        exit 1
    fi
    local alternates
    alternates=$(git -C "$destination" rev-parse --git-path objects/info/alternates)
    if [[ "$alternates" != /* ]]; then alternates="$destination/$alternates"; fi
    if [[ -s "$alternates" ]]; then
        echo "Checkout depends on external Git objects: $destination" >&2
        exit 1
    fi
    printf '%s %s\n' "$name" "$revision"
}

prepare qemu 59727bed3113942d6b7e1f61b1c08e02cc44e1c4 git@github.com:Yuer-yuan/qemu-cxl-type2.git
prepare cxlmemsim b5e183ea9732fa023c5df1a749a857430c3a237b git@github.com:Yuer-yuan/CXLMemSim.git
