#!/usr/bin/env bash
# Replay one validated trace with matched resources and explicit sensitivities.
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
    echo 'Run cache verification on a Linux server.' >&2
    exit 1
fi
if [[ $# != 2 ]]; then
    echo 'Usage: scripts/verify_cache.sh TRACE_JSONL NEW_RESULT_DIRECTORY' >&2
    exit 2
fi
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
trace=$1
run_dir=$2
mkdir -p -- "$(dirname -- "$run_dir")"
mkdir -- "$run_dir"

python3 -m cxl_nic.cache_replay --trace "$trace" --output "$run_dir/matched"
python3 -m cxl_nic.cache_replay --trace "$trace" --output "$run_dir/pressure" --background-lines 512
python3 -m cxl_nic.cache_replay --trace "$trace" --output "$run_dir/admission" --ddio-ways 0,1
python3 -m cxl_nic.cache_replay --trace "$trace" --output "$run_dir/withdraw" --withdraw-after-events 0

python3 - "$run_dir" <<'PY'
import json
from pathlib import Path
import sys

run = Path(sys.argv[1])
results = {name: json.loads((run / name / 'result.json').read_text())
           for name in ('matched', 'pressure', 'admission', 'withdraw')}
for name, result in results.items():
    if result['status'] != 'passed':
        raise SystemExit(f'{name} failed')
for name in ('matched', 'pressure'):
    if results[name]['label_invariance'] != 'passed':
        raise SystemExit(f'{name}: missing label-invariance evidence')
for arm in results['pressure']['arms'].values():
    if arm['counts']['payload_first_hits'] != 0:
        raise SystemExit('full-cache background sweep did not remove pushed payload')
for name in ('ncp-nic', 'ncp-host-control'):
    arm = results['withdraw']['arms'][name]
    if arm['counts']['payload_first_hits'] != 0 or arm['counts']['withdrawals_applied'] == 0:
        raise SystemExit('immediate withdrawal did not force payload fallback')
summary = {'status': 'passed', 'trace_sha256': results['matched']['trace_sha256'],
           'scope': 'symbolic cache sensitivity; no measured latency or hardware hit rate',
           'cases': {name: {'label_invariance': result['label_invariance'],
                            'arms': {arm: {'first_payload_hits': data['counts']['payload_first_hits'],
                                           'first_payload_misses': data['counts']['payload_first_misses'],
                                           'first_payload_hit_rate': data['payload_first_demand_hit_rate']}
                                     for arm, data in result['arms'].items()}}
                     for name, result in results.items()}}
(run / 'result.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
print(json.dumps(summary))
PY
