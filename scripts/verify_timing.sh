#!/usr/bin/env bash
# Run deterministic virtual-time policy comparisons on a Linux server.
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
    echo 'Run timing verification on a Linux server.' >&2
    exit 1
fi
if [[ $# != 1 ]]; then
    echo 'Usage: scripts/verify_timing.sh NEW_RESULT_DIRECTORY' >&2
    exit 2
fi
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
run_dir=$1
mkdir -p -- "$(dirname -- "$run_dir")"
mkdir -- "$run_dir"

common=(--flows 2 --packets-per-flow 32 --interarrival-ns 80
        --reorder-jitter-ns 120 --gap-every 8 --seed 1)
core_policies='C,B1,D1,D1-gated,D1-host-control'

python3 -m cxl_nic.timing "${common[@]}" --gap-delay-ns 800 \
    --output "$run_dir/matrix" > "$run_dir/matrix.stdout.json"
python3 -m cxl_nic.timing "${common[@]}" --gap-delay-ns 0 \
    --policies "$core_policies" --output "$run_dir/gap-0000" > "$run_dir/gap-0000.stdout.json"
python3 -m cxl_nic.timing "${common[@]}" --gap-delay-ns 200 \
    --policies "$core_policies" --output "$run_dir/gap-0200" > "$run_dir/gap-0200.stdout.json"
python3 -m cxl_nic.timing "${common[@]}" --gap-delay-ns 800 \
    --policies "$core_policies" --output "$run_dir/gap-0800" > "$run_dir/gap-0800.stdout.json"
python3 -m cxl_nic.timing "${common[@]}" --gap-delay-ns 2400 \
    --policies "$core_policies" --output "$run_dir/gap-2400" > "$run_dir/gap-2400.stdout.json"
python3 -m cxl_nic.timing "${common[@]}" --gap-delay-ns 800 \
    --background-interval-ns 20 --background-working-set-lines 1024 \
    --policies "$core_policies" --output "$run_dir/pressure" > "$run_dir/pressure.stdout.json"
python3 -m cxl_nic.timing "${common[@]}" --gap-delay-ns 800 \
    --ddio-ways 0,1 --ncp-ways all --policies "$core_policies" \
    --output "$run_dir/admission" > "$run_dir/admission.stdout.json"
python3 -m cxl_nic.timing "${common[@]}" --gap-delay-ns 800 \
    --ncp-withdraw-ns 200 --policies C,D1,E \
    --output "$run_dir/withdraw" > "$run_dir/withdraw.stdout.json"
python3 -m cxl_nic.timing "${common[@]}" --gap-delay-ns 800 \
    --push-credit-bytes-per-flow 1536 --policies B1,D1,D1-host-control \
    --output "$run_dir/credit-1536" > "$run_dir/credit-1536.stdout.json"
python3 -m cxl_nic.timing "${common[@]}" --gap-delay-ns 800 \
    --packet-stride-lines 128 --policies "$core_policies" \
    --output "$run_dir/stride-128" > "$run_dir/stride-128.stdout.json"
python3 -m cxl_nic.timing "${common[@]}" --gap-delay-ns 800 \
    --packet-stride-lines 129 --policies "$core_policies" \
    --output "$run_dir/stride-129" > "$run_dir/stride-129.stdout.json"
python3 -m cxl_nic.timing "${common[@]}" --gap-delay-ns 800 \
    --ncp-gate-resident-lines 0 --policies D1,D1-gated \
    --output "$run_dir/gate-0000" > "$run_dir/gate-0000.stdout.json"
python3 -m cxl_nic.timing "${common[@]}" --gap-delay-ns 800 \
    --ncp-gate-resident-lines 32 --policies D1,D1-gated \
    --output "$run_dir/gate-0032" > "$run_dir/gate-0032.stdout.json"
python3 -m cxl_nic.timing "${common[@]}" --gap-delay-ns 800 \
    --ncp-gate-resident-lines 513 --policies D1,D1-gated \
    --output "$run_dir/gate-0513" > "$run_dir/gate-0513.stdout.json"

python3 - "$run_dir" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

run = Path(sys.argv[1])
names = ('matrix', 'gap-0000', 'gap-0200', 'gap-0800', 'gap-2400',
         'pressure', 'admission', 'withdraw', 'credit-1536', 'stride-128',
         'stride-129', 'gate-0000', 'gate-0032', 'gate-0513')
results = {name: json.loads((run / name / 'result.json').read_text()) for name in names}
for name, result in results.items():
    if result['status'] != 'passed' or not result['assumptions']['reliable_delivery']:
        raise SystemExit(f'{name}: failed or changed the reliable-delivery scope')
for name in ('matrix', 'gap-0000', 'gap-0200', 'gap-0800', 'gap-2400',
             'pressure', 'credit-1536', 'stride-128', 'stride-129'):
    if results[name]['fairness_control'] != 'passed':
        raise SystemExit(f'{name}: matched B1/D1-host label control failed')
if results['admission']['fairness_control'] != 'not_applicable_different_policy':
    raise SystemExit('admission: unequal way policies were not identified')
for name in ('gap-0200', 'gap-0800', 'gap-2400'):
    arms = results[name]['arms']
    if arms['C']['sequence_wait_ns']['max'] != 0 or arms['D1']['sequence_wait_ns']['max'] <= 0:
        raise SystemExit(f'{name}: sequence-aware injection did not wait for the gap')
if (results['stride-128']['arms']['C']['payload_first_demand'] ==
        results['stride-129']['arms']['C']['payload_first_demand']):
    raise SystemExit('packet-stride sensitivity case did not change the C cache result')
for result in results.values():
    for arm in result['arms'].values():
        demand = arm['payload_first_demand']
        if demand['hits'] + demand['misses'] != demand['lines']:
            raise SystemExit('first-demand denominator is inconsistent')
        if arm['link_bytes'] != arm['producer_link_bytes'] + arm['cpu_nic_read_bytes']:
            raise SystemExit('modeled link traffic is inconsistent')

gate_zero = results['gate-0000']['arms']['D1-gated']
gate_mixed = results['gate-0032']['arms']['D1-gated']
gate_full = results['gate-0513']['arms']['D1-gated']
if (gate_zero['adaptive_gate']['ncp_lines'] != 0
        or gate_zero['adaptive_gate']['nc_write_lines'] != gate_zero['payload_first_demand']['lines']
        or gate_zero['adaptive_gate']['nc_write_bytes'] != gate_zero['payload_first_demand']['lines'] * 64
        or gate_zero['payload_first_demand']['misses'] != gate_zero['payload_first_demand']['lines']):
    raise SystemExit('zero-threshold gate did not send every payload line to NIC backing')
if not (gate_mixed['adaptive_gate']['ncp_lines'] > 0
        and gate_mixed['adaptive_gate']['nc_write_lines'] > 0):
    raise SystemExit('threshold-32 gate did not exercise both placement choices')
if (gate_full['adaptive_gate']['nc_write_lines'] != 0
        or gate_full['adaptive_gate']['ncp_lines'] != gate_full['payload_first_demand']['lines']):
    raise SystemExit('above-capacity gate did not push every payload line')
for key in ('duration_ns', 'delivery_latency_ns', 'sequence_wait_ns',
            'push_to_first_demand_ns', 'payload_first_demand', 'link_bytes',
            'producer_link_bytes', 'cpu_nic_read_bytes', 'payload_push_bytes',
            'background_demand', 'backing_traffic_bytes', 'credit_stall_ns',
            'packet_records', 'cache_before_final_flush'):
    if gate_full[key] != results['gate-0513']['arms']['D1'][key]:
        raise SystemExit(f'above-capacity gate changed D1 behavior: {key}')

def short(arm):
    return {'p50_ns': arm['delivery_latency_ns']['p50'],
            'p99_ns': arm['delivery_latency_ns']['p99'],
            'first_hit_rate': arm['payload_first_demand']['hit_rate'],
            'background_hit_rate': arm['background_demand']['hit_rate'],
            'prematurely_absent_lines': arm['admitted_absent_at_first_demand'],
            'producer_link_bytes': arm['producer_link_bytes'],
            'cpu_nic_read_bytes': arm['cpu_nic_read_bytes'],
            'cpu_reorder_buffer_peak_bytes': arm['cpu_reorder_buffer_peak_bytes'],
            'credit_stall_ns': sum(arm['credit_stall_ns'].values()),
            'adaptive_gate': arm['adaptive_gate'],
            'backing_traffic_bytes': arm['backing_traffic_bytes']}

summary = {
    'status': 'passed',
    'scope': 'uncalibrated integer virtual time; reliable finite reordering only',
    'checks': {'gate_endpoints': 'passed', 'gate_mixed_choice': 'passed',
               'gate_d1_label_invariance': 'passed'},
    'cases': {name: {policy: short(arm) for policy, arm in result['arms'].items()}
              for name, result in results.items()},
    'result_sha256': {name: hashlib.sha256((run / name / 'result.json').read_bytes()).hexdigest()
                      for name in names},
}
(run / 'result.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
print(json.dumps(summary, sort_keys=True))
PY
