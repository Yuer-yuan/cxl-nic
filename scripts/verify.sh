#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: scripts/verify.sh NEW_RESULT_DIRECTORY" >&2
    exit 2
fi

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"
run_dir=$1
mkdir -p -- "$(dirname -- "$run_dir")"
mkdir -- "$run_dir"

python3 - <<'PY'
import sys
if sys.flags.optimize:
    raise SystemExit("Verification requires Python assertions enabled (no -O/PYTHONOPTIMIZE).")
PY

if ! python3 -m unittest discover -s tests -v > "$run_dir/unit-tests.log" 2>&1; then
    cat "$run_dir/unit-tests.log"
    exit 1
fi
tail -n 5 "$run_dir/unit-tests.log"

python3 -m cxl_nic.verify --output "$run_dir/verification" \
    --seeds "${VERIFY_SEEDS:-64}" \
    --packets-per-flow "${VERIFY_PACKETS_PER_FLOW:-48}"

python3 - "$run_dir" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

run = Path(sys.argv[1])
files = [Path('.gitignore'), Path('README.md')]
for directory in ('cxl_nic', 'tests', 'scripts'):
    files.extend(p for p in Path(directory).rglob('*')
                 if p.is_file() and '__pycache__' not in p.parts and p.suffix in ('.py', '.sh'))
manifest = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}
result = json.loads((run / 'verification/result.json').read_text())
evidence = {'status': result['status'], 'source_sha256': manifest,
            'unit_test_log_sha256': hashlib.sha256((run / 'unit-tests.log').read_bytes()).hexdigest(),
            'result_sha256': hashlib.sha256((run / 'verification/result.json').read_bytes()).hexdigest()}
(run / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n')
print('Evidence:', run / 'evidence.json')
PY
