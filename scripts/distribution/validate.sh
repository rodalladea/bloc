#!/usr/bin/env bash
set -euo pipefail
mkdir -p evidence
RUSTUP_AUTO_INSTALL=1 rustup show active-toolchain
printf 'Starting source checks/audit alongside distribution validation.\n'
bash scripts/distribution/source-checks.sh >evidence/source-validation.log 2>&1 &
source_pid=$!
finish_source() {
  if [[ -n "$source_pid" ]]; then
    local status=0
    wait "$source_pid" || status=1
    source_pid=
    cat evidence/source-validation.log
    return "$status"
  fi
}
trap 'finish_source || true' EXIT
python3 -m unittest discover -s tests/distribution -p 'test_*.py' -v 2>&1 | tee evidence/release-policy.log
python3 tests/distribution/chart.py 2>&1 | tee evidence/chart-schema.log
revision=$(git rev-parse HEAD)
version=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml","rb"))["package"]["version"])')
python3 scripts/distribution/candidate.py --platform platforms/amd64/image --platform platforms/arm64/image --revision "$revision" --version "$version"
bash tests/distribution/setup-cluster.sh candidate/image
finish_source
printf 'Source checks and all cluster suites passed; completing candidate evidence.\n'
python3 tests/distribution/registry.py --layout candidate/image --revision "$revision" 2>&1 | tee evidence/registry.log
cp platforms/amd64/smoke.log evidence/amd64.log
cp platforms/arm64/smoke.log evidence/arm64.log
cp -R evidence candidate/evidence
python3 - <<'PY'
import json, subprocess, sys, tomllib
from pathlib import Path
sys.path.insert(0,'scripts/distribution')
from oci import Layout
from release import REQUIRED, evidence
record={'revision':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
        'version':tomllib.load(open('Cargo.toml','rb'))['package']['version'],
        'image':Layout('candidate/image').root()['digest'],
        'chart':Layout('candidate/chart').root()['digest'],
        'helm':'4.3.1','kubernetes':'1.36.5','passed':sorted(REQUIRED)}
Path('candidate/evidence.json').write_text(json.dumps(record,indent=2)+'\n')
evidence(Path('candidate'),record['revision'],record['version'])
PY
