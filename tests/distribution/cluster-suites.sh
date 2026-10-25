#!/usr/bin/env bash
set -euo pipefail
mkdir -p evidence
lifecycle=()
for check in {9..18} 20 21; do lifecycle+=(--check "C$check"); done
printf 'Starting lifecycle/C18 and disconnected-recovery/C19 in separate namespaces; intentional upgrade failures use 60-second fixture timeouts.\n'
python3 -u tests/distribution/cluster.py "$@" "${lifecycle[@]}" 2>&1 | tee evidence/cluster-lifecycle.log &
lifecycle_pid=$!
python3 -u tests/distribution/cluster.py "$@" --check C19 2>&1 | tee evidence/cluster-recovery.log &
recovery_pid=$!
status=0
if wait "$lifecycle_pid"; then
  printf 'Lifecycle/C18 suite passed.\n'
else
  printf 'Lifecycle/C18 suite failed; see evidence/cluster-lifecycle.log.\n' >&2
  status=1
fi
if wait "$recovery_pid"; then
  printf 'Disconnected-recovery/C19 suite passed.\n'
else
  printf 'Disconnected-recovery/C19 suite failed; see evidence/cluster-recovery.log.\n' >&2
  status=1
fi
exit "$status"
