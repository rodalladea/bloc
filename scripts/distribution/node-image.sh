#!/usr/bin/env bash
# Cache the disposable node image, never a running cluster or application evidence.
set -euo pipefail
image=bloc-test-node:v1.36.5
cache_dir=${RUNNER_TEMP:+$RUNNER_TEMP/node-image}
if docker image inspect "$image" >/dev/null 2>&1; then
  exit 0
fi
if [[ -n "$cache_dir" && -f "$cache_dir/node.tar.zst" ]]; then
  zstd --decompress --stdout "$cache_dir/node.tar.zst" | docker load
else
  kind build node-image --type release v1.36.5 --image "$image" \
    --base-image kindest/base:v20260820-69b56db7@sha256:8098fa3cae05bc15d9c4b93a566d19e1f8e65a25e26ebeb993b6cb41142cf791
  if [[ -n "$cache_dir" ]]; then
    mkdir -p "$cache_dir"
    docker save "$image" | zstd -T0 -3 -o "$cache_dir/node.tar.zst.tmp"
    mv "$cache_dir/node.tar.zst.tmp" "$cache_dir/node.tar.zst"
  fi
fi
docker image inspect "$image" >/dev/null
