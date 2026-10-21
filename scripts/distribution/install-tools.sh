#!/usr/bin/env bash
set -euo pipefail
# CI tools are isolated from the application runtime.
case "${1:-all}" in
  all|helm) ;;
  *) echo "Usage: $0 [all|helm]" >&2; exit 2 ;;
esac
arch=$(uname -m)
case "$arch" in
  x86_64) arch=amd64; helm_sha=0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b; kind_sha=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d ;;
  aarch64) arch=arm64; helm_sha=8cf8f66ecbc252ac8f7f06cca68aba88508ddfde3a6a34feb1678ad1694b4f88; kind_sha=20022bee6cfcd5086cb7234d218e3454e6090022f2a8f55d1fa7fcf42c3867a2 ;;
  *) echo 'CI supports Linux amd64/arm64 only' >&2; exit 1 ;;
esac
tools_dir="${RUNNER_TEMP:?}/bloc-tools"
mkdir -p "$tools_dir"
curl --fail --location --retry 3 "https://get.helm.sh/helm-v4.3.1-linux-${arch}.tar.gz" -o "$tools_dir/helm.tar.gz"
printf '%s  %s\n' "$helm_sha" "$tools_dir/helm.tar.gz" | sha256sum --check
tar -xzf "$tools_dir/helm.tar.gz" -C "$tools_dir"
cp "$tools_dir/linux-$arch/helm" "$tools_dir/helm"
chmod +x "$tools_dir/helm"
if [[ "${1:-all}" == all ]]; then
  curl --fail --location --retry 3 "https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-${arch}" -o "$tools_dir/kind"
  printf '%s  %s\n' "$kind_sha" "$tools_dir/kind" | sha256sum --check
  chmod +x "$tools_dir/kind"
fi
printf '%s\n' "$tools_dir" >> "$GITHUB_PATH"
