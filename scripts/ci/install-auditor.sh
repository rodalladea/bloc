#!/usr/bin/env bash
set -euo pipefail
root="${BLOC_CI_TOOLS_DIR:-${HOME}/.cache/bloc-tools}"
version=0.22.2
if [[ ! -x "$root/bin/cargo-audit" ]] || [[ "$("$root/bin/cargo-audit" --version)" != "cargo-audit $version" ]]; then
  cargo install cargo-audit --version "$version" --locked --root "$root" --force
fi
export PATH="$root/bin:$PATH"
if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "$root/bin" >> "$GITHUB_PATH"
fi
