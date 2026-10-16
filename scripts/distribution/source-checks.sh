#!/usr/bin/env bash
set -euo pipefail
mkdir -p evidence
cargo fmt --all -- --check 2>&1 | tee evidence/format.log
cargo clippy --locked --all-targets -- -D warnings 2>&1 | tee evidence/lint.log
cargo test --locked --all-targets 2>&1 | tee evidence/test.log
RUSTDOCFLAGS='-D warnings' cargo doc --locked --no-deps 2>&1 | tee evidence/documentation.log
cargo install cargo-audit --version 0.22.2 --locked
cargo audit 2>&1 | tee evidence/audit.log
