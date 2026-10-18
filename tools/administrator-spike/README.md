# Administrator prerequisite spikes

This isolated package benchmarks synthetic Argon2id work for issue #5. It is not
linked into bloc, and adds no authentication feature or application dependency.
The contract and results belong in Catapio Drive, rather than this directory.

Build with the pinned Docker bases and the committed dependency lockfile:

```sh
docker build -t bloc-administrator-spike:local tools/administrator-spike
python3 tools/administrator-spike/run.py --output evidence/administrator-spike-new-run
```

The runner refuses an image whose architecture differs from the Docker engine.
It limits each container to 1 CPU, 512 MiB memory and no swap, drops capabilities,
disables networking, and captures raw CSV timings plus environment/cgroup data.
It runs 20 warmups and 200 measured operations per case: two candidate parameter
sets, two concurrency levels, four operations and two synthetic input types.
Each case gets a fresh container. Output directories must be new; partial output
is retained on failure and must not be interpreted as a completed matrix.
Container state, exit status and OOM indication are captured before that case's
container is removed. A targeted retry can use repeated `--case` arguments in a
new output directory; selected-case runs are explicitly identified in metadata
and must not be presented as a clean full-matrix run.

Use `--mmap-threshold 131072` for a separately named allocator comparison.
It passes `MALLOC_MMAP_THRESHOLD_=131072` to each container and records the
setting in environment metadata and the inspected container environment.
Omitting the flag preserves the original allocator environment and resource
limits. A comparison does not replace or erase the original OOM evidence.
Runner tests: `python3 -m unittest discover -s tools/administrator-spike -p 'test_*.py' -v`.

The synthetic verification fixture uses a fixed salt. Every measured new hash
uses fresh operating-system randomness. No supplied credentials are accepted,
and passwords and PHC encodings are not emitted.

These results cover primitive hashing and verification only. They do not settle
HTTP latency, database authority, CSRF, blocklist lookup cost, service admission,
health under overload or production readiness. Docker Desktop measurements are
virtualized native-architecture evidence, not a hardware capacity guarantee.
Native Linux amd64 evidence is required separately from Linux arm64 evidence.
The `.github/workflows/administrator-spike.yml` prepares both native runner jobs
and uploads raw results. It runs for pull requests changing the spike/probe or
workflow, and supports manual dispatch once available on the default branch.
It neither publishes images nor deploys bloc. It has to be reviewed and available
on GitHub before it can run.

Run format/lint checks independently of the application:

```sh
cargo fmt --manifest-path tools/administrator-spike/Cargo.toml -- --check
cargo clippy --manifest-path tools/administrator-spike/Cargo.toml --locked --all-targets -- -D warnings
```

The adjacent dependency probe checks crate APIs on the pinned Rust toolchain:

```sh
cargo test --manifest-path tools/administrator-dependency-probe/Cargo.toml --locked
```

That probe builds an unserved router and a lazy pool; it makes no database
connection. Its results cannot establish TLS negotiation or PostgreSQL runtime
compatibility. It also checks token primitives, rather than implementing CSRF.
