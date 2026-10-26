# bloc

Open-source identity and access management, built with Rust and HTMX.

bloc aims to provide centralized login, configurable identity providers, OpenID
Connect, OAuth authorization for third-party applications, and SAML federation.

**Status: administrator access implemented for development and evaluation.** Server-rendered
setup, sign-in, sessions, password change, operator recovery and administration
home now use shared PostgreSQL. Production authentication approval remains blocked
on full acceptance and MFA; application-user authentication, provider configuration,
OIDC/OAuth token issuance and SAML are not implemented.

Realm and realm-bound user directories are managed at `/admin/realms`; directory
records do not authenticate users. See [directory management](docs/realm-user-management.md).

## Run locally

Install the pinned Rust toolchain and provision PostgreSQL 17 or 18 with separate
runtime/migrator/operator/maintenance roles and verified TLS. Follow the
[administrator operations runbook](docs/administrator-access.md), including the
local HTTPS proxy and required secret-file configuration. `.env.example` lists
variable names; bloc does not load `.env` files automatically.

Run explicit migrations with migrator credentials before starting runtime replicas:

```sh
cargo run --locked -- database migrate
cargo run --locked
```

The canonical root redirects to `/admin/login`. Initial ownership requires an
attached `bloc admin setup-code` invocation and explicit `/admin/setup` access.
`/healthz` is process liveness; `/readyz` checks compatible primary authority.
Ctrl-C/SIGTERM trigger graceful shutdown. Never use operator credentials to serve
HTTP traffic or expose operator code output through routine container logs.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo doc --locked --no-deps
```

The test profile optimizes the Argon2 dependency to avoid repeating expensive
unoptimized password work. Password parameters, application debug assertions,
and release settings are unchanged.

PostgreSQL integration tests use disposable Docker fixtures:

```sh
docker pull postgres:17.11-bookworm
docker pull postgres:18.6-bookworm
python3 tests/run_storage.py --output /tmp/bloc-storage-new
```

Use `--major 17` or `--major 18` to run one database version. The runner pulls
only the selected images and cleans up its disposable containers. Each fixture
has a two-CPU limit. Test output streams to the console and the per-major log
in the output directory while tests run, including before a test completes.

PR CI runs formatting, lint, ordinary tests, packaging policy tests and docs for
code/build changes; documentation-only changes omit compilation and database jobs.
Database suites run on PostgreSQL 17 and 18 in parallel when runtime, tests,
dependencies, chart or build configuration changes. Documentation-only changes
omit database fixtures. Distribution scripts/tests and unrelated workflow changes
run source/policy checks without database fixtures. Templates, assets, chart and
shared-fixture changes retain both database suites. Unknown paths default to full
validation. Rust dependencies/build outputs are cached per CI lane and revision,
restoring the latest compatible dependency/toolchain cache. GitHub manages cache
quota and eviction; caches never substitute for executing checks.
PR title edits run only the lightweight title check.
See the [CI behavior record](docs/behaviors/ci-efficiency.md) for selection rules
and verification boundaries.

Python CI and distribution policy tests require the pinned test-only YAML parser:

```sh
python3 -m venv /tmp/bloc-test-venv
. /tmp/bloc-test-venv/bin/activate
python3 -m pip install --requirement tests/requirements.txt
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m unittest discover -s tests/distribution -p 'test_*.py' -v
```

The distribution tests also require the pinned Helm executable described below.

The dependency audit runs for dependency/toolchain/auditor changes, weekly, or
manually. The pinned auditor executable is cached and its version checked before
reuse; the advisory audit still runs every time. Full
multi-platform image/Kubernetes validation runs through the **Distribution**
workflow manually or on version tags. Run it for packaging changes before merging
or releasing. Capacity benchmarks run manually through **Administrator service
capacity** and as part of Distribution; ordinary PRs do not build benchmark images.
Distribution builds each native platform once. Native smoke/capacity measurements
and source/Kubernetes validation then run in parallel against those retained
images. Candidate completion requires both native records, matched to the exact
platform manifests and source revision. BuildKit layers are
cached per native architecture; Rust dependencies occupy a separate build layer,
and each refreshed cache replaces its predecessor to avoid accumulating old blobs.
Exact primary-key hits still build/export the attested image but skip cache export;
partial restores and misses refresh the cache only after a successful build.
The **Release cache warming** workflow prepares both native build caches and the
pinned kind node image on relevant main-branch changes, making them available to
new tags. Distribution can also restore a compatible Rust check-lane cache from
main. Node caches contain a compressed image, never a cluster or validation proof.
Intentional C18/C19 upgrade failures use 60-second fixture timeouts; successful
operations and the operator runbook retain five-minute waits. Cluster lifecycle/ingress,
probes with automatic rollback, and disconnected recovery run in three isolated
namespaces. Every group must pass; all C9–C21 scenarios remain required.

See the [storage runbook](docs/administrator-setup-storage.md#verification) for
fixture requirements. Previews and one-off experiments are kept outside this repository.

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, commits, pull requests, and review.
Use the [BDD workflow](docs/development-workflow.md) to define feature behavior
with examples and connect decisions to tests.

## Distribution

Container packaging and the Helm chart target Linux amd64 and arm64, with the
first unified release version `0.0.1`. See the [installation runbook](docs/install.md)
for configuration, optional ingress, upgrades, recovery, and uninstall, and the
[release procedure](docs/releases.md) for publication gates and retry rules.
Public package availability requires a completed GitHub release; the presence of
packaging source does not mean a release has been published. The source chart
requires an explicit image digest; release packaging supplies the verified digest.

The initial cluster exercise baseline is Helm 4.3.1 and Kubernetes 1.36.5.
Administrator acceptance requires the mapped integration proofs and native full-service
measurements. Check the current CI results and verification record before acceptance.
See [AGENTS.md](AGENTS.md) for the AI agent instruction index.

## Project guide

- [GitHub repository](https://github.com/rodalladea/bloc) and [issue tracker](https://github.com/rodalladea/bloc/issues)
- [Architecture](docs/architecture.md) and [decision records](docs/adr/0001-foundation.md)
- [Roadmap](docs/roadmap.md)
- [Security policy](SECURITY.md) and [security design requirements](docs/security.md)
- [Code of conduct](CODE_OF_CONDUCT.md) and [governance](GOVERNANCE.md)
- [Changelog](CHANGELOG.md) and [release process](docs/releases.md)

## License

bloc is licensed under [Apache-2.0](LICENSE). Contributions use the same license.
Vendored dependencies retain their own licenses; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

The chart proof requires Helm 4.3.1 on `PATH` (or set `BLOC_HELM` to its executable).
The explicit `native_service_capacity` proof deliberately fails without
`BLOC_NATIVE_SERVICE_EVIDENCE` containing real full-service records from **both**
native Linux architectures. Run
`python3 tests/support/native_service_capacity.py --output <new-external-directory>`
on each native architecture, retain raw records, and combine the two `record.json`
objects in one JSON array. Invoke the proof with
`cargo test --locked --test administrator_access native_service_capacity -- --ignored --exact`
and `BLOC_NATIVE_SERVICE_EVIDENCE` pointing to that array. Distribution validates
both records against the current application fingerprint; ordinary unit checks
do not run this heavyweight proof or establish capacity acceptance.

Live browser tests additionally require Playwright and a local pinned HTTPS proxy
at `https://bloc.example.test:4443` forwarding to two loopback service ports31001
and31002. Run `tests/run_storage.py` with `--browser-python <python>` and
`--tls-spki <synthetic-SPKI-pin>` to include the twelve named browser checks on both
database majors. The fixture suite requires local Docker and does not exercise a
production ingress certificate. Run service/browser suites serially to avoid
colliding with their fixed test ports. For focused directory iteration, add
`--target realm_user_management`; `--proof directory_c01` selects one exact proof.
Use `--cached-images` only when the pinned fixture images are already present and
registry access is unavailable; the evidence still records their image IDs/digests.

To check both executable/schema upgrade directions, build the current binary and
run `python3 tests/directory_binary_compatibility.py --legacy-binary <retained-pre-directory-binary> --current-binary target/debug/bloc --output <new-external-directory>`.
This snapshots both executables and uses disposable PostgreSQL 17/18 fixtures.
