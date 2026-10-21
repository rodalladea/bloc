# bloc

Open-source identity and access management, built with Rust and HTMX.

bloc aims to provide centralized login, configurable identity providers, OpenID
Connect, OAuth authorization for third-party applications, and SAML federation.

**Status: administrator access implementation under verification.** Server-rendered
setup, sign-in, sessions, password change, operator recovery and administration
home now use shared PostgreSQL. Production authentication approval remains blocked
on full acceptance and MFA; application-user identity, provider configuration,
OIDC/OAuth token issuance and SAML are not implemented.

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

PostgreSQL integration tests use disposable Docker fixtures:

```sh
docker pull postgres:17.11-bookworm
docker pull postgres:18.6-bookworm
python3 tests/run_storage.py --output /tmp/bloc-storage-new
```

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
Administrator integration and native full-service acceptance remain under verification.
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
`native_service_capacity` deliberately fails without
`BLOC_NATIVE_SERVICE_EVIDENCE` containing real full-service records from **both**
native Linux architectures. Run
`python3 tests/support/native_service_capacity.py --output <new-external-directory>`
on each native architecture, retain raw records, and combine the two `record.json`
objects in one JSON array. This gate is currently pending; no successful full
feature acceptance is claimed from the ordinary unit checks.

Live browser tests additionally require Playwright and a local pinned HTTPS proxy
at `https://bloc.example.test:4443` forwarding to two loopback service ports31001
and31002. Run `tests/run_storage.py` with `--browser-python <python>` and
`--tls-spki <synthetic-SPKI-pin>` to include the five named browser checks on both
database majors. The fixture suite requires local Docker and does not exercise a
production ingress certificate. Run service/browser suites serially to avoid
colliding with their fixed test ports.
