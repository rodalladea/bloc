# bloc

Open-source identity and access management, built with Rust and HTMX.

bloc aims to provide centralized login, configurable identity providers, OpenID
Connect, OAuth authorization for third-party applications, and SAML federation.

**Status: HTTP scaffold with internal setup storage.** The HTTP server,
development landing page, HTMX status interaction, and liveness endpoint work.
Browser authentication, user management, provider configuration, token issuance,
and SAML are **not implemented**. Do not
use this scaffold to protect applications or process real credentials.

Internal administrator setup storage, explicit migrations and an operator
setup-code command are available for integration work. No browser setup or
authentication route is exposed. See the [setup storage runbook](docs/administrator-setup-storage.md)
for separate database roles, configuration and live PostgreSQL tests.

## Run locally

Install Rust using [rustup](https://rustup.rs/). The repository pins its toolchain
in `rust-toolchain.toml`; Cargo downloads dependencies on the first build.

```sh
cargo run --locked
```

Open <http://127.0.0.1:3000>. No Node.js, database, or external identity provider
is needed. HTMX is pinned and served locally.

Configuration comes from process environment variables. `.env.example` is a
reference; `.env` files are not loaded automatically.

| Variable | Default | Purpose |
| --- | --- | --- |
| `BLOC_BIND_ADDR` | `127.0.0.1:3000` | Socket address for the HTTP listener |
| `RUST_LOG` | `info` | Log filter |

```sh
BLOC_BIND_ADDR=127.0.0.1:4000 RUST_LOG=debug cargo run --locked
```

`GET /healthz` reports process liveness only. It is not a dependency readiness or
security check. Ctrl-C and, on Unix, SIGTERM trigger graceful shutdown.

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
Distribution still contains only the scaffold, with no identity features.
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
