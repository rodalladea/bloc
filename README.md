# bloc

Open-source identity and access management, built with Rust and HTMX.

bloc aims to provide centralized login, configurable identity providers, OpenID
Connect, OAuth authorization for third-party applications, and SAML federation.

**Status: initial scaffold.** The HTTP server, development landing page, HTMX
status interaction, and liveness endpoint work. Authentication, users, storage,
provider configuration, token issuance, and SAML are **not implemented**. Do not
use this scaffold to protect applications or process real credentials.

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

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, commits, pull requests, and review.
Use the [BDD workflow](docs/development-workflow.md) to define feature behavior
with examples and connect decisions to tests.
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
