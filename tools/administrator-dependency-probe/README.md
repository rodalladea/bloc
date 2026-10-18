# Administrator dependency probe

This isolated package checks candidate dependency APIs and PostgreSQL transport.
It is not linked into bloc and implements no authentication or application schema.

Run the four API/vector tests with the pinned toolchain:

```sh
cargo test --manifest-path tools/administrator-dependency-probe/Cargo.toml --locked
```

Run the live TLS checks with Docker, Python 3 and OpenSSL available:

```sh
python3 tools/administrator-dependency-probe/live.py --output evidence/administrator-postgres-tls-new
```

The runner pulls the official PostgreSQL 17.11 and 18.6 bookworm images, records
their resolved identities and actual server versions, and creates disposable
fixtures bound to random loopback ports. Each container has a 256-MiB memory
limit, no swap and half a CPU. Generated CAs, private keys and synthetic database
credentials are test fixtures only; private keys are never saved as evidence.
The runner removes its containers and anonymous volumes on success or failure.
Use a new output directory each time; partial evidence remains visible on failure.

Each major runs four named Rust integration tests: a verified encrypted connection
to the expected server major, an untrusted CA, a certificate for another IP, and a
server without TLS. Certificate refusals assert their specific cause, so a TCP
connection failure cannot pass. SQLx 0.9 reports certificate handshake errors as
I/O errors wrapping certificate failures. Tests require the live runner and are
explicitly ignored in the API-only command above; the runner enables all four.

These checks establish transport behavior for the pinned SQLx feature set and
tested PostgreSQL images. They do not prove application configuration, migrations,
database privileges, transactions, readiness, two-instance authority or production
security. The root application's dependencies and routes remain unchanged.

Sources: [SQLx options](https://docs.rs/sqlx/0.9.0/sqlx/postgres/struct.PgConnectOptions.html),
[PostgreSQL TLS](https://www.postgresql.org/docs/18/ssl-tcp.html), and the
[official PostgreSQL image](https://hub.docker.com/_/postgres).
