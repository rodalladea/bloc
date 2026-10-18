# Administrator setup storage

This is the internal storage and operator-command delivery. There is no browser
setup, password validation/hashing, sign-in or recovery endpoint yet. Do not use
it to protect applications or process real credentials. ADR 0004 is proposed.

The requester-approved policy, finalized setup-storage RFC and task live in Drive:

- `projects/bloc/design/administrator-access-prerequisites.md`, ID `e8e306130bdbf3a9b158f1fe1c757a6baed52ae8f212b4fa`.
- `projects/bloc/design/administrator-access-security-storage.md`, ID `4bcaafc1a56954360b14426d7fe92239d1a351dcd0a55487`.
- `projects/bloc/.tasks/administrator-access.md`, ID `87bd2c0006669399f6e64c832b144da78fd0bbeca80fb059`.

## Database authority

Use a writable PostgreSQL 17 or 18 primary, current minor release, with TLS and
an explicit CA whose certificate matches the TCP hostname. No standby or local
filesystem fallback is supported. bloc does not provision database availability.

The database operator provisions these capability roles once:

```sql
CREATE ROLE bloc_runtime NOLOGIN NOINHERIT;
CREATE ROLE bloc_operator NOLOGIN NOINHERIT;
CREATE ROLE bloc_maintenance NOLOGIN NOINHERIT;
```

Provision separate login identities for migrations, runtime, attached operator
commands and maintenance; inject their credentials from operator-owned Secrets.
Only the migration login owns the application database/schema/functions. Grant
each other login only membership in its matching capability role. No capability
role/login may be a superuser, create roles/databases, bypass RLS, inherit migration
authority, own the database, or create objects in trusted schemas. These grants
cannot protect against an operator who changes the database security policy.
The maintenance role currently has no operations.

The explicit migration creates the private `bloc` schema, four setup tables and
two guarded functions. Runtime can claim an existing code; operator can issue or
replace one. Neither has direct table writes. Application statement logging is
disabled. Database operators must also disable bind-parameter logging, including
`log_parameter_max_length_on_error`, and sensitive statement capture in database
proxies/audit tooling. Application logs cannot control external database logging.

## Commands

Set `BLOC_DATABASE_URL_FILE` to a mounted file containing one PostgreSQL TCP URL
(at most 16 KiB) and `BLOC_DATABASE_CA_FILE` to the trusted PEM CA file. URL
`sslmode` is overridden with VerifyFull; URL `options` are rejected. bloc sets
statement timeout to 3 seconds, lock timeout to 1 second, pool acquisition timeout
to 2 seconds and at most 5 connections. Options/credentials never enter errors.

Run migrations explicitly with migration credentials:

```sh
bloc database migrate
```

Migrations are forward only, locked and checksum validated. Serving replicas do
not auto-migrate. The binary requires exactly its applied migration set/checksums
before issuing or consuming authority. No incompatible mixed-version migration
support is claimed. Do not edit a migration once applied to a retained database.

With separate operator credentials, use an attached authorized exec stream:

```sh
bloc admin setup-code
```

Successful stdout contains exactly two lines, `code=<secret>` and
`expires_at=<UTC RFC3339>`, after commit. The command takes no secret arguments.
Never use it as a pod/Job entrypoint: Kubernetes collects main-process stdout.
Restrict exec permissions and terminal recording. Lost output is resolved by
issuing a replacement; every replacement invalidates its predecessor. Codes
expire at their 15-minute deadline, and setup closes permanently after ownership.

Exit codes: 0 success/help, 1 storage/audit/output failure, 2 usage/configuration,
3 setup closed. Database failure emits no code. Output transport failure can
occur after commit; output cannot be made transactional with PostgreSQL.

The internal `Storage::claim_owner` accepts only a validated identifier and PHC
hash from a trusted application consumer. It is not a public operator API and
performs no password hashing. Browser consumers must enforce canonical origin,
trusted ingress identity, CSRF, input/credential validation, shared admission and
bounded hashing before this call. No such consumer is exposed yet.

## Verification

With Docker, Python 3, OpenSSL and the pinned Rust toolchain:

```sh
docker pull postgres:17.11-bookworm
docker pull postgres:18.6-bookworm
python3 tools/administrator-setup-tests.py --output /tmp/bloc-setup-new
```

The runner reuses disposable TLS fixtures from the dependency probe, binds only
loopback random ports, creates synthetic role-separated databases and runs all
ten named live proofs per major. It records server/image identity and output,
fails if any named proof was omitted, and removes containers/volumes/keys on exit.
Regular `cargo test --locked --all-targets` marks these live tests ignored; it does
not substitute for the fixture runner. This delivery changes no chart/startup
readiness behavior. Full-service overload, browser, restore and two-instance
deployment acceptance remain outstanding.
