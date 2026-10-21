# Administrator access operations

This increment is for development and evaluation. MFA, application-user identity,
OIDC, OAuth, SAML and production authentication approval remain outside this
increment. ADR 0004 remains proposed. The HTTP implementation uses shared
PostgreSQL authority; acceptance evidence and gaps are recorded in the behavior
record. Do not infer native service capacity from primitive hashing measurements.

## Deployment

Provision PostgreSQL 17 or 18 with a verified server certificate and the separate
roles described in [setup storage](administrator-setup-storage.md). Back up the
database with its role provisioning and migration metadata. Encrypt backups and
restrict restore, migration, operator exec and terminal/session recording access.
The database must be a writable primary. Replicas never migrate automatically.

A runtime process requires these environment variables, in addition to its bind
address and optional redacted log filter:

| Variable | Value |
| --- | --- |
| BLOC_DATABASE_URL_FILE | File with the runtime PostgreSQL URL, at most 16 KiB |
| BLOC_DATABASE_CA_FILE | Trusted database CA certificate file |
| BLOC_CANONICAL_ORIGIN | Exact public HTTPS origin, including nondefault port |
| BLOC_TRUSTED_PROXY_CIDRS | Explicit comma-separated immediate ingress peer CIDRs |
| BLOC_ABUSE_KEY_FILE | Deployment-shared file of exactly 32 random binary bytes |

Generate the abuse key outside logs and provision it identically to every
replica. Never mount migrator, operator or maintenance credentials into serving
replicas. Configuration failures exit 2 with a bounded error. A temporary primary
outage leaves `/healthz` live and `/readyz` unavailable; protected operations fail
closed with 503. Readiness checks the exact embedded migration checksums and
writable-primary status. New/old schema mismatch requires a coordinated rollout.

Terminate TLS at an ingress that overwrites incoming `X-Forwarded-For` and
`X-Forwarded-Proto`, emits exactly one source IP and `https`, and preserves the
canonical Host. Forwarded Host never grants authority. Network policy must restrict
backend access to that ingress; configuring a broad trusted CIDR is not equivalent
to restricting ingress. Browser operations require canonical Origin, or an HTTPS
same-origin Referer fallback, and shared CSRF state.

For local HTTPS, run bloc on loopback behind a local TLS reverse proxy. Use a
locally trusted development certificate, an explicit canonical HTTPS origin and
loopback proxy CIDR. Configure the proxy to overwrite forwarding headers as above.
Direct HTTP browser access does not satisfy the Secure-cookie contract. Never
disable production certificate verification to reproduce local tests.

The Helm chart references an operator-owned Secret with `runtime-url`, `ca.crt`
and `abuse-key`; operations additionally use `migrator-url`, `operator-url` and
`maintenance-url`. Set `access.secretName`, `access.canonicalOrigin` and
`access.trustedProxyCIDRs` explicitly. Optional `migrationJob`, `operatorPod` and
`maintenanceJob` render separate identities; enable a migration Job only in a
coordinated migration release, then disable it. The maintenance CronJob runs daily;
monitor Job failures and missing executions. An operator Pod sleeps and receives
codes only through an attached exec, never its primary command.

The integration resource envelope is 1 CPU/512 MiB, one immediate-acquisition
password worker per process, Argon2id v19 m=65536,t=3,p=1 and
`MALLOC_MMAP_THRESHOLD_=131072` on Linux/glibc. This allocator setting reflects
native primitive evidence. Full-service native amd64 and arm64 capacity acceptance
is separate and remains required; emulation is not evidence. Hash saturation
returns 503/Retry-After 1 without queueing; shared admission returns 429 and a
release-covering Retry-After. Multi-bucket refusal reserves no units.

## Initial ownership and recovery

Using migrator credentials, run `bloc database migrate` explicitly, then deploy
runtime replicas. Using operator credentials in an attached terminal, run:

```sh
kubectl exec -it bloc-operator -- /usr/local/bin/bloc admin setup-code
```

Use the actual chart operator Pod name (`<release>-bloc-operator` according to
name overrides); it is a Pod, not a serving Deployment. The exact command prints
only `code=<secret>` and `expires_at=<UTC RFC3339>`, each followed by a newline,
after durable commit. Open `/admin/setup` explicitly; there is no public onboarding
link. Choose the unverified email identifier and a 15–128 Unicode-scalar password
(maximum 512 UTF-8 bytes), then sign in. Spaces/paste are permitted; no composition
or breached-password screening is applied. No verification email is sent.

Codes last exactly 15 minutes; issuing a replacement invalidates its predecessor.
Lost operator output requires replacement. Closed/no-owner action refusal exits 3;
configuration/usage exits 2; database/audit/output failure exits 1. Never pass codes
or passwords as command-line arguments or put code output in routine logs.

For access recovery, use the same attached exec with `bloc admin recovery-code`
and open `/admin/recovery`. Issuance leaves current credentials and sessions usable.
Successful recovery changes the password, preserves owner identity, increments
credential version and ends every session atomically. Ordinary password change
requires the current password and has the same global session invalidation.
Codes and cookies are stored only as digests; CSRF readable tokens are independent
of digest-only browser bearers. Sessions expire at 30 minutes idle or 12 hours
absolute, and are checked against PostgreSQL on each protected request.

## Backup and restore

1. Fence ingress and stop **all** serving replicas and operator activity. Keep
   traffic fenced throughout restore, invalidation and recovery; readiness alone
   does not prove that restored authority is safe.
2. Restore a consistent encrypted PostgreSQL backup, including `_sqlx_migrations`,
   and provision the separate roles. Use a supported writable primary and verify
   the binary's exact migration contract. Do not edit migration checksums.
3. With operator credentials run `bloc admin invalidate-access`. This transaction
   increments credential version, revokes sessions, deletes all operator codes
   and form authority, appends restore audit, and sets a durable recovery fence
   for an owned installation. The restored owner and password hash are retained,
   but password sign-in remains blocked until authorized recovery succeeds.
4. If ownership existed, issue a **new** recovery code after invalidation and
   complete recovery through a restricted maintenance path. If no owner existed,
   issue a **new** setup code and complete setup. Old restored codes, browser form
   authority and sessions must fail on both replicas.
5. Start two runtime replicas behind a restricted verification path. Verify old
   cookie/code rejection, new-password sign-in, cross-instance session behavior,
   logout replay rejection, healthy readiness and liveness. Only then reopen
   ingress. Failed invalidation, audit append or recovery keeps traffic fenced.

After a committed response is lost, ownership/new credentials remain authoritative;
replaying setup returns closed and replaying recovery cannot replace credentials.
Never recover by directly editing password or session tables. Success audit failure
rolls back the complete security transition. Failed logout clears browser cookies
but does not claim database revocation; retry after availability is restored.

## Maintenance and verification

Run `bloc database maintain` with maintenance credentials daily. Each invocation
deletes up to 1,000 success audits older than 90 days and 1,000 denial aggregates
older than 7 days, plus bounded expired form/admission state. Repeat while batches
remain; monitor failures, scheduler freshness and retention lag. Fixed denial
categories use saturating counters without identifiers/IPs or individual events.
Storage errors are bounded operational failures, never authorization success.

Run the README checks and `tests/run_storage.py` for real TLS PostgreSQL fixtures.
The administrator integration suite distinguishes HTTP, database, real service and
browser evidence; ignored tests require explicit fixture execution. Native capacity
acceptance must preserve raw failures and demonstrate both native architectures,
1 CPU/512 MiB/no swap, 20 simultaneous submissions over 60 seconds, peak <=384 MiB,
p95 full credential latency <1 second, immediate overload, no OOM and healthy
probes. A passing unit suite cannot substitute for that service acceptance.
