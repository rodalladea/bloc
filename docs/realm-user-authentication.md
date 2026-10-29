# Realm-user authentication and My Account

Status: implemented; independent acceptance pending. Use for development and
evaluation only. This runbook describes the agreed contract; the
[behavior coverage](behaviors/realm-user-authentication.md) and independent Drive
verification determine which flows have actually passed. MFA and maintainer
production-security approval remain required.

## Upgrade and rollback

Follow the existing [administrator operations](administrator-access.md) and
[installation](install.md) procedures for verified PostgreSQL 17/18 TLS and separate
runtime, migrator, operator and maintenance credentials. Stop incompatible serving
replicas, retain an appropriate backup and run explicit migrations with the
migrator identity before starting the new binary:

```sh
cargo run --locked -- database migrate
```

Migration 0005 preserves realm/user IDs, emails, lifecycle, versions/timestamps
and historical audit. It seeds default policies and leaves every existing user
credential-less. Neither an active directory record nor a matching email grants
sign-in. Runtime startup does not migrate. Readiness rejects both a new binary on
the old schema and an old binary on the new schema; mixed incompatible rollouts
and binary-only rollback are unsupported. Retain pre-upgrade executables for the
compatibility proof, not as a supported rollback without matching schema recovery.

## Administrator workflow

Open a realm under `/admin/realms`, then Authentication. Settings remain editable
for suspended realms, but public access is unavailable. The public sign-in URL uses
the immutable realm UUID. Registration starts disabled.

| Setting | Default | Valid range |
| --- | --- | --- |
| Minimum password length |16 Unicode scalars|16–128|
| Uppercase/lowercase/number/special requirements |All off|Independent checkboxes|
| Activation lifetime |86400 seconds|300–604800|
| Reset lifetime |1800 seconds|300–86400|
| Idle session lifetime |1800 seconds|60–86400|
| Absolute session lifetime |43200 seconds|300–2592000|
| Active sessions per user/realm |10|1–100|

Idle must not exceed absolute lifetime. Lifetime controls convert units exactly
without rounding. Changes to timeout/cap require version-bound confirmation and
may immediately end sessions. Expired sessions cannot be restored by increasing
limits. Link lifetime changes apply only to newly issued links. A stale form
returns 409 with reload guidance; do not replay it automatically.

For an active credential-less user, confirm the person's identity and issue an
activation link. For a credentialed user, issue a reset link. The administrator's
identity confirmation is a human assertion. Issuance returns a canonical HTTPS
fragment link, a separate copyable code and expiry once. Do not send output through
routine logs. A lost output cannot be retrieved: issue a replacement and warn the
recipient that the old link no longer works. Reset issuance alone leaves the old
password and sessions usable until reset consumption.

Suspending a user or realm invalidates affected sessions/links/forms. Reactivation
does not restore them. Confirmed administrator email changes preserve UUID and
password, invalidate authority, and leave the replacement address unverified.
Display-name-only changes preserve outstanding links.

## User workflow

At `/realms/{realm_id}/login`, sign in with that realm's email/password. Registration
is shown only when enabled. Enrollment creates a new realm-local account, never
claims an existing directory record, and returns to sign-in without automatic
login. Generic collision feedback directs the person to an administrator.
Addresses remain unverified. There is no public recovery lookup or issuance.

An activation/reset link opens a code-entry page. JavaScript removes the fragment
from browser history and fills a password-type code field before an explicit
Continue POST. Without JavaScript, paste the separate code into the ordinary form.
GET never consumes the link. Exchange redirects to a secret-free password page;
consumption happens only on compliant password submission. An expired browser
form can be exchanged again while the original link remains valid. Replaced,
consumed, expired or wrong-purpose/realm links share generic administrator-contact
feedback. Do not put codes in query strings.

Native forms require a browser that supplies Fetch Metadata. With no-referrer,
the server accepts null Origin only for a verified same-origin document navigation
with valid canonical HTTPS ingress and CSRF. Browsers or intermediaries omitting
that metadata fail closed; do not disable origin or CSRF checks to accommodate them.

My Account derives the user from current realm authority. Profile permits only
display-name editing and labels email read-only/unverified. Password change needs
the current password, revokes old sessions/links/forms and renews current access.
Reset ends all sessions and returns to sign-in. Sessions shows only owned active
sessions in the standard directory table, ordered by created time and UUID, with
an informational device label and current-session marker. Confirming End all
other sessions preserves current access; ending the current session signs out.
An already-ended owned-session replay is a no-op.

Passwords preserve whitespace and Unicode exactly, up to 128 scalars/512 bytes.
Upper/lower composition uses Unicode letter properties; numbers mean ASCII 0–9,
special means ASCII punctuation. Policy changes affect new credentials at commit,
not the usability of existing passwords. Realm and administrator policies differ.

## Failures and recovery

- 422: correct adjacent field errors; secret fields are always cleared.
- 403 CSRF: reopen a fresh form or exchange the original link again if it is usable.
- 409: reload the current record/policy and review changes before resubmitting.
- 429: wait for Retry-After, which reflects all exhausted required budgets.
- 503 with Retry-After 1: local password worker is occupied; no waiting queue exists.
- 503 with Retry-After 60: bounded temporary-state capacity is full; live authority
is not evicted to admit new requests.
- 503 storage/audit/fence: no partial success is claimed. Failed logout clears only
the selected realm's browser bearer; durable server revocation is unconfirmed.

Multiple realms and administrator access can coexist in one browser. Oversized
headers fail closed; no global cookie-clearing response is issued. Use a separate
clean browser profile or clear only the affected realm's site cookie through
browser controls if necessary. Browser/header limits do not promise unlimited
simultaneous realm sessions. The direct server test accepted a 524,034-byte
selected-realm cookie value and rejected 524,035 bytes with HTTP 431 and no
Set-Cookie header, with the fixture's other headers and cookies held fixed.
This measures that request's server boundary, not a general cookie allowance;
deployment proxies and browsers may impose lower limits.

After restore, use the existing operator invalidation/recovery procedure. Realm
sessions, links and forms are invalidated with the durable recovery fence; retained
pre-restore bearers must not become usable after recovery. Do not use operator
credentials to serve HTTP or create realm credentials directly.

Maintenance remains bounded to 1000 eligible rows per category per invocation.
Repeat while retention lag remains. Success retention targets 90 days and denials
seven days; bounded cleanup is not an exact-time deletion guarantee. No inactive
users are automatically deleted and no cumulative registration quota applies.

Use a database-owner monitoring connection to measure retention backlog; runtime,
operator and maintenance credentials deliberately lack direct table access. This
query returns aggregate ages and counts without identity or bearer data:

```sql
WITH expired AS (
  SELECT 'success' AS category, occurred_at AS oldest_at,
         interval '90 days' AS retention
    FROM bloc.security_audit_event
   WHERE occurred_at < statement_timestamp() - interval '90 days'
  UNION ALL
  SELECT 'realm_denial', minute, interval '7 days'
    FROM bloc.realm_denial_aggregate
   WHERE minute < statement_timestamp() - interval '7 days'
  UNION ALL
  SELECT 'administrator_denial', minute, interval '7 days'
    FROM bloc.administrator_denial_aggregate
   WHERE minute < statement_timestamp() - interval '7 days'
)
SELECT category, count(*) AS eligible_rows,
       statement_timestamp() - min(oldest_at + retention) AS retention_lag
  FROM expired GROUP BY category;
```

An empty result means no expired audit backlog. If rows remain after a maintenance
job, schedule further bounded invocations and check that counts fall. Alert when
backlog persists across successive successful jobs or the job fails; select the
schedule and paging delay for the installation's retention obligations. Do not
grant runtime table access to make monitoring easier.

## Verification

The new integration target is `realm_authentication` in the existing fixture runner.
Run both database majors, with a synthetic pinned HTTPS proxy for browser proofs:

```sh
python3 tests/run_storage.py --target realm_authentication --output /tmp/bloc-realm-auth-new
```

Use `--browser-python` and `--tls-spki` together for real browser checks as described
in README. Add `--cached-images` only when pinned images are already available.
The ordinary format/lint/test/doc checks do not replace PostgreSQL, concurrency,
real-browser or native capacity evidence.

Mixed native capacity uses the established measured framework:

```sh
python3 tests/support/native_service_capacity.py --realm-auth --output /tmp/bloc-realm-native-new
```

Run on native Linux amd64 and arm64 with matching final application fingerprints.
Emulation and old administrator-only records are not realm acceptance evidence.
The harness retains the 1 CPU/512MiB/no-swap baseline, live probes and redaction,
and measures shared administrator/public admission. See the
[threat model](realm-authentication-threat-model.md) and
[ADR 0007](adr/0007-realm-user-authentication.md). No production approval follows
from compilation or a subset of these checks.
