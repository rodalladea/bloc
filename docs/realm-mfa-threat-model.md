# Realm MFA threat model

Status: implemented; independent functional verification recorded. Native amd64
capacity and production acceptance remain open.

This extends the [realm authentication threat model](realm-authentication-threat-model.md).
The [behavior agreement](behaviors/realm-two-factor-authentication.md) links the
approved task, encryption RFC, WebAuthn experiment and screen design.
[ADR 0008](adr/0008-realm-mfa-secret-authority.md) and the
[operations runbook](realm-mfa-operations.md) describe the implementation boundary.

## Assets and authority

Protect factor secrets, WebAuthn public credential integrity, ordinary sessions,
restricted browser flows, recovery authority, policy versions, factor epochs and
security audit integrity. Realm and user management UUIDs identify records; they
are not bearers. A realm-user identity remains separate from the installation
administrator even when both use the same email.

The password worker verifies passwords outside database locks. Maintained
cryptography libraries verify factor material against a snapshot. Guarded
PostgreSQL operations decide whether the proof can commit using current database
time, lifecycle, policy/credential versions, factor epoch and owner. Successful
proof consumption, evidence update, session issuance and audit must commit
together. Cryptographic validity alone does not authorize a stale operation.

A lost database connection after a possible commit leaves the outcome unknown.
The failure response issues no new bearer, but cannot establish that the database
rolled back. The interface distinguishes this case from a known rollback or a
failure before commit; operators must inspect the durable audit rather than
infer a committed outcome from the failed response.

An ordinary session requires the current policy's evidence. Restricted flows
grant only their purpose: challenge, initial enrollment, exact sensitive action,
replacement or code handoff. They cannot open ordinary account data or become
authentication merely because a browser follows a continuation URL.

## Attacks and required controls

| Threat | Required control | Behavior scenarios |
| --- | --- | --- |
| Stolen password used against an enrolled or required account | Issue restricted authority only; require an allowed active factor or restricted initial enrollment for an owner with no active factors | 4–6, 11–13 |
| Older session bypasses a tightened policy | Re-evaluate current policy, owned active factor evidence and epoch on every protected request; refuse protected POST without mutation | 7, 13, 53–56 |
| Disallowed factor or presentation preference overrides policy | Treat realm/user preferences as presentation only; select allowed owned factors | 4, 6, 51 |
| Reused OTP or parallel completion creates multiple sessions | Consume accepted TOTP step, ceremony/flow or recovery code atomically; setup consumes its accepted step | 19, 23, 25, 34, 39 |
| Policy, password, suspension or factor changes race with verification | Final guarded commit rechecks all captured versions, time and lifecycle; stale authority never revives | 10, 18–20, 47, 58 |
| Password or account session replaces an existing factor | Require fresh password plus existing allowed factor in exact-action, browser/version-bound single-use proof; recovered users receive replacement-only authority | 26, 43–45, 52 |
| Recovery code becomes normal authentication | Consume code and revoke sessions, then permit replacement only; normal access follows confirmed replacement and applicable code acknowledgment | 36–39, 45–46 |
| Ordinary password reset bypasses factor protection | Preserve factors; revoke sessions and invalidate pending MFA authority | 47 |
| Administrator recovery link leaks or is replaced | Separate purpose and digest, immutable expiry, fragment removal, explicit CSRF exchange and current password; replacement invalidates previous link-bound authority | 40–44 |
| Lost code response causes plaintext redisplay or bypass | Persist digests plus temporary encrypted handoff only; replace the unacknowledged generation under live authority; maintain acknowledgment gate on later login | 36–38 |
| Cross-realm factor, credential or ciphertext transfer | Composite owner lookups/foreign keys; installation-wide credential ID uniqueness; expected-owner AAD and full WebAuthn user-handle checks | 32–33, 58, 63 |
| WebAuthn wrong origin, RP ID, ceremony, challenge or missing UV | Exact canonical HTTPS origin and installation RP ID; maintained library with required UV and server-only ceremony state | 28–35 |
| Browser cancellation or unsupported authenticator weakens assurance | Retain fixed parent deadline and policy; offer only eligible methods/recovery, without downgrade | 15–16, 29–30 |
| Guessing budgets reset by method switching or new flow | Shared account/source/realm admission plus immutable per-flow failure/expiry bounds, across replicas | 14–17 |
| Flow flooding or cleanup removes live authority | Bounded live-flow capacity and cleanup; refuse capacity instead of evicting live authority | 16–17, 66 |
| Secret leaks in URLs, fragments, logs, history or ordinary swaps | Full-page no-store secret handoff, disabled history snapshots, local QR generation, redacted fixed audit dimensions and errors | 21, 36–38, 40–42, 63 |
| Database ciphertext disclosure or ownership tampering | Dedicated mounted keys, versioned authenticated envelope, authoritative expected-owner/purpose/record binding; no plaintext fallback | 60, 63, 67 |
| Partial key rollout or stale writer loses decryptability | Readiness requires every nonretired key; guarded registry generation chooses writer key; explicit replica restart confirmation precedes activation | 60–61 |
| Re-encryption resurrects replaced/deleted state | Bounded operator-only conditional writes preserve identity, epochs, replay floor, lifecycle and expiry; conflict rolls back | 61, 66 |
| Key retirement strands retained ciphertext | Refuse active/referenced keys; count retained revoked and expired payload rows until physical deletion; separately escrow keys for retained backups | 62 |
| Restore revives sessions, saved codes or an already used OTP | Recovery fence; invalidate temporary authority/code generations and session epochs; advance factor epoch and TOTP replay floor to at least completion step plus one | 64 |
| Incompatible executable serves changed schema | Exact checksum/version readiness and explicit stopped-replica migration; no mixed serving or binary-only rollback | 59, 65 |
| Audit failure permits unobserved authentication | Security transition and success audit share transaction; unavailable storage/audit cannot issue a successful bearer | 19–20, 66 |

Canonical ingress, origin/Fetch Metadata checks, synchronizer CSRF, secure scoped
cookies, escaping and existing password/admission controls apply to every new
HTML, fragment and JSON surface. WebAuthn's larger finish-request bound does not
raise the ordinary form limit. An untrusted browser response never becomes
authoritative server ceremony state or a directly stored public credential.

## Residual trust and recovery

The installation administrator controls realm policy, directory passwords and
assisted recovery. It is therefore a takeover-capable trust boundary. Password
re-entry is not administrator MFA. Disabling assisted recovery removes that
specific path but does not remove the administrator's policy control. No
per-user bypass exemption is introduced.

A database-only attacker does not obtain operator-mounted encryption keys from
a database backup, but can damage availability, alter metadata, or restore an
internally consistent earlier database state. Authenticated encryption does not
prevent consistent database rollback. A compromised runtime must be assumed able
to decrypt TOTP and temporary handoff buffers; a compromised origin can steal
proofs. WebAuthn does not protect all account operations from an already
compromised application origin. No stronger isolation claim is made.

Memory clearing limits owned plaintext-buffer lifetime but cannot guarantee
removal from every allocator, compiler or operating-system copy. Lost encryption
keys have no cryptographic bypass. Preserve data and use only the authorized
recovery model; never manufacture a successful factor proof. Escrow and backup
retention are operator responsibilities that a confirmation flag cannot prove.

Synced passkeys are permitted with the maintained library's counter/backup
handling. Accepting backup flags or signed zero counters does not prove physical
cloud synchronization. Touch-only keys unable to meet user verification are
outside the supported profile.

The maintainer approved a scoped audit exception on 2026-11-08 for
[RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html).
The inspected `webauthn-rs 0.6.2` / `crypto-glue 0.2.2` / `rsa 0.10.0-rc.19`
path verifies public signatures and does not perform the affected private-key
operations. The auditor ignores the single advisory ID; it cannot restrict the
exception by call site. Re-review any change to the dependency chain or RSA use,
and remove the exception when a fixed version is available. See the
[dependency review](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=6831e2c878e121922e03dbf8e8f2eda2220ac66a4364369b)
at `projects/bloc/.checks/realm-mfa-dependency-review.md`.

## Required acceptance evidence

The behavior coverage record must distinguish implementation from actual proof.
Negative HTTP tests must cross the production router and assert both the response
and authority effects. Database tests cover both supported majors, narrow roles,
two replicas, final-commit races, audit rollback, stale/expired flows, key
loss/rotation/retirement and real restore completion. Browser tests cover no-JS
TOTP/recovery, secret handoff network loss, navigation and repeated interactions,
and real WebAuthn integration with explicitly qualified device support.

Final-source capacity needs real native Linux amd64 and arm64 measurements.
Independent security review and maintainer full-flow acceptance remain required
for go-live. Unit, fixture, browser or capacity checks alone do not confer
production approval or protocol conformance.
