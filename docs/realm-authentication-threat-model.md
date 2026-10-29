# Realm authentication threat model

Status: independent review in progress. This records design threats and required
proofs; it is not completed security acceptance or production approval.

## Assets and trust boundaries

Assets are realm credentials, sessions, single-use access links, synchronizer form
authority, directory ownership and success-audit integrity. The installation
administrator can administer any realm but cannot substitute an administrator
cookie for a realm-user identity. Public browsers and submitted realm/user/session
IDs are untrusted. Trusted proxy configuration selects ingress authority and source
IP. Runtime is trusted to validate and hash credentials, but PostgreSQL roles limit
it to guarded authority functions. Migrator/database owner and operator access
remain privileged deployment boundaries. A compromised origin can act with all
same-origin browser authority; separate realm cookie names do not solve that.

Native forms on no-referrer pages can send `Origin: null`. For the new realm
public/account and realm-administration forms, the approved fallback requires
canonical HTTPS ingress plus single exact `Sec-Fetch-Site: same-origin`,
`Sec-Fetch-Mode: navigate` and `Sec-Fetch-Dest: document` headers. Browser scripts
cannot set these forbidden headers. Null Origin alone, same-site requests,
ambiguous headers and missing metadata are refused; valid server-side CSRF is
still required. The shared administrator logout uses this same bounded fallback
for native forms on Authentication and User access; `realm_auth_c09` checks
revocation and rejected metadata/CSRF, and `realm_auth_c19` exercises both pages
with JavaScript disabled. Existing administrator setup/login/account validation
is unchanged.
This is a browser-origin defense, not authentication of arbitrary HTTP clients.

See [ADR 0007](adr/0007-realm-user-authentication.md) and the
[behavior agreement](behaviors/realm-user-authentication.md) for approved sources.
All proof names below belong to `tests/realm_authentication.rs` and must run against
PostgreSQL 17 and 18; browser/native coverage is additional where specified.

| Threat | Required defense | Negative/concurrent proof |
| --- | --- | --- |
| Cross-realm or administrator authority substitution | Server-derived principal; composite ownership; matching realm cookie and bound form/link | realm_auth_c09, realm_auth_c15, realm_auth_c33, realm_auth_c43, realm_auth_c51, realm_auth_c59 |
| Claiming a directory account by unverified email | Registration creates only new realm-local identity; collisions never modify existing credentials/status | realm_auth_c23, realm_auth_c25 |
| Password enumeration or resource exhaustion | Same bounded dummy verification; collision hash; shared admission and one worker; no arbitrary sleep | realm_auth_c10, realm_auth_c11, realm_auth_c12, realm_auth_c13, realm_auth_c14, realm_auth_c63 |
| CSRF, forged ingress or parser bypass | Canonical origin/ingress, strict 16 KiB form parsing, realm/purpose/browser/session synchronizer binding | realm_auth_c09, realm_auth_c15, realm_auth_c32 |
| Stale successful password verification after revocation | Commit-time lifecycle/version/fence/time checks under shared lock | realm_auth_c17, realm_auth_c35, realm_auth_c49, realm_auth_c50, realm_auth_c55 |
| Expiry resurrection or concurrent cap bypass | Stored deadline checked first; old/new policy expiry terminal; atomic oldest-first eviction | realm_auth_c06, realm_auth_c07, realm_auth_c44, realm_auth_c45 |
| Recovery-code leakage and unintended GET consumption | Fragment removal before explicit POST; no query/path secret; one-time output; no-referrer/no-store; local scripts | realm_auth_c28, realm_auth_c30, realm_auth_c31, realm_auth_c39 (real browser required) |
| Link replay/replacement race | Digest/purpose/realm binding, immutable expiry, atomic consume and bound-form invalidation | realm_auth_c29, realm_auth_c33, realm_auth_c34, realm_auth_c35, realm_auth_c37, realm_auth_c38 |
| Lost response/repeated destructive submission | Atomic uniqueness and single-use consumption; owned ended-session replay is an unaudited no-op | realm_auth_c25, realm_auth_c28, realm_auth_c60 |
| Audit append/storage failure grants partial authority | Security transition plus one fixed success event in the same transaction; 503 on failure | realm_auth_c16, realm_auth_c18, realm_auth_c47 |
| Log/audit/cardinality leakage | Fixed action/reason dimensions, redacted diagnostics, bounded sanitized device labels | realm_auth_c19, realm_auth_c20, realm_auth_c39, realm_auth_c57, realm_auth_native_capacity |
| Runtime or maintenance privilege escalation | Private tables/helpers; narrow guarded function grants; maintenance cannot create credentials | realm_auth_upgrade_roles |
| Session-management ID used as bearer | Management UUID never authenticates; ownership check and explicit revoke confirmation | realm_auth_c56, realm_auth_c58, realm_auth_c59, realm_auth_c60 |
| Restored authority becomes usable again | Durable recovery fence and complete realm state invalidation across replicas | realm_auth_c50 |
| XSS/HTMX bypass | Autoescaped templates, local assets, restrictive CSP, same authorization in full/fragment responses | realm_auth_c62 (real browser required) |

## Residual limits

Registration intentionally has distinguishable success and failure; generic
collision wording does not promise that address availability is undiscoverable.
Administrator identity confirmation is a human assertion, not automated proof.
Fragment removal does not erase clipboard or external delivery history. Shared
admission reserves capacity but cannot guarantee administrator CPU availability
against distributed abuse. The database lock serializes transitions and requires
native overload measurement before capacity acceptance.

Public sessions, forms and admission keys have temporary-state limits; those are
not directory-user quotas. Maintenance targets 90 days for success and seven days
for denials, with bounded batches and lag monitoring rather than exact deletion
times. Oversized header rejection must preserve unrelated cookies; actual server
and ingress bounds are recorded with final integration evidence.

## Review gate

The independent verifier must inspect located assertions and actual database,
browser and native results, and report every unproven threat path. Native Linux
amd64 and arm64 records must match the final application source. No static preview,
unit-only pass, emulated run or stale capacity record substitutes for this evidence.
MFA and maintainer production-security acceptance remain separate prerequisites.
