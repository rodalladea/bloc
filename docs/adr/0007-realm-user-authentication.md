# 0007: realm-user authentication and My Account

Status: accepted design — 2026-10-26; implementation verification pending.

## Context

The requester approved realm-user email/password access, opt-in registration,
administrator-assisted activation and recovery, and My Account in the task below.
These identities extend the immutable directories established by ADRs
[0005](0005-tenant-user-directories.md) and [0006](0006-realm-terminology.md).
They never acquire installation-administrator authority through this feature.

- [projects/bloc/.tasks/realm-user-authentication-and-my-account.md](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=8fc565a08878652aad8b6a5ceae0dc5e8eaf638f4a5a6dec), file ID `8fc565a08878652aad8b6a5ceae0dc5e8eaf638f4a5a6dec`: approved build contract.
- [projects/bloc/.design/realm-user-authentication-and-my-account.md](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=807a88ce48c15761920b6b779b78e892a4ea5ab866ed6ca8), file ID `807a88ce48c15761920b6b779b78e892a4ea5ab866ed6ca8`: product rules and security guardrails.
- [projects/bloc/.design/realm-user-authentication-preview/realm-user-authentication-preview.html](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=f2dcc634f47b5e7acb784ccca96a5730a348d6f2329a84e8), file ID `f2dcc634f47b5e7acb784ccca96a5730a348d6f2329a84e8`: binding interface, including the revised standard directory Sessions table.

## Decision

An optional credential belongs to the composite `(realm_id,user_id)` identity.
There is no global person, email-based claiming, extra profile table or special
administrator realm. Existing directory users begin without credentials. Public
registration creates a new active directory user and credential atomically;
collisions never claim or replace any existing record. Email remains unverified.

The public HTML/form routes use immutable realm UUIDs under `/realms/{realm_id}`.
My Account derives its principal from the requested realm's current session.
Administrator settings and link issuance remain under `/admin/realms`.
Each realm has one versioned policy, initially registration off, minimum 16
Unicode scalars, no composition requirements, activation 86400 seconds, reset
1800 seconds, idle 1800 seconds, absolute 43200 seconds and session cap 10.
The separate administrator minimum stays 15.

PostgreSQL guarded functions serialize authority commits with the installation
singleton. They recheck database time, lifecycle, credential/policy versions,
restore fence and relevant browser/session/link authority. Credential hashing
stays outside transactions, using the same bounded PasswordWorker as administrator
flows. Runtime has guarded operations, not direct authority-table privileges.
Success audit and the security transition commit together. Audits can identify
a realm-user actor only with a complete matching realm/user pair, exclusive with
an administrator actor; public registration/link consumption invent no actor.

A session has a random bearer digest and a separate management UUID. Cookies are
`__Host-bloc-realm-{realm_uuid}`, Secure, HttpOnly, SameSite=Lax, Path=/, with no
Domain. Browser forms use independent random synchronizer tokens and
realm/purpose-qualified bearers. The requested realm selects the only accepted
cookie; matching duplicates or malformed bearers fail closed.

Session expiry is terminal. Validation checks stored expiry before refresh.
Timeout changes terminally expire sessions under both old and new policy before
publishing the new policy. Cap enforcement keeps newest `(created_at,id)`
sessions. Suspension, administrator email change and restore invalidate affected
sessions, access links and forms atomically. Reactivation never restores them.
Password change replaces all old authority while issuing a fresh current session;
reset ends all sessions and returns to sign-in.

Activation/reset links occupy one slot per realm/user/purpose, store only a
32-byte random code's digest and have immutable issuance expiry. The administrator
confirms identity, then receives the secret only in the issuance response.
Generated links use a fragment, locally removed before explicit browser-CSRF POST
exchange. The exchange issues link-bound HttpOnly form authority and leaves the
link unconsumed. Ordinary code-entry POST works without JavaScript. GET never
changes credentials or consumes a link. Replacement invalidates bound forms;
only one concurrent consumer commits. Display-name-only edits preserve links.

No-referrer native forms can serialize Origin as null. The approved native-form
fallback requires canonical HTTPS ingress, exact single same-origin/navigate/document
Fetch Metadata headers and unchanged synchronizer CSRF. It applies to the new
realm forms, including administrator settings/issuance; existing administrator
setup/login/account guards remain unchanged. Null Origin alone is never sufficient.

Realm admission uses fixed keyed dimensions and bounded temporary state. Public
hash work is limited to 20 units per rolling 60 seconds; existing administrator
and public work share one 30-unit total. Password change reserves two before
verification. All required bucket reservations succeed or none do. Form/key
capacity is separate from administrator budgets. Noncredential account mutations
use a separate 30-per-minute principal budget. No cumulative directory quota or
inactive-user deletion is introduced.

Migration 0005 is explicit and checksum-verified. Historical migrations remain
unchanged. It preserves directory records and historical audit, seeds default
settings and creates no credentials for existing users. New and old executables
reject incompatible schemas. Serving replicas never migrate.

## Alternatives

| Alternative | Reason rejected |
| --- | --- |
| Email-based account claiming or global users | Unverified addresses cannot transfer ownership or merge independent realms. |
| Replica-local positive authority or unrestricted runtime writes | Cannot enforce transactional cross-replica revocation and audit. |
| Separate public/admin workers or independent total budgets | Doubles resource exposure and bypasses the agreed combined limit. |
| Secret query/path URLs or GET consumption | Leaks recovery authority into request URLs and enables unintended consumption. |
| Shared administrator/realm cookie | Cannot represent independent principals and realm authority. |
| Refreshing before expiry checks | Can revive expired sessions after a policy increase. |
| Migration on serve or mixed incompatible rollout | Violates the exact executable/schema readiness contract. |

## Consequences

This is development/evaluation authentication. MFA, full authentication acceptance
and maintainer production-security approval remain open gates. Email delivery and
verification, user email changes/deletion, delegated administration, OIDC/OAuth,
SAML and external providers remain outside scope. Same-origin cookie isolation is
not protection against a compromised bloc origin or privileged database owner.

The [behavior agreement](../behaviors/realm-user-authentication.md),
[threat model](../realm-authentication-threat-model.md) and
[runbook](../realm-user-authentication.md) record required negative/race tests,
operational handling and verification limits. No production/conformance claim
follows from this ADR.
