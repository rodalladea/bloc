# 0005: independent tenant-user directories

Status: accepted — 2026-10-21

## Context

bloc needs a durable directory boundary before application-user authentication
and protocols consume identities. The installation administrator remains a
separate identity. The requester confirmed independent tenant directories and
adopted the proposed engineering contracts on 2026-10-21 in response to the
implementation prerequisite questions ("Ok, go with it").

Sources in Catapio Drive:

- `projects/bloc/.design/tenant-user-management.md`, ID
  `5e5497c1f23b1c58a59c292673c21ea770bae91caa62406c`.
- `projects/bloc/.tasks/tenant-user-management.md`, ID
  `80eef47830bfb5c6c2ea4e75225dd789894993ad3f6d0dbf`.

This records the adopted boundary; it does not claim implementation or
verification. The requester subsequently approved the concrete interface set:
`projects/bloc/.design/tenant-user-management-screens.md`, ID
`884509362acfc8d88e9ca47ece59bd2deb598e37e405c125`, with embedded preview source
ID `8360fbadc81cf795b130e8ec13994a7c23b4b5b1769bc400`. These are binding interface
sources. The [behavior record](../behaviors/tenant-user-management.md) maps the
agreed examples and pending proofs.

## Options

| Option | Decision |
| --- | --- |
| Independent tenant-bound users in shared PostgreSQL | Selected: matches independent directories and existing shared authority |
| Global persons and cross-tenant memberships | Rejected: equal emails across tenants must not link identities |
| Separate databases per tenant | Deferred: no independent restore, residency or physical isolation requirement |
| Handler-only authorization or ambient connection tenant settings | Rejected: neither protects the committing transaction |
| Cascading tenant suspension into user status | Rejected: loses independent user state |

## Decision

Tenants and tenant users have immutable UUID identities. A creation form's UUID
becomes the record ID; reusing it refuses creation with 409. Each user belongs
immutably to one tenant. Tenant names may repeat. User emails are unverified,
editable and unique within their tenant under the existing email normalization:
trimmed ASCII, at most 254 bytes, domain lowercased, local part preserved exactly,
without alias rewriting. Suspended records retain uniqueness.

Tenant names and nonempty display names are trimmed, contain no controls, and
have at most 128 Unicode scalars and 512 UTF-8 bytes. Empty display names become
null; empty tenant names are invalid. Lists use 50-row keyset pagination in
stable `(created_at, id)` order, tenant-bound for users. There is no total count,
search or filtering contract.

Both record types start active and have independent active/suspended states.
Tenant suspension leaves user records unchanged and permits directory management.
Combined directory status is active only when both are active. This state does
not authenticate anyone or promise a working sign-in capability.

Versions begin at 1. A real change increments the version and uses database time;
a current-version normalized no-op preserves version, timestamp and audit count.
Stale versions refuse with 409; clients do not automatically replay mutations.

Private tables extend the guarded PostgreSQL capability model of
[ADR 0004](0004-initial-administrator-access.md). Every read and mutation requires
current installation administrator authority and recovery-fence checks. Mutations
share installation authority serialization with revocation and recheck authority
inside the committing operation. User operations bind parent and user explicitly.
Runtime has only guarded operations, operator credentials gain no directory
capability, and maintenance keeps bounded cleanup authority.

Each actual mutation and exactly one tenant-aware success event commit together.
User events bind the matching tenant/user pair. No profile values or arbitrary
text enter events. Denials use fixed management categories and existing reasons.
Existing retention remains 90 days for success and seven days for denials, with
cleanup bounded to 1,000 per existing category. Existing administrator events
retain null directory targets.

An explicit checksum migration extends the exact binary/schema readiness
contract; serving replicas never migrate. No mixed incompatible binary rollout
is promised. Unavailable authority or audit append failure yields 503 without a
directory mutation.

Malformed resource paths yield 404. Invalid cursors or form UUIDs, versions and
status values yield 422 with safe recovery and no mutation. Missing or mismatched
parent/user pairs yield the same 404. Existing request-security refusals retain
their codes and precedence. Unsupported fields yield 422. Existing ingress and
form-issuance protections remain; no new directory quota is introduced.

## Consequences

Future credentials and protocols must explicitly consume these immutable
identities and lifecycle states. Email changes do not move identities. Deletion,
transfers, delegation, credentials, verification, providers, protocols and public
administration APIs remain outside this increment.

Shared storage supplies logical ownership isolation, not isolation from a
compromised privileged service or database owner. Installation-wide authority
serialization preserves existing ordering and may require future measurement
before a different locking design is justified.

Implementation must prove transactional authority, concurrency, tenant-local
uniqueness, atomic audit, role restrictions, migration compatibility and existing
administrator behavior on PostgreSQL 17 and 18. Architecture acceptance does not
establish completion, production readiness, protocol conformance, merge,
publication or deployment authorization.
