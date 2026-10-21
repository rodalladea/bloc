# Tenant and user management

Status: implemented; author proofs passed on PostgreSQL 17 and 18. Independent verification pending.

## Problem and scope

The installation administrator needs independent tenant directories and stable
tenant-bound user identities before later authentication features consume them.
This increment covers built-in tenant and user listing, creation, profile edits,
suspension/reactivation, shared authority and atomic directory auditing.

Tenant users cannot sign in. Credentials, verification/delivery, recovery,
invitations, self-registration, delegation, global persons/memberships, transfers,
deletion, providers, protocols, public management APIs, bulk operations, search,
filtering and an audit viewer remain out of scope. Shared storage provides logical
ownership isolation, not isolation from privileged service/database compromise.

## Rules and decisions

The requester adopted the engineering recommendations on 2026-10-21 and then
explicitly approved the completed six-screen design set. The
[accepted tenancy ADR](../adr/0005-tenant-user-directories.md) records immutable
ownership, tenant-local email equality, independent lifecycle, guarded authority,
version/replay semantics and atomic auditing. Administrator identity remains
installation-scoped and separate from every directory user.

Sources in Catapio Drive:

- [projects/bloc/.tasks/tenant-user-management.md](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=80eef47830bfb5c6c2ea4e75225dd789894993ad3f6d0dbf), ID
  `80eef47830bfb5c6c2ea4e75225dd789894993ad3f6d0dbf`: criteria 1–37 and final
  resolution logs. Historical pending wording is superseded by those logs.
- [projects/bloc/.design/tenant-user-management.md](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=5e5497c1f23b1c58a59c292673c21ea770bae91caa62406c), ID
  `5e5497c1f23b1c58a59c292673c21ea770bae91caa62406c`: product rationale.
- [projects/bloc/.design/tenant-user-management-screens.md](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=884509362acfc8d88e9ca47ece59bd2deb598e37e405c125), ID
  `884509362acfc8d88e9ca47ece59bd2deb598e37e405c125`, and preview source
  [8360fbadc81cf795b130e8ec13994a7c23b4b5b1769bc400](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=8360fbadc81cf795b130e8ec13994a7c23b4b5b1769bc400): approved binding T1–T3 and
  U1–U3 screens, including responsive arrangement, copy and interaction states.

## Open questions and assumptions

All five task questions are resolved in its decision logs. Malformed resource
paths return 404; invalid cursor/form UUID/version/status values return 422 with
safe recovery. Existing request-security refusal codes retain their precedence.
No directory-specific admission quota is added. Screen previews are design
evidence, not application acceptance evidence.

## Scenarios

### tenant-user-management-01: empty tenant directory

Given a current administrator and no tenants
When the administrator opens `/admin/tenants`
Then the response is 200 with an empty directory and Create tenant
And no default tenant is created.

### tenant-user-management-02: create a durable tenant

Given an unused creation UUID
When the administrator creates a tenant named ` Acme `
Then the response is 303 to that tenant's immutable UUID detail
And it shows Acme, active, version 1 and equal database-time timestamps.

### tenant-user-management-03: distinguish repeated tenant names

Given an Acme tenant
When another Acme is created with a different creation UUID
Then both records have different immutable IDs visible in list and detail.

### tenant-user-management-04: validate tenant names

Given a tenant creation or profile form
When its name is missing, empty, contains controls, exceeds 128 Unicode scalars
or exceeds 512 UTF-8 bytes
Then the response is 422 with field guidance and safe input retained
And neither a directory mutation nor a success event occurs.

Given a trimmed nonempty name within both limits and without controls
When the form is submitted with current authority
Then the name is accepted.

### tenant-user-management-05: refuse tenant creation replay

Given the same creation UUID submitted again or concurrently to two instances
When the guarded creations contend
Then at most one tenant is created
And the loser receives 409 with a review-existing link and cannot replace it.

### tenant-user-management-06: rename without replacing ownership

Given a tenant with users and its current version
When its name is changed
Then the response redirects to the same tenant detail
And its version increases by one, updated time uses database time, and tenant
identity and every user's ownership remain unchanged.

### tenant-user-management-07: suspend without cascading user changes

Given an active tenant and its current version
When the administrator explicitly requests suspended
Then detail shows the suspended tenant and explains that user states are unchanged
And persisted user statuses and versions remain unchanged.

### tenant-user-management-08: reactivate without reactivating users

Given a suspended tenant containing a suspended user
When the administrator explicitly requests active with the current tenant version
Then detail shows the active tenant
And the individually suspended user remains suspended.

### tenant-user-management-09: manage a suspended directory

Given a suspended tenant
When the administrator lists or edits it, creates/edits users or changes user status
Then those management actions remain available
And user screens retain the suspended tenant context.

### tenant-user-management-10: refuse stale tenant mutations

Given two instances holding the same tenant version
When they submit different profile/status changes concurrently
Then only one commits
And the stale request receives 409 with reload guidance, no mutation and no event.

### tenant-user-management-11: leave tenant no-ops unchanged

Given the current version
When an identical normalized name or already-current explicit status is submitted
Then the response redirects to the same detail
And version, updated time and success-event count are unchanged.

### tenant-user-management-12: share durable state across instances

Given a tenant created or edited on instance A
When detail is read on instance B or after service restart
Then the same committed ID, profile, version and status are shown.

### tenant-user-management-13: paginate tenants in stable order

Given 51 committed tenants without concurrent mutation
When the first page and its continuation are read
Then the pages contain 50 and one records without duplicates
And ordering is stable by creation time and ID.

### tenant-user-management-14: cancel without mutation

Given a tenant creation, edit or status confirmation
When the administrator cancels or abandons it
Then no directory mutation occurs and list/detail navigation remains usable.

### tenant-user-management-15: show an empty tenant-bound user directory

Given an existing tenant with no users
When its user list is opened
Then the response is 200 with an empty directory and Create user
And tenant name and immutable ID remain visible.

### tenant-user-management-16: create an unverified directory user

Given a valid email, optional display name and unused creation UUID
When a user is created in a tenant
Then the response is 303 to the tenant-bound immutable user detail
And it shows active, version 1, equal initial timestamps, unverified email and no
sign-in capability.

### tenant-user-management-17: keep equal emails independent across tenants

Given Alice@example.com in Acme and Contoso
When either user's profile is edited
Then their user IDs are different
And the other user's profile, version, status and ownership remain unchanged.

### tenant-user-management-18: enforce exact tenant-local email equality

Given Alice@example.com in a tenant, including a suspended record
When ` Alice@EXAMPLE.com ` is submitted in that tenant
Then canonical Alice@example.com conflicts with 409
And alice@example.com remains a distinct acceptable address.

### tenant-user-management-19: reuse the existing email policy

Given an email submitted to a user creation or profile form
When it is validated
Then the existing `normalize_email` ASCII syntax and 254-byte bound apply
And invalid email returns 422 guidance without changing a record.

### tenant-user-management-20: validate optional display names

Given an optional display name
When it is submitted
Then it is trimmed and empty becomes null
And controls, more than 128 Unicode scalars or more than 512 UTF-8 bytes return
422 with safe input retained and no mutation.

### tenant-user-management-21: edit profile without replacing user identity

Given the current user version
When email or display name changes
Then the response redirects to the same detail with version increased by one and
database updated time
And ID, tenant, status and prior audit target links remain unchanged.

Given only normalization changes the submitted profile
When the current-version form is submitted
Then version, time and success-event count remain unchanged.

### tenant-user-management-22: change user status independently

Given a current user version
When active or suspended is explicitly requested
Then only that user's status changes, preserving identity and tenant state
And an already-current request leaves version, time and audit count unchanged.

### tenant-user-management-23: distinguish combined directory status

Given each combination of active/suspended tenant and user
When user detail is read
Then tenant, user and combined directory states are labeled separately
And combined active requires both active, without claiming authentication.

### tenant-user-management-24: reject unsupported form fields

Given a creation, profile or status form
When undeclared fields attempt to set ownership, roles, verification or credentials
Then the response is 422 without moving or elevating a user
And only the declared form allowlist is accepted.

### tenant-user-management-25: bind every user operation to its path tenant

Given a missing user or a user belonging to a different path tenant
When GET, profile POST, status POST or their enhanced forms are requested
Then each returns the same 404 without user data or mutation
And guarded storage checks the parent/user pair explicitly.

### tenant-user-management-26: serialize competing canonical emails

Given two instances creating or changing users to the same email in one tenant
When the guarded operations contend
Then exactly one commits and the loser receives 409
And only the committed mutation has a success event.

### tenant-user-management-27: refuse user creation replay without cross-tenant disclosure

Given a previously used user creation UUID
When it is submitted again
Then the response is 409 without replacement or a second record
And review-existing links appear only for a record in the requested tenant.

Given the UUID belongs to another tenant
When the collision is refused
Then neither record metadata nor a review-existing link is disclosed.

### tenant-user-management-28: refuse stale user mutations

Given two concurrent profile/status changes from the same user version
When their guarded operations contend
Then one commits and the loser receives 409 with reload guidance
And it does not automatically resubmit, mutate or create a success event.

### tenant-user-management-29: paginate and recover without creation replay

Given 51 users in one tenant and users in another
When the unchanged directory pages are followed
Then pages contain 50 and one records in stable creation-time/ID order
And another tenant's users are absent.

Given a cancelled form or a lost mutation response
When the administrator returns to list/detail
Then cancellation caused no mutation and any committed result is visible
And creation is not automatically replayed.

### tenant-user-management-30: require current authority on every route

Given missing, expired, revoked or recovery-fenced administrator authority
When any new read/write route or fragment is requested
Then there is no directory disclosure or mutation
And ordinary requests use the existing 303 sign-in redirect while enhanced
requests use 401 with HX-Redirect to `/admin/login?expired=1`.

### tenant-user-management-31: order mutations against authority revocation

Given concurrent sign-out, credential replacement or restore fencing
When a directory mutation contends for installation authority
Then fresh authority is checked inside the guarded transaction
And a mutation ordered after revocation/fencing cannot commit; one before may.

### tenant-user-management-32: retain request-security refusals

Given a directory POST
When origin/CSRF is invalid or expired, the body exceeds 16 KiB, the media type is
wrong, or encoding/duplicate fields are malformed
Then the respective response is 403, 413, 415 or 400
And shared browser/session-bound form authority and no-mutation behavior remain.

### tenant-user-management-33: fail closed on primary or audit failure

Given unavailable/incompatible primary authority or injected audit append failure
When a directory operation is attempted
Then the response is 503 rather than an empty directory or local success
And an audit failure rolls back the entire mutation.

### tenant-user-management-34: commit one attributable success event

Given each actual tenant/user create, profile update, suspend or reactivate
When it commits
Then exactly one matching fixed action has the current administrator, UTC time,
request UUID and correct tenant/user target
And rejected, repeated, conflicting and no-op requests create no success event.

### tenant-user-management-35: bound audit data and denial dimensions

Given directory success events and denied requests
When audit data is inspected
Then success events contain no profile history, body, password, token, digest,
source IP or arbitrary text
And denials use only fixed tenant_management/tenant_user_management categories
with existing fixed reasons, observable when storage is available.

### tenant-user-management-36: retain bounded cleanup and administrator compatibility

Given eligible success events older than 90 days and denials older than seven days
When existing maintenance runs
Then each existing category deletes at most 1,000 eligible rows
And existing cleanup failure/lag reporting remains without a deletion deadline.

Given administrator events predating the migration
When the new contract is installed
Then their directory targets remain null and administrator operations remain usable.

### tenant-user-management-37: restrict capabilities and schema compatibility

Given separate runtime, operator, migrator and maintenance credentials
When the forward migration is explicitly applied
Then runtime can execute only granted guarded directory operations without direct
directory-table access, operator gains no directory management and maintenance
retains bounded cleanup only
And checksum/count readiness rejects incompatible binary/schema combinations;
serving replicas never migrate.

## Verification

Every numbered scenario maps to the same-numbered task criterion. The named
HTTP/database proofs are `tests/tenant_user_management.rs::directory_c01` through
`directory_c37`, respectively. Each mapped named proof passed in the author runs on PostgreSQL 17 and 18;
the Drive checklist records raw logs, focused final reruns and source boundaries.

| Scenario | Coverage | Exact test in `tests/tenant_user_management.rs` |
| --- | --- | --- |
| tenant-user-management-01 | Author passed, PG17/18 | `directory_c01` |
| tenant-user-management-02 | Author passed, PG17/18 | `directory_c02` |
| tenant-user-management-03 | Author passed, PG17/18 | `directory_c03` |
| tenant-user-management-04 | Author passed, PG17/18 | `directory_c04` |
| tenant-user-management-05 | Author passed, PG17/18 | `directory_c05` |
| tenant-user-management-06 | Author passed, PG17/18 | `directory_c06` |
| tenant-user-management-07 | Author passed, PG17/18 | `directory_c07` |
| tenant-user-management-08 | Author passed, PG17/18 | `directory_c08` |
| tenant-user-management-09 | Author passed, PG17/18 | `directory_c09` |
| tenant-user-management-10 | Author passed, PG17/18 | `directory_c10` |
| tenant-user-management-11 | Author passed, PG17/18 | `directory_c11` |
| tenant-user-management-12 | Author passed, PG17/18 | `directory_c12` |
| tenant-user-management-13 | Author passed, PG17/18 | `directory_c13` |
| tenant-user-management-14 | Author passed, PG17/18 | `directory_c14` |
| tenant-user-management-15 | Author passed, PG17/18 | `directory_c15` |
| tenant-user-management-16 | Author passed, PG17/18 | `directory_c16` |
| tenant-user-management-17 | Author passed, PG17/18 | `directory_c17` |
| tenant-user-management-18 | Author passed, PG17/18 | `directory_c18` |
| tenant-user-management-19 | Author passed, PG17/18 | `directory_c19` |
| tenant-user-management-20 | Author passed, PG17/18 | `directory_c20` |
| tenant-user-management-21 | Author passed, PG17/18 | `directory_c21` |
| tenant-user-management-22 | Author passed, PG17/18 | `directory_c22` |
| tenant-user-management-23 | Author passed, PG17/18 | `directory_c23` |
| tenant-user-management-24 | Author passed, PG17/18 | `directory_c24` |
| tenant-user-management-25 | Author passed, PG17/18 | `directory_c25` |
| tenant-user-management-26 | Author passed, PG17/18 | `directory_c26` |
| tenant-user-management-27 | Author passed, PG17/18 | `directory_c27` |
| tenant-user-management-28 | Author passed, PG17/18 | `directory_c28` |
| tenant-user-management-29 | Author passed, PG17/18 | `directory_c29` |
| tenant-user-management-30 | Author passed, PG17/18 | `directory_c30` |
| tenant-user-management-31 | Author passed, PG17/18 | `directory_c31` |
| tenant-user-management-32 | Author passed, PG17/18 | `directory_c32` |
| tenant-user-management-33 | Author passed, PG17/18 | `directory_c33` |
| tenant-user-management-34 | Author passed, PG17/18 | `directory_c34` |
| tenant-user-management-35 | Author passed, PG17/18 | `directory_c35` |
| tenant-user-management-36 | Author passed, PG17/18 | `directory_c36` |
| tenant-user-management-37 | Author passed, PG17/18 | `directory_c37` |

| Additional boundary | Required named proof in `tests/tenant_user_management.rs` |
| --- | --- |
| Adopted malformed-input refusals | `directory_input_refusals` |
| Approved T1, T2, T3 screens | `directory_screen_t1`, `directory_screen_t2`, `directory_screen_t3` |
| Approved U1, U2, U3 screens | `directory_screen_u1`, `directory_screen_u2`, `directory_screen_u3` |
| Confirmation/cancel, keyboard, ordinary forms, HTMX, response-loss recovery | `directory_browser_interactions` |
| Full-page/fragment escaping, response headers and redirects | `directory_response_policy` |

The proof checklist lives in Drive at
[projects/bloc/.checks/tenant-user-management.md](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=e75ac2357f1d873e2a39d195f22011ed54a51f59f292cf59), ID
`e75ac2357f1d873e2a39d195f22011ed54a51f59f292cf59`.
Acceptance requires actual named executions on PostgreSQL 17 and 18, live
production-assembly browser checks, the existing administrator regressions and
an independent verification report accounting for every check. Author executions
are recorded in the checklist. Independent light-profile verification passed all
64 checks at `247cd5a`; see
[projects/bloc/.checks/tenant-user-management.verified.md](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=9ac2d4afdd4e6c61cdeb6477edd99d2701d587a35a3d09b8).
No faults were injected under that profile. A directory-only result cannot establish
production authentication readiness or identity-protocol conformance.
