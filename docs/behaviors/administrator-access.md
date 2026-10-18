# Initial administrator access

Status: agreed — interview scope only; implementation and verification pending.

## Problem and scope

- Actor: the operator of a new bloc installation.
- Outcome: establish installation ownership, return to administer it, and recover
  access without transferring ownership.
- In scope: setup, administrator sign-in, password change, recovery, sign-out,
  and a small administration home; multiple bloc instances in one region.
- Out of scope: public administration API, tenant users, application integration,
  additional administrators, email verification/delivery, shared-disk persistence,
  and multi-region operation. MFA follows before production authentication use.
- Breached/common-password screening is excluded by requester decision on
  2026-10-18. No online lookup or offline password dataset is required.

## Rules and decisions

Source: requester confirmations in the tlc-discover conversation on 2026-10-16.
The [design](../../.design/administrator-access.md) records the confirmed
decisions once and separates proposed contracts from unresolved work. The
[proposed ADR](../adr/0004-initial-administrator-access.md) captures architecture
and alternatives. This record agrees only the examples below; it does not
silently approve all proposed engineering details in the design.

## Open questions and assumptions

The requester approved prerequisite policy and the five-screen preview; native
hashing matrices and live TLS evidence are available. The finalized setup-storage
contract is `projects/bloc/design/administrator-access-security-storage.md`, Drive
ID `4bcaafc1a56954360b14426d7fe92239d1a351dcd0a55487`. The task alignment is
`projects/bloc/.tasks/administrator-access.md`, Drive ID
`87bd2c0006669399f6e64c832b144da78fd0bbeca80fb059`.
Full-service overload, HTTP security, browser and deployment acceptance remain
pending. Storage coverage alone never establishes these outcomes.

The 2026-10-18 screening exclusion removes corpus preparation, lookup, refresh,
revision activation, and screening availability from the prerequisite gates.
The remaining password length, confirmation, hashing, abuse-control, and
credential/session requirements are unchanged. This is a scope decision;
no administrator runtime behavior is implemented by this documentation change.

## Scenarios

### administrator-access-01: restricted setup

Given a fresh installation with no administrator
When a visitor attempts to claim it without deployment-authorized setup
Then no administrator is created.

Given that the operator obtained a valid setup code through the operator command
When the operator completes setup with an email address and password
Then one installation administrator exists and setup closes.

### administrator-access-02: setup retries and competing instances

Given setup was abandoned before account creation
When the operator restarts setup
Then the unclaimed installation can still be initialized.

Given two bloc instances receive competing valid setup submissions
When both attempt account creation
Then exactly one administrator is created
And subsequent setup attempts cannot replace or add an administrator.

### administrator-access-03: operator-code lifecycle

Given an operator code issued at 10:00 UTC
When it is submitted at 10:15 UTC
Then it cannot authorize an operation.

Given an unconsumed code
When the operator generates a replacement for the same purpose
Then the earlier code is invalid across all instances.

Given a code already consumed by a successful operation
When it is replayed through another instance
Then no second operation is authorized.

### administrator-access-04: return and session expiry

Given the administrator signed in at 08:00 UTC
When protected activity continues without a 30-minute idle interval
Then the session still expires at 20:00 UTC.

Given the last session activity was at 09:00 UTC
When the administrator returns at 09:30 UTC
Then fresh sign-in is required.

Given valid administrator credentials and persisted installation state
When bloc restarts or a request reaches another instance
Then ownership remains available and valid session state is evaluated consistently.

### administrator-access-05: recovery preserves ownership

Given an existing administrator with active sessions
When the operator generates a recovery code but abandons recovery
Then the current password and sessions remain usable within their normal limits.

Given a valid recovery code
When recovery completes with a replacement password
Then the administrator retains the same ownership
And all earlier sessions end across instances
And the administrator must sign in with the replacement password.

### administrator-access-06: normal password change

Given a signed-in administrator
When they provide the correct current password and complete a password change
Then all active sessions end and fresh sign-in is required.

Given an incorrect current password
When password change is attempted
Then the password remains unchanged.

### administrator-access-07: administration home and email semantics

Given successful setup without email delivery or mailbox verification
When the administrator signs in through the built-in interface
Then they see their account and installation status with password-change and
sign-out actions
And the email address is not treated as verified or as account-linking authority
And no tenant or application-management placeholder is presented as working.

### administrator-access-08: shared storage boundary

Given multiple bloc instances operating in one region
When they access administrator, session, operator-code, or audit state
Then PostgreSQL is the shared authoritative store
And database-free shared-disk operation is outside the supported scope.

## Verification

| Scenario | Delivery / coverage | Evidence |
| --- | --- | --- |
| administrator-access-01 | Partial storage coverage / HTTP missing | administrator-storage-01/03 below; browser setup remains unimplemented |
| administrator-access-02 | Partial storage coverage / two-service requests missing | `tests/setup_storage.rs::competing_claims`; HTTP race not yet tested |
| administrator-access-03 | Partial storage coverage / HTTP missing | `issue_and_replace`, `unusable_codes`, `expiry_after_lock` in `tests/setup_storage.rs` |
| administrator-access-04 | Planned / missing | Requires controlled time and restart/cross-instance checks |
| administrator-access-05 | Planned / missing | Requires recovery and cross-instance revocation assertions |
| administrator-access-06 | Planned / missing | Requires current-password and revocation assertions |
| administrator-access-07 | Planned / missing | Requires HTTP and browser evidence |
| administrator-access-08 | Partial setup storage / other state missing | Real role-separated PostgreSQL setup tests; session and other state remain planned |

Discovery changed documentation only. The storage delivery below is partial
coverage of the agreed increment; HTTP setup remains closed.

## Setup storage contracts — requester continuation, 2026-10-18

### administrator-storage-01: durable operator authority

Given an unclaimed installation and operator database credentials
When `bloc admin setup-code` commits successfully
Then stdout contains only `code=<43-character base64url>` and
`expires_at=<UTC RFC3339>` on two lines, and exit is 0
And PostgreSQL stores only its SHA-256 digest and a 15-minute lifetime.

Given a storage or success-audit failure
When code issuance fails
Then exit is 1 with no code output and no partial replacement.

### administrator-storage-02: privilege separation

Given runtime database authority
When code issuance or direct authority writes are attempted
Then PostgreSQL refuses them.

Given operator database authority
When owner creation or direct password replacement is attempted
Then PostgreSQL refuses them.

### administrator-storage-03: atomic ownership and current code

Given a valid setup code and validated identifier/password hash
When two independent runtime connections compete to claim ownership
Then exactly one creates an owner with code consumption and setup audit
And the other observes setup closed without creating a second owner.

Given expired, replaced or consumed setup authority
When a claim attempts to commit
Then no owner is created; expiry is checked after acquiring the ownership lock.

Given setup success-audit insertion fails
When a valid claim attempts to commit
Then ownership and code consumption both roll back and the code remains usable.

| Scenario | Coverage | Exact tests |
| --- | --- | --- |
| administrator-storage-01 | Automated CLI/storage | `tests/operator.rs::durable_output_and_failures`; `tests/setup_storage.rs::issue_and_replace`; `tests/setup_storage.rs::audit_failure_rolls_back` |
| administrator-storage-02 | Automated database roles | `tests/setup_storage.rs::capability_roles` |
| administrator-storage-03 | Automated independent connections | `tests/setup_storage.rs::competing_claims`; `claim_and_replacement_serialize`; `unusable_codes`; `expiry_after_lock`; `audit_failure_rolls_back` |

These tests use disposable TLS PostgreSQL 17 and 18 via
`python3 tests/run_storage.py --output <new-directory>`.
Administrator-access-01/02/03/08 have storage-level coverage only; all their HTTP,
browser and two-service assertions remain unverified. The remaining interview
scenarios remain planned. These are checklist-derived tests added in the same
change as implementation; no red-before-implementation BDD sequence is claimed.
