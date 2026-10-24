# Initial administrator access

Status: agreed — HTTP journey implemented; acceptance requires the mapped proofs
and source-matched native capacity evidence.

## Problem and scope

- Actor: the operator of a new bloc installation.
- Outcome: establish installation ownership, return to administer it, and recover
  access without transferring ownership.
- In scope: setup, administrator sign-in, password change, recovery, sign-out,
  and a small administration home; multiple bloc instances in one region.
- Out of scope: public administration API, realm users, application integration,
  additional administrators, email verification/delivery, shared-disk persistence,
  and multi-region operation. MFA follows before production authentication use.
- Breached/common-password screening is excluded by requester decision on
  2026-10-18. No online lookup or offline password dataset is required.

## Rules and decisions

Source: requester confirmations in the tlc-discover conversation on 2026-10-16.
The [design](../../.design/administrator-access.md) records the confirmed
decisions once and separates proposed contracts from unresolved work. The
[accepted ADR](../adr/0004-initial-administrator-access.md) captures architecture
and alternatives. This record agrees only the examples below; it does not
silently approve all proposed engineering details in the design.

## Open questions and assumptions

The requester approved prerequisite policy and the five-screen preview; native
hashing matrices and live TLS evidence are available. The finalized setup-storage
contract is [projects/bloc/.design/administrator-access-security-storage.md](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=b490b2ad6fe83a7616a19e5c37b177b63a6ea6214f9aa05d), Drive
ID `b490b2ad6fe83a7616a19e5c37b177b63a6ea6214f9aa05d`. The task alignment is
[projects/bloc/.tasks/administrator-access.md](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=87bd2c0006669399f6e64c832b144da78fd0bbeca80fb059), Drive ID
`87bd2c0006669399f6e64c832b144da78fd0bbeca80fb059`.
Full-service overload, HTTP security, browser and deployment acceptance require
their named proofs. Storage coverage alone never establishes these outcomes.

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
And no realm or application-management placeholder is presented as working.

### administrator-access-08: shared storage boundary

Given multiple bloc instances operating in one region
When they access administrator, session, operator-code, or audit state
Then PostgreSQL is the shared authoritative store
And database-free shared-disk operation is outside the supported scope.

## Verification

| Scenario | Delivery / coverage | Evidence |
| --- | --- | --- |
| administrator-access-01 | HTTP/database tests implemented | `tests/administrator_access.rs::setup_page`, `setup_code_refusal`, `setup_success`, `email_policy`, `password_policy` |
| administrator-access-02 | Independent application HTTP race | `setup_http_race`, `setup_closed`, `setup_abandonment` |
| administrator-access-03 | Code lifecycle and durable CLI | `operator_code_boundaries`, `setup_cli_contract`; original storage tests retained |
| administrator-access-04 | Shared session authority and boundaries | `session_deadlines`, `session_restart`, `session_activity_races`, `two_instance_service`, `expiry_navigation` |
| administrator-access-05 | Recovery and concurrent credentials | `recovery_issue`, `recovery_success`, `recovery_refusal`, `login_recovery_race`, `credential_change_race`, `credential_atomicity` |
| administrator-access-06 | HTTP password change | `password_change_success`, `password_change_refusal` |
| administrator-access-07 | Escaped home and email semantics | `administration_home`, `email_semantics`; five named `browser_*` proofs exercise Chromium |
| administrator-access-08 | Shared primary, privileges, readiness | `authority_outage`, `readiness_liveness`, `capability_roles_extended`, `security_audit_atomicity` |

The table maps assertions, not a claim that every acceptance gate passed. The
remaining-feature checklist is in Drive at
[projects/bloc/.checks/administrator-access-remaining.md](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=fafb19e31501b64e2ba792592f2160bcbcfa0131e8512fa6) (ID
`fafb19e31501b64e2ba792592f2160bcbcfa0131e8512fa6`). Native full-service
amd64+arm64 evidence is a separate required gate; a named validator without
measurements is not a performance proof. Independent verification of the complete
checklist is required; the source-bound result is recorded in Drive at
[projects/bloc/.checks/administrator-access-remaining.verified.md](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=40c5445b513b94595a600be6c25ad39b98ab2dde29e25703) (ID
`40c5445b513b94595a600be6c25ad39b98ab2dde29e25703`).
Only the initial validation/hash tests were confirmed red before implementation;
the wider integration tests were added during implementation. No broader test-first
sequence is claimed.

## Additional HTTP/security examples

### administrator-access-09: browser authority and bounds

Given an untrusted immediate peer or malformed forwarding authority
When an administrator request reaches bloc
Then it returns 403 for an untrusted peer or 400 for invalid canonical forwarding.

Given equivalent HTTPS Host/Origin authority with host case or explicit default443
When an administrator request reaches bloc through a trusted immediate peer
Then it follows the same policy as the normalized authority; different hosts/ports,
userinfo, whitespace, backslashes and Origin paths/queries/fragments are refused.

Given a valid form
When its Origin is null/foreign, or its CSRF token belongs to another browser
Then the mutation returns 403 without password work or authority changes.

Given malformed/duplicate form values, unsupported media or an encoded body over
16 KiB, when submitted, then the HTTP status is 400, 415 or 413 respectively.
Exact tests: `proxy_authority`, `request_security_http`, `origin_csrf`,
`form_input_bounds`, `csrf_lifecycle`, `csrf_capacity`, `parsed_authority_contract`,
`streaming_form_bounds`, and library proof
`administrator::tests::request_rejections_precede_password_work`. Equivalent
parsed authority regression was reproduced red before the fix; the additional
coverage observations strengthen existing agreed policy.

### administrator-access-10: restore and retention

Given a fenced restored installation
When the operator runs `admin invalidate-access`
Then credential version advances, restored cookies/form/code authority fail,
and password sign-in is fenced until newly authorized recovery succeeds.

Given old audits and denial aggregates
When maintenance runs under its own role
Then it deletes bounded batches and grants no new access authority.
Exact tests: `restore_invalidation`, `restore_two_instances`,
`maintenance_retention`, `audit_data_bounds`, `capability_roles_extended`.
The live invalidation exercise does not by itself prove a physical backup restore.

### administrator-access-11: ordinary and enhanced forms

Given the five administration screens
When JavaScript is disabled, then real forms and links complete the journey.
When HTMX is enabled, designated errors replace the main fragment, focus its
single alert summary and never refill code/password fields. Normal success is303;
enhanced success is200 with HX-Redirect because XHR consumes3xx redirects.
When a request cannot be confirmed, show the approved network message, clear
secret fields and require an explicit retry. Exact tests: `browser_no_javascript`,
`browser_validation`, `browser_loading_network`, `browser_session_expiry`,
`browser_preview`.

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
The original storage evidence remains intact. The HTTP continuation above extends
the current implementation; final native capacity and independent acceptance are
separate gates.


## Throttled form retry — PR review F1, requester fix, 2026-10-20

### administrator-access-throttle-01: retry the returned form

Given a valid browser-bound form for setup, sign-in, recovery or password change
(and a current administrator session for password change)
When shared admission rejects its POST
Then the full-page or enhanced response is 429 with positive Retry-After
And it retains the same nonempty CSRF token and safe email, without refilling
operator codes or passwords.
When admission becomes available and the returned form is submitted without a GET
Then the operation succeeds with the normal redirect or enhanced HX-Redirect.

### administrator-access-throttle-02: reload when issuance is throttled

Given a browser without a usable form token on any administrator screen
When form issuance is throttled
Then the full-page or enhanced response is 429 with positive Retry-After,
an alert and a same-screen Reload form link, with no form or CSRF field.
When admission becomes available and the link is followed
Then a usable form is issued and its token passes CSRF validation.

| Scenario | Coverage | Exact tests |
| --- | --- | --- |
| administrator-access-throttle-01 | PostgreSQL-backed HTTP, full pages and HX fragments, four POST routes | `tests/administrator_access.rs::throttled_post_forms_remain_usable` |
| administrator-access-throttle-02 | PostgreSQL-backed HTTP, full pages and HX fragments, five GET screens | `tests/administrator_access.rs::throttled_form_issuance_requires_reload` |

Decision source: [PR #6 judge finding F1](https://github.com/rodalladea/bloc/pull/6#discussion_r4332392851)
and the request to fix the review feedback. These regressions exercise HTTP output;
they do not establish browser-engine swap/focus behavior or production acceptance.

## Architectural acceptance — 2026-10-21

The maintainer requested formal acceptance of [ADR 0004](../adr/0004-initial-administrator-access.md)
after PR #6 review. The ADR records the accepted development/evaluation scope,
current hosted checks and evidence revisions. Historical 59/59 verification does
not cover the subsequent F1 application change: fresh source-matched native
capacity and full Distribution validation remain publication gates. This record
retains its scenario mappings and evidence limitations; architectural acceptance
does not authorize release, deployment, or production authentication use.
