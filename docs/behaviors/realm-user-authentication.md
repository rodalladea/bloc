# Realm-user authentication and My Account

Status: implemented — independent verification proves 65/66 checks; paired native capacity remains pending.

## Problem and scope

Realm directory users need independent access before application protocols can
consume their identities. This agreement covers opt-in registration, administrator
activation/recovery, email/password sign-in, realm sessions and My Account.
Email verification/delivery, MFA, public recovery issuance, user email change or
deletion, delegated administration and identity protocols remain outside scope.

## Rules and decisions

The requester approved technical and visual direction on 2026-10-26 and subsequently
requested implementation. [ADR 0007](../adr/0007-realm-user-authentication.md)
records the identity/storage boundary. See the [threat model](../realm-authentication-threat-model.md),
[runbook](../realm-user-authentication.md) and [DESIGN.md](../../DESIGN.md).

- [projects/bloc/.tasks/realm-user-authentication-and-my-account.md](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=8fc565a08878652aad8b6a5ceae0dc5e8eaf638f4a5a6dec), file ID `8fc565a08878652aad8b6a5ceae0dc5e8eaf638f4a5a6dec`: approved build contract.
- [projects/bloc/.design/realm-user-authentication-and-my-account.md](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=807a88ce48c15761920b6b779b78e892a4ea5ab866ed6ca8), file ID `807a88ce48c15761920b6b779b78e892a4ea5ab866ed6ca8`: product rules and security guardrails.
- [projects/bloc/.design/realm-user-authentication-preview/realm-user-authentication-preview.html](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=f2dcc634f47b5e7acb784ccca96a5730a348d6f2329a84e8), file ID `f2dcc634f47b5e7acb784ccca96a5730a348d6f2329a84e8`: binding interface, including the revised standard directory Sessions table.

## Open questions and assumptions

Production MFA/full acceptance/maintainer security approval remains unsatisfied.
Keep existing server/ingress header bounds and record observed refusal codes,
without a new configurable quota. Sessions display in stable ascending
(created_at,id) order; eviction remains oldest first. These are the task's
specified open defaults, not newly approved product policy.

## Scenarios

### realm-auth-settings

Given an authenticated installation administrator and an active or suspended realm.
When the administrator opens authentication settings, saves a current version or submits a stale/invalid policy.
Then defaults are off/16/no composition/86400/1800/1800/43200/10; valid changes redirect 303 with one event; invalid bounds return 422; stale versions return 409 without overwrite.

### realm-auth-session-policy

Given sessions whose stored expiry or old/new policy deadline equals database time, plus more sessions than a proposed cap.
When the administrator confirms a version-bound timeout/cap change.
Then expired sessions end before the new policy becomes visible; increasing limits never revives them, cap reduction keeps newest (created_at,id), and existing links retain issuance expiry.

### realm-auth-password-policy

Given a realm with minimum 16 and independently enabled Unicode upper/lower and ASCII digit/punctuation rules.
When a person registers, activates, resets or changes a password.
Then commit uses current policy, preserves Unicode/whitespace, permits at most 128 scalars/512 bytes and clears invalid secrets; tighter policy does not invalidate existing passwords.

### realm-auth-request-authority

Given untrusted ingress, malformed/oversized/unsupported forms or mismatched realm/browser/session/purpose CSRF.
When a request reaches a credential or account endpoint.
Then existing400/403/413/415 precedence applies before password work; invalid CSRF makes zero mutations and provides fresh-GET guidance.

### realm-auth-administrator-native-logout

Decision source: [PR #27 review](https://github.com/rodalladea/bloc/pull/27#discussion_r4408094605).
Given an authenticated administrator on Authentication or User access with no-referrer protection.
When they submit the shared logout form with JavaScript disabled.
Then exact same-origin/navigate/document Fetch Metadata permits a null Origin, valid session-bound CSRF revokes the administrator session and redirects to sign-in; invalid CSRF or foreign metadata returns 403 without revocation. Other administrator forms retain their existing strict origin guard.

### realm-auth-admission

Given two replicas sharing fixed rolling 60-second budgets, one local worker each and bounded temporary state.
When requests compete for the last admission unit, two-unit password change or occupied worker.
Then one last-slot request wins; failed multi-bucket admission reserves nothing, capacity does not evict live state, unknown identities take dummy verification and public work stays within 20 of the combined 30 units.

### realm-auth-atomicity

Given current credentials and an in-flight password operation, or failing shared storage/audit.
When a competing lifecycle/reset/email/restore transition wins before credential commit.
Then stale authority yields no usable session or credential; failed audit rolls back all state and returns 503; fixed success actors/events and bounded denial dimensions contain no secrets.

### realm-auth-maintenance

Given more than 1000 eligible temporary rows in a category and retained directory users.
When the maintenance capability runs one invocation.
Then at most 1000 eligible rows per category are removed, bound forms precede links, live state and inactive directory users remain, and retention lag can be monitored.

### realm-auth-registration

Given an active enrollment-enabled realm and a new normalized email, or a collision with a credential-less/suspended record.
When the person submits registration or concurrent requests race for that email.
Then one active independent user/credential/event commits at most, followed by303 sign-in and no session; collisions return generic 422 administrator-contact guidance, invalid fields preserve safe input, and disabled/suspended-at-commit realms refuse without creation.

### realm-auth-link-issuance

Given an administrator viewing a current active user with or without credentials.
When the administrator confirms identity and issues the matching activation/reset purpose, or replaces that link.
Then issuance returns one-time canonical HTTPS fragment link, separate code and expiry; missing confirmation returns 422 and wrong purpose/stale version409; replacement invalidates old bound forms while reset issuance preserves current sessions.

### realm-auth-link-transport

Given a valid or invalid administrator-delivered access code and anonymous browser authority.
When the user opens the URL then explicitly continues, with JavaScript enabled or disabled.
Then GET changes no credential; JavaScript removes the fragment before POST, native code entry also works, successful exchange redirects to a secret-free password page without consuming the link, and no raw code leaks outside delivery output.

### realm-auth-link-consumption

Given link-bound forms in two browsers, including expiry/replacement/wrong realm or purpose.
When the browsers submit compliant passwords or race consumption against replacement/suspension/email edit.
Then only one credential transition commits; activation creates no session, reset ends all sessions/forms, invalid links share 403 feedback, expired forms can reexchange until original expiry, and policy errors clear secrets without extending authority.

### realm-auth-sign-in

Given an active realm/user with credentials, alongside an independent realm and administrator session.
When the person signs in with valid or invalid credentials and then opens account.
Then valid access creates one fresh realm session and redirects 303 to account/profile; unknown/missing/suspended/wrong credentials share 422, and cookies from other principals never substitute authority.

### realm-auth-session-lifecycle

Given active sessions at expiry equality or the current cap, including concurrent sign-ins.
When access refreshes, the eleventh sign-in at cap 10 commits, or the user signs out.
Then expiry is terminal, cap stays 10 with oldest evicted, logout ends only the requested realm session/forms, and failed logout clears its browser bearer with503 without claiming durable revocation.

### realm-auth-directory-restore

Given realm/user sessions, links and forms with unrelated realm/administrator cookies.
When oversized headers arrive, an administrator confirms email change or suspends a realm/user, or the operator invalidates after restore.
Then oversize fails closed without clearing other cookies; lifecycle/email changes atomically invalidate affected authority, email/password ownership stays immutable, reactivation never revives it, and restore fence denies both replicas.

### realm-auth-profile

Given a valid realm session, empty optional display name or concurrently edited version.
When the person opens or saves Profile.
Then email is read-only/unverified, principal is server-derived, trimmed name is at most 128 scalars/512 bytes with no controls, empty becomes null, valid update redirects 303 with one event, invalid 422 and stale 409 do not overwrite.

### realm-auth-password-change

Given an authenticated realm user with current password and other sessions/links.
When the user submits a confirmed compliant replacement, wrong current password or races a winning reset/suspension.
Then success replaces credentials, revokes all old sessions/forms/links and renews current authority before303; invalid 422 clears secrets and preserves credentials/sessions; stale authority cannot commit.

### realm-auth-session-management

Given a valid realm session and owned current/other/ended sessions plus a foreign management UUID.
When the user lists sessions and confirms revoke-one, revoke-current or revoke-others.
Then only owned active rows appear in the standard directory table with bounded sanitized labels; other revocation preserves current access, current revocation redirects to sign-in, foreign IDs return 404, and ended-owned replay redirects 303 with no duplicate event.

### realm-auth-browser

Given each of the 36 approved interface states at desktop/mobile and light/dark.
When a person follows ordinary links/forms without JavaScript or uses HTMX, repeated swaps/history and keyboard drawer controls.
Then the same canonical authority/escaping/no-store/CSP/HTMX settings hold; shared loading/error feedback and safe focus/navigation remain usable with the standard Sessions table.

## Verification

The mappings below passed independent round 2 on PostgreSQL 17 and 18. Overall
acceptance remains pending the paired native capacity evidence. The main integration target is
`tests/realm_authentication.rs`; included contract cases also compile into that
target. Each named proof must exist, run, and assert every mapped contract clause
on PostgreSQL 17 and 18. Browser and native scenarios require actual runtime
measurements, beyond HTML/source inspection.

PR #27 correction: the native administrator logout regression reproduced a 403
before the fix. C9 now asserts revocation and rejects foreign metadata/invalid
CSRF from both administrator pages; C19 exercises native submissions with
JavaScript disabled. C17 pauses verification before returning its result while
the competing invalidation completes, then checks the original denial status
and absence of issued sessions. Splitting the HTTP module changes no other
agreed behavior. All 64 named realm database/browser proofs were rerun locally
on PostgreSQL 17.11 and 18.6 after these corrections and passed on both. Native
capacity records must be regenerated for the changed application fingerprint on
both Linux architectures before acceptance.

| Scenario | Task criteria | Exact integration tests | Coverage |
| --- | --- | --- | --- |
| realm-auth-settings | C1, C2, C3, C4 | `realm_auth_c01`, `realm_auth_c02`, `realm_auth_c03`, `realm_auth_c04` | Verified, round 2 |
| realm-auth-session-policy | C5, C6, C7 | `realm_auth_c05`, `realm_auth_c06`, `realm_auth_c07` | Verified, round 2 |
| realm-auth-password-policy | C8 | `realm_auth_c08` | Verified, round 2 |
| realm-auth-administrator-native-logout | PR #27 F2 | `realm_auth_c09` (`administrator_native_logout`), `realm_auth_c19` (native browser checks on both pages) | Verified on PostgreSQL 17 and 18, including native browser submissions |
| realm-auth-request-authority | C9, C15 | `realm_auth_c09`, `realm_auth_c15` | Verified, round 2 |
| realm-auth-admission | C10, C11, C12, C13, C14, C63 | `realm_auth_c10`, `realm_auth_c11`, `realm_auth_c12`, `realm_auth_c13`, `realm_auth_c14`, `realm_auth_c63` | Verified, round 2 |
| realm-auth-atomicity | C16, C17, C18, C19 | `realm_auth_c16`, `realm_auth_c17`, `realm_auth_c18`, `realm_auth_c19` | Verified, round 2 |
| realm-auth-maintenance | C20 | `realm_auth_c20` | Verified, round 2 |
| realm-auth-registration | C21, C22, C23, C24, C25, C26 | `realm_auth_c21`, `realm_auth_c22`, `realm_auth_c23`, `realm_auth_c24`, `realm_auth_c25`, `realm_auth_c26` | Verified, round 2 |
| realm-auth-link-issuance | C27, C28, C29 | `realm_auth_c27`, `realm_auth_c28`, `realm_auth_c29` | Verified, round 2 |
| realm-auth-link-transport | C30, C31, C32, C39 | `realm_auth_c30`, `realm_auth_c31`, `realm_auth_c32`, `realm_auth_c39` | Verified, round 2 |
| realm-auth-link-consumption | C33, C34, C35, C36, C37, C38 | `realm_auth_c33`, `realm_auth_c34`, `realm_auth_c35`, `realm_auth_c36`, `realm_auth_c37`, `realm_auth_c38` | Verified, round 2 |
| realm-auth-sign-in | C40, C41, C42, C43 | `realm_auth_c40`, `realm_auth_c41`, `realm_auth_c42`, `realm_auth_c43` | Verified, round 2 |
| realm-auth-session-lifecycle | C44, C45, C46, C47 | `realm_auth_c44`, `realm_auth_c45`, `realm_auth_c46`, `realm_auth_c47` | Verified, round 2 |
| realm-auth-directory-restore | C48, C49, C50 | `realm_auth_c48`, `realm_auth_c49`, `realm_auth_c50` | Verified, round 2 |
| realm-auth-profile | C51, C52, C53, C61 | `realm_auth_c51`, `realm_auth_c52`, `realm_auth_c53`, `realm_auth_c61` | Verified, round 2 |
| realm-auth-password-change | C54, C55 | `realm_auth_c54`, `realm_auth_c55` | Verified, round 2 |
| realm-auth-session-management | C56, C57, C58, C59, C60 | `realm_auth_c56`, `realm_auth_c57`, `realm_auth_c58`, `realm_auth_c59`, `realm_auth_c60` | Verified, round 2 |
| realm-auth-browser | C62 | `realm_auth_c62` | Verified, round 2 |

Migration/role/compatibility proof: `realm_auth_upgrade_roles`; unchanged
administrator policy: `administrator_policy_unchanged`. Native mixed-load proof:
`realm_auth_native_capacity`, requiring both native architectures and the final
source fingerprint. Documentation mapping proof:
`python3 -m unittest discover -s tests -p 'test_realm_authentication_docs.py' -v`.

Initial test-first observation: `realm_auth_c01` ran on PostgreSQL 17.11 before
implementation and failed on 404 versus required 200. This establishes the missing
route, not completion of any scenario. Final results and the independent verdict
belong in the Drive implementation checklist/report; update this coverage status
only after actual proofs.


Independent verification and correction evidence is maintained in
[projects/bloc/.checks/realm-user-authentication-and-my-account.verified.md](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=bd67ae7ab592ea4a01d2e1f8af139900ff84462353abff05),
file ID `bd67ae7ab592ea4a01d2e1f8af139900ff84462353abff05`.
The first review identified rejected-POST session refresh and collision navigation
issues; both are corrected. Independent round 2 proves 65/66 whole criteria,
including all 64 named database/browser proofs on each supported PostgreSQL
version. No further implementation defect was found. C65 remains unproven until
matching final-source native arm64 and amd64 capacity evidence is available.

## Interface consistency follow-up (2026-10-29)

Maintainer-requested presentation correction; authentication rules are unchanged.

### realm-auth-interface-consistency

- **Given** a realm user viewing My Account, **when** they open Appearance,
  **then** the shared administrator-style menu offers System, Light and Dark,
  persists the selection and returns focus to its trigger after selection/Escape.
- **Given** public access, **when** an authenticated workspace has a saved theme,
  **then** the public page still follows system appearance without a selector.
- **Given** account forms, link delivery or confirmation screens, **when** viewed
  on desktop or mobile, **then** actions have space from adjacent content, long
  details wrap and the page does not overflow horizontally.

Manual/browser-script coverage: 54 synthetic render variants (nine representative
states × 375/768/1440px × light/dark), appearance persistence, keyboard dismissal,
public system appearance and no-JavaScript selector fallback passed. Actual
Askama templates were rendered with synthetic data; this is presentation evidence,
not a repeat of database/TLS or authenticated navigation acceptance. No new
business-rule test is needed for the spacing/component reuse.

Evidence and reproduction scripts:
[projects/bloc/.checks/realm-interface-review-2026-10-29.zip](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=74657d31db5b4ef33910ec0c43796dd7481844cfe1cc8146).
