# Realm two-factor authentication

Status: implemented; the 67 source scenarios were independently verified on
2026-11-08. Native Linux amd64 capacity and production acceptance remain open.

Realm users need an independent second proof after their password. The maintainer
approved realm policy, TOTP and WebAuthn, restricted enrollment and recovery, and
personal factor management. The current implementation request supersedes the
historical preparation-only restriction in the source documents. This agreement
does not establish production acceptance.

Decision sources:

- [projects/bloc/.tasks/realm-two-factor-authentication.md](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=beea76e2e5e6028d16bd30753dc1c64d8c73109a17daed60),
  file ID `beea76e2e5e6028d16bd30753dc1c64d8c73109a17daed60`: 67 source-state criteria and contract snapshot.
- [projects/bloc/.design/realm-mfa-secret-encryption-rfc.md](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=9079e744fda4686a70c20cd55497b85881aa2257adab7c7a),
  file ID `9079e744fda4686a70c20cd55497b85881aa2257adab7c7a`: approved secret/key lifecycle.
- [projects/bloc/.design/realm-webauthn-spike.md](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=a3f5a29be9ed92823b2583afbfe7b1554ffcfbcaac6a72f8),
  file ID `a3f5a29be9ed92823b2583afbfe7b1554ffcfbcaac6a72f8`: exact library contract and qualified interoperability evidence.
- [projects/bloc/.design/realm-mfa-screen-design.md](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=50647bb5cf70f9aed58d7e51d08aca760dddf54f3ef3ba0d),
  file ID `50647bb5cf70f9aed58d7e51d08aca760dddf54f3ef3ba0d`: binding corrected component reuse and screen arrangement.

See the [secret authority decision](../adr/0008-realm-mfa-secret-authority.md),
[threat model](../realm-mfa-threat-model.md), and
[operations runbook](../realm-mfa-operations.md).

## Boundary

Includes independent per-realm policy, password-plus-factor sign-in, immediate
policy enforcement, TOTP and WebAuthn enrollment, purpose-bound reauthentication,
recovery codes, optional administrator-assisted replacement, audit, bounded
authority, encrypted secret lifecycle and exact executable/schema compatibility.

Excludes installation-administrator MFA, passwordless access, SMS/email/push,
remembered devices, grace periods, bypass exemptions, hardware-only assurance,
delegated administration, protocol issuance and production approval.

## Agreed examples

The following examples retain the source-state outcomes. Each named test must
exercise the complete outcome, including its refusal branches, before the
coverage row can be marked verified. Fixed bounds and mechanisms in the task
and approved prerequisites remain part of the contract.

### Realm 2FA policy

- **realm-mfa-01** — Given New or upgraded realm, when the applicable realm 2fa policy action is exercised, then Default optional; both shipped methods permitted; no existing user silently enrolled; the caller observes Existing password login remains available to unenrolled users.
- **realm-mfa-02** — Given Disabled, when the applicable realm 2fa policy action is exercised, then Do not enforce or permit new factor enrollment; retain records and show the protection is disabled; the caller observes Explicit disabled status; existing factors remain manageable for removal after password proof.
- **realm-mfa-03** — Given Optional, no factors, when the applicable realm 2fa policy action is exercised, then Permit password-only session; enrollment is voluntary; the caller observes Account enrollment actions.
- **realm-mfa-04** — Given Optional, any active factor, when the applicable realm 2fa policy action is exercised, then Require an allowed active factor; a disallowed factor never authenticates; the caller observes Challenge, or recovery if none are allowed.
- **realm-mfa-05** — Given Required, no active factors, when the applicable realm 2fa policy action is exercised, then After password proof permit only initial enrollment and logout; the caller observes Enrollment required.
- **realm-mfa-06** — Given Required, existing factors but none allowed, when the applicable realm 2fa policy action is exercised, then Do not treat user as unenrolled; require recovery rather than password-only replacement; the caller observes Contact administrator or enabled recovery.
- **realm-mfa-07** — Given Tightening or disabling a method, when the applicable realm 2fa policy action is exercised, then Preview affected accounts, require fresh administrator password and explicit version-bound confirmation; immediately apply on next request; the caller observes Confirmation with counts; compliant sessions continue.
- **realm-mfa-08** — Given Zero allowed methods with optional/required, when the applicable realm 2fa policy action is exercised, then Refuse an unusable policy; the caller observes 422; no policy change.
- **realm-mfa-09** — Given Stale policy form, when the applicable realm 2fa policy action is exercised, then Reject rather than overwrite; the caller observes 409; reload.
- **realm-mfa-10** — Given Change while a factor flow is open, when the applicable realm 2fa policy action is exercised, then Invalidate that flow; preserve existing factors; the caller observes Restart with current policy.

### Realm MFA flow

- **realm-mfa-11** — Given Correct password, no factor required, when the applicable realm mfa flow action is exercised, then Existing session issuance with password evidence; the caller observes 303 My Account.
- **realm-mfa-12** — Given Correct password, factor required, when the applicable realm mfa flow action is exercised, then Issue only a restricted MFA flow; the caller observes 303 second-factor page; no ordinary session bearer.
- **realm-mfa-13** — Given Old session becomes noncompliant, when the applicable realm mfa flow action is exercised, then Refuse the original protected action; require fresh password and current factor/enrollment; the caller observes GET navigates to login; POST returns 403 with restart guidance and performs no mutation.
- **realm-mfa-14** — Given Wrong, used or expired proof, when the applicable realm mfa flow action is exercised, then Do not issue session or renew expiry; the caller observes 422 generic proof error; expired flow restarts login.
- **realm-mfa-15** — Given User switches allowed method, when the applicable realm mfa flow action is exercised, then Same flow, immutable deadline and aggregate attempt count; the caller observes Method picker.
- **realm-mfa-16** — Given User cancels or abandons, when the applicable realm mfa flow action is exercised, then Cancel on explicit POST; otherwise expire without changing factors; the caller observes Login; no authenticated state.
- **realm-mfa-17** — Given Five rejected proof submissions, when the applicable realm mfa flow action is exercised, then End the flow; aggregate account budgets remain; the caller observes 429 and Retry-After; restart after wait.
- **realm-mfa-18** — Given Policy/credential/epoch/lifecycle changed, when the applicable realm mfa flow action is exercised, then Refuse stale proof even if cryptographically valid; the caller observes 409 restart, or existing unavailable response for suspension.
- **realm-mfa-19** — Given Two replicas finish one flow, when the applicable realm mfa flow action is exercised, then Exactly one commits; no second bearer or double success audit; the caller observes Winner redirects; loser gets consumed-flow error.
- **realm-mfa-20** — Given Storage/audit unavailable, when the applicable realm mfa flow action is exercised, then No authentication success; the caller observes 503; existing retry policy.

### TOTP factor

- **realm-mfa-21** — Given Eligible enrollment, when the applicable totp factor action is exercised, then Generate candidate secret and encrypted pending state; the caller observes QR plus manual secret, visible only during authorized enrollment.
- **realm-mfa-22** — Given Candidate not yet confirmed, when the applicable totp factor action is exercised, then Never treat as active protection; the caller observes Pending setup; cancel allowed.
- **realm-mfa-23** — Given Correct confirmation, when the applicable totp factor action is exercised, then Atomically activate factor and consume its step; the caller observes Success; initial flow continues to recovery-code handoff.
- **realm-mfa-24** — Given Incorrect/expired confirmation, when the applicable totp factor action is exercised, then No active factor and no extended deadline; the caller observes 422 or restart.
- **realm-mfa-25** — Given Repeated valid OTP, including setup code used again, when the applicable totp factor action is exercised, then Only the first eligible consumption succeeds; the caller observes Generic proof rejection; wait for new code.
- **realm-mfa-26** — Given Replacement, when the applicable totp factor action is exercised, then Confirm new factor while old factor remains usable; authorized commit revokes old factor atomically; the caller observes No interval without protection.
- **realm-mfa-27** — Given Second independent TOTP enrollment, when the applicable totp factor action is exercised, then Release permits one active TOTP factor per user; the caller observes Replace existing authenticator action.

### WebAuthn factor

- **realm-mfa-28** — Given Supported browser, allowed method, when the applicable webauthn factor action is exercised, then Offer verified registration or authentication ceremony; the caller observes Platform/browser prompt.
- **realm-mfa-29** — Given Unavailable JavaScript or authenticator, when the applicable webauthn factor action is exercised, then Do not silently downgrade the policy; the caller observes Other allowed enrolled method, recovery, or clear unsupported guidance.
- **realm-mfa-30** — Given User cancels prompt, when the applicable webauthn factor action is exercised, then No factor/session change; parent deadline stays fixed; the caller observes Retry or select another method.
- **realm-mfa-31** — Given Successful registration, when the applicable webauthn factor action is exercised, then Store owned public credential, not a private key; the caller observes Named factor in Account factors.
- **realm-mfa-32** — Given Wrong origin, RP ID, user, UV, challenge or ceremony, when the applicable webauthn factor action is exercised, then Refuse even if another field appears valid; the caller observes Generic verification error.
- **realm-mfa-33** — Given Cross-realm attempt with a known credential, when the applicable webauthn factor action is exercised, then Current realm/account lookup cannot find matching authority; the caller observes Denied; no credential reuse.
- **realm-mfa-34** — Given Duplicate or concurrent finish, when the applicable webauthn factor action is exercised, then Only one consume/activation succeeds; the caller observes Replay/conflict response.
- **realm-mfa-35** — Given Non-increasing signature counter, when the applicable webauthn factor action is exercised, then Apply library/spec backup-aware validation; do not assume all synced passkeys have increasing counters; the caller observes Verified result or refusal as established by spike.

### Factor recovery

- **realm-mfa-36** — Given First factor confirmed, codes enabled, when the applicable factor recovery action is exercised, then Generate code set and require explicit saved acknowledgment before granting normal access; the caller observes Full-page download/copy handoff.
- **realm-mfa-37** — Given Lost code response, when the applicable factor recovery action is exercised, then Never retrieve plaintext from stored digest; repeat handoff by replacing the unacknowledged set under still-valid enrollment authority; the caller observes New set; prior set invalid.
- **realm-mfa-38** — Given Later code regeneration, when the applicable factor recovery action is exercised, then Require Key decision 4; replace entire generation atomically; the caller observes New codes shown once.
- **realm-mfa-39** — Given Valid password plus saved code, when the applicable factor recovery action is exercised, then Consume one code and invalidate all ordinary sessions; grant only factor-replacement authority; the caller observes Restricted recovery/setup.
- **realm-mfa-40** — Given No saved code, admin recovery enabled, when the applicable factor recovery action is exercised, then Administrator confirms identity and re-enters current administrator password before issuing purpose-specific link; the caller observes One-time fragment link and separate code.
- **realm-mfa-41** — Given Admin issues replacement link, when the applicable factor recovery action is exercised, then New link replaces prior link; issuance alone does not revoke working factors or sessions; the caller observes Expiry and replacement warning.
- **realm-mfa-42** — Given Link exchange, when the applicable factor recovery action is exercised, then Existing fragment-removal and explicit CSRF POST pattern; GET never consumes; the caller observes Password/re-enrollment flow.
- **realm-mfa-43** — Given Link plus current user password, when the applicable factor recovery action is exercised, then Consume link, revoke sessions, enter restricted replacement; retain old factors until replacement commits; the caller observes Only replacement, cancel or sign out.
- **realm-mfa-44** — Given Recovery abandoned, when the applicable factor recovery action is exercised, then Expire replacement authority; do not silently remove old factors; the caller observes Restart login/recovery.
- **realm-mfa-45** — Given Replacement confirmed, when the applicable factor recovery action is exercised, then Atomically revoke previous factors, invalidate old recovery generation and links, install new factor and present fresh codes if enabled; the caller observes Normal access only after completed handoff.
- **realm-mfa-46** — Given Codes disabled or exhausted and no allowed factor, when the applicable factor recovery action is exercised, then Use admin path only if enabled; otherwise no self-service bypass; the caller observes Explain that administrator policy change is required.
- **realm-mfa-47** — Given Ordinary password reset, when the applicable factor recovery action is exercised, then Preserve factors, revoke sessions per existing contract, invalidate pending MFA flows; the caller observes Login still requires factor.
- **realm-mfa-48** — Given Codes disabled after generation, when the applicable factor recovery action is exercised, then Reject saved codes while disabled; explicit administrator re-enable may restore unused, noninvalidated codes; the caller observes No implicit issue/consume.

### Account factors

- **realm-mfa-49** — Given No factors, optional, when the applicable account factors action is exercised, then Offer allowed enrollment methods; the caller observes Unprotected status and available actions.
- **realm-mfa-50** — Given Active factors, when the applicable account factors action is exercised, then Show label, type, creation, last successful use and personal default; the caller observes Own factors only; no secret redisplay.
- **realm-mfa-51** — Given Default method disallowed, when the applicable account factors action is exercised, then Ignore presentation preference and offer eligible factors; the caller observes Current allowed choices.
- **realm-mfa-52** — Given Add, replace, remove or regenerate codes, when the applicable account factors action is exercised, then Require exact recent proof under Key decision 4; recovered users have only replacement authority; the caller observes Reauthentication before mutation.
- **realm-mfa-53** — Given Remove one of several eligible factors, when the applicable account factors action is exercised, then Revoke it and rotate current authority after commit; the caller observes Updated list; all other sessions ended.
- **realm-mfa-54** — Given Remove last factor, optional, when the applicable account factors action is exercised, then Explicitly confirm return to password-only protection, invalidate code generation and other authority; the caller observes Password-only status.
- **realm-mfa-55** — Given Remove last factor, required, when the applicable account factors action is exercised, then Refuse; allow confirmed replacement instead; the caller observes 409; enroll replacement.
- **realm-mfa-56** — Given Disabled realm, when the applicable account factors action is exercised, then Label protection suspended; allow own factor deletion with fresh password, but no enrollment or code issuance; the caller observes Explicit inactive-policy explanation.
- **realm-mfa-57** — Given Preferred-factor change or label edit, when the applicable account factors action is exercised, then Current compliant session and CSRF suffice; no assurance change; the caller observes Updated display, no forced logout.
- **realm-mfa-58** — Given Stale/cross-owner factor action, when the applicable account factors action is exercised, then Reject without changing factors; the caller observes 409 stale or existing not-found response.

### Operations

- **realm-mfa-59** — Given Upgrade existing installation, when the applicable operations action is exercised, then Seed optional policy, no factors, factor epoch 1 and password-only session evidence; preserve established expiry/revocation; the caller observes Existing unenrolled user behavior.
- **realm-mfa-60** — Given Missing/invalid required operator keyring, when the applicable operations action is exercised, then Refuse new binary readiness; never auto-generate replacement keys; the caller observes Not ready with redacted diagnostic.
- **realm-mfa-61** — Given Rotation in progress, when the applicable operations action is exercised, then Read old and new keys; new encryptions use active key; bounded re-encryption preserves factor identity; the caller observes No factor reset.
- **realm-mfa-62** — Given Key removal while referenced, when the applicable operations action is exercised, then Refuse operation rather than lose secret access; the caller observes Operator error.
- **realm-mfa-63** — Given Ciphertext tamper or ownership swap, when the applicable operations action is exercised, then Refuse decryption and proof; no fallback; the caller observes Generic 503 and redacted operational signal.
- **realm-mfa-64** — Given Restore, when the applicable operations action is exercised, then Existing recovery fence blocks use; invalidate temporary MFA authority, saved-code generations and previous session epochs; restore completion sets each TOTP replay floor to at least the recovery-completion time step plus one; the caller observes Existing operator recovery process.
- **realm-mfa-65** — Given Old executable/new schema or inverse, when the applicable operations action is exercised, then Existing exact compatibility contract refuses readiness; the caller observes No mixed serving rollout.
- **realm-mfa-66** — Given Maintenance failure, when the applicable operations action is exercised, then No live authority deletion or proof success; the caller observes Redacted failure and retained backlog.
- **realm-mfa-67** — Given Database owner/runtime compromise, when the applicable operations action is exercised, then Document limits: database alone lacks encryption keys, but runtime must decrypt TOTP; neither protects against a compromised origin/runtime; the caller observes No exaggerated isolation claim.



## Scenario coverage

The following proofs passed independently on PostgreSQL 17 and 18. The
[independent verification report](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=08f304c80a579ea21a1603823cfed72e707f4b741ff6ab11)
at `projects/bloc/.checks/realm-two-factor-authentication.verified.md` records
the exact tests, assertions, and limits.

| Scenario | Named proof | Verified coverage |
| --- | --- | --- |
| realm-mfa-01 | `realm_mfa_c01` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-02 | `realm_mfa_c02` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-03 | `realm_mfa_c03` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-04 | `realm_mfa_c04` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-05 | `realm_mfa_c05` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-06 | `realm_mfa_c06` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-07 | `realm_mfa_c07` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-08 | `realm_mfa_c08` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-09 | `realm_mfa_c09` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-10 | `realm_mfa_c10` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-11 | `realm_mfa_c11` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-12 | `realm_mfa_c12` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-13 | `realm_mfa_c13` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-14 | `realm_mfa_c14` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-15 | `realm_mfa_c15` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-16 | `realm_mfa_c16` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-17 | `realm_mfa_c17` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-18 | `realm_mfa_c18` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-19 | `realm_mfa_c19` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-20 | `realm_mfa_c20` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-21 | `realm_mfa_c21` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-22 | `realm_mfa_c22` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-23 | `realm_mfa_c23` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-24 | `realm_mfa_c24` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-25 | `realm_mfa_c25` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-26 | `realm_mfa_c26` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-27 | `realm_mfa_c27` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-28 | `realm_mfa_c28` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-29 | `realm_mfa_c29` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-30 | `realm_mfa_c30` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-31 | `realm_mfa_c31` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-32 | `realm_mfa_c32` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-33 | `realm_mfa_c33` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-34 | `realm_mfa_c34` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-35 | `realm_mfa_c35` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-36 | `realm_mfa_c36` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-37 | `realm_mfa_c37` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-38 | `realm_mfa_c38` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-39 | `realm_mfa_c39` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-40 | `realm_mfa_c40` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-41 | `realm_mfa_c41` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-42 | `realm_mfa_c42` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-43 | `realm_mfa_c43` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-44 | `realm_mfa_c44` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-45 | `realm_mfa_c45` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-46 | `realm_mfa_c46` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-47 | `realm_mfa_c47` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-48 | `realm_mfa_c48` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-49 | `realm_mfa_c49` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-50 | `realm_mfa_c50` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-51 | `realm_mfa_c51` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-52 | `realm_mfa_c52` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-53 | `realm_mfa_c53` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-54 | `realm_mfa_c54` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-55 | `realm_mfa_c55` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-56 | `realm_mfa_c56` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-57 | `realm_mfa_c57` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-58 | `realm_mfa_c58` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-59 | `realm_mfa_c59` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-60 | `realm_mfa_c60` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-61 | `realm_mfa_c61` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-62 | `realm_mfa_c62` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-63 | `realm_mfa_c63` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-64 | `realm_mfa_c64` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-65 | `realm_mfa_c65` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-66 | `realm_mfa_c66` in `tests/realm_authentication.rs` and its included support modules | Independently verified |
| realm-mfa-67 | `realm_mfa_c67` in `tests/realm_authentication.rs` and its included support modules | Independently verified |

Additional required proofs cover keyring/envelope validation, CLI and Helm
contracts, shared admission and capacity bounds, ingress/CSRF and JSON limits,
shared UI components, real browser flows and transactional privilege/audit
boundaries. They are tracked in the implementation checklist in Drive, rather
than inferred from the 67 example names.

## Acceptance limits

Both PostgreSQL majors and two-replica races require real fixture execution.
HTTP tests cannot prove keyboard behavior, JavaScript ceremonies or HTMX swaps.
The prerequisite spike's three-engine automation used injected authenticators;
native Firefox/WebKit platform ceremonies and cloud synchronization were not
proved. Touch ID registration and authentication were reported and recorded, but
the exact browser/version was not captured.

The [source-matched native arm64 record](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=605121e7a0cb4540b4f0816535363cb18e10339419d3a11d)
at `projects/bloc/.checks/realm-mfa-c77-native-arm64-20261108-record.json` met its
measured limits. Native Linux amd64 evidence is unavailable, so the combined
capacity check remains incomplete. Independent security review and maintainer
full-flow acceptance remain separate gates. Automated tests establish neither
production approval nor standards conformance.
