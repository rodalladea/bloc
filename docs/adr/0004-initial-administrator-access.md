# 0004: initial administrator access with shared PostgreSQL

Status: accepted — 2026-10-21

## Context

bloc has an HTTP scaffold and distribution packaging but no identity persistence
or administration boundary. In discovery on 2026-10-16, the requester selected
initial installation ownership and administrator access as the first identity
feature, then required multiple instances in one region for enterprise-oriented
deployments. This record captures the agreed direction and remaining design
work. The dated acceptance below records the subsequent maintainer decision.

See the [design](../../.design/administrator-access.md) and
[behavior record](../behaviors/administrator-access.md).

## Options

| Option | Disposition |
| --- | --- |
| One instance with local persistence | Rejected: requester requires multiple concurrent instances |
| Shared disk without an external database | Considered, then deferred with requester agreement; coordination and filesystem recovery would need separate investigation |
| Shared PostgreSQL | Selected by requester; one authoritative store for administrator, sessions, operator codes, and audit events |
| Multiple database engines initially | Deferred; no requirement for another engine was identified |
| Separate session service | Not justified without measured contention; adds another state-consistency boundary |
| Multi-region operation | Excluded by requester; one region is the agreed baseline |

## Decision

The accepted architecture implements the confirmed interview decisions in the
design's Key decisions section. Deployment access authorizes the first
installation administrator through an operator-generated code, and later
authorizes recovery of that same account. The built-in HTML interface is the
only administration interface in this increment. PostgreSQL coordinates all
instances; instance-local files and positive authorization caches cannot be
the authority for ownership or session validity.

The administrator is installation-scoped and is not a tenant user or a protocol
identity. No application-user sign-in, issuer, federation, or account-linking
behavior follows from this decision. MFA is outside this increment but must
precede a production authentication release, as confirmed by the requester.

On 2026-10-18, the requester excluded breached/common-password screening from
this increment. There is no online lookup, offline corpus, screening revision
field, or dataset provisioning/refresh requirement. Password hashing and the
other agreed password and authority controls remain required. This scope update
does not change the proposed status of this ADR.

## Consequences

Database configuration, migrations, readiness, credential injection, and restore
behavior become deployment requirements. An instance can fail without losing
authoritative identity state, but database availability depends on the operator's
database deployment. Authentication fails closed during loss of that authority.

Deployment/database credentials are privileged recovery authority. The operator
command is not a public API and must not expose its output through routine logs.
Password changes and recovery must be coordinated with concurrent sign-in and
session checks, not merely delete a cookie on one instance.

The requester approved the concrete prerequisite policy and five-screen preview.
Native primitive hashing matrices and verified PostgreSQL 17/18 TLS evidence are
available. The finalized setup-storage RFC supplies the schema/grant mechanism:
`projects/bloc/design/administrator-access-security-storage.md`, Drive ID
`4bcaafc1a56954360b14426d7fe92239d1a351dcd0a55487`, section
“Implementation contract — restricted setup storage, 2026-10-18”. The task is
`projects/bloc/.tasks/administrator-access.md`, Drive ID
`87bd2c0006669399f6e64c832b144da78fd0bbeca80fb059`.

Use SQLx 0.9.0 with explicit locked, checksum-validated forward migrations and
VerifyFull database TLS. Provision separate NOLOGIN capability roles before
migration. The private `bloc` schema and guarded SECURITY DEFINER functions
separate operator issuance from runtime consumption; neither role gets direct
authority-table writes. Functions pin `pg_catalog, bloc, pg_temp` search order,
and PUBLIC cannot execute them. Setup claims and code replacement lock the
installation singleton, then read fresh database time. Unique installation
ownership and atomic success audit enforce the transaction boundary. See the
[setup storage runbook](../administrator-setup-storage.md) for provisioning.

The first delivery covers storage and operator CLI only. No browser setup route
is opened. Session/form/admission/denial tables arrive with their consumers.
The existing scaffold startup contract changes only with the later HTTP slice.
Full-service hashing/overload/health measurements, browser security integration,
deployment, restore and two-instance acceptance remain required. No
production-readiness or conformance claim is made; this ADR remains proposed.

## Behavior and verification

The linked behavior record distinguishes storage proofs from missing browser
acceptance. Formal ADR acceptance follows [governance](../../GOVERNANCE.md).

## HTTP integration continuation — 2026-10-19

The requester approved Askama 0.16.1 for embedded compile-time checked,
autoescaped HTML templates. Runtime-interpreted MiniJinja was considered; runtime
theme loading is not required by the five built-in screens. Migration 0002 adds
shared digest sessions, browser-bound synchronizer form state, atomic rolling
admission, denial aggregates, guarded recovery/password replacement, restore fence
and bounded maintenance. Required origin/proxy/secret-file configuration and
separate operational chart workloads accompany the interface.

The HTTP implementation is delivered for development and evaluation; this does
not constitute formal ADR acceptance. The
[operations runbook](../administrator-access.md) governs deployment and restore.
Native full-service capacity on both architectures and independent verification
are acceptance gates, with source-bound results recorded by CI and the behavior
record. The historical internal-only status above describes the
first delivery rather than the current HTTP implementation.

## Formal acceptance — 2026-10-21

Rodrigo Dalla Dea, sole maintainer, requested formal acceptance after completing
[PR #6](https://github.com/rodalladea/bloc/pull/6)'s review. Under
[governance](../../GOVERNANCE.md), this accepts the architecture and scoped
engineering decisions recorded here for development and evaluation, including
shared PostgreSQL authority, restricted database capabilities, explicit migrations,
Askama templates, and the installation-scoped administrator boundary.

Evidence considered:

- Independent verification records PASS for 59/59 whole claims under the light
  profile, without fault injection, with runtime proofs at `f3af672` and a
  scheduling-only addendum at `3f578e1`. The
  [behavior record](../behaviors/administrator-access.md) identifies the retained
  Drive report and scenario mappings.
- At PR head `2cdf11e15f89e5f7abce55195aefff7bab864d02`,
  [CI](https://github.com/rodalladea/bloc/actions/runs/39535100459),
  [dependency audit](https://github.com/rodalladea/bloc/actions/runs/39535100418),
  and [PR title](https://github.com/rodalladea/bloc/actions/runs/39535100412)
  completed successfully. This head includes the throttled-form F1 correction
  and mapped HTTP regression tests. Its review conversation was unresolved
  at acceptance and was subsequently resolved during release preparation; passing
  required checks remains a merge gate.

Architectural acceptance does not waive release validation. The retained native
capacity evidence measures application fingerprint
`dfb7a42dbd58b614015d36290ff80551b9488d8d4854afd334bb61d9fb08091b`;
the F1 fix changes the current fingerprint to
`da99e64cff11267e3688091a6f21a422ee1f8ceb7f04a2b70a7c006829478c4b`.
Fresh source-matched native amd64/arm64 capacity evidence and the complete
Distribution gates are required before publication. Earlier browser and cluster
results are historical evidence, not fresh executions of the corrected head.

This decision authorizes neither merging, tagging, publication nor deployment.
Release and deployment await explicit authorization and the release procedure;
deployment additionally requires an identified operator environment. MFA remains
a prerequisite for production authentication use. No identity-protocol conformance
or production-readiness claim follows from this ADR's acceptance.
