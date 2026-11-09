# 0008: realm MFA secret authority

Status: accepted design, implementation in progress — 2026-10-31.

## Context

The maintainer approved realm two-factor authentication and its dedicated secret
encryption RFC. Realm users remain independent of installation administrators.
The [task](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=beea76e2e5e6028d16bd30753dc1c64d8c73109a17daed60),
`projects/bloc/.tasks/realm-two-factor-authentication.md`, file ID
`beea76e2e5e6028d16bd30753dc1c64d8c73109a17daed60`, and
[RFC](https://drive.catap.io/s/24c13732f9478655a99ae9cd3eac7dcbdf7ece27d9edd394?file=9079e744fda4686a70c20cd55497b85881aa2257adab7c7a),
`projects/bloc/.design/realm-mfa-secret-encryption-rfc.md`, file ID
`9079e744fda4686a70c20cd55497b85881aa2257adab7c7a`, settle the contracts.

## Decision

Keep shared PostgreSQL as authority for current policy, factor/session evidence,
restricted purpose-bound flows, recovery generations and encryption writer key.
Dedicated operator-mounted key material remains outside the database. Migration
0006 adds an installation UUID retained across restore, immutable owner keys and
versioned authenticated BMFA envelopes using pinned XChaCha20Poly1305 0.11.0.
Encryption binds installation, realm, user, purpose, record and payload version.

Normalize active TOTP, pending TOTP and recovery handoff ciphertext into one
owner-bound encrypted-payload table. Typed factor/flow records reference it.
This keeps registry reference accounting and conditional re-encryption consistent
across all three purposes; runtime retains only narrow guarded operations.
Secrets and decrypted owned buffers use memory clearing, with no claim that all
compiler, allocator or OS copies can be erased.

The database registry chooses the writer key; startup-loaded keyrings contain
material only. Readiness requires every nonretired registered key. Operator
rotation uses explicit replica staging confirmation and resumable bounded batches
with revision/generation checks and atomic audit. Retirement requires zero retained
references and operator acknowledgment of independent backup escrow.

## Alternatives

Plaintext secret storage, reuse of the abuse key and replica-local writer selection
violate the approved confidentiality and rotation boundary. Separate envelope
stores would duplicate lifecycle/reference accounting. KMS or external MFA custody
would introduce an unapproved external service boundary.

## Consequences

Upgrade stops incompatible replicas, explicitly migrates and initializes the
keyring registry before serving. Exact executable/schema compatibility remains;
binary-only rollback is unsupported. Restore retains the recovery fence, ends
temporary MFA authority/code generations and advances epochs; recovery completion
advances TOTP replay floors to at least its current time step plus one.

The [operations runbook](../realm-mfa-operations.md) covers distribution, retirement,
backup escrow and lost-key limits. The database owner still controls availability
and metadata, runtime compromise can decrypt TOTP, and origin compromise can steal
proofs. This ADR establishes no production approval or completed MFA UI behavior.
