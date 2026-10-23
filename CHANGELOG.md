# changelog

User-visible changes are recorded here. Released versions will use Semantic
Versioning; pre-1.0 APIs and configuration may change between minor releases.

## Unreleased

## 0.2.0 - 2026-10-23

### Added

- Administrator-only tenant and tenant-user directory management with immutable
  identities, tenant-local email uniqueness, independent suspension/reactivation,
  version conflicts, guarded PostgreSQL authority and atomic targeted audit events.
  Directory records do not authenticate users. Requires explicit migration 0003;
  old and new binaries cannot share an incompatible schema contract.

## 0.1.1 - 2026-10-21

### Changed

- Reissue administrator access with cleaned release metadata. Runtime behavior
  and database migrations are unchanged.

## 0.1.0 - 2026-10-21

### Added

- Internal PostgreSQL setup storage, explicit migrations, restricted operator
  setup-code command, and atomic owner/audit transactions with live role and
  concurrency tests.
- Installation administrator setup, password sign-in and sign-out, server-side
  sessions, password changes, and operator-authorized recovery, with secure
  request handling, accessible server-rendered screens, and restore invalidation
  procedures. Native service capacity acceptance is required before release.

### Fixed

- Preserve administrator form CSRF tokens after throttled submissions so retries
  can succeed; offer a reload link when new form issuance is throttled.

- Update TLS certificate verification and trust roots for RUSTSEC-2026-0382 and
  RUSTSEC-2026-0381, and remove the unused Askama configuration dependency on
  unmaintained `basic-toml`.
- Verify anonymous Docker pulls using the reported registry digest when pulling
  a second platform clears the local image's `RepoDigests` metadata.

## 0.0.1 - 2026-10-15

### Added

- Rust HTTP server with local HTMX assets, development page, and liveness endpoint.
- Apache-2.0 licensing, contributor and agent documentation, and CI workflows.
- Container packaging and a digest-pinned Helm chart for the scaffold, with
  optional operator-owned ingress and documented upgrade/rollback procedures.
- Distribution validation and immutable-release automation targeting the initial
  unified version `0.0.1`; public availability remains gated on release verification.

Identity and federation protocols are not yet implemented.
