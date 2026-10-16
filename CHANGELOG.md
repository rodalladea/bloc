# changelog

User-visible changes are recorded here. Released versions will use Semantic
Versioning; pre-1.0 APIs and configuration may change between minor releases.

## Unreleased

## 0.0.1 - 2026-10-15

### Added

- Rust HTTP server with local HTMX assets, development page, and liveness endpoint.
- Apache-2.0 licensing, contributor and agent documentation, and CI workflows.
- Container packaging and a digest-pinned Helm chart for the scaffold, with
  optional operator-owned ingress and documented upgrade/rollback procedures.
- Distribution validation and immutable-release automation targeting the initial
  unified version `0.0.1`; public availability remains gated on release verification.

Identity and federation protocols are not yet implemented.
