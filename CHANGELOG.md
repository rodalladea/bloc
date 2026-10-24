# changelog

User-visible changes are recorded here. Released versions will use Semantic
Versioning; pre-1.0 APIs and configuration may change between minor releases.

## Unreleased

## 0.4.0 - 2026-10-24

### Changed

- Rename tenant directories to realms, including administration URLs
  (`/admin/realms`), forms and directory ownership terminology. Explicit migration 0004 must run before the new binary and
  preserves existing records and historical audit events;
  previous `/admin/tenants` URLs are no longer supported.

## 0.3.2 - 2026-10-24

### Fixed

- Offer tenant creation directly in the workspace dropdown and move Manage tenants
  into the sidebar Settings group.

- Remove page-heading dividers and restore the narrower Account security layout.

- Add placeholders to editable fields and remove field dividers from login and
  password recovery while preserving the internal settings form style.

- Simplify public access, enlarge its controls, and follow the system theme without
  a selector. Align workspace page widths, contain tables and menus, space sidebar
  links and form footers, and consolidate tenant creation in the Tenants list.

- Generate GitHub release descriptions from the matching dated changelog section
  and use version-specific titles instead of repeating administrator-access text.

## 0.3.1 - 2026-10-23

### Fixed

- Validate scoped administrator styles and the shared appearance assets in the
  packaged-container smoke test. Version 0.3.0 failed this gate before publication.

### Changed

- Round sidebar and workspace-menu icon geometry while retaining the shared
  outline weight and sizing.

- Remove the workspace header; move tenant/account navigation into the sidebar
  menu and appearance, feedback and help into its footer.

- Unify rounded components around the shared 12px radius, including navigation,
  panels, notices, badges and controls.
- Align dark controls and focus colours with the workspace's neutral graphite
  palette, preserving the approved light theme and existing green status badges.
- Make buttons and fields more compact and rounded, with cool neutral surfaces,
  clearer control borders and a translucent neutral field-focus ring.
- Add subtle raised edges to primary and secondary buttons in both themes.
- Soften separators and field borders in both themes, and indicate the active
  navigation item with a neutral fill instead of a border and green dot.
- Unify the administrator overview, tenant directories, and account security in a
  responsive dashboard with persistent navigation, clearer action hierarchy,
  compact account details, and shared neutral/lime styling.
- Redesign administration with a single theme-integrated navigation menu,
  compact controls, bordered settings rows, integrated directory tables and
  focused access screens. Add persistent
  light/dark/system appearance and reusable HTML/CSS/JavaScript UI assets that
  remain local to bloc and can be extracted later.

## 0.2.1 - 2026-10-23

### Security

- Update the transitive ctutils dependency to 0.4.4 to address
  [RUSTSEC-2026-0385](https://github.com/RustCrypto/utils/pull/1569), affecting
  constant-time mask generation and 128-bit comparisons.

### Changed

- Update Argon2 to 0.6.0 and base64 to 0.23.1, preserving existing
  administrator password hashes and password parameters.
- Reuse CI build caches, avoid repeated distribution builds and capacity checks,
  preserve binary/schema compatibility checks, and update actions/cache to 6.1.0.

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
