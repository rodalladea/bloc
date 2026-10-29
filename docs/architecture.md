# architecture

bloc is intended to be an identity and access management server, with two distinct
roles: acting as an issuer for applications that trust bloc, and brokering login
to external identity providers. OAuth provides delegated authorization; OpenID
Connect adds authentication. SAML federation is a separate planned protocol surface.

## Current implementation

One Rust package uses Axum/Tokio, Askama 0.16.1 compile-time autoescaped HTML,
and locally served HTMX 2.0.8. `main.rs` assembles validated configuration and
shared storage; `administrator::router` is the production HTTP assembly. Domain
credential validation and bounded Argon2 work are independent of HTTP parsing.

Shared PostgreSQL 17/18 is the only owner/session/form/admission/audit authority.
Guarded SECURITY DEFINER operations serialize security transitions through the
installation singleton and recheck database time and credential version. Separate
runtime, operator, migrator and maintenance capabilities have no unrestricted
runtime authority-table writes. Explicit SQLx checksum migrations never run from
serving replicas. Restore sets a durable recovery fence until operator-authorized
credential replacement. See [administrator operations](administrator-access.md).

The canonical HTTPS ingress is trusted only by explicit immediate-peer CIDRs;
requests validate exact Host, one source IP and HTTPS forwarding. Every response
retains restrictive CSP/no-store/referrer/frame protections. Admin POSTs also
require canonical Origin or HTTPS Referer and shared browser/session-bound CSRF.
Logout additionally accepts native no-referrer form navigation only with exact
same-origin Fetch Metadata; ingress and CSRF checks remain mandatory.

The Helm chart mounts operator-owned secret references, uses `/readyz` for primary
compatibility and `/healthz` for liveness, and separates optional operational Jobs
and operator Pod credentials. Full-service native capacity remains acceptance work;
no production readiness or identity-protocol conformance is claimed.

Independent realm/user directories extend this guarded authority model. Each
user has immutable realm ownership, realm-local canonical email uniqueness and
independent lifecycle status. Reads and atomic directory/audit mutations recheck
current administrator authority under the installation lock. See
[ADR 0005](adr/0005-tenant-user-directories.md),
[realm terminology decision](adr/0006-realm-terminology.md), and the
[directory runbook](realm-user-management.md). Directory records alone confer no
authentication authority. Migration 0005 adds separate realm credentials,
realm/purpose-bound forms, sessions, access links and policy. Realm HTTP assembly
and shared form/security helpers live in
`realm_authentication.rs`; its focused `access`, `account`, `admin`, `submission`
and `view` modules separate route handling, credential commits and rendering.
Guarded database calls live in `realm_storage.rs`.
They share the administrator's bounded password worker and installation admission
budget, while principal authority remains separate. See
[ADR 0007](adr/0007-realm-user-authentication.md) and the
[authentication runbook](realm-user-authentication.md). Browser, native capacity
and independent security acceptance remain pending.

## Planned boundaries

- Domain: external identities, clients, roles, grants; realm/user directories are implemented.
- Application: login orchestration, consent, account linking, admin authorization.
- Protocol adapters: OIDC/OAuth issuer, OIDC broker, SAML IdP and SP roles.
- Infrastructure: persistence, key storage/rotation, email, audit events.
- Web: server-rendered admin and login pages, HTMX fragments, HTTP APIs.

These are boundaries to establish as features land, not empty crates to generate.
Realm isolation and protocol boundaries require separate ADRs. The administrator
increment uses shared PostgreSQL; accepted [ADR 0004](adr/0004-initial-administrator-access.md)
records its setup schema, SQLx migration and privilege boundaries. The HTTP server requires validated PostgreSQL configuration; serving replicas do
not run migrations.

Provider selection will be driven by enabled, validated configurations scoped to
a realm. Provider secrets remain server-side. Explicit account-linking policy
must prevent identity takeover; matching email alone is insufficient.

Protocol implementations must use maintained libraries, published specifications,
negative tests, and conformance tooling. Passing application tests alone does not
establish protocol conformance. See [security requirements](security.md).
