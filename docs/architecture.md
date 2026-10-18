# architecture

bloc is intended to be an identity and access management server, with two distinct
roles: acting as an issuer for applications that trust bloc, and brokering login
to external identity providers. OAuth provides delegated authorization; OpenID
Connect adds authentication. SAML federation is a separate planned protocol surface.

## Current implementation

One Rust package uses Axum and Tokio. `main.rs` owns process startup and shutdown;
`lib.rs` builds a testable router. HTML and assets are embedded at compile time.
HTMX enhances a status link by fetching an HTML fragment. The HTTP router has no
database dependency, provider registry, session store, login flow, or token service. An internal setup
storage module and explicit migration/operator commands now target PostgreSQL
17/18; no HTTP route consumes them yet. See the [storage runbook](administrator-setup-storage.md).

The listener defaults to loopback. Responses use a restrictive CSP, no-store,
no-sniff, no-referrer, and frame denial. These are scaffold protections, not a
complete identity security model. Container packaging binds to all interfaces
inside the container while source startup retains its loopback default.

The Helm chart creates a namespaced Deployment and ClusterIP Service, optionally
referencing operator-owned ingress/TLS infrastructure. It uses the release's
multi-platform image digest and requires no persistent storage. Both probes use
process liveness for this dependency-free scaffold; future dependencies require
a separate readiness decision. See [ADR 0003](adr/0003-initial-distribution.md)
(proposed), the [installation runbook](install.md), and [release gates](releases.md).
Packaging source and local checks do not establish public artifact availability.

## Planned boundaries

- Domain: tenants/realms, users, external identities, clients, roles, grants.
- Application: login orchestration, consent, account linking, admin authorization.
- Protocol adapters: OIDC/OAuth issuer, OIDC broker, SAML IdP and SP roles.
- Infrastructure: persistence, key storage/rotation, email, audit events.
- Web: server-rendered admin and login pages, HTMX fragments, HTTP APIs.

These are boundaries to establish as features land, not empty crates to generate.
Tenancy and protocol boundaries require separate ADRs. The planned administrator
increment selects shared PostgreSQL; proposed [ADR 0004](adr/0004-initial-administrator-access.md)
records its setup schema, SQLx migration and privilege boundaries. The scaffold
HTTP server remains database-free until that integration lands.

Provider selection will be driven by enabled, validated configurations scoped to
a tenant. Provider secrets remain server-side. Explicit account-linking policy
must prevent identity takeover; matching email alone is insufficient.

Protocol implementations must use maintained libraries, published specifications,
negative tests, and conformance tooling. Passing application tests alone does not
establish protocol conformance. See [security requirements](security.md).
