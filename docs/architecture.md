# architecture

bloc is intended to be an identity and access management server, with two distinct
roles: acting as an issuer for applications that trust bloc, and brokering login
to external identity providers. OAuth provides delegated authorization; OpenID
Connect adds authentication. SAML federation is a separate planned protocol surface.

## Current implementation

One Rust package uses Axum and Tokio. `main.rs` owns process startup and shutdown;
`lib.rs` builds a testable router. HTML and assets are embedded at compile time.
HTMX enhances a status link by fetching an HTML fragment. There is no database,
user model, provider registry, session store, login flow, or token service.

The listener defaults to loopback. Responses use a restrictive CSP, no-store,
no-sniff, no-referrer, and frame denial. These are scaffold protections, not a
complete identity security model. TLS termination and deployment are not set up.

## Planned boundaries

- Domain: tenants/realms, users, external identities, clients, roles, grants.
- Application: login orchestration, consent, account linking, admin authorization.
- Protocol adapters: OIDC/OAuth issuer, OIDC broker, SAML IdP and SP roles.
- Infrastructure: persistence, key storage/rotation, email, audit events.
- Web: server-rendered admin and login pages, HTMX fragments, HTTP APIs.

These are boundaries to establish as features land, not empty crates to generate.
Persistent storage, tenancy semantics, migration tooling, and library choices
require separate ADRs. PostgreSQL is a candidate, not an existing requirement.

Provider selection will be driven by enabled, validated configurations scoped to
a tenant. Provider secrets remain server-side. Explicit account-linking policy
must prevent identity takeover; matching email alone is insufficient.

Protocol implementations must use maintained libraries, published specifications,
negative tests, and conformance tooling. Passing application tests alone does not
establish protocol conformance. See [security requirements](security.md).
