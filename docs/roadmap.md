# roadmap

This is an intended sequence, not a release commitment. The foundation and installation administrator
access are implemented for development and evaluation; broader identity features
remain planned. Open an issue to refine each milestone before implementation using the
[BDD workflow](development-workflow.md). Record agreed examples and open questions
before treating a milestone as an implementation task.

1. **Foundation (current):** Rust/HTMX scaffold, local development, CI, contributor
   policies, architecture and security requirements. Initial container/Helm
   distribution is tracked by [issue #2](https://github.com/rodalladea/bloc/issues/2);
   public availability depends on its release verification and GHCR bootstrap.
2. **Identity core:** storage ADR and migrations, realm isolation, user lifecycle,
   password hashing, verified recovery, sessions, audit events, admin permissions.
3. **OIDC/OAuth issuer:** client registration and exact redirect validation,
   discovery/JWKS, authorization code with PKCE, consent/scopes, token validation,
   refresh rotation/revocation, signing-key lifecycle, conformance tests.
4. **Provider brokering:** configurable OIDC providers, enabled-provider selection
   in login, safe callback handling, explicit linking/unlinking, secret management.
   Provider-specific OAuth login needs provider-specific identity verification.
5. **SAML federation:** separately scoped SP and IdP support, metadata, hardened
   XML/signature validation, replay prevention, certificate rotation, interoperability.
6. **Operational readiness:** deployment guidance, backups and restore tests, rate
   limits, observability with redaction, MFA/passkeys, accessibility and security
   review, compatibility and release support policy.

No authentication release should precede security requirements for its shipped
flows. Do not interpret this ordering as permission to defer those controls.

Administrator access HTTP implementation provides shared sessions,
setup, password change/recovery, request security and operations with source
and integration tests. Acceptance requires source-matched native full-service
measurements and independent verification. MFA must precede production authentication; no application-user
identity protocol is delivered by this increment.

Independent realm/user directory management now establishes immutable realm-bound
identities and independent lifecycle states. It does not implement realm-user
credentials, authentication, delegation or identity protocols. See the
[directory runbook](realm-user-management.md) for its boundary.
