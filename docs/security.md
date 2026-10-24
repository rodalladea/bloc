# security design requirements

These are requirements for future features, not claims about implemented controls.
Record a threat model and test plan for every authentication or federation flow.

- Enforce realm isolation in storage access and authorization; deny by default.
  Treat admin APIs and HTML fragments as equally protected surfaces.
- Use maintained password-hashing and cryptography libraries; design key storage,
  rotation, revocation, and recovery before issuing credentials.
- Use secure, HttpOnly session cookies with explicit SameSite policy, CSRF defense
  for state changes, session rotation, expiry, logout, and fixation prevention.
- For OIDC/OAuth, validate issuer, audience, signature, algorithms, expiry, nonce,
  state, PKCE, client authentication, scopes, and exact redirect URI allowlists.
  Make codes single-use and short-lived. Prevent refresh replay and mix-up attacks.
- For SAML, disable dangerous XML features; validate signatures against trusted
  metadata, signed element binding, audience, destination, recipient, correlation,
  timestamps, and replay. Plan metadata and certificate rotation.
- Provider discovery and callbacks require SSRF controls and bounded network
  requests. Never treat unverified email claims as account-linking authority.
- Rate-limit sensitive operations, resist enumeration, and audit security actions
  without logging credentials, tokens, cookies, or sensitive query strings.
- Keep templates escaped. Use CSP, server-side validation, and redacted errors.
  Do not trust HTMX headers as authentication or authorization evidence.
- Define TLS/proxy trust, secret injection, encryption, backups, retention, and
  dependency response procedures before deployment documentation claims readiness.

Future protocol work must reference the relevant official specifications and
current library docs, include attack-path tests, and document residual limitations.
