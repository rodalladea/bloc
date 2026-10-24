# security guidance for agents

Read [the security design](../security.md) before identity work. The administrator boundary is under verification; application-user identity
protocols remain unimplemented.

Do not implement cryptography, token verification, XML signature validation, or
protocol flows from memory. Consult protocol specifications and maintained library
documentation; record the relevant decisions and attack cases. Never replace a
missing validator with an always-successful stub.

Treat realm identity, redirects, issuer/audience selection, provider callbacks,
and account linking as explicit trust boundaries. Require negative tests when
implementing them. Authorization checks belong on every protected server action,
including HTMX fragment endpoints.

Never log passwords, tokens, authorization codes, session cookies, signing keys,
or full callback URLs. Use synthetic fixtures only. Never commit private keys or
production identity records. Report security issues according to SECURITY.md;
do not put exploit details into public issues.

Do not claim production readiness, standards compliance, or completed security
review from compilation and unit tests alone.
