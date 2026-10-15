# 0001: Rust and server-rendered HTMX foundation

Status: accepted

## Context

bloc starts as an open-source identity project with no existing implementation.
The requested stack is Rust and HTMX, and the chosen license is Apache-2.0.

## Decision

Start with one Rust package, Axum/Tokio for HTTP, embedded HTML/assets, and locally
served, version-pinned HTMX. Separate process startup from the router so HTTP
behavior can be tested without sockets. Use Conventional Commits and squash PRs.
Keep AGENTS.md as an index to focused agent guidance.

Document protocol features as planned until implemented and reviewed. Defer storage,
tenancy, and protocol-library choices to focused ADRs rather than guessing interfaces.

## Consequences

No JavaScript build system or external service is needed for the scaffold. Asset
changes require recompilation. Dynamic pages will need an escaping template engine.
Authentication and federation remain substantial future work and require explicit
security design, negative testing, and interoperability validation.
