# agent guide for bloc

This file is the entry point and index for agents working in this repository.
Keep it concise; put detailed guidance in the linked documents.

## Start here

1. Read [README.md](README.md) for current capabilities and local setup.
2. Read [architecture](docs/architecture.md) and the relevant
   [decision records](docs/adr/0001-foundation.md) before changing boundaries.
3. Follow the [BDD workflow](docs/development-workflow.md) for feature decisions
   and behavior changes, and [development guidance](docs/agents/development.md)
   for implementation, including code design, dependency injection, Rust practices,
   and [HTMX 2.0.8 practices](docs/agents/development.md#htmx-practices-208).
4. Read [DESIGN.md](DESIGN.md) before changing the interface; follow its visual
   direction, design tokens, and component guidance.
5. Read [security guidance](docs/agents/security.md) for identity, HTTP, secrets,
   persistence, or dependency changes.
6. Follow [review guidance](docs/agents/review.md) before handing work back.

## Repository rules

- Write the project name as `bloc`, always lowercase.
- Use Rust for the server and server-rendered HTML with HTMX for the interface.
- Keep implemented features distinct from planned features. Never describe a
  placeholder as working authentication or a conformant identity protocol.
- Preserve user changes. Keep diffs scoped; do not commit, publish, or release
  unless instructed. Never introduce credentials or real identity data.
- Follow [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Use Context7 MCP for current library, framework, SDK, API, CLI, and cloud-service
  documentation. Resolve the library ID first, then query the selected library
  for a focused concept. Use version-specific docs where available. If unavailable,
  state that limitation and use official documentation. This is unnecessary for
  general programming, business logic, review, or pure refactoring.
- Add a focused instruction file only when a subsystem needs different guidance;
  link it here. Avoid duplicate instructions for individual AI tools.

## Task map

| Task | Read |
| --- | --- |
| Feature discovery, behavior changes, acceptance examples | [BDD workflow](docs/development-workflow.md), [behavior template](docs/behaviors/template.md) |
| HTTP, templates, assets, tests | [Development](docs/agents/development.md) |
| HTMX interactions, fragments, navigation | [HTMX 2.0.8 practices](docs/agents/development.md#htmx-practices-208) |
| Design patterns, dependency injection, code quality | [Code design](docs/agents/development.md#code-design-and-patterns), [dependency injection](docs/agents/development.md#dependency-injection), [Rust practices](docs/agents/development.md#rust-practices) |
| Interface design, styling, components | [Design](DESIGN.md), [development](docs/agents/development.md) |
| Authentication, federation, authorization | [Security](docs/agents/security.md), [security design](docs/security.md) |
| New subsystem or dependency | [Architecture](docs/architecture.md), [foundation ADR](docs/adr/0001-foundation.md) |
| Commits, PRs, checks | [Review](docs/agents/review.md), [contributing](CONTRIBUTING.md) |
| Release or repository administration | [Releases](docs/releases.md), [governance](GOVERNANCE.md) |
